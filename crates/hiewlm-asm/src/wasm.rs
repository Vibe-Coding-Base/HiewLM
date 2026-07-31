//! WebAssembly bytecode decoder.
//!
//! WASM is a stack machine with variable-length instructions: a single-byte
//! opcode (or a `0xFC`/`0xFD` prefix pair) followed by LEB128-encoded
//! immediates. This decodes the MVP instruction set plus the saturating
//! conversions, which is what a `.wasm` module body actually contains.
//!
//! Decoding only names bytes — no module is instantiated or run. (Executing
//! WASM happens exclusively in the sandboxed plugin host, and only for plugin
//! modules the user supplies, never for the file under inspection.)

use crate::{Flow, Insn, Token, TokenKind};

/// Read an unsigned LEB128. Returns the value and the bytes consumed.
fn uleb(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let (mut result, mut shift, mut n) = (0u64, 0u32, 0usize);
    loop {
        let byte = *data.get(at + n)?;
        n += 1;
        if shift < 64 {
            result |= u64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((result, n));
        }
        // A LEB128 longer than 10 bytes cannot encode a u64: malformed.
        if n >= 10 {
            return None;
        }
    }
}

/// Read a signed LEB128.
fn sleb(data: &[u8], at: usize) -> Option<(i64, usize)> {
    let (mut result, mut shift, mut n) = (0i64, 0u32, 0usize);
    loop {
        let byte = *data.get(at + n)?;
        n += 1;
        if shift < 64 {
            result |= i64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            // Sign-extend if the payload's sign bit is set.
            if shift < 64 && byte & 0x40 != 0 {
                result |= -1i64 << shift;
            }
            return Some((result, n));
        }
        if n >= 10 {
            return None;
        }
    }
}

/// Immediate shapes that follow an opcode.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Imm {
    None,
    /// One unsigned LEB (local/global/func/label index).
    Idx,
    /// Two unsigned LEBs (call_indirect, memory.copy/init).
    Idx2,
    /// A block type: a single signed LEB.
    Block,
    /// align + offset (memory access).
    MemArg,
    /// Signed LEB constant.
    I32,
    I64,
    /// Fixed-width float constant.
    F32,
    F64,
    /// br_table: a vector of label indices plus a default.
    BrTable,
}

fn opcode(op: u8) -> Option<(&'static str, Imm, Flow)> {
    use Flow::*;
    use Imm::*;
    Some(match op {
        0x00 => ("unreachable", None, Flow::Seq),
        0x01 => ("nop", None, Flow::Seq),
        0x02 => ("block", Block, Flow::Seq),
        0x03 => ("loop", Block, Flow::Seq),
        0x04 => ("if", Block, CondJump),
        0x05 => ("else", Imm::None, Jump),
        0x0b => ("end", Imm::None, Flow::Seq),
        0x0c => ("br", Idx, Jump),
        0x0d => ("br_if", Idx, CondJump),
        0x0e => ("br_table", BrTable, Jump),
        0x0f => ("return", Imm::None, Ret),
        0x10 => ("call", Idx, Call),
        0x11 => ("call_indirect", Idx2, Call),
        0x1a => ("drop", Imm::None, Flow::Seq),
        0x1b => ("select", Imm::None, Flow::Seq),
        0x20 => ("local.get", Idx, Flow::Seq),
        0x21 => ("local.set", Idx, Flow::Seq),
        0x22 => ("local.tee", Idx, Flow::Seq),
        0x23 => ("global.get", Idx, Flow::Seq),
        0x24 => ("global.set", Idx, Flow::Seq),
        0x28 => ("i32.load", MemArg, Flow::Seq),
        0x29 => ("i64.load", MemArg, Flow::Seq),
        0x2a => ("f32.load", MemArg, Flow::Seq),
        0x2b => ("f64.load", MemArg, Flow::Seq),
        0x2c => ("i32.load8_s", MemArg, Flow::Seq),
        0x2d => ("i32.load8_u", MemArg, Flow::Seq),
        0x2e => ("i32.load16_s", MemArg, Flow::Seq),
        0x2f => ("i32.load16_u", MemArg, Flow::Seq),
        0x30 => ("i64.load8_s", MemArg, Flow::Seq),
        0x31 => ("i64.load8_u", MemArg, Flow::Seq),
        0x32 => ("i64.load16_s", MemArg, Flow::Seq),
        0x33 => ("i64.load16_u", MemArg, Flow::Seq),
        0x34 => ("i64.load32_s", MemArg, Flow::Seq),
        0x35 => ("i64.load32_u", MemArg, Flow::Seq),
        0x36 => ("i32.store", MemArg, Flow::Seq),
        0x37 => ("i64.store", MemArg, Flow::Seq),
        0x38 => ("f32.store", MemArg, Flow::Seq),
        0x39 => ("f64.store", MemArg, Flow::Seq),
        0x3a => ("i32.store8", MemArg, Flow::Seq),
        0x3b => ("i32.store16", MemArg, Flow::Seq),
        0x3c => ("i64.store8", MemArg, Flow::Seq),
        0x3d => ("i64.store16", MemArg, Flow::Seq),
        0x3e => ("i64.store32", MemArg, Flow::Seq),
        0x3f => ("memory.size", Idx, Flow::Seq),
        0x40 => ("memory.grow", Idx, Flow::Seq),
        0x41 => ("i32.const", I32, Flow::Seq),
        0x42 => ("i64.const", I64, Flow::Seq),
        0x43 => ("f32.const", F32, Flow::Seq),
        0x44 => ("f64.const", F64, Flow::Seq),
        _ => return numeric(op).map(|n| (n, Imm::None, Flow::Seq)),
    })
}

/// The dense block of stack-only numeric/comparison operators (0x45..=0xC4).
fn numeric(op: u8) -> Option<&'static str> {
    const TABLE: &[(u8, &str)] = &[
        (0x45, "i32.eqz"), (0x46, "i32.eq"), (0x47, "i32.ne"),
        (0x48, "i32.lt_s"), (0x49, "i32.lt_u"), (0x4a, "i32.gt_s"), (0x4b, "i32.gt_u"),
        (0x4c, "i32.le_s"), (0x4d, "i32.le_u"), (0x4e, "i32.ge_s"), (0x4f, "i32.ge_u"),
        (0x50, "i64.eqz"), (0x51, "i64.eq"), (0x52, "i64.ne"),
        (0x53, "i64.lt_s"), (0x54, "i64.lt_u"), (0x55, "i64.gt_s"), (0x56, "i64.gt_u"),
        (0x57, "i64.le_s"), (0x58, "i64.le_u"), (0x59, "i64.ge_s"), (0x5a, "i64.ge_u"),
        (0x5b, "f32.eq"), (0x5c, "f32.ne"), (0x5d, "f32.lt"), (0x5e, "f32.gt"),
        (0x5f, "f32.le"), (0x60, "f32.ge"),
        (0x61, "f64.eq"), (0x62, "f64.ne"), (0x63, "f64.lt"), (0x64, "f64.gt"),
        (0x65, "f64.le"), (0x66, "f64.ge"),
        (0x67, "i32.clz"), (0x68, "i32.ctz"), (0x69, "i32.popcnt"),
        (0x6a, "i32.add"), (0x6b, "i32.sub"), (0x6c, "i32.mul"),
        (0x6d, "i32.div_s"), (0x6e, "i32.div_u"), (0x6f, "i32.rem_s"), (0x70, "i32.rem_u"),
        (0x71, "i32.and"), (0x72, "i32.or"), (0x73, "i32.xor"),
        (0x74, "i32.shl"), (0x75, "i32.shr_s"), (0x76, "i32.shr_u"),
        (0x77, "i32.rotl"), (0x78, "i32.rotr"),
        (0x79, "i64.clz"), (0x7a, "i64.ctz"), (0x7b, "i64.popcnt"),
        (0x7c, "i64.add"), (0x7d, "i64.sub"), (0x7e, "i64.mul"),
        (0x7f, "i64.div_s"), (0x80, "i64.div_u"), (0x81, "i64.rem_s"), (0x82, "i64.rem_u"),
        (0x83, "i64.and"), (0x84, "i64.or"), (0x85, "i64.xor"),
        (0x86, "i64.shl"), (0x87, "i64.shr_s"), (0x88, "i64.shr_u"),
        (0x89, "i64.rotl"), (0x8a, "i64.rotr"),
        (0x8b, "f32.abs"), (0x8c, "f32.neg"), (0x8d, "f32.ceil"), (0x8e, "f32.floor"),
        (0x8f, "f32.trunc"), (0x90, "f32.nearest"), (0x91, "f32.sqrt"),
        (0x92, "f32.add"), (0x93, "f32.sub"), (0x94, "f32.mul"), (0x95, "f32.div"),
        (0x96, "f32.min"), (0x97, "f32.max"), (0x98, "f32.copysign"),
        (0x99, "f64.abs"), (0x9a, "f64.neg"), (0x9b, "f64.ceil"), (0x9c, "f64.floor"),
        (0x9d, "f64.trunc"), (0x9e, "f64.nearest"), (0x9f, "f64.sqrt"),
        (0xa0, "f64.add"), (0xa1, "f64.sub"), (0xa2, "f64.mul"), (0xa3, "f64.div"),
        (0xa4, "f64.min"), (0xa5, "f64.max"), (0xa6, "f64.copysign"),
        (0xa7, "i32.wrap_i64"),
        (0xa8, "i32.trunc_f32_s"), (0xa9, "i32.trunc_f32_u"),
        (0xaa, "i32.trunc_f64_s"), (0xab, "i32.trunc_f64_u"),
        (0xac, "i64.extend_i32_s"), (0xad, "i64.extend_i32_u"),
        (0xae, "i64.trunc_f32_s"), (0xaf, "i64.trunc_f32_u"),
        (0xb0, "i64.trunc_f64_s"), (0xb1, "i64.trunc_f64_u"),
        (0xb2, "f32.convert_i32_s"), (0xb3, "f32.convert_i32_u"),
        (0xb4, "f32.convert_i64_s"), (0xb5, "f32.convert_i64_u"),
        (0xb6, "f32.demote_f64"),
        (0xb7, "f64.convert_i32_s"), (0xb8, "f64.convert_i32_u"),
        (0xb9, "f64.convert_i64_s"), (0xba, "f64.convert_i64_u"),
        (0xbb, "f64.promote_f32"),
        (0xbc, "i32.reinterpret_f32"), (0xbd, "i64.reinterpret_f64"),
        (0xbe, "f32.reinterpret_i32"), (0xbf, "f64.reinterpret_i64"),
        (0xc0, "i32.extend8_s"), (0xc1, "i32.extend16_s"),
        (0xc2, "i64.extend8_s"), (0xc3, "i64.extend16_s"), (0xc4, "i64.extend32_s"),
    ];
    TABLE.iter().find(|(o, _)| *o == op).map(|(_, n)| *n)
}

/// The `0xFC` prefix space (saturating truncation, bulk memory).
fn prefixed_fc(sub: u32) -> (&'static str, Imm) {
    match sub {
        0 => ("i32.trunc_sat_f32_s", Imm::None),
        1 => ("i32.trunc_sat_f32_u", Imm::None),
        2 => ("i32.trunc_sat_f64_s", Imm::None),
        3 => ("i32.trunc_sat_f64_u", Imm::None),
        4 => ("i64.trunc_sat_f32_s", Imm::None),
        5 => ("i64.trunc_sat_f32_u", Imm::None),
        6 => ("i64.trunc_sat_f64_s", Imm::None),
        7 => ("i64.trunc_sat_f64_u", Imm::None),
        8 => ("memory.init", Imm::Idx2),
        9 => ("data.drop", Imm::Idx),
        10 => ("memory.copy", Imm::Idx2),
        11 => ("memory.fill", Imm::Idx),
        12 => ("table.init", Imm::Idx2),
        13 => ("elem.drop", Imm::Idx),
        14 => ("table.copy", Imm::Idx2),
        _ => ("fc.unknown", Imm::None),
    }
}

fn tok(text: &str, kind: TokenKind) -> Token {
    (text.to_string(), kind)
}

/// Decode up to `max` instructions from `data`, which must start at an
/// instruction boundary.
pub fn decode(data: &[u8], base_off: u64, base_va: u64, max: usize) -> Vec<Insn> {
    let mut out = Vec::new();
    let mut at = 0usize;

    while out.len() < max && at < data.len() {
        let op = data[at];
        let start = at;
        let mut text = String::new();
        let mut tokens: Vec<Token> = Vec::new();
        let mut n = 1usize;

        let (name, imm, fl) = if op == 0xfc || op == 0xfd {
            // Prefixed opcode: the sub-opcode is a ULEB.
            match uleb(data, at + 1) {
                Some((sub, used)) => {
                    n += used;
                    if op == 0xfc {
                        let (nm, im) = prefixed_fc(sub as u32);
                        (nm, im, Flow::Seq)
                    } else {
                        // SIMD (0xFD) is named but its operands are not decoded.
                        ("v128.op", Imm::None, Flow::Seq)
                    }
                }
                None => break,
            }
        } else {
            match opcode(op) {
                Some(t) => t,
                None => {
                    // Unknown opcode: emit one byte so the view keeps advancing
                    // rather than silently stopping mid-function.
                    out.push(Insn {
                        offset: base_off + start as u64,
                        va: base_va + start as u64,
                        len: 1,
                        bytes: vec![op],
                        text: format!("db {op:#04x}"),
                        tokens: vec![tok("db", TokenKind::Mnemonic), tok(" ", TokenKind::Text),
                                     tok(&format!("{op:#04x}"), TokenKind::Number)],
                        target: None,
                        flow: Flow::Seq,
                    });
                    at += 1;
                    continue;
                }
            }
        };
        let flow = fl;
        text.push_str(name);
        tokens.push(tok(name, TokenKind::Mnemonic));

        // Decode the immediate operands.
        let push_num = |tokens: &mut Vec<Token>, text: &mut String, s: String| {
            text.push(' ');
            text.push_str(&s);
            tokens.push(tok(" ", TokenKind::Text));
            tokens.push(tok(&s, TokenKind::Number));
        };

        let ok = match imm {
            Imm::None => true,
            Imm::Idx => match uleb(data, at + n) {
                Some((v, used)) => {
                    n += used;
                    push_num(&mut tokens, &mut text, v.to_string());
                    true
                }
                None => false,
            },
            Imm::Idx2 => {
                let mut good = true;
                for _ in 0..2 {
                    match uleb(data, at + n) {
                        Some((v, used)) => {
                            n += used;
                            push_num(&mut tokens, &mut text, v.to_string());
                        }
                        None => {
                            good = false;
                            break;
                        }
                    }
                }
                good
            }
            Imm::Block => match sleb(data, at + n) {
                Some((v, used)) => {
                    n += used;
                    let s = match v {
                        -64 => "".to_string(), // 0x40: empty block type
                        -1 => " (i32)".to_string(),
                        -2 => " (i64)".to_string(),
                        -3 => " (f32)".to_string(),
                        -4 => " (f64)".to_string(),
                        other => format!(" type[{other}]"),
                    };
                    if !s.is_empty() {
                        text.push_str(&s);
                        tokens.push(tok(&s, TokenKind::Text));
                    }
                    true
                }
                None => false,
            },
            Imm::MemArg => {
                match (uleb(data, at + n), None::<()>) {
                    (Some((align, u1)), _) => {
                        n += u1;
                        match uleb(data, at + n) {
                            Some((offset, u2)) => {
                                n += u2;
                                let s = format!("align={} offset={offset:#x}", 1u64 << align.min(63));
                                text.push(' ');
                                text.push_str(&s);
                                tokens.push(tok(" ", TokenKind::Text));
                                tokens.push(tok(&s, TokenKind::Number));
                                true
                            }
                            None => false,
                        }
                    }
                    _ => false,
                }
            }
            Imm::I32 | Imm::I64 => match sleb(data, at + n) {
                Some((v, used)) => {
                    n += used;
                    push_num(&mut tokens, &mut text, format!("{v}"));
                    true
                }
                None => false,
            },
            Imm::F32 => match data.get(at + n..at + n + 4) {
                Some(b) => {
                    let v = f32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                    n += 4;
                    push_num(&mut tokens, &mut text, format!("{v}"));
                    true
                }
                None => false,
            },
            Imm::F64 => match data.get(at + n..at + n + 8) {
                Some(b) => {
                    let v = f64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                    n += 8;
                    push_num(&mut tokens, &mut text, format!("{v}"));
                    true
                }
                None => false,
            },
            Imm::BrTable => match uleb(data, at + n) {
                Some((count, used)) => {
                    n += used;
                    let mut good = true;
                    // count targets, then the default label.
                    for _ in 0..count.saturating_add(1).min(4096) {
                        match uleb(data, at + n) {
                            Some((_, u)) => n += u,
                            None => {
                                good = false;
                                break;
                            }
                        }
                    }
                    if good {
                        push_num(&mut tokens, &mut text, format!("[{count} targets]"));
                    }
                    good
                }
                None => false,
            },
        };

        if !ok || at + n > data.len() {
            // Truncated immediate: stop rather than invent bytes.
            break;
        }

        out.push(Insn {
            offset: base_off + start as u64,
            va: base_va + start as u64,
            len: n,
            bytes: data[start..start + n].to_vec(),
            text,
            tokens,
            target: None,
            flow,
        });
        at += n;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128_unsigned_and_signed() {
        assert_eq!(uleb(&[0x00], 0), Some((0, 1)));
        assert_eq!(uleb(&[0x7f], 0), Some((127, 1)));
        assert_eq!(uleb(&[0x80, 0x01], 0), Some((128, 2)));
        assert_eq!(uleb(&[0xe5, 0x8e, 0x26], 0), Some((624485, 3)));
        assert_eq!(sleb(&[0x7f], 0), Some((-1, 1)));
        assert_eq!(sleb(&[0x3f], 0), Some((63, 1)));
        assert_eq!(sleb(&[0x40], 0), Some((-64, 1)));
        // Truncated input must not panic or loop forever.
        assert_eq!(uleb(&[0x80], 0), None);
        assert_eq!(uleb(&[0x80; 12], 0), None);
    }

    #[test]
    fn decodes_simple_function_body() {
        // local.get 0; local.get 1; i32.add; end
        let data = [0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b];
        let ins = decode(&data, 0, 0, 16);
        assert_eq!(ins.len(), 4);
        assert_eq!(ins[0].text, "local.get 0");
        assert_eq!(ins[1].text, "local.get 1");
        assert_eq!(ins[2].text, "i32.add");
        assert_eq!(ins[3].text, "end");
        assert_eq!(ins.iter().map(|i| i.len).sum::<usize>(), data.len());
    }

    #[test]
    fn decodes_constants() {
        // i32.const -1 ; i64.const 128
        let ins = decode(&[0x41, 0x7f, 0x42, 0x80, 0x01], 0, 0, 8);
        assert_eq!(ins[0].text, "i32.const -1");
        assert_eq!(ins[1].text, "i64.const 128");
    }

    #[test]
    fn decodes_memarg_and_call() {
        // i32.load align=4 offset=0x10 ; call 3
        let ins = decode(&[0x28, 0x02, 0x10, 0x10, 0x03], 0, 0, 8);
        assert!(ins[0].text.contains("i32.load"));
        assert!(ins[0].text.contains("align=4"));
        assert!(ins[0].text.contains("offset=0x10"));
        assert_eq!(ins[1].text, "call 3");
        assert_eq!(ins[1].flow, Flow::Call);
    }

    #[test]
    fn control_flow_is_classified() {
        let ins = decode(&[0x0f], 0, 0, 1); // return
        assert_eq!(ins[0].flow, Flow::Ret);
        let ins = decode(&[0x0d, 0x00], 0, 0, 1); // br_if 0
        assert_eq!(ins[0].flow, Flow::CondJump);
        let ins = decode(&[0x0c, 0x00], 0, 0, 1); // br 0
        assert_eq!(ins[0].flow, Flow::Jump);
    }

    #[test]
    fn block_types_are_named() {
        // block (empty) — 0x02 0x40
        let ins = decode(&[0x02, 0x40], 0, 0, 1);
        assert_eq!(ins[0].text, "block");
        assert_eq!(ins[0].len, 2);
        // block (i32) — 0x02 0x7f
        let ins = decode(&[0x02, 0x7f], 0, 0, 1);
        assert!(ins[0].text.contains("i32"), "{}", ins[0].text);
    }

    #[test]
    fn saturating_conversions_via_fc_prefix() {
        let ins = decode(&[0xfc, 0x00], 0, 0, 1);
        assert_eq!(ins[0].text, "i32.trunc_sat_f32_s");
        assert_eq!(ins[0].len, 2);
    }

    #[test]
    fn unknown_opcode_emits_a_byte_and_keeps_going() {
        // 0x06 is not a valid opcode; decoding must not stall.
        let ins = decode(&[0x06, 0x01], 0, 0, 4);
        assert_eq!(ins.len(), 2);
        assert!(ins[0].text.starts_with("db "));
        assert_eq!(ins[1].text, "nop");
    }

    #[test]
    fn truncated_immediate_stops_cleanly() {
        // i32.const with a LEB that never terminates.
        let ins = decode(&[0x41, 0x80], 0, 0, 4);
        assert!(ins.is_empty(), "{ins:?}");
    }

    #[test]
    fn offsets_and_vas_advance_correctly() {
        let ins = decode(&[0x20, 0x00, 0x6a], 0x100, 0x2000, 8);
        assert_eq!((ins[0].offset, ins[0].va), (0x100, 0x2000));
        assert_eq!((ins[1].offset, ins[1].va), (0x102, 0x2002));
    }

    #[test]
    fn hostile_input_does_not_panic() {
        for b in 0u16..=255 {
            let byte = b as u8;
            let _ = decode(&[byte], 0, 0, 4);
            let _ = decode(&[byte, 0xff, 0xff, 0xff, 0xff], 0, 0, 4);
        }
        let _ = decode(&[0xff; 64], 0, 0, 64);
        let _ = decode(&[], 0, 0, 4);
    }
}
