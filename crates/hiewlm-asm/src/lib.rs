//! Disassembly. x86/x86-64 use iced-x86 (pure Rust, with branch-target
//! resolution); ARM/ARM64/MIPS/RISC-V/PowerPC/SPARC use Capstone. Decoding only turns bytes
//! into text — it never executes them (design §22.1).

pub mod asm_text;
pub mod wasm;

pub use asm_text::{assemble, assemble_into, AsmError};

use hiewlm_core::Arch;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, FormatterOutput, FormatterTextKind,
    Instruction, NasmFormatter, OpKind,
};

/// Syntax class of a piece of instruction text, for coloring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Mnemonic,
    Register,
    Number,
    Punct,
    Text,
}

/// One display token: a run of text with a single syntax class.
pub type Token = (String, TokenKind);

/// Control-flow class of an instruction, for recursive-traversal analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Seq,
    Call,
    Jump,
    CondJump,
    Ret,
}

/// One decoded instruction.
#[derive(Debug, Clone)]
pub struct Insn {
    /// File offset of the instruction's first byte.
    pub offset: u64,
    /// Virtual address of the instruction.
    pub va: u64,
    pub len: usize,
    pub bytes: Vec<u8>,
    pub text: String,
    /// The instruction text split into colored tokens.
    pub tokens: Vec<Token>,
    /// Branch/call target VA, if this is a direct near branch/call (x86 only for now).
    pub target: Option<u64>,
    pub flow: Flow,
}

/// Multi-architecture disassembler.
#[derive(Debug, Clone, Copy)]
pub struct Disassembler {
    arch: Arch,
    bits: u8,
}

impl Disassembler {
    pub fn new(arch: Arch, bits: u8) -> Self {
        Self { arch, bits }
    }

    pub fn supports(arch: Arch) -> bool {
        matches!(
            arch,
            Arch::X86
                | Arch::X86_64
                | Arch::Arm
                | Arch::Arm64
                | Arch::Mips
                | Arch::Riscv
                | Arch::Ppc
                | Arch::Sparc
                | Arch::Wasm
                | Arch::Unknown
        )
    }

    /// Decode up to `max` instructions from `data`, whose first byte is at file
    /// offset `base_off` and virtual address `base_va`.
    pub fn decode(&self, data: &[u8], base_off: u64, base_va: u64, max: usize) -> Vec<Insn> {
        match self.arch {
            Arch::X86 | Arch::X86_64 | Arch::Unknown => self.decode_x86(data, base_off, base_va, max),
            // WASM is a stack machine, not a capstone target: own decoder.
            Arch::Wasm => wasm::decode(data, base_off, base_va, max),
            _ => self.decode_capstone(data, base_off, base_va, max),
        }
    }

    fn decode_x86(&self, data: &[u8], base_off: u64, base_va: u64, max: usize) -> Vec<Insn> {
        let bitness = match self.bits {
            16 => 16,
            32 => 32,
            _ => 64,
        };
        let mut decoder = Decoder::with_ip(bitness, data, base_va, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        let mut instr = Instruction::default();
        let mut out = Vec::with_capacity(max);

        while decoder.can_decode() && out.len() < max {
            let pos = decoder.position();
            decoder.decode_out(&mut instr);
            let len = instr.len();
            if len == 0 || pos + len > data.len() {
                break;
            }
            let mut sink = TokenSink::default();
            formatter.format(&instr, &mut sink);
            let text: String = sink.tokens.iter().map(|(t, _)| t.as_str()).collect();
            out.push(Insn {
                offset: base_off + pos as u64,
                va: instr.ip(),
                len,
                bytes: data[pos..pos + len].to_vec(),
                text,
                tokens: sink.tokens,
                target: branch_target(&instr),
                flow: flow_of(&instr),
            });
        }
        out
    }

    fn decode_capstone(&self, data: &[u8], base_off: u64, base_va: u64, max: usize) -> Vec<Insn> {
        let Some(cs) = build_capstone(self.arch, self.bits) else {
            return Vec::new();
        };
        let Ok(insns) = cs.disasm_count(data, base_va, max) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(insns.len());
        for i in insns.iter() {
            let addr = i.address();
            let bytes = i.bytes().to_vec();
            let mnem = i.mnemonic().unwrap_or("(bad)");
            let op = i.op_str().unwrap_or("");
            let text = if op.is_empty() { mnem.to_string() } else { format!("{mnem} {op}") };
            out.push(Insn {
                offset: base_off + addr.saturating_sub(base_va),
                va: addr,
                len: bytes.len(),
                bytes,
                text,
                tokens: tokenize_heuristic(mnem, op),
                target: None,
                flow: Flow::Seq,
            });
        }
        out
    }
}

fn build_capstone(arch: Arch, bits: u8) -> Option<capstone::Capstone> {
    use capstone::arch::{arm, arm64, mips, ppc, riscv, sparc, BuildsCapstone, BuildsCapstoneEndian};
    use capstone::{Capstone, Endian};

    match arch {
        Arch::Arm64 => Capstone::new().arm64().mode(arm64::ArchMode::Arm).build().ok(),
        Arch::Arm => Capstone::new().arm().mode(arm::ArchMode::Arm).build().ok(),
        Arch::Mips => {
            let mode = if bits == 64 { mips::ArchMode::Mips64 } else { mips::ArchMode::Mips32 };
            Capstone::new().mips().mode(mode).endian(Endian::Little).build().ok()
        }
        Arch::Riscv => {
            let mode = if bits == 64 { riscv::ArchMode::RiscV64 } else { riscv::ArchMode::RiscV32 };
            Capstone::new().riscv().mode(mode).build().ok()
        }
        // PowerPC is big-endian in every deployment hiewLM sees; capstone's
        // SPARC backend is big-endian only and takes no endian setter.
        Arch::Ppc => {
            let mode = if bits == 64 { ppc::ArchMode::Mode64 } else { ppc::ArchMode::Mode32 };
            Capstone::new().ppc().mode(mode).endian(Endian::Big).build().ok()
        }
        Arch::Sparc => Capstone::new().sparc().mode(sparc::ArchMode::Default).build().ok(),
        _ => None,
    }
}

/// Captures iced-x86's formatter output as colored tokens (accurate token kinds).
#[derive(Default)]
struct TokenSink {
    tokens: Vec<Token>,
}

impl FormatterOutput for TokenSink {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let tk = match kind {
            FormatterTextKind::Mnemonic | FormatterTextKind::Keyword | FormatterTextKind::Prefix
            | FormatterTextKind::Directive => TokenKind::Mnemonic,
            FormatterTextKind::Register => TokenKind::Register,
            FormatterTextKind::Number
            | FormatterTextKind::LabelAddress
            | FormatterTextKind::FunctionAddress => TokenKind::Number,
            FormatterTextKind::Punctuation | FormatterTextKind::Operator => TokenKind::Punct,
            _ => TokenKind::Text,
        };
        self.tokens.push((text.to_string(), tk));
    }
}

/// Heuristic tokenizer for Capstone output (no token-kind metadata available).
fn tokenize_heuristic(mnemonic: &str, op_str: &str) -> Vec<Token> {
    let mut tokens: Vec<Token> = vec![(mnemonic.to_string(), TokenKind::Mnemonic)];
    if op_str.is_empty() {
        return tokens;
    }
    tokens.push((" ".to_string(), TokenKind::Text));
    let mut word = String::new();
    let flush = |word: &mut String, tokens: &mut Vec<Token>| {
        if word.is_empty() {
            return;
        }
        let kind = classify_word(word);
        tokens.push((std::mem::take(word), kind));
    };
    for c in op_str.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '#' || c == '.' || c == '$' {
            word.push(c);
        } else {
            flush(&mut word, &mut tokens);
            tokens.push((c.to_string(), TokenKind::Punct));
        }
    }
    flush(&mut word, &mut tokens);
    tokens
}

fn classify_word(w: &str) -> TokenKind {
    let first = w.chars().next().unwrap_or(' ');
    if first == '#' || w.starts_with("0x") || first.is_ascii_digit() {
        TokenKind::Number
    } else if first.is_ascii_alphabetic() {
        TokenKind::Register
    } else {
        TokenKind::Text
    }
}

fn flow_of(instr: &Instruction) -> Flow {
    match instr.flow_control() {
        FlowControl::Call | FlowControl::IndirectCall => Flow::Call,
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => Flow::Jump,
        FlowControl::ConditionalBranch => Flow::CondJump,
        FlowControl::Return => Flow::Ret,
        _ => Flow::Seq,
    }
}

fn branch_target(instr: &Instruction) -> Option<u64> {
    let is_branch = matches!(
        instr.flow_control(),
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Call
    );
    if !is_branch {
        return None;
    }
    match instr.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instr.near_branch_target())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_basic_x64() {
        let data = [0x55, 0x48, 0x89, 0xe5, 0xc3];
        let dis = Disassembler::new(Arch::X86_64, 64);
        let insns = dis.decode(&data, 0x1000, 0x401000, 16);
        assert_eq!(insns.len(), 3);
        assert!(insns[0].text.contains("push"));
        assert!(insns[1].text.contains("mov"));
        assert!(insns[2].text.contains("ret"));
    }

    #[test]
    fn resolves_call_target() {
        let data = [0xe8, 0x06, 0x00, 0x00, 0x00];
        let dis = Disassembler::new(Arch::X86_64, 64);
        let insns = dis.decode(&data, 0, 0x1000, 1);
        assert_eq!(insns[0].target, Some(0x100b));
    }

    #[test]
    fn x86_tokens_have_kinds() {
        let data = [0x48, 0x89, 0xe5]; // mov rbp, rsp
        let dis = Disassembler::new(Arch::X86_64, 64);
        let ins = &dis.decode(&data, 0, 0x1000, 1)[0];
        assert!(ins.tokens.iter().any(|(t, k)| *k == TokenKind::Mnemonic && t.contains("mov")));
        assert!(ins.tokens.iter().any(|(_, k)| *k == TokenKind::Register));
    }

    #[test]
    fn powerpc_decodes() {
        // 38 60 00 01  li r3, 1   |  4e 80 00 20  blr
        let d = Disassembler::new(Arch::Ppc, 32);
        let insns = d.decode(&[0x38, 0x60, 0x00, 0x01, 0x4e, 0x80, 0x00, 0x20], 0, 0, 2);
        assert_eq!(insns.len(), 2, "{insns:?}");
        assert!(insns[0].text.contains("li"), "{}", insns[0].text);
        assert!(insns[1].text.contains("blr"), "{}", insns[1].text);
    }

    #[test]
    fn sparc_decodes() {
        // 81 c3 e0 08  retl  |  90 10 20 00  clr %o0
        let d = Disassembler::new(Arch::Sparc, 32);
        let insns = d.decode(&[0x81, 0xc3, 0xe0, 0x08, 0x90, 0x10, 0x20, 0x00], 0, 0, 2);
        assert_eq!(insns.len(), 2, "{insns:?}");
        assert!(insns[0].text.contains("retl"), "{}", insns[0].text);
    }

    #[test]
    fn capstone_tokens_present() {
        let data = [0xfd, 0x7b, 0xbf, 0xa9]; // stp x29, x30, [sp, #-16]!
        let dis = Disassembler::new(Arch::Arm64, 64);
        let ins = &dis.decode(&data, 0, 0x1000, 1)[0];
        assert!(ins.tokens.iter().any(|(_, k)| *k == TokenKind::Mnemonic));
        assert!(ins.tokens.iter().any(|(_, k)| *k == TokenKind::Register));
    }

    #[test]
    fn decodes_arm64_via_capstone() {
        // ret (aarch64): c0 03 5f d6
        let data = [0xc0, 0x03, 0x5f, 0xd6];
        let dis = Disassembler::new(Arch::Arm64, 64);
        let insns = dis.decode(&data, 0, 0x1000, 4);
        assert_eq!(insns.len(), 1);
        assert!(insns[0].text.contains("ret"), "got: {}", insns[0].text);
    }
}
