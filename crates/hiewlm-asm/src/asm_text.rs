//! Text assembler for x86/x86-64 — HIEW's assemble-at-cursor (`F7` in its
//! Code mode): type `xor eax, eax` and get the encoded bytes.
//!
//! Built on `iced-x86`'s `CodeAssembler`, which picks the shortest valid
//! encoding, so the caller only has to parse operands. This is pure encoding:
//! text in, bytes out. Nothing is executed, and the caller decides whether the
//! result is written to the file.
//!
//! Coverage is the patching subset an analyst actually types — data movement,
//! arithmetic/logic, stack, branches and the common zero-operand instructions.
//! Anything outside it returns [`AsmError::Unsupported`] rather than guessing.

use iced_x86::code_asm::{
    byte_ptr, dword_ptr, gpr16, gpr32, gpr64, gpr8, ptr, qword_ptr, word_ptr, AsmMemoryOperand,
    AsmRegister16, AsmRegister32, AsmRegister64, AsmRegister8, CodeAssembler,
};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum AsmError {
    Empty,
    /// The mnemonic is not in the supported subset.
    Unsupported(String),
    /// The mnemonic is known but not with these operand kinds.
    BadOperands(String),
    Parse(String),
    /// iced rejected the instruction (invalid encoding for this bitness).
    Encode(String),
    /// Encoded fine, but does not fit the space the caller allowed.
    TooLong { got: usize, max: usize },
    /// A branch target too far away to encode as a direct relative branch.
    /// Reported rather than silently expanded into an indirect trampoline.
    BranchOutOfRange { target: u64, rip: u64 },
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsmError::Empty => write!(f, "empty instruction"),
            AsmError::Unsupported(m) => write!(f, "unsupported mnemonic '{m}'"),
            AsmError::BadOperands(m) => write!(f, "bad operands for '{m}'"),
            AsmError::Parse(s) => write!(f, "cannot parse '{s}'"),
            AsmError::Encode(e) => write!(f, "encode failed: {e}"),
            AsmError::TooLong { got, max } => {
                write!(f, "encodes to {got} bytes, only {max} available")
            }
            AsmError::BranchOutOfRange { target, rip } => write!(
                f,
                "branch target {target:#x} is out of range from {rip:#x} (max ±2GB)"
            ),
        }
    }
}

impl std::error::Error for AsmError {}

/// A parsed operand.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    R8(AsmRegister8),
    R16(AsmRegister16),
    R32(AsmRegister32),
    R64(AsmRegister64),
    Imm(i64),
    Mem(AsmMemoryOperand),
}

fn reg8(n: &str) -> Option<AsmRegister8> {
    use gpr8::*;
    Some(match n {
        "al" => al, "bl" => bl, "cl" => cl, "dl" => dl,
        "ah" => ah, "bh" => bh, "ch" => ch, "dh" => dh,
        "sil" => sil, "dil" => dil, "bpl" => bpl, "spl" => spl,
        "r8b" => r8b, "r9b" => r9b, "r10b" => r10b, "r11b" => r11b,
        "r12b" => r12b, "r13b" => r13b, "r14b" => r14b, "r15b" => r15b,
        _ => return None,
    })
}

fn reg16(n: &str) -> Option<AsmRegister16> {
    use gpr16::*;
    Some(match n {
        "ax" => ax, "bx" => bx, "cx" => cx, "dx" => dx,
        "si" => si, "di" => di, "bp" => bp, "sp" => sp,
        "r8w" => r8w, "r9w" => r9w, "r10w" => r10w, "r11w" => r11w,
        "r12w" => r12w, "r13w" => r13w, "r14w" => r14w, "r15w" => r15w,
        _ => return None,
    })
}

fn reg32(n: &str) -> Option<AsmRegister32> {
    use gpr32::*;
    Some(match n {
        "eax" => eax, "ebx" => ebx, "ecx" => ecx, "edx" => edx,
        "esi" => esi, "edi" => edi, "ebp" => ebp, "esp" => esp,
        "r8d" => r8d, "r9d" => r9d, "r10d" => r10d, "r11d" => r11d,
        "r12d" => r12d, "r13d" => r13d, "r14d" => r14d, "r15d" => r15d,
        _ => return None,
    })
}

fn reg64(n: &str) -> Option<AsmRegister64> {
    use gpr64::*;
    Some(match n {
        "rax" => rax, "rbx" => rbx, "rcx" => rcx, "rdx" => rdx,
        "rsi" => rsi, "rdi" => rdi, "rbp" => rbp, "rsp" => rsp,
        "r8" => r8, "r9" => r9, "r10" => r10, "r11" => r11,
        "r12" => r12, "r13" => r13, "r14" => r14, "r15" => r15,
        _ => return None,
    })
}

/// Parse an integer: `0x`-prefixed or bare hex (HIEW's default base), decimal
/// with a `t` suffix, optional leading `-`.
fn number(s: &str) -> Option<i64> {
    let s = s.trim();
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r.trim()),
        None => (false, s),
    };
    // hiewLM writes virtual addresses as `.401000`; branch targets are already
    // absolute, so the marker only signals "hex" here.
    if let Some(va) = s.strip_prefix('.') {
        return i64::from_str_radix(va, 16).ok().map(|v| if neg { -v } else { v });
    }
    let v = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()?
    } else if let Some(d) = s.strip_suffix('t').or_else(|| s.strip_suffix('T')) {
        d.parse::<i64>().ok()?
    } else if let Some(h) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        i64::from_str_radix(h, 16).ok()?
    } else {
        // Bare token: hex if it looks like hex, else decimal.
        i64::from_str_radix(s, 16).ok().or_else(|| s.parse::<i64>().ok())?
    };
    Some(if neg { -v } else { v })
}

/// Parse `[base + index*scale + disp]`, with an optional `dword ptr` style
/// size prefix already stripped by the caller.
fn memory(inner: &str, size_bits: u32) -> Option<AsmMemoryOperand> {
    let body = inner.trim();
    let mut base: Option<AsmRegister64> = None;
    let mut base32: Option<AsmRegister32> = None;
    let mut index: Option<(AsmRegister64, u32)> = None;
    let mut disp: i64 = 0;

    // Split on +/- while keeping the sign with each term.
    let mut terms: Vec<(i64, String)> = Vec::new();
    let (mut sign, mut cur) = (1i64, String::new());
    for chr in body.chars() {
        match chr {
            '+' | '-' => {
                if !cur.trim().is_empty() {
                    terms.push((sign, cur.trim().to_string()));
                }
                cur.clear();
                sign = if chr == '-' { -1 } else { 1 };
            }
            other => cur.push(other),
        }
    }
    if !cur.trim().is_empty() {
        terms.push((sign, cur.trim().to_string()));
    }

    for (sgn, term) in terms {
        let t = term.to_ascii_lowercase();
        if let Some((r, sc)) = t.split_once('*') {
            let scale: u32 = sc.trim().parse().ok()?;
            if !matches!(scale, 1 | 2 | 4 | 8) {
                return None;
            }
            index = Some((reg64(r.trim())?, scale));
        } else if let Some(r) = reg64(&t) {
            if base.is_none() && index.is_none() {
                base = Some(r);
            } else if index.is_none() {
                index = Some((r, 1));
            } else {
                return None;
            }
        } else if let Some(r) = reg32(&t) {
            base32 = Some(r);
        } else {
            disp += sgn * number(&t)?;
        }
    }

    let mut m = match (base, base32) {
        (Some(b), _) => b + 0i64,
        (None, Some(b)) => b + 0i64,
        (None, None) => return None,
    };
    if let Some((ix, sc)) = index {
        m = m + ix * sc;
    }
    if disp != 0 {
        m = m + disp;
    }
    Some(match size_bits {
        8 => byte_ptr(m),
        16 => word_ptr(m),
        32 => dword_ptr(m),
        64 => qword_ptr(m),
        _ => ptr(m),
    })
}

fn operand(tok: &str) -> Result<Op, AsmError> {
    let t = tok.trim();
    let low = t.to_ascii_lowercase();
    if let Some(r) = reg64(&low) {
        return Ok(Op::R64(r));
    }
    if let Some(r) = reg32(&low) {
        return Ok(Op::R32(r));
    }
    if let Some(r) = reg16(&low) {
        return Ok(Op::R16(r));
    }
    if let Some(r) = reg8(&low) {
        return Ok(Op::R8(r));
    }

    // Optional size prefix: "dword ptr [..]", "byte [..]".
    let (size_bits, rest) = {
        let mut s = low.as_str();
        let mut bits = 0u32;
        for (kw, b) in [("byte", 8u32), ("word", 16), ("dword", 32), ("qword", 64)] {
            if let Some(r) = s.strip_prefix(kw) {
                bits = b;
                s = r.trim_start();
                break;
            }
        }
        (bits, s.strip_prefix("ptr").map(str::trim_start).unwrap_or(s))
    };
    if let Some(inner) = rest.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return memory(inner, size_bits).map(Op::Mem).ok_or_else(|| AsmError::Parse(t.into()));
    }
    number(&low).map(Op::Imm).ok_or_else(|| AsmError::Parse(t.into()))
}

/// `mov` is the one arith-shaped mnemonic whose 64-bit immediate form is
/// `i64` rather than a sign-extended `i32`.
macro_rules! mov_dispatch {
    ($a:ident, $dst:expr, $src:expr, $name:expr) => {
        match ($dst, $src) {
            (Op::R64(d), Op::Imm(i)) => $a.mov(d, i),
            (Op::R64(d), Op::R64(s)) => $a.mov(d, s),
            (Op::R64(d), Op::Mem(s)) => $a.mov(d, s),
            (Op::R32(d), Op::R32(s)) => $a.mov(d, s),
            (Op::R32(d), Op::Mem(s)) => $a.mov(d, s),
            (Op::R32(d), Op::Imm(i)) => $a.mov(d, i as i32),
            (Op::R16(d), Op::R16(s)) => $a.mov(d, s),
            (Op::R16(d), Op::Mem(s)) => $a.mov(d, s),
            (Op::R16(d), Op::Imm(i)) => $a.mov(d, i as i32),
            (Op::R8(d), Op::R8(s)) => $a.mov(d, s),
            (Op::R8(d), Op::Mem(s)) => $a.mov(d, s),
            (Op::R8(d), Op::Imm(i)) => $a.mov(d, i as i32),
            (Op::Mem(d), Op::R64(s)) => $a.mov(d, s),
            (Op::Mem(d), Op::R32(s)) => $a.mov(d, s),
            (Op::Mem(d), Op::R16(s)) => $a.mov(d, s),
            (Op::Mem(d), Op::R8(s)) => $a.mov(d, s),
            (Op::Mem(d), Op::Imm(i)) => $a.mov(d, i as i32),
            _ => return Err(AsmError::BadOperands($name.into())),
        }
    };
}

/// `test` and `xchg` have no register-destination/memory-source overload.
macro_rules! bin_no_mem_src {
    ($a:ident, $m:ident, $dst:expr, $src:expr, $name:expr, imm) => {
        match ($dst, $src) {
            (Op::R64(d), Op::R64(s)) => $a.$m(d, s),
            (Op::R32(d), Op::R32(s)) => $a.$m(d, s),
            (Op::R16(d), Op::R16(s)) => $a.$m(d, s),
            (Op::R8(d), Op::R8(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R64(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R32(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R16(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R8(s)) => $a.$m(d, s),
            (Op::R64(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::R32(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::R16(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::R8(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::Mem(d), Op::Imm(i)) => $a.$m(d, i as i32),
            _ => return Err(AsmError::BadOperands($name.into())),
        }
    };
    ($a:ident, $m:ident, $dst:expr, $src:expr, $name:expr, noimm) => {
        match ($dst, $src) {
            (Op::R64(d), Op::R64(s)) => $a.$m(d, s),
            (Op::R32(d), Op::R32(s)) => $a.$m(d, s),
            (Op::R16(d), Op::R16(s)) => $a.$m(d, s),
            (Op::R8(d), Op::R8(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R64(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R32(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R16(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R8(s)) => $a.$m(d, s),
            _ => return Err(AsmError::BadOperands($name.into())),
        }
    };
}

/// Shifts take an immediate or `cl` as the count.
macro_rules! shift {
    ($a:ident, $m:ident, $dst:expr, $src:expr, $name:expr) => {
        match ($dst, $src) {
            (Op::R64(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::R32(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::R16(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::R8(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::Mem(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::R64(d), Op::R8(s)) => $a.$m(d, s),
            (Op::R32(d), Op::R8(s)) => $a.$m(d, s),
            (Op::R16(d), Op::R8(s)) => $a.$m(d, s),
            (Op::R8(d), Op::R8(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R8(s)) => $a.$m(d, s),
            _ => return Err(AsmError::BadOperands($name.into())),
        }
    };
}

/// Dispatch a two-operand arithmetic/logic mnemonic across the operand-kind
/// combinations that `CodeAssembler` provides typed overloads for.
macro_rules! bin {
    ($a:ident, $m:ident, $dst:expr, $src:expr, $name:expr) => {
        match ($dst, $src) {
            (Op::R64(d), Op::R64(s)) => $a.$m(d, s),
            (Op::R64(d), Op::Mem(s)) => $a.$m(d, s),
            (Op::R64(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::R32(d), Op::R32(s)) => $a.$m(d, s),
            (Op::R32(d), Op::Mem(s)) => $a.$m(d, s),
            (Op::R32(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::R16(d), Op::R16(s)) => $a.$m(d, s),
            (Op::R16(d), Op::Mem(s)) => $a.$m(d, s),
            (Op::R16(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::R8(d), Op::R8(s)) => $a.$m(d, s),
            (Op::R8(d), Op::Mem(s)) => $a.$m(d, s),
            (Op::R8(d), Op::Imm(i)) => $a.$m(d, i as i32),
            (Op::Mem(d), Op::R64(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R32(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R16(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::R8(s)) => $a.$m(d, s),
            (Op::Mem(d), Op::Imm(i)) => $a.$m(d, i as i32),
            _ => return Err(AsmError::BadOperands($name.into())),
        }
    };
}

/// Dispatch a one-operand mnemonic (inc/dec/neg/not/push/pop/mul/div).
macro_rules! un {
    ($a:ident, $m:ident, $op:expr, $name:expr) => {
        match $op {
            Op::R64(r) => $a.$m(r),
            Op::R32(r) => $a.$m(r),
            Op::R16(r) => $a.$m(r),
            Op::R8(r) => $a.$m(r),
            Op::Mem(m) => $a.$m(m),
            _ => return Err(AsmError::BadOperands($name.into())),
        }
    };
}

/// Assemble one instruction at `rip` for `bits` (16/32/64), returning bytes.
///
/// `rip` matters for branches: `jmp 401000` is encoded relative to it.
pub fn assemble(text: &str, bits: u8, rip: u64) -> Result<Vec<u8>, AsmError> {
    let line = text.split(';').next().unwrap_or("").trim();
    if line.is_empty() {
        return Err(AsmError::Empty);
    }
    let (mnemonic, rest) = match line.split_once(char::is_whitespace) {
        Some((m, r)) => (m.to_ascii_lowercase(), r.trim()),
        None => (line.to_ascii_lowercase(), ""),
    };
    let ops: Vec<&str> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(',').map(str::trim).collect()
    };

    let bitness = match bits {
        16 => 16u32,
        32 => 32,
        _ => 64,
    };
    let mut a = CodeAssembler::new(bitness).map_err(|e| AsmError::Encode(e.to_string()))?;
    let m = mnemonic.as_str();

    let res: Result<(), iced_x86::IcedError> = match (m, ops.len()) {
        // ── zero operands ───────────────────────────────────────────
        ("nop", 0) => a.nop(),
        ("ret" | "retn", 0) => a.ret(),
        ("leave", 0) => a.leave(),
        ("int3", 0) => a.int3(),
        ("hlt", 0) => a.hlt(),
        ("cdq", 0) => a.cdq(),
        ("cqo", 0) => a.cqo(),
        ("cwd", 0) => a.cwd(),
        ("pushfq", 0) => a.pushfq(),
        ("popfq", 0) => a.popfq(),
        ("pushfd", 0) => a.pushfd(),
        ("popfd", 0) => a.popfd(),
        ("stc", 0) => a.stc(),
        ("clc", 0) => a.clc(),
        ("std", 0) => a.std(),
        ("cld", 0) => a.cld(),
        ("syscall", 0) => a.syscall(),
        ("ud2", 0) => a.ud2(),

        // ── one operand ─────────────────────────────────────────────
        ("ret" | "retn", 1) => match operand(ops[0])? {
            Op::Imm(i) => a.ret_1(i as i32),
            _ => return Err(AsmError::BadOperands(m.into())),
        },
        ("int", 1) => match operand(ops[0])? {
            Op::Imm(i) => a.int(i as i32),
            _ => return Err(AsmError::BadOperands(m.into())),
        },
        ("inc", 1) => un!(a, inc, operand(ops[0])?, m),
        ("dec", 1) => un!(a, dec, operand(ops[0])?, m),
        ("neg", 1) => un!(a, neg, operand(ops[0])?, m),
        ("not", 1) => un!(a, not, operand(ops[0])?, m),
        ("mul", 1) => un!(a, mul, operand(ops[0])?, m),
        ("div", 1) => un!(a, div, operand(ops[0])?, m),
        ("idiv", 1) => un!(a, idiv, operand(ops[0])?, m),
        ("push", 1) => match operand(ops[0])? {
            Op::R64(r) => a.push(r),
            Op::R32(r) => a.push(r),
            Op::R16(r) => a.push(r),
            Op::Mem(mm) => a.push(mm),
            Op::Imm(i) => a.push(i as i32),
            _ => return Err(AsmError::BadOperands(m.into())),
        },
        ("pop", 1) => match operand(ops[0])? {
            Op::R64(r) => a.pop(r),
            Op::R32(r) => a.pop(r),
            Op::R16(r) => a.pop(r),
            Op::Mem(mm) => a.pop(mm),
            _ => return Err(AsmError::BadOperands(m.into())),
        },

        // ── branches: absolute target in text, encoded relative ─────
        (
            "jmp" | "call" | "je" | "jz" | "jne" | "jnz" | "ja" | "jae" | "jb" | "jbe" | "jg"
            | "jge" | "jl" | "jle" | "js" | "jns" | "jo" | "jno" | "jc" | "jnc" | "jp" | "jnp"
            | "loop",
            1,
        ) => match operand(ops[0])? {
            Op::Imm(target) => {
                // iced would silently expand an unreachable branch into an
                // indirect trampoline plus a data slot. A patcher must never
                // get that by surprise, so refuse instead.
                let target = target as u64;
                let delta = (target as i64).wrapping_sub(rip as i64);
                if delta < i32::MIN as i64 || delta > i32::MAX as i64 {
                    return Err(AsmError::BranchOutOfRange { target, rip });
                }
                branch(&mut a, m, target)
            }
            // Indirect forms: `jmp rax`, `call qword ptr [rax]`.
            Op::R64(r) if m == "jmp" => a.jmp(r),
            Op::R64(r) if m == "call" => a.call(r),
            Op::R32(r) if m == "jmp" => a.jmp(r),
            Op::R32(r) if m == "call" => a.call(r),
            Op::Mem(mm) if m == "jmp" => a.jmp(mm),
            Op::Mem(mm) if m == "call" => a.call(mm),
            _ => return Err(AsmError::BadOperands(m.into())),
        },

        // ── two operands ────────────────────────────────────────────
        ("mov", 2) => mov_dispatch!(a, operand(ops[0])?, operand(ops[1])?, m),
        ("add", 2) => bin!(a, add, operand(ops[0])?, operand(ops[1])?, m),
        ("sub", 2) => bin!(a, sub, operand(ops[0])?, operand(ops[1])?, m),
        ("and", 2) => bin!(a, and, operand(ops[0])?, operand(ops[1])?, m),
        ("or", 2) => bin!(a, or, operand(ops[0])?, operand(ops[1])?, m),
        ("xor", 2) => bin!(a, xor, operand(ops[0])?, operand(ops[1])?, m),
        ("cmp", 2) => bin!(a, cmp, operand(ops[0])?, operand(ops[1])?, m),
        ("test", 2) => bin_no_mem_src!(a, test, operand(ops[0])?, operand(ops[1])?, m, imm),
        ("adc", 2) => bin!(a, adc, operand(ops[0])?, operand(ops[1])?, m),
        ("sbb", 2) => bin!(a, sbb, operand(ops[0])?, operand(ops[1])?, m),
        ("xchg", 2) => bin_no_mem_src!(a, xchg, operand(ops[0])?, operand(ops[1])?, m, noimm),
        ("shl", 2) => shift!(a, shl, operand(ops[0])?, operand(ops[1])?, m),
        ("shr", 2) => shift!(a, shr, operand(ops[0])?, operand(ops[1])?, m),
        ("sar", 2) => shift!(a, sar, operand(ops[0])?, operand(ops[1])?, m),
        ("lea", 2) => match (operand(ops[0])?, operand(ops[1])?) {
            (Op::R64(d), Op::Mem(s)) => a.lea(d, s),
            (Op::R32(d), Op::Mem(s)) => a.lea(d, s),
            (Op::R16(d), Op::Mem(s)) => a.lea(d, s),
            _ => return Err(AsmError::BadOperands(m.into())),
        },
        ("movzx", 2) => match (operand(ops[0])?, operand(ops[1])?) {
            (Op::R64(d), Op::R8(s)) => a.movzx(d, s),
            (Op::R32(d), Op::R8(s)) => a.movzx(d, s),
            (Op::R32(d), Op::R16(s)) => a.movzx(d, s),
            (Op::R32(d), Op::Mem(s)) => a.movzx(d, s),
            _ => return Err(AsmError::BadOperands(m.into())),
        },
        ("movsx", 2) => match (operand(ops[0])?, operand(ops[1])?) {
            (Op::R64(d), Op::R8(s)) => a.movsx(d, s),
            (Op::R32(d), Op::R8(s)) => a.movsx(d, s),
            (Op::R32(d), Op::R16(s)) => a.movsx(d, s),
            (Op::R32(d), Op::Mem(s)) => a.movsx(d, s),
            _ => return Err(AsmError::BadOperands(m.into())),
        },

        _ if ops.len() > 2 => return Err(AsmError::BadOperands(m.into())),
        _ => return Err(AsmError::Unsupported(m.into())),
    };
    res.map_err(|e| AsmError::Encode(e.to_string()))?;

    let bytes = a.assemble(rip).map_err(|e| AsmError::Encode(e.to_string()))?;

    // Guard against any other silent multi-instruction expansion: every
    // mnemonic in the supported subset encodes to a single instruction, and
    // the longest direct form (0F 8x rel32 / operand-size-prefixed) is short.
    if is_branch(m) && bytes.len() > 6 {
        return Err(AsmError::Encode(format!(
            "'{line}' expanded to {} bytes (indirect trampoline); use a reachable target",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn is_branch(m: &str) -> bool {
    matches!(
        m,
        "jmp" | "call" | "je" | "jz" | "jne" | "jnz" | "ja" | "jae" | "jb" | "jbe" | "jg" | "jge"
            | "jl" | "jle" | "js" | "jns" | "jo" | "jno" | "jc" | "jnc" | "jp" | "jnp" | "loop"
    )
}

fn branch(a: &mut CodeAssembler, m: &str, target: u64) -> Result<(), iced_x86::IcedError> {
    match m {
        "jmp" => a.jmp(target),
        "call" => a.call(target),
        "je" | "jz" => a.je(target),
        "jne" | "jnz" => a.jne(target),
        "ja" => a.ja(target),
        "jae" | "jnc" => a.jae(target),
        "jb" | "jc" => a.jb(target),
        "jbe" => a.jbe(target),
        "jg" => a.jg(target),
        "jge" => a.jge(target),
        "jl" => a.jl(target),
        "jle" => a.jle(target),
        "js" => a.js(target),
        "jns" => a.jns(target),
        "jo" => a.jo(target),
        "jno" => a.jno(target),
        "jp" => a.jp(target),
        "jnp" => a.jnp(target),
        "loop" => a.loop_(target),
        _ => unreachable!("branch mnemonic {m} not in dispatch list"),
    }
}

/// Assemble and pad with NOPs to exactly `slot` bytes, so a patch never
/// disturbs the following instruction. Fails if it does not fit.
pub fn assemble_into(text: &str, bits: u8, rip: u64, slot: usize) -> Result<Vec<u8>, AsmError> {
    let mut bytes = assemble(text, bits, rip)?;
    if bytes.len() > slot {
        return Err(AsmError::TooLong { got: bytes.len(), max: slot });
    }
    bytes.resize(slot, 0x90);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asm(t: &str, bits: u8) -> Vec<u8> {
        assemble(t, bits, 0x1000).unwrap_or_else(|e| panic!("{t}: {e}"))
    }

    #[test]
    fn classic_zero_idiom() {
        assert_eq!(asm("xor eax, eax", 64), vec![0x31, 0xC0]);
        assert_eq!(asm("xor eax,eax", 32), vec![0x31, 0xC0]);
    }

    #[test]
    fn zero_operand_forms() {
        assert_eq!(asm("ret", 64), vec![0xC3]);
        assert_eq!(asm("nop", 64), vec![0x90]);
        assert_eq!(asm("int3", 64), vec![0xCC]);
        assert_eq!(asm("leave", 64), vec![0xC9]);
    }

    #[test]
    fn mov_immediate_and_registers() {
        assert_eq!(asm("mov eax, 1", 64), vec![0xB8, 0x01, 0, 0, 0]);
        assert_eq!(asm("mov eax, ebx", 64), vec![0x89, 0xD8]);
        // Bare numbers are hex, HIEW-style: 10 == 0x10.
        assert_eq!(asm("mov eax, 10", 64), vec![0xB8, 0x10, 0, 0, 0]);
        assert_eq!(asm("mov eax, 10t", 64), vec![0xB8, 0x0A, 0, 0, 0]);
        assert_eq!(asm("mov eax, 0x10", 64), vec![0xB8, 0x10, 0, 0, 0]);
    }

    #[test]
    fn rex_registers_encode_in_64bit() {
        assert_eq!(asm("mov rax, rbx", 64), vec![0x48, 0x89, 0xD8]);
        assert_eq!(asm("xor r8, r8", 64), vec![0x4D, 0x31, 0xC0]);
    }

    #[test]
    fn branches_are_relative_to_rip() {
        // jmp forward from 0x1000 to 0x1010: EB 0E (2-byte instruction).
        assert_eq!(assemble("jmp 1010", 64, 0x1000).unwrap(), vec![0xEB, 0x0E]);
        // call is rel32: E8 + 4 bytes.
        let c = assemble("call 1010", 64, 0x1000).unwrap();
        assert_eq!(c[0], 0xE8);
        assert_eq!(c.len(), 5);
    }

    #[test]
    fn unreachable_branch_is_refused_not_trampolined() {
        // Far target: iced would emit `jmp qword ptr [rip+N]` + an 8-byte slot.
        let e = assemble("jmp 1010", 64, 0x1_0000_1000);
        assert!(
            matches!(e, Err(AsmError::BranchOutOfRange { .. })),
            "expected out-of-range, got {e:?}"
        );
        // A reachable target still encodes directly.
        assert_eq!(assemble("jmp 1010", 64, 0x1000).unwrap(), vec![0xEB, 0x0E]);
    }

    #[test]
    fn va_notation_is_accepted_for_targets() {
        assert_eq!(
            assemble("jmp .1010", 64, 0x1000).unwrap(),
            assemble("jmp 1010", 64, 0x1000).unwrap()
        );
    }

    #[test]
    fn conditional_branch_aliases_agree() {
        let a = assemble("je 1010", 64, 0x1000).unwrap();
        let b = assemble("jz 1010", 64, 0x1000).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            assemble("jne 1010", 64, 0x1000).unwrap(),
            assemble("jnz 1010", 64, 0x1000).unwrap()
        );
    }

    #[test]
    fn memory_operands() {
        assert_eq!(asm("mov eax, [rbx]", 64), vec![0x8B, 0x03]);
        assert_eq!(asm("mov eax, dword ptr [rbx+8]", 64), vec![0x8B, 0x43, 0x08]);
        // Scaled index.
        let s = asm("mov eax, [rbx+rcx*4]", 64);
        assert_eq!(s[0], 0x8B);
        // Store direction.
        assert_eq!(asm("mov [rbx], eax", 64), vec![0x89, 0x03]);
    }

    #[test]
    fn unary_and_stack() {
        assert_eq!(asm("push rbp", 64), vec![0x55]);
        assert_eq!(asm("pop rbp", 64), vec![0x5D]);
        assert_eq!(asm("inc eax", 64), vec![0xFF, 0xC0]);
        assert_eq!(asm("neg eax", 64), vec![0xF7, 0xD8]);
    }

    #[test]
    fn lea_requires_memory_source() {
        assert!(assemble("lea rax, [rbx+8]", 64, 0x1000).is_ok());
        assert_eq!(
            assemble("lea rax, rbx", 64, 0x1000),
            Err(AsmError::BadOperands("lea".into()))
        );
    }

    #[test]
    fn comments_and_whitespace_tolerated() {
        assert_eq!(asm("  xor   eax ,  eax   ; zero it", 64), vec![0x31, 0xC0]);
    }

    #[test]
    fn errors_are_specific_not_silent() {
        assert_eq!(assemble("", 64, 0), Err(AsmError::Empty));
        assert_eq!(assemble("   ", 64, 0), Err(AsmError::Empty));
        assert!(matches!(assemble("frobnicate eax", 64, 0), Err(AsmError::Unsupported(_))));
        assert!(matches!(assemble("mov eax, zzz", 64, 0), Err(AsmError::Parse(_))));
        assert!(matches!(assemble("mov eax", 64, 0), Err(AsmError::Unsupported(_))));
    }

    #[test]
    fn assemble_into_pads_with_nops() {
        // 2-byte xor padded into a 5-byte slot.
        let b = assemble_into("xor eax, eax", 64, 0x1000, 5).unwrap();
        assert_eq!(b, vec![0x31, 0xC0, 0x90, 0x90, 0x90]);
    }

    #[test]
    fn assemble_into_refuses_to_overflow_the_slot() {
        let e = assemble_into("mov eax, 12345678", 64, 0x1000, 2);
        assert!(matches!(e, Err(AsmError::TooLong { got: 5, max: 2 })), "{e:?}");
    }

    #[test]
    fn bitness_changes_encoding() {
        // push 1 is 6A 01 in both, but operand-size prefixes differ for 16-bit.
        assert_eq!(asm("mov ax, 1", 16), vec![0xB8, 0x01, 0x00]);
        assert_eq!(asm("mov ax, 1", 32), vec![0x66, 0xB8, 0x01, 0x00]);
    }

    /// Everything this assembler emits must decode back to the same text.
    #[test]
    fn round_trips_through_the_disassembler() {
        use crate::Disassembler;
        let d = Disassembler::new(hiewlm_core::Arch::X86_64, 64);
        for src in [
            "xor eax, eax",
            "mov rax, rbx",
            "push rbp",
            "ret",
            "add rsp, 28",
            "cmp eax, 1",
        ] {
            let bytes = assemble(src, 64, 0x1000).unwrap();
            let back = d.decode(&bytes, 0, 0x1000, 1);
            assert_eq!(back.len(), 1, "{src}");
            assert_eq!(back[0].len, bytes.len(), "{src}");
        }
    }
}
