//! Crypt engine (HIEW `Alt+F3`): a tiny interpreter for the byte-level
//! transforms used to unmask obfuscated data — XOR/ADD/SUB/ROL/ROR/NOT/NEG.
//!
//! This is deliberately *not* a general scripting language. It is a pipeline of
//! stateless byte operations, applied left to right, so the result is always
//! predictable and reversible by construction. The engine only transforms
//! bytes; it never interprets them as code.
//!
//! Syntax — a comma- or semicolon-separated list of steps:
//!
//! ```text
//! xor 5a              XOR every byte with 0x5A
//! xor 5a, rol 3       XOR, then rotate left 3 bits
//! add 10, not         ADD 0x10 (wrapping), then complement
//! xor deadbeef        XOR with a repeating multi-byte key
//! xor "secret"        XOR with a repeating ASCII key
//! ```
//!
//! Numbers are hex (HIEW's default). A key longer than one byte repeats across
//! the block, indexed from the block start.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Repeating-key XOR. A one-byte key is the common case.
    Xor(Vec<u8>),
    Add(u8),
    Sub(u8),
    /// Rotate left / right by 1..=7 bits.
    Rol(u32),
    Ror(u32),
    /// Bitwise complement.
    Not,
    /// Two's-complement negation.
    Neg,
    And(u8),
    Or(u8),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CryptError {
    Empty,
    UnknownOp(String),
    MissingOperand(String),
    BadOperand(String),
    /// Rotation counts outside 1..=7 do nothing useful; reject them.
    BadRotation(u32),
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptError::Empty => write!(f, "empty recipe"),
            CryptError::UnknownOp(o) => write!(f, "unknown operation '{o}'"),
            CryptError::MissingOperand(o) => write!(f, "'{o}' needs an operand"),
            CryptError::BadOperand(o) => write!(f, "cannot parse operand '{o}'"),
            CryptError::BadRotation(n) => write!(f, "rotation must be 1..7, got {n}"),
        }
    }
}

impl std::error::Error for CryptError {}

impl Op {
    /// Apply to `data`. `index_base` is the block-relative offset of `data[0]`,
    /// so a repeating key stays aligned when applied in chunks.
    pub fn apply(&self, data: &mut [u8], index_base: usize) {
        match self {
            Op::Xor(key) if !key.is_empty() => {
                for (i, b) in data.iter_mut().enumerate() {
                    *b ^= key[(index_base + i) % key.len()];
                }
            }
            Op::Xor(_) => {}
            Op::Add(n) => data.iter_mut().for_each(|b| *b = b.wrapping_add(*n)),
            Op::Sub(n) => data.iter_mut().for_each(|b| *b = b.wrapping_sub(*n)),
            Op::Rol(n) => data.iter_mut().for_each(|b| *b = b.rotate_left(*n)),
            Op::Ror(n) => data.iter_mut().for_each(|b| *b = b.rotate_right(*n)),
            Op::Not => data.iter_mut().for_each(|b| *b = !*b),
            Op::Neg => data.iter_mut().for_each(|b| *b = b.wrapping_neg()),
            Op::And(n) => data.iter_mut().for_each(|b| *b &= *n),
            Op::Or(n) => data.iter_mut().for_each(|b| *b |= *n),
        }
    }

    /// The operation that undoes this one, when there is one. `and`/`or` lose
    /// bits, so they have no inverse — reported rather than faked.
    pub fn inverse(&self) -> Option<Op> {
        Some(match self {
            Op::Xor(k) => Op::Xor(k.clone()),
            Op::Add(n) => Op::Sub(*n),
            Op::Sub(n) => Op::Add(*n),
            Op::Rol(n) => Op::Ror(*n),
            Op::Ror(n) => Op::Rol(*n),
            Op::Not => Op::Not,
            Op::Neg => Op::Neg,
            Op::And(_) | Op::Or(_) => return None,
        })
    }
}

/// A parsed pipeline of operations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recipe(pub Vec<Op>);

impl Recipe {
    pub fn apply(&self, data: &mut [u8], index_base: usize) {
        for op in &self.0 {
            op.apply(data, index_base);
        }
    }

    /// The recipe that undoes this one (reverse order, each step inverted),
    /// or `None` if any step is lossy.
    pub fn inverse(&self) -> Option<Recipe> {
        let mut ops = Vec::with_capacity(self.0.len());
        for op in self.0.iter().rev() {
            ops.push(op.inverse()?);
        }
        Some(Recipe(ops))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn parse_key(tok: &str) -> Result<Vec<u8>, CryptError> {
    let t = tok.trim();
    // Quoted ASCII key: xor "secret"
    if let Some(inner) = t.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        return Ok(inner.as_bytes().to_vec());
    }
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CryptError::BadOperand(t.to_string()));
    }
    // Odd-length hex is a single byte value ("5" == 0x05), matching how a user
    // types a short key; even length is a byte string.
    if t.len() <= 2 {
        return u8::from_str_radix(t, 16)
            .map(|b| vec![b])
            .map_err(|_| CryptError::BadOperand(t.to_string()));
    }
    let padded = if t.len() % 2 == 1 {
        format!("0{t}")
    } else {
        t.to_string()
    };
    (0..padded.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&padded[i..i + 2], 16)
                .map_err(|_| CryptError::BadOperand(t.to_string()))
        })
        .collect()
}

fn parse_byte(tok: &str) -> Result<u8, CryptError> {
    let k = parse_key(tok)?;
    match k.as_slice() {
        [b] => Ok(*b),
        _ => Err(CryptError::BadOperand(tok.trim().to_string())),
    }
}

/// Parse a recipe like `xor 5a, rol 3`.
pub fn parse(text: &str) -> Result<Recipe, CryptError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(CryptError::Empty);
    }
    let mut ops = Vec::new();
    for step in text
        .split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let (name, arg) = match step.split_once(char::is_whitespace) {
            Some((n, a)) => (n.to_ascii_lowercase(), a.trim()),
            None => (step.to_ascii_lowercase(), ""),
        };
        let need = |a: &str| -> Result<(), CryptError> {
            if a.is_empty() {
                Err(CryptError::MissingOperand(name.clone()))
            } else {
                Ok(())
            }
        };
        let op = match name.as_str() {
            "xor" => {
                need(arg)?;
                Op::Xor(parse_key(arg)?)
            }
            "add" => {
                need(arg)?;
                Op::Add(parse_byte(arg)?)
            }
            "sub" => {
                need(arg)?;
                Op::Sub(parse_byte(arg)?)
            }
            "and" => {
                need(arg)?;
                Op::And(parse_byte(arg)?)
            }
            "or" => {
                need(arg)?;
                Op::Or(parse_byte(arg)?)
            }
            "rol" | "ror" => {
                need(arg)?;
                let n: u32 = arg
                    .parse()
                    .map_err(|_| CryptError::BadOperand(arg.to_string()))?;
                if !(1..=7).contains(&n) {
                    return Err(CryptError::BadRotation(n));
                }
                if name == "rol" {
                    Op::Rol(n)
                } else {
                    Op::Ror(n)
                }
            }
            "not" => Op::Not,
            "neg" => Op::Neg,
            other => return Err(CryptError::UnknownOp(other.to_string())),
        };
        ops.push(op);
    }
    if ops.is_empty() {
        return Err(CryptError::Empty);
    }
    Ok(Recipe(ops))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(recipe: &str, data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        parse(recipe).unwrap().apply(&mut v, 0);
        v
    }

    #[test]
    fn single_byte_xor() {
        assert_eq!(run("xor 5a", b"AAAA"), vec![0x1B; 4]);
    }

    #[test]
    fn repeating_multibyte_key() {
        // "de ad" repeats across four bytes.
        assert_eq!(run("xor dead", &[0, 0, 0, 0]), vec![0xDE, 0xAD, 0xDE, 0xAD]);
    }

    #[test]
    fn ascii_key() {
        let out = run(r#"xor "AB""#, &[0, 0, 0, 0]);
        assert_eq!(out, vec![b'A', b'B', b'A', b'B']);
    }

    #[test]
    fn pipeline_applies_left_to_right() {
        // xor 0xFF then add 1  ≠  add 1 then xor 0xFF
        assert_ne!(run("xor ff, add 1", &[0x10]), run("add 1, xor ff", &[0x10]));
        assert_eq!(run("xor ff, add 1", &[0x10]), vec![0xF0]); // 0x10^0xFF=0xEF, +1=0xF0
    }

    #[test]
    fn arithmetic_wraps_not_panics() {
        assert_eq!(run("add ff", &[0xFF]), vec![0xFE]);
        assert_eq!(run("sub 1", &[0x00]), vec![0xFF]);
        assert_eq!(run("neg", &[0x00]), vec![0x00]);
    }

    #[test]
    fn rotations() {
        assert_eq!(run("rol 1", &[0b1000_0001]), vec![0b0000_0011]);
        assert_eq!(run("ror 1", &[0b0000_0011]), vec![0b1000_0001]);
    }

    #[test]
    fn inverse_round_trips() {
        let data = b"Hello, world!".to_vec();
        for recipe in [
            "xor 5a",
            "add 10",
            "rol 3",
            "xor dead, add 7, ror 2",
            "not",
            "neg",
        ] {
            let r = parse(recipe).unwrap();
            let inv = r.inverse().expect("invertible");
            let mut v = data.clone();
            r.apply(&mut v, 0);
            assert_ne!(v, data, "{recipe} did nothing");
            inv.apply(&mut v, 0);
            assert_eq!(v, data, "{recipe} did not round-trip");
        }
    }

    #[test]
    fn lossy_ops_report_no_inverse() {
        assert!(parse("and 0f").unwrap().inverse().is_none());
        assert!(parse("or f0").unwrap().inverse().is_none());
        assert!(parse("xor 5a, and 0f").unwrap().inverse().is_none());
    }

    /// A repeating key must stay aligned when the block is processed in chunks.
    #[test]
    fn index_base_keeps_repeating_key_aligned() {
        let r = parse("xor dead").unwrap();
        let mut whole = vec![0u8; 4];
        r.apply(&mut whole, 0);

        let mut chunked = vec![0u8; 4];
        let (a, b) = chunked.split_at_mut(1);
        r.apply(a, 0);
        r.apply(b, 1);
        assert_eq!(whole, chunked);
    }

    #[test]
    fn errors_are_specific() {
        assert_eq!(parse(""), Err(CryptError::Empty));
        assert_eq!(parse("  "), Err(CryptError::Empty));
        assert_eq!(parse("frob 1"), Err(CryptError::UnknownOp("frob".into())));
        assert_eq!(parse("xor"), Err(CryptError::MissingOperand("xor".into())));
        assert_eq!(parse("rol 9"), Err(CryptError::BadRotation(9)));
        assert!(matches!(parse("xor zz"), Err(CryptError::BadOperand(_))));
        // A multi-byte key is not a valid operand where one byte is required.
        assert!(matches!(parse("add dead"), Err(CryptError::BadOperand(_))));
    }

    #[test]
    fn empty_data_is_a_no_op() {
        let mut empty: Vec<u8> = Vec::new();
        parse("xor 5a, rol 3").unwrap().apply(&mut empty, 0);
        assert!(empty.is_empty());
    }
}
