//! Binary structure templates — a Kaitai-flavoured description language.
//!
//! A template is pure data: a list of typed fields. Applying one only reads the
//! buffer; nothing is ever executed (design §22.4).
//!
//! ```text
//! meta endian be              # file-level default (le if omitted)
//!
//! magic    u32 = 0x464C457F   # validated: flagged when it does not match
//! class    u8  enum { 1=ELF32 2=ELF64 }
//! version  u32le              # per-field endian override
//! namelen  u16
//! name     char[namelen]      # length taken from an earlier field
//! entries  u32[4]             # fixed-size array
//! rest     bytes[8]
//! ```
//!
//! Supported: `u8/u16/u32/u64`, `i8/i16/i32/i64`, `f32/f64` (each with an
//! optional `le`/`be` suffix), `char[N]`, `bytes[N]`, and `TYPE[N]` arrays,
//! where `N` is a literal or the name of an earlier integer field. Fields may
//! carry an `enum { v=NAME … }` map and an `= value` expectation.

use crate::buffer::EditBuffer;
use crate::FileOffset;
use std::collections::HashMap;

/// Guard against a corrupt length field turning into a huge allocation.
const MAX_LEN: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endian {
    #[default]
    Little,
    Big,
}

/// A count that is either literal or read from an earlier field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Len {
    Fixed(usize),
    /// Name of a previously-parsed integer field.
    Field(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scalar {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

impl Scalar {
    pub fn size(&self) -> usize {
        match self {
            Scalar::U8 | Scalar::I8 => 1,
            Scalar::U16 | Scalar::I16 => 2,
            Scalar::U32 | Scalar::I32 | Scalar::F32 => 4,
            Scalar::U64 | Scalar::I64 | Scalar::F64 => 8,
        }
    }

    fn is_integer(&self) -> bool {
        !matches!(self, Scalar::F32 | Scalar::F64)
    }

    /// Parse a scalar name with an optional `le`/`be` suffix.
    fn parse(tok: &str) -> Option<(Self, Option<Endian>)> {
        let (base, endian) = match tok {
            // Bare names first: `i8`/`u8` must not be read as a `be` suffix.
            "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "f32" | "f64" => {
                (tok, None)
            }
            _ if tok.ends_with("le") => (&tok[..tok.len() - 2], Some(Endian::Little)),
            _ if tok.ends_with("be") => (&tok[..tok.len() - 2], Some(Endian::Big)),
            _ => (tok, None),
        };
        let s = match base {
            "u8" => Scalar::U8,
            "u16" => Scalar::U16,
            "u32" => Scalar::U32,
            "u64" => Scalar::U64,
            "i8" => Scalar::I8,
            "i16" => Scalar::I16,
            "i32" => Scalar::I32,
            "i64" => Scalar::I64,
            "f32" => Scalar::F32,
            "f64" => Scalar::F64,
            _ => return None,
        };
        Some((s, endian))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    Scalar(Scalar),
    Ascii(Len),
    Bytes(Len),
    Array(Scalar, Len),
}

impl FieldType {
    /// Byte size when it is known without reading the data.
    pub fn static_size(&self) -> Option<usize> {
        match self {
            FieldType::Scalar(s) => Some(s.size()),
            FieldType::Ascii(Len::Fixed(n)) | FieldType::Bytes(Len::Fixed(n)) => Some(*n),
            FieldType::Array(s, Len::Fixed(n)) => Some(s.size() * n),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub ty: FieldType,
    /// Per-field endian override; falls back to the template default.
    pub endian: Option<Endian>,
    /// Value names for integer fields, e.g. `enum { 2=EXEC 3=DYN }`.
    pub enum_map: HashMap<u64, String>,
    /// An expected value; a mismatch is reported in the rendered output.
    pub expect: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct Template {
    pub fields: Vec<Field>,
    pub endian: Endian,
}

/// Parse an integer literal: `0x` hex, `0b` binary, else decimal.
fn parse_int(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(b) = s.strip_prefix("0b") {
        u64::from_str_radix(b, 2).ok()
    } else {
        s.parse().ok()
    }
}

/// Split off an `enum { ... }` clause, returning (remaining text, map).
fn take_enum(s: &str, lineno: usize) -> Result<(String, HashMap<u64, String>), String> {
    let Some(at) = s.find("enum") else {
        return Ok((s.to_string(), HashMap::new()));
    };
    let after = &s[at + 4..];
    let open = after
        .find('{')
        .ok_or_else(|| format!("line {lineno}: enum needs {{ … }}"))?;
    let close = after
        .find('}')
        .ok_or_else(|| format!("line {lineno}: unterminated enum"))?;
    if close < open {
        return Err(format!("line {lineno}: unterminated enum"));
    }
    let mut map = HashMap::new();
    for pair in after[open + 1..close].split_whitespace() {
        let (v, name) = pair
            .split_once('=')
            .ok_or_else(|| format!("line {lineno}: enum entry '{pair}' must be value=NAME"))?;
        let value = parse_int(v).ok_or_else(|| format!("line {lineno}: bad enum value '{v}'"))?;
        map.insert(value, name.to_string());
    }
    Ok((format!("{}{}", &s[..at], &after[close + 1..]), map))
}

fn parse_len(s: &str) -> Len {
    match parse_int(s) {
        Some(n) => Len::Fixed(n as usize),
        None => Len::Field(s.trim().to_string()),
    }
}

fn parse_type(tok: &str, lineno: usize) -> Result<(FieldType, Option<Endian>), String> {
    let bad = || format!("line {lineno}: bad type '{tok}'");
    if let Some((s, e)) = Scalar::parse(tok) {
        return Ok((FieldType::Scalar(s), e));
    }
    let (base, inner) = tok
        .split_once('[')
        .and_then(|(b, r)| r.strip_suffix(']').map(|i| (b, i)))
        .ok_or_else(bad)?;
    let len = parse_len(inner);
    match base {
        "char" => Ok((FieldType::Ascii(len), None)),
        "bytes" => Ok((FieldType::Bytes(len), None)),
        other => {
            let (s, e) = Scalar::parse(other).ok_or_else(bad)?;
            Ok((FieldType::Array(s, len), e))
        }
    }
}

impl Template {
    pub fn parse(text: &str) -> Result<Template, String> {
        let mut fields = Vec::new();
        let mut endian = Endian::Little;

        for (i, raw_line) in text.lines().enumerate() {
            let lineno = i + 1;
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("meta ") {
                let mut it = rest.split_whitespace();
                match (it.next(), it.next()) {
                    (Some("endian"), Some("be")) => endian = Endian::Big,
                    (Some("endian"), Some("le")) => endian = Endian::Little,
                    _ => {
                        return Err(format!(
                            "line {lineno}: only `meta endian be|le` is supported"
                        ))
                    }
                }
                continue;
            }

            let (line, enum_map) = take_enum(line, lineno)?;
            let (line, expect) = match line.split_once('=') {
                Some((head, want)) => {
                    let v = parse_int(want).ok_or_else(|| {
                        format!("line {lineno}: bad expected value '{}'", want.trim())
                    })?;
                    (head.to_string(), Some(v))
                }
                None => (line, None),
            };

            let mut it = line.split_whitespace();
            let name = it
                .next()
                .ok_or_else(|| format!("line {lineno}: missing field name"))?;
            let tyname = it
                .next()
                .ok_or_else(|| format!("line {lineno}: missing type for '{name}'"))?;
            let (ty, field_endian) = parse_type(tyname, lineno)?;

            let is_int_scalar = matches!(&ty, FieldType::Scalar(s) if s.is_integer());
            if expect.is_some() && !is_int_scalar {
                return Err(format!(
                    "line {lineno}: '= value' only applies to integer fields"
                ));
            }
            if !enum_map.is_empty() && !is_int_scalar {
                return Err(format!(
                    "line {lineno}: enum only applies to integer fields"
                ));
            }

            fields.push(Field {
                name: name.to_string(),
                ty,
                endian: field_endian,
                enum_map,
                expect,
            });
        }
        if fields.is_empty() {
            return Err("template has no fields".into());
        }
        Ok(Template { fields, endian })
    }

    /// Byte size when every length is literal; `None` if the layout depends on
    /// values only known once the data is read.
    pub fn static_size(&self) -> Option<u64> {
        self.fields
            .iter()
            .try_fold(0u64, |acc, f| f.ty.static_size().map(|n| acc + n as u64))
    }

    /// Size for callers that just want a number; 0 when data-dependent.
    pub fn total_size(&self) -> u64 {
        self.static_size().unwrap_or(0)
    }
}

/// A field resolved against a buffer at a base offset.
#[derive(Debug, Clone)]
pub struct ResolvedField {
    pub name: String,
    pub offset: u64,
    pub size: usize,
    pub value: String,
    /// Set when an `= value` expectation failed, or a length could not resolve.
    pub mismatch: bool,
}

fn read_uint(raw: &[u8], endian: Endian) -> u64 {
    let mut v = 0u64;
    match endian {
        Endian::Little => {
            for (i, &b) in raw.iter().take(8).enumerate() {
                v |= (b as u64) << (8 * i);
            }
        }
        Endian::Big => {
            for &b in raw.iter().take(8) {
                v = (v << 8) | b as u64;
            }
        }
    }
    v
}

/// Sign-extend an `n`-byte two's-complement value.
fn sign_extend(v: u64, bytes: usize) -> i64 {
    let bits = bytes * 8;
    if bits >= 64 {
        return v as i64;
    }
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

fn render_scalar(
    s: &Scalar,
    raw: &[u8],
    endian: Endian,
    enum_map: &HashMap<u64, String>,
) -> String {
    match s {
        Scalar::F32 => {
            let b: [u8; 4] = raw
                .get(0..4)
                .and_then(|r| r.try_into().ok())
                .unwrap_or_default();
            let v = match endian {
                Endian::Little => f32::from_le_bytes(b),
                Endian::Big => f32::from_be_bytes(b),
            };
            return v.to_string();
        }
        Scalar::F64 => {
            let b: [u8; 8] = raw
                .get(0..8)
                .and_then(|r| r.try_into().ok())
                .unwrap_or_default();
            let v = match endian {
                Endian::Little => f64::from_le_bytes(b),
                Endian::Big => f64::from_be_bytes(b),
            };
            return v.to_string();
        }
        _ => {}
    }
    let u = read_uint(raw, endian);
    if !s.is_integer() {
        return u.to_string();
    }
    if matches!(s, Scalar::I8 | Scalar::I16 | Scalar::I32 | Scalar::I64) {
        return sign_extend(u, s.size()).to_string();
    }
    match enum_map.get(&u) {
        Some(name) => format!("{u:#x} ({name})"),
        None => format!("{u:#x} ({u})"),
    }
}

/// Apply `template` at `base`, reading each field in order. Lengths that refer
/// to an earlier field are resolved from the values already read.
pub fn apply(template: &Template, buf: &EditBuffer, base: u64) -> Vec<ResolvedField> {
    let mut out = Vec::with_capacity(template.fields.len());
    let mut off = base;
    // Integer values seen so far, for `char[namelen]`-style lengths.
    let mut seen: HashMap<String, u64> = HashMap::new();

    for field in &template.fields {
        let endian = field.endian.unwrap_or(template.endian);
        let resolve = |len: &Len, seen: &HashMap<String, u64>| -> Option<usize> {
            match len {
                Len::Fixed(n) => Some(*n),
                Len::Field(name) => seen.get(name).map(|&v| v as usize),
            }
        };
        let read_n = |n: usize| -> Vec<u8> {
            let n = n.min(MAX_LEN);
            let mut raw = vec![0u8; n];
            buf.read_at(FileOffset(off), &mut raw);
            raw
        };

        let (size, value, mismatch) = match &field.ty {
            FieldType::Scalar(s) => {
                let raw = read_n(s.size());
                let u = read_uint(&raw, endian);
                if s.is_integer() {
                    seen.insert(field.name.clone(), u);
                }
                let bad = field.expect.is_some_and(|want| want != u);
                let mut text = render_scalar(s, &raw, endian, &field.enum_map);
                if let (true, Some(want)) = (bad, field.expect) {
                    text.push_str(&format!("  != expected {want:#x}"));
                }
                (s.size(), text, bad)
            }
            FieldType::Ascii(len) => match resolve(len, &seen) {
                Some(n) => {
                    let raw = read_n(n);
                    let s: String = raw
                        .iter()
                        .map(|&b| {
                            if (0x20..0x7f).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    (raw.len(), format!("\"{s}\""), false)
                }
                None => (0, format!("<unknown length '{}'>", len_name(len)), true),
            },
            FieldType::Bytes(len) => match resolve(len, &seen) {
                Some(n) => {
                    let raw = read_n(n);
                    let hex = raw
                        .iter()
                        .take(16)
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let text = if raw.len() > 16 {
                        format!("{hex} … ({} bytes)", raw.len())
                    } else {
                        hex
                    };
                    (raw.len(), text, false)
                }
                None => (0, format!("<unknown length '{}'>", len_name(len)), true),
            },
            FieldType::Array(s, len) => match resolve(len, &seen) {
                Some(n) => {
                    let unit = s.size().max(1);
                    let count = n.min(MAX_LEN / unit);
                    let raw = read_n(unit * count);
                    let items: Vec<String> = raw
                        .chunks_exact(unit)
                        .take(16)
                        .map(|c| render_scalar(s, c, endian, &field.enum_map))
                        .collect();
                    let more = if count > 16 {
                        format!(" … ({count} items)")
                    } else {
                        String::new()
                    };
                    (raw.len(), format!("[{}]{more}", items.join(", ")), false)
                }
                None => (0, format!("<unknown length '{}'>", len_name(len)), true),
            },
        };

        out.push(ResolvedField {
            name: field.name.clone(),
            offset: off,
            size,
            value,
            mismatch,
        });
        off += size as u64;
    }
    out
}

fn len_name(len: &Len) -> String {
    match len {
        Len::Fixed(n) => n.to_string(),
        Len::Field(f) => f.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::MemSource;
    use std::sync::Arc;

    fn buf(data: Vec<u8>) -> EditBuffer {
        EditBuffer::new(Arc::new(MemSource::new(data)))
    }

    #[test]
    fn parse_and_apply() {
        let tpl = Template::parse("magic u32\nver u16\nname char[4]").unwrap();
        assert_eq!(tpl.total_size(), 10);
        let data = vec![0x7f, b'E', b'L', b'F', 0x01, 0x00, b'a', b'b', b'c', b'd'];
        let fields = apply(&tpl, &buf(data), 0);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "magic");
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[1].offset, 4);
        assert_eq!(fields[2].value, "\"abcd\"");
    }

    #[test]
    fn bad_type_rejected() {
        assert!(Template::parse("x wat").is_err());
        assert!(Template::parse("").is_err());
    }

    #[test]
    fn meta_endian_be_flips_byte_order() {
        let t = Template::parse("meta endian be\nmagic u32").unwrap();
        assert_eq!(t.endian, Endian::Big);
        let r = apply(&t, &buf(vec![0x12, 0x34, 0x56, 0x78]), 0);
        assert!(r[0].value.starts_with("0x12345678"), "{}", r[0].value);
    }

    #[test]
    fn per_field_endian_overrides_the_default() {
        let t = Template::parse("meta endian be\na u32\nb u32le").unwrap();
        let r = apply(&t, &buf(vec![0, 0, 0, 1, 1, 0, 0, 0]), 0);
        assert!(r[0].value.starts_with("0x1 "), "{}", r[0].value);
        assert!(r[1].value.starts_with("0x1 "), "{}", r[1].value);
    }

    /// `i8`/`u8` must not have their trailing "8" confused with a `be` suffix.
    #[test]
    fn bare_scalar_names_are_not_read_as_endian_suffixes() {
        for name in [
            "u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "f32", "f64",
        ] {
            let t = Template::parse(&format!("x {name}")).unwrap();
            assert_eq!(t.fields[0].endian, None, "{name}");
        }
    }

    #[test]
    fn length_can_reference_an_earlier_field() {
        let t = Template::parse("len u8\nname char[len]").unwrap();
        assert_eq!(t.static_size(), None, "layout is data-dependent");
        let mut data = vec![3u8];
        data.extend_from_slice(b"abcXXXX");
        let r = apply(&t, &buf(data), 0);
        assert_eq!(r[1].value, "\"abc\"");
        assert_eq!(r[1].size, 3);
    }

    #[test]
    fn unknown_length_reference_is_reported_not_guessed() {
        let t = Template::parse("name char[nosuch]").unwrap();
        let r = apply(&t, &buf(vec![0; 8]), 0);
        assert!(r[0].mismatch);
        assert!(r[0].value.contains("nosuch"), "{}", r[0].value);
    }

    #[test]
    fn arrays_render_their_items() {
        let t = Template::parse("xs u16[3]").unwrap();
        let r = apply(&t, &buf(vec![1, 0, 2, 0, 3, 0]), 0);
        assert_eq!(r[0].size, 6);
        assert!(r[0].value.contains("0x1"), "{}", r[0].value);
        assert!(r[0].value.contains("0x3"), "{}", r[0].value);
    }

    #[test]
    fn enum_names_are_shown() {
        let t = Template::parse("kind u16 enum { 2=EXEC 3=DYN }").unwrap();
        let r = apply(&t, &buf(vec![3, 0]), 0);
        assert!(r[0].value.contains("DYN"), "{}", r[0].value);
    }

    #[test]
    fn expected_value_mismatch_is_flagged() {
        let t = Template::parse("magic u32 = 0x464C457F").unwrap();
        let ok = apply(&t, &buf(vec![0x7F, 0x45, 0x4C, 0x46]), 0);
        assert!(!ok[0].mismatch, "{}", ok[0].value);
        let bad = apply(&t, &buf(vec![0, 0, 0, 0]), 0);
        assert!(bad[0].mismatch);
        assert!(bad[0].value.contains("expected"));
    }

    #[test]
    fn signed_integers_are_sign_extended() {
        let t = Template::parse("a i8\nb i16\nc i32").unwrap();
        let r = apply(&t, &buf(vec![0xFF; 7]), 0);
        assert_eq!(r[0].value, "-1");
        assert_eq!(r[1].value, "-1");
        assert_eq!(r[2].value, "-1");
    }

    #[test]
    fn floats_respect_endianness() {
        let t = Template::parse("meta endian be\nx f32").unwrap();
        assert_eq!(
            apply(&t, &buf(1.5f32.to_be_bytes().to_vec()), 0)[0].value,
            "1.5"
        );
        let t = Template::parse("x f64").unwrap();
        assert_eq!(
            apply(&t, &buf(2.5f64.to_le_bytes().to_vec()), 0)[0].value,
            "2.5"
        );
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let t = Template::parse("# header\n\nmagic u32  # the magic\n").unwrap();
        assert_eq!(t.fields.len(), 1);
    }

    #[test]
    fn errors_are_specific() {
        assert!(Template::parse("# only a comment").is_err());
        assert!(Template::parse("name")
            .unwrap_err()
            .contains("missing type"));
        assert!(Template::parse("name frob")
            .unwrap_err()
            .contains("bad type"));
        assert!(Template::parse("meta endian middle").is_err());
        assert!(Template::parse("name char[4] = 5")
            .unwrap_err()
            .contains("integer"));
        assert!(Template::parse("k u8 enum { bad }")
            .unwrap_err()
            .contains("value=NAME"));
    }

    #[test]
    fn absurd_length_field_does_not_allocate_wildly() {
        let t = Template::parse("len u32\nname bytes[len]").unwrap();
        let mut data = 0xFFFF_FFFFu32.to_le_bytes().to_vec();
        data.resize(64, 0);
        let r = apply(&t, &buf(data), 0);
        assert!(r[1].size <= MAX_LEN);
    }

    /// The template shipped in examples/ must keep parsing and decoding a real
    /// ELF64 header, so the documented syntax cannot drift from the parser.
    #[test]
    fn shipped_elf_example_template_decodes_a_real_header() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/templates/elf_header.tpl"
        );
        let text = std::fs::read_to_string(path).expect("example template present");
        let t = Template::parse(&text).expect("example template parses");

        // A minimal but real ELF64 header: x86-64, DYN, SysV.
        let mut h = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0];
        h.resize(16, 0); // pad to e_ident[16]
        h.extend_from_slice(&3u16.to_le_bytes()); // e_type = DYN
        h.extend_from_slice(&62u16.to_le_bytes()); // e_machine = x86-64
        h.extend_from_slice(&1u32.to_le_bytes()); // e_version
        h.extend_from_slice(&0x1040u64.to_le_bytes()); // e_entry
        h.resize(64, 0);

        let r = apply(&t, &buf(h), 0);
        let get = |n: &str| r.iter().find(|f| f.name == n).expect(n);
        assert!(!get("magic").mismatch, "magic: {}", get("magic").value);
        assert!(!get("version").mismatch);
        assert!(
            get("class").value.contains("ELF64"),
            "{}",
            get("class").value
        );
        assert!(get("type").value.contains("DYN"), "{}", get("type").value);
        assert!(
            get("machine").value.contains("x86-64"),
            "{}",
            get("machine").value
        );
        assert!(
            get("entry").value.contains("0x1040"),
            "{}",
            get("entry").value
        );
        // e_ident is 16 bytes, so e_type must land exactly at offset 16.
        assert_eq!(get("type").offset, 16);
    }

    #[test]
    fn reading_past_end_of_buffer_is_zero_filled_not_a_panic() {
        let t = Template::parse("a u64\nb char[16]").unwrap();
        assert_eq!(apply(&t, &buf(vec![1, 2]), 0).len(), 2);
    }
}
