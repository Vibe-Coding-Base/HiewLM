//! Copying text to the *system* clipboard from inside the terminal, using the
//! OSC 52 escape sequence.
//!
//! Triage output is only useful if it can leave the terminal: a SHA-256 has to
//! reach a ticket, an IOC list has to reach a report. OSC 52 does that with no
//! dependency and — unlike a platform clipboard API — it also works over SSH,
//! which is where malware analysis usually happens.
//!
//! Not every terminal enables it (tmux needs `set -g set-clipboard on`), so the
//! caller always tells the user what was copied and how much.

use std::io::Write;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub fn base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let idx = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        out.push(B64[idx[0] as usize] as char);
        out.push(B64[idx[1] as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[idx[2] as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[idx[3] as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Put `text` on the system clipboard. Large payloads are refused rather than
/// silently truncated — terminals drop over-long OSC sequences.
pub fn copy(text: &str) -> Result<usize, String> {
    const LIMIT: usize = 512 * 1024;
    if text.is_empty() {
        return Err("nothing to copy".into());
    }
    if text.len() > LIMIT {
        return Err(format!(
            "{} bytes is too much for the terminal clipboard (limit {LIMIT}); write it to a file with the b menu instead",
            text.len()
        ));
    }
    let seq = format!("\x1b]52;c;{}\x07", base64(text.as_bytes()));
    let mut out = std::io::stdout();
    out.write_all(seq.as_bytes()).map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    Ok(text.len())
}

/// `de ad be ef` — what a search box or a YARA rule wants.
pub fn as_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A C array literal, for dropping into a harness.
pub fn as_c_array(bytes: &[u8]) -> String {
    let mut s = String::from("unsigned char data[] = {\n");
    for row in bytes.chunks(12) {
        s.push_str("    ");
        s.push_str(
            &row.iter()
                .map(|b| format!("0x{b:02x}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        s.push_str(",\n");
    }
    s.push_str("};\n");
    s
}

/// A Python bytes literal.
pub fn as_python(bytes: &[u8]) -> String {
    let mut s = String::from("data = b\"");
    for b in bytes {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            0x20..=0x7e => s.push(*b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s.push('"');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn oversized_payload_is_refused_not_truncated() {
        let big = "x".repeat(600 * 1024);
        assert!(copy(&big).is_err());
        assert!(copy("").is_err());
    }

    #[test]
    fn byte_formats_round_trip_visually() {
        let b = [0x90u8, 0x00, b'A', 0xff];
        assert_eq!(as_hex(&b), "90 00 41 ff");
        assert!(as_c_array(&b).contains("0x90, 0x00, 0x41, 0xff"));
        assert_eq!(as_python(&b), "data = b\"\\x90\\x00A\\xff\"");
    }
}
