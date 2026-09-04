//! Byte search over [`EditBuffer`]: hex, text (case-sensitive or not), UTF-16 and
//! assembled instructions, in both directions, with single-byte wildcards.

use crate::addr::FileOffset;
use crate::buffer::EditBuffer;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    Forward,
    Backward,
}

/// Search pattern: bytes to match; a `false` in `mask` is a wildcard (matches any
/// byte).
#[derive(Clone, Debug)]
pub struct Pattern {
    bytes: Vec<u8>,
    mask: Vec<bool>,
    /// Compare ASCII letters without case. Malware strings are rarely typed the
    /// way you remember them, so a case-blind text search saves a second try.
    ci: bool,
}

impl Pattern {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let mask = vec![true; bytes.len()];
        Self {
            bytes,
            mask,
            ci: false,
        }
    }

    pub fn from_text(text: &str) -> Self {
        Self::from_bytes(text.as_bytes().to_vec())
    }

    /// Case-insensitive ASCII text (the pattern is stored folded to lowercase).
    pub fn from_text_ci(text: &str) -> Self {
        let mut p = Self::from_bytes(text.as_bytes().to_ascii_lowercase());
        p.ci = true;
        p
    }

    pub fn is_case_insensitive(&self) -> bool {
        self.ci
    }

    /// A hex string like "de ad ??" — `?`/`??` is a single-byte wildcard.
    pub fn from_hex(input: &str) -> Result<Self, HexParseError> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        for tok in input.split_whitespace() {
            for pair in Self::split_pairs(tok)? {
                if pair == "??" || pair == "?" {
                    bytes.push(0);
                    mask.push(false);
                } else {
                    let v = u8::from_str_radix(&pair, 16).map_err(|_| HexParseError)?;
                    bytes.push(v);
                    mask.push(true);
                }
            }
        }
        if bytes.is_empty() {
            return Err(HexParseError);
        }
        Ok(Self {
            bytes,
            mask,
            ci: false,
        })
    }

    fn split_pairs(tok: &str) -> Result<Vec<String>, HexParseError> {
        if tok == "?" || tok == "??" {
            return Ok(vec!["??".into()]);
        }
        if tok.len() % 2 != 0 {
            return Err(HexParseError);
        }
        Ok(tok
            .as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect())
    }

    /// The literal bytes, if the pattern has no wildcards (needed for replace).
    /// A case-insensitive pattern has none: the bytes on disk are not what was
    /// typed, so replacing them would corrupt the case.
    pub fn literal_bytes(&self) -> Option<&[u8]> {
        if !self.ci && self.mask.iter().all(|&m| m) {
            Some(&self.bytes)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn matches_at(&self, buf: &EditBuffer, at: u64) -> bool {
        if at + self.bytes.len() as u64 > buf.len() {
            return false;
        }
        let mut window = vec![0u8; self.bytes.len()];
        buf.read_at(FileOffset(at), &mut window);
        let ci = self.ci;
        window
            .iter()
            .zip(&self.bytes)
            .zip(&self.mask)
            .all(|((&got, &want), &active)| {
                !active
                    || if ci {
                        got.to_ascii_lowercase() == want
                    } else {
                        got == want
                    }
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HexParseError;

impl std::fmt::Display for HexParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid hex string")
    }
}

impl std::error::Error for HexParseError {}

/// Find the first occurrence of `pat` from `from` in direction `dir`.
///
/// A linear scan: fast enough for interactive use on the window sizes involved,
/// and simple enough to be obviously correct against hostile input.
pub fn find(
    buf: &EditBuffer,
    pat: &Pattern,
    from: FileOffset,
    dir: Direction,
) -> Option<FileOffset> {
    if pat.is_empty() || buf.len() < pat.len() as u64 {
        return None;
    }
    let last_start = buf.len() - pat.len() as u64;
    match dir {
        Direction::Forward => {
            let mut at = from.get().min(last_start);
            loop {
                if pat.matches_at(buf, at) {
                    return Some(FileOffset(at));
                }
                if at >= last_start {
                    return None;
                }
                at += 1;
            }
        }
        Direction::Backward => {
            let mut at = from.get().min(last_start);
            loop {
                if pat.matches_at(buf, at) {
                    return Some(FileOffset(at));
                }
                if at == 0 {
                    return None;
                }
                at -= 1;
            }
        }
    }
}

/// Collect every match of `pat` whose start is in `[start, end)`. Bounded to the
/// given window, so highlighting the visible viewport stays cheap on huge files.
pub fn find_all(
    buf: &EditBuffer,
    pat: &Pattern,
    start: FileOffset,
    end: FileOffset,
) -> Vec<FileOffset> {
    let mut hits = Vec::new();
    if pat.is_empty() {
        return hits;
    }
    let mut at = start.get();
    let stop = end.get();
    while at < stop {
        if pat.matches_at(buf, at) {
            hits.push(FileOffset(at));
        }
        at += 1;
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::MemSource;
    use std::sync::Arc;

    fn buf(data: &[u8]) -> EditBuffer {
        EditBuffer::new(Arc::new(MemSource::new(data.to_vec())))
    }

    #[test]
    fn find_text_forward() {
        let b = buf(b"the quick brown fox");
        let hit = find(
            &b,
            &Pattern::from_text("brown"),
            FileOffset(0),
            Direction::Forward,
        );
        assert_eq!(hit, Some(FileOffset(10)));
    }

    #[test]
    fn find_backward() {
        let b = buf(b"aXbXc");
        let hit = find(
            &b,
            &Pattern::from_text("X"),
            FileOffset(4),
            Direction::Backward,
        );
        assert_eq!(hit, Some(FileOffset(3)));
    }

    #[test]
    fn hex_with_wildcard() {
        let b = buf(&[0xde, 0xad, 0xbe, 0xef]);
        let pat = Pattern::from_hex("de ?? be").unwrap();
        assert_eq!(
            find(&b, &pat, FileOffset(0), Direction::Forward),
            Some(FileOffset(0))
        );
    }

    #[test]
    fn case_insensitive_text_matches_any_case() {
        let b = buf(b"call VirtualAllocEx now");
        let pat = Pattern::from_text_ci("virtualallocex");
        assert_eq!(
            find(&b, &pat, FileOffset(0), Direction::Forward),
            Some(FileOffset(5))
        );
        // ...and it is not offered for replacement, which would change the case.
        assert!(pat.literal_bytes().is_none());
        assert!(Pattern::from_text("VirtualAllocEx")
            .literal_bytes()
            .is_some());
    }

    #[test]
    fn no_match_returns_none() {
        let b = buf(b"abc");
        assert_eq!(
            find(
                &b,
                &Pattern::from_text("zzz"),
                FileOffset(0),
                Direction::Forward
            ),
            None
        );
    }

    #[test]
    fn bad_hex_rejected() {
        assert!(Pattern::from_hex("xyz").is_err());
        assert!(Pattern::from_hex("").is_err());
    }

    #[test]
    fn find_all_within_window() {
        let b = buf(b"aXbXcXd");
        let hits = find_all(&b, &Pattern::from_text("X"), FileOffset(0), FileOffset(7));
        assert_eq!(hits, vec![FileOffset(1), FileOffset(3), FileOffset(5)]);
        // Bounded: only matches starting before offset 4.
        let hits = find_all(&b, &Pattern::from_text("X"), FileOffset(0), FileOffset(4));
        assert_eq!(hits, vec![FileOffset(1), FileOffset(3)]);
    }
}
