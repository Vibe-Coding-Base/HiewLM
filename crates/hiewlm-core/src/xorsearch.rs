//! Find plaintext hidden behind a single-byte transform, and recover the key.
//!
//! Malware rarely stores its C2 URL in the clear, but it usually does not do
//! anything sophisticated either: one XOR/ADD/ROL byte over an otherwise plain
//! ASCII string. Brute-forcing 255 keys against a handful of known plaintexts is
//! milliseconds of work and routinely produces the configuration outright.
//!
//! Pure byte arithmetic — the transformed data is never interpreted or run.

use crate::addr::FileOffset;
use crate::buffer::EditBuffer;

/// The reversible byte transforms worth brute-forcing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Xor,
    Add,
    Sub,
    Rol,
}

impl Op {
    pub fn label(self) -> &'static str {
        match self {
            Op::Xor => "xor",
            Op::Add => "add",
            Op::Sub => "sub",
            Op::Rol => "rol",
        }
    }

    /// Apply the transform that turns *file* bytes into *plaintext*.
    pub fn decode(self, b: u8, key: u8) -> u8 {
        match self {
            Op::Xor => b ^ key,
            // `add k` on the file means the plaintext was shifted up by k.
            Op::Add => b.wrapping_sub(key),
            Op::Sub => b.wrapping_add(key),
            Op::Rol => b.rotate_right(key as u32 % 8),
        }
    }

    /// Apply the transform in the encoding direction (plaintext -> file bytes).
    pub fn encode(self, b: u8, key: u8) -> u8 {
        match self {
            Op::Xor => b ^ key,
            Op::Add => b.wrapping_add(key),
            Op::Sub => b.wrapping_sub(key),
            Op::Rol => b.rotate_left(key as u32 % 8),
        }
    }

    /// Keys worth trying for this op (rotations only have 7 useful values).
    pub fn key_range(self) -> std::ops::RangeInclusive<u16> {
        match self {
            Op::Rol => 1..=7,
            _ => 1..=255,
        }
    }
}

/// Ops that get a dedicated scan. `Sub` is not searched separately: it is `Add`
/// with the complementary key, and results are normalized to whichever reads
/// better for a human.
pub const OPS: [Op; 4] = [Op::Xor, Op::Add, Op::Sub, Op::Rol];

/// Plaintexts that betray an encoded blob. Short enough to appear in a config,
/// specific enough not to fire at random.
pub const DEFAULT_NEEDLES: [&str; 12] = [
    "http://",
    "https://",
    "This program",
    "kernel32",
    "GetProcAddress",
    "LoadLibrary",
    "\\Software\\Microsoft",
    "cmd.exe",
    "powershell",
    "User-Agent",
    "Content-Type",
    "MZ\u{90}\u{0}",
];

/// One recovered plaintext.
#[derive(Clone, Debug)]
pub struct Hit {
    pub offset: u64,
    pub op: Op,
    pub key: u8,
    /// The needle that matched.
    pub needle: String,
    /// Decoded context around the hit, for the results list.
    pub preview: String,
}

impl Hit {
    /// The recipe that decodes this region, in `crypt` syntax.
    pub fn recipe(&self) -> String {
        match self.op {
            Op::Rol => format!("ror {}", self.key),
            _ => format!("{} {:02x}", self.op.label(), self.key),
        }
    }
}

/// Search `data` for any of `needles` under every single-byte transform.
/// `max_hits` bounds the work on hostile input.
///
/// Brute-forcing 255 keys per needle would mean hundreds of passes over the
/// file. Instead this exploits the fact that a constant XOR (or ADD) leaves the
/// *differences* between neighbouring bytes untouched: one pass finds the
/// difference pattern, and the key falls out of a single byte. Only rotations,
/// which have just seven useful keys, are still brute-forced.
pub fn search(data: &[u8], needles: &[&str], max_hits: usize) -> Vec<Hit> {
    let mut hits = Vec::new();
    for needle in needles {
        let plain = needle.as_bytes();
        if plain.is_empty() || plain.len() > data.len() {
            continue;
        }
        scan_delta(data, plain, needle, Op::Xor, &mut hits, max_hits);
        if hits.len() >= max_hits {
            return hits;
        }
        scan_delta(data, plain, needle, Op::Add, &mut hits, max_hits);
        if hits.len() >= max_hits {
            return hits;
        }
        // Rotations do not preserve differences, but there are only seven keys.
        for key in 1..=7u8 {
            let encoded: Vec<u8> = plain.iter().map(|&b| Op::Rol.encode(b, key)).collect();
            let mut from = 0usize;
            while let Some(pos) = find_sub(&data[from..], &encoded) {
                let at = from + pos;
                hits.push(Hit {
                    offset: at as u64,
                    op: Op::Rol,
                    key,
                    needle: (*needle).to_string(),
                    preview: decode_preview(data, at, Op::Rol, key),
                });
                if hits.len() >= max_hits {
                    return hits;
                }
                from = at + 1;
                if from >= data.len() {
                    break;
                }
            }
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits
}

/// One pass looking for `plain`'s difference signature under `op` (Xor or Add).
fn scan_delta(
    data: &[u8],
    plain: &[u8],
    needle: &str,
    op: Op,
    hits: &mut Vec<Hit>,
    max_hits: usize,
) {
    let n = plain.len();
    if n < 2 || data.len() < n {
        return;
    }
    let delta = |a: u8, b: u8| match op {
        Op::Xor => a ^ b,
        _ => b.wrapping_sub(a),
    };
    let want: Vec<u8> = plain.windows(2).map(|w| delta(w[0], w[1])).collect();

    for at in 0..=data.len() - n {
        if !data[at..at + n]
            .windows(2)
            .zip(&want)
            .all(|(w, &d)| delta(w[0], w[1]) == d)
        {
            continue;
        }
        // The pattern matched; the key is whatever maps plain[0] to data[at].
        let (op, key) = match op {
            Op::Xor => (Op::Xor, data[at] ^ plain[0]),
            _ => {
                let k = data[at].wrapping_sub(plain[0]);
                // `add f9` and `sub 07` are the same thing; show the small one.
                if k > 0x80 {
                    (Op::Sub, 0u8.wrapping_sub(k))
                } else {
                    (Op::Add, k)
                }
            }
        };
        // Key 0 is the identity — that string is not hidden, `s` already lists it.
        if key == 0 {
            continue;
        }
        hits.push(Hit {
            offset: at as u64,
            op,
            key,
            needle: needle.to_string(),
            preview: decode_preview(data, at, op, key),
        });
        if hits.len() >= max_hits {
            return;
        }
    }
}

/// Same search over a buffer, reading in overlapping chunks so a hit spanning a
/// chunk boundary is not missed.
pub fn search_buffer(
    buf: &EditBuffer,
    needles: &[&str],
    max_hits: usize,
    max_bytes: u64,
) -> Vec<Hit> {
    let limit = if max_bytes == 0 { buf.len() } else { max_bytes.min(buf.len()) };
    let longest = needles.iter().map(|n| n.len()).max().unwrap_or(0) as u64;
    let mut hits = Vec::new();
    let step = 1024 * 1024u64;
    let mut off = 0u64;
    while off < limit && hits.len() < max_hits {
        let end = (off + step + longest).min(limit);
        let n = (end - off) as usize;
        let mut chunk = vec![0u8; n];
        buf.read_at(FileOffset(off), &mut chunk);
        for mut h in search(&chunk, needles, max_hits - hits.len()) {
            // Drop hits that start in the overlap; the next chunk owns them.
            if off > 0 && h.offset < longest {
                continue;
            }
            h.offset += off;
            hits.push(h);
        }
        off += step;
    }
    hits.sort_by_key(|h| h.offset);
    hits.dedup_by(|a, b| a.offset == b.offset && a.op == b.op && a.key == b.key);
    hits
}

/// Recover the key from a region whose plaintext you already know
/// (`known` must be what the region decodes to at `at`).
pub fn key_from_known(data: &[u8], at: usize, known: &str) -> Vec<(Op, u8)> {
    let mut out = Vec::new();
    if known.is_empty() || at + known.len() > data.len() {
        return out;
    }
    for op in OPS {
        for key in op.key_range() {
            let key = key as u8;
            if known
                .bytes()
                .enumerate()
                .all(|(i, p)| op.decode(data[at + i], key) == p)
            {
                out.push((op, key));
            }
        }
    }
    out
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Decode up to 64 bytes around a hit into a printable preview.
fn decode_preview(data: &[u8], at: usize, op: Op, key: u8) -> String {
    let end = (at + 64).min(data.len());
    data[at..end]
        .iter()
        .map(|&b| {
            let d = op.decode(b, key);
            if (0x20..0x7f).contains(&d) {
                d as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_xored_url_and_recipe() {
        let plain = b"cfg http://c2.example.top/gate.php end";
        let data: Vec<u8> = plain.iter().map(|&b| b ^ 0x5a).collect();
        let hits = search(&data, &DEFAULT_NEEDLES, 32);
        let hit = hits.iter().find(|h| h.op == Op::Xor && h.key == 0x5a).expect("xor 5a hit");
        assert!(hit.preview.contains("http://c2.example.top"), "{}", hit.preview);
        assert_eq!(hit.recipe(), "xor 5a");
    }

    #[test]
    fn finds_add_and_rol_encodings() {
        let plain = b"xx https://evil.top/x";
        let added: Vec<u8> = plain.iter().map(|&b| b.wrapping_add(7)).collect();
        assert!(search(&added, &DEFAULT_NEEDLES, 32).iter().any(|h| h.op == Op::Add && h.key == 7));
        let rolled: Vec<u8> = plain.iter().map(|&b| b.rotate_left(3)).collect();
        assert!(search(&rolled, &DEFAULT_NEEDLES, 32).iter().any(|h| h.op == Op::Rol && h.key == 3));
    }

    #[test]
    fn key_recovered_from_known_plaintext() {
        let data: Vec<u8> = b"MZ\x90\x00".iter().map(|&b| b ^ 0x37).collect();
        assert!(key_from_known(&data, 0, "MZ").contains(&(Op::Xor, 0x37)));
    }

    #[test]
    fn clean_data_yields_no_hits() {
        let data = vec![0u8; 4096];
        assert!(search(&data, &["http://"], 8).is_empty());
    }

    #[test]
    fn buffer_search_spans_chunk_boundary() {
        use crate::buffer::MemSource;
        use std::sync::Arc;
        let mut data = vec![0xaau8; 1024 * 1024 - 4];
        data.extend(b"http://boundary.top/x".iter().map(|&b| b ^ 0x11));
        data.extend(std::iter::repeat(0xaau8).take(1000));
        let buf = EditBuffer::new(Arc::new(MemSource::new(data)));
        let hits = search_buffer(&buf, &DEFAULT_NEEDLES, 16, 0);
        assert!(hits.iter().any(|h| h.key == 0x11 && h.op == Op::Xor), "{hits:?}");
    }
}
