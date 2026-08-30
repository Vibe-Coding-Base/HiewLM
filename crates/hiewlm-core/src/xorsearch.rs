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
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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
/// Two ideas keep this near one pass over the file instead of hundreds:
///
/// 1. A constant XOR (or ADD) leaves the *differences* between neighbouring
///    bytes untouched, so one scan finds the difference signature and the key
///    falls out of a single byte — no 255-key brute force.
/// 2. All needles are checked at every position through a 256-entry table keyed
///    on the first difference, so adding needles costs a table entry, not a pass.
///
/// Rotations do not preserve differences, but they have only seven useful keys,
/// and those are folded into the same one-pass-per-key shape.
pub fn search(data: &[u8], needles: &[&str], max_hits: usize) -> Vec<Hit> {
    let mut hits = Vec::new();
    scan_delta(data, needles, Op::Xor, &mut hits, max_hits);
    if hits.len() < max_hits {
        scan_delta(data, needles, Op::Add, &mut hits, max_hits);
    }
    if hits.len() < max_hits {
        scan_rotations(data, needles, &mut hits, max_hits);
    }
    hits.sort_by_key(|h| h.offset);
    hits
}

/// Difference between two neighbouring plaintext bytes under `op`.
fn delta(op: Op, a: u8, b: u8) -> u8 {
    match op {
        Op::Xor => a ^ b,
        _ => b.wrapping_sub(a),
    }
}

/// Index of needles by the first byte of their signature, so one pass over the
/// data can test every needle at once.
fn bucket_by_first(keys: impl Iterator<Item = (usize, u8)>) -> [Vec<usize>; 256] {
    let mut table: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
    for (idx, first) in keys {
        table[first as usize].push(idx);
    }
    table
}

/// One pass looking for every needle's difference signature under `op`.
fn scan_delta(data: &[u8], needles: &[&str], op: Op, hits: &mut Vec<Hit>, max_hits: usize) {
    let usable: Vec<(usize, &[u8])> = needles
        .iter()
        .enumerate()
        .map(|(i, n)| (i, n.as_bytes()))
        .filter(|(_, b)| b.len() >= 2 && b.len() <= data.len())
        .collect();
    if usable.is_empty() || data.len() < 2 {
        return;
    }
    let table = bucket_by_first(
        usable.iter().map(|(i, b)| (*i, delta(op, b[0], b[1]))),
    );
    let by_idx: std::collections::BTreeMap<usize, &[u8]> = usable.into_iter().collect();

    for at in 0..data.len() - 1 {
        let d = delta(op, data[at], data[at + 1]);
        for &ni in &table[d as usize] {
            let plain = by_idx[&ni];
            if at + plain.len() > data.len() {
                continue;
            }
            let matched = data[at..at + plain.len()]
                .windows(2)
                .zip(plain.windows(2))
                .all(|(w, p)| delta(op, w[0], w[1]) == delta(op, p[0], p[1]));
            if !matched {
                continue;
            }
            // The signature matched; the key is whatever maps plain[0] to data[at].
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
            // Key 0 is the identity — that string is not hidden, `strings` has it.
            if key == 0 {
                continue;
            }
            hits.push(Hit {
                offset: at as u64,
                op,
                key,
                needle: needles[ni].to_string(),
                preview: decode_preview(data, at, op, key),
            });
            if hits.len() >= max_hits {
                return;
            }
        }
    }
}

/// One pass per rotation key, all needles at once.
fn scan_rotations(data: &[u8], needles: &[&str], hits: &mut Vec<Hit>, max_hits: usize) {
    for key in 1..=7u8 {
        let encoded: Vec<(usize, Vec<u8>)> = needles
            .iter()
            .enumerate()
            .filter(|(_, n)| !n.is_empty() && n.len() <= data.len())
            .map(|(i, n)| (i, n.bytes().map(|b| Op::Rol.encode(b, key)).collect()))
            .collect();
        if encoded.is_empty() {
            return;
        }
        let table = bucket_by_first(encoded.iter().map(|(i, e)| (*i, e[0])));
        let by_idx: std::collections::BTreeMap<usize, &Vec<u8>> =
            encoded.iter().map(|(i, e)| (*i, e)).collect();

        for at in 0..data.len() {
            for &ni in &table[data[at] as usize] {
                let want = by_idx[&ni];
                if at + want.len() > data.len() || &data[at..at + want.len()] != want.as_slice() {
                    continue;
                }
                hits.push(Hit {
                    offset: at as u64,
                    op: Op::Rol,
                    key,
                    needle: needles[ni].to_string(),
                    preview: decode_preview(data, at, Op::Rol, key),
                });
                if hits.len() >= max_hits {
                    return;
                }
            }
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
