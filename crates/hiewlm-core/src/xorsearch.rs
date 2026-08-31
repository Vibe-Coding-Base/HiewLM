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
    let table = bucket_by_first(usable.iter().map(|(i, b)| (*i, delta(op, b[0], b[1]))));
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
    let limit = if max_bytes == 0 {
        buf.len()
    } else {
        max_bytes.min(buf.len())
    };
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

/// A candidate repeating XOR key recovered from a block.
#[derive(Clone, Debug)]
pub struct KeyCandidate {
    pub key: Vec<u8>,
    /// Fraction of the block that decodes to printable text (0..1) — the number
    /// to show an analyst.
    pub score: f32,
    /// Average log-likelihood per byte under the plaintext model, minus what the
    /// key itself costs to describe. Higher is better. Charging for the key is
    /// what stops a long key from always winning: it has a free parameter per
    /// byte, so it fits anything if you let it.
    pub fit: f32,
    /// The start of the decoded block, for eyeballing the answer.
    pub preview: String,
}

impl KeyCandidate {
    /// The key as a `crypt`/lens recipe (`xor deadbeef`).
    pub fn recipe(&self) -> String {
        let hex: String = self.key.iter().map(|b| format!("{b:02x}")).collect();
        format!("xor {hex}")
    }

    /// The same recipe rotated so it lines up when applied at absolute file
    /// offsets rather than from the block start.
    ///
    /// The lens indexes the key by file offset, but the key was recovered
    /// relative to `block_start`; without this the decode is right only when the
    /// block happens to begin on a key boundary.
    pub fn recipe_at(&self, block_start: u64) -> String {
        let n = self.key.len();
        if n == 0 {
            return "xor 00".into();
        }
        let shift = (block_start % n as u64) as usize;
        let rotated: Vec<u8> = (0..n).map(|j| self.key[(j + n - shift) % n]).collect();
        let hex: String = rotated.iter().map(|b| format!("{b:02x}")).collect();
        format!("xor {hex}")
    }
}

/// Relative frequency of a byte in the kind of plaintext that hides behind an
/// XOR key: URLs, key=value configuration, Windows paths, NUL padding.
///
/// Flat "is it printable" scoring is not enough to pick a key — with a short
/// column, many wrong keys also decode to printable bytes. Weighting by how
/// *likely* each byte is separates the real key from the merely-printable ones.
fn byte_weight(b: u8) -> f32 {
    // The arms are deliberately ordered specific-to-general: the named bytes
    // carry their own weight and the trailing printable range catches whatever
    // is left. Rust takes the first match, which is exactly what is wanted.
    #[allow(clippy::match_overlapping_arm)]
    match b {
        b' ' => 15.0,
        b'e' => 12.0,
        b't' => 9.0,
        b'a' => 8.0,
        b'o' => 7.5,
        b'i' | b'n' => 7.0,
        b's' => 6.5,
        b'r' => 6.0,
        b'h' => 5.0,
        b'l' | b'd' => 4.0,
        b'c' | b'u' => 3.0,
        b'm' => 2.5,
        b'p' | b'f' | b'g' | b'w' | b'y' => 2.0,
        b'b' => 1.5,
        b'v' => 1.0,
        b'k' => 0.8,
        b'x' => 0.3,
        b'j' | b'q' | b'z' => 0.2,
        b'0'..=b'9' => 2.0,
        b'.' => 3.0,
        b'/' => 2.0,
        b':' | b'=' | b'-' => 1.5,
        b'_' => 1.0,
        b';' | b',' | b'\\' => 0.8,
        b'%' | b'&' | b'?' => 0.5,
        b'"' => 0.4,
        b'@' | b'+' | b'(' | b')' | b'\'' | b'!' => 0.3,
        b'*' | b'#' | b'$' => 0.2,
        b'A'..=b'Z' => 0.6,
        0x00 => 4.0,
        b'\t' | b'\r' | b'\n' => 0.5,
        0x20..=0x7e => 0.1,
        // Anything else is not plaintext; the log of this is a heavy penalty.
        _ => 0.0005,
    }
}

/// Log-likelihood of a decoded byte under [`byte_weight`].
fn log_likelihood(b: u8) -> f32 {
    byte_weight(b).ln()
}

/// Share of a decoded block that looks like plaintext, for display.
fn printable_fraction(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let good = data
        .iter()
        .filter(|&&b| (0x20..0x7f).contains(&b) || b == 0 || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    good as f32 / data.len() as f32
}

/// Recover repeating-XOR keys from a block.
///
/// A single-byte key is the textbook case; real configuration blobs usually use
/// a short repeating one. For every candidate length, each key column is chosen
/// independently as the byte that decodes its column into the most plaintext —
/// no frequency assumptions beyond "the answer looks like text or NUL padding".
///
/// Returns the best `top` candidates, longest-explaining first. Keys that are
/// just a shorter key repeated are collapsed into the shorter one.
pub fn infer_repeating_key(data: &[u8], max_len: usize, top: usize) -> Vec<KeyCandidate> {
    if data.len() < 8 || max_len == 0 {
        return Vec::new();
    }
    // Bounded so an accidental "select the whole file" stays interactive.
    let data = &data[..data.len().min(64 * 1024)];
    let mut candidates: Vec<KeyCandidate> = Vec::new();

    // Each key column is chosen from its own samples, so a longer key always
    // fits at least as well — it has more free parameters. Two guards keep that
    // from making the answer "the longest key you allowed": a column needs real
    // evidence behind it, and the key is charged for in the score (see `fit`).
    const MIN_SAMPLES_PER_COLUMN: usize = 8;
    let effective_max = max_len.min(data.len() / MIN_SAMPLES_PER_COLUMN).max(1);

    for len in 1..=effective_max {
        let mut key = Vec::with_capacity(len);
        let mut total = 0.0f32;
        let mut counted = 0usize;
        for col in 0..len {
            let column: Vec<u8> = data.iter().skip(col).step_by(len).copied().collect();
            if column.is_empty() {
                key.push(0);
                continue;
            }
            let (best_k, best_score) = (0u16..256)
                .map(|k| {
                    let k = k as u8;
                    let s: f32 = column.iter().map(|&b| log_likelihood(b ^ k)).sum();
                    (k, s)
                })
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or((0, 0.0));
            key.push(best_k);
            total += best_score;
            counted += column.len();
        }
        if counted == 0 {
            continue;
        }
        // Minimum-description-length: the average log-likelihood per byte, minus
        // the ~ln(256) nats each key byte costs, amortised over the block. A
        // longer key must earn its extra parameters.
        const KEY_BYTE_COST: f32 = 5.545;
        let fit = (total - KEY_BYTE_COST * len as f32) / counted as f32;
        let decoded: Vec<u8> = data
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        candidates.push(KeyCandidate {
            key: shrink(&key),
            fit,
            score: printable_fraction(&decoded),
            preview: decoded
                .iter()
                .take(72)
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect(),
        });
    }

    // Ties (within a whisker on the description length) go to the shorter key.
    const MARGIN: f32 = 0.02;
    let best = candidates.iter().map(|c| c.fit).fold(f32::MIN, f32::max);
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by(|&a, &b| {
        let (ca, cb) = (&candidates[a], &candidates[b]);
        let near = |c: &KeyCandidate| c.fit >= best - MARGIN;
        match (near(ca), near(cb)) {
            (true, true) => ca.key.len().cmp(&cb.key.len()),
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (false, false) => cb
                .fit
                .partial_cmp(&ca.fit)
                .unwrap_or(std::cmp::Ordering::Equal),
        }
    });
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(top);
    for i in order {
        let c = &candidates[i];
        if !c.key.is_empty() && seen.insert(c.key.clone()) {
            out.push(c.clone());
        }
        if out.len() >= top {
            break;
        }
    }
    out
}

/// Collapse a key that is a shorter key repeated (`abab` -> `ab`).
fn shrink(key: &[u8]) -> Vec<u8> {
    for period in 1..=key.len() / 2 {
        if key.len() % period == 0 && key.chunks(period).all(|c| c == &key[..period]) {
            return key[..period].to_vec();
        }
    }
    key.to_vec()
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
        let hit = hits
            .iter()
            .find(|h| h.op == Op::Xor && h.key == 0x5a)
            .expect("xor 5a hit");
        assert!(
            hit.preview.contains("http://c2.example.top"),
            "{}",
            hit.preview
        );
        assert_eq!(hit.recipe(), "xor 5a");
    }

    #[test]
    fn finds_add_and_rol_encodings() {
        let plain = b"xx https://evil.top/x";
        let added: Vec<u8> = plain.iter().map(|&b| b.wrapping_add(7)).collect();
        assert!(search(&added, &DEFAULT_NEEDLES, 32)
            .iter()
            .any(|h| h.op == Op::Add && h.key == 7));
        let rolled: Vec<u8> = plain.iter().map(|&b| b.rotate_left(3)).collect();
        assert!(search(&rolled, &DEFAULT_NEEDLES, 32)
            .iter()
            .any(|h| h.op == Op::Rol && h.key == 3));
    }

    #[test]
    fn key_recovered_from_known_plaintext() {
        let data: Vec<u8> = b"MZ\x90\x00".iter().map(|&b| b ^ 0x37).collect();
        assert!(key_from_known(&data, 0, "MZ").contains(&(Op::Xor, 0x37)));
    }

    /// A configuration blob of the size these actually are. Recovery is a
    /// statistical argument: each key column is decided by its own samples, so
    /// how much data there is decides how exactly the key comes back.
    const CONFIG: &[u8] = b"host=c2.example.top;port=443;id=BOT-0007;interval=60;retry=5;\
path=/gate.php;ua=Mozilla/5.0 (Windows NT 10.0; Win64; x64);key=0123456789abcdef;\
mutex=Global\\SessionLock77;persist=SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run;\
drop=%APPDATA%\\svc.exe;fallback=http://backup.example.top/p.php;sleep=300;jitter=15;";

    fn xored(plain: &[u8], key: &[u8]) -> Vec<u8> {
        plain
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect()
    }

    #[test]
    fn recovers_a_repeating_key_from_a_config_blob() {
        let key = b"S3cr3t!";
        let cands = infer_repeating_key(&xored(CONFIG, key), 20, 4);
        let best = cands.first().expect("a candidate");
        assert_eq!(
            best.key,
            key,
            "recovered {:?}",
            String::from_utf8_lossy(&best.key)
        );
        assert!(best.score > 0.95, "printable fraction {}", best.score);
        assert!(
            best.preview.starts_with("host=c2.example.top"),
            "{}",
            best.preview
        );
        assert_eq!(best.recipe(), "xor 53336372337421");
    }

    #[test]
    fn recovers_a_long_key_without_inventing_a_longer_one() {
        // The length is the part that must be exact — get it wrong and nothing
        // decodes. With ~20 samples per column a stray byte can still be missed,
        // so the assertion is "the right length, near-exact bytes, readable
        // output", which is what the tool actually promises.
        let key = b"longer-key-16byt";
        let best = infer_repeating_key(&xored(CONFIG, key), 24, 1)
            .into_iter()
            .next()
            .expect("candidate");
        assert_eq!(
            best.key.len(),
            key.len(),
            "recovered a key of the wrong length"
        );
        let wrong = best.key.iter().zip(key).filter(|(a, b)| a != b).count();
        assert!(
            wrong <= 1,
            "{wrong} key bytes wrong: {:?}",
            String::from_utf8_lossy(&best.key)
        );
        assert!(best.score > 0.95, "printable fraction {}", best.score);
    }

    #[test]
    fn single_byte_key_is_not_padded_into_a_longer_one() {
        // The danger with per-column fitting: a 1-byte key has one parameter and
        // a 6-byte key has six, so the longer one always fits better unless it is
        // charged for.
        let plain = b"https://one.example.top/path?q=1&r=2 and some more plain text here";
        let best = infer_repeating_key(&xored(plain, &[0x5a]), 8, 1)
            .into_iter()
            .next()
            .expect("candidate");
        assert_eq!(best.key, vec![0x5a]);
    }

    #[test]
    fn short_block_still_decodes_to_text() {
        // 64 bytes is too few samples per column to pin every key byte. The
        // guarantee that survives is the useful one: the block decodes to
        // something plainly textual, which is what the analyst reads before
        // marking a bigger block and trying again.
        let key = b"S3cr3t!";
        let short = &xored(CONFIG, key)[..64];
        let best = infer_repeating_key(short, 16, 3)
            .into_iter()
            .next()
            .expect("candidate");
        assert!(
            best.score > 0.9,
            "printable fraction {} — {}",
            best.score,
            best.preview
        );
    }

    #[test]
    fn repeated_key_is_collapsed_to_its_period() {
        assert_eq!(shrink(&[1, 2, 1, 2, 1, 2]), vec![1, 2]);
        assert_eq!(shrink(&[1, 2, 3]), vec![1, 2, 3]);
    }

    #[test]
    fn recipe_is_rotated_to_the_block_offset() {
        let c = KeyCandidate {
            key: vec![0xaa, 0xbb, 0xcc],
            score: 1.0,
            fit: 0.0,
            preview: String::new(),
        };
        // Applied from the block start, the key reads aa bb cc.
        assert_eq!(c.recipe(), "xor aabbcc");
        // A block starting at offset 1 must present the key rotated, so that the
        // lens (which indexes by file offset) uses aa at offset 1.
        assert_eq!(c.recipe_at(1), "xor ccaabb");
        assert_eq!(c.recipe_at(3), "xor aabbcc");
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
        assert!(
            hits.iter().any(|h| h.key == 0x11 && h.op == Op::Xor),
            "{hits:?}"
        );
    }
}
