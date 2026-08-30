//! ssdeep-compatible fuzzy hashing (spamsum), in pure Rust.
//!
//! Cryptographic hashes answer "is this the same file"; triage needs "is this
//! the same family". A fuzzy hash survives repacking, config swaps and appended
//! junk, so a folder of samples can be clustered before anything is opened.
//!
//! Implements the classic spamsum construction ssdeep uses, so digests are
//! comparable with ssdeep output from other tools.

const SPAMSUM_LENGTH: usize = 64;
const MIN_BLOCKSIZE: u32 = 3;
const ROLLING_WINDOW: usize = 7;
const HASH_PRIME: u32 = 0x0100_0193;
const HASH_INIT: u32 = 0x2802_1967;
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The rolling hash that decides where a block ends: content-defined chunking is
/// what makes the digest survive insertions.
#[derive(Default)]
struct Roll {
    window: [u8; ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl Roll {
    fn update(&mut self, c: u8) -> u32 {
        self.h2 = self.h2.wrapping_sub(self.h1);
        self.h2 = self.h2.wrapping_add((ROLLING_WINDOW as u32).wrapping_mul(c as u32));
        self.h1 = self.h1.wrapping_add(c as u32);
        self.h1 = self.h1.wrapping_sub(self.window[self.n] as u32);
        self.window[self.n] = c;
        self.n = (self.n + 1) % ROLLING_WINDOW;
        self.h3 = self.h3 << 5;
        self.h3 ^= c as u32;
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

fn sum_hash(c: u8, h: u32) -> u32 {
    h.wrapping_mul(HASH_PRIME) ^ c as u32
}

/// The ssdeep digest of `data`, as `blocksize:hash1:hash2`.
pub fn ssdeep(data: &[u8]) -> String {
    let mut bs = MIN_BLOCKSIZE;
    while (bs as u64) * (SPAMSUM_LENGTH as u64) < data.len() as u64 {
        bs *= 2;
    }

    loop {
        let mut roll = Roll::default();
        let (mut h1, mut h2) = (HASH_INIT, HASH_INIT);
        let mut sig1 = Vec::with_capacity(SPAMSUM_LENGTH);
        let mut sig2 = Vec::with_capacity(SPAMSUM_LENGTH / 2);
        let mut rh = 0u32;

        for &c in data {
            rh = roll.update(c);
            h1 = sum_hash(c, h1);
            h2 = sum_hash(c, h2);
            if rh % bs == bs - 1 && sig1.len() < SPAMSUM_LENGTH - 1 {
                sig1.push(B64[(h1 % 64) as usize]);
                h1 = HASH_INIT;
            }
            if rh % (bs * 2) == bs * 2 - 1 && sig2.len() < SPAMSUM_LENGTH / 2 - 1 {
                sig2.push(B64[(h2 % 64) as usize]);
                h2 = HASH_INIT;
            }
        }
        if rh != 0 {
            sig1.push(B64[(h1 % 64) as usize]);
            sig2.push(B64[(h2 % 64) as usize]);
        }

        // Too few pieces to be meaningful: halve the block size and retry.
        if bs > MIN_BLOCKSIZE && sig1.len() < SPAMSUM_LENGTH / 2 {
            bs /= 2;
            continue;
        }
        return format!(
            "{bs}:{}:{}",
            String::from_utf8_lossy(&sig1),
            String::from_utf8_lossy(&sig2)
        );
    }
}

/// Similarity of two ssdeep digests, 0..100. 0 means "not comparable or nothing
/// in common"; anything above ~50 is worth looking at as the same family.
pub fn compare(a: &str, b: &str) -> u32 {
    let Some((bs1, a1, a2)) = split(a) else { return 0 };
    let Some((bs2, b1, b2)) = split(b) else { return 0 };
    if bs1 == 0 || bs2 == 0 {
        return 0;
    }
    // Only digests within one doubling of each other can be compared.
    if bs1 != bs2 && bs1 != bs2 * 2 && bs2 != bs1 * 2 {
        return 0;
    }
    let (a1, a2) = (elide(a1), elide(a2));
    let (b1, b2) = (elide(b1), elide(b2));
    if bs1 == bs2 {
        if a1 == b1 && a2 == b2 {
            return 100;
        }
        score(&a1, &b1, bs1).max(score(&a2, &b2, bs1.saturating_mul(2)))
    } else if bs1 == bs2 * 2 {
        score(&a1, &b2, bs1)
    } else {
        score(&a2, &b1, bs2)
    }
}

fn split(s: &str) -> Option<(u32, &str, &str)> {
    let mut it = s.splitn(3, ':');
    let bs = it.next()?.parse::<u32>().ok()?;
    let h1 = it.next()?;
    // The second half may carry a ",filename" comment, as ssdeep files do.
    let h2 = it.next()?.split(',').next().unwrap_or("");
    Some((bs, h1, h2))
}

/// Collapse runs of more than three identical characters, as ssdeep does before
/// comparing, so long repeats do not dominate the edit distance.
fn elide(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = 0;
    let mut prev = None;
    for c in s.chars() {
        if Some(c) == prev {
            run += 1;
        } else {
            run = 1;
            prev = Some(c);
        }
        if run <= 3 {
            out.push(c);
        }
    }
    out
}

/// Do the two strings share a substring of at least ROLLING_WINDOW characters?
/// ssdeep requires this before scoring, to reject coincidental similarity.
fn has_common_substring(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() < ROLLING_WINDOW || b.len() < ROLLING_WINDOW {
        return false;
    }
    a.windows(ROLLING_WINDOW).any(|w| b.windows(ROLLING_WINDOW).any(|v| v == w))
}

/// Levenshtein distance with ssdeep's weights: 1 for insert/delete, 3 for change.
fn edit_distance(a: &str, b: &str) -> u32 {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut prev: Vec<u32> = (0..=b.len() as u32).collect();
    let mut cur = vec![0u32; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i as u32 + 1;
        for (j, &cb) in b.iter().enumerate() {
            let sub = prev[j] + if ca == cb { 0 } else { 3 };
            cur[j + 1] = sub.min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

fn score(a: &str, b: &str, block_size: u32) -> u32 {
    if a.is_empty() || b.is_empty() || !has_common_substring(a, b) {
        return 0;
    }
    let d = edit_distance(a, b);
    let total = (a.len() + b.len()) as u32;
    let mut s = d * SPAMSUM_LENGTH as u32 / total;
    s = s * 100 / SPAMSUM_LENGTH as u32;
    s = 100u32.saturating_sub(s);
    // Short block sizes cannot support a high score (ssdeep's match cap).
    let cap = (block_size / MIN_BLOCKSIZE).saturating_mul(a.len().min(b.len()) as u32);
    s.min(cap).min(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(seed: u8, n: usize) -> Vec<u8> {
        // Deterministic pseudo-random bytes: real content, not a constant run.
        let mut v = Vec::with_capacity(n);
        let mut x = seed as u32 | 1;
        for _ in 0..n {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            v.push((x >> 16) as u8);
        }
        v
    }

    #[test]
    fn digest_has_three_fields() {
        let d = ssdeep(&pattern(1, 8192));
        let parts: Vec<&str> = d.split(':').collect();
        assert_eq!(parts.len(), 3, "{d}");
        assert!(parts[0].parse::<u32>().is_ok());
        assert!(!parts[1].is_empty());
    }

    #[test]
    fn identical_input_scores_100() {
        let d = ssdeep(&pattern(7, 20_000));
        assert_eq!(compare(&d, &d), 100);
    }

    #[test]
    fn small_edit_stays_similar() {
        let base = pattern(9, 20_000);
        let mut edited = base.clone();
        // Change a handful of bytes, as a repacked build of the same family would.
        for i in (100..200).step_by(7) {
            edited[i] ^= 0xff;
        }
        let s = compare(&ssdeep(&base), &ssdeep(&edited));
        assert!(s > 50, "similar files should score high, got {s}");
    }

    #[test]
    fn unrelated_inputs_score_low() {
        let s = compare(&ssdeep(&pattern(1, 20_000)), &ssdeep(&pattern(200, 20_000)));
        assert!(s < 30, "unrelated files should score low, got {s}");
    }

    #[test]
    fn empty_and_malformed_are_safe() {
        assert!(!ssdeep(b"").is_empty());
        assert_eq!(compare("", ""), 0);
        assert_eq!(compare("3:abc", "3:abc:def"), 0);
    }
}
