//! One-pass, case-insensitive, multi-pattern byte scanning.
//!
//! Searching a file once per rule is quadratic in the size of the rule table,
//! and building a lowercase copy of a 23 MB PDF to make the search
//! case-insensitive costs more than the search itself. This walks the data once,
//! using a first-byte bucket to decide which rules are even worth comparing at
//! each position.
//!
//! It also keeps *every* hit rather than a count. A finding that says "300
//! occurrences" is only useful if you can then look at the three hundred.

/// Where one pattern matched.
#[derive(Clone, Debug)]
pub struct Hit {
    /// Index into the pattern list that was passed in.
    pub pattern: usize,
    pub offset: u64,
}

fn fold(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

/// Find every occurrence of every pattern, case-insensitively.
///
/// `max_per_pattern` bounds a pathological file (a PDF with a million `/URI`s
/// is a denial of service, not a document); `0` means unlimited.
pub fn scan(data: &[u8], patterns: &[&[u8]], max_per_pattern: usize) -> Vec<Hit> {
    let mut buckets: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
    for (i, p) in patterns.iter().enumerate() {
        if let Some(&first) = p.first() {
            buckets[fold(first) as usize].push(i);
            // An upper-case first byte lands in the same bucket once folded, so
            // one entry per pattern is enough.
        }
    }

    let mut counts = vec![0usize; patterns.len()];
    let mut hits = Vec::new();
    for at in 0..data.len() {
        let candidates = &buckets[fold(data[at]) as usize];
        if candidates.is_empty() {
            continue;
        }
        for &i in candidates {
            if max_per_pattern > 0 && counts[i] >= max_per_pattern {
                continue;
            }
            let p = patterns[i];
            if at + p.len() > data.len() {
                continue;
            }
            if data[at..at + p.len()]
                .iter()
                .zip(p)
                .all(|(a, b)| fold(*a) == fold(*b))
            {
                counts[i] += 1;
                hits.push(Hit {
                    pattern: i,
                    offset: at as u64,
                });
            }
        }
    }
    hits
}

/// A printable excerpt starting at `offset`, for showing what a hit actually is
/// — the URL, not just "there is a URL here".
pub fn preview(data: &[u8], offset: u64, len: usize) -> String {
    let start = offset as usize;
    let end = (start + len).min(data.len());
    data.get(start..end)
        .map(|s| {
            s.iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        ' '
                    }
                })
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_every_occurrence_of_every_pattern() {
        let data = b"/URI (a) /uri (b) /JS x /URI (c)";
        let pats: Vec<&[u8]> = vec![b"/URI", b"/JS"];
        let hits = scan(data, &pats, 0);
        let uris: Vec<u64> = hits
            .iter()
            .filter(|h| h.pattern == 0)
            .map(|h| h.offset)
            .collect();
        assert_eq!(uris, vec![0, 9, 24], "case-insensitive, and all of them");
        assert_eq!(hits.iter().filter(|h| h.pattern == 1).count(), 1);
    }

    #[test]
    fn respects_the_per_pattern_cap() {
        let data = b"aaaaaaaaaa";
        let pats: Vec<&[u8]> = vec![b"a"];
        assert_eq!(scan(data, &pats, 3).len(), 3);
        assert_eq!(scan(data, &pats, 0).len(), 10);
    }

    #[test]
    fn preview_shows_the_text_not_the_bytes() {
        let data = b"/URI (http://example.top/a)\x00\x00binary";
        assert!(preview(data, 0, 26).contains("http://example.top/a"));
    }

    #[test]
    fn empty_inputs_are_safe() {
        assert!(scan(b"", &[b"x"], 0).is_empty());
        assert!(scan(b"xxx", &[], 0).is_empty());
        assert_eq!(preview(b"", 5, 10), "");
    }
}
