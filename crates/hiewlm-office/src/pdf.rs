//! PDF structure and active content.
//!
//! PDF earns a place next to the Office formats because it is the same problem:
//! a container whose structure is the evidence. The object map says what is in
//! the file and where, and a short list of names says what it will do when
//! opened — `/OpenAction` with `/JS` is the whole verdict.
//!
//! Streams are never decompressed and no action is followed, so the analysis is
//! of what the file *declares*. Two consequences are reported rather than
//! hidden: objects inside `/ObjStm` are not enumerated, and JavaScript inside a
//! compressed stream is not visible to the marker scan.

use hiewlm_core::{Finding, Severity};

/// The header must appear within the first 1 KiB (PDF 1.7 §7.5.2).
const HEADER_WINDOW: usize = 1024;
/// Cap structural scanning so a huge file cannot stall the UI.
const SCAN_CAP: usize = 64 * 1024 * 1024;
/// A document with a million `/URI`s is a denial of service, not a document.
const MAX_HITS_PER_RULE: usize = 2000;

/// One indirect object: `12 0 obj`.
#[derive(Clone, Debug)]
pub struct Object {
    pub number: u32,
    pub generation: u32,
    pub offset: u64,
    /// `/Type` value when the object declares one, for the structure listing.
    pub kind: String,
}

/// Every hit of one rule, with an excerpt of each — what turns "300 occurrences"
/// into a list you can read.
#[derive(Clone, Debug)]
pub struct MatchGroup {
    pub label: String,
    pub hits: Vec<(u64, String)>,
}

#[derive(Clone, Debug, Default)]
pub struct Pdf {
    /// Offset of `%PDF-`; non-zero means something precedes it.
    pub header_off: u64,
    pub version: String,
    pub objects: Vec<Object>,
    /// `%%EOF` count — more than one means incremental updates.
    pub revisions: usize,
    pub findings: Vec<Finding>,
    /// `(key, value)` from the trailer and the document info, when readable.
    pub metadata: Vec<(String, String)>,
    pub match_groups: Vec<MatchGroup>,
}

pub fn is_pdf(bytes: &[u8]) -> bool {
    header_at(bytes).is_some()
}

/// Offset of the `%PDF-` header. The spec tolerates leading bytes and malware
/// exploits that, so the whole window is searched rather than only offset 0.
fn header_at(bytes: &[u8]) -> Option<usize> {
    let win = &bytes[..bytes.len().min(HEADER_WINDOW)];
    find_from(win, b"%PDF-", 0)
}

fn find_from(hay: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() || start >= hay.len() {
        return None;
    }
    hay[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

fn count_occurrences(hay: &[u8], needle: &[u8]) -> (usize, Option<usize>) {
    let (mut n, mut first, mut at) = (0usize, None, 0usize);
    while let Some(p) = find_from(hay, needle, at) {
        if first.is_none() {
            first = Some(p);
        }
        n += 1;
        at = p + needle.len();
        if n >= 100_000 {
            break;
        }
    }
    (n, first)
}

/// Scan for `N G obj` indirect-object headers.
fn scan_objects(bytes: &[u8]) -> Vec<Object> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(p) = find_from(bytes, b"obj", at) {
        at = p + 3;
        // `obj` must be a token, not the tail of a longer name.
        if bytes.get(p + 3).is_some_and(|b| b.is_ascii_alphanumeric()) {
            continue;
        }
        // Walk back: whitespace, generation digits, whitespace, object number.
        let mut i = p;
        while i > 0 && bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        let gen_end = i;
        while i > 0 && bytes[i - 1].is_ascii_digit() {
            i -= 1;
        }
        let gen_start = i;
        if gen_start == gen_end {
            continue;
        }
        while i > 0 && bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        let num_end = i;
        while i > 0 && bytes[i - 1].is_ascii_digit() {
            i -= 1;
        }
        if i == num_end {
            continue;
        }
        let number = std::str::from_utf8(&bytes[i..num_end])
            .ok()
            .and_then(|s| s.parse().ok());
        let generation = std::str::from_utf8(&bytes[gen_start..gen_end])
            .ok()
            .and_then(|s| s.parse().ok());
        let (Some(number), Some(generation)) = (number, generation) else {
            continue;
        };

        // The object's `/Type`, when it declares one within a short window.
        let end = (p + 512).min(bytes.len());
        let head = &bytes[p..end];
        let kind = find_from(head, b"/Type", 0)
            .map(|t| {
                head[t + 5..]
                    .iter()
                    .skip_while(|b| b.is_ascii_whitespace() || **b == b'/')
                    .take_while(|b| b.is_ascii_alphanumeric())
                    .map(|&b| b as char)
                    .collect::<String>()
            })
            .unwrap_or_default();

        out.push(Object {
            number,
            generation,
            offset: i as u64,
            kind,
        });
        if out.len() >= 100_000 {
            break;
        }
    }
    out
}

/// Is the byte at `at` a PDF name terminator? A name runs until whitespace or
/// one of the delimiter characters (PDF 1.7 §7.2.2).
fn name_ends_at(bytes: &[u8], at: usize) -> bool {
    match bytes.get(at) {
        None => true,
        Some(b) => b.is_ascii_whitespace() || b"()<>[]{}/%".contains(b),
    }
}

/// A PDF name written with hex escapes (`/J#61vaScript`) is obfuscation: the
/// spec allows it, readers accept it, and nothing legitimate needs it.
fn obfuscated_names(bytes: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(p) = find_from(bytes, b"/", at) {
        at = p + 1;
        let end = (p + 40).min(bytes.len());
        if let Some(h) = bytes[p..end].iter().position(|&b| b == b'#') {
            // `#` must be followed by two hex digits to be an escape.
            let i = p + h;
            if bytes.get(i + 1).is_some_and(|b| b.is_ascii_hexdigit())
                && bytes.get(i + 2).is_some_and(|b| b.is_ascii_hexdigit())
            {
                out.push(p as u64);
                if out.len() >= 64 {
                    break;
                }
            }
        }
    }
    out
}

pub fn parse(bytes: &[u8]) -> Option<Pdf> {
    let header_off = header_at(bytes)?;
    let scan = &bytes[..bytes.len().min(SCAN_CAP)];
    let mut p = Pdf {
        header_off: header_off as u64,
        ..Default::default()
    };

    p.version = bytes
        .get(header_off + 5..header_off + 8)
        .map(|v| String::from_utf8_lossy(v).trim().to_string())
        .unwrap_or_default();
    p.objects = scan_objects(scan);
    p.revisions = count_occurrences(scan, b"%%EOF").0;

    // Data before the header: a polyglot, or a payload with a PDF glued on.
    if header_off > 0 {
        p.findings.push(
            Finding::suspicious(format!(
                "{header_off} bytes precede the %PDF- header (polyglot or prepended data)"
            ))
            .at(0),
        );
    }
    // More than one header is the same trick from the other direction.
    let (headers, _) = count_occurrences(scan, b"%PDF-");
    if headers > 1 {
        p.findings.push(Finding::suspicious(format!(
            "{headers} %PDF- headers — the file contains more than one document"
        )));
    }

    // Active content and historically-abused features, from the rule table.
    //
    // One pass over the file for the whole table: searching once per rule, and
    // lowercasing 23 MB of PDF to make the search case-insensitive, cost more
    // than everything else in this function put together.
    let rules = crate::rules::rules("pdf");
    let patterns: Vec<&[u8]> = rules.iter().map(|r| r.value.as_bytes()).collect();
    let hits = crate::scan::scan(scan, &patterns, MAX_HITS_PER_RULE);
    for (i, rule) in rules.iter().enumerate() {
        let is_name = rule.value.starts_with('/');
        let offsets: Vec<u64> = hits
            .iter()
            .filter(|h| h.pattern == i)
            // A PDF name ends at a delimiter. Without this, `/AA` matches inside
            // the font subset name `/AAAAAA+ArialMT` — 278 times in one real
            // document — and reports auto-run actions that are not there.
            .filter(|h| !is_name || name_ends_at(scan, h.offset as usize + rule.value.len()))
            .map(|h| h.offset)
            .collect();
        if offsets.is_empty() {
            continue;
        }
        let msg = if offsets.len() > 1 {
            format!(
                "{}: {} ({} occurrences)",
                rule.value,
                rule.note,
                offsets.len()
            )
        } else {
            format!("{}: {}", rule.value, rule.note)
        };
        p.findings.push(Finding {
            severity: rule.severity,
            message: msg,
            offset: offsets.first().copied(),
        });
        // Keep every hit with an excerpt, so "300 occurrences" can be opened.
        p.match_groups.push(MatchGroup {
            label: rule.value.clone(),
            hits: offsets
                .iter()
                .map(|&o| (o, crate::scan::preview(scan, o, 140)))
                .collect(),
        });
    }

    // Auto-run plus script is the combination that matters, not either alone.
    let seen: Vec<String> = p.findings.iter().map(|f| f.message.clone()).collect();
    let has = |needle: &str| seen.iter().any(|m| m.starts_with(needle));
    if (has("/OpenAction") || has("/AA")) && (has("/JavaScript") || has("/JS")) {
        p.findings.push(Finding::suspicious(
            "JavaScript that runs on open — no interaction required",
        ));
    }
    if has("/Launch") || has("/EmbeddedFile") {
        p.findings.push(Finding::suspicious(
            "the document carries or launches something other than a page",
        ));
    }

    // One is enough to say it; the offset points at the first.
    if let Some(off) = obfuscated_names(scan).first() {
        p.findings.push(
            Finding::suspicious("PDF name written with #hex escapes — deliberate obfuscation")
                .at(*off),
        );
    }

    if p.revisions > 1 {
        p.findings.push(Finding::info(format!(
            "{} revisions (incremental updates) — earlier content is still in the file",
            p.revisions
        )));
    }
    if p.objects.is_empty() {
        p.findings.push(Finding::suspicious(
            "no indirect objects found — malformed, or everything is inside object streams",
        ));
    }
    if has("/ObjStm") {
        p.findings.push(Finding::info(
            "objects inside /ObjStm are not enumerated (streams are never decompressed)",
        ));
    }
    if bytes.len() > SCAN_CAP {
        p.findings.push(Finding::info(
            "file larger than the scan cap; results are partial",
        ));
    }

    p.metadata
        .push(("Version".into(), format!("PDF-{}", p.version)));
    p.metadata
        .push(("Objects".into(), p.objects.len().to_string()));
    p.metadata
        .push(("Revisions".into(), p.revisions.to_string()));
    Some(p)
}

/// Severity of the worst finding, for the caller's summary.
pub fn worst(p: &Pdf) -> Severity {
    if p.findings
        .iter()
        .any(|f| f.severity == Severity::Suspicious)
    {
        Severity::Suspicious
    } else {
        Severity::Info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &[u8] = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Count 1 >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";

    #[test]
    fn maps_objects_with_their_offsets() {
        let p = parse(CLEAN).expect("pdf");
        assert_eq!(p.version, "1.4");
        assert_eq!(p.objects.len(), 2);
        assert_eq!(p.objects[0].number, 1);
        assert_eq!(p.objects[0].kind, "Catalog");
        assert_eq!(&CLEAN[p.objects[0].offset as usize..][..5], b"1 0 o");
        assert!(
            !p.findings
                .iter()
                .any(|f| f.severity == Severity::Suspicious),
            "{:?}",
            p.findings
        );
    }

    #[test]
    fn javascript_that_runs_on_open_is_called_out() {
        let doc = b"%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.launchURL) >> >>\nendobj\n%%EOF";
        let p = parse(doc).expect("pdf");
        assert!(
            p.findings
                .iter()
                .any(|f| f.message.contains("runs on open")),
            "{:?}",
            p.findings
        );
        assert!(p
            .findings
            .iter()
            .any(|f| f.message.starts_with("app.launchURL")));
    }

    #[test]
    fn data_before_the_header_is_reported() {
        let mut doc = b"MZ\x90\x00 this is a PE, and then...".to_vec();
        doc.extend_from_slice(CLEAN);
        let p = parse(&doc).expect("pdf");
        assert!(p.header_off > 0);
        assert!(p
            .findings
            .iter()
            .any(|f| f.message.contains("precede the %PDF- header")));
    }

    #[test]
    fn hex_escaped_names_are_obfuscation() {
        let doc = b"%PDF-1.4\n1 0 obj\n<< /J#61vaScript 2 0 R >>\nendobj\n%%EOF";
        let p = parse(doc).expect("pdf");
        assert!(
            p.findings
                .iter()
                .any(|f| f.message.contains("#hex escapes")),
            "{:?}",
            p.findings
        );
    }

    #[test]
    fn a_name_marker_does_not_match_inside_a_longer_name() {
        // `/AAAAAA+ArialMT` is a font subset name, not an /AA action; one real
        // document matched it 278 times.
        let doc = b"%PDF-1.4\n1 0 obj\n<< /BaseFont /AAAAAA+ArialMT /Type /Font >>\nendobj\n%%EOF";
        let p = parse(doc).expect("pdf");
        assert!(
            !p.findings.iter().any(|f| f.message.starts_with("/AA")),
            "{:?}",
            p.findings
        );

        // ...but a real /AA is still found.
        let doc = b"%PDF-1.4\n1 0 obj\n<< /AA << /O 2 0 R >> >>\nendobj\n%%EOF";
        let p = parse(doc).expect("pdf");
        assert!(
            p.findings.iter().any(|f| f.message.starts_with("/AA")),
            "{:?}",
            p.findings
        );
    }

    #[test]
    fn every_occurrence_is_kept_with_an_excerpt() {
        let doc = b"%PDF-1.4\n1 0 obj\n<< /URI (http://one.example.top/a) >>\nendobj\n\
2 0 obj\n<< /URI (http://two.example.top/b) >>\nendobj\n%%EOF";
        let p = parse(doc).expect("pdf");
        let g = p
            .match_groups
            .iter()
            .find(|g| g.label == "/URI")
            .expect("a /URI group");
        assert_eq!(g.hits.len(), 2, "both, not just a count");
        assert!(
            g.hits[0].1.contains("http://one.example.top/a"),
            "{:?}",
            g.hits[0]
        );
        assert!(g.hits[1].1.contains("http://two.example.top/b"));
        assert!(p
            .findings
            .iter()
            .any(|f| f.message.contains("(2 occurrences)")));
    }

    #[test]
    fn incremental_updates_are_noted() {
        let mut doc = CLEAN.to_vec();
        doc.extend_from_slice(b"3 0 obj\n<< >>\nendobj\n%%EOF\n");
        let p = parse(&doc).expect("pdf");
        assert_eq!(p.revisions, 2);
        assert!(p.findings.iter().any(|f| f.message.contains("revisions")));
    }

    #[test]
    fn non_pdf_is_rejected() {
        assert!(parse(b"PK\x03\x04").is_none());
        assert!(parse(&[]).is_none());
    }
}
