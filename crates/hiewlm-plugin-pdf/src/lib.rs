//! PDF container plugin.
//!
//! Walks the document structure — header, indirect objects, trailer, xref —
//! and lists each object with its file offset so the viewer can jump to it.
//!
//! PDF is a common malware carrier, so the parser also reports *active
//! content*: JavaScript, auto-run actions, launch actions, embedded files and
//! historically-exploited decoders. Everything here is inspection only: no
//! stream is decompressed, no action is followed, nothing is executed.
//!
//! Known limit, reported in the summary rather than hidden: objects stored
//! inside compressed object streams (`/ObjStm`) are not enumerated, because
//! that would require inflating stream data.

use hiewlm_core::container::{Container, ContainerParser, Finding, Member};

/// The header must appear within the first 1 KiB (PDF 1.7 §7.5.2).
const HEADER_WINDOW: usize = 1024;
/// Cap structural scanning so a huge file cannot stall the UI.
const SCAN_CAP: usize = 64 * 1024 * 1024;

/// Markers of active or historically-abused content. `(needle, suspicious, note)`
const MARKERS: &[(&str, bool, &str)] = &[
    ("/JavaScript", true, "JavaScript action"),
    ("/JS", true, "JavaScript entry"),
    ("/OpenAction", true, "runs automatically when the document opens"),
    ("/AA", true, "additional (auto-triggered) actions"),
    ("/Launch", true, "launches an external application"),
    ("/EmbeddedFile", true, "embedded file payload"),
    ("/RichMedia", true, "embedded rich media (Flash)"),
    ("/JBIG2Decode", true, "JBIG2 decoder (historically exploited)"),
    ("/SubmitForm", true, "submits data to a remote endpoint"),
    ("/GoToR", true, "remote go-to action"),
    ("/XFA", true, "XFA form (script-capable)"),
    ("/ObjStm", false, "compressed object stream"),
    ("/Encrypt", false, "encrypted document"),
    ("/AcroForm", false, "interactive form"),
    ("/URI", false, "external link"),
];

#[derive(Debug, Default)]
pub struct PdfPlugin;

impl ContainerParser for PdfPlugin {
    fn name(&self) -> &'static str {
        "pdf"
    }

    fn description(&self) -> &'static str {
        "PDF documents: object map, trailer, and active-content (JS/launch/embedded) checks"
    }

    fn sniff(&self, bytes: &[u8]) -> bool {
        header_at(bytes).is_some()
    }

    fn parse(&self, bytes: &[u8]) -> Option<Container> {
        parse(bytes)
    }
}

/// Offset of the `%PDF-` header. The spec tolerates leading bytes, and real
/// malware exploits that, so the whole window is searched rather than only [0].
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

fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

/// Scan for `N G obj` indirect-object headers, returning (offset, num, gen).
fn scan_objects(bytes: &[u8]) -> Vec<(u64, u32, u32)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(p) = find_from(bytes, b"obj", at) {
        at = p + 3;
        // `obj` must be a token, not the tail of a longer name.
        if bytes.get(p + 3).is_some_and(|b| b.is_ascii_alphanumeric()) {
            continue;
        }
        // Walk back over: whitespace, generation digits, whitespace, number digits.
        let mut i = p;
        while i > 0 && bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        let gen_end = i;
        while i > 0 && is_digit(bytes[i - 1]) {
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
        if num_end == gen_start {
            continue;
        }
        while i > 0 && is_digit(bytes[i - 1]) {
            i -= 1;
        }
        let num_start = i;
        if num_start == num_end {
            continue;
        }
        // The object number must start at a token boundary. Without this,
        // the "4" of a "%PDF-1.4" header would be read as an object number.
        if num_start > 0 {
            let prev = bytes[num_start - 1];
            let delimiter = prev.is_ascii_whitespace() || b"()<>[]{}/%".contains(&prev);
            if !delimiter {
                continue;
            }
        }
        let parse_at = |a: usize, b: usize| -> Option<u32> {
            std::str::from_utf8(&bytes[a..b]).ok()?.parse().ok()
        };
        let (Some(num), Some(gen)) = (parse_at(num_start, num_end), parse_at(gen_start, gen_end))
        else {
            continue;
        };
        out.push((num_start as u64, num, gen));
        if out.len() >= 100_000 {
            break;
        }
    }
    out
}

/// The `/Type` of the object body, when it is stated plainly enough to read.
fn object_type(bytes: &[u8], start: usize) -> String {
    let end = find_from(bytes, b"endobj", start).unwrap_or(bytes.len()).min(start + 2048);
    let body = &bytes[start.min(bytes.len())..end.min(bytes.len())];
    let Some(p) = find_from(body, b"/Type", 0) else {
        return String::new();
    };
    let mut i = p + 5;
    while i < body.len() && (body[i].is_ascii_whitespace()) {
        i += 1;
    }
    if body.get(i) != Some(&b'/') {
        return String::new();
    }
    i += 1;
    let s = i;
    while i < body.len() && (body[i].is_ascii_alphanumeric() || body[i] == b'_') {
        i += 1;
    }
    String::from_utf8_lossy(&body[s..i]).into_owned()
}

pub fn parse(bytes: &[u8]) -> Option<Container> {
    let hdr = header_at(bytes)?;
    let scan = &bytes[..bytes.len().min(SCAN_CAP)];

    let version = bytes
        .get(hdr + 5..hdr + 8)
        .map(|v| String::from_utf8_lossy(v).trim().to_string())
        .unwrap_or_default();

    let objects = scan_objects(scan);
    let mut members: Vec<Member> = objects
        .iter()
        .map(|&(off, num, gen)| {
            let t = object_type(scan, off as usize);
            let detail = if t.is_empty() { String::new() } else { format!("/{t}") };
            Member::new(format!("obj {num} {gen}"), off, 0, detail)
        })
        .collect();

    let mut findings = Vec::new();

    if hdr > 0 {
        findings.push(
            Finding::suspicious(format!("{hdr} bytes precede the %PDF- header (polyglot or prepended data)"))
                .at(0),
        );
    }

    for &(needle, suspicious, note) in MARKERS {
        let (n, first) = count_occurrences(scan, needle.as_bytes());
        if n == 0 {
            continue;
        }
        let msg = format!("{needle} ×{n} — {note}");
        let f = if suspicious { Finding::suspicious(msg) } else { Finding::info(msg) };
        findings.push(if let Some(p) = first { f.at(p as u64) } else { f });
    }

    // Incremental updates: each save appends a new xref + %%EOF. Extra ones are
    // normal in edited documents but are also how content gets hidden.
    let (eofs, _) = count_occurrences(scan, b"%%EOF");
    let (streams, _) = count_occurrences(scan, b"stream");
    let (xrefs, _) = count_occurrences(scan, b"xref");
    if eofs > 1 {
        findings.push(Finding::info(format!(
            "{eofs} %%EOF markers — {} incremental update(s)",
            eofs - 1
        )));
    }
    if objects.is_empty() {
        findings.push(Finding::suspicious(
            "no indirect objects found — malformed, or the body is inside object streams",
        ));
    }

    let startxref = count_occurrences(scan, b"startxref").1.map(|p| {
        let tail = &scan[p + 9..scan.len().min(p + 40)];
        String::from_utf8_lossy(tail).trim().lines().next().unwrap_or("").trim().to_string()
    });

    if count_occurrences(scan, b"/ObjStm").0 > 0 {
        findings.push(Finding::info(
            "objects inside /ObjStm are not enumerated (streams are not decompressed)",
        ));
    }

    members.sort_by_key(|m| m.offset);

    let summary = vec![
        ("Type".into(), "PDF document".to_string()),
        ("Version".into(), format!("PDF-{version}")),
        ("Header at".into(), format!("{hdr:#010x}")),
        ("Objects".into(), objects.len().to_string()),
        ("Streams".into(), streams.to_string()),
        ("xref sections".into(), xrefs.to_string()),
        ("%%EOF markers".into(), eofs.to_string()),
        ("startxref".into(), startxref.unwrap_or_else(|| "none".into())),
        ("Encrypted".into(), if count_occurrences(scan, b"/Encrypt").0 > 0 { "yes".into() } else { "no".to_string() }),
    ];

    Some(Container { kind: "PDF document".into(), summary, members, findings })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &[u8] = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\ntrailer\n<< /Root 1 0 R >>\nstartxref\n116\n%%EOF\n";

    #[test]
    fn sniffs_pdf_header() {
        let p = PdfPlugin;
        assert!(p.sniff(MINIMAL));
        assert!(!p.sniff(b"PK\x03\x04"));
        assert!(!p.sniff(b""));
    }

    #[test]
    fn lists_objects_with_offsets_and_types() {
        let c = parse(MINIMAL).unwrap();
        assert_eq!(c.members.len(), 2);
        assert_eq!(c.members[0].name, "obj 1 0");
        assert_eq!(c.members[0].detail, "/Catalog");
        assert_eq!(c.members[1].detail, "/Pages");
        // Offsets must point at the object header itself.
        assert_eq!(&MINIMAL[c.members[0].offset as usize..][..7], b"1 0 obj");
        assert_eq!(&MINIMAL[c.members[1].offset as usize..][..7], b"2 0 obj");
    }

    #[test]
    fn clean_document_is_not_flagged() {
        let c = parse(MINIMAL).unwrap();
        assert_eq!(c.suspicious().count(), 0, "{:?}", c.findings);
    }

    #[test]
    fn flags_javascript_and_openaction() {
        let mut d = MINIMAL.to_vec();
        d.extend_from_slice(b"3 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n");
        let c = parse(&d).unwrap();
        assert!(c.suspicious().any(|f| f.message.contains("/JavaScript")));
        assert!(c.suspicious().any(|f| f.message.contains("/OpenAction")));
    }

    #[test]
    fn flags_launch_and_embedded_file() {
        let mut d = MINIMAL.to_vec();
        d.extend_from_slice(b"4 0 obj\n<< /Launch (cmd.exe) /EmbeddedFile 5 0 R >>\nendobj\n");
        let c = parse(&d).unwrap();
        assert!(c.suspicious().any(|f| f.message.contains("/Launch")));
        assert!(c.suspicious().any(|f| f.message.contains("/EmbeddedFile")));
    }

    #[test]
    fn flags_prepended_data_polyglot() {
        let mut d = b"GIF89a-junk-".to_vec();
        d.extend_from_slice(MINIMAL);
        let c = parse(&d).unwrap();
        assert!(c.suspicious().any(|f| f.message.contains("precede the %PDF- header")));
        // Object offsets must still be absolute within the whole file.
        assert_eq!(&d[c.members[0].offset as usize..][..7], b"1 0 obj");
    }

    #[test]
    fn reports_incremental_updates() {
        let mut d = MINIMAL.to_vec();
        d.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\nstartxref\n900\n%%EOF\n");
        let c = parse(&d).unwrap();
        assert!(c.findings.iter().any(|f| f.message.contains("incremental update")));
    }

    #[test]
    fn objstm_limitation_is_reported() {
        let mut d = MINIMAL.to_vec();
        d.extend_from_slice(b"5 0 obj\n<< /Type /ObjStm /N 3 >>\nstream\nendobj\n");
        let c = parse(&d).unwrap();
        assert!(c.findings.iter().any(|f| f.message.contains("not enumerated")));
    }

    #[test]
    fn obj_token_must_not_match_inside_a_name() {
        // "/Subject" ends in no "obj", but "12 0 objfoo" must not count.
        let d = b"%PDF-1.4\n12 0 objfoo\n";
        assert!(scan_objects(d).is_empty());
    }

    #[test]
    fn object_scan_requires_number_and_generation() {
        assert!(scan_objects(b"%PDF-1.4\nobj\n").is_empty());
        assert!(scan_objects(b"%PDF-1.4\n7 obj\n").is_empty());
        assert_eq!(scan_objects(b"%PDF-1.4\n7 0 obj\n").len(), 1);
    }

    #[test]
    fn truncated_and_hostile_input_does_not_panic() {
        for n in 0..MINIMAL.len() {
            let _ = parse(&MINIMAL[..n]);
        }
        let _ = parse(&[b'%'; 4096]);
        let _ = parse(b"%PDF-");
        let mut noisy = b"%PDF-1.7\n".to_vec();
        noisy.extend(std::iter::repeat(b'0').take(10_000));
        noisy.extend_from_slice(b" 0 obj");
        let _ = parse(&noisy);
    }
}
