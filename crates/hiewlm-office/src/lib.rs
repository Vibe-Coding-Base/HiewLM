//! Document analysis: what is inside an Office file, and whether it is a lure.
//!
//! Three formats arrive under the same name. A `.doc` is an OLE compound file, a
//! `.docx` is a ZIP of XML parts, and an `.rtf` is neither — and malware uses
//! all three, often with the extension lying about which. This crate detects
//! what a file actually is and produces one model for all of them: a structure
//! tree the analyst can navigate, the macros recovered and decompressed, the
//! external references, and the findings that decide whether to keep going.
//!
//! Nothing is executed, no macro is run, no linked resource is fetched. A
//! remote template target is *reported*, never resolved.

pub mod cfb;
pub mod ooxml;
pub mod rtf;
pub mod vba;

use hiewlm_core::{Finding, Severity};

/// Which container the document really is, whatever the extension says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DocKind {
    /// OLE2 compound file: `.doc`, `.xls`, `.ppt`, and `vbaProject.bin`.
    Ole,
    /// OOXML package: `.docx`, `.xlsx`, `.pptx`.
    Ooxml,
    Rtf,
}

impl DocKind {
    pub fn label(self) -> &'static str {
        match self {
            DocKind::Ole => "OLE2 compound document",
            DocKind::Ooxml => "OOXML package",
            DocKind::Rtf => "RTF document",
        }
    }
}

/// One node of the structure tree, whatever the underlying format calls it.
#[derive(Clone, Debug)]
pub struct Node {
    pub path: String,
    /// storage / stream / part / object.
    pub kind: &'static str,
    pub size: u64,
    pub depth: usize,
    /// Where it starts in the file, when that is meaningful — `Enter` navigates
    /// here, which is the point of showing structure in a hex editor.
    pub file_off: Option<u64>,
    pub detail: String,
}

/// The analysed document.
#[derive(Clone, Debug)]
pub struct Document {
    pub kind: DocKind,
    /// A more specific description than the kind ("Word document with macros").
    pub format: String,
    pub nodes: Vec<Node>,
    pub findings: Vec<Finding>,
    pub metadata: Vec<(String, String)>,
    pub macros: Vec<vba::Module>,
    /// External references, already rendered for display.
    pub external: Vec<String>,
}

impl Document {
    pub fn suspicious_count(&self) -> usize {
        self.findings.iter().filter(|f| f.severity == Severity::Suspicious).count()
    }

    pub fn has_macros(&self) -> bool {
        !self.macros.is_empty()
    }

    /// Every macro keyword found, deduplicated — the quick answer to "what does
    /// this macro do".
    pub fn macro_keywords(&self) -> Vec<String> {
        let mut all: Vec<String> =
            self.macros.iter().flat_map(|m| m.keywords.clone()).collect();
        all.sort();
        all.dedup();
        all
    }
}

/// Analyse `bytes` as a document, or `None` if it is not one.
pub fn parse(bytes: &[u8]) -> Option<Document> {
    if cfb::is_cfb(bytes) {
        return parse_ole(bytes);
    }
    if ooxml::is_zip(bytes) {
        // A ZIP is only a document if it looks like an OOXML package; an
        // ordinary archive is the zip plugin's business.
        return parse_ooxml(bytes);
    }
    if rtf::is_rtf(bytes) {
        return parse_rtf(bytes);
    }
    None
}

// ── OLE ──────────────────────────────────────────────────────────────────────

/// Stream and storage names that only ever appear for a reason.
const OLE_MARKERS: &[(&str, Severity, &str)] = &[
    ("macros", Severity::Suspicious, "VBA macro storage"),
    ("_vba_project", Severity::Suspicious, "VBA project"),
    ("vbaproject", Severity::Suspicious, "VBA project"),
    ("objectpool", Severity::Suspicious, "embedded OLE objects"),
    ("ole10native", Severity::Suspicious, "embedded native payload (Packager)"),
    ("package", Severity::Suspicious, "embedded package — often the dropped file"),
    ("equation native", Severity::Suspicious, "Equation Editor object (CVE-2017-11882 vector)"),
    ("encryptedpackage", Severity::Suspicious, "encrypted document — content hidden from scanners"),
    ("macrosheet", Severity::Suspicious, "Excel 4.0 macro sheet"),
    ("worddocument", Severity::Info, "Word document body"),
    ("workbook", Severity::Info, "Excel workbook body"),
    ("powerpoint document", Severity::Info, "PowerPoint document body"),
    ("summaryinformation", Severity::Info, "document metadata"),
];

fn parse_ole(bytes: &[u8]) -> Option<Document> {
    let c = cfb::parse(bytes)?;
    let mut doc = Document {
        kind: DocKind::Ole,
        format: "OLE2 compound document".into(),
        nodes: Vec::new(),
        findings: Vec::new(),
        metadata: Vec::new(),
        macros: Vec::new(),
        external: Vec::new(),
    };

    for e in &c.entries {
        doc.nodes.push(Node {
            path: e.path.clone(),
            kind: match e.kind {
                cfb::EntryKind::Storage => "storage",
                cfb::EntryKind::Stream => "stream",
                cfb::EntryKind::Root => "root",
            },
            size: e.size,
            depth: e.depth,
            file_off: e.file_off,
            detail: String::new(),
        });
    }

    // Name the application from the body stream that is present.
    if c.has_entry("WordDocument") {
        doc.format = "Word document (OLE2)".into();
    } else if c.has_entry("Workbook") || c.has_entry("Book") {
        doc.format = "Excel workbook (OLE2)".into();
    } else if c.has_entry("PowerPoint Document") {
        doc.format = "PowerPoint presentation (OLE2)".into();
    }

    for e in &c.entries {
        let lower = e.name.to_ascii_lowercase();
        for (marker, severity, meaning) in OLE_MARKERS {
            if lower.contains(marker) {
                let f = Finding {
                    severity: *severity,
                    message: format!("{}: {meaning}", e.path),
                    offset: e.file_off,
                };
                if !doc.findings.iter().any(|x| x.message == f.message) {
                    doc.findings.push(f);
                }
            }
        }
    }

    doc.macros = vba::modules(&c);
    finish_macros(&mut doc);
    Some(doc)
}

// ── OOXML ────────────────────────────────────────────────────────────────────

fn parse_ooxml(bytes: &[u8]) -> Option<Document> {
    let pkg = ooxml::parse(bytes)?;
    // Not every ZIP is a document. Require the package marker.
    let is_package = pkg
        .parts
        .iter()
        .any(|p| p.name == "[Content_Types].xml" || p.name.starts_with("_rels/"));
    if !is_package {
        return None;
    }

    let mut doc = Document {
        kind: DocKind::Ooxml,
        format: "OOXML package".into(),
        nodes: Vec::new(),
        findings: Vec::new(),
        metadata: pkg.metadata.clone(),
        macros: Vec::new(),
        external: Vec::new(),
    };

    let has = |needle: &str| pkg.parts.iter().any(|p| p.name.contains(needle));
    doc.format = if has("word/") {
        "Word document (OOXML)".into()
    } else if has("xl/") {
        "Excel workbook (OOXML)".into()
    } else if has("ppt/") {
        "PowerPoint presentation (OOXML)".into()
    } else {
        "OOXML package".into()
    };

    for p in &pkg.parts {
        let depth = p.name.matches('/').count();
        doc.nodes.push(Node {
            path: p.name.clone(),
            kind: "part",
            size: p.uncompressed_size,
            depth,
            file_off: Some(p.file_off),
            detail: format!("{} · {} compressed", p.method, p.compressed_size),
        });
    }

    // External relationships: the remote-template and remote-object routes.
    for r in &pkg.relationships {
        if !r.external {
            continue;
        }
        let line = format!("{} -> {} (in {})", r.kind, r.target, r.source);
        doc.external.push(line.clone());
        let remote = r.target.starts_with("http://")
            || r.target.starts_with("https://")
            || r.target.starts_with("\\\\")
            || r.target.starts_with("mhtml:")
            || r.target.starts_with("ms-msdt:");
        let severity = match r.kind.as_str() {
            "attachedTemplate" | "oleObject" | "frame" | "subDocument" if remote => {
                Severity::Suspicious
            }
            _ if remote && r.kind != "hyperlink" => Severity::Suspicious,
            _ => Severity::Info,
        };
        doc.findings.push(Finding {
            severity,
            message: match r.kind.as_str() {
                "attachedTemplate" => {
                    format!("remote template: {} — fetched and its macros run on open", r.target)
                }
                "oleObject" => format!("remote OLE object: {}", r.target),
                _ => format!("external {}: {}", r.kind, r.target),
            },
            offset: None,
        });
    }

    // Part names that are themselves the finding.
    const PART_MARKERS: &[(&str, &str)] = &[
        ("vbaProject.bin", "VBA macro project"),
        ("vbaData.xml", "VBA data"),
        ("macrosheets/", "Excel 4.0 macro sheet (XLM)"),
        ("xl/macrosheet", "Excel 4.0 macro sheet (XLM)"),
        ("activeX/", "ActiveX control"),
        ("embeddings/", "embedded object"),
        ("oleObject", "embedded OLE object"),
        ("customXml/", "custom XML part"),
        ("printerSettings", "printer settings blob"),
    ];
    for p in &pkg.parts {
        for (needle, meaning) in PART_MARKERS {
            if p.name.contains(needle) {
                doc.findings.push(Finding {
                    severity: Severity::Suspicious,
                    message: format!("{}: {meaning}", p.name),
                    offset: Some(p.file_off),
                });
                break;
            }
        }
    }

    // DDE fields hide in the body's field instructions.
    let body = pkg.body_sample.to_ascii_uppercase();
    if body.contains("DDEAUTO") || body.contains("DDE ") {
        doc.findings.push(Finding::suspicious(
            "DDE field in the document body — executes without macros",
        ));
    }

    // The macro project is itself a compound file; go one level deeper.
    if let Some(project) = &pkg.vba_project {
        if let Some(inner) = cfb::parse(project) {
            doc.macros = vba::modules(&inner);
        }
    }
    finish_macros(&mut doc);
    Some(doc)
}

// ── RTF ──────────────────────────────────────────────────────────────────────

fn parse_rtf(bytes: &[u8]) -> Option<Document> {
    let r = rtf::parse(bytes)?;
    let mut doc = Document {
        kind: DocKind::Rtf,
        format: "RTF document".into(),
        nodes: Vec::new(),
        findings: Vec::new(),
        metadata: Vec::new(),
        macros: Vec::new(),
        external: Vec::new(),
    };
    for h in &r.hits {
        doc.nodes.push(Node {
            path: h.what.clone(),
            kind: "object",
            size: 0,
            depth: 0,
            file_off: Some(h.offset),
            detail: h.detail.clone(),
        });
        doc.findings.push(
            Finding::suspicious(format!("{} — {}", h.what, h.detail)).at(h.offset),
        );
    }
    for class in &r.object_classes {
        let known_bad = class.starts_with("Equation")
            || class.eq_ignore_ascii_case("Package")
            || class.starts_with("Word.Document")
            || class.starts_with("OLE2Link");
        doc.findings.push(Finding {
            severity: if known_bad { Severity::Suspicious } else { Severity::Info },
            message: format!("object class: {class}"),
            offset: None,
        });
    }
    Some(doc)
}

// ── Shared ───────────────────────────────────────────────────────────────────

/// Turn recovered macros into findings and nodes.
fn finish_macros(doc: &mut Document) {
    if doc.macros.is_empty() {
        return;
    }
    doc.findings.push(Finding::suspicious(format!(
        "{} VBA module(s) recovered and decompressed",
        doc.macros.len()
    )));
    for m in &doc.macros {
        doc.nodes.push(Node {
            path: m.path.clone(),
            kind: "macro",
            size: m.source.len() as u64,
            depth: m.path.matches('/').count(),
            file_off: None,
            detail: format!("{} line(s)", m.source.lines().count()),
        });
    }
    let keywords = doc.macro_keywords();
    let auto = keywords.iter().any(|k| k.starts_with("auto-exec:"));
    let exec = keywords.iter().any(|k| k.starts_with("execution:"));
    if auto && exec {
        doc.findings.push(Finding::suspicious(
            "macro runs on open AND executes a program — this is the payload path",
        ));
    }
    for group in ["auto-exec", "execution", "download", "obfuscation", "memory"] {
        let found: Vec<&str> = keywords
            .iter()
            .filter(|k| k.starts_with(&format!("{group}:")))
            .map(|k| k.split_once(':').map(|(_, v)| v).unwrap_or(k))
            .collect();
        if !found.is_empty() {
            doc.findings.push(Finding::suspicious(format!(
                "macro {group}: {}",
                found.join(", ")
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_rtf_lure_is_recognised_and_explained() {
        let doc_bytes = br#"{\rtf1\ansi{\object\objupdate{\*\objclass Equation.3}{\*\objdata 01050000d0cf11e0}}}"#;
        let d = parse(doc_bytes).expect("document");
        assert_eq!(d.kind, DocKind::Rtf);
        assert!(d.suspicious_count() >= 3, "{:?}", d.findings);
        assert!(d.findings.iter().any(|f| f.message.contains("Equation.3")));
        // Every node has a file offset, so the structure view can navigate.
        assert!(d.nodes.iter().all(|n| n.file_off.is_some()));
    }

    #[test]
    fn a_plain_file_is_not_a_document() {
        assert!(parse(b"MZ\x90\x00 this is a PE").is_none());
        assert!(parse(b"").is_none());
        // A ZIP that is not an OOXML package belongs to the zip plugin.
        let plain_zip = {
            let mut v = b"PK\x03\x04".to_vec();
            v.extend(std::iter::repeat(0u8).take(64));
            v.extend(b"PK\x05\x06");
            v.extend(std::iter::repeat(0u8).take(18));
            v
        };
        assert!(parse(&plain_zip).is_none());
    }
}
