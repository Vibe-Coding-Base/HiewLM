//! Removing identity metadata to a cleaned copy.
//!
//! Scrub never touches the original file — it returns new bytes for a new path,
//! which is the whole safety model: the sample or the document you started from
//! is still there, byte for byte. The "identity" level removes the fingerprint
//! that identifies a person or their device — author, last-saved-by, company,
//! manager, template path, GPS, owner, copyright, the camera make and model, and
//! the authoring software — and leaves what does not identify: the timestamps
//! and the technical image parameters.
//!
//! Images are scrubbed in place inside their own bytes (see [`crate::image`]);
//! an OOXML package is repackaged, its `docProps` rewritten and everything else
//! copied through unchanged.

use crate::{image, meta, ooxml};

/// A cleaned copy and the list of what was removed, for the preview and report.
#[derive(Clone, Debug)]
pub struct Scrubbed {
    pub removed: Vec<(String, String)>,
    pub bytes: Vec<u8>,
}

/// A cleaned copy with identity metadata removed, or `None` if the format is not
/// one scrub can rewrite (a bare ZIP, a `.doc`, a PDF, an unsupported image).
pub fn scrub_identity(bytes: &[u8]) -> Option<Scrubbed> {
    if ooxml::is_zip(bytes) {
        return scrub_ooxml(bytes);
    }
    let (out, removed) = image::scrub(bytes)?;
    Some(Scrubbed {
        removed,
        bytes: out,
    })
}

// ── OOXML ────────────────────────────────────────────────────────────────────

fn scrub_ooxml(bytes: &[u8]) -> Option<Scrubbed> {
    let mut entries = read_zip(bytes)?;
    // A bare ZIP is not a document; require the package markers before rewriting.
    if !entries
        .iter()
        .any(|e| e.name == "[Content_Types].xml" || e.name.starts_with("_rels/"))
    {
        return None;
    }

    let mut removed = Vec::new();
    for e in &mut entries {
        let tags: &[&str] = match e.name.as_str() {
            "docProps/core.xml" => &["dc:creator", "cp:lastModifiedBy"],
            // Application and AppVersion name the software that wrote the file —
            // a fingerprint, like a camera model, so identity too.
            "docProps/app.xml" => &[
                "Company",
                "Manager",
                "Template",
                "Application",
                "AppVersion",
            ],
            _ => continue,
        };
        let Some(xml) = inflate_entry(e) else {
            continue;
        };
        let Ok(mut text) = String::from_utf8(xml) else {
            continue;
        };
        let mut changed = false;
        for tag in tags {
            if let Some((new, val)) = blank_element(&text, tag) {
                let name = meta::classify(tag).map(|(n, _)| n).unwrap_or(tag);
                removed.push((name.to_string(), val));
                text = new;
                changed = true;
            }
        }
        if changed {
            replace_entry(e, text.into_bytes());
        }
    }

    if removed.is_empty() {
        return None;
    }
    Some(Scrubbed {
        removed,
        bytes: write_zip(&entries),
    })
}

/// Empty one element's content: `<tag ...>value</tag>` becomes `<tag ...></tag>`,
/// keeping the element so the document schema is unchanged. Returns the new XML
/// and the value that was removed, or `None` if the element is absent or empty.
fn blank_element(xml: &str, tag: &str) -> Option<(String, String)> {
    let open = format!("<{tag}");
    let i = xml.find(&open)?;
    let gt = xml[i..].find('>')? + i + 1;
    // A self-closing `<tag/>` holds nothing.
    if xml.as_bytes().get(gt.wrapping_sub(2)) == Some(&b'/') {
        return None;
    }
    let close = format!("</{tag}>");
    let j = xml[gt..].find(&close)? + gt;
    let val = xml[gt..j].trim().to_string();
    if val.is_empty() {
        return None;
    }
    Some((format!("{}{}", &xml[..gt], &xml[j..]), val))
}

// ── minimal ZIP read/write ───────────────────────────────────────────────────

struct RawEntry {
    name: String,
    method: u16,
    crc: u32,
    uncompressed: u32,
    /// Raw stored/deflated bytes, exactly as they sit in the archive.
    comp: Vec<u8>,
}

fn read_zip(bytes: &[u8]) -> Option<Vec<RawEntry>> {
    let eocd = find_eocd(bytes)?;
    let count = u16le(bytes, eocd + 10) as usize;
    let cd_off = u32le(bytes, eocd + 16) as usize;
    let mut p = cd_off;
    let mut out = Vec::new();
    for _ in 0..count.min(8192) {
        if p + 46 > bytes.len() || &bytes[p..p + 4] != b"PK\x01\x02" {
            break;
        }
        let method = u16le(bytes, p + 10);
        let crc = u32le(bytes, p + 16);
        let csize = u32le(bytes, p + 20) as usize;
        let uncompressed = u32le(bytes, p + 24);
        let name_len = u16le(bytes, p + 28) as usize;
        let extra_len = u16le(bytes, p + 30) as usize;
        let comment_len = u16le(bytes, p + 32) as usize;
        let local_off = u32le(bytes, p + 42) as usize;
        let name = String::from_utf8_lossy(bytes.get(p + 46..p + 46 + name_len)?).into_owned();
        let comp = local_data(bytes, local_off, csize)?;
        out.push(RawEntry {
            name,
            method,
            crc,
            uncompressed,
            comp,
        });
        p += 46 + name_len + extra_len + comment_len;
    }
    (!out.is_empty()).then_some(out)
}

/// The compressed bytes that follow a local file header.
fn local_data(bytes: &[u8], local_off: usize, csize: usize) -> Option<Vec<u8>> {
    if local_off + 30 > bytes.len() || &bytes[local_off..local_off + 4] != b"PK\x03\x04" {
        return None;
    }
    let name_len = u16le(bytes, local_off + 26) as usize;
    let extra_len = u16le(bytes, local_off + 28) as usize;
    let start = local_off + 30 + name_len + extra_len;
    let end = start.checked_add(csize)?;
    bytes.get(start..end).map(<[u8]>::to_vec)
}

fn inflate_entry(e: &RawEntry) -> Option<Vec<u8>> {
    match e.method {
        0 => Some(e.comp.clone()),
        8 => {
            use flate2::read::DeflateDecoder;
            use std::io::Read;
            let mut out = Vec::new();
            DeflateDecoder::new(&e.comp[..])
                .take(64 * 1024 * 1024)
                .read_to_end(&mut out)
                .ok()?;
            Some(out)
        }
        _ => None,
    }
}

/// Re-deflate a rewritten part and refresh its CRC and sizes.
fn replace_entry(e: &mut RawEntry, data: Vec<u8>) {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    let comp = if enc.write_all(&data).is_ok() {
        enc.finish().unwrap_or_default()
    } else {
        Vec::new()
    };
    e.crc = crc32fast::hash(&data);
    e.uncompressed = data.len() as u32;
    e.method = 8;
    e.comp = comp;
}

fn write_zip(entries: &[RawEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut dir = Vec::new();
    for e in entries {
        let local_off = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags (no descriptor)
        out.extend_from_slice(&e.method.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // mod time + date
        out.extend_from_slice(&e.crc.to_le_bytes());
        out.extend_from_slice(&(e.comp.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.uncompressed.to_le_bytes());
        out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(e.name.as_bytes());
        out.extend_from_slice(&e.comp);

        dir.extend_from_slice(b"PK\x01\x02");
        dir.extend_from_slice(&20u16.to_le_bytes()); // version made by
        dir.extend_from_slice(&20u16.to_le_bytes()); // version needed
        dir.extend_from_slice(&0u16.to_le_bytes()); // flags
        dir.extend_from_slice(&e.method.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes()); // time + date
        dir.extend_from_slice(&e.crc.to_le_bytes());
        dir.extend_from_slice(&(e.comp.len() as u32).to_le_bytes());
        dir.extend_from_slice(&e.uncompressed.to_le_bytes());
        dir.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        dir.extend_from_slice(&0u16.to_le_bytes()); // extra
        dir.extend_from_slice(&0u16.to_le_bytes()); // comment
        dir.extend_from_slice(&0u16.to_le_bytes()); // disk
        dir.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        dir.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        dir.extend_from_slice(&local_off.to_le_bytes());
        dir.extend_from_slice(e.name.as_bytes());
    }
    let cd_off = out.len() as u32;
    let cd_len = dir.len() as u32;
    out.extend_from_slice(&dir);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    let n = entries.len() as u16;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    let start = bytes.len().saturating_sub(66_000);
    (start..bytes.len().saturating_sub(21))
        .rev()
        .find(|&i| &bytes[i..i + 4] == b"PK\x05\x06")
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal deflate-based OOXML package with the given parts.
    fn package(parts: &[(&str, &str)]) -> Vec<u8> {
        let entries: Vec<RawEntry> = parts
            .iter()
            .map(|(name, body)| {
                let mut e = RawEntry {
                    name: (*name).to_string(),
                    method: 0,
                    crc: 0,
                    uncompressed: 0,
                    comp: Vec::new(),
                };
                replace_entry(&mut e, body.as_bytes().to_vec());
                e
            })
            .collect();
        write_zip(&entries)
    }

    #[test]
    fn ooxml_scrub_removes_identity_and_stays_a_package() {
        let core = r#"<?xml version="1.0"?><cp:coreProperties><dc:creator>Jane Doe</dc:creator><cp:lastModifiedBy>attacker</cp:lastModifiedBy><dc:title>Report</dc:title></cp:coreProperties>"#;
        let app = r#"<Properties><Company>ACME</Company><Template>\\FS\report.dotx</Template><Application>Word</Application></Properties>"#;
        let pkg = package(&[
            ("[Content_Types].xml", "<Types/>"),
            ("docProps/core.xml", core),
            ("docProps/app.xml", app),
        ]);

        let scrubbed = scrub_identity(&pkg).expect("a package is scrubbable");
        // The identity fields are reported and gone; attribution stays.
        let keys: Vec<&str> = scrubbed.removed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"Author"), "{keys:?}");
        assert!(keys.contains(&"Company"), "{keys:?}");
        assert!(keys.contains(&"Template path"), "{keys:?}");

        // The result is still a readable package with the identity gone and the
        // rest intact.
        assert!(
            keys.contains(&"Application"),
            "the app fingerprint too: {keys:?}"
        );

        let doc = crate::parse(&scrubbed.bytes).expect("scrubbed file still parses");
        let md: std::collections::HashMap<_, _> = doc.metadata.into_iter().collect();
        assert!(!md.contains_key("dc:creator"), "creator should be gone");
        assert!(!md.contains_key("Company"), "company should be gone");
        assert!(
            !md.contains_key("Application"),
            "application should be gone"
        );
    }

    #[test]
    fn a_bare_zip_is_not_scrubbed() {
        let zip = package(&[("readme.txt", "hello")]);
        assert!(
            scrub_identity(&zip).is_none(),
            "a bare zip is not a document"
        );
    }
}
