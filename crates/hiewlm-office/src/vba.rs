//! VBA macro extraction: the compressed module source inside a compound file.
//!
//! Macro source is stored run-length compressed (MS-OVBA §2.4.1), which is why
//! `strings` on a macro-bearing document shows nothing useful — the giveaway
//! keywords are compressed away. Decompressing turns "this document has macros"
//! into "this document runs powershell from AutoOpen", which is the difference
//! between a lead and a verdict.

use crate::cfb::Cfb;

/// One recovered macro module.
#[derive(Clone, Debug)]
pub struct Module {
    /// Stream path inside the document.
    pub path: String,
    pub source: String,
    /// Keywords found in this module's source, worth putting in the report.
    pub keywords: Vec<String>,
}

/// Decompress an MS-OVBA compressed container.
///
/// The format is a sequence of chunks; each chunk has a header giving its size
/// and whether it is compressed, then tokens driven by a flag byte: a clear bit
/// is one literal byte, a set bit is a (offset, length) copy from what has
/// already been produced.
pub fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    // A container starts with the signature byte 0x01.
    let start = data.iter().position(|&b| b == 0x01)?;
    let data = &data[start + 1..];
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0usize;

    while pos + 2 <= data.len() {
        let header = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let size = (header & 0x0FFF) + 3;
        let compressed = header & 0x8000 != 0;
        let end = (pos + size - 2).min(data.len());
        if pos >= end {
            break;
        }
        let chunk = &data[pos..end];
        pos = end;

        if !compressed {
            out.extend_from_slice(chunk);
            continue;
        }

        let mut i = 0usize;
        while i < chunk.len() {
            let flags = chunk[i];
            i += 1;
            for bit in 0..8 {
                if i >= chunk.len() {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    out.push(chunk[i]);
                    i += 1;
                    continue;
                }
                if i + 1 >= chunk.len() {
                    break;
                }
                let token = u16::from_le_bytes([chunk[i], chunk[i + 1]]) as usize;
                i += 2;
                // The split between offset and length bits depends on how much
                // output exists so far — the window grows as the stream does.
                let mut bits = 4usize;
                let mut limit = 16usize;
                while limit < out.len() && bits < 12 {
                    limit <<= 1;
                    bits += 1;
                }
                let len_mask = (1usize << (16 - bits)) - 1;
                let length = (token & len_mask) + 3;
                let offset = (token >> (16 - bits)) + 1;
                if offset > out.len() || out.len() + length > 64 * 1024 * 1024 {
                    return Some(out); // crafted token: keep what we have
                }
                let from = out.len() - offset;
                for k in 0..length {
                    let b = out[from + k];
                    out.push(b);
                }
            }
        }
    }
    Some(out)
}

/// The suspicious keywords present in a macro source, as `group:keyword`
/// (`autoexec:AutoOpen`). Groups and keywords come from the rule table, so an
/// analyst can add their family's giveaway without rebuilding.
pub fn scan_keywords(source: &str) -> Vec<String> {
    let lower = source.to_ascii_lowercase();
    let mut out = Vec::new();
    for group in crate::rules::VBA_GROUPS {
        let short = group.strip_prefix("vba-").unwrap_or(group);
        for r in crate::rules::all_matches(group, &lower) {
            out.push(format!("{short}:{}", r.value));
        }
    }
    out
}

/// Recover every VBA module from a compound file (a `.doc`, or the
/// `vbaProject.bin` lifted out of a `.docx`).
pub fn modules(cfb: &Cfb) -> Vec<Module> {
    let mut out = Vec::new();
    for (path, data) in cfb.streams_matching("vba/") {
        // Inside the VBA storage, the module streams are the ones that
        // decompress to text; dir/_VBA_PROJECT are structural.
        let base = path.rsplit('/').next().unwrap_or(path);
        if base.eq_ignore_ascii_case("dir")
            || base.eq_ignore_ascii_case("_VBA_PROJECT")
            || base.eq_ignore_ascii_case("PROJECT")
            || base.eq_ignore_ascii_case("PROJECTwm")
        {
            continue;
        }
        let Some(raw) = decompress(data) else {
            continue;
        };
        let text: String = raw
            .iter()
            .map(|&b| if b == b'\r' { '\n' } else { b as char })
            .filter(|c| *c == '\n' || *c == '\t' || (' '..='~').contains(c))
            .collect();
        // A module that decompressed to nothing readable is not a module.
        if text.trim().len() < 8 {
            continue;
        }
        let keywords = scan_keywords(&text);
        out.push(Module {
            path: path.to_string(),
            source: text,
            keywords,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a container with a single uncompressed chunk, which is a valid
    /// encoding and exercises the header maths.
    fn raw_container(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01u8];
        let header = ((payload.len() + 2 - 3) & 0x0FFF) as u16; // uncompressed
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn decompresses_an_uncompressed_chunk() {
        let text = b"Sub AutoOpen()\r\n  Shell \"cmd.exe\"\r\nEnd Sub";
        let got = decompress(&raw_container(text)).expect("decompressed");
        assert!(
            got.starts_with(b"Sub AutoOpen()"),
            "{:?}",
            String::from_utf8_lossy(&got)
        );
    }

    #[test]
    fn decompresses_a_back_reference() {
        // "abcabcabc": three literals then a copy of what came before, which is
        // the case a naive implementation gets wrong (the copy overlaps).
        // Flag byte: a clear bit is a literal, a set bit is a copy. Three
        // literals, then one copy.
        let mut chunk = vec![0b0000_1000u8, b'a', b'b', b'c'];
        // token: offset 3, length 6 -> with <=16 bytes of output, 4 offset bits
        let token: u16 = (((3 - 1) as u16) << 12) | ((6 - 3) as u16);
        chunk.extend_from_slice(&token.to_le_bytes());
        let mut data = vec![0x01u8];
        let header = 0x8000u16 | ((chunk.len() + 2 - 3) as u16 & 0x0FFF);
        data.extend_from_slice(&header.to_le_bytes());
        data.extend_from_slice(&chunk);

        let got = decompress(&data).expect("decompressed");
        assert_eq!(String::from_utf8_lossy(&got), "abcabcabc");
    }

    #[test]
    fn keyword_scan_groups_what_it_finds() {
        let src = "Sub AutoOpen()\n Shell \"powershell -enc AAA\"\n End Sub";
        let k = scan_keywords(src);
        assert!(k.iter().any(|x| x == "autoexec:AutoOpen"), "{k:?}");
        assert!(k.iter().any(|x| x.starts_with("execution:")));
        assert!(scan_keywords("Sub Nothing()\nEnd Sub").is_empty());
    }

    #[test]
    fn keyword_groups_cover_the_modern_shapes() {
        // A dropper that allocates memory, checks for a sandbox and asks the
        // user to enable content should light up four different groups.
        let src = "Private Declare PtrSafe Function VirtualAlloc Lib \"kernel32\" \n\
                   If Application.RecentFiles.Count < 3 Then Exit Sub\n\
                   MsgBox \"Please Enable Content to view this invoice\"\n\
                   Set h = CreateObject(\"MSXML2.XMLHTTP\")";
        let k = scan_keywords(src);
        for group in ["memory:", "evasion:", "lure:", "download:", "execution:"] {
            assert!(
                k.iter().any(|x| x.starts_with(group)),
                "missing {group} in {k:?}"
            );
        }
    }

    #[test]
    fn malformed_input_does_not_hang_or_panic() {
        assert!(decompress(&[]).is_none());
        assert!(decompress(&[0x00, 0x00]).is_none());
        // A chunk header claiming more than exists.
        let _ = decompress(&[0x01, 0xff, 0xff, 0x41]);
        // A back-reference pointing before the start of output.
        let _ = decompress(&[0x01, 0x03, 0x80, 0b1111_1111, 0xff, 0xff]);
    }
}
