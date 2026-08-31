//! RTF — not a container at all, but a control-word stream that Word will
//! happily be told to embed and auto-update an object from.
//!
//! RTF is a delivery format precisely because it is not structured: there is no
//! part list to inspect, only control words. The ones that matter are few, and
//! they are what CVE-2017-0199 and CVE-2017-11882 documents are built from.

/// One thing found in the stream, with where it was found.
#[derive(Clone, Debug)]
pub struct Hit {
    pub what: String,
    pub offset: u64,
    pub detail: String,
    pub severity: hiewlm_core::Severity,
}

#[derive(Clone, Debug, Default)]
pub struct Rtf {
    pub hits: Vec<Hit>,
    /// Object class names declared with `\objclass`.
    pub object_classes: Vec<String>,
}

pub fn is_rtf(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(16)];
    head.starts_with(b"{\\rt")
}

/// Case-insensitive search for an ASCII needle.
fn find_ci(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (from..=haystack.len() - needle.len())
        .find(|&i| haystack[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

pub fn parse(bytes: &[u8]) -> Option<Rtf> {
    if !is_rtf(bytes) {
        return None;
    }
    let mut r = Rtf::default();

    // Control words and literals both come from the rule table.
    for rule in crate::rules::rules("rtf") {
        let mut from = 0usize;
        let mut count = 0;
        while let Some(at) = find_ci(bytes, rule.value.as_bytes(), from) {
            if count == 0 {
                r.hits.push(Hit {
                    what: rule.value.clone(),
                    offset: at as u64,
                    detail: rule.note.clone(),
                    severity: rule.severity,
                });
            }
            count += 1;
            from = at + 1;
            if count > 4096 {
                break;
            }
        }
        if count > 1 {
            if let Some(h) = r.hits.last_mut() {
                h.detail = format!("{} ({count} occurrences)", h.detail);
            }
        }
    }

    // `\objclass Equation.3` and friends: the class name says which handler the
    // document is aiming at, and Equation.3 has only ever meant one thing.
    let mut from = 0usize;
    while let Some(at) = find_ci(bytes, b"\\objclass", from) {
        let start = at + 9;
        let end = (start + 64).min(bytes.len());
        let name: String = bytes[start..end]
            .iter()
            .skip_while(|b| b.is_ascii_whitespace())
            .take_while(|&&b| b != b'}' && b != b'\\' && b != b';')
            .map(|&b| b as char)
            .collect();
        let name = name.trim().to_string();
        if !name.is_empty() && !r.object_classes.contains(&name) {
            r.object_classes.push(name);
        }
        from = at + 1;
        if r.object_classes.len() > 64 {
            break;
        }
    }

    // The hex-encoded OLE and MZ headers are rules in the table like everything
    // else, so there is nothing special-cased here any more.
    r.hits.sort_by_key(|h| h.offset);
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_an_auto_updating_embedded_object() {
        let doc = br#"{\rtf1\ansi{\object\objautlink\objupdate{\*\objclass Equation.3}{\*\objdata 01050000d0cf11e0}}}"#;
        let r = parse(doc).expect("rtf");
        assert!(r.hits.iter().any(|h| h.what == "\\objupdate"));
        assert!(r.hits.iter().any(|h| h.what == "\\objdata"));
        assert!(r.hits.iter().any(|h| h.what == "d0cf11e0"), "{:?}", r.hits);
        assert_eq!(r.object_classes, vec!["Equation.3".to_string()]);
    }

    #[test]
    fn detects_dde_without_macros() {
        let doc =
            br#"{\rtf1{\field{\*\fldinst {DDEAUTO c:\\windows\\system32\\cmd.exe "/c calc"}}}}"#;
        let r = parse(doc).expect("rtf");
        assert!(r.hits.iter().any(|h| h.what == "DDEAUTO"), "{:?}", r.hits);
    }

    #[test]
    fn control_words_are_matched_case_insensitively() {
        // RTF control words are case sensitive in the spec, but the readers are
        // forgiving and so is the malware.
        let r = parse(br#"{\rtf1\OBJDATA 0102}"#).expect("rtf");
        assert!(r.hits.iter().any(|h| h.what == "\\objdata"));
    }

    #[test]
    fn a_clean_rtf_reports_nothing() {
        let r = parse(br#"{\rtf1\ansi Hello, this is a document.}"#).expect("rtf");
        assert!(r.hits.is_empty(), "{:?}", r.hits);
    }

    #[test]
    fn non_rtf_is_rejected() {
        assert!(parse(b"PK\x03\x04").is_none());
        assert!(!is_rtf(b"not rtf"));
    }
}
