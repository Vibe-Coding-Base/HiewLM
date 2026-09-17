//! Which metadata fields leak identity, and how they read as findings.
//!
//! Documents and images collect metadata as plain `(key, value)` pairs. Some of
//! those fields are attribution context — the application, the producer library
//! — and some are identity: who authored the file, on whose machine, at what
//! coordinates. This module is the one place that decides which is which, so the
//! Findings pane, the triage badge and a later privacy scrub all agree.

use hiewlm_core::{Finding, Severity};

/// The stable label every metadata finding starts with, so the triage layer and
/// the finding grouping can recognise them.
pub const LABEL: &str = "identity";

/// Map a raw metadata key (from any format) to a friendly name and whether it
/// leaks identity. Unknown keys return `None` and stay metadata-only.
pub fn classify(key: &str) -> Option<(&'static str, bool)> {
    Some(match key {
        // OOXML docProps
        "dc:creator" => ("Author", true),
        "cp:lastModifiedBy" => ("Last saved by", true),
        "Manager" => ("Manager", true),
        "Company" => ("Company", true),
        // A template is often a UNC path — it leaks internal infrastructure.
        "Template" => ("Template path", true),
        "Application" => ("Application", false),
        "AppVersion" => ("App version", false),
        // PDF Info dictionary
        "Author" => ("Author", true),
        "Creator" => ("Creator tool", false),
        "Producer" => ("Producer", false),
        "CreationDate" => ("Created", false),
        "ModDate" => ("Modified", false),
        // RTF \info
        "operator" => ("Last saved by", true),
        _ => return None,
    })
}

/// Whether a metadata key is identity-sensitive — the fields a privacy scrub at
/// the "identity" level removes.
pub fn is_identity(key: &str) -> bool {
    classify(key).map(|(_, id)| id).unwrap_or(false)
}

/// A uniform identity finding, so every format phrases it the same way and the
/// triage badge can key on [`LABEL`].
pub fn finding(friendly: &str, value: &str) -> Finding {
    Finding {
        severity: Severity::Info,
        message: format!("{LABEL}: {friendly} = {value}"),
        offset: None,
    }
}

/// Identity findings for a document's metadata, in the order the keys appear.
/// Non-identity keys stay in the metadata list only; they are context, not a
/// flag worth raising.
pub fn findings_from_metadata(metadata: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (key, value) in metadata {
        if value.trim().is_empty() {
            continue;
        }
        if let Some((friendly, true)) = classify(key) {
            let f = finding(friendly, value.trim());
            if !out.iter().any(|x: &Finding| x.message == f.message) {
                out.push(f);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn author_is_identity_producer_is_not() {
        assert!(is_identity("dc:creator"));
        assert!(is_identity("Author"));
        assert!(is_identity("Template"));
        assert!(!is_identity("Producer"));
        assert!(!is_identity("Application"));
        assert!(!is_identity("unknown-key"));
    }

    #[test]
    fn builds_findings_only_for_identity_fields() {
        let md = vec![
            ("dc:creator".to_string(), "Bob".to_string()),
            ("Producer".to_string(), "iText 5.5".to_string()),
            ("Company".to_string(), "ACME".to_string()),
            ("Template".to_string(), "".to_string()), // empty -> skipped
        ];
        let f = findings_from_metadata(&md);
        assert_eq!(f.len(), 2, "creator and company only");
        assert!(f.iter().any(|x| x.message == "identity: Author = Bob"));
        assert!(f.iter().any(|x| x.message == "identity: Company = ACME"));
        assert!(f.iter().all(|x| x.severity == Severity::Info));
    }
}
