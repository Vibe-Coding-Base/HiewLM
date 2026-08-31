//! The document indicator table, loaded from `data/documents.txt`.
//!
//! These used to be `const` arrays scattered across the modules that used them,
//! which meant adding an indicator was a code change — inconsistent with every
//! other detection table in hiewLM, and invisible in review among the logic.

use hiewlm_core::Severity;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// One indicator: what to look for, how much it matters, and why.
#[derive(Clone, Debug)]
pub struct DocRule {
    /// Matched case-insensitively as a substring.
    pub value: String,
    /// Lowercase copy, so matching does not re-allocate per candidate.
    pub needle: String,
    pub severity: Severity,
    pub note: String,
}

fn table() -> &'static BTreeMap<String, Vec<DocRule>> {
    static TABLE: OnceLock<BTreeMap<String, Vec<DocRule>>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut map: BTreeMap<String, Vec<DocRule>> = BTreeMap::new();
        for row in hiewlm_core::ruledata::table("documents", 4) {
            let severity = if row[2].eq_ignore_ascii_case("suspicious") {
                Severity::Suspicious
            } else {
                Severity::Info
            };
            map.entry(row[0].clone()).or_default().push(DocRule {
                needle: row[1].to_ascii_lowercase(),
                value: row[1].clone(),
                severity,
                note: row[3].clone(),
            });
        }
        map
    })
}

/// The rules of one kind (`ole`, `ooxml`, `rtf`, `pdf`, `vba-execution`, …).
pub fn rules(kind: &str) -> &'static [DocRule] {
    table().get(kind).map(Vec::as_slice).unwrap_or(&[])
}

/// The VBA keyword groups, in report order.
pub const VBA_GROUPS: [&str; 8] = [
    "vba-autoexec",
    "vba-execution",
    "vba-download",
    "vba-memory",
    "vba-persistence",
    "vba-obfuscation",
    "vba-evasion",
    "vba-lure",
];

/// Total rules loaded, for `hiewlmc rules`.
pub fn rule_count() -> usize {
    table().values().map(Vec::len).sum()
}

/// The first rule of `kind` whose value occurs in `haystack` (already lowercase).
pub fn first_match<'a>(kind: &'a str, haystack_lower: &str) -> Option<&'a DocRule> {
    rules(kind)
        .iter()
        .find(|r| haystack_lower.contains(&r.needle))
}

/// Every rule of `kind` whose value occurs in `haystack` (already lowercase).
pub fn all_matches<'a>(kind: &'a str, haystack_lower: &str) -> Vec<&'a DocRule> {
    rules(kind)
        .iter()
        .filter(|r| haystack_lower.contains(&r.needle))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_is_populated() {
        for kind in ["ole", "ooxml", "rtf", "pdf"] {
            assert!(!rules(kind).is_empty(), "no rules for `{kind}`");
        }
        for group in VBA_GROUPS {
            assert!(!rules(group).is_empty(), "no rules for `{group}`");
        }
        assert!(rule_count() > 150, "only {} rules loaded", rule_count());
    }

    #[test]
    fn matching_is_case_insensitive_and_carries_the_reason() {
        let hit = first_match("rtf", "{\\rtf1\\OBJUPDATE}".to_ascii_lowercase().as_str())
            .expect("objupdate");
        assert_eq!(hit.severity, Severity::Suspicious);
        assert!(hit.note.contains("no click"), "{}", hit.note);
    }

    #[test]
    fn an_unknown_kind_is_empty_not_a_panic() {
        assert!(rules("no-such-kind").is_empty());
        assert!(first_match("no-such-kind", "anything").is_none());
    }
}
