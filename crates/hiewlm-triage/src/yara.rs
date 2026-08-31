//! YARA scanning, via yara-x (pure Rust — no libyara, no native loading, which
//! is what lets it live inside hiewLM's security model).
//!
//! Compiled out unless the `yara` feature is on; the stub keeps the call sites
//! identical so the UI does not branch on a feature flag.

use crate::YaraHit;

/// Why a scan could not run, or did not match.
#[derive(Debug)]
pub enum YaraError {
    /// The build has no YARA support.
    Unsupported,
    /// The rule file did not compile (message from yara-x).
    Compile(String),
    Io(String),
    Scan(String),
}

impl std::fmt::Display for YaraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            YaraError::Unsupported => {
                f.write_str("this build has no YARA support — rebuild with `--features yara`")
            }
            YaraError::Compile(m) => write!(f, "rule error: {m}"),
            YaraError::Io(m) => write!(f, "cannot read rules: {m}"),
            YaraError::Scan(m) => write!(f, "scan failed: {m}"),
        }
    }
}

impl std::error::Error for YaraError {}

/// Compile `rules_source` and scan `data`.
#[cfg(feature = "yara")]
pub fn scan(rules_source: &str, data: &[u8]) -> Result<Vec<YaraHit>, YaraError> {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(rules_source)
        .map_err(|e| YaraError::Compile(e.to_string()))?;
    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner
        .scan(data)
        .map_err(|e| YaraError::Scan(e.to_string()))?;

    let mut out = Vec::new();
    for rule in results.matching_rules() {
        let mut matches = Vec::new();
        for pattern in rule.patterns() {
            for m in pattern.matches() {
                let range = m.range();
                matches.push((
                    range.start as u64,
                    (range.end - range.start) as u64,
                    pattern.identifier().to_string(),
                ));
            }
        }
        matches.sort_by_key(|m| m.0);
        out.push(YaraHit {
            rule: rule.identifier().to_string(),
            tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
            matches,
        });
    }
    Ok(out)
}

#[cfg(not(feature = "yara"))]
pub fn scan(_rules_source: &str, _data: &[u8]) -> Result<Vec<YaraHit>, YaraError> {
    Err(YaraError::Unsupported)
}

/// True when this build can scan.
pub const fn available() -> bool {
    cfg!(feature = "yara")
}

/// Read a rule file (or every `.yar`/`.yara` in a directory) and scan.
pub fn scan_path(rules: &std::path::Path, data: &[u8]) -> Result<Vec<YaraHit>, YaraError> {
    let source = read_rules(rules)?;
    scan(&source, data)
}

/// Concatenate the rule sources at `path`: one file, or every rule file in a
/// directory (an analyst's rule collection is usually a folder).
pub fn read_rules(path: &std::path::Path) -> Result<String, YaraError> {
    if path.is_dir() {
        let mut all = String::new();
        let entries = std::fs::read_dir(path).map_err(|e| YaraError::Io(e.to_string()))?;
        let mut files: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yar") | Some("yara")
                )
            })
            .collect();
        files.sort();
        if files.is_empty() {
            return Err(YaraError::Io(format!(
                "no .yar/.yara files in {}",
                path.display()
            )));
        }
        for f in files {
            let text = std::fs::read_to_string(&f).map_err(|e| YaraError::Io(e.to_string()))?;
            all.push_str(&text);
            all.push('\n');
        }
        Ok(all)
    } else {
        std::fs::read_to_string(path).map_err(|e| YaraError::Io(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_build_says_how_to_enable() {
        if !available() {
            let e = scan("rule x { condition: true }", b"abc").unwrap_err();
            assert!(e.to_string().contains("--features yara"));
        }
    }

    #[cfg(feature = "yara")]
    #[test]
    fn matches_a_string_and_reports_its_offset() {
        let rules = r#"
            rule finds_marker : demo {
                strings: $a = "INFECTED"
                condition: $a
            }
        "#;
        let hits = scan(rules, b"harmless.....INFECTED.....tail").expect("scan");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "finds_marker");
        assert_eq!(hits[0].tags, vec!["demo".to_string()]);
        assert_eq!(hits[0].matches[0].0, 13);
        assert_eq!(hits[0].matches[0].1, 8);
    }

    #[cfg(feature = "yara")]
    #[test]
    fn broken_rules_report_a_compile_error() {
        let e = scan("rule { this is not yara }", b"x").unwrap_err();
        assert!(matches!(e, YaraError::Compile(_)), "{e}");
    }

    #[test]
    fn missing_rule_file_is_an_io_error() {
        let e = read_rules(std::path::Path::new("/nonexistent/rules.yar")).unwrap_err();
        assert!(matches!(e, YaraError::Io(_)), "{e}");
    }
}
