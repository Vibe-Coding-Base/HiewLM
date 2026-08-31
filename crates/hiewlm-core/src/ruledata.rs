//! Loading the signature tables that drive detection.
//!
//! The tables used to be Rust literals in the middle of the code that consumed
//! them, which made the two things that happen most often — "add an API",
//! "add a packer" — a code change, invisible in review among the logic.
//!
//! They now live in `data/*.txt`, embedded at build time so a binary is still
//! self-contained, and overridable at run time from a rules directory so an
//! analyst can extend them without a toolchain. Only *data* is ever read: no
//! path here can introduce code (design §22.1).
//!
//! ## Format
//!
//! One record per line, fields separated by `|`, `#` starts a comment. Blank
//! lines are ignored and whitespace around fields is trimmed. Deliberately not
//! TOML or JSON: these are flat tables, and a line-per-record file stays
//! readable in a diff when a hundred entries are added at once.

use std::path::PathBuf;

/// A parsed record: the fields of one line, already trimmed.
pub type Row = Vec<String>;

/// The built-in tables, embedded so the binary needs no data files beside it.
const BUILTIN: &[(&str, &str)] = &[
    ("apis", include_str!("../data/apis.txt")),
    ("packers", include_str!("../data/packers.txt")),
    ("indicators", include_str!("../data/indicators.txt")),
    ("documents", include_str!("../data/documents.txt")),
];

/// Where run-time overrides are looked for: `$HIEWLM_RULES_DIR`, else
/// `$XDG_CONFIG_HOME/hiewlm/rules`, else `~/.config/hiewlm/rules`, else
/// `%APPDATA%\hiewlm\rules`.
pub fn rules_dir() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("HIEWLM_RULES_DIR") {
        return Some(PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))?;
    Some(base.join("hiewlm").join("rules"))
}

/// The source text of a table: the user's `<rules_dir>/<name>.txt` when it
/// exists, else the built-in copy.
///
/// An override *replaces* the built-in rather than merging with it, so what you
/// get is exactly what you can read in one file — a merge would leave you
/// guessing which entry won.
fn source(name: &str) -> String {
    source_in(rules_dir().as_deref(), name)
}

/// The seam the tests use: an explicit directory instead of the process-wide
/// environment, so a test cannot race another one that is loading a table.
fn source_in(dir: Option<&std::path::Path>, name: &str) -> String {
    if let Some(dir) = dir {
        if let Ok(text) = std::fs::read_to_string(dir.join(format!("{name}.txt"))) {
            return text;
        }
    }
    BUILTIN
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, text)| (*text).to_string())
        .unwrap_or_default()
}

/// Parse a table into rows of at least `min_fields` fields. Short or malformed
/// lines are skipped rather than failing the load: one bad line an analyst added
/// must not take the whole table down.
pub fn table(name: &str, min_fields: usize) -> Vec<Row> {
    parse(&source(name), min_fields)
}

/// [`table`], reading overrides from an explicit directory. Test-only.
#[cfg(test)]
pub(crate) fn table_in(dir: Option<&std::path::Path>, name: &str, min_fields: usize) -> Vec<Row> {
    parse(&source_in(dir, name), min_fields)
}

pub fn parse(text: &str, min_fields: usize) -> Vec<Row> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<String> = line.split('|').map(|f| f.trim().to_string()).collect();
        if fields.len() >= min_fields && !fields[0].is_empty() {
            out.push(fields);
        }
    }
    out
}

/// Names of the built-in tables, for `hiewlmc rules`.
pub fn builtin_names() -> Vec<&'static str> {
    BUILTIN.iter().map(|(n, _)| *n).collect()
}

/// Whether a table is currently being overridden from disk, and from where.
pub fn override_path(name: &str) -> Option<PathBuf> {
    let path = rules_dir()?.join(format!("{name}.txt"));
    path.is_file().then_some(path)
}

/// The built-in text of a table, for `hiewlmc rules --dump`.
pub fn builtin(name: &str) -> Option<&'static str> {
    BUILTIN.iter().find(|(n, _)| *n == name).map(|(_, t)| *t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_and_ignores_comments() {
        let text = "\
# behaviour | api | strength | note
injection | WriteProcessMemory | strong | writes into another process

  network  |  connect  | weak | outbound   # trailing comment
tld | com
bad line without any separator
";
        let rows = parse(text, 4);
        assert_eq!(rows.len(), 2, "short rows are dropped at min 4: {rows:?}");
        assert_eq!(rows[0][1], "WriteProcessMemory");
        // Whitespace is trimmed and the trailing comment removed.
        assert_eq!(rows[1], vec!["network", "connect", "weak", "outbound"]);

        // A two-field table sees the short row as well.
        let rows = parse(text, 2);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2], vec!["tld", "com"]);
    }

    #[test]
    fn every_builtin_table_parses_and_is_not_empty() {
        for name in builtin_names() {
            let rows = table(name, 2);
            assert!(!rows.is_empty(), "table `{name}` came back empty");
        }
    }

    #[test]
    fn a_file_in_the_rules_directory_replaces_the_builtin() {
        let dir = std::env::temp_dir().join("hiewlm_rules_override_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("indicators.txt"),
            "# my own vocabulary\ntld | example\nlolbin | my-custom-tool\n",
        )
        .unwrap();

        let rows = table_in(Some(&dir), "indicators", 2);
        assert_eq!(rows.len(), 2, "the override replaces, it does not merge");
        assert_eq!(rows[0], vec!["tld", "example"]);
        // A table with no override in that directory still comes from the
        // built-in copy.
        assert!(table_in(Some(&dir), "apis", 4).len() > 100);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_table_is_empty_not_a_panic() {
        assert!(table("no-such-table", 2).is_empty());
        assert!(builtin("no-such-table").is_none());
    }
}
