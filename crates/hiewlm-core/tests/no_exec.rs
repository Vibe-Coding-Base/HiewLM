//! Security pillar (design §22.7): scan the source to guarantee no code path loads
//! or executes target-file content.

use std::fs;
use std::path::{Path, PathBuf};

/// Process-spawning / code-loading APIs that must never appear — these would let
/// the target file's content run. (Note: `std::process::exit`/`ExitCode` are self
/// process-control, not execution, and are allowed — e.g. the CLI's exit codes.)
const FORBIDDEN: &[&str] = &[
    "Command::new",
    "process::Command",
    "libloading",
    "dlopen",
    "LoadLibrary",
];

fn workspace_root() -> PathBuf {
    // crates/hiewlm-core -> ../../
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// Strip line comments and string literals so the scan sees executable code
/// only. Prose may legitimately name a banned API to explain why it is banned
/// (see `container.rs`), and format parsers legitimately carry format keywords
/// as data literals; neither is a call.
fn code_only(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let mut in_str = false;
        let mut prev_backslash = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if !in_str && c == '/' && chars.peek() == Some(&'/') {
                break; // line comment: drop the rest
            }
            if c == '"' && !prev_backslash {
                in_str = !in_str;
                out.push(' ');
                continue;
            }
            prev_backslash = in_str && c == '\\' && !prev_backslash;
            out.push(if in_str { ' ' } else { c });
        }
        out.push('\n');
    }
    out
}

fn scan(dir: &Path, hits: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name == "target" || name.starts_with('.') {
                continue;
            }
            scan(&path, hits);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            // This test itself contains the forbidden strings, so exclude it.
            if name == "no_exec.rs" {
                continue;
            }
            let Ok(src) = fs::read_to_string(&path) else {
                continue;
            };
            let code = code_only(&src);
            for needle in FORBIDDEN {
                if code.contains(needle) {
                    hits.push(format!("{}: contains `{needle}`", path.display()));
                }
            }
        }
    }
}

/// The stripper must not blind the guard: real calls still have to be caught.
#[test]
fn code_only_still_detects_real_usage() {
    let real = "fn go() { let _ = std::process::Command::new(\"sh\"); }";
    let stripped = code_only(real);
    assert!(FORBIDDEN.iter().any(|n| stripped.contains(n)), "{stripped}");

    let via_import = "use libloading::Library;\nfn f() {}";
    assert!(code_only(via_import).contains("libloading"));
}

/// ...but prose and data literals naming an API are not calls.
#[test]
fn code_only_ignores_comments_and_literals() {
    assert!(!code_only("// we never call dlopen here").contains("dlopen"));
    assert!(!code_only("/// Explains why LoadLibrary is banned.").contains("LoadLibrary"));
    assert!(!code_only("let s = \"dlopen\";").contains("dlopen"));
    assert!(!code_only("let m = MARKER(\"LoadLibrary\"); // and dlopen").contains("LoadLibrary"));
    // Code after a closing quote is still scanned.
    assert!(code_only("let s = \"x\"; Command::new(y)").contains("Command::new"));
}

#[test]
fn no_code_execution_apis_in_source() {
    let mut hits = Vec::new();
    scan(&workspace_root().join("crates"), &mut hits);
    assert!(
        hits.is_empty(),
        "Found forbidden code-loading/execution APIs (design §22.1):\n{}",
        hits.join("\n")
    );
}
