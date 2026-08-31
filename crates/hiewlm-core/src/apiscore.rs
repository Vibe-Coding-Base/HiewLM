//! Import risk tagging: turn a flat import list into behaviour categories.
//!
//! A PE's import table is the cheapest capability signal there is — you can read
//! "injects into another process, resolves APIs at runtime, talks HTTP, and
//! checks for a debugger" straight off it before disassembling a byte. This
//! module maps API names to behaviour categories and scores the mix.
//!
//! It is a *hint* engine: benign software imports these too. The score orders a
//! queue of samples; it does not convict one.

use std::collections::BTreeMap;

/// Behaviour bucket for an imported API.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Category {
    Injection,
    Evasion,
    Credentials,
    Ransom,
    AntiAnalysis,
    Lateral,
    DynamicResolve,
    Capture,
    Persistence,
    Privilege,
    Crypto,
    Network,
    Discovery,
    Process,
    Service,
    Com,
    Memory,
    Registry,
    FileSystem,
    Sync,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Injection => "injection",
            Category::Evasion => "evasion",
            Category::Credentials => "credentials",
            Category::Ransom => "ransom",
            Category::AntiAnalysis => "anti-analysis",
            Category::Lateral => "lateral",
            Category::DynamicResolve => "dynamic-resolve",
            Category::Capture => "capture",
            Category::Persistence => "persistence",
            Category::Privilege => "privilege",
            Category::Crypto => "crypto",
            Category::Network => "network",
            Category::Discovery => "discovery",
            Category::Process => "process",
            Category::Service => "service",
            Category::Com => "com",
            Category::Memory => "memory",
            Category::Registry => "registry",
            Category::FileSystem => "filesystem",
            Category::Sync => "sync",
        }
    }

    /// Parse the behaviour column of the rule table.
    pub fn parse(name: &str) -> Option<Category> {
        Some(match name {
            "injection" => Category::Injection,
            "evasion" => Category::Evasion,
            "credentials" => Category::Credentials,
            "ransom" => Category::Ransom,
            "anti-analysis" => Category::AntiAnalysis,
            "lateral" => Category::Lateral,
            "dynamic-resolve" => Category::DynamicResolve,
            "capture" => Category::Capture,
            "persistence" => Category::Persistence,
            "privilege" => Category::Privilege,
            "crypto" => Category::Crypto,
            "network" => Category::Network,
            "discovery" => Category::Discovery,
            // `shell` used to be its own bucket; running another program is
            // process behaviour, and keeping the old name working means an
            // analyst's existing rules file does not break.
            "process" | "shell" => Category::Process,
            "service" => Category::Service,
            "com" => Category::Com,
            "memory" => Category::Memory,
            "registry" => Category::Registry,
            "filesystem" => Category::FileSystem,
            "sync" => Category::Sync,
            _ => return None,
        })
    }

    /// Contribution of the category to the overall suspicion score.
    pub fn weight(self) -> u8 {
        match self {
            Category::Injection => 30,
            Category::Evasion => 28,
            Category::Credentials => 26,
            Category::Ransom => 26,
            Category::AntiAnalysis => 20,
            Category::Lateral => 18,
            Category::DynamicResolve => 15,
            Category::Capture => 15,
            Category::Persistence => 12,
            Category::Privilege => 12,
            Category::Crypto => 10,
            Category::Network => 10,
            Category::Discovery => 8,
            Category::Process => 8,
            Category::Service => 8,
            Category::Com => 6,
            Category::Memory => 5,
            Category::Registry => 4,
            Category::FileSystem => 3,
            Category::Sync => 2,
        }
    }
}

/// One entry of the API table, parsed once from `data/apis.txt`.
struct ApiRule {
    /// Lowercase API name as written in the table.
    name: String,
    category: Category,
    note: String,
    /// False for APIs common in benign software: listed, but not scored.
    strong: bool,
}

/// The table, loaded on first use (and from the user's rules directory when one
/// is present). Kept behind a `OnceLock` because a triage run over a folder
/// calls into this once per sample.
fn rules() -> &'static [ApiRule] {
    static RULES: std::sync::OnceLock<Vec<ApiRule>> = std::sync::OnceLock::new();
    RULES.get_or_init(|| {
        crate::ruledata::table("apis", 4)
            .into_iter()
            .filter_map(|row| {
                Some(ApiRule {
                    category: Category::parse(&row[0])?,
                    name: row[1].to_ascii_lowercase(),
                    strong: row[2].eq_ignore_ascii_case("strong"),
                    note: row[3].clone(),
                })
            })
            .collect()
    })
}

/// How many API rules are loaded — shown by `hiewlmc rules`.
pub fn rule_count() -> usize {
    rules().len()
}

/// One matched import.
#[derive(Clone, Debug)]
pub struct ApiHit {
    /// The import as it appeared, e.g. `kernel32.dll!VirtualAllocEx`.
    pub full: String,
    pub func: String,
    pub category: Category,
    pub note: String,
    /// False for APIs common in benign software: listed, but not scored.
    pub strong: bool,
}

/// Verdict over a whole import table.
#[derive(Clone, Debug, Default)]
pub struct ImportReport {
    pub hits: Vec<ApiHit>,
    /// 0..100 — how loudly the import mix suggests malicious capability.
    pub score: u8,
    /// Extra observations that are not a single API (tiny IAT, resolve pair, …).
    pub notes: Vec<String>,
    pub total_imports: usize,
}

impl ImportReport {
    /// Categories present, each with its matched APIs, in category order.
    pub fn by_category(&self) -> BTreeMap<Category, Vec<&ApiHit>> {
        let mut map: BTreeMap<Category, Vec<&ApiHit>> = BTreeMap::new();
        for h in &self.hits {
            map.entry(h.category).or_default().push(h);
        }
        map
    }

    pub fn verdict(&self) -> &'static str {
        match self.score {
            0..=19 => "low",
            20..=44 => "notable",
            45..=69 => "suspicious",
            _ => "high",
        }
    }
}

/// Look up one API name (with or without a `dll!` prefix and A/W suffix).
pub fn categorize(name: &str) -> Option<(Category, &'static str)> {
    lookup(name).map(|(c, n, _)| (c, n))
}

/// As [`categorize`], plus whether the API is a strong signal on its own.
///
/// One table entry covers `CreateFileA` and `CreateFileW`: the trailing
/// character is dropped when the base name is what the table lists.
pub fn lookup(name: &str) -> Option<(Category, &'static str, bool)> {
    let func = name.rsplit('!').next().unwrap_or(name);
    let lower = func.to_ascii_lowercase();
    let trimmed = lower.strip_suffix(['a', 'w']).unwrap_or(&lower);
    for candidate in [lower.as_str(), trimmed] {
        if let Some(r) = rules().iter().find(|r| r.name == candidate) {
            return Some((r.category, r.note.as_str(), r.strong));
        }
    }
    None
}

/// Score a whole import table. `names` are `dll!func` (or bare `func`) strings.
///
/// Assumes the format has a real import table whose size is meaningful (PE).
pub fn analyze(names: &[String]) -> ImportReport {
    analyze_with(names, true)
}

/// As [`analyze`], but `iat_size_matters` says whether a short list is itself a
/// signal. It is for a PE — a Windows program with five imports is hiding
/// something — and it is not for Mach-O/ELF, where linkers legitimately emit a
/// handful of entries.
pub fn analyze_with(names: &[String], iat_size_matters: bool) -> ImportReport {
    let mut report = ImportReport { total_imports: names.len(), ..Default::default() };
    for full in names {
        let func = full.rsplit('!').next().unwrap_or(full).to_string();
        if let Some((category, note, strong)) = lookup(full) {
            report.hits.push(ApiHit {
                full: full.clone(),
                func,
                category,
                note: note.to_string(),
                strong,
            });
        }
    }

    // Score: each present category counts once (a program importing five file
    // APIs is not five times more suspicious), with a bonus for the pairs that
    // only make sense together.
    let present: std::collections::BTreeSet<Category> =
        report.hits.iter().map(|h| h.category).collect();
    // Only categories backed by at least one strong API contribute weight; the
    // rest are still shown, because they are context for the strong ones.
    let scoring: std::collections::BTreeSet<Category> =
        report.hits.iter().filter(|h| h.strong).map(|h| h.category).collect();
    let mut score: u32 = scoring.iter().map(|c| c.weight() as u32).sum();

    let has = |c: Category| present.contains(&c);
    if iat_size_matters && has(Category::DynamicResolve) && report.total_imports > 0 && report.total_imports <= 15 {
        report.notes.push(format!(
            "only {} imports but resolves APIs at runtime — the real import table is hidden",
            report.total_imports
        ));
        score += 25;
    } else if iat_size_matters && report.total_imports > 0 && report.total_imports <= 8 {
        report.notes.push(format!("tiny import table ({}) — packed or dynamically resolved", report.total_imports));
        score += 15;
    }
    if has(Category::Injection) && has(Category::Memory) {
        report.notes.push("allocate + write + execute in another process: injection chain".into());
        score += 10;
    }
    if has(Category::Crypto) && has(Category::FileSystem) {
        report.notes.push("crypto + file enumeration: ransomware shape".into());
        score += 10;
    }
    if has(Category::Capture) && has(Category::Network) {
        report.notes.push("capture + network: spyware/exfiltration shape".into());
        score += 10;
    }
    report.score = score.min(100) as u8;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_with_dll_prefix_and_ansi_suffix() {
        assert_eq!(categorize("kernel32.dll!CreateFileW").map(|(c, _)| c), Some(Category::FileSystem));
        assert_eq!(categorize("CreateRemoteThread").map(|(c, _)| c), Some(Category::Injection));
        assert_eq!(categorize("advapi32.dll!RegSetValueExA").map(|(c, _)| c), Some(Category::Persistence));
        assert!(categorize("kernel32.dll!lstrlenW").is_none());
    }

    #[test]
    fn injection_chain_scores_high() {
        let r = analyze(&names(&[
            "kernel32.dll!OpenProcess",
            "kernel32.dll!VirtualAllocEx",
            "kernel32.dll!WriteProcessMemory",
            "kernel32.dll!CreateRemoteThread",
            "kernel32.dll!VirtualProtect",
        ]));
        assert!(r.score >= 45, "{r:?}");
        assert!(r.notes.iter().any(|n| n.contains("injection chain")));
        assert!(r.by_category().contains_key(&Category::Injection));
    }

    #[test]
    fn ubiquitous_apis_alone_do_not_raise_the_score() {
        // A stock C-runtime import list: listed for context, but not damning.
        let r = analyze(&names(&[
            "kernel32.dll!QueryPerformanceCounter",
            "kernel32.dll!GetTickCount",
            "kernel32.dll!SetUnhandledExceptionFilter",
            "kernel32.dll!AddVectoredExceptionHandler",
            "kernel32.dll!CreateFileW",
            "kernel32.dll!WriteFile",
            "kernel32.dll!VirtualAlloc",
            "kernel32.dll!VirtualProtect",
            "kernel32.dll!GetProcAddress",
            "kernel32.dll!LoadLibraryA",
            "user32.dll!GetForegroundWindow",
            "advapi32.dll!RegOpenKeyExW",
            "kernel32.dll!CreateFileMappingW",
            "kernel32.dll!MapViewOfFile",
            "kernel32.dll!CreateMutexW",
            "kernel32.dll!GetTempPathW",
        ]));
        assert!(!r.hits.is_empty(), "they are still reported");
        assert!(r.hits.iter().all(|h| !h.strong));
        assert!(r.score < 20, "weak APIs alone should stay quiet, got {}", r.score);
    }

    #[test]
    fn weak_apis_still_count_toward_combination_rules() {
        // Tiny IAT plus runtime resolution: individually weak, together loud.
        let r = analyze(&names(&["kernel32.dll!LoadLibraryA", "kernel32.dll!GetProcAddress"]));
        assert!(r.notes.iter().any(|n| n.contains("hidden")), "{r:?}");
    }

    #[test]
    fn benign_import_list_scores_low() {
        let r = analyze(&names(&[
            "kernel32.dll!lstrcmpW",
            "user32.dll!MessageBoxW",
            "msvcrt.dll!printf",
            "kernel32.dll!GetCommandLineW",
            "kernel32.dll!ExitProcess",
            "kernel32.dll!HeapFree",
            "kernel32.dll!GetLastError",
            "kernel32.dll!SetLastError",
            "kernel32.dll!MultiByteToWideChar",
        ]));
        assert!(r.score < 20, "{r:?}");
    }

    #[test]
    fn tiny_iat_with_dynamic_resolve_is_flagged() {
        let r = analyze(&names(&["kernel32.dll!LoadLibraryA", "kernel32.dll!GetProcAddress"]));
        assert!(r.notes.iter().any(|n| n.contains("hidden")), "{r:?}");
    }
}
