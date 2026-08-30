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
    DynamicResolve,
    AntiAnalysis,
    Network,
    Crypto,
    Persistence,
    Privilege,
    Process,
    Memory,
    FileSystem,
    Registry,
    Capture,
    Service,
    Shell,
    Sync,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Injection => "injection",
            Category::DynamicResolve => "dynamic-resolve",
            Category::AntiAnalysis => "anti-analysis",
            Category::Network => "network",
            Category::Crypto => "crypto",
            Category::Persistence => "persistence",
            Category::Privilege => "privilege",
            Category::Process => "process",
            Category::Memory => "memory",
            Category::FileSystem => "filesystem",
            Category::Registry => "registry",
            Category::Capture => "capture",
            Category::Service => "service",
            Category::Shell => "shell",
            Category::Sync => "sync",
        }
    }

    /// Contribution of the category to the overall suspicion score.
    pub fn weight(self) -> u8 {
        match self {
            Category::Injection => 30,
            Category::AntiAnalysis => 20,
            Category::DynamicResolve => 15,
            Category::Capture => 15,
            Category::Persistence => 12,
            Category::Privilege => 12,
            Category::Crypto => 10,
            Category::Network => 10,
            Category::Process => 8,
            Category::Service => 8,
            Category::Shell => 8,
            Category::Memory => 5,
            Category::Registry => 4,
            Category::FileSystem => 3,
            Category::Sync => 2,
        }
    }
}

/// `(lowercase api name, category, why it matters)`.
type Entry = (&'static str, Category, &'static str);

const TABLE: &[Entry] = &[
    // -- Process injection / code execution in another process ---------------
    ("writeprocessmemory", Category::Injection, "writes into another process"),
    ("readprocessmemory", Category::Injection, "reads another process"),
    ("virtualallocex", Category::Injection, "allocates in another process"),
    ("virtualprotectex", Category::Injection, "changes page rights remotely"),
    ("createremotethread", Category::Injection, "starts a thread in another process"),
    ("ntcreatethreadex", Category::Injection, "undocumented remote thread"),
    ("rtlcreateuserthread", Category::Injection, "undocumented remote thread"),
    ("queueuserapc", Category::Injection, "APC injection"),
    ("ntqueueapcthread", Category::Injection, "APC injection"),
    ("setthreadcontext", Category::Injection, "process hollowing"),
    ("getthreadcontext", Category::Injection, "process hollowing"),
    ("ntunmapviewofsection", Category::Injection, "unmaps the original image (hollowing)"),
    ("zwunmapviewofsection", Category::Injection, "unmaps the original image (hollowing)"),
    ("ntmapviewofsection", Category::Injection, "section-based injection"),
    ("setwindowshookex", Category::Injection, "loads a DLL into other processes"),
    ("createprocessinternalw", Category::Injection, "low-level process creation"),
    // -- Runtime API resolution (imports hidden from the IAT) ----------------
    ("loadlibrary", Category::DynamicResolve, "loads a module at runtime"),
    ("loadlibraryex", Category::DynamicResolve, "loads a module at runtime"),
    ("getprocaddress", Category::DynamicResolve, "resolves APIs at runtime"),
    ("ldrloaddll", Category::DynamicResolve, "loader-level module load"),
    ("ldrgetprocedureaddress", Category::DynamicResolve, "loader-level resolve"),
    // -- Anti-debug / anti-analysis ------------------------------------------
    ("isdebuggerpresent", Category::AntiAnalysis, "debugger check"),
    ("checkremotedebuggerpresent", Category::AntiAnalysis, "debugger check"),
    ("ntqueryinformationprocess", Category::AntiAnalysis, "debug-flag query"),
    ("ntsetinformationthread", Category::AntiAnalysis, "hides threads from debuggers"),
    ("outputdebugstring", Category::AntiAnalysis, "debugger probe"),
    ("gettickcount", Category::AntiAnalysis, "timing check"),
    ("gettickcount64", Category::AntiAnalysis, "timing check"),
    ("queryperformancecounter", Category::AntiAnalysis, "timing check"),
    ("ntquerysysteminformation", Category::AntiAnalysis, "enumerates system/debug state"),
    ("createtoolhelp32snapshot", Category::AntiAnalysis, "enumerates processes (AV/sandbox check)"),
    ("process32first", Category::AntiAnalysis, "process enumeration"),
    ("process32next", Category::AntiAnalysis, "process enumeration"),
    ("findwindow", Category::AntiAnalysis, "looks for analysis tool windows"),
    ("blockinput", Category::AntiAnalysis, "blocks the analyst's input"),
    ("setunhandledexceptionfilter", Category::AntiAnalysis, "exception-based anti-debug"),
    ("addvectoredexceptionhandler", Category::AntiAnalysis, "exception-based control flow"),
    ("ntraiseexception", Category::AntiAnalysis, "exception-based control flow"),
    ("getsystemfirmwaretable", Category::AntiAnalysis, "VM fingerprinting"),
    // -- Network -------------------------------------------------------------
    ("internetopen", Category::Network, "WinINet HTTP client"),
    ("internetopenurl", Category::Network, "fetches a URL"),
    ("internetconnect", Category::Network, "connects out"),
    ("internetreadfile", Category::Network, "downloads content"),
    ("httpsendrequest", Category::Network, "HTTP request"),
    ("httpopenrequest", Category::Network, "HTTP request"),
    ("winhttpopen", Category::Network, "WinHTTP client"),
    ("winhttpconnect", Category::Network, "connects out"),
    ("winhttpsendrequest", Category::Network, "HTTP request"),
    ("winhttpreaddata", Category::Network, "downloads content"),
    ("urldownloadtofile", Category::Network, "downloads to disk (dropper)"),
    ("wsastartup", Category::Network, "raw sockets"),
    ("socket", Category::Network, "raw sockets"),
    ("connect", Category::Network, "outbound connection"),
    ("send", Category::Network, "sends data"),
    ("recv", Category::Network, "receives data"),
    ("bind", Category::Network, "listens (backdoor)"),
    ("listen", Category::Network, "listens (backdoor)"),
    ("accept", Category::Network, "accepts connections (backdoor)"),
    ("gethostbyname", Category::Network, "DNS lookup"),
    ("getaddrinfo", Category::Network, "DNS lookup"),
    ("dnsquery_a", Category::Network, "DNS lookup"),
    ("ftpputfile", Category::Network, "exfiltration over FTP"),
    // -- Crypto --------------------------------------------------------------
    ("cryptencrypt", Category::Crypto, "encrypts data (ransomware / C2)"),
    ("cryptdecrypt", Category::Crypto, "decrypts data (config / payload)"),
    ("cryptgenkey", Category::Crypto, "generates keys"),
    ("cryptderivekey", Category::Crypto, "derives keys from a password"),
    ("cryptacquirecontext", Category::Crypto, "crypto provider"),
    ("cryptimportkey", Category::Crypto, "imports an embedded key"),
    ("bcryptencrypt", Category::Crypto, "encrypts data (CNG)"),
    ("bcryptdecrypt", Category::Crypto, "decrypts data (CNG)"),
    ("bcryptgeneratesymmetrickey", Category::Crypto, "symmetric key (CNG)"),
    ("crypthashdata", Category::Crypto, "hashing"),
    ("cryptstringtobinary", Category::Crypto, "decodes base64 blobs"),
    // -- Persistence ---------------------------------------------------------
    ("regsetvalueex", Category::Persistence, "writes a registry value (Run key?)"),
    ("regcreatekeyex", Category::Persistence, "creates a registry key"),
    ("createservice", Category::Persistence, "installs a service"),
    ("openscmanager", Category::Service, "service control"),
    ("startservice", Category::Service, "starts a service"),
    ("controlservice", Category::Service, "controls a service"),
    ("deleteservice", Category::Service, "removes a service"),
    ("schedule", Category::Persistence, "scheduled task"),
    ("copyfile", Category::Persistence, "copies itself"),
    ("moveFileEx", Category::Persistence, "replaces a file on reboot"),
    ("getstartupinfo", Category::Process, "startup context"),
    // -- Privilege -----------------------------------------------------------
    ("adjusttokenprivileges", Category::Privilege, "raises privileges"),
    ("openprocesstoken", Category::Privilege, "token access"),
    ("lookupprivilegevalue", Category::Privilege, "privilege lookup"),
    ("impersonateloggedonuser", Category::Privilege, "impersonation"),
    ("duplicatetokenex", Category::Privilege, "token theft"),
    ("shellexecute", Category::Shell, "runs another program"),
    ("shellexecuteex", Category::Shell, "runs another program"),
    ("winexec", Category::Shell, "runs another program"),
    ("system", Category::Shell, "runs a shell command"),
    ("createprocess", Category::Process, "creates a process"),
    ("openprocess", Category::Process, "opens another process"),
    ("terminateprocess", Category::Process, "kills a process"),
    ("exitwindowsex", Category::Process, "reboots/shuts down"),
    ("initiatesystemshutdown", Category::Process, "reboots/shuts down"),
    // -- Memory --------------------------------------------------------------
    ("virtualalloc", Category::Memory, "allocates memory (unpacking)"),
    ("virtualprotect", Category::Memory, "makes memory executable"),
    ("ntprotectvirtualmemory", Category::Memory, "makes memory executable"),
    ("ntallocatevirtualmemory", Category::Memory, "allocates memory"),
    ("heapcreate", Category::Memory, "private heap"),
    ("createfilemapping", Category::Memory, "shared section"),
    ("mapviewoffile", Category::Memory, "maps a section"),
    // -- Filesystem / registry -----------------------------------------------
    ("createfile", Category::FileSystem, "file access"),
    ("writefile", Category::FileSystem, "writes a file"),
    ("deletefile", Category::FileSystem, "deletes a file"),
    ("findfirstfile", Category::FileSystem, "enumerates files"),
    ("findnextfile", Category::FileSystem, "enumerates files"),
    ("setfileattributes", Category::FileSystem, "hides files"),
    ("gettemppath", Category::FileSystem, "drops to %TEMP%"),
    ("shgetfolderpath", Category::FileSystem, "locates user folders"),
    ("shgetknownfolderpath", Category::FileSystem, "locates user folders"),
    ("regopenkeyex", Category::Registry, "reads the registry"),
    ("regqueryvalueex", Category::Registry, "reads a registry value"),
    ("regdeletevalue", Category::Registry, "deletes a registry value"),
    ("regenumkeyex", Category::Registry, "enumerates the registry"),
    // -- Capture (spyware) ---------------------------------------------------
    ("getasynckeystate", Category::Capture, "keylogging"),
    ("getkeystate", Category::Capture, "keylogging"),
    ("getkeyboardstate", Category::Capture, "keylogging"),
    ("getforegroundwindow", Category::Capture, "tracks the active window"),
    ("getwindowtext", Category::Capture, "reads window titles"),
    ("bitblt", Category::Capture, "screen capture"),
    ("getdc", Category::Capture, "screen capture"),
    ("createcompatiblebitmap", Category::Capture, "screen capture"),
    ("waveinopen", Category::Capture, "microphone capture"),
    ("capcreatecapturewindow", Category::Capture, "webcam capture"),
    ("getclipboarddata", Category::Capture, "clipboard theft"),
    // -- Sync ----------------------------------------------------------------
    ("createmutex", Category::Sync, "single-instance mutex (IOC)"),
    ("openmutex", Category::Sync, "single-instance mutex (IOC)"),
    ("createevent", Category::Sync, "named event"),
];

/// APIs that appear in almost every compiled program (CRT startup, ordinary
/// file and registry access). They stay in the table because context matters —
/// `GetTickCount` next to `IsDebuggerPresent` is a timing check — but on their
/// own they must not raise the score, or every Rust and MSVC binary looks armed.
const WEAK: &[&str] = &[
    "gettickcount",
    "gettickcount64",
    "queryperformancecounter",
    "setunhandledexceptionfilter",
    "addvectoredexceptionhandler",
    "outputdebugstring",
    "ntquerysysteminformation",
    "getforegroundwindow",
    "getwindowtext",
    "getdc",
    "createfile",
    "writefile",
    "deletefile",
    "findfirstfile",
    "findnextfile",
    "setfileattributes",
    "gettemppath",
    "shgetfolderpath",
    "shgetknownfolderpath",
    "regopenkeyex",
    "regqueryvalueex",
    "regenumkeyex",
    "regdeletevalue",
    "createevent",
    "createmutex",
    "openmutex",
    "mapviewoffile",
    "createfilemapping",
    "heapcreate",
    "virtualalloc",
    "virtualprotect",
    "getstartupinfo",
    "createprocess",
    "loadlibrary",
    "loadlibraryex",
    "getprocaddress",
    "getlasterror",
    "copyfile",
];

/// One matched import.
#[derive(Clone, Debug)]
pub struct ApiHit {
    /// The import as it appeared, e.g. `kernel32.dll!VirtualAllocEx`.
    pub full: String,
    pub func: String,
    pub category: Category,
    pub note: &'static str,
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
pub fn lookup(name: &str) -> Option<(Category, &'static str, bool)> {
    let func = name.rsplit('!').next().unwrap_or(name);
    let lower = func.to_ascii_lowercase();
    let candidates = [
        lower.as_str(),
        lower.strip_suffix('a').unwrap_or(&lower),
        lower.strip_suffix('w').unwrap_or(&lower),
    ];
    for c in candidates {
        if let Some((n, cat, note)) = TABLE.iter().find(|(n, _, _)| *n == c) {
            return Some((*cat, *note, !WEAK.contains(n)));
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
            report.hits.push(ApiHit { full: full.clone(), func, category, note, strong });
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
