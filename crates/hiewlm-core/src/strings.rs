//! String extraction with malware-triage classification.
//!
//! Two things separate this from `strings(1)`: it reads UTF-16LE (where Windows
//! malware keeps most of its interesting text) alongside ASCII, and it tags each
//! result with the indicator categories an analyst actually greps for — URLs,
//! IPs, registry keys, LOLBin command lines, PDB paths, mutexes.
//!
//! Everything here is pure byte inspection; nothing is decoded, followed or run.

use crate::addr::FileOffset;
use crate::buffer::EditBuffer;

/// How a string was encoded in the file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StrEnc {
    Ascii,
    Utf16Le,
}

impl StrEnc {
    pub fn label(self) -> &'static str {
        match self {
            StrEnc::Ascii => "a",
            StrEnc::Utf16Le => "w",
        }
    }
}

/// An indicator category. The order is the display/sort order: the categories an
/// analyst wants first come first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Kind {
    Url,
    Ipv4,
    Email,
    Domain,
    Registry,
    LolBin,
    UserAgent,
    Mutex,
    Path,
    Unc,
    Pdb,
    Guid,
    Base64,
    Module,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Url => "url",
            Kind::Ipv4 => "ip",
            Kind::Email => "email",
            Kind::Domain => "domain",
            Kind::Registry => "registry",
            Kind::LolBin => "lolbin",
            Kind::UserAgent => "user-agent",
            Kind::Mutex => "mutex",
            Kind::Path => "path",
            Kind::Unc => "unc",
            Kind::Pdb => "pdb",
            Kind::Guid => "guid",
            Kind::Base64 => "base64",
            Kind::Module => "module",
        }
    }

    /// How much this category should pull a string up the triage list (0..100).
    pub fn weight(self) -> u8 {
        match self {
            Kind::Url | Kind::Ipv4 => 90,
            Kind::LolBin => 85,
            Kind::Registry => 70,
            Kind::Domain | Kind::Email => 65,
            Kind::Unc | Kind::Mutex => 60,
            Kind::UserAgent => 55,
            Kind::Pdb => 50,
            Kind::Base64 => 40,
            Kind::Path => 30,
            Kind::Guid => 20,
            Kind::Module => 15,
        }
    }
}

/// One extracted string.
#[derive(Clone, Debug)]
pub struct FoundString {
    pub offset: u64,
    pub text: String,
    pub enc: StrEnc,
    pub kinds: Vec<Kind>,
}

impl FoundString {
    /// Triage interest: the strongest category, plus a nudge for wide strings
    /// (Windows malware hides its configuration in UTF-16).
    pub fn score(&self) -> u8 {
        let base = self.kinds.iter().map(|k| k.weight()).max().unwrap_or(0);
        let wide = u8::from(self.enc == StrEnc::Utf16Le && !self.kinds.is_empty()) * 3;
        base.saturating_add(wide)
    }

    /// `url,ip` — the categories, for display and filtering.
    pub fn kind_list(&self) -> String {
        self.kinds.iter().map(|k| k.label()).collect::<Vec<_>>().join(",")
    }
}

/// Extraction limits and encodings. Defaults are tuned for interactive triage.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub min_len: usize,
    pub ascii: bool,
    pub utf16: bool,
    /// Stop after this many results (0 = unlimited).
    pub max_results: usize,
    /// Stop after this many bytes of input (0 = whole file).
    pub max_bytes: u64,
    /// Keep only strings carrying at least one indicator category.
    pub only_tagged: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            min_len: 4,
            ascii: true,
            utf16: true,
            max_results: 50_000,
            max_bytes: 256 * 1024 * 1024,
            only_tagged: false,
        }
    }
}

/// Result of a scan, including whether limits cut it short — a silently
/// truncated string list hides exactly the appended payload you were looking for.
#[derive(Clone, Debug, Default)]
pub struct Scan {
    pub strings: Vec<FoundString>,
    pub truncated: bool,
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

/// A run of bytes being accumulated into a candidate string.
#[derive(Default)]
struct Run {
    start: u64,
    bytes: Vec<u8>,
}

impl Run {
    fn push(&mut self, at: u64, b: u8) {
        if self.bytes.is_empty() {
            self.start = at;
        }
        self.bytes.push(b);
    }

    fn take(&mut self, enc: StrEnc, opts: &Options, out: &mut Vec<FoundString>) {
        if self.bytes.len() >= opts.min_len {
            let text: String = self.bytes.iter().map(|&c| c as char).collect();
            let kinds = classify(&text);
            if !opts.only_tagged || !kinds.is_empty() {
                out.push(FoundString { offset: self.start, text, enc, kinds });
            }
        }
        self.bytes.clear();
    }
}

/// Streaming scanner: feed it chunks, then `finish`. Runs that cross a chunk
/// boundary are carried over, so results do not depend on the chunk size.
struct Scanner {
    ascii: Run,
    /// UTF-16LE candidates at even and odd byte parity (a wide string may start
    /// at any offset, so both grids are scanned).
    wide: [Run; 2],
    /// Low byte of a wide pair whose high byte lands in the next chunk.
    pending: [Option<(u64, u8)>; 2],
}

impl Scanner {
    fn new() -> Self {
        Self {
            ascii: Run::default(),
            wide: [Run::default(), Run::default()],
            pending: [None, None],
        }
    }

    fn feed(&mut self, chunk: &[u8], base: u64, opts: &Options, out: &mut Vec<FoundString>) {
        if opts.ascii {
            for (i, &b) in chunk.iter().enumerate() {
                let at = base + i as u64;
                if printable(b) {
                    self.ascii.push(at, b);
                } else {
                    self.ascii.take(StrEnc::Ascii, opts, out);
                }
            }
        }
        if opts.utf16 {
            for parity in 0..2usize {
                let mut i = 0usize;
                // Consume a low byte carried over from the previous chunk.
                if let Some((at, lo)) = self.pending[parity].take() {
                    if !chunk.is_empty() {
                        let hi = chunk[0];
                        if hi == 0 && printable(lo) {
                            self.wide[parity].push(at, lo);
                        } else {
                            self.wide[parity].take(StrEnc::Utf16Le, opts, out);
                        }
                        i = 1;
                    } else {
                        self.pending[parity] = Some((at, lo));
                    }
                } else if base == 0 {
                    i = parity;
                }
                while i + 1 < chunk.len() + 1 {
                    if i + 1 >= chunk.len() {
                        // Odd tail: remember the low byte for the next chunk.
                        if i < chunk.len() {
                            self.pending[parity] = Some((base + i as u64, chunk[i]));
                        }
                        break;
                    }
                    let (lo, hi) = (chunk[i], chunk[i + 1]);
                    if hi == 0 && printable(lo) {
                        self.wide[parity].push(base + i as u64, lo);
                    } else {
                        self.wide[parity].take(StrEnc::Utf16Le, opts, out);
                    }
                    i += 2;
                }
            }
        }
    }

    fn finish(&mut self, opts: &Options, out: &mut Vec<FoundString>) {
        self.ascii.take(StrEnc::Ascii, opts, out);
        for w in &mut self.wide {
            w.take(StrEnc::Utf16Le, opts, out);
        }
    }
}

/// Extract strings from a byte slice.
pub fn extract(data: &[u8], opts: &Options) -> Scan {
    let mut out = Vec::new();
    let mut sc = Scanner::new();
    sc.feed(data, 0, opts, &mut out);
    sc.finish(opts, &mut out);
    finalize(out, opts, false)
}

/// Extract strings from a buffer without materializing it, honouring `max_bytes`.
pub fn extract_buffer(buf: &EditBuffer, opts: &Options) -> Scan {
    let limit = if opts.max_bytes == 0 { buf.len() } else { opts.max_bytes.min(buf.len()) };
    let mut out = Vec::new();
    let mut sc = Scanner::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut off = 0u64;
    while off < limit {
        let n = ((limit - off) as usize).min(chunk.len());
        buf.read_at(FileOffset(off), &mut chunk[..n]);
        sc.feed(&chunk[..n], off, opts, &mut out);
        off += n as u64;
    }
    sc.finish(opts, &mut out);
    finalize(out, opts, limit < buf.len())
}

/// Sort by offset, drop wide duplicates of the same span, and apply the result cap.
fn finalize(mut out: Vec<FoundString>, opts: &Options, mut truncated: bool) -> Scan {
    out.sort_by_key(|s| (s.offset, s.enc == StrEnc::Utf16Le));
    // The two wide parities can rediscover the same text one byte apart; keep one.
    out.dedup_by(|a, b| {
        a.enc == StrEnc::Utf16Le && b.enc == StrEnc::Utf16Le && a.text == b.text
            && a.offset.abs_diff(b.offset) <= 1
    });
    if opts.max_results > 0 && out.len() > opts.max_results {
        out.truncate(opts.max_results);
        truncated = true;
    }
    Scan { strings: out, truncated }
}

/// The indicator categories a string belongs to (possibly none).
pub fn classify(s: &str) -> Vec<Kind> {
    let mut kinds = Vec::new();
    let lower = s.to_ascii_lowercase();

    if has_url(&lower) {
        kinds.push(Kind::Url);
    }
    if find_ipv4(s).is_some() {
        kinds.push(Kind::Ipv4);
    }
    if is_email(s) {
        kinds.push(Kind::Email);
    }
    if !kinds.contains(&Kind::Url) && !kinds.contains(&Kind::Email) && is_domain(&lower) {
        kinds.push(Kind::Domain);
    }
    if is_registry(&lower) {
        kinds.push(Kind::Registry);
    }
    if let Some(_hit) = lolbin_hit(&lower) {
        kinds.push(Kind::LolBin);
    }
    if lower.starts_with("mozilla/") || lower.contains("user-agent") {
        kinds.push(Kind::UserAgent);
    }
    if lower.contains("global\\") || lower.contains("local\\") || lower.contains("\\basenamedobjects\\") {
        kinds.push(Kind::Mutex);
    }
    if lower.starts_with("\\\\") || lower.starts_with("\\\\?\\") {
        kinds.push(Kind::Unc);
    } else if is_path(s, &lower) {
        kinds.push(Kind::Path);
    }
    if lower.ends_with(".pdb") {
        kinds.push(Kind::Pdb);
    }
    if is_guid(s) {
        kinds.push(Kind::Guid);
    }
    if is_base64_blob(s) {
        kinds.push(Kind::Base64);
    }
    if is_module(&lower) {
        kinds.push(Kind::Module);
    }
    kinds
}

const SCHEMES: [&str; 8] = ["http://", "https://", "ftp://", "ftps://", "ws://", "wss://", "file://", "ldap://"];

fn has_url(lower: &str) -> bool {
    SCHEMES.iter().any(|s| lower.contains(s)) || lower.starts_with("www.")
}

/// The first dotted-quad in `s` whose octets are all in range, ignoring version
/// numbers like "1.0.0.0" only insofar as they are still valid addresses (they
/// are reported; the analyst filters).
pub fn find_ipv4(s: &str) -> Option<(usize, String)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() || (i > 0 && (bytes[i - 1].is_ascii_digit() || bytes[i - 1] == b'.')) {
            i += 1;
            continue;
        }
        let start = i;
        let mut octets = 0;
        let mut j = i;
        let mut ok = true;
        while octets < 4 {
            let ds = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() && j - ds < 3 {
                j += 1;
            }
            if j == ds {
                ok = false;
                break;
            }
            if s[ds..j].parse::<u32>().unwrap_or(256) > 255 {
                ok = false;
                break;
            }
            octets += 1;
            if octets < 4 {
                if j < bytes.len() && bytes[j] == b'.' {
                    j += 1;
                } else {
                    ok = false;
                    break;
                }
            }
        }
        // Reject when more digits/dots follow (that is a version, not an address).
        if ok && j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
            ok = false;
        }
        if ok {
            return Some((start, s[start..j].to_string()));
        }
        i = j.max(i + 1);
    }
    None
}

fn is_email(s: &str) -> bool {
    let Some((user, host)) = s.split_once('@') else {
        return false;
    };
    !user.is_empty()
        && !user.contains(char::is_whitespace)
        && user.len() <= 64
        && is_domain(&host.to_ascii_lowercase())
}

/// A bare hostname: dotted labels ending in an alphabetic TLD, no spaces, and
/// not merely a filename like "kernel32.dll".
fn is_domain(lower: &str) -> bool {
    let host = lower.split(['/', '?', '#', ':', ' ']).next().unwrap_or(lower);
    if host.len() < 4 || host.len() > 253 || !host.contains('.') {
        return false;
    }
    if host.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')) {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    if tld.len() < 2 || tld.len() > 24 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    !FILE_EXTS.contains(&tld)
}

/// Extensions that make a dotted token a filename rather than a hostname.
const FILE_EXTS: [&str; 24] = [
    "dll", "exe", "sys", "ocx", "bin", "dat", "tmp", "log", "txt", "ini", "cfg", "xml", "json",
    "png", "jpg", "gif", "ico", "cur", "bmp", "pdb", "lib", "obj", "res", "manifest",
];

fn is_module(lower: &str) -> bool {
    matches!(
        lower.rsplit('.').next(),
        Some("dll" | "sys" | "exe" | "ocx" | "cpl" | "scr" | "drv")
    ) && !lower.contains(' ')
        && lower.len() <= 128
}

fn is_registry(lower: &str) -> bool {
    const ROOTS: [&str; 8] = [
        "hkey_local_machine",
        "hkey_current_user",
        "hkey_classes_root",
        "hkey_users",
        "hklm\\",
        "hkcu\\",
        "hkcr\\",
        "software\\microsoft\\windows\\currentversion",
    ];
    ROOTS.iter().any(|r| lower.contains(r))
}

/// Living-off-the-land binaries and the command shapes malware builds with them.
const LOLBINS: [&str; 24] = [
    "powershell", "-encodedcommand", "cmd.exe /c", "cmd /c", "rundll32", "regsvr32", "mshta",
    "certutil", "bitsadmin", "wmic ", "schtasks", "vssadmin", "bcdedit", "wscript", "cscript",
    "net user", "net localgroup", "reg add", "reg delete", "sc create", "installutil",
    "msbuild", "curl ", "wget ",
];

pub fn lolbin_hit(lower: &str) -> Option<&'static str> {
    LOLBINS.iter().copied().find(|b| lower.contains(b))
}

fn is_path(s: &str, lower: &str) -> bool {
    if s.len() < 6 {
        return false;
    }
    let drive = s.as_bytes().windows(3).any(|w| w[0].is_ascii_alphabetic() && w[1] == b':' && w[2] == b'\\');
    drive
        || lower.starts_with("%appdata%")
        || lower.starts_with("%temp%")
        || lower.starts_with("%programdata%")
        || lower.starts_with("%userprofile%")
        || (s.starts_with('/') && s.matches('/').count() >= 2 && !s.contains(' '))
}

fn is_guid(s: &str) -> bool {
    let t = s.trim_matches(['{', '}']);
    let parts: Vec<&str> = t.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12] == [parts[0].len(), parts[1].len(), parts[2].len(), parts[3].len(), parts[4].len()]
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// A long, dense run of base64 characters — how configuration blobs and staged
/// payloads usually look in strings output.
fn is_base64_blob(s: &str) -> bool {
    let t = s.trim_end_matches('=');
    if t.len() < 32 || t.contains(' ') {
        return false;
    }
    if !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/') {
        return false;
    }
    // Require a real mix, so plain identifiers and hex blobs do not qualify.
    let upper = t.chars().filter(|c| c.is_ascii_uppercase()).count();
    let lower = t.chars().filter(|c| c.is_ascii_lowercase()).count();
    let digit = t.chars().filter(|c| c.is_ascii_digit()).count();
    upper > 0 && lower > 0 && digit > 0 && (upper + lower) * 4 > t.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_and_wide_strings() {
        let mut data = b"..hello world..".to_vec();
        data.extend(b"m\0a\0l\0w\0a\0r\0e\0".iter());
        let scan = extract(&data, &Options { min_len: 4, ..Default::default() });
        let texts: Vec<&str> = scan.strings.iter().map(|s| s.text.as_str()).collect();
        assert!(texts.iter().any(|t| t.contains("hello world")), "{texts:?}");
        assert!(texts.contains(&"malware"), "{texts:?}");
    }

    #[test]
    fn wide_string_at_odd_offset_is_found() {
        let mut data = vec![0xffu8];
        data.extend(b"c\0o\0n\0f\0i\0g\0".iter());
        let scan = extract(&data, &Options::default());
        assert!(scan.strings.iter().any(|s| s.text == "config" && s.enc == StrEnc::Utf16Le));
    }

    #[test]
    fn chunked_scan_matches_whole_scan() {
        use crate::buffer::MemSource;
        use std::sync::Arc;
        let mut data = vec![0u8; 70_000];
        data.extend(b"http://evil.example.com/gate.php".iter());
        data.extend([0u8; 10]);
        let buf = EditBuffer::new(Arc::new(MemSource::new(data.clone())));
        let a = extract(&data, &Options::default());
        let b = extract_buffer(&buf, &Options::default());
        let ta: Vec<&str> = a.strings.iter().map(|s| s.text.as_str()).collect();
        let tb: Vec<&str> = b.strings.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(ta, tb);
        assert!(ta.contains(&"http://evil.example.com/gate.php"));
    }

    #[test]
    fn classifies_indicators() {
        assert!(classify("http://x.example.com/a").contains(&Kind::Url));
        assert!(classify("185.220.101.7").contains(&Kind::Ipv4));
        assert!(classify("ops@evil.tld").contains(&Kind::Email));
        assert!(classify("evil-domain.tld").contains(&Kind::Domain));
        assert!(classify("HKEY_CURRENT_USER\\Software\\Run").contains(&Kind::Registry));
        assert!(classify("powershell -EncodedCommand ZQBj").contains(&Kind::LolBin));
        assert!(classify("C:\\Users\\a\\AppData\\x.exe").contains(&Kind::Path));
        assert!(classify("Global\\MyMutex7").contains(&Kind::Mutex));
        assert!(classify("D:\\build\\loader.pdb").contains(&Kind::Pdb));
        assert!(classify("{21EC2020-3AEA-1069-A2DD-08002B30309D}").contains(&Kind::Guid));
    }

    #[test]
    fn version_numbers_are_not_addresses() {
        assert!(find_ipv4("1.0.0.0.1").is_none());
        assert!(find_ipv4("999.1.1.1").is_none());
        assert_eq!(find_ipv4("host 10.0.0.5 up").map(|(_, s)| s), Some("10.0.0.5".into()));
    }

    #[test]
    fn filenames_are_not_domains() {
        assert!(!classify("kernel32.dll").contains(&Kind::Domain));
        assert!(classify("kernel32.dll").contains(&Kind::Module));
    }

    #[test]
    fn base64_blob_needs_length_and_mix() {
        assert!(classify("TVqQAAMAAAAEAAAAf8AAALg0aGVsbG8x").contains(&Kind::Base64));
        assert!(!classify("shortstring").contains(&Kind::Base64));
    }

    #[test]
    fn only_tagged_keeps_indicators_only() {
        let data = b"just some prose here\0http://c2.example.tld/p\0";
        let scan = extract(data, &Options { only_tagged: true, ..Default::default() });
        assert_eq!(scan.strings.len(), 1);
        assert!(scan.strings[0].kinds.contains(&Kind::Url));
    }
}
