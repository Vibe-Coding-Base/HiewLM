//! One-screen triage verdict for a sample.
//!
//! The point of this crate is a single answer to "what am I looking at?" that
//! costs one keystroke instead of six: identity (hashes a feed will recognise),
//! shape (format, sections, entropy, packer), capability (what the imports can
//! do), structure (overlay, TLS callbacks, signature, anomalies) and indicators
//! (URLs, IPs, registry keys, LOLBin command lines) in one pass over the bytes.
//!
//! The score is a triage *ordering*, not a verdict: it decides which of fifty
//! samples you open first. Every input is passive data — nothing is executed.

use hiewlm_core::apiscore::{self, ImportReport};
use hiewlm_core::strings::{self, FoundString, Options as StrOptions};
use hiewlm_core::{Arch, Container, EditBuffer, FileOffset, Finding, Format, Severity};
use hiewlm_fmt::pe_extra::PeDetails;
use serde::Serialize;

pub mod render;
pub mod yara;
pub use render::Pane;
pub use yara::{scan as yara_scan, scan_path as yara_scan_path, YaraError};

/// Hash set for identification and clustering.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Hashes {
    pub crc32: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    /// ssdeep fuzzy digest — clusters repacked builds of the same family.
    pub ssdeep: String,
    /// PE import hash.
    pub imphash: Option<String>,
    /// MD5 of the decoded Rich header — a build-toolchain fingerprint.
    pub rich_hash: Option<String>,
    /// SHA-256 of the Authenticode-covered bytes (excludes the signature).
    pub authentihash: Option<String>,
}

/// A section as triage cares about it.
#[derive(Clone, Debug, Serialize)]
pub struct SectionRow {
    pub name: String,
    pub file_off: u64,
    pub va: u64,
    pub raw_size: u64,
    pub virt_size: u64,
    pub perms: String,
    pub entropy: f32,
}

/// One entropy sample over a slice of the file, for the map pane.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct MapCell {
    pub offset: u64,
    pub len: u64,
    pub entropy: f32,
}

/// A YARA match (populated when the `yara` feature is on and rules are given).
#[derive(Clone, Debug, Serialize)]
pub struct YaraHit {
    pub rule: String,
    pub tags: Vec<String>,
    /// `(offset, length, identifier)` for each matched string.
    pub matches: Vec<(u64, u64, String)>,
}

/// A finding rendered for output: severity, message, optional offset.
#[derive(Clone, Debug, Serialize)]
pub struct ReportFinding {
    pub severity: String,
    pub message: String,
    pub offset: Option<u64>,
}

impl From<&Finding> for ReportFinding {
    fn from(f: &Finding) -> Self {
        Self {
            severity: match f.severity {
                Severity::Info => "info".into(),
                Severity::Suspicious => "suspicious".into(),
            },
            message: f.message.clone(),
            offset: f.offset,
        }
    }
}

/// An indicator string, flattened for output.
#[derive(Clone, Debug, Serialize)]
pub struct Indicator {
    pub offset: u64,
    pub kinds: String,
    pub enc: &'static str,
    /// The indicator itself (the URL, not the log line that mentions it).
    pub value: String,
    /// The whole string it was found in, for context.
    pub text: String,
}

impl From<&FoundString> for Indicator {
    fn from(s: &FoundString) -> Self {
        Self {
            offset: s.offset,
            kinds: s.kind_list(),
            enc: if s.enc == strings::StrEnc::Utf16Le { "utf-16" } else { "ascii" },
            value: s.value(),
            text: s.text.clone(),
        }
    }
}

/// Plaintext recovered from behind a single-byte transform — a URL or command
/// the sample took the trouble to hide, which is worth more than one it did not.
#[derive(Clone, Debug, Serialize)]
pub struct HiddenString {
    pub offset: u64,
    /// The recipe that decodes it, in `crypt`/lens syntax (`xor 5a`).
    pub recipe: String,
    pub needle: String,
    pub preview: String,
}

/// A capability group: the behaviour bucket and the APIs that put it there.
#[derive(Clone, Debug, Serialize)]
pub struct Capability {
    pub category: String,
    pub apis: Vec<String>,
    pub note: String,
}

/// The full triage result.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TriageReport {
    pub name: String,
    pub size: u64,
    pub format: String,
    pub arch: String,
    pub bits: u8,
    pub entry_va: Option<u64>,
    pub entry_off: Option<u64>,
    pub timestamp: Option<String>,
    pub hashes: Hashes,
    pub entropy: f32,
    pub packer: Option<String>,
    pub packer_likelihood: u8,
    pub signed: bool,
    pub signature_note: Option<String>,
    pub overlay: Option<(u64, u64)>,
    pub pdb_path: Option<String>,
    pub tls_callbacks: Vec<u64>,
    pub sections: Vec<SectionRow>,
    pub capabilities: Vec<Capability>,
    pub import_score: u8,
    pub import_notes: Vec<String>,
    pub import_count: usize,
    pub export_count: usize,
    pub anomalies: Vec<ReportFinding>,
    pub indicators: Vec<Indicator>,
    pub hidden: Vec<HiddenString>,
    pub map: Vec<MapCell>,
    pub yara: Vec<YaraHit>,
    pub container_kind: Option<String>,
    pub container_findings: Vec<ReportFinding>,
    /// 0..100 triage priority.
    pub score: u8,
    /// Short badges for the status line: `PACKED`, `OVERLAY+128K`, `UNSIGNED`…
    pub badges: Vec<String>,
    /// Set when the scan hit its byte/result limits.
    pub truncated: bool,
}

/// Knobs for [`analyze`].
#[derive(Clone, Debug)]
pub struct Options {
    /// Bytes of the file to scan for strings (0 = all).
    pub max_string_bytes: u64,
    pub min_string_len: usize,
    /// Indicator strings kept in the report.
    pub max_indicators: usize,
    /// Cells in the entropy map.
    pub map_cells: usize,
    /// Bytes searched for plaintext hidden behind a single-byte key
    /// (0 disables the hunt).
    pub max_xor_bytes: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_string_bytes: 64 * 1024 * 1024,
            min_string_len: 5,
            max_indicators: 400,
            map_cells: 64,
            max_xor_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Shannon entropy (0..8) of a byte range, sampled so huge files stay fast.
pub fn range_entropy(buf: &EditBuffer, start: u64, len: u64) -> f32 {
    if len == 0 {
        return 0.0;
    }
    let cap = len.min(8 * 1024 * 1024);
    let mut freq = [0u64; 256];
    let mut chunk = vec![0u8; 64 * 1024];
    let mut off = start;
    let mut remaining = cap;
    while remaining > 0 {
        let n = (remaining as usize).min(chunk.len());
        buf.read_at(FileOffset(off), &mut chunk[..n]);
        for &b in &chunk[..n] {
            freq[b as usize] += 1;
        }
        off += n as u64;
        remaining -= n as u64;
    }
    let total = cap as f64;
    let mut h = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / total;
            h -= p * p.log2();
        }
    }
    h as f32
}

/// Build the triage report for an already-open buffer.
///
/// `name` is only used for display; `container` is the plugin-parsed structure
/// when one claimed the file (the TUI already has it, the CLI passes `None`).
pub fn analyze(
    name: &str,
    buf: &EditBuffer,
    container: Option<&Container>,
    opts: &Options,
) -> TriageReport {
    let mut r = TriageReport { name: name.to_string(), size: buf.len(), ..Default::default() };

    // Whole-file bytes are needed by the format parsers; bounded like they are.
    let cap = buf.len().min(256 * 1024 * 1024) as usize;
    let mut bytes = vec![0u8; cap];
    buf.read_at(FileOffset(0), &mut bytes);
    r.truncated = (cap as u64) < buf.len();

    r.hashes = hashes(buf, &bytes);
    r.entropy = range_entropy(buf, 0, buf.len());
    r.map = entropy_map(buf, opts.map_cells);

    let model = hiewlm_fmt::detect(buf);
    let pe = hiewlm_fmt::pe_details(&bytes);

    if let Some(m) = &model {
        r.format = m.format.label().to_string();
        r.arch = m.arch.label().to_string();
        r.bits = m.bits;
        r.entry_va = m.entry;
        r.entry_off = m
            .entry
            .and_then(|va| m.address_space.offset_of(hiewlm_core::Va(va)))
            .map(|o| o.get());
        r.import_count = m.imports.len();
        r.export_count = m.exports.len();
        r.timestamp = m
            .header_fields
            .iter()
            .find(|(k, _)| k == "TimeDateStamp")
            .map(|(_, v)| v.clone());

        for (i, s) in m.address_space.sections().iter().enumerate() {
            let perms = pe
                .as_ref()
                .and_then(|p| p.sections.get(i))
                .map(|p| p.perms())
                .unwrap_or_else(|| "?".into());
            let raw_size = pe
                .as_ref()
                .and_then(|p| p.sections.get(i))
                .map(|p| p.raw_size as u64)
                .unwrap_or(s.size);
            r.sections.push(SectionRow {
                name: s.name.clone(),
                file_off: s.file_off,
                va: s.va,
                raw_size,
                virt_size: s.size,
                perms,
                entropy: range_entropy(buf, s.file_off, raw_size.min(s.size.max(raw_size))),
            });
        }

        let names: Vec<String> = m.imports.iter().map(|s| s.name.clone()).collect();
        // A short import list only means something where the loader needs a full
        // IAT; Mach-O/ELF routinely have a handful of entries.
        let ir = apiscore::analyze_with(&names, m.format == Format::Pe);
        r.import_score = ir.score;
        r.import_notes = ir.notes.clone();
        r.capabilities = capabilities(&ir);
        if m.format == Format::Pe && !names.is_empty() {
            r.hashes.imphash = Some(imphash(&names));
        }
        r.packer_likelihood = packer(m, buf, &r.sections, &mut r.packer);
    } else {
        r.format = "raw".into();
        r.arch = Arch::Unknown.label().into();
    }

    if let Some(p) = &pe {
        r.signed = p.is_signed();
        if p.is_signed() {
            r.signature_note = Some(format!(
                "certificate table {} bytes at {:#x}; header checksum {}",
                p.cert.map(|c| c.size).unwrap_or(0),
                p.cert.map(|c| c.offset).unwrap_or(0),
                if p.checksum_ok() { "matches" } else { "MISMATCH" }
            ));
            r.hashes.authentihash = Some(authentihash(buf, p));
        }
        r.overlay = p.overlay.map(|o| (o.offset, o.payload_size()));
        r.pdb_path = p.pdb_path.clone();
        r.tls_callbacks = p.tls_callbacks.clone();
        r.hashes.rich_hash = p.rich_clear.as_ref().map(|c| md5_hex(c));
        r.anomalies = p.anomalies.iter().map(ReportFinding::from).collect();
    }

    if let Some(c) = container {
        r.container_kind = Some(c.kind.clone());
        r.container_findings = c.findings.iter().map(ReportFinding::from).collect();
    }

    // Indicators: tagged strings only, strongest first, then by offset.
    let scan = strings::extract_buffer(
        buf,
        &StrOptions {
            min_len: opts.min_string_len,
            ascii: true,
            utf16: true,
            max_results: 200_000,
            max_bytes: opts.max_string_bytes,
            only_tagged: true,
        },
    );
    r.truncated |= scan.truncated;
    let mut tagged = scan.strings;
    tagged.sort_by(|a, b| b.score().cmp(&a.score()).then(a.offset.cmp(&b.offset)));
    // Deduplicate on the indicator itself: one error message repeated across a
    // binary should contribute one URL, not forty near-identical lines.
    let mut seen = std::collections::HashSet::new();
    tagged.retain(|s| seen.insert((s.kind_list(), s.value())));
    tagged.truncate(opts.max_indicators);
    r.indicators = tagged.iter().map(Indicator::from).collect();

    // Anything the sample bothered to hide behind a key.
    if opts.max_xor_bytes > 0 {
        let hits = hiewlm_core::xorsearch::search_buffer(
            buf,
            &hiewlm_core::xorsearch::DEFAULT_NEEDLES,
            64,
            opts.max_xor_bytes,
        );
        let mut seen = std::collections::HashSet::new();
        for h in hits {
            if seen.insert((h.op, h.key, h.needle.clone())) {
                r.hidden.push(HiddenString {
                    offset: h.offset,
                    recipe: h.recipe(),
                    needle: h.needle.clone(),
                    preview: h.preview.clone(),
                });
            }
        }
    }

    score(&mut r);
    r
}

fn capabilities(ir: &ImportReport) -> Vec<Capability> {
    ir.by_category()
        .into_iter()
        .map(|(cat, hits)| Capability {
            category: cat.label().to_string(),
            // A `*` marks the APIs that are strong on their own, so the pane
            // shows which ones actually drove the score.
            apis: hits
                .iter()
                .map(|h| if h.strong { format!("{}*", h.func) } else { h.func.clone() })
                .collect(),
            note: hits
                .iter()
                .find(|h| h.strong)
                .or_else(|| hits.first())
                .map(|h| h.note.to_string())
                .unwrap_or_default(),
        })
        .collect()
}

fn packer(
    m: &hiewlm_core::ExecutableModel,
    buf: &EditBuffer,
    sections: &[SectionRow],
    out: &mut Option<String>,
) -> u8 {
    let entry_off = m
        .entry
        .and_then(|va| m.address_space.offset_of(hiewlm_core::Va(va)))
        .map(|o| o.get())
        .unwrap_or(0);
    let n = 32.min(buf.len().saturating_sub(entry_off) as usize);
    let mut entry = vec![0u8; n];
    buf.read_at(FileOffset(entry_off), &mut entry);
    let secs: Vec<hiewlm_core::packer::SectionInfo> = sections
        .iter()
        .map(|s| hiewlm_core::packer::SectionInfo { name: s.name.clone(), entropy: s.entropy })
        .collect();
    let rep = hiewlm_core::packer::detect(&entry, &secs, m.imports.len());
    if rep.name.is_some() || !rep.indicators.is_empty() {
        *out = Some(rep.summary());
    }
    rep.likelihood
}

fn hashes(buf: &EditBuffer, bytes: &[u8]) -> Hashes {
    use md5::Digest;
    let mut crc = crc32fast::Hasher::new();
    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();
    let mut sha256 = sha2::Sha256::new();

    let mut chunk = vec![0u8; 64 * 1024];
    let mut off = 0u64;
    while off < buf.len() {
        let n = ((buf.len() - off) as usize).min(chunk.len());
        buf.read_at(FileOffset(off), &mut chunk[..n]);
        crc.update(&chunk[..n]);
        md5.update(&chunk[..n]);
        sha1.update(&chunk[..n]);
        sha256.update(&chunk[..n]);
        off += n as u64;
    }
    Hashes {
        crc32: format!("{:08X}", crc.finalize()),
        md5: hex(&md5.finalize()),
        sha1: hex(&sha1.finalize()),
        sha256: hex(&sha256.finalize()),
        // Fuzzy hashing needs the bytes in one piece; it is capped like parsing.
        ssdeep: hiewlm_core::fuzzy::ssdeep(bytes),
        ..Default::default()
    }
}

fn authentihash(buf: &EditBuffer, p: &PeDetails) -> String {
    use md5::Digest;
    let mut sha = sha2::Sha256::new();
    let mut chunk = vec![0u8; 64 * 1024];
    for &(start, end) in &p.authentihash_ranges {
        let mut off = start;
        while off < end {
            let n = ((end - off) as usize).min(chunk.len());
            buf.read_at(FileOffset(off), &mut chunk[..n]);
            sha.update(&chunk[..n]);
            off += n as u64;
        }
    }
    hex(&sha.finalize())
}

fn md5_hex(data: &[u8]) -> String {
    use md5::Digest;
    hex(&md5::Md5::digest(data))
}

/// The industry-standard PE import hash (MD5 of the normalized `dll.func` list).
pub fn imphash(names: &[String]) -> String {
    let parts: Vec<String> = names
        .iter()
        .map(|name| {
            let (dll, func) = name.split_once('!').unwrap_or(("", name.as_str()));
            let mut dll = dll.to_lowercase();
            for ext in [".dll", ".sys", ".ocx", ".exe"] {
                if let Some(s) = dll.strip_suffix(ext) {
                    dll = s.to_string();
                    break;
                }
            }
            format!("{dll}.{}", func.to_lowercase())
        })
        .collect();
    md5_hex(parts.join(",").as_bytes())
}

fn entropy_map(buf: &EditBuffer, cells: usize) -> Vec<MapCell> {
    if buf.is_empty() || cells == 0 {
        return Vec::new();
    }
    let len = buf.len();
    let step = (len / cells as u64).max(1);
    let mut out = Vec::with_capacity(cells);
    let mut off = 0u64;
    while off < len && out.len() < cells {
        let n = step.min(len - off);
        out.push(MapCell { offset: off, len: n, entropy: range_entropy(buf, off, n) });
        off += n;
    }
    out
}

/// Combine the signals into a 0..100 triage priority and the status badges.
fn score(r: &mut TriageReport) {
    let mut s: u32 = 0;

    s += (r.import_score as u32 * 40) / 100;
    s += (r.packer_likelihood as u32 * 25) / 100;
    if r.packer_likelihood >= 50 {
        r.badges.push("PACKED".into());
    }

    let suspicious = r.anomalies.iter().filter(|a| a.severity == "suspicious").count();
    s += (suspicious as u32 * 6).min(20);

    if r.entropy >= 7.5 {
        s += 8;
        r.badges.push(format!("ENT{:.1}", r.entropy));
    }
    if let Some((_, size)) = r.overlay {
        if size > 4096 {
            s += 8;
            r.badges.push(format!("OVL+{}", human(size)));
        }
    }
    if !r.tls_callbacks.is_empty() {
        s += 5;
        r.badges.push("TLS".into());
    }
    if r.signed {
        if r.signature_note.as_deref().is_some_and(|n| n.contains("MISMATCH")) {
            s += 15;
            r.badges.push("SIG-BROKEN".into());
        } else {
            r.badges.push("signed".into());
        }
    }
    let strong_iocs = r
        .indicators
        .iter()
        .filter(|i| i.kinds.contains("url") || i.kinds.contains("ip") || i.kinds.contains("lolbin"))
        .count();
    s += (strong_iocs as u32 * 2).min(12);
    if strong_iocs > 0 {
        r.badges.push(format!("IOC{strong_iocs}"));
    }
    if !r.hidden.is_empty() {
        // Obfuscation is intent: a URL behind an XOR key is not an accident.
        s += 20;
        r.badges.push(format!("HIDDEN{}", r.hidden.len()));
    }
    if !r.yara.is_empty() {
        s += 25;
        r.badges.push(format!("YARA{}", r.yara.len()));
    }
    if r.container_findings.iter().any(|f| f.severity == "suspicious") {
        s += 15;
        r.badges.push("CONTAINER".into());
    }
    r.score = s.min(100) as u8;
}

/// Short byte-size label for badges (`128K`, `3M`).
pub fn human(n: u64) -> String {
    match n {
        0..=1023 => format!("{n}B"),
        1024..=1_048_575 => format!("{}K", n / 1024),
        _ => format!("{}M", n / (1024 * 1024)),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl TriageReport {
    /// How urgent this sample is, in words.
    pub fn verdict(&self) -> &'static str {
        match self.score {
            0..=19 => "low",
            20..=39 => "notable",
            40..=64 => "suspicious",
            65..=84 => "high",
            _ => "critical",
        }
    }

    /// The badge string for a status line.
    pub fn badge_line(&self) -> String {
        self.badges.join(" ")
    }

    /// Attach YARA results and re-score. Scanning is a separate, optional step
    /// (it needs rules), so the report is built first and told afterwards.
    pub fn set_yara(&mut self, hits: Vec<YaraHit>) {
        self.yara = hits;
        self.badges.clear();
        self.score = 0;
        score(self);
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiewlm_core::MemSource;
    use std::sync::Arc;

    fn buf(data: Vec<u8>) -> EditBuffer {
        EditBuffer::new(Arc::new(MemSource::new(data)))
    }

    #[test]
    fn raw_file_gets_hashes_and_low_score() {
        let b = buf(b"just some ordinary text in a file, nothing to see".to_vec());
        let r = analyze("t.bin", &b, None, &Options::default());
        assert_eq!(r.hashes.md5.len(), 32);
        assert_eq!(r.hashes.sha1.len(), 40);
        assert_eq!(r.hashes.sha256.len(), 64);
        assert!(r.hashes.ssdeep.contains(':'));
        assert!(r.score < 20, "{r:?}");
        assert_eq!(r.verdict(), "low");
    }

    #[test]
    fn indicators_are_extracted_and_ranked() {
        let mut data = b"padding padding padding\0".to_vec();
        data.extend(b"http://c2.example.top/gate.php\0");
        data.extend(b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\0");
        data.extend(b"just some prose that is not an indicator at all\0");
        let r = analyze("t.bin", &buf(data), None, &Options::default());
        assert!(r.indicators.iter().any(|i| i.value == "http://c2.example.top/gate.php"));
        assert!(r.indicators.iter().all(|i| !i.kinds.is_empty()));
        assert!(r.indicators[0].kinds.contains("url"), "URLs sort first: {:?}", r.indicators[0]);
    }

    #[test]
    fn entropy_map_covers_the_file() {
        let b = buf(vec![0u8; 10_000]);
        let r = analyze("t.bin", &b, None, &Options { map_cells: 10, ..Default::default() });
        assert_eq!(r.map.len(), 10);
        assert_eq!(r.map.iter().map(|c| c.len).sum::<u64>(), 10_000);
        assert!(r.map[0].entropy < 0.1, "zeros have no entropy");
    }

    #[test]
    fn plaintext_hidden_behind_a_key_is_found_and_scored() {
        let mut data = vec![0u8; 256];
        data.extend(b"http://hidden.example.top/a.php".iter().map(|&b| b ^ 0x41));
        let r = analyze("t.bin", &buf(data), None, &Options::default());
        let h = r.hidden.first().expect("a hidden string");
        assert_eq!(h.recipe, "xor 41");
        assert!(h.preview.contains("http://hidden.example.top"), "{}", h.preview);
        assert!(r.badges.iter().any(|b| b.starts_with("HIDDEN")), "{:?}", r.badges);
    }

    #[test]
    fn yara_hits_raise_the_score_and_badge() {
        let mut r = analyze("t.bin", &buf(b"abcd".to_vec()), None, &Options::default());
        let before = r.score;
        r.set_yara(vec![YaraHit {
            rule: "family_x".into(),
            tags: vec!["trojan".into()],
            matches: vec![(0, 4, "$a".into())],
        }]);
        assert!(r.score > before);
        assert!(r.badges.iter().any(|b| b.starts_with("YARA")), "{:?}", r.badges);
        // Re-scoring must not double-count on a second call.
        let once = r.score;
        r.set_yara(r.yara.clone());
        assert_eq!(r.score, once);
    }

    #[test]
    fn json_round_trips() {
        let r = analyze("t.bin", &buf(b"abcd".to_vec()), None, &Options::default());
        let j = r.to_json();
        assert!(j.contains("\"sha256\""));
        assert!(serde_json::from_str::<serde_json::Value>(&j).is_ok());
    }

    #[test]
    fn empty_file_does_not_panic() {
        let r = analyze("empty", &buf(Vec::new()), None, &Options::default());
        assert_eq!(r.size, 0);
        assert!(r.map.is_empty());
    }
}
