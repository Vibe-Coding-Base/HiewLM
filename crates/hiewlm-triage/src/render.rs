//! Turning a [`TriageReport`] into lines. The TUI renders these panes directly
//! and the CLI prints them all, so the two can never drift apart.
//!
//! A line is `(text, Option<file offset>)`: entries with an offset are jump
//! targets in the UI and simply informative on the command line.

use crate::{human, TriageReport};

/// Panes of the triage screen, in tab order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pane {
    Overview,
    Risk,
    Sections,
    Capabilities,
    Ioc,
    Map,
    Yara,
}

impl Pane {
    pub const ALL: [Pane; 7] = [
        Pane::Overview,
        Pane::Risk,
        Pane::Sections,
        Pane::Capabilities,
        Pane::Ioc,
        Pane::Map,
        Pane::Yara,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Pane::Overview => "Overview",
            Pane::Risk => "Risk",
            Pane::Sections => "Sections",
            Pane::Capabilities => "Capabilities",
            Pane::Ioc => "IOC",
            Pane::Map => "Map",
            Pane::Yara => "YARA",
        }
    }

    pub fn next(self) -> Self {
        let i = Self::ALL.iter().position(|&p| p == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let i = Self::ALL.iter().position(|&p| p == self).unwrap_or(0);
        Self::ALL[(i + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

fn kv(key: &str, value: impl AsRef<str>) -> (String, Option<u64>) {
    (format!("{key:<16} {}", value.as_ref()), None)
}

/// The lines of one pane.
pub fn pane_lines(r: &TriageReport, pane: Pane) -> Vec<(String, Option<u64>)> {
    match pane {
        Pane::Overview => overview(r),
        Pane::Risk => risk(r),
        Pane::Sections => sections(r),
        Pane::Capabilities => capabilities(r),
        Pane::Ioc => iocs(r),
        Pane::Map => map(r),
        Pane::Yara => yara(r),
    }
}

fn overview(r: &TriageReport) -> Vec<(String, Option<u64>)> {
    let mut v = vec![
        kv("Verdict", format!("{} ({}/100)  {}", r.verdict().to_uppercase(), r.score, r.badge_line())),
        kv("File", format!("{}  {} bytes ({})", r.name, r.size, human(r.size))),
        kv("Format", format!("{} / {} / {}-bit", r.format, r.arch, r.bits)),
    ];
    if let Some(k) = &r.container_kind {
        v.push(kv("Container", k));
    }
    if let Some(va) = r.entry_va {
        v.push((
            format!("{:<16} .{va:08X}   [Enter jumps]", "Entry point"),
            r.entry_off,
        ));
    }
    if let Some(t) = &r.timestamp {
        v.push(kv("Compiled", t));
    }
    v.push(kv("Entropy", format!("{:.3} / 8.0", r.entropy)));
    if let Some(p) = &r.packer {
        v.push(kv("Packer", p));
    }
    v.push(kv("Imports", format!("{} ({} exports)", r.import_count, r.export_count)));
    v.push(kv("Signature", if r.signed {
        r.signature_note.clone().unwrap_or_else(|| "present".into())
    } else {
        "unsigned".into()
    }));
    if let Some(p) = &r.pdb_path {
        v.push(kv("PDB path", p));
    }
    for (k, val) in &r.extra {
        v.push(kv(k, val));
    }
    if let Some((off, size)) = r.overlay {
        v.push((format!("{:<16} {size} bytes at {off:#x}   [Enter jumps]", "Overlay"), Some(off)));
    }
    v.push((String::new(), None));
    v.push(kv("MD5", &r.hashes.md5));
    v.push(kv("SHA-1", &r.hashes.sha1));
    v.push(kv("SHA-256", &r.hashes.sha256));
    v.push(kv("CRC32", &r.hashes.crc32));
    v.push(kv("ssdeep", &r.hashes.ssdeep));
    if let Some(h) = &r.hashes.imphash {
        v.push(kv("imphash", h));
    }
    if let Some(h) = &r.hashes.rich_hash {
        v.push(kv("rich hash", h));
    }
    if let Some(h) = &r.hashes.authentihash {
        v.push(kv("authentihash", h));
    }
    if r.truncated {
        v.push(kv("NOTE", "scan hit its size limit — results are partial"));
    }
    v
}

fn risk(r: &TriageReport) -> Vec<(String, Option<u64>)> {
    let mut v = Vec::new();
    for f in &r.anomalies {
        v.push((format!("[{}] {}", f.severity, f.message), f.offset));
    }
    for f in &r.container_findings {
        v.push((format!("[{}] container: {}", f.severity, f.message), f.offset));
    }
    for n in &r.import_notes {
        v.push((format!("[imports] {n}"), None));
    }
    for (i, va) in r.tls_callbacks.iter().enumerate() {
        v.push((format!("[info] TLS callback {} -> .{va:08X}", i + 1), None));
    }
    if v.is_empty() {
        v.push(("(no structural anomalies found)".into(), None));
    }
    v
}

fn sections(r: &TriageReport) -> Vec<(String, Option<u64>)> {
    if r.sections.is_empty() {
        return vec![("(no sections)".into(), None)];
    }
    let mut v = vec![(
        format!(
            "{:<12} {:>10} {:>10} {:>10} {:>10} {:<5} {:>6}",
            "name", "offset", "va", "raw", "virtual", "perms", "ent"
        ),
        None,
    )];
    for s in &r.sections {
        v.push((
            format!(
                "{:<12} {:>10X} {:>10X} {:>10X} {:>10X} {:<5} {:>6.2}{}",
                s.name,
                s.file_off,
                s.va,
                s.raw_size,
                s.virt_size,
                s.perms,
                s.entropy,
                if s.entropy >= 7.2 { "  <- high" } else { "" }
            ),
            Some(s.file_off),
        ));
    }
    v
}

fn capabilities(r: &TriageReport) -> Vec<(String, Option<u64>)> {
    if r.capabilities.is_empty() {
        return vec![("(no recognised APIs in the import table)".into(), None)];
    }
    let mut v = vec![(
        format!("import risk {}/100 · {} imports", r.import_score, r.import_count),
        None,
    )];
    for c in &r.capabilities {
        v.push((format!("{:<16} {}", c.category, c.note), None));
        for chunk in c.apis.chunks(4) {
            v.push((format!("{:<16}   {}", "", chunk.join(", ")), None));
        }
    }
    v
}

fn iocs(r: &TriageReport) -> Vec<(String, Option<u64>)> {
    // Obfuscated strings come first: the sample told you they mattered.
    let mut v: Vec<(String, Option<u64>)> = r
        .hidden
        .iter()
        .map(|h| {
            let preview: String = h.preview.chars().take(90).collect();
            (
                format!("{:08X} HIDDEN {:<14} {preview}   (lens: {})", h.offset, h.needle, h.recipe),
                Some(h.offset),
            )
        })
        .collect();
    if r.indicators.is_empty() && v.is_empty() {
        return vec![("(no indicator strings found)".into(), None)];
    }
    v.extend(indicator_rows(r));
    v
}

fn indicator_rows(r: &TriageReport) -> Vec<(String, Option<u64>)> {
    r.indicators
        .iter()
        .map(|i| {
            let value: String = i.value.chars().take(110).collect();
            // Show the context only when it adds something beyond the indicator.
            let context = if i.text.trim() == i.value {
                String::new()
            } else {
                let ctx: String = i.text.chars().take(60).collect();
                format!("   ({ctx})")
            };
            (
                format!("{:08X} {:<6} {:<22} {value}{context}", i.offset, i.enc, i.kinds),
                Some(i.offset),
            )
        })
        .collect()
}

/// Eight-level bar for one entropy value.
fn bar(entropy: f32) -> char {
    const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let idx = ((entropy / 8.0) * LEVELS.len() as f32) as usize;
    LEVELS[idx.min(LEVELS.len() - 1)]
}

fn map(r: &TriageReport) -> Vec<(String, Option<u64>)> {
    if r.map.is_empty() {
        return vec![("(empty file)".into(), None)];
    }
    let mut v = vec![(
        "entropy per block — high plateaus are packed or encrypted regions".into(),
        None,
    )];
    for c in &r.map {
        let filled = ((c.entropy / 8.0) * 40.0) as usize;
        let flag = if c.entropy >= 7.2 { " HIGH" } else { "" };
        v.push((
            format!(
                "{:08X} {} {:<40} {:.2}{flag}",
                c.offset,
                bar(c.entropy),
                "#".repeat(filled.min(40)),
                c.entropy
            ),
            Some(c.offset),
        ));
    }
    v
}

fn yara(r: &TriageReport) -> Vec<(String, Option<u64>)> {
    if r.yara.is_empty() {
        return vec![(
            "(no YARA matches — press Y to scan with a rule file, or build with --features yara)"
                .into(),
            None,
        )];
    }
    let mut v = Vec::new();
    for h in &r.yara {
        let tags = if h.tags.is_empty() { String::new() } else { format!(" [{}]", h.tags.join(" ")) };
        v.push((format!("rule {}{tags}", h.rule), h.matches.first().map(|m| m.0)));
        for (off, len, id) in h.matches.iter().take(32) {
            v.push((format!("    {off:08X}  {len:>5}  {id}"), Some(*off)));
        }
    }
    v
}

/// The whole report as text, pane by pane — what the CLI prints.
pub fn text(r: &TriageReport) -> String {
    let mut out = String::new();
    for pane in Pane::ALL {
        // The YARA pane is noise on the command line when nothing was scanned.
        if pane == Pane::Yara && r.yara.is_empty() {
            continue;
        }
        out.push_str(&format!("== {} ==\n", pane.label()));
        for (line, _) in pane_lines(r, pane) {
            out.push_str(&line);
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

/// The report as Markdown, for pasting into a ticket or a case note.
///
/// Deliberately not the pane text with hashes bolted on: a report someone else
/// reads wants the verdict first, the identity second, and the evidence in
/// tables they can scan.
pub fn markdown(r: &TriageReport) -> String {
    let mut m = String::new();
    m.push_str(&format!("# Triage — {}\n\n", r.name));
    m.push_str(&format!(
        "**{}** ({}/100){}\n\n",
        r.verdict().to_uppercase(),
        r.score,
        if r.badges.is_empty() { String::new() } else { format!(" · `{}`", r.badge_line()) }
    ));

    m.push_str("## Identity\n\n");
    m.push_str("| | |\n|---|---|\n");
    let row = |m: &mut String, k: &str, v: &str| {
        if !v.is_empty() {
            m.push_str(&format!("| {k} | `{v}` |\n"));
        }
    };
    row(&mut m, "Size", &format!("{} bytes ({})", r.size, human(r.size)));
    row(&mut m, "Format", &format!("{} / {} / {}-bit", r.format, r.arch, r.bits));
    row(&mut m, "SHA-256", &r.hashes.sha256);
    row(&mut m, "SHA-1", &r.hashes.sha1);
    row(&mut m, "MD5", &r.hashes.md5);
    row(&mut m, "ssdeep", &r.hashes.ssdeep);
    if let Some(h) = &r.hashes.imphash {
        row(&mut m, "imphash", h);
    }
    if let Some(h) = &r.hashes.authentihash {
        row(&mut m, "authentihash", h);
    }
    if let Some(t) = &r.timestamp {
        row(&mut m, "Compiled", t);
    }
    row(&mut m, "Entropy", &format!("{:.3} / 8.0", r.entropy));
    if let Some(p) = &r.packer {
        row(&mut m, "Packer", p);
    }
    row(&mut m, "Signature", if r.signed { "present" } else { "unsigned" });
    if let Some(p) = &r.pdb_path {
        row(&mut m, "PDB path", p);
    }
    m.push('\n');

    if !r.anomalies.is_empty() || !r.container_findings.is_empty() || !r.import_notes.is_empty() {
        m.push_str("## Findings\n\n");
        for f in r.anomalies.iter().chain(&r.container_findings) {
            let mark = if f.severity == "suspicious" { "**!**" } else { "-" };
            match f.offset {
                Some(o) => m.push_str(&format!("{mark} {} (`{o:#x}`)\n", f.message)),
                None => m.push_str(&format!("{mark} {}\n", f.message)),
            }
        }
        for n in &r.import_notes {
            m.push_str(&format!("**!** imports: {n}\n"));
        }
        m.push('\n');
    }

    if !r.capabilities.is_empty() {
        m.push_str(&format!("## Capabilities (import risk {}/100)\n\n", r.import_score));
        m.push_str("| Category | APIs |\n|---|---|\n");
        for c in &r.capabilities {
            m.push_str(&format!("| {} | {} |\n", c.category, c.apis.join(", ")));
        }
        m.push('\n');
    }

    if !r.hidden.is_empty() {
        m.push_str("## Hidden strings\n\n");
        m.push_str("| Offset | Recipe | Decoded |\n|---|---|---|\n");
        for h in &r.hidden {
            let preview: String = h.preview.chars().take(80).collect();
            m.push_str(&format!("| `{:08X}` | `{}` | `{}` |\n", h.offset, h.recipe, preview));
        }
        m.push('\n');
    }

    if !r.indicators.is_empty() {
        m.push_str("## Indicators\n\n");
        m.push_str("| Offset | Kind | Value |\n|---|---|---|\n");
        for i in r.indicators.iter().take(100) {
            let value: String = i.value.chars().take(110).collect();
            m.push_str(&format!("| `{:08X}` | {} | `{}` |\n", i.offset, i.kinds, value));
        }
        m.push('\n');
    }

    if !r.sections.is_empty() {
        m.push_str("## Sections\n\n");
        m.push_str("| Name | Offset | VA | Raw | Virtual | Perms | Entropy |\n");
        m.push_str("|---|---|---|---|---|---|---|\n");
        for s in &r.sections {
            m.push_str(&format!(
                "| `{}` | `{:X}` | `{:X}` | `{:X}` | `{:X}` | `{}` | {:.2} |\n",
                s.name, s.file_off, s.va, s.raw_size, s.virt_size, s.perms, s.entropy
            ));
        }
        m.push('\n');
    }

    if !r.yara.is_empty() {
        m.push_str("## YARA\n\n");
        for h in &r.yara {
            let tags =
                if h.tags.is_empty() { String::new() } else { format!(" [{}]", h.tags.join(" ")) };
            m.push_str(&format!("- **{}**{tags} — {} match(es)\n", h.rule, h.matches.len()));
        }
        m.push('\n');
    }

    if r.truncated {
        m.push_str("> Note: the scan hit its size limit, so these results are partial.\n");
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze, Options};
    use hiewlm_core::{EditBuffer, MemSource};
    use std::sync::Arc;

    fn report() -> TriageReport {
        let mut data = b"MZ padding".to_vec();
        data.extend(b"\0http://c2.example.top/gate.php\0");
        analyze(
            "t.bin",
            &EditBuffer::new(Arc::new(MemSource::new(data))),
            None,
            &Options::default(),
        )
    }

    #[test]
    fn every_pane_renders_something() {
        let r = report();
        for pane in Pane::ALL {
            assert!(!pane_lines(&r, pane).is_empty(), "{pane:?} was empty");
        }
    }

    #[test]
    fn panes_cycle_both_ways() {
        assert_eq!(Pane::Overview.next().prev(), Pane::Overview);
        assert_eq!(Pane::Yara.next(), Pane::Overview);
        assert_eq!(Pane::Overview.prev(), Pane::Yara);
    }

    #[test]
    fn text_output_includes_the_hashes_and_the_ioc() {
        let t = text(&report());
        assert!(t.contains("SHA-256"));
        assert!(t.contains("http://c2.example.top/gate.php"), "{t}");
        assert!(!t.contains("== YARA =="), "empty YARA pane is skipped on the CLI");
    }

    #[test]
    fn markdown_leads_with_the_verdict_and_tabulates_the_evidence() {
        let r = report();
        let md = markdown(&r);
        assert!(md.starts_with("# Triage — t.bin"), "{md}");
        // The verdict is the first thing a reader sees, before the hashes.
        let verdict = md.find("/100)").expect("a verdict line");
        let sha = md.find("SHA-256").expect("the hash table");
        assert!(verdict < sha);
        assert!(md.contains("## Identity"));
        assert!(md.contains("## Indicators"));
        assert!(md.contains("http://c2.example.top/gate.php"));
        // Tables must be well formed, or the ticket renders as noise.
        for line in md.lines().filter(|l| l.starts_with('|')) {
            assert!(line.ends_with('|'), "malformed table row: {line}");
        }
    }

    #[test]
    fn entropy_bar_covers_the_range() {
        assert_eq!(bar(0.0), '▁');
        assert_eq!(bar(8.0), '█');
        assert_eq!(bar(7.9), '█');
    }
}
