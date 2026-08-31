//! Packer, protector, installer and runtime identification.
//!
//! Three independent signals, because each one alone is easy to defeat:
//! entry-point byte signatures, section names, and build markers anywhere in the
//! file. The tables live in `data/packers.txt` — adding a packer is an edit to a
//! data file, not a code change (see [`crate::ruledata`]).
//!
//! Identifying the *builder* matters as much as detecting compression: knowing a
//! sample is a PyInstaller bundle or an Inno Setup installer changes what you do
//! next, even though neither is malicious in itself. That is why matches carry a
//! `kind` and only some kinds argue that the image is packed.

use std::sync::OnceLock;

/// A section's name and Shannon entropy (0..8), for the heuristics.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub entropy: f32,
}

/// What a match means for the analyst.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Compresses the real image (UPX, ASPack).
    Packer,
    /// Actively resists analysis (Themida, VMProtect).
    Protector,
    /// Transforms managed code (ConfuserEx, .NET Reactor).
    Obfuscator,
    /// A self-extracting installer (NSIS, Inno, SFX archives).
    Installer,
    /// A language runtime bundle — benign in itself, but it tells you what to
    /// unpack next.
    Runtime,
}

impl Kind {
    fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "packer" => Kind::Packer,
            "protector" => Kind::Protector,
            "obfuscator" => Kind::Obfuscator,
            "installer" => Kind::Installer,
            "runtime" => Kind::Runtime,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Packer => "packer",
            Kind::Protector => "protector",
            Kind::Obfuscator => "obfuscator",
            Kind::Installer => "installer",
            Kind::Runtime => "runtime",
        }
    }

    /// How much this kind argues that the real code is hidden.
    fn weight(self) -> i32 {
        match self {
            Kind::Protector => 75,
            Kind::Packer => 70,
            Kind::Obfuscator => 45,
            Kind::Installer => 20,
            // A Go or PyInstaller binary is not "packed"; saying so would put
            // every legitimate Python tool at the top of the queue.
            Kind::Runtime => 0,
        }
    }
}

/// How a rule matched, for the report line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum How {
    EntrySignature,
    SectionName,
    Marker,
}

impl How {
    pub fn label(self) -> &'static str {
        match self {
            How::EntrySignature => "entry signature",
            How::SectionName => "section name",
            How::Marker => "build marker",
        }
    }
}

/// One identification.
#[derive(Clone, Debug)]
pub struct Match {
    pub name: String,
    pub kind: Kind,
    pub how: How,
    /// The value that matched, for the report ("UPX0", "PyInstaller").
    pub detail: String,
}

/// A parsed rule from `data/packers.txt`.
enum Rule {
    /// Entry-point bytes; `None` is a wildcard.
    Signature(Vec<Option<u8>>),
    /// Section-name substring, already lowercase.
    Section(String),
    /// ASCII marker anywhere in the file.
    Marker(Vec<u8>),
}

struct PackerRule {
    name: String,
    kind: Kind,
    rule: Rule,
}

fn rules() -> &'static [PackerRule] {
    static RULES: OnceLock<Vec<PackerRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        crate::ruledata::table("packers", 4)
            .into_iter()
            .filter_map(|row| {
                let kind = Kind::parse(&row[1])?;
                let rule = match row[0].as_str() {
                    "sig" => Rule::Signature(parse_pattern(&row[3])?),
                    "section" => Rule::Section(row[3].to_ascii_lowercase()),
                    "marker" => Rule::Marker(row[3].as_bytes().to_vec()),
                    _ => return None,
                };
                Some(PackerRule { name: row[2].clone(), kind, rule })
            })
            .collect()
    })
}

/// How many packer rules are loaded — shown by `hiewlmc rules`.
pub fn rule_count() -> usize {
    rules().len()
}

/// `60 BE ?? ?? 8D` — hex bytes with `??` wildcards.
fn parse_pattern(text: &str) -> Option<Vec<Option<u8>>> {
    let mut out = Vec::new();
    for token in text.split_whitespace() {
        if token == "??" || token == "?" {
            out.push(None);
        } else {
            out.push(Some(u8::from_str_radix(token, 16).ok()?));
        }
    }
    (!out.is_empty()).then_some(out)
}

#[derive(Debug, Clone, Default)]
pub struct PackerReport {
    /// The primary identification, if any.
    pub name: Option<String>,
    pub kind: Option<Kind>,
    /// Every rule that matched, strongest kind first.
    pub matches: Vec<Match>,
    /// Human-readable indicators that contributed to the verdict.
    pub indicators: Vec<String>,
    /// 0..100 rough likelihood the real code is packed or protected.
    pub likelihood: u8,
}

impl PackerReport {
    pub fn summary(&self) -> String {
        match (&self.name, self.kind) {
            (Some(n), Some(k)) => format!("{n} [{}] ({}%)", k.label(), self.likelihood),
            (Some(n), None) => format!("{n} ({}%)", self.likelihood),
            (None, _) if self.likelihood >= 50 => format!("likely packed ({}%)", self.likelihood),
            (None, _) => format!("none ({}%)", self.likelihood),
        }
    }

    /// Whether anything was identified at all, of any kind.
    pub fn identified(&self) -> bool {
        self.name.is_some()
    }
}

fn match_signature(pattern: &[Option<u8>], entry: &[u8]) -> bool {
    entry.len() >= pattern.len()
        // `Option::is_none_or` is newer than the workspace MSRV (1.75).
        && pattern.iter().zip(entry).all(|(p, &b)| p.map_or(true, |want| want == b))
}

/// Identify what produced this image, and how likely it is that the real code is
/// hidden.
///
/// `entry` is the bytes at the entry point, `file` the whole image (markers can
/// be anywhere). Passing an empty `file` simply skips the marker rules.
pub fn detect(
    entry: &[u8],
    sections: &[SectionInfo],
    import_count: usize,
    file: &[u8],
) -> PackerReport {
    let mut report = PackerReport::default();
    let mut score = 0i32;

    for rule in rules() {
        let hit = match &rule.rule {
            Rule::Signature(p) => {
                match_signature(p, entry).then(|| (How::EntrySignature, "entry point".to_string()))
            }
            Rule::Section(want) => sections
                .iter()
                .find(|s| s.name.to_ascii_lowercase().contains(want))
                .map(|s| (How::SectionName, s.name.clone())),
            Rule::Marker(needle) => find_bytes(file, needle)
                .map(|at| (How::Marker, format!("{:#x}", at))),
        };
        if let Some((how, detail)) = hit {
            report.matches.push(Match {
                name: rule.name.clone(),
                kind: rule.kind,
                how,
                detail,
            });
        }
    }

    // The strongest kind decides the headline; within a kind, the first match.
    report.matches.sort_by_key(|m| std::cmp::Reverse(m.kind.weight()));
    report.matches.dedup_by(|a, b| a.name == b.name && a.how == b.how);

    // "Packed" is a claim about structure and needs structural evidence. A build
    // marker is a product *name* appearing in the file, which any document,
    // installer log or analysis tool that merely mentions Themida also contains
    // — hiewLM's own signature table did, and it identified itself as protected.
    // Markers still establish what *built* a file, which is an identity claim
    // they legitimately answer.
    let headline = report
        .matches
        .iter()
        .find(|m| !(m.how == How::Marker && matches!(m.kind, Kind::Packer | Kind::Protector)))
        .cloned();
    if let Some(best) = headline.as_ref() {
        report.name = Some(best.name.clone());
        report.kind = Some(best.kind);
        score += best.kind.weight();
        for m in &report.matches {
            report
                .indicators
                .push(format!("{} [{}] via {} ({})", m.name, m.kind.label(), m.how.label(), m.detail));
        }
    }

    // High-entropy sections: packed or encrypted code, whoever produced it.
    let high: Vec<&SectionInfo> = sections.iter().filter(|s| s.entropy >= 7.2).collect();
    if !high.is_empty() {
        let names: Vec<&str> = high.iter().map(|s| s.name.as_str()).collect();
        report.indicators.push(format!("high entropy sections: {}", names.join(", ")));
        score += 25 * high.len().min(2) as i32;
    }

    // A tiny import table means the real imports are resolved at runtime.
    if import_count > 0 && import_count <= 5 {
        report.indicators.push(format!("very few imports ({import_count})"));
        score += 20;
    }

    report.likelihood = score.clamp(0, 100) as u8;
    report
}

/// First occurrence of `needle` in `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sections(names: &[(&str, f32)]) -> Vec<SectionInfo> {
        names
            .iter()
            .map(|(n, e)| SectionInfo { name: (*n).into(), entropy: *e })
            .collect()
    }

    #[test]
    fn upx_by_signature() {
        let entry = [0x60, 0xBE, 0x00, 0x10, 0x40, 0x00, 0x8D, 0xBE, 0x00];
        let r = detect(&entry, &[], 3, &[]);
        assert_eq!(r.name.as_deref(), Some("UPX"));
        assert_eq!(r.kind, Some(Kind::Packer));
        assert!(r.likelihood >= 70);
    }

    #[test]
    fn upx_by_section_name() {
        let secs = sections(&[("UPX0", 0.0), ("UPX1", 7.9)]);
        let r = detect(&[0; 8], &secs, 2, &[]);
        assert_eq!(r.name.as_deref(), Some("UPX"));
        assert!(r.indicators.iter().any(|i| i.contains("high entropy")));
    }

    #[test]
    fn a_runtime_bundle_is_named_but_not_called_packed() {
        // PyInstaller is not malicious and not compression — but knowing it is
        // there is what tells you to go looking for the embedded archive.
        let file = b"....PyInstaller: FormatMessageW failed....";
        let r = detect(&[0x55, 0x48, 0x89, 0xe5], &sections(&[(".text", 6.0)]), 90, file);
        assert_eq!(r.kind, Some(Kind::Runtime));
        assert!(r.name.as_deref().unwrap().contains("PyInstaller"));
        assert!(r.likelihood < 50, "a Python bundle must not read as packed: {}", r.likelihood);
    }

    #[test]
    fn a_product_name_in_the_file_does_not_make_it_protected() {
        // Exactly how hiewLM identified itself as Themida-protected: its own
        // rule table, embedded in the binary, contains the word.
        let file = b"packers.txt: marker | protector | Themida/WinLicense | Themida";
        let r = detect(&[0x55, 0x48, 0x89, 0xe5], &sections(&[(".text", 6.0)]), 120, file);
        assert!(!r.identified(), "a mention is not evidence: {:?}", r.name);
        assert!(r.likelihood < 50, "{}", r.likelihood);
        // The match is still visible, just not load-bearing.
        assert!(r.matches.iter().any(|m| m.name.contains("Themida")));
    }

    #[test]
    fn a_section_name_still_proves_a_protector() {
        let r = detect(&[0; 8], &sections(&[(".themida", 7.9)]), 4, b"");
        assert_eq!(r.kind, Some(Kind::Protector));
        assert!(r.likelihood >= 70);
    }

    #[test]
    fn a_protector_outranks_a_runtime_when_both_match() {
        let file = b"Go build ID: xyz .... VMProtect begin";
        let r = detect(&[0; 8], &sections(&[(".vmp0", 7.9)]), 4, file);
        assert_eq!(r.kind, Some(Kind::Protector));
        assert_eq!(r.name.as_deref(), Some("VMProtect"));
        // Both are still reported: the sample is a protected Go binary.
        assert!(r.matches.iter().any(|m| m.kind == Kind::Runtime));
    }

    #[test]
    fn installer_is_identified() {
        let file = b"xx Nullsoft Install System v3.08 xx";
        let r = detect(&[0; 8], &sections(&[(".text", 6.0)]), 40, file);
        assert_eq!(r.kind, Some(Kind::Installer));
        assert!(r.summary().contains("installer"));
    }

    #[test]
    fn clean_binary_low_score() {
        let secs = sections(&[(".text", 5.5)]);
        let r = detect(&[0x55, 0x48, 0x89, 0xe5], &secs, 120, b"nothing to see here");
        assert!(!r.identified());
        assert!(r.likelihood < 50);
    }

    #[test]
    fn wildcard_patterns_parse_and_match() {
        let p = parse_pattern("60 BE ?? ?? 8D").expect("pattern");
        assert_eq!(p.len(), 5);
        assert!(match_signature(&p, &[0x60, 0xBE, 0xAA, 0xBB, 0x8D, 0x00]));
        assert!(!match_signature(&p, &[0x60, 0xBF, 0xAA, 0xBB, 0x8D]));
        assert!(parse_pattern("").is_none());
    }

    #[test]
    fn every_builtin_packer_rule_is_well_formed() {
        // A malformed line would silently disappear; make that a test failure.
        let raw = crate::ruledata::table("packers", 4);
        assert_eq!(rules().len(), raw.len(), "some packer rules failed to parse");
    }
}
