//! Packer / protector detection: entry-point signatures (PEiD-style, with `??`
//! wildcards) plus heuristics (section names, entropy, import count). Pure data
//! analysis — nothing is executed.

/// A byte signature matched at the entry point. `None` bytes are wildcards.
struct Sig {
    name: &'static str,
    bytes: &'static [Option<u8>],
}

macro_rules! sig {
    ($name:expr, $($b:tt),* $(,)?) => {
        Sig { name: $name, bytes: &[$(sig!(@b $b)),*] }
    };
    (@b _) => { None };
    (@b $x:literal) => { Some($x) };
}

/// A small built-in signature set (entry-point bytes of common packers). `_` = any.
const SIGS: &[Sig] = &[
    sig!("UPX", 0x60, 0xBE, _, _, _, _, 0x8D, 0xBE),
    sig!("UPX", 0x60, 0xBE, _, _, _, _, 0x8D, 0xBD),
    sig!("FSG", 0x87, 0x25, _, _, _, _, 0x61, 0x94),
    sig!("ASPack", 0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB),
    sig!("ASPack", 0x60, 0xE8, _, _, _, _, 0x5D, 0x81, 0xED),
    sig!("PECompact", 0xB8, _, _, _, _, 0x50, 0x64, 0xFF, 0x35),
    sig!("MEW", 0xE9, _, _, _, _, _, _, 0x00, 0x00),
    sig!("Petite", 0xB8, _, _, _, _, 0x66, 0x9C, 0x60, 0x50),
    sig!("MPRESS", 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x05),
    sig!("Themida/WinLicense", 0xB8, _, _, _, _, 0x60, 0x0B, 0xC0, 0x74),
    sig!("tElock", 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x83, 0xC0),
];

/// A section's name and Shannon entropy (0..8), for the heuristics.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub entropy: f32,
}

#[derive(Debug, Clone, Default)]
pub struct PackerReport {
    /// A named packer if a signature/section matched.
    pub name: Option<String>,
    /// Human-readable indicators that contributed to the verdict.
    pub indicators: Vec<String>,
    /// 0..100 rough likelihood the file is packed/protected.
    pub likelihood: u8,
}

impl PackerReport {
    pub fn summary(&self) -> String {
        match &self.name {
            Some(n) => format!("{n} ({}%)", self.likelihood),
            None if self.likelihood >= 50 => format!("likely packed ({}%)", self.likelihood),
            None => format!("none ({}%)", self.likelihood),
        }
    }
}

fn match_sig(sig: &Sig, entry: &[u8]) -> bool {
    if entry.len() < sig.bytes.len() {
        return false;
    }
    sig.bytes
        .iter()
        .zip(entry)
        .all(|(pat, &b)| pat.map_or(true, |p| p == b))
}

/// Well-known packer section names → packer name.
fn section_packer(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_uppercase();
    let table = [
        ("UPX", "UPX"),
        (".ASPACK", "ASPack"),
        (".ADATA", "ASPack"),
        (".NSP", "NsPack"),
        ("NSP0", "NsPack"),
        (".MPRESS", "MPRESS"),
        ("PEC", "PECompact"),
        (".PETITE", "Petite"),
        (".MEW", "MEW"),
        ("FSG!", "FSG"),
        (".THEMIDA", "Themida"),
        (".VMP", "VMProtect"),
        (".ENIGMA", "Enigma"),
    ];
    table.iter().find(|(k, _)| n.contains(k)).map(|(_, v)| *v)
}

/// Detect packers from the entry-point bytes, sections, and import count.
pub fn detect(entry: &[u8], sections: &[SectionInfo], import_count: usize) -> PackerReport {
    let mut report = PackerReport::default();
    let mut score = 0i32;

    // 1. Entry-point signature.
    if let Some(s) = SIGS.iter().find(|s| match_sig(s, entry)) {
        report.name = Some(s.name.to_string());
        report.indicators.push(format!("entry signature matches {}", s.name));
        score += 70;
    }

    // 2. Packer section names.
    for sec in sections {
        if let Some(pk) = section_packer(&sec.name) {
            report.name.get_or_insert_with(|| pk.to_string());
            report.indicators.push(format!("section '{}' → {pk}", sec.name));
            score += 40;
            break;
        }
    }

    // 3. High-entropy sections (packed/encrypted code).
    let high: Vec<&SectionInfo> = sections.iter().filter(|s| s.entropy >= 7.2).collect();
    if !high.is_empty() {
        let names: Vec<&str> = high.iter().map(|s| s.name.as_str()).collect();
        report.indicators.push(format!("high entropy sections: {}", names.join(", ")));
        score += 25 * high.len().min(2) as i32;
    }

    // 4. Suspiciously small import table.
    if import_count > 0 && import_count <= 5 {
        report.indicators.push(format!("very few imports ({import_count})"));
        score += 20;
    }

    report.likelihood = score.clamp(0, 100) as u8;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upx_by_signature() {
        let entry = [0x60, 0xBE, 0x00, 0x10, 0x40, 0x00, 0x8D, 0xBE, 0x00];
        let r = detect(&entry, &[], 3);
        assert_eq!(r.name.as_deref(), Some("UPX"));
        assert!(r.likelihood >= 70);
    }

    #[test]
    fn upx_by_section_name() {
        let secs = vec![
            SectionInfo { name: "UPX0".into(), entropy: 0.0 },
            SectionInfo { name: "UPX1".into(), entropy: 7.9 },
        ];
        let r = detect(&[0; 8], &secs, 2);
        assert_eq!(r.name.as_deref(), Some("UPX"));
        assert!(r.indicators.iter().any(|i| i.contains("high entropy")));
    }

    #[test]
    fn clean_binary_low_score() {
        let secs = vec![SectionInfo { name: ".text".into(), entropy: 5.5 }];
        let r = detect(&[0x55, 0x48, 0x89, 0xe5], &secs, 120);
        assert!(r.name.is_none());
        assert!(r.likelihood < 50);
    }
}
