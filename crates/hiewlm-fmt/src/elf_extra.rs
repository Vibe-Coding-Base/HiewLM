//! ELF structure checks for triage.
//!
//! Linux malware was the blind spot: the PE side reported overlays, RWX sections
//! and entry-point oddities while an ELF got nothing. The same questions apply —
//! is anything appended, is memory writable *and* executable, does the entry
//! point even land in code, and are the section headers there at all (packers
//! routinely drop them, which is why `objdump` suddenly stops being useful).
//!
//! Parsed from the bytes directly, so every offset reported is navigable.

use hiewlm_core::{Finding, Severity};

/// One program header (segment) — the loader's view, which is what runs.
#[derive(Clone, Debug)]
pub struct Segment {
    pub kind: u32,
    pub kind_name: &'static str,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

impl Segment {
    pub fn readable(&self) -> bool {
        self.flags & 4 != 0
    }
    pub fn writable(&self) -> bool {
        self.flags & 2 != 0
    }
    pub fn executable(&self) -> bool {
        self.flags & 1 != 0
    }
    pub fn perms(&self) -> String {
        format!(
            "{}{}{}",
            if self.readable() { 'r' } else { '-' },
            if self.writable() { 'w' } else { '-' },
            if self.executable() { 'x' } else { '-' }
        )
    }
    pub fn file_end(&self) -> u64 {
        self.offset.saturating_add(self.filesz)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ElfDetails {
    pub is_64: bool,
    pub little_endian: bool,
    pub e_type: u16,
    pub type_name: &'static str,
    pub entry: u64,
    pub segments: Vec<Segment>,
    /// Dynamic loader path from PT_INTERP, when present.
    pub interp: Option<String>,
    /// True when the section header table is absent — normal for a packed or
    /// deliberately stripped binary, and the reason static tools go quiet.
    pub no_section_headers: bool,
    /// Bytes after everything the headers describe.
    pub overlay: Option<(u64, u64)>,
    pub anomalies: Vec<Finding>,
}

impl ElfDetails {
    pub fn is_static(&self) -> bool {
        self.interp.is_none() && !self.segments.iter().any(|s| s.kind == PT_DYNAMIC)
    }
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474_e551;

fn seg_kind_name(kind: u32) -> &'static str {
    match kind {
        0 => "NULL",
        PT_LOAD => "LOAD",
        PT_DYNAMIC => "DYNAMIC",
        PT_INTERP => "INTERP",
        4 => "NOTE",
        6 => "PHDR",
        7 => "TLS",
        0x6474_e550 => "GNU_EH_FRAME",
        PT_GNU_STACK => "GNU_STACK",
        0x6474_e552 => "GNU_RELRO",
        0x6474_e553 => "GNU_PROPERTY",
        _ => "?",
    }
}

fn elf_type_name(t: u16) -> &'static str {
    match t {
        1 => "REL (object)",
        2 => "EXEC (executable)",
        3 => "DYN (PIE or shared object)",
        4 => "CORE",
        _ => "?",
    }
}

/// Endian-aware readers: an ELF can be big-endian (MIPS, PowerPC, SPARC).
struct Rd<'a> {
    b: &'a [u8],
    le: bool,
}

impl Rd<'_> {
    fn u16(&self, off: usize) -> u16 {
        let s = self.b.get(off..off + 2).unwrap_or(&[0, 0]);
        let a = [s[0], s[1]];
        if self.le { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) }
    }
    fn u32(&self, off: usize) -> u32 {
        let s = self.b.get(off..off + 4).unwrap_or(&[0; 4]);
        let a = [s[0], s[1], s[2], s[3]];
        if self.le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
    }
    fn u64(&self, off: usize) -> u64 {
        let s = self.b.get(off..off + 8).unwrap_or(&[0; 8]);
        let a = [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]];
        if self.le { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) }
    }
    /// A NUL-terminated string at a file offset.
    fn cstr(&self, off: usize, max: usize) -> Option<String> {
        let end = (off + max).min(self.b.len());
        let slice = self.b.get(off..end)?;
        let s: String = slice
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '?' })
            .collect();
        (!s.is_empty()).then_some(s)
    }
}

/// Parse the ELF program headers and derive triage findings, or `None` when the
/// bytes are not an ELF.
pub fn parse(bytes: &[u8]) -> Option<ElfDetails> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return None;
    }
    let is_64 = match bytes[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little_endian = bytes[5] != 2;
    let r = Rd { b: bytes, le: little_endian };

    let mut d = ElfDetails { is_64, little_endian, ..Default::default() };
    d.e_type = r.u16(16);
    d.type_name = elf_type_name(d.e_type);
    let (entry, phoff, shoff, phentsize, phnum, shentsize, shnum) = if is_64 {
        (r.u64(24), r.u64(32), r.u64(40), r.u16(54), r.u16(56), r.u16(58), r.u16(60))
    } else {
        (
            r.u32(24) as u64,
            r.u32(28) as u64,
            r.u32(32) as u64,
            r.u16(42),
            r.u16(44),
            r.u16(46),
            r.u16(48),
        )
    };
    d.entry = entry;
    d.no_section_headers = shoff == 0 || shnum == 0;

    // -- Program headers ----------------------------------------------------
    let entsize = if phentsize == 0 { if is_64 { 56 } else { 32 } } else { phentsize as usize };
    for i in 0..(phnum as usize).min(256) {
        let p = phoff as usize + i * entsize;
        if p + entsize > bytes.len() {
            break;
        }
        let (kind, flags, offset, vaddr, filesz, memsz) = if is_64 {
            (r.u32(p), r.u32(p + 4), r.u64(p + 8), r.u64(p + 16), r.u64(p + 32), r.u64(p + 40))
        } else {
            (
                r.u32(p),
                r.u32(p + 24),
                r.u32(p + 4) as u64,
                r.u32(p + 8) as u64,
                r.u32(p + 16) as u64,
                r.u32(p + 20) as u64,
            )
        };
        if kind == PT_INTERP {
            d.interp = r.cstr(offset as usize, filesz.min(256) as usize);
        }
        d.segments.push(Segment {
            kind,
            kind_name: seg_kind_name(kind),
            offset,
            vaddr,
            filesz,
            memsz,
            flags,
        });
    }

    // -- Overlay: bytes past everything the headers account for --------------
    let file_len = bytes.len() as u64;
    let described = d
        .segments
        .iter()
        .map(|s| s.file_end())
        .chain(std::iter::once(
            shoff.saturating_add(shnum as u64 * shentsize as u64),
        ))
        .max()
        .unwrap_or(0);
    if described > 0 && file_len > described {
        d.overlay = Some((described, file_len - described));
    }

    d.anomalies = anomalies(&d, file_len);
    Some(d)
}

fn anomalies(d: &ElfDetails, file_len: u64) -> Vec<Finding> {
    let mut out = Vec::new();

    if d.no_section_headers {
        out.push(Finding::suspicious(
            "no section header table — stripped or packed; section-based tools will show nothing",
        ));
    }

    for s in &d.segments {
        if s.kind == PT_LOAD && s.writable() && s.executable() {
            out.push(
                Finding::suspicious(format!(
                    "LOAD segment at {:#x} is writable AND executable ({})",
                    s.vaddr,
                    s.perms()
                ))
                .at(s.offset),
            );
        }
        if s.kind == PT_GNU_STACK && s.executable() {
            out.push(Finding::suspicious("executable stack (GNU_STACK is +x)"));
        }
        if s.kind == PT_LOAD && s.filesz > 0 && s.memsz > s.filesz.saturating_mul(10) {
            out.push(
                Finding::suspicious(format!(
                    "LOAD segment expands {:.0}x in memory ({:#x} -> {:#x}) — typical of a packer",
                    s.memsz as f64 / s.filesz as f64,
                    s.filesz,
                    s.memsz
                ))
                .at(s.offset),
            );
        }
        if s.file_end() > file_len {
            out.push(
                Finding::suspicious(format!(
                    "{} segment claims data past the end of the file ({:#x} > {:#x})",
                    s.kind_name,
                    s.file_end(),
                    file_len
                ))
                .at(s.offset),
            );
        }
    }

    // The entry point has to land in something executable.
    let entry_seg = d
        .segments
        .iter()
        .find(|s| s.kind == PT_LOAD && d.entry >= s.vaddr && d.entry < s.vaddr + s.memsz);
    match entry_seg {
        None if d.entry != 0 => out.push(Finding::suspicious(format!(
            "entry point {:#x} is not inside any LOAD segment",
            d.entry
        ))),
        Some(s) if !s.executable() => out.push(Finding::suspicious(format!(
            "entry point is in a non-executable segment ({})",
            s.perms()
        ))),
        Some(s) if s.writable() => out.push(Finding::suspicious(
            "entry point is in a writable segment — self-modifying or unpacking stub".to_string(),
        )),
        _ => {}
    }

    if let Some((off, size)) = d.overlay {
        let sev = if size > 4096 { Severity::Suspicious } else { Severity::Info };
        out.push(Finding {
            severity: sev,
            message: format!("overlay: {size} bytes appended after everything the headers describe"),
            offset: Some(off),
        });
    }

    match &d.interp {
        Some(p) if !is_usual_interp(p) => {
            out.push(Finding::suspicious(format!("unusual dynamic loader: {p}")))
        }
        None if !d.segments.is_empty() && d.e_type == 2 => {
            out.push(Finding::info("statically linked (no PT_INTERP)"))
        }
        _ => {}
    }
    out
}

/// The loader paths a normal distribution binary uses.
fn is_usual_interp(path: &str) -> bool {
    path.starts_with("/lib/ld-")
        || path.starts_with("/lib64/ld-")
        || path.starts_with("/lib/ld-linux")
        || path.starts_with("/lib64/ld-linux")
        || path.starts_with("/usr/lib/ld")
        || path.starts_with("/lib/ld-musl")
        || path.starts_with("/system/bin/linker")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal 64-bit little-endian ELF with one LOAD segment.
    fn build_elf(seg_flags: u32, extra: usize, drop_sections: bool) -> Vec<u8> {
        let mut b = vec![0u8; 64 + 56];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // 64-bit
        b[5] = 1; // little endian
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // EXEC
        b[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // x86-64
        b[24..32].copy_from_slice(&0x400000u64.to_le_bytes()); // entry
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
        if !drop_sections {
            b[40..48].copy_from_slice(&120u64.to_le_bytes()); // shoff
            b[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
            b[60..62].copy_from_slice(&1u16.to_le_bytes()); // shnum
        }
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum

        let p = 64;
        b[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[p + 4..p + 8].copy_from_slice(&seg_flags.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes()); // offset
        b[p + 16..p + 24].copy_from_slice(&0x400000u64.to_le_bytes()); // vaddr
        b[p + 32..p + 40].copy_from_slice(&120u64.to_le_bytes()); // filesz
        b[p + 40..p + 48].copy_from_slice(&120u64.to_le_bytes()); // memsz
        if !drop_sections {
            b.extend(std::iter::repeat(0u8).take(64)); // one section header
        }
        b.extend(std::iter::repeat(0xccu8).take(extra));
        b
    }

    const RX: u32 = 5;
    const RWX: u32 = 7;

    #[test]
    fn parses_a_plain_executable() {
        let d = parse(&build_elf(RX, 0, false)).expect("elf");
        assert!(d.is_64 && d.little_endian);
        assert_eq!(d.type_name, "EXEC (executable)");
        assert_eq!(d.segments.len(), 1);
        assert_eq!(d.segments[0].perms(), "r-x");
        assert!(d.overlay.is_none());
        assert!(!d.no_section_headers);
    }

    #[test]
    fn flags_writable_executable_segment() {
        let d = parse(&build_elf(RWX, 0, false)).expect("elf");
        assert!(d.anomalies.iter().any(|f| f.message.contains("writable AND executable")));
    }

    #[test]
    fn missing_section_headers_are_reported() {
        let d = parse(&build_elf(RX, 0, true)).expect("elf");
        assert!(d.no_section_headers);
        assert!(d.anomalies.iter().any(|f| f.message.contains("no section header table")));
    }

    #[test]
    fn detects_appended_data() {
        let d = parse(&build_elf(RX, 9000, false)).expect("elf");
        let (off, size) = d.overlay.expect("overlay");
        assert_eq!(size, 9000);
        assert_eq!(off, 184);
        assert!(d
            .anomalies
            .iter()
            .any(|f| f.message.contains("overlay") && f.severity == Severity::Suspicious));
    }

    #[test]
    fn non_elf_is_rejected() {
        assert!(parse(b"MZ this is a PE").is_none());
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn usual_loaders_are_not_flagged() {
        assert!(is_usual_interp("/lib64/ld-linux-x86-64.so.2"));
        assert!(is_usual_interp("/lib/ld-musl-x86_64.so.1"));
        assert!(!is_usual_interp("/tmp/.x/ld-fake.so"));
    }
}
