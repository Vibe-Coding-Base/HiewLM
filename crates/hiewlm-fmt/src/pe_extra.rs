//! The parts of a PE that decide a triage verdict but are not in the basic
//! header view: overlay, TLS callbacks, debug/PDB path, Authenticode signature,
//! Rich header, and the structural anomalies that betray a packer or a tampered
//! image.
//!
//! Parsed straight from the bytes (no goblin dependency here) so the offsets it
//! reports are the ones you can navigate to. Nothing is executed or mapped.

use hiewlm_core::{Finding, Severity};

/// A section as the file declares it, with the fields anomaly checks need.
#[derive(Clone, Debug)]
pub struct SectionRaw {
    pub name: String,
    pub vaddr: u32,
    pub vsize: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl SectionRaw {
    pub fn readable(&self) -> bool {
        self.characteristics & 0x4000_0000 != 0
    }
    pub fn writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }
    pub fn executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }
    /// `rwx`-style flag string.
    pub fn perms(&self) -> String {
        format!(
            "{}{}{}",
            if self.readable() { 'r' } else { '-' },
            if self.writable() { 'w' } else { '-' },
            if self.executable() { 'x' } else { '-' }
        )
    }
    pub fn raw_end(&self) -> u64 {
        self.raw_ptr as u64 + self.raw_size as u64
    }
}

/// Data appended after the last section — installers, second-stage payloads and
/// Authenticode signatures all live here.
#[derive(Clone, Copy, Debug)]
pub struct Overlay {
    pub offset: u64,
    pub size: u64,
    /// How much of it the Authenticode certificate accounts for.
    pub cert_size: u64,
}

impl Overlay {
    /// Overlay bytes that are not the signature — the interesting part.
    pub fn payload_size(&self) -> u64 {
        self.size.saturating_sub(self.cert_size)
    }
}

/// The Authenticode certificate table (data directory 4).
#[derive(Clone, Copy, Debug)]
pub struct CertInfo {
    /// A *file offset*, not an RVA — the one data directory that works that way.
    pub offset: u64,
    pub size: u64,
}

/// One debug directory entry.
#[derive(Clone, Debug)]
pub struct DebugEntry {
    pub kind: u32,
    pub kind_name: &'static str,
    pub file_off: u64,
    pub size: u32,
    /// The PDB path, for CODEVIEW entries.
    pub pdb: Option<String>,
}

/// Everything this module recovers from a PE.
#[derive(Clone, Debug, Default)]
pub struct PeDetails {
    pub is_64: bool,
    pub image_base: u64,
    pub entry_rva: u32,
    pub sections: Vec<SectionRaw>,
    pub overlay: Option<Overlay>,
    pub cert: Option<CertInfo>,
    pub tls_callbacks: Vec<u64>,
    pub tls_dir_off: Option<u64>,
    pub debug: Vec<DebugEntry>,
    pub pdb_path: Option<String>,
    /// Byte ranges Authenticode covers, for computing the authentihash.
    pub authentihash_ranges: Vec<(u64, u64)>,
    /// The decoded ("clear") Rich header bytes, which the Rich hash is taken over.
    pub rich_clear: Option<Vec<u8>>,
    pub rich_entries: Vec<(u32, u32)>,
    /// Checksum from the header and the value recomputed from the file.
    pub checksum: (u32, u32),
    pub timestamp: u32,
    pub anomalies: Vec<Finding>,
}

impl PeDetails {
    pub fn is_signed(&self) -> bool {
        self.cert.is_some_and(|c| c.size > 0)
    }

    pub fn checksum_ok(&self) -> bool {
        self.checksum.0 == 0 || self.checksum.0 == self.checksum.1
    }

    /// The section containing an RVA, if any.
    pub fn section_of_rva(&self, rva: u32) -> Option<&SectionRaw> {
        self.sections
            .iter()
            .find(|s| rva >= s.vaddr && rva < s.vaddr + s.vsize.max(s.raw_size))
    }
}

fn u16le(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0)
}
fn u32le(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}
fn u64le(b: &[u8], off: usize) -> u64 {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .unwrap_or(0)
}

fn rva_to_off(sections: &[SectionRaw], rva: u32) -> Option<u64> {
    sections
        .iter()
        .find(|s| rva >= s.vaddr && rva < s.vaddr + s.vsize.max(s.raw_size))
        .map(|s| s.raw_ptr as u64 + (rva - s.vaddr) as u64)
}

/// Parse the extra PE structures from a whole-file byte slice.
/// Returns `None` when the file is not a PE.
pub fn parse(bytes: &[u8]) -> Option<PeDetails> {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32le(bytes, 0x3c) as usize;
    if e_lfanew + 24 > bytes.len() || &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let nsec = u16le(bytes, coff + 2) as usize;
    let timestamp = u32le(bytes, coff + 4);
    let size_of_opt = u16le(bytes, coff + 16) as usize;
    let opt = coff + 20;
    let magic = u16le(bytes, opt);
    let is_64 = magic == 0x20b;

    let mut d = PeDetails {
        is_64,
        timestamp,
        ..Default::default()
    };
    d.image_base = if is_64 {
        u64le(bytes, opt + 24)
    } else {
        u32le(bytes, opt + 28) as u64
    };
    d.entry_rva = u32le(bytes, opt + 16);
    let checksum_off = opt + 64;
    let header_checksum = u32le(bytes, checksum_off);
    let size_of_headers = u32le(bytes, opt + 60);
    let (dd_count_off, dd_off) = if is_64 {
        (opt + 108, opt + 112)
    } else {
        (opt + 92, opt + 96)
    };
    let dd_count = u32le(bytes, dd_count_off).min(16) as usize;
    let dir = |i: usize| -> (u32, u32) {
        if i < dd_count {
            (
                u32le(bytes, dd_off + i * 8),
                u32le(bytes, dd_off + i * 8 + 4),
            )
        } else {
            (0, 0)
        }
    };

    // -- Section table ------------------------------------------------------
    let sec_off = opt + size_of_opt;
    for i in 0..nsec.min(96) {
        let s = sec_off + i * 40;
        if s + 40 > bytes.len() {
            break;
        }
        let raw_name = &bytes[s..s + 8];
        let name: String = raw_name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| {
                if (0x20..0x7f).contains(&c) {
                    c as char
                } else {
                    '?'
                }
            })
            .collect();
        d.sections.push(SectionRaw {
            name,
            vsize: u32le(bytes, s + 8),
            vaddr: u32le(bytes, s + 12),
            raw_size: u32le(bytes, s + 16),
            raw_ptr: u32le(bytes, s + 20),
            characteristics: u32le(bytes, s + 36),
        });
    }

    // -- Certificate table (a file offset, uniquely among the directories) ---
    let (cert_off, cert_size) = dir(4);
    if cert_size > 0 {
        d.cert = Some(CertInfo {
            offset: cert_off as u64,
            size: cert_size as u64,
        });
    }

    // -- Overlay ------------------------------------------------------------
    let last_end = d.sections.iter().map(|s| s.raw_end()).max().unwrap_or(0);
    let file_len = bytes.len() as u64;
    if last_end > 0 && file_len > last_end {
        let cert_in_overlay = d
            .cert
            .filter(|c| c.offset >= last_end)
            .map(|c| c.size)
            .unwrap_or(0);
        d.overlay = Some(Overlay {
            offset: last_end,
            size: file_len - last_end,
            cert_size: cert_in_overlay,
        });
    }

    // -- TLS callbacks (executed before the entry point) --------------------
    let (tls_rva, tls_size) = dir(9);
    if tls_rva != 0 && tls_size != 0 {
        if let Some(off) = rva_to_off(&d.sections, tls_rva) {
            d.tls_dir_off = Some(off);
            let o = off as usize;
            // AddressOfCallBacks: VA (not RVA) at +12 (PE32) / +24 (PE32+).
            let cb_va = if is_64 {
                u64le(bytes, o + 24)
            } else {
                u32le(bytes, o + 12) as u64
            };
            if cb_va > d.image_base {
                let cb_rva = (cb_va - d.image_base) as u32;
                if let Some(cb_off) = rva_to_off(&d.sections, cb_rva) {
                    let mut p = cb_off as usize;
                    for _ in 0..64 {
                        let va = if is_64 {
                            u64le(bytes, p)
                        } else {
                            u32le(bytes, p) as u64
                        };
                        if va == 0 {
                            break;
                        }
                        d.tls_callbacks.push(va);
                        p += if is_64 { 8 } else { 4 };
                    }
                }
            }
        }
    }

    // -- Debug directory / PDB path -----------------------------------------
    let (dbg_rva, dbg_size) = dir(6);
    if dbg_rva != 0 && dbg_size != 0 {
        if let Some(off) = rva_to_off(&d.sections, dbg_rva) {
            let count = (dbg_size as usize / 28).min(32);
            for i in 0..count {
                let e = off as usize + i * 28;
                if e + 28 > bytes.len() {
                    break;
                }
                let kind = u32le(bytes, e + 12);
                let size = u32le(bytes, e + 16);
                let ptr = u32le(bytes, e + 24) as u64;
                let pdb = (kind == 2)
                    .then(|| read_codeview_pdb(bytes, ptr as usize, size as usize))
                    .flatten();
                if let Some(p) = &pdb {
                    d.pdb_path = Some(p.clone());
                }
                d.debug.push(DebugEntry {
                    kind,
                    kind_name: debug_type_name(kind),
                    file_off: ptr,
                    size,
                    pdb,
                });
            }
        }
    }

    // -- Rich header --------------------------------------------------------
    if let Some((clear, entries)) = parse_rich_clear(bytes, e_lfanew) {
        d.rich_clear = Some(clear);
        d.rich_entries = entries;
    }

    // -- Authenticode coverage & checksum ------------------------------------
    d.authentihash_ranges =
        authenticode_ranges(file_len, checksum_off as u64, dd_off as u64, &d.cert);
    d.checksum = (header_checksum, compute_checksum(bytes, checksum_off));

    d.anomalies = anomalies(&d, file_len, size_of_headers);
    Some(d)
}

fn debug_type_name(kind: u32) -> &'static str {
    match kind {
        0 => "UNKNOWN",
        1 => "COFF",
        2 => "CODEVIEW",
        3 => "FPO",
        4 => "MISC",
        5 => "EXCEPTION",
        6 => "FIXUP",
        9 => "BORLAND",
        12 => "VC_FEATURE",
        13 => "POGO",
        14 => "ILTCG",
        16 => "REPRO",
        20 => "EX_DLLCHARACTERISTICS",
        _ => "?",
    }
}

/// The PDB path inside an `RSDS`/`NB10` CodeView record.
fn read_codeview_pdb(bytes: &[u8], off: usize, size: usize) -> Option<String> {
    let end = off.checked_add(size)?.min(bytes.len());
    let rec = bytes.get(off..end)?;
    let skip = match rec.get(0..4)? {
        b"RSDS" => 24, // signature + GUID + age
        b"NB10" => 16, // signature + offset + timestamp + age
        _ => return None,
    };
    let text = rec.get(skip..)?;
    let s: String = text
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '?'
            }
        })
        .collect();
    (!s.is_empty()).then_some(s)
}

/// Authenticode hashes the whole file except the CheckSum field, the certificate
/// data-directory entry, and the certificate itself.
fn authenticode_ranges(
    file_len: u64,
    checksum_off: u64,
    dd_off: u64,
    cert: &Option<CertInfo>,
) -> Vec<(u64, u64)> {
    let cert_entry = dd_off + 4 * 8; // data directory 4
    let mut cuts = vec![
        (checksum_off, checksum_off + 4),
        (cert_entry, cert_entry + 8),
    ];
    if let Some(c) = cert {
        if c.offset > 0 && c.size > 0 {
            cuts.push((c.offset, (c.offset + c.size).min(file_len)));
        }
    }
    cuts.sort_unstable();
    let mut ranges = Vec::new();
    let mut pos = 0u64;
    for (s, e) in cuts {
        if s > pos {
            ranges.push((pos, s.min(file_len)));
        }
        pos = pos.max(e);
    }
    if pos < file_len {
        ranges.push((pos, file_len));
    }
    ranges.retain(|(s, e)| e > s);
    ranges
}

/// The PE checksum: a 16-bit ones-complement sum over the file with the CheckSum
/// field treated as zero, plus the file length. A signed file whose checksum does
/// not match has been altered after signing.
pub fn compute_checksum(bytes: &[u8], checksum_off: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        // The CheckSum field itself counts as zero.
        let word = if i >= checksum_off && i < checksum_off + 4 {
            0
        } else {
            u16::from_le_bytes([bytes[i], bytes[i + 1]]) as u64
        };
        sum += word;
        sum = (sum & 0xffff) + (sum >> 16);
        i += 2;
    }
    if i < bytes.len() {
        sum += bytes[i] as u64;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum as u32) + bytes.len() as u32
}

/// The decoded Rich header: its clear bytes (what the Rich hash covers) and the
/// `(comp-id, count)` pairs it lists.
type RichHeader = (Vec<u8>, Vec<(u32, u32)>);

fn parse_rich_clear(b: &[u8], e_lfanew: usize) -> Option<RichHeader> {
    let limit = e_lfanew.min(b.len());
    let mut rich_pos = None;
    let mut i = 0x40;
    while i + 4 <= limit {
        if &b[i..i + 4] == b"Rich" {
            rich_pos = Some(i);
            break;
        }
        i += 1;
    }
    let rp = rich_pos?;
    let key = u32le(b, rp + 4);
    // Walk back to "DanS".
    let mut start = None;
    let mut k = rp;
    while k >= 4 {
        k -= 4;
        if u32le(b, k) ^ key == 0x536E_6144 {
            start = Some(k);
            break;
        }
    }
    let start = start?;
    let mut clear = Vec::new();
    let mut entries = Vec::new();
    let mut p = start + 16; // skip DanS + 3 padding dwords
    while p + 8 <= rp {
        let compid = u32le(b, p) ^ key;
        let count = u32le(b, p + 4) ^ key;
        clear.extend_from_slice(&compid.to_le_bytes());
        clear.extend_from_slice(&count.to_le_bytes());
        entries.push((compid, count));
        p += 8;
    }
    (!entries.is_empty()).then_some((clear, entries))
}

/// Structural red flags. Each one is cheap and individually weak; together they
/// are what tells a packed dropper from a normal build at a glance.
fn anomalies(d: &PeDetails, file_len: u64, size_of_headers: u32) -> Vec<Finding> {
    let mut out = Vec::new();

    if d.sections.is_empty() {
        out.push(Finding::suspicious("no sections in the section table"));
    }
    if d.sections.len() > 12 {
        out.push(Finding::info(format!(
            "{} sections (unusually many)",
            d.sections.len()
        )));
    }

    for s in &d.sections {
        if s.writable() && s.executable() {
            out.push(
                Finding::suspicious(format!(
                    "section '{}' is writable AND executable ({})",
                    s.name,
                    s.perms()
                ))
                .at(s.raw_ptr as u64),
            );
        }
        // IMAGE_SCN_CNT_UNINITIALIZED_DATA: .bss is *supposed* to have no raw
        // data, so only flag sections that claim initialized content.
        let uninitialized = s.characteristics & 0x0000_0080 != 0;
        if s.raw_size == 0 && s.vsize > 0 && !uninitialized {
            out.push(
                Finding::suspicious(format!(
                    "section '{}' has no raw data but {:#x} bytes of memory — filled at runtime (packer)",
                    s.name, s.vsize
                ))
                .at(s.raw_ptr as u64),
            );
        } else if !uninitialized
            && s.vsize > 0
            && s.raw_size > 0
            && s.vsize as u64 > s.raw_size as u64 * 10
        {
            out.push(
                Finding::suspicious(format!(
                    "section '{}' expands {:.0}x in memory ({:#x} -> {:#x}) — typical of a packer",
                    s.name,
                    s.vsize as f64 / s.raw_size as f64,
                    s.raw_size,
                    s.vsize
                ))
                .at(s.raw_ptr as u64),
            );
        }
        if s.raw_end() > file_len {
            out.push(
                Finding::suspicious(format!(
                    "section '{}' claims data past the end of the file ({:#x} > {:#x}) — truncated or crafted",
                    s.name,
                    s.raw_end(),
                    file_len
                ))
                .at(s.raw_ptr as u64),
            );
        }
        if s.name.contains('?') || s.name.is_empty() {
            out.push(Finding::suspicious(format!(
                "section name is not printable: '{}'",
                s.name
            )));
        }
    }

    // Entry point placement.
    match d.section_of_rva(d.entry_rva) {
        None if d.entry_rva != 0 => out.push(Finding::suspicious(format!(
            "entry point RVA {:#x} is not inside any section",
            d.entry_rva
        ))),
        Some(s) if !s.executable() => out.push(Finding::suspicious(format!(
            "entry point is in non-executable section '{}' ({})",
            s.name,
            s.perms()
        ))),
        Some(s) if s.writable() => out.push(Finding::suspicious(format!(
            "entry point is in writable section '{}' — self-modifying/unpacking stub",
            s.name
        ))),
        Some(s)
            if d.sections.last().map(|l| l.name.as_str()) == Some(s.name.as_str())
                && d.sections.len() > 1 =>
        {
            out.push(Finding::info(format!(
                "entry point is in the last section '{}' (common for packed files)",
                s.name
            )))
        }
        _ => {}
    }

    if let Some(o) = d.overlay {
        if o.payload_size() > 0 {
            let sev = if o.payload_size() > 4096 {
                Severity::Suspicious
            } else {
                Severity::Info
            };
            let msg = format!(
                "overlay: {} bytes appended after the last section{}",
                o.payload_size(),
                if o.cert_size > 0 {
                    format!(" (plus a {}-byte signature)", o.cert_size)
                } else {
                    String::new()
                }
            );
            out.push(Finding {
                severity: sev,
                message: msg,
                offset: Some(o.offset),
            });
        }
    }

    if !d.tls_callbacks.is_empty() {
        out.push(
            Finding::suspicious(format!(
                "{} TLS callback(s) run before the entry point",
                d.tls_callbacks.len()
            ))
            .at(d.tls_dir_off.unwrap_or(0)),
        );
    }

    if d.is_signed() && !d.checksum_ok() {
        out.push(Finding::suspicious(format!(
            "signed, but the header checksum {:#010x} does not match the file ({:#010x})",
            d.checksum.0, d.checksum.1
        )));
    }
    if d.timestamp == 0 {
        out.push(Finding::info(
            "TimeDateStamp is zero (stripped or reproducible build)",
        ));
    }

    if size_of_headers as u64 > file_len {
        out.push(Finding::suspicious("SizeOfHeaders is larger than the file"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but structurally valid PE32 with one section, built in memory.
    fn build_pe(section_chars: u32, extra_overlay: usize) -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[0] = b'M';
        b[1] = b'Z';
        let e_lfanew = 0x80usize;
        b[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        b[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
        let coff = e_lfanew + 4;
        b[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        b[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        b[coff + 4..coff + 8].copy_from_slice(&0x6000_0000u32.to_le_bytes()); // timestamp
        b[coff + 16..coff + 18].copy_from_slice(&0xe0u16.to_le_bytes()); // size of opt
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry rva
        b[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // image base
        b[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // size of headers
        b[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // dd count
        let sec = opt + 0xe0;
        b[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // vsize
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // vaddr
        b[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        b[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw ptr
        b[sec + 36..sec + 40].copy_from_slice(&section_chars.to_le_bytes());
        b.extend(std::iter::repeat(0x90u8).take(0x200)); // section data
        b.extend(std::iter::repeat(0xccu8).take(extra_overlay));
        b
    }

    const EXEC_READ: u32 = 0x6000_0020;
    const EXEC_WRITE_READ: u32 = 0xe000_0020;

    #[test]
    fn reads_the_timestamp_from_the_coff_header() {
        let d = parse(&build_pe(EXEC_READ, 0)).expect("pe");
        assert_eq!(d.timestamp, 0x6000_0000);
        assert!(!d
            .anomalies
            .iter()
            .any(|f| f.message.contains("TimeDateStamp is zero")));
    }

    #[test]
    fn uninitialized_section_without_raw_data_is_not_flagged() {
        // IMAGE_SCN_CNT_UNINITIALIZED_DATA | READ | WRITE, no raw data: a .bss.
        let mut b = build_pe(EXEC_READ, 0);
        let sec = 0x80 + 4 + 20 + 0xe0;
        b[sec + 16..sec + 20].copy_from_slice(&0u32.to_le_bytes()); // raw size 0
        b[sec + 36..sec + 40].copy_from_slice(&0xc000_0080u32.to_le_bytes());
        let d = parse(&b).expect("pe");
        assert!(
            !d.anomalies
                .iter()
                .any(|f| f.message.contains("no raw data")),
            "{:?}",
            d.anomalies
        );
    }

    #[test]
    fn parses_sections_and_entry() {
        let d = parse(&build_pe(EXEC_READ, 0)).expect("pe");
        assert_eq!(d.sections.len(), 1);
        assert_eq!(d.sections[0].name, ".text");
        assert_eq!(d.sections[0].perms(), "r-x");
        assert_eq!(d.image_base, 0x0040_0000);
        assert!(d.section_of_rva(d.entry_rva).is_some());
    }

    #[test]
    fn flags_writable_executable_section() {
        let d = parse(&build_pe(EXEC_WRITE_READ, 0)).expect("pe");
        assert!(d
            .anomalies
            .iter()
            .any(|f| f.message.contains("writable AND executable")));
    }

    #[test]
    fn detects_overlay() {
        let d = parse(&build_pe(EXEC_READ, 5000)).expect("pe");
        let o = d.overlay.expect("overlay");
        assert_eq!(o.payload_size(), 5000);
        assert_eq!(o.offset, 0x600);
        assert!(d.anomalies.iter().any(|f| f.message.contains("overlay")));
    }

    #[test]
    fn no_overlay_when_file_ends_with_last_section() {
        let d = parse(&build_pe(EXEC_READ, 0)).expect("pe");
        assert!(d.overlay.is_none());
    }

    #[test]
    fn authenticode_ranges_cover_the_file_minus_the_cuts() {
        let bytes = build_pe(EXEC_READ, 0);
        let d = parse(&bytes).expect("pe");
        let covered: u64 = d.authentihash_ranges.iter().map(|(s, e)| e - s).sum();
        // The checksum field (4) and the certificate directory entry (8) are cut.
        assert_eq!(covered, bytes.len() as u64 - 12);
    }

    #[test]
    fn non_pe_input_is_rejected() {
        assert!(parse(b"not a pe at all, really").is_none());
        assert!(parse(&[]).is_none());
    }
}
