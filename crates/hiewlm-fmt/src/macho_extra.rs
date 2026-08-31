//! Mach-O structure checks for triage.
//!
//! macOS samples asked the same questions as PE and ELF ones and got no answer.
//! The load-command table carries most of what matters: whether any segment is
//! writable *and* executable, whether the binary is signed at all, whether a
//! segment is encrypted, where the entry point is, and whether anything is
//! appended past the last segment.

use hiewlm_core::{Finding, Severity};

/// One `LC_SEGMENT`/`LC_SEGMENT_64`.
#[derive(Clone, Debug)]
pub struct MachSegment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub file_off: u64,
    pub file_size: u64,
    /// Protection the loader applies at load time.
    pub initprot: u32,
    /// The most the segment may ever be granted.
    pub maxprot: u32,
}

impl MachSegment {
    pub fn readable(&self) -> bool {
        self.initprot & 1 != 0
    }
    pub fn writable(&self) -> bool {
        self.initprot & 2 != 0
    }
    pub fn executable(&self) -> bool {
        self.initprot & 4 != 0
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
        self.file_off.saturating_add(self.file_size)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MachoDetails {
    pub is_64: bool,
    pub filetype: u32,
    pub filetype_name: &'static str,
    pub segments: Vec<MachSegment>,
    pub dylibs: Vec<String>,
    pub rpaths: Vec<String>,
    /// `(offset, size)` of the code signature blob, when the binary is signed.
    pub code_signature: Option<(u64, u64)>,
    /// A non-zero `cryptid` means the segment ships encrypted.
    pub encrypted: bool,
    /// True when the entry point comes from the pre-10.8 `LC_UNIXTHREAD`.
    pub legacy_entry: bool,
    pub entry_offset: Option<u64>,
    pub overlay: Option<(u64, u64)>,
    pub anomalies: Vec<Finding>,
}

impl MachoDetails {
    pub fn is_signed(&self) -> bool {
        self.code_signature.is_some()
    }
}

const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const LC_MAIN: u32 = 0x8000_0028;
const LC_RPATH: u32 = 0x8000_001c;

fn filetype_name(t: u32) -> &'static str {
    match t {
        1 => "OBJECT",
        2 => "EXECUTE",
        4 => "CORE",
        6 => "DYLIB",
        7 => "DYLINKER",
        8 => "BUNDLE",
        10 => "DSYM",
        11 => "KEXT",
        _ => "?",
    }
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

/// A fixed-size, NUL-padded name field (segment names).
fn name16(b: &[u8], off: usize) -> String {
    b.get(off..off + 16)
        .map(|s| {
            s.iter()
                .take_while(|&&c| c != 0)
                .map(|&c| {
                    if (0x20..0x7f).contains(&c) {
                        c as char
                    } else {
                        '?'
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A load-command string, given as an offset from the start of the command.
fn lc_str(b: &[u8], cmd: usize, cmdsize: usize, str_off_field: usize) -> Option<String> {
    let rel = u32le(b, cmd + str_off_field) as usize;
    if rel >= cmdsize {
        return None;
    }
    let start = cmd + rel;
    let end = (cmd + cmdsize).min(b.len());
    let s: String = b
        .get(start..end)?
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

/// Parse a Mach-O's load commands. A universal (fat) binary is followed into its
/// first slice, and every offset reported is still a real file offset.
/// `None` when the bytes are not a Mach-O.
pub fn parse(bytes: &[u8]) -> Option<MachoDetails> {
    if bytes.len() < 32 {
        return None;
    }
    // Fat header: big-endian magic and counts, slices at absolute file offsets.
    let be = |off: usize| -> u32 {
        bytes
            .get(off..off + 4)
            .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
            .unwrap_or(0)
    };
    if matches!(be(0), 0xcafe_babe | 0xcafe_babf) {
        let nfat = be(4) as usize;
        if nfat == 0 || nfat > 64 {
            return None;
        }
        // Each fat_arch is 20 bytes (32) or 32 bytes (64); the offset field is at
        // +8 in both, as a 32- or 64-bit big-endian value.
        let wide = be(0) == 0xcafe_babf;
        let arch = 8;
        let slice_off = if wide {
            let hi = be(arch + 8) as u64;
            let lo = be(arch + 12) as u64;
            (hi << 32) | lo
        } else {
            be(arch + 8) as u64
        };
        let start = slice_off as usize;
        if start >= bytes.len() {
            return None;
        }
        let mut d = parse_at(&bytes[start..])?;
        // Re-base every offset so it navigates in the real file.
        for s in &mut d.segments {
            s.file_off += slice_off;
        }
        if let Some((o, sz)) = d.code_signature {
            d.code_signature = Some((o + slice_off, sz));
        }
        d.overlay = None; // "past the last segment" is meaningless inside a slice
        d.anomalies = anomalies(&d, bytes.len() as u64);
        for f in &mut d.anomalies {
            if let Some(o) = f.offset {
                f.offset = Some(o.max(slice_off));
            }
        }
        return Some(d);
    }
    parse_at(bytes)
}

fn parse_at(bytes: &[u8]) -> Option<MachoDetails> {
    if bytes.len() < 32 {
        return None;
    }
    let magic = u32le(bytes, 0);
    let is_64 = match magic {
        0xfeed_facf => true,
        0xfeed_face => false,
        // Big-endian (PowerPC-era) images are rare enough to leave to goblin.
        _ => return None,
    };
    let mut d = MachoDetails {
        is_64,
        ..Default::default()
    };
    d.filetype = u32le(bytes, 12);
    d.filetype_name = filetype_name(d.filetype);
    let ncmds = u32le(bytes, 16) as usize;
    let mut cmd = if is_64 { 32 } else { 28 };

    for _ in 0..ncmds.min(4096) {
        if cmd + 8 > bytes.len() {
            break;
        }
        let kind = u32le(bytes, cmd);
        let cmdsize = u32le(bytes, cmd + 4) as usize;
        if cmdsize < 8 || cmd + cmdsize > bytes.len() {
            break;
        }
        match kind {
            LC_SEGMENT | LC_SEGMENT_64 => {
                let wide = kind == LC_SEGMENT_64;
                let (vmaddr, vmsize, file_off, file_size, maxprot, initprot) = if wide {
                    (
                        u64le(bytes, cmd + 24),
                        u64le(bytes, cmd + 32),
                        u64le(bytes, cmd + 40),
                        u64le(bytes, cmd + 48),
                        u32le(bytes, cmd + 56),
                        u32le(bytes, cmd + 60),
                    )
                } else {
                    (
                        u32le(bytes, cmd + 24) as u64,
                        u32le(bytes, cmd + 28) as u64,
                        u32le(bytes, cmd + 32) as u64,
                        u32le(bytes, cmd + 36) as u64,
                        u32le(bytes, cmd + 40),
                        u32le(bytes, cmd + 44),
                    )
                };
                d.segments.push(MachSegment {
                    name: name16(bytes, cmd + 8),
                    vmaddr,
                    vmsize,
                    file_off,
                    file_size,
                    initprot,
                    maxprot,
                });
            }
            LC_LOAD_DYLIB => {
                if let Some(s) = lc_str(bytes, cmd, cmdsize, 8) {
                    d.dylibs.push(s);
                }
            }
            LC_RPATH => {
                if let Some(s) = lc_str(bytes, cmd, cmdsize, 8) {
                    d.rpaths.push(s);
                }
            }
            LC_CODE_SIGNATURE => {
                d.code_signature =
                    Some((u32le(bytes, cmd + 8) as u64, u32le(bytes, cmd + 12) as u64));
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                if u32le(bytes, cmd + 16) != 0 {
                    d.encrypted = true;
                }
            }
            LC_MAIN => d.entry_offset = Some(u64le(bytes, cmd + 8)),
            LC_UNIXTHREAD => d.legacy_entry = true,
            _ => {}
        }
        cmd += cmdsize;
    }

    // Overlay: past the last segment *and* past the signature, which legitimately
    // sits at the very end of the file.
    let file_len = bytes.len() as u64;
    let described = d
        .segments
        .iter()
        .map(|s| s.file_end())
        .chain(d.code_signature.map(|(o, s)| o + s))
        .max()
        .unwrap_or(0);
    if described > 0 && file_len > described {
        d.overlay = Some((described, file_len - described));
    }

    d.anomalies = anomalies(&d, file_len);
    Some(d)
}

fn anomalies(d: &MachoDetails, file_len: u64) -> Vec<Finding> {
    let mut out = Vec::new();

    for s in &d.segments {
        if s.writable() && s.executable() {
            out.push(
                Finding::suspicious(format!(
                    "segment '{}' is writable AND executable ({})",
                    s.name,
                    s.perms()
                ))
                .at(s.file_off),
            );
        }
        if s.name == "__TEXT" && s.writable() {
            out.push(
                Finding::suspicious("__TEXT is writable — self-modifying code").at(s.file_off),
            );
        }
        if s.file_end() > file_len && s.name != "__PAGEZERO" {
            out.push(
                Finding::suspicious(format!(
                    "segment '{}' claims data past the end of the file ({:#x} > {:#x})",
                    s.name,
                    s.file_end(),
                    file_len
                ))
                .at(s.file_off),
            );
        }
    }

    if !d.is_signed() && d.filetype == 2 {
        out.push(Finding::suspicious(
            "no LC_CODE_SIGNATURE — unsigned executable (macOS will refuse it without an exception)",
        ));
    }
    if d.encrypted {
        out.push(Finding::suspicious(
            "LC_ENCRYPTION_INFO cryptid is set — a segment ships encrypted and only decrypts in memory",
        ));
    }
    if d.legacy_entry {
        out.push(Finding::info(
            "entry point via LC_UNIXTHREAD rather than LC_MAIN — pre-10.8 style, also used by packers",
        ));
    }

    for p in &d.dylibs {
        if p.starts_with("/tmp/") || p.starts_with("/var/tmp/") || p.starts_with("./") {
            out.push(Finding::suspicious(format!(
                "links a library from a writable path: {p}"
            )));
        }
    }
    for p in &d.rpaths {
        if p.starts_with("/tmp/") || p.starts_with("/var/tmp/") {
            out.push(Finding::suspicious(format!(
                "rpath points at a writable path: {p}"
            )));
        }
    }

    if let Some((off, size)) = d.overlay {
        let sev = if size > 4096 {
            Severity::Suspicious
        } else {
            Severity::Info
        };
        out.push(Finding {
            severity: sev,
            message: format!("overlay: {size} bytes appended after the last segment"),
            offset: Some(off),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-bit Mach-O with one segment and optionally a code signature.
    fn build_macho(initprot: u32, signed: bool, extra: usize) -> Vec<u8> {
        let seg_size = 72usize;
        let sig_size = 16usize;
        let ncmds = 1 + u32::from(signed);
        let sizeofcmds = seg_size + if signed { sig_size } else { 0 };

        let mut b = vec![0u8; 32];
        b[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        b[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes()); // arm64
        b[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        b[16..20].copy_from_slice(&ncmds.to_le_bytes());
        b[20..24].copy_from_slice(&(sizeofcmds as u32).to_le_bytes());

        let mut seg = vec![0u8; seg_size];
        seg[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        seg[4..8].copy_from_slice(&(seg_size as u32).to_le_bytes());
        seg[8..16].copy_from_slice(b"__TEXT\0\0");
        seg[24..32].copy_from_slice(&0x1_0000_0000u64.to_le_bytes()); // vmaddr
        seg[32..40].copy_from_slice(&0x4000u64.to_le_bytes()); // vmsize
        seg[40..48].copy_from_slice(&0u64.to_le_bytes()); // file off
        seg[48..56].copy_from_slice(&200u64.to_le_bytes()); // file size
        seg[56..60].copy_from_slice(&7u32.to_le_bytes()); // maxprot
        seg[60..64].copy_from_slice(&initprot.to_le_bytes());
        b.extend_from_slice(&seg);

        if signed {
            let mut sig = vec![0u8; sig_size];
            sig[0..4].copy_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
            sig[4..8].copy_from_slice(&(sig_size as u32).to_le_bytes());
            sig[8..12].copy_from_slice(&200u32.to_le_bytes()); // data off
            sig[12..16].copy_from_slice(&64u32.to_le_bytes()); // data size
            b.extend_from_slice(&sig);
        }
        b.resize(200, 0);
        if signed {
            b.resize(264, 0xaa);
        }
        b.extend(std::iter::repeat(0xccu8).take(extra));
        b
    }

    const RX: u32 = 5;
    const RWX: u32 = 7;

    #[test]
    fn parses_segments_and_signature() {
        let d = parse(&build_macho(RX, true, 0)).expect("macho");
        assert!(d.is_64);
        assert_eq!(d.filetype_name, "EXECUTE");
        assert_eq!(d.segments.len(), 1);
        assert_eq!(d.segments[0].name, "__TEXT");
        assert_eq!(d.segments[0].perms(), "r-x");
        assert!(d.is_signed());
        assert!(d.overlay.is_none());
    }

    #[test]
    fn unsigned_executable_is_flagged() {
        let d = parse(&build_macho(RX, false, 0)).expect("macho");
        assert!(d
            .anomalies
            .iter()
            .any(|f| f.message.contains("no LC_CODE_SIGNATURE")));
    }

    #[test]
    fn writable_text_is_flagged() {
        let d = parse(&build_macho(RWX, true, 0)).expect("macho");
        assert!(d
            .anomalies
            .iter()
            .any(|f| f.message.contains("writable AND executable")));
        assert!(d
            .anomalies
            .iter()
            .any(|f| f.message.contains("__TEXT is writable")));
    }

    #[test]
    fn overlay_is_measured_past_the_signature() {
        let d = parse(&build_macho(RX, true, 5000)).expect("macho");
        let (off, size) = d.overlay.expect("overlay");
        assert_eq!(size, 5000);
        assert_eq!(off, 264, "the signature is not overlay");
    }

    #[test]
    fn fat_binary_is_followed_into_its_first_slice() {
        let thin = build_macho(RX, true, 0);
        let slice_off = 4096usize;
        let mut fat = vec![0u8; slice_off];
        fat[0..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        fat[4..8].copy_from_slice(&1u32.to_be_bytes()); // one arch
        fat[16..20].copy_from_slice(&(slice_off as u32).to_be_bytes()); // arch offset
        fat.extend_from_slice(&thin);

        let d = parse(&fat).expect("fat macho");
        assert_eq!(d.segments.len(), 1);
        // Offsets are re-based, so they navigate in the real file.
        assert_eq!(d.segments[0].file_off, slice_off as u64);
        assert!(d.is_signed());
    }

    #[test]
    fn non_macho_is_rejected() {
        assert!(parse(b"\x7fELF and the rest of a header..").is_none());
        assert!(parse(&[]).is_none());
    }
}
