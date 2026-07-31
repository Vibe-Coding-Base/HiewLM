//! ZIP container plugin.
//!
//! Parses the End-Of-Central-Directory record and walks the central directory,
//! listing every member with the offset of its local file header so the viewer
//! can jump straight to it. Read-only: nothing is decompressed or executed —
//! member *metadata* is reported, member *content* is never interpreted.
//!
//! Beyond listing, the parser flags the things that matter when a ZIP is a
//! malware carrier: encrypted entries, path traversal, droppable executables,
//! and compression ratios typical of zip bombs.

use hiewlm_core::container::{Container, ContainerParser, Finding, Member};

const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_EOCD64: u32 = 0x0606_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_LOCAL: u32 = 0x0403_4b50;

/// Extensions that execute (or can be made to execute) on a double-click.
const DROPPER_EXTS: &[&str] = &[
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "jar", "js", "jse", "vbs", "vbe", "wsf",
    "wsh", "ps1", "bat", "cmd", "hta", "lnk", "reg", "chm", "iso", "img",
];

/// Uncompressed:compressed ratio above which an entry looks like a zip bomb.
const BOMB_RATIO: u64 = 1000;
/// ...but only worth reporting once the payload is actually large.
const BOMB_MIN_SIZE: u64 = 10 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct ZipPlugin;

impl ContainerParser for ZipPlugin {
    fn name(&self) -> &'static str {
        "zip"
    }

    fn description(&self) -> &'static str {
        "ZIP archives: member list, compression, encryption and dropper checks"
    }

    fn sniff(&self, bytes: &[u8]) -> bool {
        bytes.len() >= 22 && bytes.starts_with(b"PK")
    }

    fn parse(&self, bytes: &[u8]) -> Option<Container> {
        parse(bytes)
    }
}

fn rd_u16(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u64(b: &[u8], off: usize) -> u64 {
    b.get(off..off + 8)
        .map_or(0, |s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn method_name(m: u16) -> &'static str {
    match m {
        0 => "stored",
        1 => "shrunk",
        6 => "imploded",
        8 => "deflate",
        9 => "deflate64",
        12 => "bzip2",
        14 => "lzma",
        93 => "zstd",
        95 => "xz",
        98 => "ppmd",
        _ => "method?",
    }
}

/// Decode an MS-DOS date/time pair into `YYYY-MM-DD HH:MM:SS`.
fn dos_time(date: u16, time: u16) -> String {
    let (y, mo, d) = (1980 + (date >> 9), (date >> 5) & 0xf, date & 0x1f);
    let (h, mi, s) = (time >> 11, (time >> 5) & 0x3f, (time & 0x1f) * 2);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

fn extension_of(name: &str) -> String {
    name.rsplit('/')
        .next()
        .unwrap_or(name)
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default()
}

/// A member path that would escape the extraction directory.
fn is_traversal(name: &str) -> bool {
    let n = name.replace('\\', "/");
    n.starts_with('/')
        || n.split('/').any(|c| c == "..")
        || (n.len() > 1 && n.as_bytes()[1] == b':')
}

/// Locate the End-Of-Central-Directory record by scanning back from the end.
/// The trailing comment may be up to 64 KiB, so the scan window is bounded.
fn find_eocd(bytes: &[u8]) -> Option<usize> {
    let start = bytes.len().saturating_sub(22 + 0xffff);
    (start..=bytes.len().checked_sub(22)?).rev().find(|&i| rd_u32(bytes, i) == SIG_EOCD)
}

/// Follow the ZIP64 locator when the 32-bit EOCD fields are saturated.
fn zip64_cd(bytes: &[u8], eocd: usize) -> Option<(u64, u64)> {
    let loc = eocd.checked_sub(20)?;
    if rd_u32(bytes, loc) != 0x0706_4b50 {
        return None;
    }
    let rec = rd_u64(bytes, loc + 8) as usize;
    if rd_u32(bytes, rec) != SIG_EOCD64 {
        return None;
    }
    Some((rd_u64(bytes, rec + 32), rd_u64(bytes, rec + 48)))
}

pub fn parse(bytes: &[u8]) -> Option<Container> {
    if bytes.len() < 22 || !bytes.starts_with(b"PK") {
        return None;
    }
    let eocd = find_eocd(bytes)?;

    let mut total = rd_u16(bytes, eocd + 10) as u64;
    let mut cd_off = rd_u32(bytes, eocd + 16) as u64;
    let cd_size = rd_u32(bytes, eocd + 12) as u64;
    let comment_len = rd_u16(bytes, eocd + 20) as usize;

    let mut zip64 = false;
    if total == 0xffff || cd_off == 0xffff_ffff {
        if let Some((n, off)) = zip64_cd(bytes, eocd) {
            total = n;
            cd_off = off;
            zip64 = true;
        }
    }

    let mut members = Vec::new();
    let mut findings = Vec::new();
    let (mut encrypted, mut dirs, mut total_raw, mut total_comp) = (0u64, 0u64, 0u64, 0u64);

    let mut o = cd_off as usize;
    // `total` comes from the file, so cap iterations independently of it.
    for _ in 0..total.min(200_000) {
        if o + 46 > bytes.len() || rd_u32(bytes, o) != SIG_CENTRAL {
            break;
        }
        let flags = rd_u16(bytes, o + 8);
        let method = rd_u16(bytes, o + 10);
        let mtime = rd_u16(bytes, o + 12);
        let mdate = rd_u16(bytes, o + 14);
        let crc = rd_u32(bytes, o + 16);
        let csize = rd_u32(bytes, o + 20) as u64;
        let usize_ = rd_u32(bytes, o + 24) as u64;
        let fn_len = rd_u16(bytes, o + 28) as usize;
        let ex_len = rd_u16(bytes, o + 30) as usize;
        let cm_len = rd_u16(bytes, o + 32) as usize;
        let lh_off = rd_u32(bytes, o + 42) as u64;
        let name = bytes
            .get(o + 46..o + 46 + fn_len)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();

        let is_dir = name.ends_with('/');
        let is_enc = flags & 1 != 0;
        if is_dir {
            dirs += 1;
        } else {
            total_raw += usize_;
            total_comp += csize;
        }
        if is_enc {
            encrypted += 1;
        }

        let mut detail = format!("{} {usize_}→{csize}", method_name(method));
        if is_enc {
            detail.push_str(" encrypted");
        }
        detail.push_str(&format!(" crc:{crc:08X} {}", dos_time(mdate, mtime)));

        if is_traversal(&name) {
            findings.push(
                Finding::suspicious(format!("path traversal in member name: {name:?}"))
                    .at(lh_off),
            );
        }
        let ext = extension_of(&name);
        if !is_dir && DROPPER_EXTS.contains(&ext.as_str()) {
            findings.push(
                Finding::suspicious(format!("executable member: {name} (.{ext})")).at(lh_off),
            );
        }
        if csize > 0 && usize_ / csize.max(1) > BOMB_RATIO && usize_ > BOMB_MIN_SIZE {
            findings.push(
                Finding::suspicious(format!(
                    "compression ratio {}:1 on {name} — possible zip bomb",
                    usize_ / csize.max(1)
                ))
                .at(lh_off),
            );
        }
        if lh_off as usize >= bytes.len() {
            findings.push(
                Finding::suspicious(format!("member {name} points past EOF ({lh_off:#x})")).at(lh_off),
            );
        } else if rd_u32(bytes, lh_off as usize) != SIG_LOCAL {
            findings.push(
                Finding::suspicious(format!("member {name} has no local header at {lh_off:#x}"))
                    .at(lh_off),
            );
        }

        members.push(Member::new(name, lh_off, usize_, detail));
        o += 46 + fn_len + ex_len + cm_len;
    }

    if members.len() as u64 != total {
        findings.push(Finding::suspicious(format!(
            "central directory declares {total} entries but {} were readable",
            members.len()
        )));
    }
    if encrypted > 0 {
        findings.push(Finding::info(format!("{encrypted} encrypted member(s)")));
    }
    // Data before the first local header: a self-extracting stub, or a ZIP
    // appended to a carrier file (a classic polyglot trick).
    let first = members.iter().map(|m| m.offset).min().unwrap_or(0);
    if first > 0 {
        findings.push(
            Finding::suspicious(format!("{first} bytes precede the first member (SFX stub or appended ZIP)"))
                .at(0),
        );
    }

    let ratio = if total_raw > 0 {
        format!("{:.1}%", 100.0 * total_comp as f64 / total_raw as f64)
    } else {
        "n/a".into()
    };

    let summary = vec![
        ("Type".into(), if zip64 { "ZIP64 archive".into() } else { "ZIP archive".to_string() }),
        ("Entries".into(), total.to_string()),
        ("Files".into(), (members.len() as u64 - dirs).to_string()),
        ("Directories".into(), dirs.to_string()),
        ("Encrypted".into(), encrypted.to_string()),
        ("Uncompressed".into(), total_raw.to_string()),
        ("Compressed".into(), total_comp.to_string()),
        ("Ratio".into(), ratio),
        ("Central dir".into(), format!("{cd_off:#010x} ({cd_size} bytes)")),
        ("Comment".into(), comment_len.to_string()),
    ];

    Some(Container { kind: "ZIP archive".into(), summary, members, findings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiewlm_core::container::Severity;

    /// Build a single-entry ZIP: local header at `lh`, then central dir + EOCD.
    fn zip_with(name: &str, method: u16, flags: u16, csize: u32, usize_: u32) -> Vec<u8> {
        let lh = 0usize;
        let mut buf = vec![0u8; 30];
        buf[0..4].copy_from_slice(&SIG_LOCAL.to_le_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.resize(0x100, 0);

        let cd_off = buf.len();
        let mut cd = vec![0u8; 46];
        cd[0..4].copy_from_slice(&SIG_CENTRAL.to_le_bytes());
        cd[8..10].copy_from_slice(&flags.to_le_bytes());
        cd[10..12].copy_from_slice(&method.to_le_bytes());
        cd[20..24].copy_from_slice(&csize.to_le_bytes());
        cd[24..28].copy_from_slice(&usize_.to_le_bytes());
        cd[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
        cd[42..46].copy_from_slice(&(lh as u32).to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&cd);

        let mut eocd = vec![0u8; 22];
        eocd[0..4].copy_from_slice(&SIG_EOCD.to_le_bytes());
        eocd[10..12].copy_from_slice(&1u16.to_le_bytes());
        eocd[16..20].copy_from_slice(&(cd_off as u32).to_le_bytes());
        buf.extend_from_slice(&eocd);
        buf
    }

    #[test]
    fn sniff_rejects_non_zip() {
        let p = ZipPlugin;
        assert!(!p.sniff(b"MZ\x90\x00"));
        assert!(!p.sniff(b"PK"));
        assert!(p.sniff(&zip_with("a.txt", 8, 0, 5, 9)));
    }

    #[test]
    fn lists_member_at_local_header_offset() {
        let c = parse(&zip_with("a.txt", 8, 0, 5, 9)).unwrap();
        assert_eq!(c.members.len(), 1);
        assert_eq!(c.members[0].name, "a.txt");
        assert_eq!(c.members[0].offset, 0);
        assert_eq!(c.members[0].size, 9);
        assert!(c.members[0].detail.contains("deflate"));
    }

    #[test]
    fn flags_executable_member() {
        let c = parse(&zip_with("invoice.exe", 8, 0, 5, 9)).unwrap();
        assert!(c.suspicious().any(|f| f.message.contains("executable member")));
    }

    #[test]
    fn flags_path_traversal() {
        let c = parse(&zip_with("../../etc/passwd", 0, 0, 5, 9)).unwrap();
        assert!(c.suspicious().any(|f| f.message.contains("path traversal")));
    }

    #[test]
    fn flags_encryption() {
        let c = parse(&zip_with("a.txt", 8, 1, 5, 9)).unwrap();
        assert!(c.members[0].detail.contains("encrypted"));
        assert!(c.findings.iter().any(|f| f.message.contains("encrypted member")));
    }

    #[test]
    fn flags_zip_bomb_ratio() {
        let c = parse(&zip_with("bomb.bin", 8, 0, 100, 500_000_000)).unwrap();
        assert!(c.suspicious().any(|f| f.message.contains("zip bomb")));
    }

    #[test]
    fn clean_archive_has_no_suspicious_findings() {
        let c = parse(&zip_with("readme.txt", 8, 0, 5, 9)).unwrap();
        assert_eq!(c.suspicious().count(), 0, "{:?}", c.findings);
    }

    #[test]
    fn traversal_detection_cases() {
        assert!(is_traversal("../x"));
        assert!(is_traversal("/etc/passwd"));
        assert!(is_traversal("C:\\windows\\x"));
        assert!(is_traversal("a\\..\\b"));
        assert!(!is_traversal("a/b/c.txt"));
        assert!(!is_traversal("..dotfile"));
    }

    #[test]
    fn dos_time_decoding() {
        // 2024-07-18 13:42:00
        let date = ((2024 - 1980) << 9) | (7 << 5) | 18;
        let time = (13 << 11) | (42 << 5);
        assert_eq!(dos_time(date, time), "2024-07-18 13:42:00");
    }

    #[test]
    fn truncated_and_hostile_input_does_not_panic() {
        let p = ZipPlugin;
        for n in 0..64 {
            let b = vec![b'P'; n];
            let _ = p.sniff(&b);
            let _ = parse(&b);
        }
        let mut z = zip_with("a.txt", 8, 0, 5, 9);
        z.truncate(z.len() - 10);
        let _ = parse(&z);
        // Central directory pointing far past EOF.
        let mut z2 = zip_with("a.txt", 8, 0, 5, 9);
        let n = z2.len();
        z2[n - 6..n - 2].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        let _ = parse(&z2);
    }

    #[test]
    fn severity_ordering_puts_suspicious_last() {
        assert!(Severity::Info < Severity::Suspicious);
    }
}
