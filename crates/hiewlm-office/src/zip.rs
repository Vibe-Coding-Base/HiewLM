//! ZIP archives: what is really inside, and what the archive is hiding.
//!
//! A member list is not analysis. The questions that decide whether an archive
//! is a delivery vehicle are: what are these files *actually* (not what does the
//! extension claim), is any name disguised, and does the central directory agree
//! with the local headers — because when it does not, the tool that reads one
//! and the tool that reads the other see different archives, which is precisely
//! the point of the trick.
//!
//! Member content is inflated only far enough to read a magic number (64 bytes),
//! never written out and never interpreted.

use hiewlm_core::{Finding, Severity};

const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_EOCD64: u32 = 0x0606_4b50;
const SIG_LOC64: u32 = 0x0706_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_LOCAL: u32 = 0x0403_4b50;

/// Uncompressed:compressed ratio above which an entry looks like a zip bomb…
const BOMB_RATIO: u64 = 1000;
/// …but only worth reporting once the payload is actually large.
const BOMB_MIN_SIZE: u64 = 10 * 1024 * 1024;
/// Bytes of each member inflated to read its magic number.
const SNIFF: usize = 64;

/// One archive member.
#[derive(Clone, Debug)]
pub struct Member {
    pub name: String,
    /// Offset of the local file header — where navigation goes.
    pub local_off: u64,
    pub compressed: u64,
    pub uncompressed: u64,
    pub method: u16,
    pub crc: u32,
    pub dos_datetime: u32,
    pub encrypted: bool,
    /// AES (WinZip extra field 0x9901) rather than legacy ZipCrypto.
    pub aes: bool,
    pub is_dir: bool,
    pub unix_mode: u32,
    /// What the first bytes really are, once inflated far enough to tell.
    pub content: &'static str,
    /// Per-member warnings, already worded for display.
    pub flags: Vec<String>,
}

impl Member {
    pub fn is_symlink(&self) -> bool {
        self.unix_mode & 0xF000 == 0xA000
    }

    /// Extension, lowercase, without the dot.
    pub fn extension(&self) -> String {
        self.name.rsplit('.').next().unwrap_or("").to_ascii_lowercase()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Zip {
    pub members: Vec<Member>,
    pub findings: Vec<Finding>,
    /// What the archive really is: a plain ZIP, or an APK/JAR/ODF/OOXML wearing
    /// the same container.
    pub kind: &'static str,
    /// Bytes before the first local header — an SFX stub, or a prepended file.
    pub prefix_len: u64,
    /// Bytes after the end-of-central-directory record.
    pub suffix_len: u64,
    /// More than one EOCD means more than one archive in the file.
    pub eocd_count: usize,
}

fn u16le(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32le(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Is this a ZIP?
///
/// Not just "does it start with PK": a self-extracting archive starts with an
/// executable, and that is exactly the case worth catching. A file counts when
/// its end-of-central-directory record points at a real central directory.
pub fn is_zip(bytes: &[u8]) -> bool {
    if bytes.len() < 22 {
        return false;
    }
    if &bytes[0..2] == b"PK" {
        return true;
    }
    find_eocd(bytes).0.is_some_and(|e| locate_central_directory(bytes, e).is_some())
}

/// The central directory's real position, and the offset every local-header
/// pointer must be shifted by.
///
/// In a self-extracting archive the recorded offsets are relative to the start
/// of the archive, not of the file, so everything is out by the size of the
/// stub. Real unzip implementations recover the delta the same way.
fn locate_central_directory(bytes: &[u8], eocd: usize) -> Option<(usize, u64)> {
    let declared = u32le(bytes, eocd + 16) as usize;
    if u32le(bytes, declared) == SIG_CENTRAL {
        return Some((declared, 0));
    }
    // Walk back from the EOCD for the true directory start.
    let cd_size = u32le(bytes, eocd + 12) as usize;
    let guess = eocd.checked_sub(cd_size)?;
    if u32le(bytes, guess) == SIG_CENTRAL {
        return Some((guess, (guess - declared.min(guess)) as u64));
    }
    None
}

/// The last end-of-central-directory record, and how many exist.
fn find_eocd(bytes: &[u8]) -> (Option<usize>, usize) {
    let start = bytes.len().saturating_sub(66_000);
    let mut last = None;
    let mut count = 0;
    let mut i = start;
    while i + 4 <= bytes.len() {
        if u32le(bytes, i) == SIG_EOCD {
            last = Some(i);
            count += 1;
        }
        i += 1;
    }
    (last, count)
}

/// Magic numbers worth naming. Extension lies; this does not.
fn sniff(head: &[u8]) -> &'static str {
    const MAGIC: &[(&[u8], &str)] = &[
        (b"MZ", "PE/DOS executable"),
        (b"\x7fELF", "ELF executable"),
        (b"\xfe\xed\xfa\xce", "Mach-O executable"),
        (b"\xfe\xed\xfa\xcf", "Mach-O executable"),
        (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
        (b"\xca\xfe\xba\xbe", "Mach-O universal / Java class"),
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"\xd0\xcf\x11\xe0", "OLE2 compound document"),
        (b"{\\rt", "RTF document"),
        (b"Rar!", "RAR archive"),
        (b"7z\xbc\xaf", "7-Zip archive"),
        (b"\x1f\x8b", "gzip stream"),
        (b"#!", "script with a shebang"),
        (b"<?xml", "XML"),
        (b"<!DOC", "HTML"),
        (b"\xef\xbb\xbf", "UTF-8 BOM text"),
    ];
    MAGIC
        .iter()
        .find(|(m, _)| head.starts_with(m))
        .map(|(_, n)| *n)
        .unwrap_or("")
}

/// The first `SNIFF` bytes of a member, inflating only that far.
fn member_head(bytes: &[u8], m: &Member) -> Vec<u8> {
    let lo = m.local_off as usize;
    if lo + 30 > bytes.len() || u32le(bytes, lo) != SIG_LOCAL {
        return Vec::new();
    }
    let name_len = u16le(bytes, lo + 26) as usize;
    let extra_len = u16le(bytes, lo + 28) as usize;
    let start = lo + 30 + name_len + extra_len;
    let end = (start + m.compressed as usize).min(bytes.len());
    let Some(raw) = bytes.get(start..end) else { return Vec::new() };
    if m.encrypted {
        return Vec::new(); // the bytes are ciphertext; nothing to read
    }
    match m.method {
        0 => raw.iter().take(SNIFF).copied().collect(),
        8 => {
            use flate2::read::DeflateDecoder;
            use std::io::Read;
            let mut out = Vec::new();
            let mut dec = DeflateDecoder::new(raw).take(SNIFF as u64);
            let _ = dec.read_to_end(&mut out);
            out
        }
        _ => Vec::new(),
    }
}

/// Extensions that execute (or can be made to execute) on a double-click.
const DROPPER_EXTS: &[&str] = &[
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msix", "jar", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "ps1", "psm1", "bat", "cmd", "hta", "lnk", "url", "reg", "chm", "iso", "img",
    "vhd", "vhdx", "diagcab", "appref-ms", "settingcontent-ms", "library-ms", "scf", "inf",
];

/// Extensions people expect to be harmless, which makes them the disguise.
const LURE_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt",
    "rtf", "csv", "htm", "html", "zip", "rar",
];

/// Name-level disguises. A name is not just a label here: it is what the user
/// sees before deciding to double-click.
fn name_flags(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    // Right-to-left override: "invoice\u{202E}gpj.exe" displays as "…exe.jpg".
    if name.contains('\u{202E}') || name.contains('\u{202D}') || name.contains('\u{200F}') {
        out.push("right-to-left override in the name — the displayed extension is a lie".into());
    }
    if name.chars().any(|c| (c as u32) < 0x20) {
        out.push("control characters in the name".into());
    }
    if name.ends_with(' ') || name.ends_with('.') {
        out.push("name ends in a space or dot — hides the real extension on Windows".into());
    }
    if name.len() > 200 {
        out.push(format!("name is {} characters long", name.len()));
    }
    if name.starts_with('/') || name.starts_with('\\') || name.contains(':') {
        out.push("absolute path or drive letter — extracts outside the target directory".into());
    }
    if name.contains("../") || name.contains("..\\") {
        out.push("path traversal — extracts outside the target directory".into());
    }

    // Double extension: a lure extension followed by an executable one.
    let parts: Vec<&str> = name.rsplit('.').collect();
    if parts.len() >= 3 {
        let last = parts[0].to_ascii_lowercase();
        let prev = parts[1].to_ascii_lowercase();
        if DROPPER_EXTS.contains(&last.as_str()) && LURE_EXTS.contains(&prev.as_str()) {
            out.push(format!("double extension: looks like .{prev}, is .{last}"));
        }
    }
    out
}

/// Identify what the archive really is from the parts it contains.
fn archive_kind(names: &[String]) -> &'static str {
    let has = |n: &str| names.iter().any(|m| m == n || m.starts_with(n));
    if has("AndroidManifest.xml") || has("classes.dex") {
        "Android APK"
    } else if has("[Content_Types].xml") {
        "OOXML package"
    } else if has("META-INF/MANIFEST.MF") {
        "Java JAR"
    } else if has("mimetype") && has("META-INF/") {
        "OpenDocument"
    } else if has("AppxManifest.xml") {
        "Windows APPX"
    } else {
        "ZIP archive"
    }
}

pub fn parse(bytes: &[u8]) -> Option<Zip> {
    if !is_zip(bytes) {
        return None;
    }
    let (eocd, eocd_count) = find_eocd(bytes);
    let eocd = eocd?;
    let mut z = Zip { eocd_count, ..Default::default() };

    let count = u16le(bytes, eocd + 10) as usize;
    let (cd_off, shift) = locate_central_directory(bytes, eocd)?;
    let cd_size = u32le(bytes, eocd + 12) as usize;
    let comment_len = u16le(bytes, eocd + 20) as usize;
    z.suffix_len = (bytes.len() as u64).saturating_sub((eocd + 22 + comment_len) as u64);

    // -- Central directory -------------------------------------------------
    let mut p = cd_off;
    for _ in 0..count.min(65_535) {
        if p + 46 > bytes.len() || u32le(bytes, p) != SIG_CENTRAL {
            break;
        }
        let flags = u16le(bytes, p + 8);
        let method = u16le(bytes, p + 10);
        let name_len = u16le(bytes, p + 28) as usize;
        let extra_len = u16le(bytes, p + 30) as usize;
        let comment = u16le(bytes, p + 32) as usize;
        let name = String::from_utf8_lossy(bytes.get(p + 46..p + 46 + name_len).unwrap_or_default())
            .into_owned();
        let extra = bytes.get(p + 46 + name_len..p + 46 + name_len + extra_len).unwrap_or_default();
        // WinZip AES stores the real method inside extra field 0x9901.
        let aes = extra_field(extra, 0x9901).is_some();

        let mut m = Member {
            // Shifted past the self-extracting stub, when there is one.
            local_off: u32le(bytes, p + 42) as u64 + shift,
            compressed: u32le(bytes, p + 20) as u64,
            uncompressed: u32le(bytes, p + 24) as u64,
            crc: u32le(bytes, p + 16),
            dos_datetime: u32le(bytes, p + 12),
            encrypted: flags & 1 != 0,
            aes,
            method,
            is_dir: name.ends_with('/'),
            unix_mode: u32le(bytes, p + 38) >> 16,
            flags: name_flags(&name),
            content: "",
            name,
        };
        m.content = {
            let head = member_head(bytes, &m);
            sniff(&head)
        };
        z.members.push(m);
        p += 46 + name_len + extra_len + comment;
    }

    let names: Vec<String> = z.members.iter().map(|m| m.name.clone()).collect();
    z.kind = archive_kind(&names);
    z.prefix_len = z.members.iter().map(|m| m.local_off).min().unwrap_or(0);

    findings(bytes, &mut z, cd_off, cd_size);
    Some(z)
}

/// A ZIP extra field by header id.
fn extra_field(extra: &[u8], id: u16) -> Option<&[u8]> {
    let mut i = 0usize;
    while i + 4 <= extra.len() {
        let this = u16le(extra, i);
        let len = u16le(extra, i + 2) as usize;
        if this == id {
            return extra.get(i + 4..i + 4 + len);
        }
        i += 4 + len;
    }
    None
}

fn findings(bytes: &[u8], z: &mut Zip, cd_off: usize, cd_size: usize) {
    let mut f: Vec<Finding> = Vec::new();

    if z.kind != "ZIP archive" {
        f.push(Finding::info(format!("this archive is a {}", z.kind)));
    }

    // -- Data outside the archive structure --------------------------------
    if z.prefix_len > 0 {
        let stub = sniff(&bytes[..bytes.len().min(SNIFF)]);
        let what = if stub.is_empty() { String::new() } else { format!(" ({stub})") };
        f.push(
            Finding::suspicious(format!(
                "{} bytes precede the first entry{what} — a self-extracting stub or a prepended file",
                z.prefix_len
            ))
            .at(0),
        );
    }
    if z.suffix_len > 0 {
        f.push(
            Finding::suspicious(format!("{} bytes follow the archive", z.suffix_len))
                .at(bytes.len() as u64 - z.suffix_len),
        );
    }
    if z.eocd_count > 1 {
        f.push(Finding::suspicious(format!(
            "{} end-of-central-directory records — the file holds more than one archive",
            z.eocd_count
        )));
    }

    // -- Central directory versus local headers ----------------------------
    // A reader that trusts the central directory and one that walks local
    // headers must see the same archive. Malware makes sure they do not.
    let mut local_offsets: Vec<u64> = Vec::new();
    let mut i = 0usize;
    while i + 30 <= bytes.len() && local_offsets.len() < 65_535 {
        if u32le(bytes, i) == SIG_LOCAL {
            local_offsets.push(i as u64);
            let name_len = u16le(bytes, i + 26) as usize;
            let extra_len = u16le(bytes, i + 28) as usize;
            let comp = u32le(bytes, i + 18) as usize;
            i += 30 + name_len + extra_len + comp.max(1);
        } else {
            i += 1;
        }
    }
    let declared: std::collections::HashSet<u64> = z.members.iter().map(|m| m.local_off).collect();
    let hidden = local_offsets.iter().filter(|o| !declared.contains(o)).count();
    if hidden > 0 {
        let at = local_offsets.iter().find(|o| !declared.contains(o)).copied();
        let mut finding = Finding::suspicious(format!(
            "{hidden} local file header(s) are not listed in the central directory — \
             hidden from any tool that reads the directory"
        ));
        finding.offset = at;
        f.push(finding);
    }

    for m in &z.members {
        let lo = m.local_off as usize;
        if lo + 30 > bytes.len() {
            f.push(Finding::suspicious(format!(
                "{}: local header at {:#x} is past the end of the file",
                m.name, m.local_off
            )));
            continue;
        }
        if u32le(bytes, lo) != SIG_LOCAL {
            f.push(
                Finding::suspicious(format!(
                    "{}: no local file header at {:#x}",
                    m.name, m.local_off
                ))
                .at(m.local_off),
            );
            continue;
        }
        let name_len = u16le(bytes, lo + 26) as usize;
        let local_name =
            String::from_utf8_lossy(bytes.get(lo + 30..lo + 30 + name_len).unwrap_or_default())
                .into_owned();
        if local_name != m.name {
            f.push(
                Finding::suspicious(format!(
                    "{}: the local header calls it {local_name:?} — the two directories disagree",
                    m.name
                ))
                .at(m.local_off),
            );
        }
        let local_comp = u32le(bytes, lo + 18) as u64;
        // A zero size in the local header is legal when the sizes follow in a
        // data descriptor, so only a non-zero disagreement is a finding.
        if local_comp != 0 && local_comp != m.compressed {
            f.push(
                Finding::suspicious(format!(
                    "{}: compressed size differs between the directories ({} vs {})",
                    m.name, local_comp, m.compressed
                ))
                .at(m.local_off),
            );
        }
    }

    // -- Per-member --------------------------------------------------------
    let mut ratios = 0;
    for m in &z.members {
        for flag in &m.flags {
            f.push(Finding::suspicious(format!("{}: {flag}", m.name)).at(m.local_off));
        }
        if m.is_dir {
            continue;
        }
        let ext = m.extension();
        let dropper = DROPPER_EXTS.contains(&ext.as_str());
        let executable = matches!(
            m.content,
            "PE/DOS executable" | "ELF executable" | "Mach-O executable"
        );

        // The strongest single signal: content and extension disagree.
        if executable && !dropper {
            f.push(
                Finding::suspicious(format!(
                    "{}: is a {} despite the .{ext} extension",
                    m.name, m.content
                ))
                .at(m.local_off),
            );
        } else if dropper {
            f.push(
                Finding::suspicious(format!("{}: executable content (.{ext})", m.name))
                    .at(m.local_off),
            );
        }
        if m.content == "ZIP archive" || m.content == "RAR archive" || m.content == "7-Zip archive"
        {
            f.push(
                Finding::info(format!("{}: a nested archive ({})", m.name, m.content))
                    .at(m.local_off),
            );
        }
        if m.is_symlink() {
            f.push(
                Finding::suspicious(format!(
                    "{}: a symlink — extraction can write outside the target directory",
                    m.name
                ))
                .at(m.local_off),
            );
        }
        if m.compressed > 0
            && m.uncompressed / m.compressed.max(1) >= BOMB_RATIO
            && m.uncompressed >= BOMB_MIN_SIZE
        {
            ratios += 1;
        }
    }
    if ratios > 0 {
        f.push(Finding::suspicious(format!(
            "{ratios} entr(y/ies) expand more than {BOMB_RATIO}x — decompression bomb shape"
        )));
    }

    // -- Encryption ---------------------------------------------------------
    let encrypted: Vec<&Member> = z.members.iter().filter(|m| m.encrypted).collect();
    if !encrypted.is_empty() {
        let aes = encrypted.iter().filter(|m| m.aes).count();
        f.push(Finding::suspicious(format!(
            "{} of {} entries are encrypted ({} AES, {} legacy ZipCrypto) — \
             names are still readable, so the password travels with the lure",
            encrypted.len(),
            z.members.len(),
            aes,
            encrypted.len() - aes
        )));
    }

    // -- Timestamps ---------------------------------------------------------
    let files: Vec<&Member> = z.members.iter().filter(|m| !m.is_dir).collect();
    if files.len() > 1 {
        let first = files[0].dos_datetime;
        if files.iter().all(|m| m.dos_datetime == first) {
            f.push(Finding::info(
                "every entry carries the same timestamp — generated, not collected by hand",
            ));
        }
        if files.iter().all(|m| m.dos_datetime == 0) {
            f.push(Finding::info("all timestamps are zero"));
        }
    }

    // ZIP64 and data-descriptor records are worth noting but not alarming.
    if u32le(bytes, cd_off.saturating_sub(20)) == SIG_EOCD64
        || bytes.windows(4).take(4096).any(|w| u32le(w, 0) == SIG_LOC64)
    {
        f.push(Finding::info("ZIP64 record present"));
    }
    let _ = cd_size;

    f.sort_by_key(|x| (x.severity == Severity::Info, x.offset.unwrap_or(u64::MAX)));
    z.findings = f;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ZIP built entry by entry, so tests can bend individual fields.
    struct Builder {
        out: Vec<u8>,
        dir: Vec<u8>,
        count: u16,
    }

    impl Builder {
        fn new() -> Self {
            Self { out: Vec::new(), dir: Vec::new(), count: 0 }
        }

        fn add(&mut self, name: &str, data: &[u8]) -> &mut Self {
            self.add_full(name, data, name, 0)
        }

        /// `local_name` and `flags` differ from the directory entry on purpose in
        /// the mismatch tests.
        fn add_full(&mut self, name: &str, data: &[u8], local_name: &str, flags: u16) -> &mut Self {
            let local = self.out.len() as u32;
            self.out.extend_from_slice(b"PK\x03\x04");
            self.out.extend_from_slice(&[20, 0]);
            self.out.extend_from_slice(&flags.to_le_bytes());
            self.out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            self.out.extend_from_slice(&0u32.to_le_bytes());
            self.out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            self.out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            self.out.extend_from_slice(&(local_name.len() as u16).to_le_bytes());
            self.out.extend_from_slice(&0u16.to_le_bytes());
            self.out.extend_from_slice(local_name.as_bytes());
            self.out.extend_from_slice(data);

            self.dir.extend_from_slice(b"PK\x01\x02");
            self.dir.extend_from_slice(&[20, 0, 20, 0]);
            self.dir.extend_from_slice(&flags.to_le_bytes());
            self.dir.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            self.dir.extend_from_slice(&0u32.to_le_bytes());
            self.dir.extend_from_slice(&(data.len() as u32).to_le_bytes());
            self.dir.extend_from_slice(&(data.len() as u32).to_le_bytes());
            self.dir.extend_from_slice(&(name.len() as u16).to_le_bytes());
            self.dir.extend_from_slice(&0u16.to_le_bytes());
            self.dir.extend_from_slice(&0u16.to_le_bytes());
            self.dir.extend_from_slice(&0u16.to_le_bytes());
            self.dir.extend_from_slice(&0u16.to_le_bytes());
            self.dir.extend_from_slice(&0u32.to_le_bytes());
            self.dir.extend_from_slice(&local.to_le_bytes());
            self.dir.extend_from_slice(name.as_bytes());
            self.count += 1;
            self
        }

        fn finish(&self) -> Vec<u8> {
            let mut out = self.out.clone();
            let cd_off = out.len() as u32;
            out.extend_from_slice(&self.dir);
            out.extend_from_slice(b"PK\x05\x06");
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&self.count.to_le_bytes());
            out.extend_from_slice(&self.count.to_le_bytes());
            out.extend_from_slice(&(self.dir.len() as u32).to_le_bytes());
            out.extend_from_slice(&cd_off.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out
        }
    }

    fn any(z: &Zip, needle: &str) -> bool {
        z.findings.iter().any(|f| f.message.contains(needle))
    }

    #[test]
    fn content_beats_the_extension() {
        let mut b = Builder::new();
        b.add("holiday-photo.jpg", b"MZ\x90\x00 this is a PE");
        let z = parse(&b.finish()).expect("zip");
        assert_eq!(z.members[0].content, "PE/DOS executable");
        assert!(any(&z, "is a PE/DOS executable despite the .jpg"), "{:?}", z.findings);
    }

    #[test]
    fn a_right_to_left_override_is_called_out() {
        let mut b = Builder::new();
        b.add("invoice\u{202E}gpj.exe", b"MZ");
        let z = parse(&b.finish()).expect("zip");
        assert!(any(&z, "right-to-left override"), "{:?}", z.findings);
    }

    #[test]
    fn double_extensions_and_traversal() {
        let mut b = Builder::new();
        b.add("report.pdf.exe", b"MZ");
        b.add("../../etc/cron.d/x", b"root");
        let z = parse(&b.finish()).expect("zip");
        assert!(any(&z, "double extension: looks like .pdf, is .exe"), "{:?}", z.findings);
        assert!(any(&z, "path traversal"));
    }

    #[test]
    fn directories_that_disagree_are_the_finding() {
        // The central directory says readme.txt; the local header says evil.exe.
        let mut b = Builder::new();
        b.add_full("readme.txt", b"hello", "evil.exe", 0);
        let z = parse(&b.finish()).expect("zip");
        assert!(any(&z, "the two directories disagree"), "{:?}", z.findings);
    }

    #[test]
    fn an_entry_missing_from_the_directory_is_hidden() {
        let mut b = Builder::new();
        b.add("visible.txt", b"hello");
        let mut bytes = b.finish();
        // Splice a second local header in front: present in the file, absent
        // from the central directory.
        let mut hidden = Builder::new();
        hidden.add("secret.exe", b"MZ payload");
        let secret = &hidden.out;
        let mut spliced = secret.clone();
        spliced.extend_from_slice(&bytes);
        std::mem::swap(&mut bytes, &mut spliced);
        // The directory offsets are now wrong, which is exactly the situation a
        // real hidden-entry archive creates; the parser must still report it.
        let z = parse(&bytes).expect("zip");
        assert!(any(&z, "not listed in the central directory"), "{:?}", z.findings);
    }

    #[test]
    fn identifies_what_the_archive_really_is() {
        let mut b = Builder::new();
        b.add("AndroidManifest.xml", b"\x03\x00\x08");
        b.add("classes.dex", b"dex\n035");
        let z = parse(&b.finish()).expect("zip");
        assert_eq!(z.kind, "Android APK");
        assert!(any(&z, "this archive is a Android APK"));
    }

    #[test]
    fn encrypted_entries_are_reported_with_their_scheme() {
        let mut b = Builder::new();
        b.add_full("payload.exe", b"ciphertext", "payload.exe", 1);
        let z = parse(&b.finish()).expect("zip");
        assert!(z.members[0].encrypted);
        assert!(any(&z, "encrypted"), "{:?}", z.findings);
        // Encrypted content cannot be sniffed, and the parser must not pretend.
        assert_eq!(z.members[0].content, "");
    }

    #[test]
    fn a_self_extracting_archive_is_found_behind_its_stub() {
        // A real SFX starts with an executable, and its recorded offsets are
        // relative to the archive rather than the file.
        let mut b = Builder::new();
        b.add("payload.exe", b"MZ\x90\x00 dropped file");
        let inner = b.finish();
        let stub = b"MZ\x90\x00 this is the self-extracting stub .............";
        let mut bytes = stub.to_vec();
        bytes.extend_from_slice(&inner);

        assert!(is_zip(&bytes), "an SFX must still be recognised as an archive");
        let z = parse(&bytes).expect("zip");
        assert_eq!(z.members.len(), 1);
        // The shifted offset must land on a real local header.
        let lo = z.members[0].local_off as usize;
        assert_eq!(&bytes[lo..lo + 4], b"PK\x03\x04", "offsets are rebased past the stub");
        assert_eq!(z.members[0].content, "PE/DOS executable");
        assert!(any(&z, "precede the first entry"), "{:?}", z.findings);
    }

    #[test]
    fn a_plain_archive_says_nothing_alarming() {
        let mut b = Builder::new();
        b.add("notes.txt", b"just some text");
        b.add("data.csv", b"a,b,c");
        let z = parse(&b.finish()).expect("zip");
        let suspicious: Vec<&Finding> =
            z.findings.iter().filter(|f| f.severity == Severity::Suspicious).collect();
        assert!(suspicious.is_empty(), "{suspicious:?}");
    }

    #[test]
    fn non_zip_is_rejected() {
        assert!(parse(b"%PDF-1.4").is_none());
        assert!(parse(&[]).is_none());
    }
}
