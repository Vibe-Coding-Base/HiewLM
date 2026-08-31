//! OLE2 / Compound File Binary parsing — the container behind `.doc`, `.xls`,
//! `.ppt`, and behind `vbaProject.bin` inside modern documents.
//!
//! A compound file is a FAT filesystem in a file: a directory tree of storages
//! (directories) and streams (files). What an analyst wants from it is exactly
//! what a filesystem listing gives — what is in here, how big, and where — plus
//! the handful of names that only ever appear for a reason: `Macros`,
//! `ObjectPool`, `EncryptedPackage`, `Equation Native`.
//!
//! Header and FAT are parsed; nothing is executed or handed to a system API.

/// A directory entry: a storage (directory), a stream (file), or the root.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryKind {
    Storage,
    Stream,
    Root,
}

/// One node of the compound file's directory tree.
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Depth in the tree, for indented display.
    pub depth: usize,
    /// Full path, `Macros/VBA/ThisDocument`.
    pub path: String,
    /// First sector of the stream's data, resolved to a file offset when the
    /// stream lives in the main FAT (not the mini stream).
    pub file_off: Option<u64>,
    /// Index in the directory array, for debugging odd files.
    pub index: usize,
}

/// A parsed compound file.
#[derive(Clone, Debug, Default)]
pub struct Cfb {
    pub entries: Vec<Entry>,
    pub sector_size: usize,
    /// Raw contents of every stream small enough to be worth keeping.
    streams: Vec<(String, Vec<u8>)>,
}

impl Cfb {
    /// The contents of a stream by path, if it was read.
    pub fn stream(&self, path: &str) -> Option<&[u8]> {
        self.streams
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, d)| d.as_slice())
    }

    /// Streams whose path contains `needle` (case-insensitive).
    pub fn streams_matching(&self, needle: &str) -> Vec<(&str, &[u8])> {
        let n = needle.to_ascii_lowercase();
        self.streams
            .iter()
            .filter(|(p, _)| p.to_ascii_lowercase().contains(&n))
            .map(|(p, d)| (p.as_str(), d.as_slice()))
            .collect()
    }

    pub fn has_entry(&self, name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        self.entries
            .iter()
            .any(|e| e.name.to_ascii_lowercase() == n)
    }
}

const SIG: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const FREE_SECT: u32 = 0xFFFF_FFFF;
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
const DIR_ENTRY_SIZE: usize = 128;
/// Streams larger than this are listed but not read into memory.
const MAX_STREAM: usize = 8 * 1024 * 1024;
/// Guard against crafted files with cyclic or absurd sector chains.
const MAX_CHAIN: usize = 1 << 20;

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

/// Is this a compound file?
pub fn is_cfb(bytes: &[u8]) -> bool {
    bytes.len() >= 512 && bytes[0..8] == SIG
}

/// Sector number to absolute file offset (sector 0 starts after the header).
fn sector_offset(sector: u32, sector_size: usize) -> usize {
    (sector as usize + 1) * sector_size
}

/// Follow a FAT chain, bounded against cycles.
fn chain(fat: &[u32], mut sector: u32, limit: usize) -> Vec<u32> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while sector < END_OF_CHAIN && out.len() < limit {
        if !seen.insert(sector) {
            break; // a cycle: stop rather than spin
        }
        out.push(sector);
        sector = *fat.get(sector as usize).unwrap_or(&END_OF_CHAIN);
    }
    out
}

/// Read the bytes of a sector chain.
fn read_chain(bytes: &[u8], fat: &[u32], start: u32, sector_size: usize, want: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(want.min(MAX_STREAM));
    for sec in chain(fat, start, MAX_CHAIN) {
        let off = sector_offset(sec, sector_size);
        let end = (off + sector_size).min(bytes.len());
        if off >= bytes.len() {
            break;
        }
        out.extend_from_slice(&bytes[off..end]);
        if out.len() >= want {
            break;
        }
    }
    out.truncate(want);
    out
}

/// Parse a compound file, or `None` when the bytes are not one.
pub fn parse(bytes: &[u8]) -> Option<Cfb> {
    if !is_cfb(bytes) {
        return None;
    }
    let sector_shift = u16le(bytes, 30);
    let mini_shift = u16le(bytes, 32);
    // Only the two sizes the format actually allows.
    let sector_size = match sector_shift {
        9 => 512usize,
        12 => 4096,
        _ => return None,
    };
    let mini_size = 1usize << mini_shift.min(12);
    let dir_start = u32le(bytes, 48);
    let mini_cutoff = u32le(bytes, 56) as usize;
    let mini_fat_start = u32le(bytes, 60);
    let difat_start = u32le(bytes, 68);
    let difat_count = u32le(bytes, 72) as usize;

    // -- FAT: the first 109 sector numbers are in the header, the rest follow
    //    the DIFAT chain.
    let mut fat_sectors: Vec<u32> = (0..109)
        .map(|i| u32le(bytes, 76 + i * 4))
        .filter(|&s| s < FREE_SECT)
        .collect();
    let mut difat = difat_start;
    let per_sector = sector_size / 4;
    for _ in 0..difat_count.min(4096) {
        if difat >= END_OF_CHAIN {
            break;
        }
        let base = sector_offset(difat, sector_size);
        for i in 0..per_sector.saturating_sub(1) {
            let s = u32le(bytes, base + i * 4);
            if s < FREE_SECT {
                fat_sectors.push(s);
            }
        }
        difat = u32le(bytes, base + (per_sector - 1) * 4);
    }

    let mut fat: Vec<u32> = Vec::new();
    for sec in fat_sectors.iter().take(4096) {
        let base = sector_offset(*sec, sector_size);
        if base >= bytes.len() {
            continue;
        }
        for i in 0..per_sector {
            fat.push(u32le(bytes, base + i * 4));
        }
    }
    if fat.is_empty() {
        return None;
    }

    // -- Directory entries -------------------------------------------------
    let dir_bytes = read_chain(bytes, &fat, dir_start, sector_size, MAX_STREAM);
    let count = dir_bytes.len() / DIR_ENTRY_SIZE;
    if count == 0 {
        return None;
    }

    // The root entry's stream is the mini-stream container.
    let root_start = u32le(&dir_bytes, 116);
    let root_size = u64le(&dir_bytes, 120) as usize;
    let mini_stream = read_chain(
        bytes,
        &fat,
        root_start,
        sector_size,
        root_size.min(MAX_STREAM),
    );
    let mini_fat_bytes = read_chain(bytes, &fat, mini_fat_start, sector_size, MAX_STREAM);
    let mini_fat: Vec<u32> = (0..mini_fat_bytes.len() / 4)
        .map(|i| u32le(&mini_fat_bytes, i * 4))
        .collect();

    let mut cfb = Cfb {
        sector_size,
        ..Default::default()
    };
    // Walk the red-black tree by child/sibling links, depth-first, bounded.
    let mut stack = vec![(0usize, 0usize, String::new())];
    let mut visited = std::collections::HashSet::new();
    while let Some((index, depth, prefix)) = stack.pop() {
        if index >= count || !visited.insert(index) || depth > 32 {
            continue;
        }
        let e = index * DIR_ENTRY_SIZE;
        let name_len = u16le(&dir_bytes, e + 64) as usize;
        let name = utf16_name(&dir_bytes[e..e + 64.min(dir_bytes.len() - e)], name_len);
        let kind = match dir_bytes.get(e + 66) {
            Some(1) => EntryKind::Storage,
            Some(2) => EntryKind::Stream,
            Some(5) => EntryKind::Root,
            _ => continue,
        };
        let size = u64le(&dir_bytes, e + 120);
        let start = u32le(&dir_bytes, e + 116);
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        let in_mini = kind == EntryKind::Stream && (size as usize) < mini_cutoff;
        let file_off = (!in_mini && kind == EntryKind::Stream && start < FREE_SECT)
            .then(|| sector_offset(start, sector_size) as u64);

        if kind == EntryKind::Stream && (size as usize) <= MAX_STREAM {
            let data = if in_mini {
                read_mini(&mini_stream, &mini_fat, start, mini_size, size as usize)
            } else {
                read_chain(bytes, &fat, start, sector_size, size as usize)
            };
            cfb.streams.push((path.clone(), data));
        }

        cfb.entries.push(Entry {
            name,
            kind,
            size,
            depth,
            path: path.clone(),
            file_off,
            index,
        });

        // Siblings share this node's depth and prefix; the child starts a level.
        // The root is the container, not a directory, so it contributes no path
        // component — `Macros/VBA/ThisDocument`, not `Root Entry/Macros/...`.
        let child_prefix = if kind == EntryKind::Root {
            String::new()
        } else {
            path.clone()
        };
        let child_depth = if kind == EntryKind::Root {
            depth
        } else {
            depth + 1
        };
        let left = u32le(&dir_bytes, e + 68);
        let right = u32le(&dir_bytes, e + 72);
        let child = u32le(&dir_bytes, e + 76);
        for (sib, d, p) in [
            (left, depth, prefix.clone()),
            (right, depth, prefix.clone()),
            (child, child_depth, child_prefix),
        ] {
            if sib < FREE_SECT {
                stack.push((sib as usize, d, p));
            }
        }
    }
    cfb.entries.sort_by(|a, b| a.path.cmp(&b.path));
    Some(cfb)
}

/// A directory entry name: UTF-16LE, `name_len` counts bytes including the NUL.
fn utf16_name(field: &[u8], name_len: usize) -> String {
    let len = name_len.saturating_sub(2).min(field.len()) / 2;
    let units: Vec<u16> = (0..len).map(|i| u16le(field, i * 2)).collect();
    String::from_utf16_lossy(&units)
        .chars()
        .map(|c| if (c as u32) < 0x20 { '?' } else { c })
        .collect()
}

/// Read a stream that lives in the mini-stream (small streams).
fn read_mini(mini: &[u8], mini_fat: &[u32], start: u32, mini_size: usize, want: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(want.min(MAX_STREAM));
    for sec in chain(mini_fat, start, MAX_CHAIN) {
        let off = sec as usize * mini_size;
        let end = (off + mini_size).min(mini.len());
        if off >= mini.len() {
            break;
        }
        out.extend_from_slice(&mini[off..end]);
        if out.len() >= want {
            break;
        }
    }
    out.truncate(want);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but real compound file: header, one FAT sector, a directory
    /// with a root and one stream large enough to avoid the mini-stream.
    fn build_cfb(stream_name: &str, payload: &[u8]) -> Vec<u8> {
        let ss = 512usize;
        let mut b = vec![0u8; ss * 5];
        b[0..8].copy_from_slice(&SIG);
        b[30..32].copy_from_slice(&9u16.to_le_bytes()); // 512-byte sectors
        b[32..34].copy_from_slice(&6u16.to_le_bytes()); // 64-byte mini sectors
        b[44..48].copy_from_slice(&1u32.to_le_bytes()); // one FAT sector
        b[48..52].copy_from_slice(&1u32.to_le_bytes()); // directory at sector 1
                                                        // A small mini-stream cutoff so a short payload still travels through the
                                                        // main FAT, which is the path worth testing.
        b[56..60].copy_from_slice(&64u32.to_le_bytes()); // mini cutoff
        b[60..64].copy_from_slice(&END_OF_CHAIN.to_le_bytes()); // no mini FAT
        b[68..72].copy_from_slice(&END_OF_CHAIN.to_le_bytes()); // no DIFAT
        b[76..80].copy_from_slice(&0u32.to_le_bytes()); // FAT lives in sector 0

        // FAT (sector 0): 0=FATSECT, 1=dir end, 2=stream end.
        let fat = ss; // file offset of sector 0
        b[fat..fat + 4].copy_from_slice(&0xFFFF_FFFDu32.to_le_bytes());
        b[fat + 4..fat + 8].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        b[fat + 8..fat + 12].copy_from_slice(&END_OF_CHAIN.to_le_bytes());

        // Directory (sector 1): entry 0 root, entry 1 the stream.
        let dir = ss * 2;
        let put_name = |b: &mut Vec<u8>, at: usize, name: &str| {
            let units: Vec<u16> = name.encode_utf16().collect();
            for (i, u) in units.iter().enumerate() {
                b[at + i * 2..at + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
            }
            let len = (units.len() + 1) * 2;
            b[at + 64..at + 66].copy_from_slice(&(len as u16).to_le_bytes());
        };
        put_name(&mut b, dir, "Root Entry");
        b[dir + 66] = 5; // root
        b[dir + 76..dir + 80].copy_from_slice(&1u32.to_le_bytes()); // child = entry 1
        b[dir + 116..dir + 120].copy_from_slice(&END_OF_CHAIN.to_le_bytes());

        let e1 = dir + DIR_ENTRY_SIZE;
        put_name(&mut b, e1, stream_name);
        b[e1 + 66] = 2; // stream
        b[e1 + 68..e1 + 72].copy_from_slice(&FREE_SECT.to_le_bytes()); // no left
        b[e1 + 72..e1 + 76].copy_from_slice(&FREE_SECT.to_le_bytes()); // no right
        b[e1 + 76..e1 + 80].copy_from_slice(&FREE_SECT.to_le_bytes()); // no child
        b[e1 + 116..e1 + 120].copy_from_slice(&2u32.to_le_bytes()); // data at sector 2
        b[e1 + 120..e1 + 128].copy_from_slice(&(payload.len() as u64).to_le_bytes());

        let data = ss * 3;
        b[data..data + payload.len()].copy_from_slice(payload);
        b
    }

    #[test]
    fn parses_the_directory_tree() {
        let payload = vec![b'A'; 200]; // above the 64-byte cutoff: main FAT
        let c = parse(&build_cfb("WordDocument", &payload)).expect("cfb");
        assert_eq!(c.sector_size, 512);
        assert!(c.has_entry("WordDocument"));
        let e = c.entries.iter().find(|e| e.name == "WordDocument").unwrap();
        assert_eq!(e.kind, EntryKind::Stream);
        assert_eq!(e.size, 200);
        assert_eq!(
            e.file_off,
            Some(512 * 3),
            "streams point at real file offsets"
        );
    }

    #[test]
    fn reads_stream_contents() {
        let payload = b"this is the stream body, repeated a few times. ".repeat(4);
        let c = parse(&build_cfb("Contents", &payload)).expect("cfb");
        let got = c.stream("Contents").expect("stream body");
        assert_eq!(&got[..23], b"this is the stream body");
        assert_eq!(got.len(), payload.len());
    }

    #[test]
    fn rejects_non_compound_files() {
        assert!(parse(b"PK\x03\x04 this is a zip").is_none());
        assert!(parse(&[]).is_none());
        assert!(!is_cfb(b"MZ"));
    }

    #[test]
    fn a_cyclic_chain_terminates() {
        // A FAT that points a sector at itself must not hang the parser.
        let fat = vec![0u32, 1, 2];
        assert_eq!(chain(&fat, 0, 1000).len(), 1);
        assert_eq!(chain(&fat, 1, 1000).len(), 1);
    }
}
