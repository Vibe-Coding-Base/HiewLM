//! Editable buffer: an immutable read-only source plus a piece-table overlay for
//! edit/insert/delete, with an undo/redo journal. The target file is always
//! treated as passive data.

use crate::addr::FileOffset;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Immutable byte source beneath the overlay (mapped file, in-memory buffer, disk).
pub trait DataSource: Send + Sync {
    fn len(&self) -> u64;
    fn read_at(&self, off: u64, buf: &mut [u8]);

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A read-only memory-mapped file. Empty files are not mapped (mapping a zero-
/// length region is an error).
#[derive(Debug)]
pub struct FileSource {
    map: Option<memmap2::Mmap>,
    len: u64,
    path: PathBuf,
}

impl FileSource {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let len = file.metadata()?.len();
        let map = if len == 0 {
            None
        } else {
            // SAFETY: the only unsafe site in core (design §22.7). Read-only map; if
            // the file is truncated underneath us, accessing beyond the new end can
            // SIGBUS — risk noted in design §22.2, to be replaced with checked reads
            // for untrusted sources.
            #[allow(unsafe_code)]
            Some(unsafe { memmap2::Mmap::map(&file)? })
        };
        Ok(Self { map, len, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl DataSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) {
        let Some(map) = &self.map else {
            buf.fill(0);
            return;
        };
        for (i, slot) in buf.iter_mut().enumerate() {
            let idx = off.saturating_add(i as u64);
            *slot = map.get(idx as usize).copied().unwrap_or(0);
        }
    }
}

/// Live process memory as a data source (Linux `/proc/<pid>/mem`). Offsets are
/// virtual addresses. Reading another process needs ptrace permission (same user
/// with a permissive `yama/ptrace_scope`, or root). Requires elevated caution:
/// this reads a running program's memory but never executes it.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct ProcSource {
    file: File,
    len: u64,
}

#[cfg(target_os = "linux")]
impl ProcSource {
    pub fn open(pid: u32) -> io::Result<Self> {
        let file = File::open(format!("/proc/{pid}/mem"))?;
        // Highest mapped address bounds the "file"; low unmapped gaps read as 0.
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
        let mut max = 0u64;
        for line in maps.lines() {
            if let Some((range, _)) = line.split_once(' ') {
                if let Some((_, hi)) = range.split_once('-') {
                    if let Ok(hi) = u64::from_str_radix(hi, 16) {
                        max = max.max(hi);
                    }
                }
            }
        }
        Ok(Self { file, len: max })
    }
}

#[cfg(target_os = "linux")]
impl DataSource for ProcSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) {
        use std::os::unix::fs::FileExt;
        // Unmapped pages fail the read; present them as zeros.
        if self.file.read_at(buf, off).is_err() {
            buf.fill(0);
        }
    }
}

/// In-memory source (stdin, synthetic data, tests).
#[derive(Debug)]
pub struct MemSource {
    data: Vec<u8>,
}

impl MemSource {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl DataSource for MemSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) {
        for (i, slot) in buf.iter_mut().enumerate() {
            let idx = off.saturating_add(i as u64) as usize;
            *slot = self.data.get(idx).copied().unwrap_or(0);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Origin {
    Base,
    Added,
}

#[derive(Clone, Copy, Debug)]
struct Piece {
    origin: Origin,
    start: u64,
    len: u64,
}

/// One piece-table state for undo/redo. `added` only grows and is never truncated
/// (redo's pieces still reference it), so a snapshot only needs the piece list.
#[derive(Clone)]
struct Snapshot {
    pieces: Vec<Piece>,
    len: u64,
}

/// Editable buffer: `base` is immutable, `added` holds bytes the user typed, and
/// `pieces` describes the current logical file. Edit/insert/delete operate on the
/// piece list.
pub struct EditBuffer {
    base: Arc<dyn DataSource>,
    added: Vec<u8>,
    pieces: Vec<Piece>,
    len: u64,
    undo: Vec<Snapshot>,
    redo: Vec<Snapshot>,
    dirty: bool,
}

impl std::fmt::Debug for EditBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EditBuffer")
            .field("len", &self.len)
            .field("pieces", &self.pieces.len())
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl EditBuffer {
    pub fn new(base: Arc<dyn DataSource>) -> Self {
        let len = base.len();
        let pieces = if len == 0 {
            Vec::new()
        } else {
            vec![Piece {
                origin: Origin::Base,
                start: 0,
                len,
            }]
        };
        Self {
            base,
            added: Vec::new(),
            pieces,
            len,
            undo: Vec::new(),
            redo: Vec::new(),
            dirty: false,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }

    /// Read `buf.len()` bytes from `off`; past EOF yields zeros.
    pub fn read_at(&self, off: FileOffset, buf: &mut [u8]) {
        let mut want = off.get();
        let mut out = 0usize;
        let mut cursor = 0u64;

        for piece in &self.pieces {
            if out >= buf.len() {
                break;
            }
            let piece_end = cursor + piece.len;
            if want < piece_end {
                let skip = want - cursor;
                let avail = piece.len - skip;
                let take = avail.min((buf.len() - out) as u64) as usize;
                self.read_piece(piece, skip, &mut buf[out..out + take]);
                out += take;
                want += take as u64;
            }
            cursor = piece_end;
        }
        buf[out..].fill(0);
    }

    pub fn read_byte(&self, off: FileOffset) -> u8 {
        let mut b = [0u8; 1];
        self.read_at(off, &mut b);
        b[0]
    }

    fn read_piece(&self, piece: &Piece, skip: u64, out: &mut [u8]) {
        match piece.origin {
            Origin::Base => self.base.read_at(piece.start + skip, out),
            Origin::Added => {
                let s = (piece.start + skip) as usize;
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = self.added.get(s + i).copied().unwrap_or(0);
                }
            }
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            pieces: self.pieces.clone(),
            len: self.len,
        }
    }

    fn restore(&mut self, snap: Snapshot) {
        self.pieces = snap.pieces;
        self.len = snap.len;
    }

    fn record(&mut self) {
        self.undo.push(self.snapshot());
        self.redo.clear();
        self.dirty = true;
    }

    /// Overwrite the bytes starting at `off` without changing length (extends the
    /// file if it runs past EOF).
    pub fn overwrite(&mut self, off: FileOffset, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.record();
        let start = off.get();
        let end = start + bytes.len() as u64;
        if end > self.len {
            self.pad_to(start);
        }
        let added_start = self.added.len() as u64;
        self.added.extend_from_slice(bytes);
        let replacement = Piece {
            origin: Origin::Added,
            start: added_start,
            len: bytes.len() as u64,
        };
        if end <= self.len {
            self.splice(start, end, vec![replacement]);
        } else {
            self.splice(start, self.len, vec![replacement]);
            self.len = end;
        }
    }

    /// Insert bytes at `off`, growing the file (HIEW: Shift+F3).
    pub fn insert(&mut self, off: FileOffset, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.record();
        let at = off.get().min(self.len);
        let added_start = self.added.len() as u64;
        self.added.extend_from_slice(bytes);
        let new_piece = Piece {
            origin: Origin::Added,
            start: added_start,
            len: bytes.len() as u64,
        };
        self.splice(at, at, vec![new_piece]);
        self.len += bytes.len() as u64;
    }

    /// Delete `[off, off+len)`, shrinking the file (HIEW: Shift+F2).
    pub fn delete(&mut self, off: FileOffset, len: u64) {
        if len == 0 {
            return;
        }
        self.record();
        let start = off.get().min(self.len);
        let end = (start + len).min(self.len);
        self.splice(start, end, Vec::new());
        self.len -= end - start;
    }

    pub fn undo(&mut self) -> bool {
        let Some(snap) = self.undo.pop() else {
            return false;
        };
        let cur = self.snapshot();
        self.redo.push(cur);
        self.restore(snap);
        self.dirty = self.can_undo();
        true
    }

    pub fn redo(&mut self) -> bool {
        let Some(snap) = self.redo.pop() else {
            return false;
        };
        let cur = self.snapshot();
        self.undo.push(cur);
        self.restore(snap);
        self.dirty = true;
        true
    }

    fn pad_to(&mut self, target: u64) {
        if target <= self.len {
            return;
        }
        let gap = target - self.len;
        let added_start = self.added.len() as u64;
        self.added.resize(self.added.len() + gap as usize, 0);
        self.pieces.push(Piece {
            origin: Origin::Added,
            start: added_start,
            len: gap,
        });
        self.len = target;
    }

    /// Replace the logical range `[start, end)` with a new list of pieces, in a
    /// single pass.
    fn splice(&mut self, start: u64, end: u64, middle: Vec<Piece>) {
        let mut result = Vec::with_capacity(self.pieces.len() + middle.len() + 2);
        let mut middle = Some(middle);
        let mut cursor = 0u64;

        for piece in std::mem::take(&mut self.pieces) {
            let p_start = cursor;
            let p_end = cursor + piece.len;
            cursor = p_end;

            if p_start < start {
                let keep = piece.len.min(start - p_start);
                result.push(Piece {
                    origin: piece.origin,
                    start: piece.start,
                    len: keep,
                });
            }
            if p_end >= start {
                if let Some(m) = middle.take() {
                    result.extend(m);
                }
            }
            if p_end > end {
                let tail = p_end - end;
                result.push(Piece {
                    origin: piece.origin,
                    start: piece.start + (piece.len - tail),
                    len: tail,
                });
            }
        }
        if let Some(m) = middle.take() {
            result.extend(m);
        }
        self.pieces = result;
    }

    /// Materialize the whole logical content (for committing small/medium files).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.len as usize];
        self.read_at(FileOffset(0), &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf(data: &[u8]) -> EditBuffer {
        EditBuffer::new(Arc::new(MemSource::new(data.to_vec())))
    }

    #[test]
    fn read_matches_source() {
        let b = buf(b"hello world");
        let mut out = [0u8; 5];
        b.read_at(FileOffset(6), &mut out);
        assert_eq!(&out, b"world");
    }

    #[test]
    fn overwrite_in_place() {
        let mut b = buf(b"hello world");
        b.overwrite(FileOffset(0), b"HELLO");
        assert_eq!(b.to_vec(), b"HELLO world");
        assert_eq!(b.len(), 11);
    }

    #[test]
    fn insert_grows() {
        let mut b = buf(b"ac");
        b.insert(FileOffset(1), b"b");
        assert_eq!(b.to_vec(), b"abc");
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn delete_shrinks() {
        let mut b = buf(b"abcdef");
        b.delete(FileOffset(2), 2);
        assert_eq!(b.to_vec(), b"abef");
        assert_eq!(b.len(), 4);
    }

    #[test]
    fn undo_redo_roundtrip() {
        let mut b = buf(b"abc");
        b.overwrite(FileOffset(0), b"X");
        assert_eq!(b.to_vec(), b"Xbc");
        assert!(b.undo());
        assert_eq!(b.to_vec(), b"abc");
        assert!(b.redo());
        assert_eq!(b.to_vec(), b"Xbc");
    }

    #[test]
    fn overwrite_past_eof_extends() {
        let mut b = buf(b"ab");
        b.overwrite(FileOffset(3), b"Z");
        assert_eq!(b.len(), 4);
        assert_eq!(b.to_vec(), &[b'a', b'b', 0, b'Z']);
    }

    #[test]
    fn multiple_edits_and_full_undo() {
        let mut b = buf(b"0123456789");
        b.overwrite(FileOffset(0), b"AA");
        b.insert(FileOffset(2), b"__");
        b.delete(FileOffset(8), 2);
        let mid = b.to_vec();
        assert_eq!(mid, b"AA__234589".to_vec());
        while b.undo() {}
        assert_eq!(b.to_vec(), b"0123456789");
    }
}
