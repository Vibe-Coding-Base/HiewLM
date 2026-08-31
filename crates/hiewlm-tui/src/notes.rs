//! Analysis notes that survive the session — and the sample being renamed.
//!
//! Comments and bookmarks used to live only in memory: quit, and an hour of
//! annotation was gone. Colored markers were written next to the file, so
//! renaming `sample.exe` to `emotet_2026-08.exe` — the first thing anyone does —
//! orphaned them.
//!
//! Notes are therefore stored in a per-user directory keyed by the sample's
//! *content*, not its path. Rename it, move it, copy it to another machine's
//! share: the notes follow the bytes.

use crate::app::Marker;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Everything an analyst adds to a sample by hand.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Notes {
    /// The content key these notes belong to (also the file name in the store).
    #[serde(default)]
    pub key: String,
    /// The last path the sample was seen at — informational, never a lookup key.
    #[serde(default)]
    pub last_path: String,
    #[serde(default)]
    pub markers: Vec<Marker>,
    #[serde(default)]
    pub comments: Vec<(u64, String)>,
    #[serde(default)]
    pub bookmarks: Vec<(String, u64)>,
    /// `(slot number 1-8, offset)`.
    #[serde(default)]
    pub slots: Vec<(u8, u64)>,
}

impl Notes {
    pub fn is_empty(&self) -> bool {
        self.markers.is_empty()
            && self.comments.is_empty()
            && self.bookmarks.is_empty()
            && self.slots.is_empty()
    }

    /// A one-line summary for the status line after loading.
    pub fn summary(&self) -> String {
        format!(
            "{} comment(s), {} bookmark(s), {} marker(s), {} slot(s)",
            self.comments.len(),
            self.bookmarks.len(),
            self.markers.len(),
            self.slots.len()
        )
    }
}

/// Files up to this size are keyed by their real SHA-256. Above it, hashing
/// every open would cost more than the feature is worth, so a cheaper key is
/// derived from the size and the two ends of the file.
const FULL_HASH_LIMIT: u64 = 64 * 1024 * 1024;

/// The content key for a buffer: `sha256:<hex>`, or `part:<size>-<hex>` for
/// files too large to hash on every open. The prefixes keep the two key spaces
/// from ever colliding.
pub fn content_key(buf: &hiewlm_core::EditBuffer) -> String {
    use hiewlm_core::FileOffset;
    use sha2::{Digest, Sha256};

    let len = buf.len();
    let mut sha = Sha256::new();
    if len <= FULL_HASH_LIMIT {
        let mut chunk = vec![0u8; 64 * 1024];
        let mut off = 0u64;
        while off < len {
            let n = ((len - off) as usize).min(chunk.len());
            buf.read_at(FileOffset(off), &mut chunk[..n]);
            sha.update(&chunk[..n]);
            off += n as u64;
        }
        return format!("sha256:{:x}", sha.finalize());
    }

    // Head and tail: enough to separate samples in practice, and O(1) to read.
    const EDGE: u64 = 1024 * 1024;
    let mut edge = vec![0u8; EDGE as usize];
    buf.read_at(FileOffset(0), &mut edge);
    sha.update(&edge);
    buf.read_at(FileOffset(len - EDGE), &mut edge);
    sha.update(&edge);
    sha.update(len.to_le_bytes());
    format!("part:{len}-{:x}", sha.finalize())
}

/// `$XDG_DATA_HOME/hiewlm/notes`, else `~/.local/share/hiewlm/notes`, else
/// `%APPDATA%\hiewlm\notes`. Overridable with `$HIEWLM_NOTES_DIR`.
pub fn store_dir() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("HIEWLM_NOTES_DIR") {
        return Some(PathBuf::from(p));
    }
    default_store_dir()
}

#[cfg(not(test))]
fn default_store_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share")))
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))?;
    Some(base.join("hiewlm").join("notes"))
}

/// Under test, the store is always a per-process temp directory: a test run must
/// never write into the developer's real notes.
#[cfg(test)]
fn default_store_dir() -> Option<PathBuf> {
    Some(std::env::temp_dir().join(format!("hiewlm_notes_test_{}", std::process::id())))
}

/// The file a key's notes live in. The key is sanitized because it becomes a
/// path component.
fn notes_path(key: &str) -> Option<PathBuf> {
    let safe: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Some(store_dir()?.join(format!("{safe}.toml")))
}

pub fn load(key: &str) -> Option<Notes> {
    let path = notes_path(key)?;
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

/// Write the notes, or delete the file when nothing is left to remember.
pub fn save(notes: &Notes) -> Result<(), String> {
    let path = notes_path(&notes.key).ok_or("no data directory for notes")?;
    if notes.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let text = toml::to_string(notes).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiewlm_core::{EditBuffer, MemSource};
    use std::sync::Arc;

    fn buf(data: Vec<u8>) -> EditBuffer {
        EditBuffer::new(Arc::new(MemSource::new(data)))
    }

    #[test]
    fn key_follows_content_not_name() {
        let a = content_key(&buf(b"the same bytes".to_vec()));
        let b = content_key(&buf(b"the same bytes".to_vec()));
        let c = content_key(&buf(b"different bytes".to_vec()));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("sha256:"), "{a}");
    }

    #[test]
    fn round_trips_through_the_store() {
        let notes = Notes {
            key: "sha256:deadbeef".into(),
            last_path: "/samples/x.bin".into(),
            markers: vec![Marker {
                start: 1,
                end: 4,
                color: 2,
            }],
            comments: vec![(0x10, "decrypt loop".into())],
            bookmarks: vec![("config blob".into(), 0x200)],
            slots: vec![(1, 0x40)],
        };
        save(&notes).unwrap();
        let back = load("sha256:deadbeef").expect("notes come back");
        assert_eq!(back.comments, notes.comments);
        assert_eq!(back.bookmarks, notes.bookmarks);
        assert_eq!(back.slots, notes.slots);
        assert_eq!(back.markers.len(), 1);

        // Emptying the notes removes the file rather than leaving a husk.
        let empty = Notes {
            key: "sha256:deadbeef".into(),
            ..Default::default()
        };
        save(&empty).unwrap();
        assert!(load("sha256:deadbeef").is_none());
    }

    #[test]
    fn missing_notes_are_not_an_error() {
        assert!(load("sha256:a-key-nothing-was-ever-saved-under").is_none());
    }
}
