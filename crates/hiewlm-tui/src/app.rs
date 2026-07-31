//! Editor state and command handling — independent of rendering (design §5.3).

use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use hiewlm_asm::{Disassembler, Flow, Insn};
use hiewlm_core::{
    find, find_all, AddressSpace, Arch, Direction, EditBuffer, FileOffset, FileSource, Format,
    Pattern,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

/// A persistent colored region (HIEW `.cmarkers`).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Marker {
    pub start: u64,
    pub end: u64,
    pub color: u8,
}

#[derive(Default, Serialize, Deserialize)]
struct MarkerFile {
    markers: Vec<Marker>,
}

/// Bytes read per instruction when disassembling a window (x86 max instruction len).
const MAX_INSN_LEN: usize = 15;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Hex,
    Code,
    Text,
}

impl Mode {
    /// HIEW's cycle: Hex -> Code -> Text -> Hex (the Enter key).
    fn next(self) -> Self {
        match self {
            Mode::Hex => Mode::Code,
            Mode::Code => Mode::Text,
            Mode::Text => Mode::Hex,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Mode::Hex => "hex",
            Mode::Code => "code",
            Mode::Text => "text",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddrMode {
    Offset,
    Va,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EditCol {
    Hex,
    Ascii,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SearchKind {
    Hex,
    Text,
    /// UTF-16LE text — HIEW's "Unicode" search, matching wide strings.
    Utf16,
    /// Assemble the typed instruction and search for its encoding.
    Asm,
}

impl SearchKind {
    pub fn label(self) -> &'static str {
        match self {
            SearchKind::Hex => "hex",
            SearchKind::Text => "text",
            SearchKind::Utf16 => "utf-16",
            SearchKind::Asm => "asm",
        }
    }

    /// Tab cycles through the kinds.
    pub fn next(self) -> Self {
        match self {
            SearchKind::Hex => SearchKind::Text,
            SearchKind::Text => SearchKind::Utf16,
            SearchKind::Utf16 => SearchKind::Asm,
            SearchKind::Asm => SearchKind::Hex,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeaderPane {
    Info,
    Sections,
    Imports,
    Exports,
    Resources,
}

impl HeaderPane {
    fn next(self) -> Self {
        match self {
            HeaderPane::Info => HeaderPane::Sections,
            HeaderPane::Sections => HeaderPane::Imports,
            HeaderPane::Imports => HeaderPane::Exports,
            HeaderPane::Exports => HeaderPane::Resources,
            HeaderPane::Resources => HeaderPane::Info,
        }
    }

    fn prev(self) -> Self {
        self.next().next().next().next()
    }

    pub fn label(self) -> &'static str {
        match self {
            HeaderPane::Info => "Info",
            HeaderPane::Sections => "Sections",
            HeaderPane::Imports => "Imports",
            HeaderPane::Exports => "Exports",
            HeaderPane::Resources => "Resources",
        }
    }
}

/// What to do with the file chosen in a [`Dialog::FilePicker`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PickPurpose {
    Diff,
    StructTemplate,
    /// Insert the chosen file's bytes at the cursor (HIEW Ctrl+F2).
    ReadFile,
}

/// One entry in the file picker.
#[derive(Clone, Debug)]
pub struct PickEntry {
    pub name: String,
    pub is_dir: bool,
}

pub enum Dialog {
    Goto { input: String },
    Search { input: String, kind: SearchKind },
    Replace { input: String, kind: SearchKind },
    Calc { input: String },
    /// Assemble-at-cursor: type an instruction, see the encoding, Enter patches.
    Assemble { input: String },
    ModeMenu { selected: usize },
    DisasmMenu { selected: usize },
    ColorMenu { selected: usize },
    BlockMenu { selected: usize },
    BlockWrite { input: String },
    BlockFill { input: String },
    /// Crypt engine: XOR/ADD/ROL/… recipe applied to the selected block.
    Crypt { input: String },
    /// Waiting for a digit 1-8 naming the slot to store the cursor in.
    BookmarkSlot,
    Header { pane: HeaderPane, sel: usize, filter: String },
    /// Scrollable read-only text (help, inspector, hashes).
    Comment { input: String },
    NameBookmark { input: String },
    /// An interactive directory browser used to pick an existing file.
    FilePicker {
        dir: PathBuf,
        entries: Vec<PickEntry>,
        sel: usize,
        purpose: PickPurpose,
    },
    /// A selectable list of labelled offsets to jump to (names, xrefs, …).
    JumpList { title: String, items: Vec<(String, u64)>, sel: usize },
    /// Multi-file search results; Enter opens the file at the match.
    FileHits { title: String, items: Vec<(String, PathBuf, u64)>, sel: usize },
    Message { title: String, body: String, scroll: usize },
}

pub struct App {
    pub path: PathBuf,
    pub buffer: EditBuffer,
    pub mode: Mode,
    pub addr_mode: AddrMode,
    pub address_space: AddressSpace,
    pub format: Format,
    pub arch: Arch,
    pub bits: u8,
    /// Architecture/bitness actually used for disassembly (may override `arch`/`bits`).
    pub disasm_arch: Arch,
    pub disasm_bits: u8,
    pub disasm_override: bool,
    pub entry: Option<u64>,
    pub imports: Vec<(String, u64)>,
    pub exports: Vec<(String, u64)>,
    pub header_fields: Vec<(String, String)>,
    pub resources: Vec<hiewlm_core::Resource>,
    /// Parsed container structure (ZIP/PDF), when a container plugin claimed
    /// the file. Members are listed by F12 instead of recovered functions.
    pub container: Option<hiewlm_core::Container>,
    /// Cached entropy (computed lazily when the header opens).
    file_entropy: Option<f32>,
    section_entropy: Vec<f32>,
    imphash: Option<String>,
    packer: Option<String>,
    /// Filesystem modification time (a "when" field for formats without a
    /// compile timestamp, e.g. Mach-O/ELF).
    file_mtime: Option<String>,
    pub cursor: u64,
    /// File offset of the first instruction shown in Code mode.
    pub code_top: u64,
    /// Return stack for follow-branch (BkSp goes back).
    nav_stack: Vec<u64>,
    /// Browsable history of jump origins (most recent last).
    history: Vec<u64>,
    /// Persistent colored block markers (loaded from / saved to a sidecar file).
    markers: Vec<Marker>,
    pub top: u64,
    pub bytes_per_row: usize,
    pub text_cols: usize,
    pub visible_rows: usize,
    /// Selection anchor. When `Some`, the block spans anchor..=cursor and extends
    /// as the cursor moves (HIEW `*`).
    pub mark: Option<u64>,
    pub editing: bool,
    pub edit_col: EditCol,
    pub nibble: u8,
    pub insert_mode: bool,
    pub read_only: bool,
    pub dialog: Option<Dialog>,
    pub status: String,
    pub should_quit: bool,
    last_pattern: Option<(Pattern, Direction)>,
    /// Pattern whose matches are highlighted in the view; cleared with Esc.
    highlight: Option<Pattern>,
    /// Bytes copied from a block (yank), pasted at the cursor.
    clipboard: Vec<u8>,
    /// Bookmark stack (HIEW `+` push / `-` pop) of file offsets.
    bookmarks: Vec<u64>,
    /// Numbered bookmark slots 1-8 (HIEW `Alt+1..8` to jump, `K`+digit to set).
    slots: [Option<u64>; 8],
    /// When set, searches are confined to this byte range (a marked block).
    search_scope: Option<(u64, u64)>,
    /// Named bookmarks (unlimited), listed and jumpable via F12.
    named_bookmarks: Vec<(String, u64)>,
    /// User comments keyed by file offset (shown inline in Code mode).
    comments: BTreeMap<u64, String>,
    /// Keys captured while recording a macro (`Some` = recording).
    macro_rec: Option<Vec<KeyEvent>>,
    /// The last saved macro, replayed on demand.
    macro_saved: Vec<KeyEvent>,
    /// True while replaying, so replayed keys aren't re-recorded.
    replaying: bool,
    /// Set when a search finds nothing; a looping macro stops on it (HIEW).
    macro_search_failed: bool,
    /// The other file for byte comparison (diff highlighting).
    diff_buf: Option<EditBuffer>,
    /// Render the diff as two side-by-side panes instead of inline highlighting.
    pub split_view: bool,
    pub diff_name: String,
    pub theme_kind: crate::theme::ThemeKind,
    pub encoding: crate::encoding::Encoding,
}

impl App {
    pub fn open(path: PathBuf) -> Result<Self> {
        let source = FileSource::open(&path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        let buffer = EditBuffer::new(Arc::new(source));

        let file_mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| hiewlm_core::format_unix(d.as_secs() as i64));

        let markers = load_markers(&path);

        // Config file overrides; otherwise auto-detect the text encoding.
        let cfg = crate::config::Config::load();
        let theme_kind = cfg.theme_kind().unwrap_or(crate::theme::ThemeKind::Classic);
        let bytes_per_row = cfg.bytes_per_row.filter(|&n| (4..=64).contains(&n)).unwrap_or(16);
        let encoding = cfg.encoding().unwrap_or_else(|| {
            let mut sample = vec![0u8; buffer.len().min(4096) as usize];
            buffer.read_at(FileOffset(0), &mut sample);
            crate::encoding::Encoding::detect(&sample)
        });

        let model = hiewlm_fmt::detect(&buffer);
        let (format, arch, bits, address_space, entry, imports, exports, header_fields, resources) =
            match model {
                Some(m) => {
                    let imports = m.imports.into_iter().map(|s| (s.name, s.va)).collect();
                    let exports = m.exports.into_iter().map(|s| (s.name, s.va)).collect();
                    (
                        m.format,
                        m.arch,
                        m.bits,
                        m.address_space,
                        m.entry,
                        imports,
                        exports,
                        m.header_fields,
                        m.resources,
                    )
                }
                None => (
                    Format::Raw,
                    Arch::X86_64,
                    64,
                    AddressSpace::flat(),
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            };
        // Container plugins get a look at anything the executable parsers did
        // not claim. They only read bytes — nothing is decompressed or run.
        let container = if format == Format::Raw {
            let mut reg = hiewlm_core::ContainerRegistry::new();
            reg.register(Box::new(hiewlm_plugin_zip::ZipPlugin));
            reg.register(Box::new(hiewlm_plugin_pdf::PdfPlugin));
            reg.enable(&cfg.plugins());
            let cap = buffer.len().min(256 * 1024 * 1024) as usize;
            let mut data = vec![0u8; cap];
            buffer.read_at(FileOffset(0), &mut data);
            reg.parse(&data).map(|(_, c)| c)
        } else {
            None
        };

        let ready = match &container {
            Some(c) => format!(
                "{}  ·  {} member(s){}  ·  1/? help · F12 members · q quit",
                c.kind,
                c.members.len(),
                match c.suspicious().count() {
                    0 => String::new(),
                    n => format!("  ·  {n} SUSPICIOUS"),
                }
            ),
            None => format!(
                "{} {}  ·  1/? help · e edit · g goto · / find · q quit",
                format.label(),
                arch.label()
            ),
        };

        Ok(Self {
            path,
            buffer,
            mode: Mode::Hex,
            addr_mode: AddrMode::Offset,
            address_space,
            format,
            arch,
            bits,
            disasm_arch: arch,
            disasm_bits: bits,
            disasm_override: false,
            entry,
            imports,
            exports,
            header_fields,
            resources,
            container,
            file_entropy: None,
            section_entropy: Vec::new(),
            imphash: None,
            packer: None,
            file_mtime,
            cursor: 0,
            code_top: 0,
            nav_stack: Vec::new(),
            history: Vec::new(),
            markers,
            top: 0,
            bytes_per_row,
            text_cols: 16,
            visible_rows: 1,
            mark: None,
            editing: false,
            edit_col: EditCol::Hex,
            nibble: 0,
            insert_mode: false,
            read_only: true,
            dialog: None,
            status: ready,
            should_quit: false,
            last_pattern: None,
            highlight: None,
            clipboard: Vec::new(),
            bookmarks: Vec::new(),
            slots: [None; 8],
            search_scope: None,
            named_bookmarks: Vec::new(),
            comments: BTreeMap::new(),
            macro_rec: None,
            macro_saved: Vec::new(),
            replaying: false,
            macro_search_failed: false,
            diff_buf: None,
            split_view: false,
            diff_name: String::new(),
            theme_kind,
            encoding,
        })
    }

    pub fn max_offset(&self) -> u64 {
        self.buffer.len().saturating_sub(1)
    }

    /// Bytes per visual row for the current mode: 16 for Hex/Code, the content
    /// width for Text.
    pub fn stride(&self) -> u64 {
        match self.mode {
            Mode::Text => self.text_cols.max(1) as u64,
            _ => self.bytes_per_row as u64,
        }
    }

    fn page_bytes(&self) -> u64 {
        self.visible_rows.max(1) as u64 * self.stride()
    }

    /// The current selection as an inclusive `(start, end)` range, if a block is
    /// marked.
    pub fn selection(&self) -> Option<(u64, u64)> {
        self.mark.map(|m| (m.min(self.cursor), m.max(self.cursor)))
    }

    fn set_mark(&mut self) {
        if self.mark.is_none() {
            self.mark = Some(self.cursor);
        }
    }

    /// Read the selected bytes, or `None` if no block is marked.
    fn read_selection(&self) -> Option<Vec<u8>> {
        let (s, e) = self.selection()?;
        let len = (e - s + 1) as usize;
        let mut buf = vec![0u8; len];
        self.buffer.read_at(FileOffset(s), &mut buf);
        Some(buf)
    }

    fn require_selection(&mut self) -> Option<(u64, u64)> {
        let sel = self.selection();
        if sel.is_none() {
            self.set_status("Select a block first (press * then move).");
        }
        sel
    }

    fn block_yank(&mut self) {
        if let Some(bytes) = self.read_selection() {
            let n = bytes.len();
            self.clipboard = bytes;
            self.set_status(format!("Yanked {n} bytes (p to paste)."));
        } else {
            self.require_selection();
        }
    }

    fn block_paste(&mut self) {
        if self.clipboard.is_empty() {
            self.set_status("Clipboard is empty (y to yank a block first).");
            return;
        }
        let bytes = self.clipboard.clone();
        let n = bytes.len();
        if self.insert_mode {
            self.buffer.insert(FileOffset(self.cursor), &bytes);
        } else {
            self.buffer.overwrite(FileOffset(self.cursor), &bytes);
        }
        self.set_status(format!("Pasted {n} bytes ({} mode).", if self.insert_mode { "insert" } else { "overwrite" }));
    }

    fn block_delete(&mut self) {
        let Some((s, e)) = self.require_selection() else {
            return;
        };
        let len = e - s + 1;
        self.clipboard = self.read_selection().unwrap_or_default();
        self.buffer.delete(FileOffset(s), len);
        self.mark = None;
        self.cursor = s.min(self.max_offset());
        self.ensure_visible();
        self.set_status(format!("Deleted {len} bytes (kept in clipboard)."));
    }

    fn confirm_crypt(&mut self, input: &str) {
        match hiewlm_core::crypt::parse(input) {
            Ok(recipe) => {
                self.apply_crypt(&recipe);
                self.dialog = None;
            }
            Err(e) => {
                self.set_status(format!("Crypt: {e}"));
                self.dialog = Some(Dialog::Crypt { input: input.to_string() });
            }
        }
    }

    /// Transform the selected block in place with a crypt recipe. The key index
    /// is block-relative, so a repeating key lines up with the block start.
    fn apply_crypt(&mut self, recipe: &hiewlm_core::crypt::Recipe) {
        let Some((s, e)) = self.require_selection() else {
            return;
        };
        let len = (e - s + 1) as usize;
        let mut data = vec![0u8; len];
        self.buffer.read_at(FileOffset(s), &mut data);
        recipe.apply(&mut data, 0);
        self.buffer.overwrite(FileOffset(s), &data);
        self.read_only = false;
        let undo = if recipe.inverse().is_some() {
            " (reversible: re-apply the inverse, or Ctrl+Z)"
        } else {
            " (lossy: and/or cannot be undone except with Ctrl+Z)"
        };
        self.set_status(format!("Crypt applied to {len} bytes{undo}"));
    }

    /// Copy (or move) the marked block so it starts at the bookmark pushed with
    /// `+`, mirroring HIEW's Shift+F5/Shift+F6, which copy/move a block to a
    /// previously marked destination.
    ///
    /// A move deletes the source first, so the destination is rebased when it
    /// sits after the block — otherwise the bytes would land in the wrong place.
    fn block_copy_or_move(&mut self, is_move: bool) {
        let Some((s, e)) = self.require_selection() else {
            return;
        };
        let Some(&dest) = self.bookmarks.last() else {
            self.set_status("Set a destination first: move the cursor there and press +.");
            return;
        };
        let len = e - s + 1;
        if is_move && dest > s && dest <= e {
            self.set_status("Cannot move a block into itself.");
            return;
        }
        let mut data = vec![0u8; len as usize];
        self.buffer.read_at(FileOffset(s), &mut data);

        let insert_at = if is_move {
            self.buffer.delete(FileOffset(s), len);
            // Everything after the removed block shifts down by `len`.
            if dest > e {
                dest - len
            } else {
                dest
            }
        } else {
            dest
        };
        self.buffer.insert(FileOffset(insert_at), &data);
        self.read_only = false;
        self.mark = None;
        self.cursor = insert_at;
        self.set_status(format!(
            "{} {len} bytes to {}",
            if is_move { "Moved" } else { "Copied" },
            self.display_addr(insert_at)
        ));
    }

    /// Insert the clipboard (or a zero run) at the cursor, growing the file
    /// (HIEW Shift+F3).
    fn block_insert(&mut self) {
        let bytes = if self.clipboard.is_empty() {
            vec![0u8; 1]
        } else {
            self.clipboard.clone()
        };
        let at = self.cursor;
        self.buffer.insert(FileOffset(at), &bytes);
        self.read_only = false;
        self.set_status(format!(
            "Inserted {} byte(s) at {}{}",
            bytes.len(),
            self.display_addr(at),
            if self.clipboard.is_empty() { " (zero; yank with y to insert data)" } else { "" }
        ));
    }

    /// Insert a file's contents at the cursor (HIEW Ctrl+F2).
    fn read_file_into_buffer(&mut self, path: &std::path::Path) {
        match std::fs::read(path) {
            Ok(data) if data.is_empty() => self.set_status(format!("{} is empty.", path.display())),
            Ok(data) => {
                let at = self.cursor;
                self.buffer.insert(FileOffset(at), &data);
                self.read_only = false;
                self.set_status(format!(
                    "Inserted {} bytes from {} at {}",
                    data.len(),
                    path.display(),
                    self.display_addr(at)
                ));
            }
            Err(e) => self.set_status(format!("Cannot read {}: {e}", path.display())),
        }
    }

    fn block_fill(&mut self, pattern: &[u8]) {
        let Some((s, e)) = self.require_selection() else {
            return;
        };
        if pattern.is_empty() {
            self.set_status("Empty fill pattern.");
            return;
        }
        let len = (e - s + 1) as usize;
        let filled: Vec<u8> = pattern.iter().copied().cycle().take(len).collect();
        self.buffer.overwrite(FileOffset(s), &filled);
        self.set_status(format!("Filled {len} bytes."));
    }

    fn block_write_file(&mut self, path: &str) {
        let Some(bytes) = self.read_selection() else {
            self.require_selection();
            self.dialog = None;
            return;
        };
        let n = bytes.len();
        match std::fs::write(path, &bytes) {
            Ok(()) => self.set_status(format!("Wrote {n} bytes to {path}.")),
            Err(e) => self.set_status(format!("Write failed: {e}")),
        }
        self.dialog = None;
    }

    fn confirm_block_fill(&mut self, input: &str) {
        match parse_hex_bytes(input) {
            Some(pattern) => self.block_fill(&pattern),
            None => self.set_status("Invalid fill pattern (hex bytes, e.g. 90 or 00 ff)."),
        }
        self.dialog = None;
    }

    // -- Header view -------------------------------------------------

    /// Shannon entropy (0..8) of `[start, start+len)`, sampled to stay bounded.
    fn range_entropy(&self, start: u64, len: u64) -> f32 {
        if len == 0 {
            return 0.0;
        }
        let cap = len.min(8 * 1024 * 1024);
        let mut freq = [0u64; 256];
        let mut off = start;
        let mut remaining = cap;
        let mut chunk = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let n = (remaining as usize).min(chunk.len());
            self.buffer.read_at(FileOffset(off), &mut chunk[..n]);
            for &b in &chunk[..n] {
                freq[b as usize] += 1;
            }
            off += n as u64;
            remaining -= n as u64;
        }
        let total = cap as f64;
        let mut h = 0.0f64;
        for &c in &freq {
            if c > 0 {
                let p = c as f64 / total;
                h -= p * p.log2();
            }
        }
        h as f32
    }

    /// Compute file + per-section entropy and the import hash once (cached).
    fn ensure_entropy(&mut self) {
        if self.file_entropy.is_some() {
            return;
        }
        self.file_entropy = Some(self.range_entropy(0, self.buffer.len()));
        let secs: Vec<(u64, u64)> =
            self.address_space.sections().iter().map(|s| (s.file_off, s.size)).collect();
        self.section_entropy = secs.iter().map(|&(o, l)| self.range_entropy(o, l)).collect();
        if self.format == Format::Pe && !self.imports.is_empty() {
            self.imphash = Some(self.compute_imphash());
        }
        self.packer = self.detect_packer();
    }

    /// Packer/protector verdict from entry-point bytes, section entropy, imports.
    fn detect_packer(&self) -> Option<String> {
        if self.format == Format::Raw {
            return None;
        }
        let entry_off = self.entry.and_then(|va| self.va_to_off(va)).unwrap_or(0);
        let mut entry = vec![0u8; 32.min(self.buffer.len().saturating_sub(entry_off) as usize)];
        self.buffer.read_at(FileOffset(entry_off), &mut entry);
        let sections: Vec<hiewlm_core::packer::SectionInfo> = self
            .address_space
            .sections()
            .iter()
            .enumerate()
            .map(|(i, s)| hiewlm_core::packer::SectionInfo {
                name: s.name.clone(),
                entropy: self.section_entropy.get(i).copied().unwrap_or(0.0),
            })
            .collect();
        let r = hiewlm_core::packer::detect(&entry, &sections, self.imports.len());
        (!r.indicators.is_empty() || r.name.is_some()).then(|| r.summary())
    }

    /// The industry-standard PE import hash (MD5 of normalized "dll.func" list).
    fn compute_imphash(&self) -> String {
        use md5::Digest;
        let parts: Vec<String> = self
            .imports
            .iter()
            .map(|(name, _)| {
                let (dll, func) = name.split_once('!').unwrap_or(("", name.as_str()));
                let mut dll = dll.to_lowercase();
                for ext in [".dll", ".sys", ".ocx", ".exe"] {
                    if let Some(s) = dll.strip_suffix(ext) {
                        dll = s.to_string();
                        break;
                    }
                }
                format!("{dll}.{}", func.to_lowercase())
            })
            .collect();
        hex_bytes(&md5::Md5::digest(parts.join(",").as_bytes()))
    }

    /// Entries for a header pane after applying `filter`: label + optional jump
    /// offset. Info fields are view-only (no offset); the rest are jumpable.
    pub fn header_entries(&self, pane: HeaderPane, filter: &str) -> Vec<(String, Option<u64>)> {
        let jump = |va: u64| (va != 0).then(|| self.va_to_off(va).unwrap_or(va));
        let raw: Vec<(String, Option<u64>)> = match pane {
            HeaderPane::Info => {
                let mut v = Vec::new();
                // A plugin-parsed container has no arch/bits; show its structure
                // and findings instead of an empty executable header.
                if let Some(c) = &self.container {
                    v.push((format!("{:<18} {}", "Container", c.kind), None));
                    for (k, val) in &c.summary {
                        v.push((format!("{k:<18} {val}"), None));
                    }
                    for f in &c.findings {
                        v.push((format!("{:<18} [{}] {}", "", f.severity, f.message), f.offset));
                    }
                    return apply_header_filter(v, filter);
                }
                v.push((
                    format!("{:<18} {} / {} / {}-bit", "Format", self.format.label(), self.arch.label(), self.bits),
                    None,
                ));
                if let Some(t) = &self.file_mtime {
                    // Filesystem metadata, NOT a header value and NOT compile time.
                    v.push((format!("{:<18} {t}", "File mtime (fs)"), None));
                }
                if let Some(e) = self.file_entropy {
                    v.push((format!("{:<18} {e:.3} / 8.0", "File entropy"), None));
                }
                if let Some(h) = &self.imphash {
                    v.push((format!("{:<18} {h}", "ImpHash"), None));
                }
                if let Some(p) = &self.packer {
                    v.push((format!("{:<18} {p}", "Packer"), None));
                }
                if let Some(va) = self.entry {
                    v.push((
                        format!("{:<18} .{va:08X}   [Enter jumps]", "Entry point"),
                        (va != 0).then(|| self.va_to_off(va).unwrap_or(va)),
                    ));
                }
                for (k, val) in &self.header_fields {
                    v.extend(wrap_field(k, val));
                }
                v
            }
            HeaderPane::Sections => self
                .address_space
                .sections()
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let ent = self.section_entropy.get(i).copied().unwrap_or(0.0);
                    (
                        format!("{:<12} off:{:08X} va:.{:08X} size:{:>8X} ent:{:.2}", s.name, s.file_off, s.va, s.size, ent),
                        Some(s.file_off),
                    )
                })
                .collect(),
            HeaderPane::Imports => self
                .imports
                .iter()
                .map(|(n, va)| (fmt_sym(n, *va), jump(*va)))
                .collect(),
            HeaderPane::Exports => self
                .exports
                .iter()
                .map(|(n, va)| (fmt_sym(n, *va), jump(*va)))
                .collect(),
            HeaderPane::Resources => self
                .resources
                .iter()
                .map(|r| (resource_label(r), Some(r.file_off)))
                .collect(),
        };
        apply_header_filter(raw, filter)
    }

    fn header_activate(&mut self, pane: HeaderPane, sel: usize, filter: &str) {
        if pane == HeaderPane::Resources {
            let needle = filter.to_lowercase();
            let chosen = self
                .resources
                .iter()
                .filter(|r| filter.is_empty() || resource_label(r).to_lowercase().contains(&needle))
                .nth(sel)
                .cloned();
            if let Some(r) = chosen {
                self.extract_resource(&r);
            }
            return;
        }
        let entries = self.header_entries(pane, filter);
        match entries.get(sel) {
            Some((label, Some(off))) => {
                let off = *off;
                let label = label.clone();
                self.goto_offset(off);
                self.set_status(format!("→ {}  {}", self.display_addr(off), label));
            }
            Some((_, None)) => self.set_status("This field is not a jump target."),
            None => {}
        }
    }

    // -- Block hashes ------------------------------------------------

    fn open_hashes(&mut self) {
        use md5::Digest;
        if self.buffer.is_empty() {
            self.set_status("Empty file — nothing to hash.");
            return;
        }
        let (start, end) = self.selection().unwrap_or((0, self.buffer.len() - 1));
        let len = end - start + 1;

        let mut crc = crc32fast::Hasher::new();
        let mut md5 = md5::Md5::new();
        let mut sha = sha2::Sha256::new();
        let mut blake = blake3::Hasher::new();

        let mut off = start;
        let mut remaining = len;
        let mut chunk = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let n = (remaining as usize).min(chunk.len());
            self.buffer.read_at(FileOffset(off), &mut chunk[..n]);
            crc.update(&chunk[..n]);
            md5.update(&chunk[..n]);
            sha.update(&chunk[..n]);
            blake.update(&chunk[..n]);
            off += n as u64;
            remaining -= n as u64;
        }

        let scope = if self.selection().is_some() { "selection" } else { "whole file" };
        let body = format!(
            "range   {:#x}..{:#x}  ({len} bytes, {scope})\n\
             \n\
             CRC32   {:08X}\n\
             MD5     {}\n\
             SHA-256 {}\n\
             BLAKE3  {}",
            start,
            end,
            crc.finalize(),
            hex_bytes(&md5.finalize()),
            hex_bytes(&sha.finalize()),
            blake.finalize().to_hex(),
        );
        self.dialog = Some(Dialog::Message { title: "Hashes".into(), body, scroll: 0 });
    }

    // -- Multi-file search -------------------------------------------

    /// Reopen a different file in place, preserving view preferences.
    fn reload(&mut self, path: PathBuf, cursor: u64) {
        match App::open(path) {
            Ok(mut new) => {
                new.theme_kind = self.theme_kind;
                new.encoding = self.encoding;
                new.macro_saved = std::mem::take(&mut self.macro_saved);
                *self = new;
                self.move_to(cursor);
            }
            Err(e) => self.set_status(format!("Cannot open: {e}")),
        }
    }

    fn open_replace(&mut self) {
        let Some((pat, _)) = &self.last_pattern else {
            self.set_status("Search first (/) to set the pattern, then X to replace.");
            return;
        };
        if pat.literal_bytes().is_none() {
            self.set_status("Replace needs a non-wildcard pattern.");
            return;
        }
        self.dialog = Some(Dialog::Replace { input: String::new(), kind: SearchKind::Hex });
    }

    fn confirm_replace(&mut self, input: &str, kind: SearchKind) {
        self.dialog = None;
        let Some((pat, _)) = &self.last_pattern else {
            return;
        };
        let Some(needle) = pat.literal_bytes().map(|b| b.to_vec()) else {
            self.set_status("Replace needs a non-wildcard pattern.");
            return;
        };
        let repl = match kind {
            SearchKind::Text => input.as_bytes().to_vec(),
            SearchKind::Utf16 => input.encode_utf16().flat_map(|u| u.to_le_bytes()).collect(),
            SearchKind::Asm => {
                self.set_status("Replace does not support instruction search.");
                return;
            }
            SearchKind::Hex => match parse_hex_bytes(input) {
                Some(b) => b,
                None => {
                    self.set_status("Invalid hex replacement.");
                    return;
                }
            },
        };
        self.multi_file_replace(&needle, &repl);
    }

    /// Replace every occurrence of `needle` with `repl` in every file under the
    /// current directory (recursive, budgeted). Each modified file gets a `.bak`.
    fn multi_file_replace(&mut self, needle: &[u8], repl: &[u8]) {
        if needle.is_empty() {
            return;
        }
        let root = self.path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
        let mut files = 0usize;
        let mut total = 0usize;
        let mut budget = 3000usize;
        let mut stack = vec![root];

        while let Some(dir) = stack.pop() {
            if budget == 0 {
                break;
            }
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            for entry in rd.flatten() {
                let path = entry.path();
                let Ok(ft) = entry.file_type() else { continue };
                if ft.is_dir() {
                    stack.push(path);
                } else if ft.is_file() {
                    if budget == 0 {
                        break;
                    }
                    budget -= 1;
                    if entry.metadata().map(|m| m.len() > 64 * 1024 * 1024).unwrap_or(true) {
                        continue;
                    }
                    let Ok(data) = fs::read(&path) else { continue };
                    let (new, count) = replace_all(&data, needle, repl);
                    if count > 0 {
                        let bak = path.with_extension(format!(
                            "{}.bak",
                            path.extension().and_then(|e| e.to_str()).unwrap_or("")
                        ));
                        let _ = fs::copy(&path, &bak);
                        if fs::write(&path, &new).is_ok() {
                            files += 1;
                            total += count;
                        }
                    }
                }
            }
        }
        if files == 0 {
            self.set_status("No occurrences found to replace.");
        } else {
            self.set_status(format!("Replaced {total} occurrence(s) in {files} file(s); .bak saved."));
            // The current file may have changed on disk; reload it.
            let path = self.path.clone();
            let cur = self.cursor;
            self.reload(path, cur);
        }
    }

    /// Search the last pattern across every file under the current directory
    /// (recursively, budgeted). Lists the first match per file.
    fn multi_search(&mut self) {
        let Some((pattern, _)) = self.last_pattern.clone() else {
            self.set_status("Search first (/), then x to search all files in the folder.");
            return;
        };
        let root = self.path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
        let mut hits: Vec<(String, PathBuf, u64)> = Vec::new();
        let mut file_budget = 3000usize;
        let mut stack = vec![root.clone()];

        while let Some(dir) = stack.pop() {
            if file_budget == 0 || hits.len() >= 500 {
                break;
            }
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            for entry in rd.flatten() {
                let path = entry.path();
                let Ok(ft) = entry.file_type() else { continue };
                if ft.is_dir() {
                    stack.push(path);
                } else if ft.is_file() {
                    if file_budget == 0 {
                        break;
                    }
                    file_budget -= 1;
                    if entry.metadata().map(|m| m.len() > 64 * 1024 * 1024).unwrap_or(true) {
                        continue;
                    }
                    if let Ok(src) = FileSource::open(&path) {
                        let buf = EditBuffer::new(Arc::new(src));
                        if let Some(hit) = find(&buf, &pattern, FileOffset(0), Direction::Forward) {
                            let name = path.strip_prefix(&root).unwrap_or(&path).to_string_lossy().into_owned();
                            hits.push((format!("{name}  @ {:08X}", hit.get()), path.clone(), hit.get()));
                        }
                    }
                }
            }
        }

        if hits.is_empty() {
            self.set_status("No files matched.");
            return;
        }
        self.dialog = Some(Dialog::FileHits {
            title: format!("Matches in {} ({})", root.display(), hits.len()),
            items: hits,
            sel: 0,
        });
    }

    // -- Data inspector ----------------------------------------------

    /// Values the calculator reads at the cursor (`@o`, `@b`, `@w`, `@d`, `@q`).
    pub fn calc_ctx(&self) -> hiewlm_core::calc::Ctx {
        let mut b = [0u8; 8];
        self.buffer.read_at(FileOffset(self.cursor), &mut b);
        hiewlm_core::calc::Ctx {
            offset: self.cursor,
            b: b[0] as u64,
            w: u16::from_le_bytes([b[0], b[1]]) as u64,
            d: u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64,
            q: u64::from_le_bytes(b),
        }
    }

    fn open_inspector(&mut self) {
        let mut b = [0u8; 8];
        self.buffer.read_at(FileOffset(self.cursor), &mut b);
        let u16le = u16::from_le_bytes([b[0], b[1]]);
        let u16be = u16::from_be_bytes([b[0], b[1]]);
        let u32le = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let u32be = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let u64le = u64::from_le_bytes(b);
        let u64be = u64::from_be_bytes(b);
        let body = format!(
            "bytes   {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}\n\
             \n\
             int8    {}  uint8 {}\n\
             int16   {} LE   {} BE\n\
             uint16  {} LE   {} BE\n\
             int32   {} LE   {} BE\n\
             uint32  {} LE   {} BE\n\
             int64   {} LE\n\
             uint64  {} LE   {} BE\n\
             float32 {} LE\n\
             float64 {} LE\n\
             time_t  {} (unix seconds, LE u32)",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[0] as i8, b[0],
            i16::from_le_bytes([b[0], b[1]]), i16::from_be_bytes([b[0], b[1]]),
            u16le, u16be,
            u32le as i32, u32be as i32,
            u32le, u32be,
            u64le as i64,
            u64le, u64be,
            f32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            f64::from_le_bytes(b),
            u32le,
        );
        self.dialog = Some(Dialog::Message {
            title: format!("Inspect @ {}", self.display_addr(self.cursor)),
            body,
            scroll: 0,
        });
    }

    // -- File picker -------------------------------------------------

    fn list_dir(dir: &std::path::Path) -> Vec<PickEntry> {
        let mut entries = vec![PickEntry { name: "..".into(), is_dir: true }];
        if let Ok(rd) = fs::read_dir(dir) {
            let mut items: Vec<PickEntry> = rd
                .flatten()
                .map(|e| PickEntry {
                    name: e.file_name().to_string_lossy().into_owned(),
                    is_dir: e.file_type().map(|t| t.is_dir()).unwrap_or(false),
                })
                .collect();
            // Directories first, then files; each group alphabetical.
            items.sort_by(|a, b| {
                b.is_dir
                    .cmp(&a.is_dir)
                    .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });
            entries.extend(items);
        }
        entries
    }

    fn open_file_picker(&mut self, purpose: PickPurpose) {
        // Start in the directory of the current file (fallback: cwd).
        let dir = self
            .path
            .parent()
            .map(|p| p.to_path_buf())
            .filter(|p| !p.as_os_str().is_empty())
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let entries = Self::list_dir(&dir);
        self.dialog = Some(Dialog::FilePicker { dir, entries, sel: 0, purpose });
    }

    fn picker_pick(&mut self, purpose: PickPurpose, path: &str) {
        self.dialog = None;
        match purpose {
            PickPurpose::Diff => self.open_diff(path),
            PickPurpose::StructTemplate => self.open_struct(path),
            PickPurpose::ReadFile => self.read_file_into_buffer(std::path::Path::new(path)),
        }
    }

    // -- Binary diff -------------------------------------------------

    pub fn has_diff(&self) -> bool {
        self.diff_buf.is_some()
    }

    fn open_diff(&mut self, path: &str) {
        match FileSource::open(path) {
            Ok(src) => {
                let other = EditBuffer::new(Arc::new(src));
                self.diff_name = std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path)
                    .to_string();
                self.diff_buf = Some(other);
                let n = self.diff_count();
                self.set_status(format!(
                    "Diff vs {}: {n} differing bytes · > / < next/prev · Esc clears",
                    self.diff_name
                ));
            }
            Err(e) => self.set_status(format!("Cannot open {path}: {e}")),
        }
        self.dialog = None;
    }

    /// Bytes from the diff buffer, for the right-hand pane of the split view.
    /// Positions past its end are reported as absent rather than zero-filled.
    pub fn diff_bytes(&self, off: u64, len: usize) -> Vec<Option<u8>> {
        let Some(other) = &self.diff_buf else {
            return vec![None; len];
        };
        (0..len as u64)
            .map(|i| {
                let at = off + i;
                (at < other.len()).then(|| other.read_byte(FileOffset(at)))
            })
            .collect()
    }

    pub fn diff_label(&self) -> &str {
        &self.diff_name
    }

    pub fn diff_len(&self) -> u64 {
        self.diff_buf.as_ref().map_or(0, EditBuffer::len)
    }

    /// Does the byte at `off` differ from the diff buffer (or lie past its end)?
    pub fn byte_differs(&self, off: u64) -> bool {
        let Some(other) = &self.diff_buf else {
            return false;
        };
        if off >= other.len() {
            return true;
        }
        self.buffer.read_byte(FileOffset(off)) != other.read_byte(FileOffset(off))
    }

    /// Total differing bytes over the shorter length, plus the tail-length delta,
    /// bounded so huge files stay responsive.
    fn diff_count(&self) -> usize {
        let Some(other) = &self.diff_buf else {
            return 0;
        };
        let scan = self.buffer.len().max(other.len()).min(16 * 1024 * 1024);
        (0..scan).filter(|&o| self.byte_differs(o)).count()
    }

    fn next_diff(&mut self, forward: bool) {
        let Some(other_len) = self.diff_buf.as_ref().map(EditBuffer::len) else {
            self.set_status("No diff loaded (press c).");
            return;
        };
        let max = self.buffer.len().max(other_len);
        let found = if forward {
            (self.cursor + 1..max).find(|&o| self.byte_differs(o))
        } else {
            (0..self.cursor).rev().find(|&o| self.byte_differs(o))
        };
        match found {
            Some(off) => {
                self.move_to(off);
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
                self.set_status(format!("Diff at {}", self.display_addr(off)));
            }
            None => self.set_status("No more differences."),
        }
    }

    // -- Structure viewer --------------------------------------------

    fn open_struct(&mut self, path: &str) {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                self.set_status(format!("Cannot read {path}: {e}"));
                self.dialog = None;
                return;
            }
        };
        let tpl = match hiewlm_core::Template::parse(&text) {
            Ok(t) => t,
            Err(e) => {
                self.set_status(format!("Template error: {e}"));
                self.dialog = None;
                return;
            }
        };
        let base = self.cursor;
        let fields = hiewlm_core::apply_struct(&tpl, &self.buffer, base);
        let items = fields
            .iter()
            .map(|f| {
                (
                    format!("{:<18} {}  = {}", f.name, self.display_addr(f.offset), f.value),
                    f.offset,
                )
            })
            .collect::<Vec<_>>();
        self.dialog = Some(Dialog::JumpList {
            title: format!("Struct @ {} ({} bytes)", self.display_addr(base), tpl.total_size()),
            items,
            sel: 0,
        });
    }

    // -- Colored markers ---------------------------------------------

    /// Marker color covering `off`, if any (last one wins on overlap).
    pub fn marker_color_at(&self, off: u64) -> Option<u8> {
        self.markers
            .iter()
            .rev()
            .find(|m| off >= m.start && off <= m.end)
            .map(|m| m.color)
    }

    fn open_color_menu(&mut self) {
        if self.selection().is_none() {
            self.set_status("Select a block first (*), then M to color it.");
            return;
        }
        self.dialog = Some(Dialog::ColorMenu { selected: 0 });
    }

    /// Color the current selection with palette index `idx`.
    fn color_block(&mut self, idx: u8) {
        self.dialog = None;
        let Some((start, end)) = self.selection() else {
            return;
        };
        self.markers.push(Marker { start, end, color: idx % crate::theme::Theme::MARKER_COLORS });
        self.mark = None;
        self.save_markers();
        self.set_status(format!(
            "Marked {} bytes {}. Alt+N / ] jumps between markers.",
            end - start + 1,
            crate::theme::Theme::marker_name(idx)
        ));
    }

    fn clear_markers(&mut self) {
        self.dialog = None;
        let n = self.markers.len();
        self.markers.clear();
        self.save_markers();
        self.set_status(format!("Cleared {n} marker(s)."));
    }

    /// Jump to the next/previous marker start relative to the cursor.
    fn jump_marker(&mut self, forward: bool) {
        if self.markers.is_empty() {
            self.set_status("No markers (select a block, then M).");
            return;
        }
        let mut starts: Vec<u64> = self.markers.iter().map(|m| m.start).collect();
        starts.sort_unstable();
        starts.dedup();
        let target = if forward {
            starts.iter().find(|&&s| s > self.cursor).copied().or_else(|| starts.first().copied())
        } else {
            starts.iter().rev().find(|&&s| s < self.cursor).copied().or_else(|| starts.last().copied())
        };
        if let Some(off) = target {
            self.record_jump();
            self.move_to(off);
            if self.mode == Mode::Code && self.code_supported() {
                self.enter_code();
            }
            self.set_status(format!("Marker at {}", self.display_addr(off)));
        }
    }

    fn save_markers(&self) {
        let path = markers_path(&self.path);
        if self.markers.is_empty() {
            let _ = fs::remove_file(&path);
            return;
        }
        if let Ok(s) = toml::to_string(&MarkerFile { markers: self.markers.clone() }) {
            let _ = fs::write(&path, s);
        }
    }

    // -- Comments, names, xrefs --------------------------------------

    pub fn comment_at(&self, off: u64) -> Option<&str> {
        self.comments.get(&off).map(String::as_str)
    }

    fn open_comment(&mut self) {
        let existing = self.comments.get(&self.cursor).cloned().unwrap_or_default();
        self.dialog = Some(Dialog::Comment { input: existing });
    }

    fn set_comment(&mut self, text: &str) {
        let t = text.trim();
        if t.is_empty() {
            self.comments.remove(&self.cursor);
            self.set_status("Comment removed.");
        } else {
            self.comments.insert(self.cursor, t.to_string());
            self.set_status(format!("Comment set at {}", self.display_addr(self.cursor)));
        }
        self.dialog = None;
    }

    /// Named locations: entry, sections, and user comments.
    fn names_list(&self) -> Vec<(String, u64)> {
        let mut items = Vec::new();
        // Plugin-parsed containers (ZIP/PDF) list their members.
        if let Some(c) = &self.container {
            for m in &c.members {
                items.push((
                    format!("member    {}  {}  {}", self.display_addr(m.offset), m.name, m.detail),
                    m.offset,
                ));
            }
        }
        // `ar` archives come from the executable parser, not a plugin.
        if self.format.is_container() {
            for (name, off) in &self.exports {
                items.push((format!("member    {}  {name}", self.display_addr(*off)), *off));
            }
        }
        if let Some(va) = self.entry {
            if let Some(off) = self.va_to_off(va) {
                items.push((format!("entry     .{va:08X}"), off));
            }
        }
        for s in self.address_space.sections() {
            items.push((format!("section   {:<16} .{:08X}", s.name, s.va), s.file_off));
        }
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(off) = slot {
                items.push((format!("slot {}     {}", i + 1, self.display_addr(*off)), *off));
            }
        }
        for (name, off) in &self.named_bookmarks {
            items.push((format!("bookmark  {}  {name}", self.display_addr(*off)), *off));
        }
        for (off, c) in &self.comments {
            items.push((format!("comment   {}  {c}", self.display_addr(*off)), *off));
        }
        items
    }

    /// List printable ASCII strings (>= 4 chars) in the file, jumpable (HIEW Alt+F6).
    fn open_strings(&mut self) {
        const MIN: usize = 4;
        let cap = self.buffer.len().min(64 * 1024 * 1024);
        let mut items: Vec<(String, u64)> = Vec::new();
        let mut run: Vec<u8> = Vec::new();
        let mut run_start = 0u64;
        let mut off = 0u64;
        let mut chunk = vec![0u8; 64 * 1024];
        let mut remaining = cap;
        while remaining > 0 && items.len() < 20_000 {
            let n = (remaining as usize).min(chunk.len());
            self.buffer.read_at(FileOffset(off), &mut chunk[..n]);
            for (i, &b) in chunk[..n].iter().enumerate() {
                if (0x20..0x7f).contains(&b) {
                    if run.is_empty() {
                        run_start = off + i as u64;
                    }
                    run.push(b);
                } else {
                    if run.len() >= MIN {
                        let s: String = run.iter().map(|&c| c as char).collect();
                        items.push((format!("{}  {}", self.display_addr(run_start), s), run_start));
                    }
                    run.clear();
                }
            }
            off += n as u64;
            remaining -= n as u64;
        }
        if run.len() >= MIN {
            let s: String = run.iter().map(|&c| c as char).collect();
            items.push((format!("{}  {}", self.display_addr(run_start), s), run_start));
        }
        if items.is_empty() {
            self.set_status("No strings found.");
            return;
        }
        self.dialog = Some(Dialog::JumpList {
            title: format!("Strings ({})", items.len()),
            items,
            sel: 0,
        });
    }

    /// Replace the instruction under the cursor with NOP padding (HIEW Alt+F2).
    /// x86/x64 = 0x90; ARM64 = the NOP encoding.
    fn nop_instruction(&mut self) {
        if !(self.mode == Mode::Code && self.code_supported()) {
            self.set_status("NOP works in Code mode.");
            return;
        }
        let start = self.cursor_insn_start();
        let Some(ins) = self.disasm_from(start, 1).into_iter().next() else {
            return;
        };
        let filler: Vec<u8> = match self.disasm_arch {
            Arch::Arm64 if ins.len == 4 => vec![0x1f, 0x20, 0x03, 0xd5], // nop
            _ => vec![0x90u8; ins.len], // x86/x64 nop, or byte-fill
        };
        let filler = if filler.len() == ins.len { filler } else { vec![0x90u8; ins.len] };
        self.buffer.overwrite(FileOffset(ins.offset), &filler);
        self.read_only = false;
        self.set_status(format!("NOP'd {} byte(s) at {}", ins.len, self.display_addr(ins.offset)));
    }

    /// Encode `text` for the instruction under the cursor. Returns the bytes
    /// and the size of the slot they must fit into (the current instruction).
    pub(crate) fn assemble_preview(
        &self,
        text: &str,
    ) -> Result<(Vec<u8>, usize), hiewlm_asm::AsmError> {
        let start = self.cursor_insn_start();
        let slot = self
            .disasm_from(start, 1)
            .into_iter()
            .next()
            .map(|i| i.len)
            .unwrap_or(1);
        let rip = self.va_of(start);
        let bytes = hiewlm_asm::assemble(text, self.disasm_bits, rip)?;
        Ok((bytes, slot))
    }

    /// Assemble at the cursor and overwrite the instruction in place, padding
    /// with NOPs so the following instruction is never disturbed. Refuses to
    /// write if the new encoding is longer than the instruction it replaces.
    fn commit_assemble(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        let start = self.cursor_insn_start();
        let (bytes, slot) = match self.assemble_preview(text) {
            Ok(v) => v,
            Err(e) => {
                self.set_status(format!("Assemble: {e}"));
                self.dialog = Some(Dialog::Assemble { input: text.to_string() });
                return;
            }
        };
        if bytes.len() > slot {
            self.set_status(format!(
                "Assemble: {} bytes won't fit the {slot}-byte instruction (use a shorter form).",
                bytes.len()
            ));
            self.dialog = Some(Dialog::Assemble { input: text.to_string() });
            return;
        }
        let mut patch = bytes.clone();
        patch.resize(slot, 0x90);
        self.buffer.overwrite(FileOffset(start), &patch);
        self.read_only = false;
        let pad = slot - bytes.len();
        self.set_status(format!(
            "Assembled {} byte(s){} at {}",
            bytes.len(),
            if pad > 0 { format!(" + {pad} NOP") } else { String::new() },
            self.display_addr(start)
        ));
    }

    fn open_names(&mut self) {
        let mut items = self.names_list();
        // Function recovery is only meaningful for code images, not containers.
        let is_container = self.format.is_container() || self.container.is_some();
        if !is_container {
            for &off in &self.analyze().functions {
                items.push((format!("func      {}", self.display_addr(off)), off));
            }
        }
        if items.is_empty() {
            self.set_status("No names yet (; adds a comment).");
            return;
        }
        let title = if is_container {
            format!("Members ({})", items.len())
        } else {
            format!("Names & functions ({})", items.len())
        };
        self.dialog = Some(Dialog::JumpList {
            title,
            items,
            sel: 0,
        });
    }

    /// Recursive-traversal analysis: from entry + exports, follow direct calls and
    /// jumps to find reachable code, function starts, and a cross-reference index.
    /// Budgeted so huge/hostile inputs stay bounded. x86/x64 only (needs targets).
    fn analyze(&self) -> Analysis {
        let mut functions: BTreeSet<u64> = BTreeSet::new();
        let mut xrefs: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        if !matches!(self.disasm_arch, Arch::X86 | Arch::X86_64 | Arch::Unknown) {
            return Analysis { functions, xrefs };
        }
        let mut visited: BTreeSet<u64> = BTreeSet::new();
        let mut work: Vec<u64> = Vec::new();

        if let Some(off) = self.entry.and_then(|va| self.va_to_off(va)) {
            if functions.insert(off) {
                work.push(off);
            }
        }
        for (_, va) in &self.exports {
            if *va != 0 {
                if let Some(off) = self.va_to_off(*va) {
                    if functions.insert(off) {
                        work.push(off);
                    }
                }
            }
        }
        if work.is_empty() && functions.insert(0) {
            work.push(0);
        }

        let mut budget = 200_000usize;
        while let Some(start) = work.pop() {
            let mut off = start;
            while budget > 0 && off < self.buffer.len() && !visited.contains(&off) {
                let Some(ins) = self.disasm_from(off, 1).into_iter().next() else {
                    break;
                };
                visited.insert(off);
                budget -= 1;
                let next = ins.offset + ins.len as u64;
                if let Some(t) = ins.target {
                    xrefs.entry(t).or_default().push(ins.offset);
                    if let Some(toff) = self.va_to_off(t) {
                        match ins.flow {
                            Flow::Call => {
                                if functions.insert(toff) {
                                    work.push(toff);
                                }
                            }
                            Flow::Jump | Flow::CondJump if !visited.contains(&toff) => {
                                work.push(toff);
                            }
                            _ => {}
                        }
                    }
                }
                match ins.flow {
                    Flow::Ret | Flow::Jump => break,
                    _ => off = next,
                }
            }
        }
        Analysis { functions, xrefs }
    }

    /// Build a text control-flow graph of the function containing the cursor:
    /// basic blocks + their successors. Best-effort, bounded.
    fn open_cfg(&mut self) {
        if !matches!(self.arch, Arch::X86 | Arch::X86_64 | Arch::Unknown) {
            self.set_status("CFG needs x86/x64.");
            return;
        }
        let cur = self.cursor_insn_start();
        // Function start = the recovered function at or before the cursor.
        let func_start = self
            .analyze()
            .functions
            .range(..=cur)
            .next_back()
            .copied()
            .unwrap_or(cur);

        // Collect instructions and block leaders reachable within the function.
        let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
        let mut leaders: BTreeSet<u64> = BTreeSet::new();
        leaders.insert(func_start);
        let mut work = vec![func_start];
        let mut budget = 4000usize;
        while let Some(start) = work.pop() {
            let mut off = start;
            while budget > 0 && off < self.buffer.len() && !insns.contains_key(&off) {
                let Some(ins) = self.disasm_from(off, 1).into_iter().next() else { break };
                budget -= 1;
                let next = ins.offset + ins.len as u64;
                let flow = ins.flow;
                let target = ins.target.and_then(|t| self.va_to_off(t));
                insns.insert(off, ins);
                match flow {
                    Flow::Ret => break,
                    Flow::Jump | Flow::CondJump => {
                        if let Some(t) = target {
                            leaders.insert(t);
                            work.push(t);
                        }
                        leaders.insert(next);
                        if flow == Flow::CondJump {
                            work.push(next);
                        }
                        break;
                    }
                    _ => off = next,
                }
            }
        }

        // Form blocks: a run of instructions from a leader up to (and including)
        // the next terminator or the byte before the next leader.
        let addrs: Vec<u64> = insns.keys().copied().collect();
        let mut body = format!(
            "Function {}  ·  {} basic blocks\n\n",
            self.display_addr(func_start),
            leaders.iter().filter(|l| insns.contains_key(l)).count()
        );
        let mut i = 0;
        let mut bno = 0;
        while i < addrs.len() {
            let start = addrs[i];
            if !leaders.contains(&start) {
                i += 1;
                continue;
            }
            bno += 1;
            body.push_str(&format!("── block {bno}  {} ──\n", self.display_addr(start)));
            let mut last: Option<&Insn> = None;
            while i < addrs.len() {
                let a = addrs[i];
                let ins = &insns[&a];
                body.push_str(&format!("  {}: {}\n", self.display_addr(a), ins.text));
                last = Some(ins);
                i += 1;
                let ends = matches!(ins.flow, Flow::Ret | Flow::Jump | Flow::CondJump);
                let next_is_leader = i < addrs.len() && leaders.contains(&addrs[i]);
                if ends || next_is_leader {
                    break;
                }
            }
            // Successors of the block.
            if let Some(ins) = last {
                let next = ins.offset + ins.len as u64;
                let tgt = ins.target.and_then(|t| self.va_to_off(t));
                let succs: Vec<u64> = match ins.flow {
                    Flow::Ret => vec![],
                    Flow::Jump => tgt.into_iter().collect(),
                    Flow::CondJump => tgt.into_iter().chain(std::iter::once(next)).collect(),
                    _ => vec![next],
                };
                if succs.is_empty() {
                    body.push_str("  ↳ (return)\n");
                } else {
                    let s: Vec<String> = succs.iter().map(|&o| self.display_addr(o)).collect();
                    body.push_str(&format!("  ↳ {}\n", s.join("  ")));
                }
            }
            body.push('\n');
        }

        self.dialog = Some(Dialog::Message {
            title: format!("CFG {}", self.display_addr(func_start)),
            body,
            scroll: 0,
        });
    }

    fn open_xrefs(&mut self) {
        if !matches!(self.disasm_arch, Arch::X86 | Arch::X86_64 | Arch::Unknown) {
            self.set_status("Xref needs x86/x64 (branch targets).");
            return;
        }
        let target = self.va_of(self.cursor);
        let refs = self.analyze().xrefs.get(&target).cloned().unwrap_or_default();
        if refs.is_empty() {
            self.set_status(format!("No xrefs to {}", self.display_addr(self.cursor)));
            return;
        }
        let items = refs
            .into_iter()
            .map(|off| {
                let text = self.disasm_from(off, 1).into_iter().next().map(|i| i.text).unwrap_or_default();
                (format!("{}  {text}", self.display_addr(off)), off)
            })
            .collect::<Vec<_>>();
        let title = format!("Xrefs to {} ({})", self.display_addr(self.cursor), items.len());
        self.dialog = Some(Dialog::JumpList { title, items, sel: 0 });
    }

    /// Jump to `off`, remembering the current spot for Backspace.
    fn goto_offset(&mut self, off: u64) {
        self.record_jump();
        self.nav_stack.push(self.cursor);
        self.move_to(off);
        if self.mode == Mode::Code && self.code_supported() {
            self.enter_code();
        }
    }

    /// Record the current cursor as a history entry (deduped, capped).
    fn record_jump(&mut self) {
        if self.history.last() != Some(&self.cursor) {
            self.history.push(self.cursor);
            if self.history.len() > 200 {
                self.history.remove(0);
            }
        }
    }

    fn open_history(&mut self) {
        if self.history.is_empty() {
            self.set_status("No jump history yet.");
            return;
        }
        let items: Vec<(String, u64)> = self
            .history
            .iter()
            .rev()
            .map(|&off| (self.display_addr(off), off))
            .collect();
        self.dialog = Some(Dialog::JumpList {
            title: format!("History ({})", items.len()),
            items,
            sel: 0,
        });
    }

    // -- Macros (key-level record/replay) ----------------------------

    fn macro_toggle(&mut self) {
        if self.replaying {
            return;
        }
        match self.macro_rec.take() {
            Some(keys) => {
                let n = keys.len();
                self.macro_saved = keys;
                self.set_status(format!("Macro recorded ({n} keys). Ctrl+P plays it."));
            }
            None => {
                self.macro_rec = Some(Vec::new());
                self.set_status("Recording macro… Ctrl+. to stop.");
            }
        }
    }

    fn macro_play(&mut self) {
        if self.macro_saved.is_empty() {
            self.set_status("No macro recorded (Ctrl+. to record).");
            return;
        }
        self.replaying = true;
        for k in self.macro_saved.clone() {
            self.handle_key(k);
        }
        self.replaying = false;
        self.set_status("Macro played.");
    }

    /// Play the macro repeatedly until a search inside it fails, the state stops
    /// changing, or a hard cap is hit (HIEW's loop / stop-on-search-fail).
    fn macro_play_loop(&mut self) {
        if self.macro_saved.is_empty() {
            self.set_status("No macro recorded (Ctrl+. to record).");
            return;
        }
        self.replaying = true;
        let keys = self.macro_saved.clone();
        let mut iters = 0usize;
        loop {
            self.macro_search_failed = false;
            let before = (self.cursor, self.buffer.len());
            for k in &keys {
                if self.macro_search_failed {
                    break;
                }
                self.handle_key(*k);
            }
            iters += 1;
            if self.macro_search_failed {
                break;
            }
            if (self.cursor, self.buffer.len()) == before || iters >= 100_000 {
                break;
            }
        }
        self.replaying = false;
        self.set_status(format!("Macro looped {iters} time(s)."));
    }

    fn extract_resource(&mut self, r: &hiewlm_core::Resource) {
        let dir = self.path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
        let fname = format!("res_{}_{}_{}.bin", sanitize(&r.type_name), sanitize(&r.name), r.lang);
        let path = dir.join(&fname);
        let size = r.size.min(64 * 1024 * 1024) as usize;
        let mut data = vec![0u8; size];
        self.buffer.read_at(FileOffset(r.file_off), &mut data);
        match std::fs::write(&path, &data) {
            Ok(()) => self.set_status(format!("Extracted {size} bytes → {}", path.display())),
            Err(e) => self.set_status(format!("Extract failed: {e}")),
        }
        self.dialog = None;
    }

    // -- Bookmarks (HIEW + / - stack) --------------------------------

    /// Jump to a numbered slot, or report that it is empty rather than
    /// silently moving the cursor to offset 0.
    fn jump_slot(&mut self, n: u8) {
        let Some(idx) = (1..=8).contains(&n).then(|| (n - 1) as usize) else {
            self.set_status("Slots are 1-8.");
            return;
        };
        match self.slots[idx] {
            Some(off) if off < self.buffer.len() => {
                self.record_jump();
                self.move_to(off);
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
                self.set_status(format!("Slot {n} → {}", self.display_addr(off)));
            }
            Some(_) => self.set_status(format!("Slot {n} points past end of file.")),
            None => self.set_status(format!("Slot {n} is empty (K then {n} sets it).")),
        }
    }

    fn bookmark_push(&mut self) {
        self.bookmarks.push(self.cursor);
        self.set_status(format!(
            "Bookmark pushed ({} on stack). - to return.",
            self.bookmarks.len()
        ));
    }

    fn add_named_bookmark(&mut self, name: &str) {
        let name = name.trim();
        let label = if name.is_empty() {
            format!("bookmark {}", self.display_addr(self.cursor))
        } else {
            name.to_string()
        };
        self.named_bookmarks.push((label, self.cursor));
        self.set_status(format!("Bookmark saved ({} total). F12 to jump.", self.named_bookmarks.len()));
        self.dialog = None;
    }

    fn bookmark_pop(&mut self) {
        match self.bookmarks.pop() {
            Some(off) => {
                self.move_to(off);
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
                self.set_status(format!("Returned to bookmark ({} left).", self.bookmarks.len()));
            }
            None => self.set_status("Bookmark stack is empty (+ to push)."),
        }
    }

    /// Whether the hex column holds the cursor (for highlighting): true by default;
    /// while editing it follows the selected column.
    pub fn edit_focus_hex(&self) -> bool {
        !self.editing || self.edit_col == EditCol::Hex
    }

    pub fn display_addr(&self, off: u64) -> String {
        match self.addr_mode {
            AddrMode::Va => match self.address_space.va_of(FileOffset(off)) {
                Some(va) => format!(".{:08X}", va.get()),
                None => format!("{off:08X}"),
            },
            AddrMode::Offset => format!("{off:08X}"),
        }
    }

    // -- Navigation --------------------------------------------------

    fn move_to(&mut self, off: u64) {
        self.cursor = off.min(self.max_offset());
        self.nibble = 0;
        self.ensure_visible();
    }

    fn step(&mut self, delta: i64) {
        let next = self.cursor as i64 + delta;
        let clamped = next.clamp(0, self.max_offset() as i64);
        self.move_to(clamped as u64);
    }

    /// Keep the cursor within the viewport, re-aligning `top` to the current row
    /// stride (which differs between Hex and Text). In Code mode the instruction
    /// viewport is used instead.
    pub fn ensure_visible(&mut self) {
        if self.mode == Mode::Code && self.code_supported() {
            self.ensure_code_visible();
            return;
        }
        let stride = self.stride();
        let row = self.cursor / stride;
        let top_row = self.top / stride;
        if row < top_row {
            self.top = row * stride;
        } else if row >= top_row + self.visible_rows as u64 {
            self.top = (row + 1 - self.visible_rows as u64) * stride;
        } else {
            self.top = top_row * stride;
        }
    }

    // -- Code mode (disassembly) -------------------------------------

    pub fn code_supported(&self) -> bool {
        Disassembler::supports(self.disasm_arch)
    }

    /// True when arrow keys should move by instruction (Code mode, viewing). While
    /// editing opcode bytes, movement is per byte instead.
    fn in_code_nav(&self) -> bool {
        self.mode == Mode::Code && self.code_supported() && !self.editing
    }

    fn va_of(&self, off: u64) -> u64 {
        self.address_space
            .va_of(FileOffset(off))
            .map(|v| v.get())
            .unwrap_or(off)
    }

    /// Convert a branch target VA back to a file offset (identity when unmapped).
    fn va_to_off(&self, va: u64) -> Option<u64> {
        if self.address_space.is_mapped() {
            self.address_space.offset_of(hiewlm_core::Va(va)).map(|o| o.get())
        } else {
            Some(va)
        }
    }

    /// Disassemble up to `count` instructions starting at file offset `off`.
    pub fn disasm_from(&self, off: u64, count: usize) -> Vec<Insn> {
        if off >= self.buffer.len() || count == 0 {
            return Vec::new();
        }
        let avail = (self.buffer.len() - off) as usize;
        let want = (count * MAX_INSN_LEN).min(avail);
        let mut data = vec![0u8; want];
        self.buffer.read_at(FileOffset(off), &mut data);
        Disassembler::new(self.disasm_arch, self.disasm_bits).decode(&data, off, self.va_of(off), count)
    }

    /// The start offset of the instruction containing the cursor.
    fn cursor_insn_start(&self) -> u64 {
        let back = self.cursor.saturating_sub(MAX_INSN_LEN as u64);
        for ins in self.disasm_from(back, MAX_INSN_LEN * 2) {
            if ins.offset <= self.cursor && self.cursor < ins.offset + ins.len as u64 {
                return ins.offset;
            }
            if ins.offset > self.cursor {
                break;
            }
        }
        self.cursor
    }

    /// Snap the cursor to an instruction boundary and reset the code viewport.
    fn enter_code(&mut self) {
        self.cursor = self.cursor_insn_start();
        self.code_top = self.cursor;
    }

    /// Apply a disassembly arch/bitness choice from [`DISASM_OPTIONS`].
    fn set_disasm(&mut self, idx: usize) {
        let (label, opt) = DISASM_OPTIONS[idx % DISASM_OPTIONS.len()];
        match opt {
            None => {
                self.disasm_arch = self.arch;
                self.disasm_bits = self.bits;
                self.disasm_override = false;
            }
            Some((a, b)) => {
                self.disasm_arch = a;
                self.disasm_bits = b;
                self.disasm_override = true;
            }
        }
        self.dialog = None;
        self.mode = Mode::Code;
        if self.code_supported() {
            self.enter_code();
            self.set_status(format!("Disassemble as: {label}"));
        } else {
            self.set_status(format!("{label}: disassembler not available yet"));
        }
    }

    fn code_step(&mut self, forward: bool) {
        let start = self.cursor_insn_start();
        if forward {
            if let Some(ins) = self.disasm_from(start, 1).first() {
                let next = ins.offset + ins.len as u64;
                if next <= self.max_offset() {
                    self.cursor = next;
                }
            }
        } else if start > 0 {
            let back = start.saturating_sub(MAX_INSN_LEN as u64);
            let mut prev = start.saturating_sub(1);
            for ins in self.disasm_from(back, MAX_INSN_LEN * 2) {
                if ins.offset >= start {
                    break;
                }
                prev = ins.offset;
            }
            self.cursor = prev;
        }
        self.nibble = 0;
        self.ensure_code_visible();
    }

    /// Keep the cursor's instruction visible, scrolling one instruction at a time
    /// (bounded), falling back to putting the cursor at the top for large jumps.
    fn ensure_code_visible(&mut self) {
        if self.cursor < self.code_top {
            self.code_top = self.cursor;
            return;
        }
        for _ in 0..(self.visible_rows.max(1) * 2) {
            let insns = self.disasm_from(self.code_top, self.visible_rows);
            let visible = insns
                .iter()
                .any(|i| i.offset <= self.cursor && self.cursor < i.offset + i.len as u64);
            if visible || insns.len() < self.visible_rows {
                return;
            }
            match insns.first() {
                Some(first) => self.code_top = first.offset + first.len as u64,
                None => return,
            }
            if self.code_top > self.cursor {
                break;
            }
        }
        self.code_top = self.cursor;
    }

    /// Follow the branch/call under the cursor to its target.
    fn follow_branch(&mut self) {
        let start = self.cursor_insn_start();
        let target = self.disasm_from(start, 1).into_iter().next().and_then(|i| i.target);
        let Some(va) = target else {
            self.set_status("Cursor is not on a branch/call instruction.");
            return;
        };
        match self.va_to_off(va) {
            Some(off) if off <= self.max_offset() => {
                self.record_jump();
                self.nav_stack.push(self.cursor);
                self.cursor = off;
                self.enter_code();
                self.set_status(format!("Followed to {}", self.display_addr(off)));
            }
            _ => self.set_status("Branch target is outside the file."),
        }
    }

    fn nav_back(&mut self) {
        match self.nav_stack.pop() {
            Some(off) => {
                self.cursor = off;
                self.enter_code();
                self.set_status("Back.");
            }
            None => self.set_status("Nothing to go back to."),
        }
    }

    /// Return to the previous position in the jump history (Esc, once every
    /// transient state has been cleared). Skips any entry equal to where the
    /// cursor already is, so a single Esc always produces a visible move.
    /// Returns whether it went anywhere.
    fn go_back(&mut self) -> bool {
        while let Some(off) = self.history.pop() {
            if off == self.cursor || off >= self.buffer.len() {
                continue;
            }
            self.move_to(off);
            if self.mode == Mode::Code && self.code_supported() {
                self.enter_code();
            }
            self.set_status(format!("Back to {}", self.display_addr(off)));
            return true;
        }
        false
    }

    // -- Editing -----------------------------------------------------

    fn enter_edit(&mut self) {
        if self.buffer.is_empty() {
            self.set_status("Empty file — nothing to edit.");
            return;
        }
        self.editing = true;
        self.read_only = false;
        self.nibble = 0;
        if self.mode == Mode::Code {
            self.edit_col = EditCol::Hex;
            self.set_status("EDIT opcode bytes: type hex to patch (disasm updates live) · F9 save · Esc cancel");
        } else {
            self.set_status("EDITMODE · Tab switches column · F9 save · Esc cancel");
        }
    }

    fn cancel_edit(&mut self) {
        self.editing = false;
        self.nibble = 0;
        self.set_status("Left edit mode.");
    }

    fn type_hex_nibble(&mut self, digit: u8) {
        let cur = self.buffer.read_byte(FileOffset(self.cursor));
        let new = if self.nibble == 0 {
            (digit << 4) | (cur & 0x0f)
        } else {
            (cur & 0xf0) | digit
        };
        self.buffer.overwrite(FileOffset(self.cursor), &[new]);
        if self.nibble == 0 {
            self.nibble = 1;
        } else {
            self.nibble = 0;
            self.step(1);
        }
    }

    fn type_ascii(&mut self, byte: u8) {
        if self.insert_mode {
            self.buffer.insert(FileOffset(self.cursor), &[byte]);
        } else {
            self.buffer.overwrite(FileOffset(self.cursor), &[byte]);
        }
        self.step(1);
    }

    fn insert_zero_byte(&mut self) {
        self.buffer.insert(FileOffset(self.cursor), &[0]);
        self.editing = true;
        self.read_only = false;
        self.set_status("Inserted one 0x00 byte.");
    }

    fn save(&mut self) -> Result<()> {
        if !self.buffer.is_dirty() {
            self.set_status("No changes to save.");
            return Ok(());
        }
        let backup = self.path.with_extension(format!(
            "{}.bak",
            self.path.extension().and_then(|e| e.to_str()).unwrap_or("")
        ));
        if self.path.exists() {
            fs::copy(&self.path, &backup).ok();
        }
        let tmp = self.path.with_extension("hiewlm.tmp");
        fs::write(&tmp, self.buffer.to_vec())
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("cannot replace {}", self.path.display()))?;
        self.set_status(format!("Saved (backup: {}).", backup.display()));
        Ok(())
    }

    // -- Dialogs & search --------------------------------------------

    fn confirm_goto(&mut self, input: &str) {
        match self.parse_addr(input.trim()) {
            Some(off) => {
                self.record_jump();
                self.move_to(off);
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
                self.set_status(format!("-> {}", self.display_addr(self.cursor)));
            }
            None => self.set_status("Invalid address expression."),
        }
        self.dialog = None;
    }

    /// HIEW syntax: `n` (hex), `+n`/`-n` relative, `.va` virtual address, `nt` decimal.
    fn parse_addr(&self, s: &str) -> Option<u64> {
        if s.is_empty() {
            return None;
        }
        if let Some(rest) = s.strip_prefix('.') {
            let va = parse_number(rest)?;
            return self
                .address_space
                .offset_of(hiewlm_core::Va(va))
                .map(|o| o.get())
                .or(Some(va));
        }
        if let Some(rest) = s.strip_prefix('+') {
            return Some(self.cursor.saturating_add(parse_number(rest)?));
        }
        if let Some(rest) = s.strip_prefix('-') {
            return Some(self.cursor.saturating_sub(parse_number(rest)?));
        }
        parse_number(s)
    }

    /// Turn search text into a byte pattern for the chosen kind.
    pub(crate) fn search_pattern(&self, input: &str, kind: SearchKind) -> Result<Pattern, String> {
        match kind {
            SearchKind::Text => Ok(Pattern::from_text(input)),
            SearchKind::Hex => Pattern::from_hex(input).map_err(|_| "Invalid hex string.".into()),
            SearchKind::Utf16 => {
                // UTF-16LE: each unit little-endian, so ASCII gains a 0x00 pad.
                let bytes: Vec<u8> =
                    input.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                if bytes.is_empty() {
                    return Err("Empty search string.".into());
                }
                Ok(Pattern::from_bytes(bytes))
            }
            SearchKind::Asm => {
                if !matches!(self.disasm_arch, Arch::X86 | Arch::X86_64) {
                    return Err("Instruction search supports x86/x86-64 only.".into());
                }
                // rip 0 keeps the encoding position-independent; a rip-relative
                // branch would otherwise only match at one address.
                hiewlm_asm::assemble(input, self.disasm_bits, 0)
                    .map(Pattern::from_bytes)
                    .map_err(|e| format!("Assemble: {e}"))
            }
        }
    }

    pub(crate) fn confirm_search(&mut self, input: &str, kind: SearchKind) {
        let pattern = match self.search_pattern(input, kind) {
            Ok(p) => p,
            Err(e) => {
                self.set_status(e);
                self.dialog = None;
                return;
            }
        };
        // A marked block scopes the search to it (HIEW searches in-block).
        self.search_scope = self.selection();
        self.dialog = None;
        self.run_search(pattern, Direction::Forward, self.cursor);
    }

    fn run_search(&mut self, pattern: Pattern, dir: Direction, from: u64) {
        let hit = find(&self.buffer, &pattern, FileOffset(from), dir).filter(|h| {
            // Outside the marked block does not count when a scope is active.
            self.search_scope
                .map_or(true, |(s, e)| h.get() >= s && h.get() + pattern.len() as u64 <= e + 1)
        });
        match hit {
            Some(hit) => {
                self.record_jump();
                self.move_to(hit.get());
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
                self.set_status(format!("Found at {} · Esc clears highlight", self.display_addr(hit.get())));
            }
            None => {
                self.macro_search_failed = true;
                self.set_status(match self.search_scope {
                    Some(_) => "Not found in block (Esc clears the block).",
                    None => "Not found.",
                });
            }
        }
        self.highlight = Some(pattern.clone());
        self.last_pattern = Some((pattern, dir));
    }

    /// Match ranges of the active highlight pattern overlapping `[start, end)`,
    /// bounded to that window so it stays cheap on large files.
    pub fn search_hits(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let Some(pat) = &self.highlight else {
            return Vec::new();
        };
        let plen = pat.len() as u64;
        let scan_start = start.saturating_sub(plen.saturating_sub(1));
        find_all(&self.buffer, pat, FileOffset(scan_start), FileOffset(end))
            .into_iter()
            .map(|s| (s.get(), s.get() + plen - 1))
            .collect()
    }

    /// Repeat the last search in the opposite direction (HIEW Alt+F7 back).
    fn find_prev(&mut self) {
        let Some((pattern, dir)) = self.last_pattern.take() else {
            self.set_status("No search pattern yet.");
            return;
        };
        let flipped = match dir {
            Direction::Forward => Direction::Backward,
            Direction::Backward => Direction::Forward,
        };
        let from = match flipped {
            Direction::Forward => self.cursor.saturating_add(1),
            Direction::Backward => self.cursor.saturating_sub(1),
        };
        self.run_search(pattern, flipped, from);
    }

    fn find_next(&mut self) {
        let Some((pattern, dir)) = self.last_pattern.take() else {
            self.set_status("No search pattern yet.");
            return;
        };
        let from = match dir {
            Direction::Forward => self.cursor.saturating_add(1),
            Direction::Backward => self.cursor.saturating_sub(1),
        };
        self.run_search(pattern, dir, from);
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
    }

    // -- Key dispatch ------------------------------------------------

    pub fn handle_key(&mut self, key: KeyEvent) {
        // Macro record/replay controls are handled here and never recorded.
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('.') {
            self.macro_toggle();
            return;
        }
        if ctrl && key.code == KeyCode::Char('p') {
            self.macro_play();
            return;
        }
        if ctrl && key.code == KeyCode::Char('l') {
            self.macro_play_loop();
            return;
        }
        if !self.replaying {
            if let Some(rec) = self.macro_rec.as_mut() {
                rec.push(key);
            }
        }

        if self.dialog.is_some() {
            self.handle_dialog_key(key);
            return;
        }
        if let Some(cmd) = crate::keymap::map_main(self, key) {
            self.apply(cmd);
        }
    }

    fn handle_dialog_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode::*;
        let Some(dialog) = self.dialog.take() else {
            return;
        };
        match dialog {
            Dialog::Message { title, body, scroll } => match key.code {
                Esc | Enter | Char('q') => {}
                Up => self.dialog = Some(Dialog::Message { title, body, scroll: scroll.saturating_sub(1) }),
                Down => self.dialog = Some(Dialog::Message { title, body, scroll: scroll + 1 }),
                PageUp => self.dialog = Some(Dialog::Message { title, body, scroll: scroll.saturating_sub(10) }),
                PageDown => self.dialog = Some(Dialog::Message { title, body, scroll: scroll + 10 }),
                _ => self.dialog = Some(Dialog::Message { title, body, scroll }),
            },
            Dialog::ModeMenu { selected } => match key.code {
                Up => self.dialog = Some(Dialog::ModeMenu { selected: (selected + 2) % 3 }),
                // Down, Tab, and F4-again all cycle the highlight so the menu feels responsive.
                Down | Tab | F(4) => {
                    self.dialog = Some(Dialog::ModeMenu { selected: (selected + 1) % 3 })
                }
                Enter => self.apply(Command::SetMode(mode_at(selected))),
                Char('1') | Char('h') | Char('H') => self.apply(Command::SetMode(Mode::Hex)),
                Char('2') | Char('c') | Char('C') => self.apply(Command::SetMode(Mode::Code)),
                Char('3') | Char('t') | Char('T') => self.apply(Command::SetMode(Mode::Text)),
                Esc => {}
                _ => self.dialog = Some(Dialog::ModeMenu { selected }),
            },
            Dialog::Goto { mut input } => match key.code {
                Enter => self.confirm_goto(&input.clone()),
                Esc => {}
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::Goto { input });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::Goto { input });
                }
                _ => self.dialog = Some(Dialog::Goto { input }),
            },
            Dialog::Search { mut input, kind } => match key.code {
                Enter => self.confirm_search(&input.clone(), kind),
                Esc => {}
                Tab => {
                    let kind = kind.next();
                    self.dialog = Some(Dialog::Search { input, kind });
                }
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::Search { input, kind });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::Search { input, kind });
                }
                _ => self.dialog = Some(Dialog::Search { input, kind }),
            },
            Dialog::DisasmMenu { selected } => {
                let n = DISASM_OPTIONS.len();
                match key.code {
                    Up => self.dialog = Some(Dialog::DisasmMenu { selected: (selected + n - 1) % n }),
                    Down | Tab => self.dialog = Some(Dialog::DisasmMenu { selected: (selected + 1) % n }),
                    Enter => self.set_disasm(selected),
                    Char(c @ '1'..='8') => self.set_disasm(c as usize - '1' as usize),
                    Char('0') => self.set_disasm(0),
                    Esc => {}
                    _ => self.dialog = Some(Dialog::DisasmMenu { selected }),
                }
            }
            Dialog::Assemble { mut input } => match key.code {
                Enter => self.commit_assemble(&input.clone()),
                Esc => {}
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::Assemble { input });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::Assemble { input });
                }
                _ => self.dialog = Some(Dialog::Assemble { input }),
            },
            Dialog::Calc { mut input } => match key.code {
                Enter | Esc => {}
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::Calc { input });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::Calc { input });
                }
                _ => self.dialog = Some(Dialog::Calc { input }),
            },
            Dialog::Replace { mut input, kind } => match key.code {
                Enter => self.confirm_replace(&input.clone(), kind),
                Esc => {}
                Tab => {
                    let kind = match kind {
                        SearchKind::Hex => SearchKind::Text,
                        _ => SearchKind::Hex,
                    };
                    self.dialog = Some(Dialog::Replace { input, kind });
                }
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::Replace { input, kind });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::Replace { input, kind });
                }
                _ => self.dialog = Some(Dialog::Replace { input, kind }),
            },
            Dialog::ColorMenu { selected } => {
                // 0..8 = colors, 8 = random, 9 = clear all.
                let n = 10;
                match key.code {
                    Up => self.dialog = Some(Dialog::ColorMenu { selected: (selected + n - 1) % n }),
                    Down | Tab => self.dialog = Some(Dialog::ColorMenu { selected: (selected + 1) % n }),
                    Enter => match selected {
                        c if c < 8 => self.color_block(c as u8),
                        8 => {
                            let rnd = (self.cursor ^ self.markers.len() as u64) as u8 % 8;
                            self.color_block(rnd);
                        }
                        _ => self.clear_markers(),
                    },
                    Char(c @ '1'..='8') => self.color_block(c as u8 - b'1'),
                    Char('r') | Char('R') => {
                        let rnd = (self.cursor ^ self.markers.len() as u64) as u8 % 8;
                        self.color_block(rnd);
                    }
                    Char('c') | Char('C') => self.clear_markers(),
                    Esc => {}
                    _ => self.dialog = Some(Dialog::ColorMenu { selected }),
                }
            }
            Dialog::BlockMenu { selected } => match key.code {
                Up => self.dialog = Some(Dialog::BlockMenu { selected: (selected + 3) % 4 }),
                Down | Tab => self.dialog = Some(Dialog::BlockMenu { selected: (selected + 1) % 4 }),
                Enter => self.apply(BLOCK_MENU_CMDS[selected]),
                Char('w') | Char('W') => self.apply(Command::OpenBlockWrite),
                Char('f') | Char('F') => self.apply(Command::OpenBlockFill),
                Char('z') | Char('Z') => self.apply(Command::BlockFillZero),
                Char('d') | Char('D') => self.apply(Command::BlockDelete),
                Char('r') | Char('R') => self.apply(Command::OpenBlockRead),
                Char('c') | Char('C') => self.apply(Command::BlockCopy),
                Char('m') | Char('M') => self.apply(Command::BlockMove),
                Char('i') | Char('I') => self.apply(Command::BlockInsert),
                Esc => {}
                _ => self.dialog = Some(Dialog::BlockMenu { selected }),
            },
            Dialog::BlockWrite { mut input } => match key.code {
                Enter => self.block_write_file(&input.clone()),
                Esc => {}
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::BlockWrite { input });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::BlockWrite { input });
                }
                _ => self.dialog = Some(Dialog::BlockWrite { input }),
            },
            Dialog::BookmarkSlot => match key.code {
                Char(c @ '1'..='8') => {
                    let n = c as u8 - b'0';
                    self.slots[(n - 1) as usize] = Some(self.cursor);
                    self.set_status(format!(
                        "Slot {n} = {} (Alt+{n} to jump)",
                        self.display_addr(self.cursor)
                    ));
                }
                Esc => {}
                _ => self.set_status("Slots are 1-8."),
            },
            Dialog::Crypt { mut input } => match key.code {
                Enter => self.confirm_crypt(&input.clone()),
                Esc => {}
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::Crypt { input });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::Crypt { input });
                }
                _ => self.dialog = Some(Dialog::Crypt { input }),
            },
            Dialog::BlockFill { mut input } => match key.code {
                Enter => self.confirm_block_fill(&input.clone()),
                Esc => {}
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::BlockFill { input });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::BlockFill { input });
                }
                _ => self.dialog = Some(Dialog::BlockFill { input }),
            },
            Dialog::Comment { mut input } => match key.code {
                Enter => self.set_comment(&input.clone()),
                Esc => {}
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::Comment { input });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::Comment { input });
                }
                _ => self.dialog = Some(Dialog::Comment { input }),
            },
            Dialog::NameBookmark { mut input } => match key.code {
                Enter => self.add_named_bookmark(&input.clone()),
                Esc => {}
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::NameBookmark { input });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::NameBookmark { input });
                }
                _ => self.dialog = Some(Dialog::NameBookmark { input }),
            },
            Dialog::FileHits { title, items, sel } => {
                let len = items.len().max(1);
                match key.code {
                    Up => self.dialog = Some(Dialog::FileHits { title, items, sel: sel.saturating_sub(1) }),
                    Down => self.dialog = Some(Dialog::FileHits { title, items, sel: (sel + 1).min(len - 1) }),
                    Enter => {
                        if let Some((_, path, off)) = items.get(sel).cloned() {
                            self.reload(path, off);
                        }
                    }
                    Esc => {}
                    _ => self.dialog = Some(Dialog::FileHits { title, items, sel }),
                }
            }
            Dialog::FilePicker { dir, entries, sel, purpose } => {
                let len = entries.len().max(1);
                match key.code {
                    Up => self.dialog = Some(Dialog::FilePicker { dir, entries, sel: sel.saturating_sub(1), purpose }),
                    Down => self.dialog = Some(Dialog::FilePicker { dir, entries, sel: (sel + 1).min(len - 1), purpose }),
                    Left | Backspace => {
                        let up = dir.parent().map(|p| p.to_path_buf()).unwrap_or(dir);
                        let entries = Self::list_dir(&up);
                        self.dialog = Some(Dialog::FilePicker { dir: up, entries, sel: 0, purpose });
                    }
                    Enter | Right => match entries.get(sel) {
                        Some(entry) if entry.name == ".." => {
                            let up = dir.parent().map(|p| p.to_path_buf()).unwrap_or(dir);
                            let entries = Self::list_dir(&up);
                            self.dialog = Some(Dialog::FilePicker { dir: up, entries, sel: 0, purpose });
                        }
                        Some(entry) if entry.is_dir => {
                            let sub = dir.join(&entry.name);
                            let entries = Self::list_dir(&sub);
                            self.dialog = Some(Dialog::FilePicker { dir: sub, entries, sel: 0, purpose });
                        }
                        Some(entry) => {
                            let path = dir.join(&entry.name);
                            self.picker_pick(purpose, &path.to_string_lossy());
                        }
                        None => {}
                    },
                    Esc => {}
                    _ => self.dialog = Some(Dialog::FilePicker { dir, entries, sel, purpose }),
                }
            }
            Dialog::JumpList { title, items, sel } => {
                let len = items.len().max(1);
                match key.code {
                    Up => self.dialog = Some(Dialog::JumpList { title, items, sel: sel.saturating_sub(1) }),
                    Down => {
                        self.dialog = Some(Dialog::JumpList { title, items, sel: (sel + 1).min(len - 1) })
                    }
                    Enter => {
                        if let Some(&(_, off)) = items.get(sel) {
                            self.goto_offset(off);
                        }
                    }
                    Esc => {}
                    _ => self.dialog = Some(Dialog::JumpList { title, items, sel }),
                }
            }
            Dialog::Header { pane, sel, mut filter } => {
                let len = self.header_entries(pane, &filter).len().max(1);
                match key.code {
                    // Panes switch with arrows/Tab so letters stay free for filtering.
                    Tab | Right => {
                        self.dialog = Some(Dialog::Header { pane: pane.next(), sel: 0, filter })
                    }
                    Left => {
                        self.dialog = Some(Dialog::Header { pane: pane.prev(), sel: 0, filter })
                    }
                    Up => {
                        self.dialog = Some(Dialog::Header { pane, sel: sel.saturating_sub(1), filter })
                    }
                    Down => {
                        self.dialog = Some(Dialog::Header { pane, sel: (sel + 1).min(len - 1), filter })
                    }
                    Enter => self.header_activate(pane, sel, &filter),
                    Backspace => {
                        filter.pop();
                        self.dialog = Some(Dialog::Header { pane, sel: 0, filter });
                    }
                    Char(c) => {
                        filter.push(c);
                        self.dialog = Some(Dialog::Header { pane, sel: 0, filter });
                    }
                    Esc if !filter.is_empty() => {
                        self.dialog = Some(Dialog::Header { pane, sel: 0, filter: String::new() });
                    }
                    Esc => {}
                    _ => self.dialog = Some(Dialog::Header { pane, sel, filter }),
                }
            }
        }
    }

    // -- Command dispatch --------------------------------------------

    pub fn apply(&mut self, cmd: Command) {
        match cmd {
            Command::Quit => self.should_quit = true,
            Command::Escape => {
                // Back out of the most recent transient state; never quit the app.
                // Once none remain, Esc walks back through the jump history so it
                // acts as a "return to previous position", not a way out.
                if self.highlight.take().is_some() {
                    self.set_status("Search highlight cleared.");
                } else if self.mark.take().is_some() {
                    self.set_status("Selection cleared.");
                } else if self.diff_buf.take().is_some() {
                    self.split_view = false;
                    self.diff_name.clear();
                    self.set_status("Diff closed.");
                } else if self.go_back() {
                    // Moved to the previous position in the jump history.
                } else {
                    self.set_status("Nothing to go back to · q or F10 quits.");
                }
            }
            Command::CycleMode => {
                self.mode = self.mode.next();
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
            }
            Command::OpenModeMenu => {
                self.dialog = Some(Dialog::ModeMenu { selected: mode_index(self.mode) });
                self.set_status("Pick mode: 1 Hex · 2 Code · 3 Text · Enter/arrows · Esc");
            }
            Command::SetMode(m) => {
                self.mode = m;
                self.dialog = None;
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
                self.set_status(format!("Mode: {}", m.label()));
            }
            Command::Step(d) => {
                if self.in_code_nav() {
                    self.code_step(d > 0);
                } else {
                    self.step(d);
                }
            }
            Command::StepRow(d) => {
                if self.in_code_nav() {
                    self.code_step(d > 0);
                } else {
                    self.step(d * self.stride() as i64);
                }
            }
            Command::Page(d) => {
                if self.in_code_nav() {
                    for _ in 0..self.visible_rows.max(1) {
                        self.code_step(d > 0);
                    }
                } else {
                    self.step(d * self.page_bytes() as i64);
                }
            }
            Command::FollowBranch => self.follow_branch(),
            Command::NavBack => self.nav_back(),
            Command::OpenDisasmMenu => {
                let cur = DISASM_OPTIONS
                    .iter()
                    .position(|(_, o)| *o == Some((self.disasm_arch, self.disasm_bits)))
                    .filter(|_| self.disasm_override)
                    .unwrap_or(0);
                self.dialog = Some(Dialog::DisasmMenu { selected: cur });
            }
            Command::OpenHeader => {
                self.ensure_entropy();
                self.dialog = Some(Dialog::Header {
                    pane: HeaderPane::Info,
                    sel: 0,
                    filter: String::new(),
                })
            }
            Command::LineStart => {
                let s = self.stride();
                self.move_to(self.cursor / s * s);
            }
            Command::LineEnd => {
                let s = self.stride();
                self.move_to(self.cursor / s * s + s - 1);
            }
            Command::FileStart => {
                self.move_to(0);
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
            }
            Command::FileEnd => {
                self.move_to(self.max_offset());
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
            }
            Command::ToggleMark => {
                if self.mark.is_some() {
                    self.mark = None;
                    self.set_status("Selection cleared.");
                } else {
                    self.mark = Some(self.cursor);
                    self.set_status("Mark set — move to extend, * to clear, F2 write block.");
                }
            }
            Command::SelectStep(d) => {
                self.set_mark();
                self.step(d);
            }
            Command::SelectRow(d) => {
                self.set_mark();
                self.step(d * self.stride() as i64);
            }
            Command::BlockYank => self.block_yank(),
            Command::BlockPaste => self.block_paste(),
            Command::BlockDelete => self.block_delete(),
            Command::OpenBlockMenu => {
                if self.selection().is_some() {
                    self.dialog = Some(Dialog::BlockMenu { selected: 0 });
                } else {
                    self.set_status("Select a block first (press * then move).");
                }
            }
            Command::OpenBlockWrite => {
                if self.selection().is_some() {
                    self.dialog = Some(Dialog::BlockWrite { input: String::new() });
                } else {
                    self.set_status("Select a block first (press * then move).");
                }
            }
            Command::BlockCopy => self.block_copy_or_move(false),
            Command::BlockMove => self.block_copy_or_move(true),
            Command::BlockInsert => self.block_insert(),
            Command::OpenBlockRead => self.open_file_picker(PickPurpose::ReadFile),
            Command::FindPrev => self.find_prev(),
            Command::ToggleSplitView => {
                if self.diff_buf.is_none() {
                    self.set_status("Split view needs a diff: press c to pick a file.");
                } else {
                    self.split_view = !self.split_view;
                    self.set_status(if self.split_view {
                        "Split view on — this file | diff file"
                    } else {
                        "Split view off — differences highlighted inline"
                    });
                }
            }
            Command::JumpSlot(n) => self.jump_slot(n),
            Command::SetSlotPrompt => self.dialog = Some(Dialog::BookmarkSlot),
            Command::OpenCrypt => {
                if self.selection().is_none() {
                    self.set_status("Crypt needs a block: mark with * or v first.");
                } else {
                    self.dialog = Some(Dialog::Crypt { input: String::new() });
                }
            }
            Command::OpenBlockFill => {
                if self.selection().is_some() {
                    self.dialog = Some(Dialog::BlockFill { input: String::new() });
                } else {
                    self.set_status("Select a block first (press * then move).");
                }
            }
            Command::BlockFillZero => {
                self.block_fill(&[0]);
                self.dialog = None;
            }
            Command::BookmarkPush => self.bookmark_push(),
            Command::BookmarkPop => self.bookmark_pop(),
            Command::OpenComment => self.open_comment(),
            Command::OpenNames => self.open_names(),
            Command::OpenStrings => self.open_strings(),
            Command::OpenHistory => self.open_history(),
            Command::NopInstruction => self.nop_instruction(),
            Command::ColorBlock => self.open_color_menu(),
            Command::NextMarker => self.jump_marker(true),
            Command::PrevMarker => self.jump_marker(false),
            Command::OpenCfg => self.open_cfg(),
            Command::Xref => self.open_xrefs(),
            Command::OpenDiff => self.open_file_picker(PickPurpose::Diff),
            Command::NextDiff => self.next_diff(true),
            Command::PrevDiff => self.next_diff(false),
            Command::OpenStruct => self.open_file_picker(PickPurpose::StructTemplate),
            Command::OpenInspector => self.open_inspector(),
            Command::OpenCalc => self.dialog = Some(Dialog::Calc { input: String::new() }),
            Command::OpenAssemble => {
                if self.mode != Mode::Code {
                    self.set_status("Assemble works in Code mode (Enter cycles mode).");
                } else if !matches!(self.disasm_arch, Arch::X86 | Arch::X86_64) {
                    self.set_status("Assemble supports x86/x86-64 only.");
                } else {
                    self.dialog = Some(Dialog::Assemble { input: String::new() });
                }
            }
            Command::OpenHashes => self.open_hashes(),
            Command::OpenNameBookmark => self.dialog = Some(Dialog::NameBookmark { input: String::new() }),
            Command::MultiSearch => self.multi_search(),
            Command::OpenReplace => self.open_replace(),
            Command::ToggleTheme => {
                self.theme_kind = self.theme_kind.next();
                self.set_status(format!("Theme: {}", self.theme_kind.label()));
            }
            Command::CycleEncoding => {
                self.encoding = self.encoding.next();
                self.set_status(format!("Text encoding: {}", self.encoding.label()));
            }
            Command::ToggleInsert => {
                self.insert_mode = !self.insert_mode;
                let s = if self.insert_mode { "insert" } else { "overwrite" };
                self.set_status(format!("Input mode: {s}"));
            }
            Command::ToggleAddrMode => {
                self.addr_mode = match self.addr_mode {
                    AddrMode::Offset => AddrMode::Va,
                    AddrMode::Va => AddrMode::Offset,
                };
            }
            Command::EnterEdit => self.enter_edit(),
            Command::CancelEdit => self.cancel_edit(),
            Command::ToggleEditCol => {
                self.edit_col = match self.edit_col {
                    EditCol::Hex => EditCol::Ascii,
                    EditCol::Ascii => EditCol::Hex,
                };
                self.nibble = 0;
            }
            Command::InsertByte => self.insert_zero_byte(),
            Command::Save => {
                if let Err(e) = self.save() {
                    self.set_status(format!("Save error: {e}"));
                }
            }
            Command::Undo => {
                if self.buffer.undo() {
                    self.move_to(self.cursor);
                    self.set_status("Undo.");
                } else {
                    self.set_status("Nothing to undo.");
                }
            }
            Command::Redo => {
                if self.buffer.redo() {
                    self.move_to(self.cursor);
                    self.set_status("Redo.");
                } else {
                    self.set_status("Nothing to redo.");
                }
            }
            Command::OpenGoto => self.dialog = Some(Dialog::Goto { input: String::new() }),
            Command::OpenSearch => {
                let kind = if self.mode == Mode::Text { SearchKind::Text } else { SearchKind::Hex };
                self.dialog = Some(Dialog::Search { input: String::new(), kind })
            }
            Command::FindNext => self.find_next(),
            Command::Help => {
                self.dialog = Some(Dialog::Message {
                    title: "hiewLM — help".into(),
                    body: HELP_TEXT.into(),
                    scroll: 0,
                })
            }
            Command::TypeHex(d) => {
                if self.editing && self.edit_col == EditCol::Hex {
                    self.type_hex_nibble(d);
                }
            }
            Command::TypeAscii(b) => {
                if self.editing && self.edit_col == EditCol::Ascii {
                    self.type_ascii(b);
                }
            }
        }
        self.ensure_visible();
    }
}

/// A command — every state change flows through here so undo/macro/test share a
/// single path.
#[derive(Clone, Copy, Debug)]
pub enum Command {
    Quit,
    Escape,
    CycleMode,
    OpenModeMenu,
    OpenDisasmMenu,
    SetMode(Mode),
    Step(i64),
    StepRow(i64),
    Page(i64),
    LineStart,
    LineEnd,
    FileStart,
    FileEnd,
    FollowBranch,
    NavBack,
    OpenHeader,
    ToggleMark,
    SelectStep(i64),
    SelectRow(i64),
    BlockYank,
    BlockPaste,
    BlockDelete,
    OpenBlockMenu,
    OpenBlockWrite,
    OpenBlockFill,
    OpenCrypt,
    BlockCopy,
    BlockMove,
    BlockInsert,
    OpenBlockRead,
    ToggleSplitView,
    /// Jump to numbered slot 1-8.
    JumpSlot(u8),
    /// Prompt for a digit, then store the cursor in that slot.
    SetSlotPrompt,
    FindPrev,
    BlockFillZero,
    BookmarkPush,
    BookmarkPop,
    OpenComment,
    OpenNames,
    OpenStrings,
    OpenHistory,
    NopInstruction,
    ColorBlock,
    NextMarker,
    PrevMarker,
    OpenCfg,
    Xref,
    OpenDiff,
    NextDiff,
    PrevDiff,
    OpenStruct,
    OpenReplace,
    OpenInspector,
    OpenCalc,
    OpenAssemble,
    OpenHashes,
    OpenNameBookmark,
    MultiSearch,
    ToggleTheme,
    CycleEncoding,
    ToggleInsert,
    ToggleAddrMode,
    EnterEdit,
    CancelEdit,
    ToggleEditCol,
    InsertByte,
    Save,
    Undo,
    Redo,
    OpenGoto,
    OpenSearch,
    FindNext,
    Help,
    TypeHex(u8),
    TypeAscii(u8),
}

/// Result of recursive-traversal code analysis.
#[derive(Debug, Default)]
struct Analysis {
    /// File offsets that begin a function (call targets + entry/exports).
    functions: BTreeSet<u64>,
    /// Map from target VA to the file offsets of instructions referencing it.
    xrefs: BTreeMap<u64, Vec<u64>>,
}

/// Disassembly targets offered by the arch/bitness menu (`o`).
pub(crate) const DISASM_OPTIONS: [(&str, Option<(Arch, u8)>); 11] = [
    ("auto (detected)", None),
    ("x86  16-bit", Some((Arch::X86, 16))),
    ("x86  32-bit", Some((Arch::X86, 32))),
    ("x86-64", Some((Arch::X86_64, 64))),
    ("ARM64", Some((Arch::Arm64, 64))),
    ("ARM  32-bit", Some((Arch::Arm, 32))),
    ("MIPS  32-bit", Some((Arch::Mips, 32))),
    ("RISC-V  64-bit", Some((Arch::Riscv, 64))),
    ("PowerPC  32-bit", Some((Arch::Ppc, 32))),
    ("PowerPC  64-bit", Some((Arch::Ppc, 64))),
    ("SPARC", Some((Arch::Sparc, 32))),
];

/// Block-menu entries, in display order (see [`Dialog::BlockMenu`] rendering).
pub(crate) const BLOCK_MENU_CMDS: [Command; 8] = [
    Command::OpenBlockWrite,
    Command::OpenBlockRead,
    Command::BlockCopy,
    Command::BlockMove,
    Command::BlockInsert,
    Command::OpenBlockFill,
    Command::BlockFillZero,
    Command::BlockDelete,
];

fn mode_index(m: Mode) -> usize {
    match m {
        Mode::Hex => 0,
        Mode::Code => 1,
        Mode::Text => 2,
    }
}

pub fn mode_at(i: usize) -> Mode {
    [Mode::Hex, Mode::Code, Mode::Text][i % 3]
}

/// A number with HIEW-style base prefix/suffix: hex by default; `0x`/`h` hex,
/// `t` decimal, `o` octal, `i` binary.
fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = s.strip_suffix(['t', 'T']) {
        return rest.parse().ok();
    }
    if let Some(rest) = s.strip_suffix(['o', 'O']) {
        return u64::from_str_radix(rest, 8).ok();
    }
    if let Some(rest) = s.strip_suffix(['i', 'I']) {
        return u64::from_str_radix(rest, 2).ok();
    }
    let rest = s.strip_suffix(['h', 'H']).unwrap_or(s);
    u64::from_str_radix(rest, 16).ok()
}

/// Format a header field, wrapping long values onto indented continuation lines
/// so nothing is clipped by the dialog box. Returns view-only entries.
fn wrap_field(key: &str, value: &str) -> Vec<(String, Option<u64>)> {
    const INDENT: usize = 19;
    const WIDTH: usize = 84;
    let avail = WIDTH.saturating_sub(INDENT).max(8);
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in value.split(' ') {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > avail {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() || lines.is_empty() {
        lines.push(cur);
    }
    let pad = " ".repeat(INDENT);
    let mut out = vec![(format!("{key:<18} {}", lines[0]), None)];
    for l in &lines[1..] {
        out.push((format!("{pad}{l}"), None));
    }
    out
}

/// A one-line label for a PE resource (used for display and filtering).
fn resource_label(r: &hiewlm_core::Resource) -> String {
    format!(
        "{:<14} #{:<8} lang:{:<5} off:{:08X} size:{:>7X}  [Enter extract]",
        r.type_name, r.name, r.lang, r.file_off, r.size
    )
}

/// Sanitize a component for use in an extracted-resource filename.
fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if cleaned.is_empty() { "x".into() } else { cleaned }
}

/// Lowercase hex encoding of a byte slice.
fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Format an import/export entry: address column (if known) then the name.
fn fmt_sym(name: &str, va: u64) -> String {
    if va != 0 {
        format!(".{va:08X}  {name}")
    } else {
        format!("          {name}")
    }
}

/// Sidecar path for a file's colored markers.
fn markers_path(path: &std::path::Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".hiewlm.markers");
    PathBuf::from(s)
}

fn load_markers(path: &std::path::Path) -> Vec<Marker> {
    fs::read_to_string(markers_path(path))
        .ok()
        .and_then(|s| toml::from_str::<MarkerFile>(&s).ok())
        .map(|f| f.markers)
        .unwrap_or_default()
}

/// Replace every occurrence of `needle` in `data` with `repl`; returns the new
/// bytes and the number of replacements.
fn replace_all(data: &[u8], needle: &[u8], repl: &[u8]) -> (Vec<u8>, usize) {
    if needle.is_empty() || data.len() < needle.len() {
        return (data.to_vec(), 0);
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    let mut count = 0;
    while i < data.len() {
        if i + needle.len() <= data.len() && &data[i..i + needle.len()] == needle {
            out.extend_from_slice(repl);
            i += needle.len();
            count += 1;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    (out, count)
}

/// Parse a run of hex byte pairs like "90" or "00 ff 90"; `None` if malformed.
fn parse_hex_bytes(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for tok in input.split_whitespace() {
        if tok.len() % 2 != 0 || tok.is_empty() {
            return None;
        }
        for pair in tok.as_bytes().chunks(2) {
            let s = std::str::from_utf8(pair).ok()?;
            out.push(u8::from_str_radix(s, 16).ok()?);
        }
    }
    (!out.is_empty()).then_some(out)
}

const HELP_TEXT: &str = "\
Every action has a plain-key shortcut; function keys are optional
(many terminals, e.g. macOS, don't send F1-F12).  up/down to scroll.

NAVIGATE
  arrows PgUp PgDn Home End     move / scroll
  Ctrl+Home  Ctrl+End           start / end of file
  g  or  5                      goto  (n, +n, -n, .va, nt)
  + / -                         push / pop bookmark
  k                             name a bookmark
  Backspace                     go back (return stack)

VIEW
  Enter                         cycle Hex / Code / Text
  m  or  4                      mode menu
  a                             toggle offset / VA
  \\                             cycle theme
  E                             cycle text encoding

EDIT
  e  or  3                      edit (Tab hex<->ascii, Esc done)
  Ins                           insert / overwrite
  Ctrl+Z   Ctrl+Y               undo / redo
  w  or  9                      save (atomic, .bak backup)

SEARCH
  /  or  7                      find (highlights all matches)
  n                             find next
  s                             list strings (jumpable)
  x                             search across the whole folder
  X                             replace across the folder (.bak)

BLOCK  (select: * or v, or Shift+arrows)
  y   p   d                     yank / paste / delete
  b                             block menu (write / fill / zero)
  M                             color the block (saved to sidecar)
  ] / [                         jump to next / prev colored marker

CODE  (disassembly)
  f                             follow branch under cursor
  o                             disassemble as x86 / x64 / ARM64 / ...
  6  or  F6                     cross-references to cursor
  N                             NOP the instruction under cursor
  G                             control-flow graph of this function
  ;                             add / edit comment
  H                             jump history

ANALYSIS
  8  or  F8                     header view (info / sections /
                                imports / exports / resources)
  i                             data inspector (int/float, LE+BE)
  =                             calculator (@o/@b/@w/@d/@q operands)
  A                             assemble at cursor (x86/x64, Code mode)
  C                             crypt engine on block (xor/add/rol/...)
  K then 1-8                    set numbered bookmark slot
  Alt+1..8                      jump to numbered slot
  Alt+N                         search backwards (find previous)
  S                             split 2-pane diff view (needs c first)
  h                             hashes (CRC32/MD5/SHA-256/BLAKE3)
  c                             compare with a file (diff); >/< next
  t                             apply a struct template
  F12                           names, slots & functions (members for ZIP/PDF)

MISC
  Ctrl+.  Ctrl+P  Ctrl+L       record / play / loop macro (stops on search-fail)
  ?  or  1                     this help
  q  or  0  or  F10            quit
  Esc                          clear highlight/block, then go back (never quits)

Read-only by default.  The target file is data, never executed.";

/// Case-insensitive substring filter for header pane rows.
fn apply_header_filter(
    raw: Vec<(String, Option<u64>)>,
    filter: &str,
) -> Vec<(String, Option<u64>)> {
    if filter.is_empty() {
        return raw;
    }
    let needle = filter.to_lowercase();
    raw.into_iter().filter(|(l, _)| l.to_lowercase().contains(&needle)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let mut a = App::open(PathBuf::from("/dev/null")).unwrap();
        a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(b"0123456789ABCDEF".to_vec())));
        a
    }

    #[test]
    fn parse_addr_forms() {
        let a = app();
        assert_eq!(a.parse_addr("10"), Some(0x10));
        assert_eq!(a.parse_addr("10t"), Some(10));
        assert_eq!(a.parse_addr("0xff"), Some(255));
        assert_eq!(a.parse_addr("+4"), Some(4));
    }

    #[test]
    fn hex_edit_writes_byte() {
        let mut a = app();
        a.apply(Command::EnterEdit);
        a.apply(Command::TypeHex(0x4));
        a.apply(Command::TypeHex(0x1));
        assert_eq!(a.buffer.read_byte(FileOffset(0)), 0x41);
        assert_eq!(a.cursor, 1);
    }

    #[test]
    fn mode_cycle_matches_hiew() {
        let mut a = app();
        assert_eq!(a.mode, Mode::Hex);
        a.apply(Command::CycleMode);
        assert_eq!(a.mode, Mode::Code);
        a.apply(Command::CycleMode);
        assert_eq!(a.mode, Mode::Text);
        a.apply(Command::CycleMode);
        assert_eq!(a.mode, Mode::Hex);
    }

    #[test]
    fn goto_dialog_moves_cursor() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.handle_key(KeyEvent::from(KeyCode::F(5)));
        a.handle_key(KeyEvent::from(KeyCode::Char('a')));
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(a.cursor, 0x0a);
        assert!(a.dialog.is_none());
    }

    #[test]
    fn f4_menu_switches_mode() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.handle_key(KeyEvent::from(KeyCode::F(4))); // open mode menu
        assert!(a.dialog.is_some());
        a.handle_key(KeyEvent::from(KeyCode::Char('3'))); // pick Text directly
        assert_eq!(a.mode, Mode::Text);
        assert!(a.dialog.is_none());
    }

    #[test]
    fn f4_again_cycles_highlight_then_enter_switches() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.handle_key(KeyEvent::from(KeyCode::F(4))); // menu, highlight = Hex(0)
        a.handle_key(KeyEvent::from(KeyCode::F(4))); // cycle -> Code(1)
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(a.mode, Mode::Code);
    }

    #[test]
    fn letter_and_digit_aliases_work_without_fn_keys() {
        use crossterm::event::{KeyCode, KeyEvent};
        // 'g' opens goto (like F5)
        let mut a = app();
        a.handle_key(KeyEvent::from(KeyCode::Char('g')));
        a.handle_key(KeyEvent::from(KeyCode::Char('8')));
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(a.cursor, 0x08);

        // 'e' enters edit (like F3); '5' opens goto (digit mirrors the Fn-bar)
        let mut b = app();
        b.handle_key(KeyEvent::from(KeyCode::Char('e')));
        assert!(b.editing);
        b.handle_key(KeyEvent::from(KeyCode::Esc)); // leave edit
        assert!(!b.editing);
        b.handle_key(KeyEvent::from(KeyCode::Char('5')));
        assert!(matches!(b.dialog, Some(Dialog::Goto { .. })));

        // 'q' quits from the view
        let mut c = app();
        c.handle_key(KeyEvent::from(KeyCode::Char('q')));
        assert!(c.should_quit);
    }

    fn code_app() -> App {
        // push rbp; mov rbp,rsp; call +6; 6x nop; ret  (16 bytes, x64)
        let data = vec![
            0x55, 0x48, 0x89, 0xe5, 0xe8, 0x06, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0xc3,
        ];
        let mut a = App::open(PathBuf::from("/dev/null")).unwrap();
        a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(data)));
        a.arch = Arch::X86_64;
        a.bits = 64;
        a.visible_rows = 10;
        a
    }

    #[test]
    fn code_mode_disassembles_and_steps_by_instruction() {
        let mut a = code_app();
        a.apply(Command::SetMode(Mode::Code));
        assert_eq!(a.mode, Mode::Code);
        let insns = a.disasm_from(0, 4);
        assert!(insns[0].text.contains("push"));
        assert!(insns[1].text.contains("mov"));
        assert!(insns[2].text.contains("call"));

        // Down steps one instruction: 0 (push,len1) -> 1 (mov)
        a.apply(Command::StepRow(1));
        assert_eq!(a.cursor, 1);
        // -> 4 (call)
        a.apply(Command::StepRow(1));
        assert_eq!(a.cursor, 4);
        // Up steps back one instruction
        a.apply(Command::StepRow(-1));
        assert_eq!(a.cursor, 1);
    }

    #[test]
    fn code_mode_xref_finds_caller() {
        let mut a = code_app();
        a.apply(Command::SetMode(Mode::Code));
        // Recursive analysis from offset 0 sees `call +6` (offset 4) → target VA 15.
        let analysis = a.analyze();
        assert!(analysis.xrefs.get(&15).map(|v| v.contains(&4)).unwrap_or(false));
        // The call target (offset 15) is recorded as a function start.
        assert!(analysis.functions.contains(&15));
    }

    #[test]
    fn comment_set_and_removed() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.handle_key(KeyEvent::from(KeyCode::Char(';')));
        a.handle_key(KeyEvent::from(KeyCode::Char('h')));
        a.handle_key(KeyEvent::from(KeyCode::Char('i')));
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(a.comment_at(0), Some("hi"));
        // Re-open and clear it.
        a.handle_key(KeyEvent::from(KeyCode::Char(';')));
        a.handle_key(KeyEvent::from(KeyCode::Backspace));
        a.handle_key(KeyEvent::from(KeyCode::Backspace));
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(a.comment_at(0), None);
    }

    #[test]
    fn macro_record_and_play() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut a = app(); // "0123456789ABCDEF"
        let ctrl_dot = KeyEvent::new(KeyCode::Char('.'), KeyModifiers::CONTROL);
        a.handle_key(ctrl_dot); // start recording
        a.handle_key(KeyEvent::from(KeyCode::Right)); // cursor 0 -> 1
        a.handle_key(KeyEvent::from(KeyCode::Right)); // -> 2
        a.handle_key(ctrl_dot); // stop
        assert_eq!(a.cursor, 2);
        a.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL)); // replay: +2
        assert_eq!(a.cursor, 4);
    }

    #[test]
    fn cfg_builds_multiple_blocks() {
        // xor eax,eax; test eax,eax; jz +2; inc eax; ret
        let data = vec![0x31, 0xc0, 0x85, 0xc0, 0x74, 0x02, 0xff, 0xc0, 0xc3];
        let mut a = App::open(PathBuf::from("/dev/null")).unwrap();
        a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(data)));
        a.arch = Arch::X86_64;
        a.bits = 64;
        a.disasm_arch = Arch::X86_64;
        a.disasm_bits = 64;
        a.visible_rows = 10;
        a.apply(Command::SetMode(Mode::Code));
        a.open_cfg();
        match &a.dialog {
            Some(Dialog::Message { body, title, .. }) => {
                assert!(title.starts_with("CFG"));
                assert!(body.matches("── block").count() >= 2, "cfg:\n{body}");
                assert!(body.contains("(return)"));
            }
            _ => panic!("expected CFG dialog"),
        }
    }

    #[test]
    fn code_mode_follow_branch_and_back() {
        let mut a = code_app();
        a.apply(Command::SetMode(Mode::Code));
        // Move the cursor onto the `call +6` instruction (offset 4).
        a.apply(Command::StepRow(1)); // -> mov (offset 1)
        a.apply(Command::StepRow(1)); // -> call (offset 4)
        assert_eq!(a.cursor, 4);
        a.apply(Command::FollowBranch); // target is file offset 15
        assert_eq!(a.cursor, 15);
        a.apply(Command::NavBack);
        assert_eq!(a.cursor, 4);
    }

    #[test]
    fn code_mode_opcode_patch_updates_disasm() {
        let mut a = code_app();
        a.apply(Command::SetMode(Mode::Code));
        a.apply(Command::EnterEdit);
        assert!(a.editing);
        // Patch 0x55 (push rbp) -> 0x58 (pop rax).
        a.apply(Command::TypeHex(0x5));
        a.apply(Command::TypeHex(0x8));
        assert_eq!(a.buffer.read_byte(FileOffset(0)), 0x58);
        assert!(a.disasm_from(0, 1)[0].text.contains("pop"));
    }

    #[test]
    fn code_edit_steps_by_byte_not_instruction() {
        let mut a = code_app();
        a.apply(Command::SetMode(Mode::Code));
        a.apply(Command::StepRow(1)); // -> mov at offset 1 (3 bytes)
        assert_eq!(a.cursor, 1);
        a.apply(Command::EnterEdit);
        a.apply(Command::Step(1)); // while editing: byte step, not to next instruction
        assert_eq!(a.cursor, 2);
    }

    #[test]
    fn disasm_override_and_reset() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = code_app();
        a.apply(Command::OpenDisasmMenu);
        assert!(matches!(a.dialog, Some(Dialog::DisasmMenu { .. })));
        a.handle_key(KeyEvent::from(KeyCode::Char('3'))); // option 3 = x86 32-bit
        assert_eq!(a.disasm_arch, Arch::X86);
        assert_eq!(a.disasm_bits, 32);
        assert!(a.disasm_override);
        a.apply(Command::OpenDisasmMenu);
        a.handle_key(KeyEvent::from(KeyCode::Char('1'))); // option 1 = auto
        assert!(!a.disasm_override);
        assert_eq!(a.disasm_arch, a.arch);
    }

    #[test]
    fn code_mode_digits_are_fnbar_not_follow() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = code_app();
        a.apply(Command::SetMode(Mode::Code));
        // '5' must open Goto (Fn-bar alias), not do a follow.
        a.handle_key(KeyEvent::from(KeyCode::Char('5')));
        assert!(matches!(a.dialog, Some(Dialog::Goto { .. })));
    }

    #[test]
    fn block_yank_and_paste() {
        let mut a = app(); // "0123456789ABCDEF"
        a.apply(Command::ToggleMark);
        a.apply(Command::Step(2)); // select offsets 0..=2 = "012"
        a.apply(Command::BlockYank);
        a.mark = None;
        a.cursor = a.buffer.len(); // append position
        a.insert_mode = true;
        a.apply(Command::BlockPaste);
        let v = a.buffer.to_vec();
        assert_eq!(v.len(), 19);
        assert_eq!(&v[16..19], b"012");
    }

    #[test]
    fn block_delete_shrinks_and_clears_mark() {
        let mut a = app();
        a.apply(Command::ToggleMark);
        a.apply(Command::Step(3)); // select "0123"
        a.apply(Command::BlockDelete);
        assert_eq!(a.buffer.to_vec(), b"456789ABCDEF");
        assert!(a.selection().is_none());
    }

    #[test]
    fn block_fill_via_dialog() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.apply(Command::ToggleMark);
        a.apply(Command::Step(2)); // select "012"
        a.apply(Command::OpenBlockFill);
        a.handle_key(KeyEvent::from(KeyCode::Char('9')));
        a.handle_key(KeyEvent::from(KeyCode::Char('0')));
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        let v = a.buffer.to_vec();
        assert_eq!(&v[0..3], &[0x90, 0x90, 0x90]);
        assert_eq!(&v[3..], b"3456789ABCDEF");
    }

    #[test]
    fn header_opens_and_cycles_panes() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.handle_key(KeyEvent::from(KeyCode::Char('8')));
        assert!(matches!(a.dialog, Some(Dialog::Header { pane: HeaderPane::Info, .. })));
        a.handle_key(KeyEvent::from(KeyCode::Tab));
        assert!(matches!(a.dialog, Some(Dialog::Header { pane: HeaderPane::Sections, .. })));
        a.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(a.dialog.is_none());
    }

    #[test]
    fn header_info_enter_jumps_to_entry() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.entry = Some(0x0a); // flat address space -> offset 0x0a
        a.handle_key(KeyEvent::from(KeyCode::Char('8'))); // Header, Info pane
        // Filter to just the "Entry point" line (robust to field-order changes).
        for c in "entry".chars() {
            a.handle_key(KeyEvent::from(KeyCode::Char(c)));
        }
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(a.cursor, 0x0a);
        assert!(a.dialog.is_none());
    }

    #[test]
    fn header_imports_jump_and_filter() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.imports = vec![("alpha".into(), 0x04), ("beta".into(), 0x08)];
        a.handle_key(KeyEvent::from(KeyCode::Char('8')));
        a.handle_key(KeyEvent::from(KeyCode::Right)); // Info -> Sections
        a.handle_key(KeyEvent::from(KeyCode::Right)); // -> Imports
        // Filter by typing "bet" -> only "beta" remains, at sel 0.
        for c in "bet".chars() {
            a.handle_key(KeyEvent::from(KeyCode::Char(c)));
        }
        let entries = a.header_entries(HeaderPane::Imports, "bet");
        assert_eq!(entries.len(), 1);
        a.handle_key(KeyEvent::from(KeyCode::Enter)); // jump to beta @ va 0x08 (flat)
        assert_eq!(a.cursor, 0x08);
    }

    #[test]
    fn bookmark_push_pop() {
        let mut a = app();
        a.cursor = 5;
        a.apply(Command::BookmarkPush);
        a.cursor = 0;
        a.apply(Command::BookmarkPop);
        assert_eq!(a.cursor, 5);
    }

    #[test]
    fn struct_viewer_applies_template() {
        let tpl = std::env::temp_dir().join("hiewlm_tpl.txt");
        std::fs::write(&tpl, "a u16\nb u16\n").unwrap();
        let mut a = app(); // "0123456789ABCDEF"
        a.cursor = 0;
        a.open_struct(tpl.to_str().unwrap());
        match &a.dialog {
            Some(Dialog::JumpList { items, .. }) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[1].1, 2); // second field starts at offset 2
            }
            _ => panic!("expected struct field list"),
        }
        std::fs::remove_file(&tpl).ok();
    }

    #[test]
    fn imphash_is_normalized() {
        let mut a = app();
        a.format = Format::Pe;
        a.imports = vec![("KERNEL32.dll!GetProcAddress".into(), 0)];
        let h1 = a.compute_imphash();
        // Same import in different case / with a stripped extension → same hash.
        a.imports = vec![("kernel32.DLL!getprocaddress".into(), 0)];
        let h2 = a.compute_imphash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn long_field_wraps_without_clipping() {
        let long = "0x8160 [HIGH_ENTROPY_VA DYNAMIC_BASE(ASLR) NX_COMPAT(DEP) GUARD_CF TERMINAL_SERVER_AWARE FORCE_INTEGRITY NO_SEH]";
        let lines = wrap_field("DllCharacteristics", long);
        assert!(lines.len() > 1, "long value should wrap onto multiple lines");
        // No wrapped line exceeds the dialog width.
        assert!(lines.iter().all(|(l, _)| l.chars().count() <= 84));
    }

    #[test]
    fn entropy_bounds() {
        let mut a = app();
        a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(vec![7u8; 2000])));
        assert!(a.range_entropy(0, 2000) < 0.01, "constant data should be ~0");
        let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(uniform)));
        assert!(a.range_entropy(0, 4096) > 7.9, "uniform data should be ~8");
    }

    #[test]
    fn header_has_resources_pane() {
        let a = app();
        // Raw file: no resources, but the pane exists and doesn't panic.
        assert!(a.header_entries(HeaderPane::Resources, "").is_empty());
        // Pane cycle reaches Resources.
        assert_eq!(HeaderPane::Exports.next(), HeaderPane::Resources);
    }

    #[test]
    fn calc_dialog_evaluates() {
        let mut a = app();
        a.apply(Command::OpenCalc);
        assert!(matches!(a.dialog, Some(Dialog::Calc { .. })));
        let ctx = a.calc_ctx();
        assert_eq!(hiewlm_core::calc::eval("2+3*4", &ctx).unwrap(), 14);
        assert_eq!(hiewlm_core::calc::eval("@o + 0x10", &ctx).unwrap(), 0x10);
    }

    #[test]
    fn macro_loop_terminates_on_no_progress() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app(); // 16 bytes
        a.macro_saved = vec![KeyEvent::from(KeyCode::Right)];
        a.cursor = 0;
        a.macro_play_loop();
        // Right advances to the last offset, then no progress → loop stops.
        assert_eq!(a.cursor, a.max_offset());
    }

    #[test]
    fn markers_color_jump_and_persist() {
        let path = std::env::temp_dir().join("hiewlm_markers_test.bin");
        std::fs::write(&path, b"0123456789ABCDEF").unwrap();
        let sidecar = super::markers_path(&path);
        std::fs::remove_file(&sidecar).ok();

        let mut a = App::open(path.clone()).unwrap();
        a.mark = Some(2);
        a.cursor = 4; // selection 2..=4
        a.color_block(0);
        assert_eq!(a.marker_color_at(3), Some(0));
        assert!(a.selection().is_none());

        // Persisted and reloaded.
        let b = App::open(path.clone()).unwrap();
        assert_eq!(b.marker_color_at(3), Some(0));

        // Jump to marker start.
        a.cursor = 0;
        a.jump_marker(true);
        assert_eq!(a.cursor, 2);

        std::fs::remove_file(&sidecar).ok();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn inspector_and_hashes_open() {
        let mut a = app();
        a.apply(Command::OpenInspector);
        match &a.dialog {
            Some(Dialog::Message { body, .. }) => assert!(body.contains("uint32")),
            _ => panic!("expected inspector"),
        }
        a.dialog = None;
        a.apply(Command::OpenHashes);
        match &a.dialog {
            Some(Dialog::Message { body, .. }) => {
                assert!(body.contains("CRC32"));
                assert!(body.contains("SHA-256"));
            }
            _ => panic!("expected hashes"),
        }
    }

    #[test]
    fn named_bookmark_appears_in_names() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.cursor = 6;
        a.handle_key(KeyEvent::from(KeyCode::Char('k'))); // name bookmark
        for c in "loop".chars() {
            a.handle_key(KeyEvent::from(KeyCode::Char(c)));
        }
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(a.names_list().iter().any(|(l, off)| l.contains("loop") && *off == 6));
    }

    /// A plugin-parsed container (ZIP/PDF) lists members via F12 and must not
    /// run function recovery over compressed data.
    #[test]
    fn utf16_search_matches_wide_strings() {
        let a = app();
        let p = a.search_pattern("AB", SearchKind::Utf16).unwrap();
        assert_eq!(p.literal_bytes().unwrap(), &[b'A', 0, b'B', 0]);
    }

    #[test]
    fn instruction_search_assembles_the_pattern() {
        let mut a = app();
        a.disasm_arch = Arch::X86_64;
        a.disasm_bits = 64;
        let p = a.search_pattern("xor eax, eax", SearchKind::Asm).unwrap();
        assert_eq!(p.literal_bytes().unwrap(), &[0x31, 0xC0]);
        // A non-x86 target must say so rather than search for nothing.
        a.disasm_arch = Arch::Arm64;
        assert!(a.search_pattern("nop", SearchKind::Asm).is_err());
    }

    #[test]
    fn search_kind_tab_cycles_all_four() {
        let mut k = SearchKind::Hex;
        let mut seen = vec![k.label()];
        for _ in 0..3 {
            k = k.next();
            seen.push(k.label());
        }
        assert_eq!(seen, vec!["hex", "text", "utf-16", "asm"]);
        assert_eq!(k.next().label(), "hex", "must wrap around");
    }

    #[test]
    fn block_scope_confines_search_to_the_marked_range() {
        let mut a = app(); // "0123456789ABCDEF"
        // "9" lives at offset 9; scope the search to 0..=4 so it must not match.
        a.mark = Some(0);
        a.cursor = 4;
        a.confirm_search("9", SearchKind::Text);
        assert!(a.status.contains("Not found"), "{}", a.status);
        assert_ne!(a.cursor, 9);

        // Without a block, the same search succeeds.
        a.mark = None;
        a.cursor = 0;
        a.search_scope = None;
        a.confirm_search("9", SearchKind::Text);
        assert_eq!(a.cursor, 9, "{}", a.status);
    }

    #[test]
    fn find_prev_searches_backwards() {
        let mut a = app(); // "0123456789ABCDEF"
        a.mark = None;
        a.cursor = 0;
        a.confirm_search("5", SearchKind::Text);
        assert_eq!(a.cursor, 5);
        // Move past it, then search back.
        a.cursor = 12;
        a.apply(Command::FindPrev);
        assert_eq!(a.cursor, 5, "{}", a.status);
    }

    #[test]
    fn numbered_slot_set_and_jump() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut a = app();
        a.cursor = 7;
        a.apply(Command::SetSlotPrompt);
        a.handle_key(KeyEvent::from(KeyCode::Char('3')));
        assert_eq!(a.slots[2], Some(7));

        a.cursor = 0;
        a.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::ALT));
        assert_eq!(a.cursor, 7, "Alt+3 must jump to slot 3");
        // Slots show up in the F12 list.
        assert!(a.names_list().iter().any(|(l, off)| l.contains("slot 3") && *off == 7));
    }

    #[test]
    fn empty_slot_reports_instead_of_jumping_to_zero() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut a = app();
        a.cursor = 5;
        a.handle_key(KeyEvent::new(KeyCode::Char('6'), KeyModifiers::ALT));
        assert_eq!(a.cursor, 5, "cursor must not move for an empty slot");
        assert!(a.status.contains("empty"), "{}", a.status);
    }

    #[test]
    fn block_copy_to_bookmark() {
        let mut a = app();               // buffer: "0123456789ABCDEF"
        a.apply(Command::ToggleMark);
        a.apply(Command::Step(2));       // select "012"
        a.cursor = 8;
        a.apply(Command::BookmarkPush);  // destination = offset 8
        a.cursor = 0;
        a.mark = Some(0);
        a.cursor = 2;
        a.apply(Command::BlockCopy);
        let v = a.buffer.to_vec();
        assert_eq!(v.len(), 19, "copy must grow the file by 3");
        assert_eq!(&v[8..11], b"012");
    }

    #[test]
    fn block_move_rebases_destination_after_the_block() {
        let mut a = app();
        a.cursor = 8;
        a.apply(Command::BookmarkPush);  // destination after the source block
        a.mark = Some(0);
        a.cursor = 2;                    // source = 0..=2 ("012")
        a.apply(Command::BlockMove);
        let v = a.buffer.to_vec();
        assert_eq!(v.len(), 16, "move must not change the file size");
        // "3456789ABCDEF" with "012" reinserted at the rebased destination.
        assert_eq!(String::from_utf8_lossy(&v), "34567012 89ABCDEF".replace(' ', ""));
    }

    #[test]
    fn block_move_into_itself_is_refused() {
        let mut a = app();
        let before = a.buffer.to_vec();
        a.cursor = 1;
        a.apply(Command::BookmarkPush);  // destination inside the block
        a.mark = Some(0);
        a.cursor = 4;
        a.apply(Command::BlockMove);
        assert_eq!(a.buffer.to_vec(), before, "buffer must be untouched");
        assert!(a.status.contains("into itself"), "{}", a.status);
    }

    #[test]
    fn block_insert_uses_clipboard_and_grows_file() {
        let mut a = app();
        a.mark = Some(0);
        a.cursor = 2;
        a.apply(Command::BlockYank);     // clipboard = "012"
        a.mark = None;
        a.cursor = 16;
        a.apply(Command::BlockInsert);
        let v = a.buffer.to_vec();
        assert_eq!(v.len(), 19);
        assert_eq!(&v[16..19], b"012");
    }

    #[test]
    fn block_menu_labels_match_command_order() {
        // Enter indexes BLOCK_MENU_CMDS by the rendered row, so a mismatch
        // would silently run the wrong operation.
        assert_eq!(BLOCK_MENU_CMDS.len(), 8);
    }

    #[test]
    fn crypt_transforms_block_and_round_trips() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        let before = a.buffer.to_vec();
        a.mark = Some(0);
        a.cursor = 3;
        a.apply(Command::OpenCrypt);
        assert!(matches!(a.dialog, Some(Dialog::Crypt { .. })));
        for c in "xor 5a".chars() {
            a.handle_key(KeyEvent::from(KeyCode::Char(c)));
        }
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        let after = a.buffer.to_vec();
        assert_ne!(after[0..4], before[0..4], "block must change");
        assert_eq!(after[4..], before[4..], "bytes outside the block must not");

        // XOR is its own inverse: applying it again restores the block.
        a.mark = Some(0);
        a.cursor = 3;
        a.apply(Command::OpenCrypt);
        for c in "xor 5a".chars() {
            a.handle_key(KeyEvent::from(KeyCode::Char(c)));
        }
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(a.buffer.to_vec(), before);
    }

    #[test]
    fn crypt_without_a_block_is_refused() {
        let mut a = app();
        a.mark = None;
        a.apply(Command::OpenCrypt);
        assert!(a.dialog.is_none());
        assert!(a.status.contains("block"), "{}", a.status);
    }

    #[test]
    fn assemble_patches_instruction_and_pads_with_nops() {
        let mut a = app();
        a.mode = Mode::Code;
        a.disasm_arch = Arch::X86_64;
        a.disasm_bits = 64;
        a.cursor = 0;
        // Preview reports the encoding and the slot it must fit.
        let (bytes, _slot) = a.assemble_preview("xor eax, eax").unwrap();
        assert_eq!(bytes, vec![0x31, 0xC0]);

        a.apply(Command::OpenAssemble);
        assert!(matches!(a.dialog, Some(Dialog::Assemble { .. })));
        for c in "xor eax, eax".chars() {
            a.handle_key(KeyEvent::from(KeyCode::Char(c)));
        }
        a.handle_key(KeyEvent::from(KeyCode::Enter));

        let mut got = [0u8; 2];
        a.buffer.read_at(FileOffset(0), &mut got);
        assert_eq!(got, [0x31, 0xC0]);
        assert!(!a.read_only);
    }

    #[test]
    fn assemble_refuses_when_encoding_exceeds_the_slot() {
        let mut a = app();
        a.mode = Mode::Code;
        a.disasm_arch = Arch::X86_64;
        a.disasm_bits = 64;
        a.cursor = 0;
        let before = {
            let mut b = vec![0u8; 8];
            a.buffer.read_at(FileOffset(0), &mut b);
            b
        };
        a.apply(Command::OpenAssemble);
        // 5 bytes into whatever short instruction sits at offset 0.
        for c in "mov eax, 12345678".chars() {
            a.handle_key(KeyEvent::from(KeyCode::Char(c)));
        }
        a.handle_key(KeyEvent::from(KeyCode::Enter));
        let mut after = vec![0u8; 8];
        a.buffer.read_at(FileOffset(0), &mut after);
        if a.status.contains("won't fit") {
            assert_eq!(before, after, "buffer must be untouched when the patch is refused");
        }
    }

    #[test]
    fn assemble_is_rejected_outside_code_mode() {
        let mut a = app();
        a.mode = Mode::Hex;
        a.apply(Command::OpenAssemble);
        assert!(a.dialog.is_none());
        assert!(a.status.contains("Code mode"), "{}", a.status);
    }

    #[test]
    fn plugin_container_lists_members_not_functions() {
        use hiewlm_core::container::{Container, Member};
        let mut a = app();
        a.container = Some(Container {
            kind: "ZIP archive".into(),
            summary: vec![("Entries".into(), "2".into())],
            members: vec![
                Member::new("a.txt", 0x00, 10, "stored"),
                Member::new("evil.exe", 0x49, 20, "deflate"),
            ],
            findings: vec![hiewlm_core::container::Finding::suspicious("executable member")],
        });
        let names = a.names_list();
        assert!(names.iter().any(|(l, off)| l.contains("evil.exe") && *off == 0x49));
        a.open_names();
        match &a.dialog {
            Some(Dialog::JumpList { title, items, .. }) => {
                assert!(title.starts_with("Members"), "{title}");
                assert!(items.iter().all(|(l, _)| !l.contains("func")));
            }
            _ => panic!("expected members list"),
        }
        // The header Info pane shows container summary + findings.
        let info = a.header_entries(HeaderPane::Info, "");
        assert!(info.iter().any(|(l, _)| l.contains("ZIP archive")));
        assert!(info.iter().any(|(l, _)| l.contains("SUSPICIOUS")));
    }

    #[test]
    fn container_names_list_members_not_functions() {
        let mut a = app();
        a.format = Format::Archive;
        a.exports = vec![("a.txt".into(), 0x00), ("b.txt".into(), 0x49)];
        let names = a.names_list();
        assert!(names.iter().any(|(l, off)| l.contains("member") && l.contains("b.txt") && *off == 0x49));
        // Function recovery must be skipped for containers.
        a.open_names();
        match &a.dialog {
            Some(Dialog::JumpList { title, items, .. }) => {
                assert!(title.starts_with("Members"));
                assert!(items.iter().all(|(l, _)| !l.contains("func")));
            }
            _ => panic!("expected members list"),
        }
    }

    #[test]
    fn theme_and_encoding_cycle() {
        use crate::encoding::Encoding;
        use crate::theme::ThemeKind;
        let mut a = app();
        assert_eq!(a.theme_kind, ThemeKind::Classic);
        a.apply(Command::ToggleTheme);
        assert_eq!(a.theme_kind, ThemeKind::Dark);
        assert_eq!(a.encoding, Encoding::Ascii);
        a.apply(Command::CycleEncoding);
        assert_eq!(a.encoding, Encoding::Cp437);
        assert_eq!(Encoding::Cp437.decode(0x01), '☺');
    }

    #[test]
    fn replace_all_helper() {
        let (out, n) = replace_all(b"aXbXc", b"X", b"YY");
        assert_eq!(n, 2);
        assert_eq!(out, b"aYYbYYc");
    }

    #[test]
    fn strings_list_finds_text() {
        let mut a = app();
        a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(
            b"\x00\x01Hello world\x00\x02".to_vec(),
        )));
        a.apply(Command::OpenStrings);
        match &a.dialog {
            Some(Dialog::JumpList { items, .. }) => {
                assert!(items.iter().any(|(l, off)| l.contains("Hello world") && *off == 2));
            }
            _ => panic!("expected strings list"),
        }
    }

    #[test]
    fn nav_history_records_jumps() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.cursor = 3;
        a.handle_key(KeyEvent::from(KeyCode::Char('g'))); // goto
        for c in "0a".chars() {
            a.handle_key(KeyEvent::from(KeyCode::Char(c)));
        }
        a.handle_key(KeyEvent::from(KeyCode::Enter)); // jump from 3 to 0x0a
        assert!(a.history.contains(&3));
        a.apply(Command::OpenHistory);
        assert!(matches!(a.dialog, Some(Dialog::JumpList { .. })));
    }

    #[test]
    fn nop_overwrites_x86_instruction() {
        let mut a = code_app(); // push rbp (1 byte) at offset 0
        a.apply(Command::SetMode(Mode::Code));
        a.apply(Command::NopInstruction);
        assert_eq!(a.buffer.read_byte(FileOffset(0)), 0x90);
    }

    #[test]
    fn utf16_detect_and_glyph() {
        use crate::encoding::Encoding;
        let wide: Vec<u8> = "Hello".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(Encoding::detect(&wide.repeat(4)), Encoding::Utf16Le);
        assert_eq!(Encoding::wide_glyph(b'H', 0), 'H');
    }

    #[test]
    fn multi_search_finds_matching_file() {
        let dir = std::env::temp_dir().join("hiewlm_multi_test");
        std::fs::create_dir_all(&dir).unwrap();
        let f1 = dir.join("open.bin");
        let f2 = dir.join("hit.bin");
        std::fs::write(&f1, b"nothing here").unwrap();
        std::fs::write(&f2, b"xxNEEDLExx").unwrap();

        let mut a = App::open(f1).unwrap();
        a.last_pattern = Some((Pattern::from_text("NEEDLE"), Direction::Forward));
        a.multi_search();
        match &a.dialog {
            Some(Dialog::FileHits { items, .. }) => {
                assert!(items.iter().any(|(l, _, off)| l.contains("hit.bin") && *off == 2));
            }
            _ => panic!("expected file hits"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_picker_selects_diff_file() {
        use crossterm::event::{KeyCode, KeyEvent};
        let dir = std::env::temp_dir().join("hiewlm_pick_test");
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        std::fs::write(&a, b"AAAA").unwrap();
        std::fs::write(&b, b"AABA").unwrap();

        let mut app = App::open(a.clone()).unwrap();
        app.apply(Command::OpenDiff); // opens the picker in a's directory
        let idx = match &app.dialog {
            Some(Dialog::FilePicker { entries, purpose: PickPurpose::Diff, .. }) => {
                entries.iter().position(|e| e.name == "b.bin").expect("b.bin listed")
            }
            _ => panic!("expected file picker"),
        };
        for _ in 0..idx {
            app.handle_key(KeyEvent::from(KeyCode::Down));
        }
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(app.has_diff());
        assert_eq!(app.diff_name, "b.bin");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn diff_detects_and_navigates() {
        let a_path = std::env::temp_dir().join("hiewlm_diff_a.bin");
        let b_path = std::env::temp_dir().join("hiewlm_diff_b.bin");
        std::fs::write(&a_path, b"AAAA").unwrap();
        std::fs::write(&b_path, b"AABA").unwrap(); // differs at offset 2

        let mut app = App::open(a_path.clone()).unwrap();
        app.open_diff(b_path.to_str().unwrap());
        assert!(app.has_diff());
        assert!(!app.byte_differs(0));
        assert!(app.byte_differs(2));

        app.cursor = 0;
        app.next_diff(true);
        assert_eq!(app.cursor, 2);

        std::fs::remove_file(&a_path).ok();
        std::fs::remove_file(&b_path).ok();
    }

    #[test]
    fn esc_backs_out_without_quitting() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        // Selection active -> Esc clears it, does not quit.
        a.apply(Command::ToggleMark);
        a.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(a.selection().is_none());
        assert!(!a.should_quit);
        // Search highlight active -> Esc clears it, does not quit.
        a.confirm_search("2", SearchKind::Text);
        assert!(!a.search_hits(0, a.buffer.len()).is_empty());
        a.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(a.search_hits(0, a.buffer.len()).is_empty());
        assert!(!a.should_quit);
        // Nothing active -> Esc still does not quit.
        a.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(!a.should_quit);
    }

    #[test]
    fn esc_returns_to_previous_position() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app(); // "0123456789ABCDEF"
        a.cursor = 2;
        // A goto records the origin (2) and moves to the destination (10).
        a.confirm_goto("a");
        assert_eq!(a.cursor, 10);
        // With no transient state active, Esc walks back to where we jumped from.
        a.handle_key(KeyEvent::from(KeyCode::Esc));
        assert_eq!(a.cursor, 2, "Esc should return to the pre-jump position");
        assert!(!a.should_quit);
        // Once history is exhausted, Esc reports it and still never quits.
        a.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(a.status.contains("Nothing to go back to"), "{}", a.status);
        assert!(!a.should_quit);
    }

    #[test]
    fn esc_clears_transient_state_before_going_back() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.cursor = 1;
        a.confirm_goto("8"); // origin 1 recorded, cursor -> 8
        a.apply(Command::ToggleMark); // start a selection at 8
        a.cursor = 12;
        // First Esc clears the selection but must NOT move the cursor yet.
        a.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(a.selection().is_none());
        assert_eq!(a.cursor, 12);
        // Second Esc now goes back to the jump origin.
        a.handle_key(KeyEvent::from(KeyCode::Esc));
        assert_eq!(a.cursor, 1);
    }

    #[test]
    fn search_highlights_all_matches() {
        let mut a = app(); // "0123456789ABCDEF" has one '5'
        a.confirm_search("5", SearchKind::Text);
        let hits = a.search_hits(0, a.buffer.len());
        assert_eq!(hits, vec![(5, 5)]);
    }

    #[test]
    fn mark_and_extend_selection() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app(); // "0123456789ABCDEF"
        a.handle_key(KeyEvent::from(KeyCode::Char('*'))); // mark at 0
        assert_eq!(a.selection(), Some((0, 0)));
        for _ in 0..3 {
            a.handle_key(KeyEvent::from(KeyCode::Right)); // extend to offset 3
        }
        assert_eq!(a.cursor, 3);
        assert_eq!(a.selection(), Some((0, 3))); // 4 bytes selected
        a.handle_key(KeyEvent::from(KeyCode::Char('*'))); // clear
        assert_eq!(a.selection(), None);
    }

    #[test]
    fn shift_arrow_starts_selection() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut a = app();
        a.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::SHIFT));
        assert_eq!(a.selection(), Some((0, 1)));
    }

    #[test]
    fn text_mode_navigation_uses_content_width() {
        let mut a = app();
        a.mode = Mode::Text;
        a.text_cols = 4; // pretend the content area is 4 columns wide
        a.apply(Command::StepRow(1)); // down one visual row = +4 bytes
        assert_eq!(a.cursor, 4);
    }

    #[test]
    fn aliases_do_not_fire_while_ascii_editing() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut a = app();
        a.apply(Command::EnterEdit);
        a.apply(Command::ToggleEditCol); // switch to ASCII column
        a.handle_key(KeyEvent::from(KeyCode::Char('q'))); // must type 'q', not quit
        assert!(!a.should_quit);
        assert_eq!(a.buffer.read_byte(FileOffset(0)), b'q');
    }

    /// Drive the full stack key -> command -> buffer -> disk: edit one byte, save.
    #[test]
    fn edit_and_save_roundtrip() {
        use crossterm::event::{KeyCode, KeyEvent};
        let path = std::env::temp_dir().join("hiewlm_e2e_edit.bin");
        std::fs::write(&path, b"AAAA").unwrap();

        let mut a = App::open(path.clone()).unwrap();
        a.handle_key(KeyEvent::from(KeyCode::F(3))); // enter edit (hex)
        assert!(a.editing);
        a.handle_key(KeyEvent::from(KeyCode::Char('4')));
        a.handle_key(KeyEvent::from(KeyCode::Char('2'))); // byte0 = 0x42
        a.handle_key(KeyEvent::from(KeyCode::F(9))); // save

        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk, b"BAAA");

        std::fs::remove_file(&path).ok();
    }
}
