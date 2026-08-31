//! Editor state and command handling — independent of rendering (design §5.3).

use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use hiewlm_asm::{Disassembler, Flow, Insn};
use hiewlm_core::{
    find, find_all, AddressSpace, Arch, Direction, EditBuffer, FileOffset, FileSource, Format,
    Pattern,
};
use hiewlm_triage::Pane as TriagePane;
use serde::{Deserialize, Serialize};

// The editor state is one type with many concerns; each concern lives in its
// own file and adds its methods through `impl super::App`. Rust lets a module's
// descendants see its private items, so nothing had to be widened to do this.
mod analysis;
mod copy;
mod dialogs;
mod docview;
mod help;
mod hunt;
mod triageview;

#[cfg(test)]
mod tests;

pub use help::palette_matches;
use help::HELP_TEXT;
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

/// Rows a PgUp/PgDn moves inside a scrollable dialog list.
const LIST_PAGE: usize = 10;

/// Bytes read per instruction when disassembling a window (x86 max instruction len).
const MAX_INSN_LEN: usize = 15;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Hex,
    Code,
    Text,
    /// Document structure: OLE storages, OOXML parts, RTF objects, macros.
    /// Only reachable when a document parser claimed the file.
    Doc,
}

impl Mode {
    /// HIEW's cycle: Hex -> Code -> Text -> (Doc) -> Hex (the Enter key).
    /// Doc is in the cycle only for files that have a structure to show; the
    /// caller skips it otherwise.
    fn next(self) -> Self {
        match self {
            Mode::Hex => Mode::Code,
            Mode::Code => Mode::Text,
            Mode::Text => Mode::Doc,
            Mode::Doc => Mode::Hex,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Mode::Hex => "hex",
            Mode::Code => "code",
            Mode::Text => "text",
            Mode::Doc => "doc",
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
    /// ASCII text, ignoring case.
    TextI,
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
            SearchKind::TextI => "text/i",
            SearchKind::Utf16 => "utf-16",
            SearchKind::Asm => "asm",
        }
    }

    /// Tab cycles through the kinds.
    pub fn next(self) -> Self {
        match self {
            SearchKind::Hex => SearchKind::Text,
            SearchKind::Text => SearchKind::TextI,
            SearchKind::TextI => SearchKind::Utf16,
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

/// Panes of the document view, in tab order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DocPane {
    Structure,
    Findings,
    Macros,
    Info,
}

impl DocPane {
    pub const ALL: [DocPane; 4] = [
        DocPane::Structure,
        DocPane::Findings,
        DocPane::Macros,
        DocPane::Info,
    ];

    pub fn label(self) -> &'static str {
        match self {
            DocPane::Structure => "Structure",
            DocPane::Findings => "Findings",
            DocPane::Macros => "Macros",
            DocPane::Info => "Info",
        }
    }

    pub fn next(self) -> Self {
        let i = Self::ALL.iter().position(|&p| p == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let i = Self::ALL.iter().position(|&p| p == self).unwrap_or(0);
        Self::ALL[(i + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// What to do with the file chosen in a [`Dialog::FilePicker`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PickPurpose {
    Diff,
    StructTemplate,
    /// A YARA rule file (or a directory of them) to scan with.
    YaraRules,
    /// Another sample to open in place of this one.
    Open,
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
    Goto {
        input: String,
    },
    Search {
        input: String,
        kind: SearchKind,
    },
    Calc {
        input: String,
    },
    /// Assemble-at-cursor: type an instruction, see the encoding, Enter patches.
    Assemble {
        input: String,
    },
    ModeMenu {
        selected: usize,
    },
    DisasmMenu {
        selected: usize,
    },
    ColorMenu {
        selected: usize,
    },
    BlockMenu {
        selected: usize,
    },
    /// Copy something to the system clipboard (OSC 52).
    CopyMenu {
        selected: usize,
    },
    BlockWrite {
        input: String,
    },
    BlockFill {
        input: String,
    },
    /// Crypt engine: XOR/ADD/ROL/… recipe applied to the selected block.
    Crypt {
        input: String,
    },
    /// The same recipe syntax, but applied to the *view* instead of the bytes.
    Lens {
        input: String,
    },
    /// Fuzzy command launcher (`:`) — every command by name, for the ones whose
    /// letter you do not remember.
    Palette {
        input: String,
        sel: usize,
    },
    /// Plaintext recovered from under a single-byte transform: Enter jumps there
    /// and puts the recovering recipe on the lens in one step.
    XorHits {
        items: Vec<(String, u64, String)>,
        sel: usize,
        filter: String,
    },
    /// Waiting for a digit 1-8 naming the slot to store the cursor in.
    BookmarkSlot,
    Header {
        pane: HeaderPane,
        sel: usize,
        filter: String,
    },
    /// The triage screen: one keystroke, every signal that decides whether this
    /// sample is worth opening. Panes mirror [`hiewlm_triage::Pane`].
    Triage {
        pane: TriagePane,
        sel: usize,
        filter: String,
    },
    /// Scrollable read-only text (help, inspector, hashes).
    Comment {
        input: String,
    },
    NameBookmark {
        input: String,
    },
    /// An interactive directory browser used to pick an existing file.
    FilePicker {
        dir: PathBuf,
        entries: Vec<PickEntry>,
        sel: usize,
        purpose: PickPurpose,
    },
    /// A selectable list of labelled offsets to jump to (names, xrefs, …).
    /// `filter` narrows it as you type — these lists routinely hold thousands of
    /// entries (strings, functions), and arrowing through them is not triage.
    /// `sel` indexes the *filtered* view.
    JumpList {
        title: String,
        items: Vec<(String, u64)>,
        sel: usize,
        filter: String,
    },
    /// Multi-file search results; Enter opens the file at the match.
    FileHits {
        title: String,
        items: Vec<(String, PathBuf, u64)>,
        sel: usize,
        filter: String,
    },
    Message {
        title: String,
        body: String,
        scroll: usize,
    },
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
    /// Structure from a user-supplied container plugin, if one claimed the file.
    /// ZIP, PDF and Office are handled by the document analyser now, which gives
    /// them a navigable view; this stays as the extension point.
    pub container: Option<hiewlm_core::Container>,
    /// Parsed document structure, when the file is an Office document.
    pub document: Option<hiewlm_office::Document>,
    pub doc_pane: DocPane,
    pub doc_sel: usize,
    /// Horizontal scroll for every list-shaped view and popup. Long lines used
    /// to be truncated at the panel edge, which silently hid the end of exactly
    /// the strings worth reading.
    pub hscroll: usize,
    /// Content key (SHA-256 of the sample) the persistent notes hang off, so
    /// renaming or moving the file never loses an hour of annotation.
    notes_key: String,
    /// VA -> symbol name, for annotating disassembly (imports and exports).
    sym_by_va: BTreeMap<u64, String>,
    /// Recently used search patterns; Up/Down in the find dialog walks them.
    search_history: Vec<String>,
    /// Position in `search_history` while browsing it (0 = not browsing).
    search_hist_pos: usize,
    /// Rule file/folder from the config, scanned by `R` without prompting.
    default_yara_rules: Option<PathBuf>,
    /// A non-destructive view transform: bytes are decoded on their way to the
    /// screen (and to the disassembler), the buffer is never touched. This is
    /// how you read an XOR-ed config or unpack a stub visually without
    /// committing a patch you would then have to undo.
    lens: Option<(hiewlm_core::CryptRecipe, String)>,
    /// Cached triage report (computed on first use — it hashes the whole file).
    triage: Option<hiewlm_triage::TriageReport>,
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
    /// The write lock. A malware sample is evidence: hiewLM opens it locked and
    /// refuses every buffer-modifying command until the analyst unlocks with
    /// Ctrl+W (or starts with `--rw`). This is a real guard, not a status flag.
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
        let source =
            FileSource::open(&path).with_context(|| format!("cannot open {}", path.display()))?;
        let buffer = EditBuffer::new(Arc::new(source));

        let file_mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| hiewlm_core::format_unix(d.as_secs() as i64));

        // Notes are keyed by content, so they follow the bytes rather than the
        // path. The legacy per-path marker sidecar is imported once.
        let notes_key = crate::notes::content_key(&buffer);
        let mut notes = crate::notes::load(&notes_key).unwrap_or_default();
        notes.key = notes_key.clone();
        notes.last_path = path.to_string_lossy().into_owned();
        if notes.markers.is_empty() {
            let legacy = load_markers(&path);
            if !legacy.is_empty() {
                notes.markers = legacy;
                let _ = crate::notes::save(&notes);
            }
        }
        let restored = (!notes.is_empty()).then(|| notes.summary());
        let markers = notes.markers.clone();
        let comments: BTreeMap<u64, String> = notes.comments.iter().cloned().collect();
        let named_bookmarks = notes.bookmarks.clone();
        let mut slots: [Option<u64>; 8] = [None; 8];
        for (n, off) in &notes.slots {
            if (1..=8).contains(n) {
                slots[(*n - 1) as usize] = Some(*off);
            }
        }

        // Config file overrides; otherwise auto-detect the text encoding.
        let cfg = crate::config::Config::load();
        let theme_kind = cfg.theme_kind().unwrap_or(crate::theme::ThemeKind::Classic);
        let bytes_per_row = cfg
            .bytes_per_row
            .filter(|&n| (4..=64).contains(&n))
            .unwrap_or(16);
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
            reg.enable(&cfg.plugins());
            let cap = buffer.len().min(256 * 1024 * 1024) as usize;
            let mut data = vec![0u8; cap];
            buffer.read_at(FileOffset(0), &mut data);
            reg.parse(&data).map(|(_, c)| c)
        } else {
            None
        };

        // Documents are parsed up front: it is cheap, and whether a file is a
        // macro-bearing document decides the whole session.
        let document = {
            let cap = buffer.len().min(64 * 1024 * 1024) as usize;
            let mut data = vec![0u8; cap];
            buffer.read_at(FileOffset(0), &mut data);
            hiewlm_office::parse(&data)
        };

        let ready = match &restored {
            Some(summary) => format!("Notes restored: {summary}  ·  1/? help · 2 triage · q quit"),
            None => String::new(),
        };
        let ready = if !ready.is_empty() {
            ready
        } else {
            match &container {
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
            }
        };

        // VA -> name, so a call through the IAT can be shown by name.
        let mut syms: BTreeMap<u64, String> = BTreeMap::new();
        for (name, va) in imports.iter().chain(exports.iter()) {
            if *va != 0 {
                syms.entry(*va).or_insert_with(|| name.clone());
            }
        }

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
            sym_by_va: syms,
            search_history: Vec::new(),
            search_hist_pos: 0,
            default_yara_rules: cfg.yara_rules.clone(),
            document,
            doc_pane: DocPane::Structure,
            doc_sel: 0,
            hscroll: 0,
            lens: None,
            triage: None,
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
            notes_key,
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
            slots,
            search_scope: None,
            named_bookmarks,
            comments,
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

    /// Open a *directory*: rank its samples and show the queue straight away.
    ///
    /// `hiewlm ~/samples/` is how a triage session actually starts — with a
    /// folder, not a file. The highest-scoring sample is opened underneath, so
    /// closing the list leaves you somewhere useful.
    pub fn open_folder(dir: PathBuf) -> Result<Self> {
        let mut files: Vec<PathBuf> = fs::read_dir(&dir)
            .with_context(|| format!("cannot read {}", dir.display()))?
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .map(|e| e.path())
            .collect();
        files.sort();
        let first = files
            .into_iter()
            .find(|p| FileSource::open(p).is_ok())
            .ok_or_else(|| anyhow::anyhow!("no readable files in {}", dir.display()))?;
        let mut app = App::open(first)?;
        app.apply(Command::FolderTriage);
        // Opening the worst one first matches the ranking the list just showed.
        if let Some(Dialog::FileHits { items, .. }) = &app.dialog {
            if let Some((_, path, _)) = items.first().cloned() {
                if path != app.path {
                    let dialog = app.dialog.take();
                    app.reload(path, 0);
                    app.dialog = dialog;
                }
            }
        }
        Ok(app)
    }

    /// Version, author and how this build was configured.
    fn open_about(&mut self) {
        self.dialog = Some(Dialog::Message {
            title: "About".into(),
            body: help::about_text(&self.path),
            scroll: 0,
        });
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

    /// Gate for every command that modifies the buffer. Returns false (and says
    /// why) while the sample is locked, so a stray keystroke can never alter
    /// evidence.
    fn ensure_writable(&mut self) -> bool {
        if self.read_only {
            self.set_status("READ-ONLY: sample is locked · Ctrl+W unlocks (or start with --rw).");
            return false;
        }
        true
    }

    fn toggle_writable(&mut self) {
        self.read_only = !self.read_only;
        if self.read_only {
            self.editing = false;
            self.set_status("LOCKED: read-only — the sample cannot be modified.");
        } else {
            self.set_status("UNLOCKED: writes allowed. Ctrl+W re-locks · F9 saves (.bak kept).");
        }
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
        if !self.ensure_writable() {
            return;
        }
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
        self.set_status(format!(
            "Pasted {n} bytes ({} mode).",
            if self.insert_mode {
                "insert"
            } else {
                "overwrite"
            }
        ));
    }

    fn block_delete(&mut self) {
        if !self.ensure_writable() {
            return;
        }
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
                self.dialog = Some(Dialog::Crypt {
                    input: input.to_string(),
                });
            }
        }
    }

    /// Transform the selected block in place with a crypt recipe. The key index
    /// is block-relative, so a repeating key lines up with the block start.
    fn apply_crypt(&mut self, recipe: &hiewlm_core::crypt::Recipe) {
        if !self.ensure_writable() {
            return;
        }
        let Some((s, e)) = self.require_selection() else {
            return;
        };
        let len = (e - s + 1) as usize;
        let mut data = vec![0u8; len];
        self.buffer.read_at(FileOffset(s), &mut data);
        recipe.apply(&mut data, 0);
        self.buffer.overwrite(FileOffset(s), &data);
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
        if !self.ensure_writable() {
            return;
        }
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
        if !self.ensure_writable() {
            return;
        }
        let bytes = if self.clipboard.is_empty() {
            vec![0u8; 1]
        } else {
            self.clipboard.clone()
        };
        let at = self.cursor;
        self.buffer.insert(FileOffset(at), &bytes);
        self.set_status(format!(
            "Inserted {} byte(s) at {}{}",
            bytes.len(),
            self.display_addr(at),
            if self.clipboard.is_empty() {
                " (zero; yank with y to insert data)"
            } else {
                ""
            }
        ));
    }

    /// Insert a file's contents at the cursor (HIEW Ctrl+F2).
    fn read_file_into_buffer(&mut self, path: &std::path::Path) {
        if !self.ensure_writable() {
            return;
        }
        match std::fs::read(path) {
            Ok(data) if data.is_empty() => self.set_status(format!("{} is empty.", path.display())),
            Ok(data) => {
                let at = self.cursor;
                self.buffer.insert(FileOffset(at), &data);
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
        if !self.ensure_writable() {
            return;
        }
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
        let secs: Vec<(u64, u64)> = self
            .address_space
            .sections()
            .iter()
            .map(|s| (s.file_off, s.size))
            .collect();
        self.section_entropy = secs
            .iter()
            .map(|&(o, l)| self.range_entropy(o, l))
            .collect();
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
        // Build markers can be anywhere in the image, so the whole (bounded)
        // file is scanned, not just the entry point.
        let cap = self.buffer.len().min(64 * 1024 * 1024) as usize;
        let mut file = vec![0u8; cap];
        self.buffer.read_at(FileOffset(0), &mut file);
        let r = hiewlm_core::packer::detect(&entry, &sections, self.imports.len(), &file);
        (!r.indicators.is_empty() || r.identified()).then(|| r.summary())
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

        let scope = if self.selection().is_some() {
            "selection"
        } else {
            "whole file"
        };
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
        self.dialog = Some(Dialog::Message {
            title: "Hashes".into(),
            body,
            scroll: 0,
        });
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

    /// Search the last pattern across every file under the current directory
    /// (recursively, budgeted). Lists the first match per file.
    fn multi_search(&mut self) {
        let Some((pattern, _)) = self.last_pattern.clone() else {
            self.set_status("Search first (/), then x to search all files in the folder.");
            return;
        };
        let root = self
            .path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
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
                    if entry
                        .metadata()
                        .map(|m| m.len() > 64 * 1024 * 1024)
                        .unwrap_or(true)
                    {
                        continue;
                    }
                    if let Ok(src) = FileSource::open(&path) {
                        let buf = EditBuffer::new(Arc::new(src));
                        if let Some(hit) = find(&buf, &pattern, FileOffset(0), Direction::Forward) {
                            let name = path
                                .strip_prefix(&root)
                                .unwrap_or(&path)
                                .to_string_lossy()
                                .into_owned();
                            hits.push((
                                format!("{name}  @ {:08X}", hit.get()),
                                path.clone(),
                                hit.get(),
                            ));
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
            filter: String::new(),
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
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[0] as i8,
            b[0],
            i16::from_le_bytes([b[0], b[1]]),
            i16::from_be_bytes([b[0], b[1]]),
            u16le,
            u16be,
            u32le as i32,
            u32be as i32,
            u32le,
            u32be,
            u64le as i64,
            u64le,
            u64be,
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
        let mut entries = vec![PickEntry {
            name: "..".into(),
            is_dir: true,
        }];
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
        self.dialog = Some(Dialog::FilePicker {
            dir,
            entries,
            sel: 0,
            purpose,
        });
    }

    fn picker_pick(&mut self, purpose: PickPurpose, path: &str) {
        self.dialog = None;
        match purpose {
            PickPurpose::Diff => self.open_diff(path),
            PickPurpose::StructTemplate => self.open_struct(path),
            PickPurpose::ReadFile => self.read_file_into_buffer(std::path::Path::new(path)),
            PickPurpose::YaraRules => self.run_yara(std::path::Path::new(path)),
            PickPurpose::Open => self.reload(PathBuf::from(path), 0),
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
                    format!(
                        "{:<18} {}  = {}",
                        f.name,
                        self.display_addr(f.offset),
                        f.value
                    ),
                    f.offset,
                )
            })
            .collect::<Vec<_>>();
        self.dialog = Some(Dialog::JumpList {
            title: format!(
                "Struct @ {} ({} bytes)",
                self.display_addr(base),
                tpl.total_size()
            ),
            items,
            sel: 0,
            filter: String::new(),
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
        self.markers.push(Marker {
            start,
            end,
            color: idx % crate::theme::Theme::MARKER_COLORS,
        });
        self.mark = None;
        self.save_notes();
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
        self.save_notes();
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
            starts
                .iter()
                .find(|&&s| s > self.cursor)
                .copied()
                .or_else(|| starts.first().copied())
        } else {
            starts
                .iter()
                .rev()
                .find(|&&s| s < self.cursor)
                .copied()
                .or_else(|| starts.last().copied())
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

    /// Persist every hand-made annotation under the sample's content key.
    /// Called after each change, so a crash costs nothing.
    fn save_notes(&self) {
        let notes = crate::notes::Notes {
            key: self.notes_key.clone(),
            last_path: self.path.to_string_lossy().into_owned(),
            markers: self.markers.clone(),
            comments: self.comments.iter().map(|(o, c)| (*o, c.clone())).collect(),
            bookmarks: self.named_bookmarks.clone(),
            slots: self
                .slots
                .iter()
                .enumerate()
                .filter_map(|(i, s)| s.map(|off| (i as u8 + 1, off)))
                .collect(),
        };
        let _ = crate::notes::save(&notes);
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
            self.set_status(format!(
                "Comment set at {} (saved)",
                self.display_addr(self.cursor)
            ));
        }
        self.save_notes();
        self.dialog = None;
    }

    /// Named locations: entry, sections, and user comments.
    fn names_list(&self) -> Vec<(String, u64)> {
        let mut items = Vec::new();
        // A document's parts are named locations like any other.
        if let Some(d) = &self.document {
            for n in &d.nodes {
                if let Some(off) = n.file_off {
                    items.push((
                        format!("{:<9} {}  {}", n.kind, self.display_addr(off), n.path),
                        off,
                    ));
                }
            }
        }
        if let Some(c) = &self.container {
            for m in &c.members {
                items.push((
                    format!(
                        "member    {}  {}  {}",
                        self.display_addr(m.offset),
                        m.name,
                        m.detail
                    ),
                    m.offset,
                ));
            }
        }
        // `ar` archives come from the executable parser, not a plugin.
        if self.format.is_container() {
            for (name, off) in &self.exports {
                items.push((
                    format!("member    {}  {name}", self.display_addr(*off)),
                    *off,
                ));
            }
        }
        if let Some(va) = self.entry {
            if let Some(off) = self.va_to_off(va) {
                items.push((format!("entry     .{va:08X}"), off));
            }
        }
        for s in self.address_space.sections() {
            items.push((
                format!("section   {:<16} .{:08X}", s.name, s.va),
                s.file_off,
            ));
        }
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(off) = slot {
                items.push((
                    format!("slot {}     {}", i + 1, self.display_addr(*off)),
                    *off,
                ));
            }
        }
        for (name, off) in &self.named_bookmarks {
            items.push((
                format!("bookmark  {}  {name}", self.display_addr(*off)),
                *off,
            ));
        }
        for (off, c) in &self.comments {
            items.push((format!("comment   {}  {c}", self.display_addr(*off)), *off));
        }
        items
    }

    /// List the file's strings, jumpable and filterable (HIEW Alt+F6, grown up).
    ///
    /// ASCII *and* UTF-16LE, each tagged with the indicator categories it
    /// matches, so typing `url` in the list filters to the URLs.
    fn open_strings(&mut self) {
        let scan = hiewlm_core::strings::extract_buffer(
            &self.buffer,
            &hiewlm_core::strings::Options {
                min_len: 4,
                ascii: true,
                utf16: true,
                max_results: 50_000,
                max_bytes: 64 * 1024 * 1024,
                only_tagged: false,
            },
        );
        if scan.strings.is_empty() {
            self.set_status("No strings found.");
            return;
        }
        let tagged = scan.strings.iter().filter(|s| !s.kinds.is_empty()).count();
        let items: Vec<(String, u64)> = scan
            .strings
            .iter()
            .map(|f| {
                let tags = if f.kinds.is_empty() {
                    String::new()
                } else {
                    format!("[{}] ", f.kind_list())
                };
                let text: String = f.text.chars().take(160).collect();
                let warn = if f.kinds.is_empty() { "" } else { "!" };
                (
                    format!(
                        "{warn}{} {} {tags}{text}",
                        self.display_addr(f.offset),
                        f.enc.label()
                    ),
                    f.offset,
                )
            })
            .collect();
        let truncated = if scan.truncated { "  [TRUNCATED]" } else { "" };
        self.dialog = Some(Dialog::JumpList {
            title: format!("Strings ({}, {tagged} tagged){truncated}", items.len()),
            items,
            sel: 0,
            filter: String::new(),
        });
        self.set_status("Type to filter (try: url, ip, registry, lolbin, mutex) · Enter jumps");
    }

    /// Replace the instruction under the cursor with NOP padding (HIEW Alt+F2).
    /// x86/x64 = 0x90; ARM64 = the NOP encoding.
    fn nop_instruction(&mut self) {
        if !(self.mode == Mode::Code && self.code_supported()) {
            self.set_status("NOP works in Code mode.");
            return;
        }
        if !self.ensure_writable() {
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
        let filler = if filler.len() == ins.len {
            filler
        } else {
            vec![0x90u8; ins.len]
        };
        self.buffer.overwrite(FileOffset(ins.offset), &filler);
        self.set_status(format!(
            "NOP'd {} byte(s) at {}",
            ins.len,
            self.display_addr(ins.offset)
        ));
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
        if !self.ensure_writable() {
            self.dialog = None;
            return;
        }
        let start = self.cursor_insn_start();
        let (bytes, slot) = match self.assemble_preview(text) {
            Ok(v) => v,
            Err(e) => {
                self.set_status(format!("Assemble: {e}"));
                self.dialog = Some(Dialog::Assemble {
                    input: text.to_string(),
                });
                return;
            }
        };
        if bytes.len() > slot {
            self.set_status(format!(
                "Assemble: {} bytes won't fit the {slot}-byte instruction (use a shorter form).",
                bytes.len()
            ));
            self.dialog = Some(Dialog::Assemble {
                input: text.to_string(),
            });
            return;
        }
        let mut patch = bytes.clone();
        patch.resize(slot, 0x90);
        self.buffer.overwrite(FileOffset(start), &patch);
        let pad = slot - bytes.len();
        self.set_status(format!(
            "Assembled {} byte(s){} at {}",
            bytes.len(),
            if pad > 0 {
                format!(" + {pad} NOP")
            } else {
                String::new()
            },
            self.display_addr(start)
        ));
    }

    fn open_names(&mut self) {
        let mut items = self.names_list();
        // Function recovery is only meaningful for code images, not containers.
        let is_container =
            self.format.is_container() || self.container.is_some() || self.document.is_some();
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
            format!("Parts & names ({})", items.len())
        } else {
            format!("Names & functions ({})", items.len())
        };
        self.dialog = Some(Dialog::JumpList {
            title,
            items,
            sel: 0,
            filter: String::new(),
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
                let Some(ins) = self.disasm_from(off, 1).into_iter().next() else {
                    break;
                };
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
            body.push_str(&format!(
                "── block {bno}  {} ──\n",
                self.display_addr(start)
            ));
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
        let refs = self
            .analyze()
            .xrefs
            .get(&target)
            .cloned()
            .unwrap_or_default();
        if refs.is_empty() {
            self.set_status(format!("No xrefs to {}", self.display_addr(self.cursor)));
            return;
        }
        let items = refs
            .into_iter()
            .map(|off| {
                let text = self
                    .disasm_from(off, 1)
                    .into_iter()
                    .next()
                    .map(|i| i.text)
                    .unwrap_or_default();
                (format!("{}  {text}", self.display_addr(off)), off)
            })
            .collect::<Vec<_>>();
        let title = format!(
            "Xrefs to {} ({})",
            self.display_addr(self.cursor),
            items.len()
        );
        self.dialog = Some(Dialog::JumpList {
            title,
            items,
            sel: 0,
            filter: String::new(),
        });
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
            filter: String::new(),
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
        let dir = self
            .path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let fname = format!(
            "res_{}_{}_{}.bin",
            sanitize(&r.type_name),
            sanitize(&r.name),
            r.lang
        );
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
        self.save_notes();
        self.set_status(format!(
            "Bookmark saved ({} total). F12 to jump.",
            self.named_bookmarks.len()
        ));
        self.dialog = None;
    }

    fn bookmark_pop(&mut self) {
        match self.bookmarks.pop() {
            Some(off) => {
                self.move_to(off);
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
                self.set_status(format!(
                    "Returned to bookmark ({} left).",
                    self.bookmarks.len()
                ));
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
            self.address_space
                .offset_of(hiewlm_core::Va(va))
                .map(|o| o.get())
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
        // Through the lens, so an encrypted stub disassembles as what it will be
        // at runtime without patching the sample first.
        self.view_bytes(off, &mut data);
        Disassembler::new(self.disasm_arch, self.disasm_bits).decode(
            &data,
            off,
            self.va_of(off),
            count,
        )
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
        let target = self
            .disasm_from(start, 1)
            .into_iter()
            .next()
            .and_then(|i| i.target);
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
        if !self.ensure_writable() {
            return;
        }
        if self.buffer.is_empty() {
            self.set_status("Empty file — nothing to edit.");
            return;
        }
        self.editing = true;
        self.nibble = 0;
        if self.mode == Mode::Code {
            self.edit_col = EditCol::Hex;
            self.set_status(
                "EDIT opcode bytes: type hex to patch (disasm updates live) · F9 save · Esc cancel",
            );
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
        if !self.ensure_writable() {
            return;
        }
        self.buffer.insert(FileOffset(self.cursor), &[0]);
        self.editing = true;
        self.set_status("Inserted one 0x00 byte.");
    }

    fn save(&mut self) -> Result<()> {
        if self.read_only {
            self.set_status("READ-ONLY: nothing written · Ctrl+W unlocks.");
            return Ok(());
        }
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
            SearchKind::TextI => Ok(Pattern::from_text_ci(input)),
            SearchKind::Hex => Pattern::from_hex(input).map_err(|_| "Invalid hex string.".into()),
            SearchKind::Utf16 => {
                // UTF-16LE: each unit little-endian, so ASCII gains a 0x00 pad.
                let bytes: Vec<u8> = input.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
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
        if !input.is_empty() && self.search_history.last().map(String::as_str) != Some(input) {
            self.search_history.push(input.to_string());
            if self.search_history.len() > 50 {
                self.search_history.remove(0);
            }
        }
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
            self.search_scope.map_or(true, |(s, e)| {
                h.get() >= s && h.get() + pattern.len() as u64 <= e + 1
            })
        });
        match hit {
            Some(hit) => {
                self.record_jump();
                self.move_to(hit.get());
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
                self.set_status(format!(
                    "Found at {} · Esc clears highlight",
                    self.display_addr(hit.get())
                ));
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

    /// Every dialog opens at the left edge; carrying a scroll offset from the
    /// previous popup into a new one is never what the user meant.
    fn reset_hscroll(&mut self) {
        self.hscroll = 0;
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
        // Quit from anywhere, including a dialog. Five dialogs treat a bare
        // letter as filter input — which is right — so `q` typed at the folder
        // queue lands in the filter and looks like the program has hung.
        if (ctrl && key.code == KeyCode::Char('q')) || key.code == KeyCode::F(10) {
            self.should_quit = true;
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

    // -- Command dispatch --------------------------------------------

    pub fn apply(&mut self, cmd: Command) {
        // A popup opens at the left edge: carrying the previous one's sideways
        // scroll into it is never what the user meant.
        let had_dialog = self.dialog.is_some();
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
                // Doc is only in the cycle for files that have one.
                if self.mode == Mode::Doc && !self.doc_supported() {
                    self.mode = self.mode.next();
                }
                if self.mode == Mode::Code && self.code_supported() {
                    self.enter_code();
                }
            }
            Command::OpenModeMenu => {
                self.dialog = Some(Dialog::ModeMenu {
                    selected: mode_index(self.mode),
                });
                self.set_status("Pick mode: 1 Hex · 2 Code · 3 Text · Enter/arrows · Esc");
            }
            Command::SetMode(m) => {
                if m == Mode::Doc && !self.doc_supported() {
                    self.dialog = None;
                    self.set_status("Not an Office document (no OLE, OOXML or RTF structure).");
                    return;
                }
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
            Command::OpenTriage => {
                self.ensure_triage();
                self.dialog = Some(Dialog::Triage {
                    pane: TriagePane::Overview,
                    sel: 0,
                    filter: String::new(),
                });
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
            Command::OpenCopyMenu => {
                self.dialog = Some(Dialog::CopyMenu { selected: 0 });
                self.set_status("Copy to the system clipboard (works over SSH via OSC 52).");
            }
            Command::CopyItem(i) => self.copy_item(i),
            Command::OpenBlockWrite => {
                if self.selection().is_some() {
                    self.dialog = Some(Dialog::BlockWrite {
                        input: String::new(),
                    });
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
                    self.dialog = Some(Dialog::Crypt {
                        input: String::new(),
                    });
                }
            }
            Command::OpenLens => {
                let current = self
                    .lens
                    .as_ref()
                    .map(|(_, l)| l.clone())
                    .unwrap_or_default();
                self.dialog = Some(Dialog::Lens { input: current });
            }
            Command::XorSearch => self.xor_search(),
            Command::XorKey => self.xor_key(),
            Command::StackStrings => self.open_stack_strings(),
            Command::DocMove(d) => self.doc_move(d),
            Command::DocPageMove(d) => self.doc_move(d * LIST_PAGE as i64),
            Command::DocPane(d) => {
                self.doc_pane = if d > 0 {
                    self.doc_pane.next()
                } else {
                    self.doc_pane.prev()
                };
                self.doc_sel = 0;
            }
            Command::DocActivate => self.doc_activate(),
            Command::HScroll(d) => self.hscroll_by(d),
            Command::OpenBlockFill => {
                if self.selection().is_some() {
                    self.dialog = Some(Dialog::BlockFill {
                        input: String::new(),
                    });
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
            Command::OpenFile => self.open_file_picker(PickPurpose::Open),
            Command::FolderTriage => self.folder_triage(),
            Command::About => self.open_about(),
            Command::OpenPalette => {
                self.dialog = Some(Dialog::Palette {
                    input: String::new(),
                    sel: 0,
                });
                self.set_status("Type a command name · Enter runs it · Esc cancels");
            }
            Command::SearchAll => self.search_all(),
            Command::RunYara => match self.default_yara_rules.clone() {
                Some(p) => self.run_yara(&p),
                None => {
                    self.set_status(
                        "Pick a YARA rule file or folder (set `yara_rules` in config.toml to skip this).",
                    );
                    self.open_file_picker(PickPurpose::YaraRules);
                }
            },
            Command::Xref => self.open_xrefs(),
            Command::OpenDiff => self.open_file_picker(PickPurpose::Diff),
            Command::NextDiff => self.next_diff(true),
            Command::PrevDiff => self.next_diff(false),
            Command::OpenStruct => self.open_file_picker(PickPurpose::StructTemplate),
            Command::OpenInspector => self.open_inspector(),
            Command::OpenCalc => {
                self.dialog = Some(Dialog::Calc {
                    input: String::new(),
                })
            }
            Command::OpenAssemble => {
                if self.mode != Mode::Code {
                    self.set_status("Assemble works in Code mode (Enter cycles mode).");
                } else if !matches!(self.disasm_arch, Arch::X86 | Arch::X86_64) {
                    self.set_status("Assemble supports x86/x86-64 only.");
                } else {
                    self.dialog = Some(Dialog::Assemble {
                        input: String::new(),
                    });
                }
            }
            Command::OpenHashes => self.open_hashes(),
            Command::OpenNameBookmark => {
                self.dialog = Some(Dialog::NameBookmark {
                    input: String::new(),
                })
            }
            Command::MultiSearch => self.multi_search(),
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
                let s = if self.insert_mode {
                    "insert"
                } else {
                    "overwrite"
                };
                self.set_status(format!("Input mode: {s}"));
            }
            Command::ToggleWritable => self.toggle_writable(),
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
            Command::OpenGoto => {
                self.dialog = Some(Dialog::Goto {
                    input: String::new(),
                })
            }
            Command::OpenSearch => {
                let kind = if self.mode == Mode::Text {
                    SearchKind::Text
                } else {
                    SearchKind::Hex
                };
                self.search_hist_pos = 0;
                self.dialog = Some(Dialog::Search {
                    input: String::new(),
                    kind,
                });
                self.set_status("Tab: hex/text/text-i/utf-16/asm · ↑↓ history · Ctrl+A lists all");
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
        if !had_dialog && self.dialog.is_some() {
            self.reset_hscroll();
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
    /// The triage screen (`2` / `T` / F2).
    OpenTriage,
    ToggleMark,
    SelectStep(i64),
    SelectRow(i64),
    BlockYank,
    BlockPaste,
    BlockDelete,
    OpenBlockMenu,
    /// `Y`: copy a hash / the selection / the IOC list to the system clipboard.
    OpenCopyMenu,
    CopyItem(usize),
    OpenBlockWrite,
    OpenBlockFill,
    OpenCrypt,
    /// `L`: view the file through a byte transform without modifying it.
    OpenLens,
    /// `Alt+X`: find plaintext hidden behind a single-byte transform.
    XorSearch,
    /// `Alt+K`: recover a repeating XOR key from the marked block.
    XorKey,
    /// `Alt+S`: rebuild strings this function assembles on the stack.
    StackStrings,
    /// Document view: move the selection, switch pane, follow a node.
    DocMove(i64),
    DocPageMove(i64),
    DocPane(i64),
    DocActivate,
    /// Scroll the current list or popup sideways.
    HScroll(i64),
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
    /// `O`: open another sample without leaving hiewLM.
    OpenFile,
    /// `F`: rank every file in this folder by triage score.
    FolderTriage,
    /// `:`: the command palette.
    OpenPalette,
    /// `V`: version, author and how this build was configured.
    About,
    /// List every match of the last search instead of stepping through them.
    SearchAll,
    /// `R`: scan with YARA rules (from the config path, else pick a file).
    RunYara,
    Xref,
    OpenDiff,
    NextDiff,
    PrevDiff,
    OpenStruct,
    OpenInspector,
    OpenCalc,
    OpenAssemble,
    OpenHashes,
    OpenNameBookmark,
    MultiSearch,
    ToggleTheme,
    CycleEncoding,
    ToggleInsert,
    /// Ctrl+W: lock / unlock the sample for writing (locked at startup).
    ToggleWritable,
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
pub(crate) const BLOCK_MENU_CMDS: [Command; 9] = [
    Command::OpenBlockWrite,
    Command::OpenBlockRead,
    Command::BlockCopy,
    Command::BlockMove,
    Command::BlockInsert,
    Command::OpenBlockFill,
    Command::BlockFillZero,
    Command::BlockDelete,
    Command::NopInstruction,
];

fn mode_index(m: Mode) -> usize {
    match m {
        Mode::Hex => 0,
        Mode::Code => 1,
        Mode::Text => 2,
        Mode::Doc => 3,
    }
}

/// How many modes the mode menu offers. Adding a mode without updating this is
/// how `Doc` shipped unreachable from the menu.
pub const MODES: usize = 4;

pub fn mode_at(i: usize) -> Mode {
    [Mode::Hex, Mode::Code, Mode::Text, Mode::Doc][i % MODES]
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
    if cleaned.is_empty() {
        "x".into()
    } else {
        cleaned
    }
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

/// A readable string from a run of stack bytes: UTF-16LE when every other byte
/// is zero, otherwise ASCII. Both stop at the NUL terminator the code wrote.
fn decode_run(bytes: &[u8], min: usize) -> Option<String> {
    let printable = |b: u8| (0x20..0x7f).contains(&b);

    // UTF-16LE first: an odd trailing byte cannot be part of a wide character.
    let even = bytes.len() & !1;
    let wide = &bytes[..even];
    if !wide.is_empty()
        && wide
            .chunks_exact(2)
            .all(|c| c[1] == 0 && (printable(c[0]) || c[0] == 0))
    {
        let text: String = wide
            .chunks_exact(2)
            .map(|c| c[0])
            .take_while(|&b| b != 0)
            .map(|b| b as char)
            .collect();
        if text.chars().count() >= min {
            return Some(text);
        }
    }

    let text: String = bytes
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .map(|b| b as char)
        .collect();
    (text.chars().count() >= min && text.bytes().all(printable)).then_some(text)
}

/// Shorten a label to `n` characters for a fixed-width column.
fn truncate_label(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).collect::<String>() + "~"
    }
}

/// Indices of the entries whose label contains `filter` (case-insensitive).
/// Shared by every scrollable list so filtering behaves identically everywhere.
pub fn filter_indices<'a, T: 'a>(
    items: &'a [T],
    label: impl Fn(&'a T) -> &'a str,
    filter: &str,
) -> Vec<usize> {
    if filter.is_empty() {
        return (0..items.len()).collect();
    }
    let needle = filter.to_lowercase();
    items
        .iter()
        .enumerate()
        .filter(|(_, it)| label(it).to_lowercase().contains(&needle))
        .map(|(i, _)| i)
        .collect()
}

/// The visible rows of a [`Dialog::JumpList`] under its filter.
pub fn jump_view<'a>(items: &'a [(String, u64)], filter: &str) -> Vec<&'a (String, u64)> {
    filter_indices(items, |it: &(String, u64)| it.0.as_str(), filter)
        .into_iter()
        .map(|i| &items[i])
        .collect()
}

/// Case-insensitive substring filter for header pane rows.
fn apply_header_filter(
    raw: Vec<(String, Option<u64>)>,
    filter: &str,
) -> Vec<(String, Option<u64>)> {
    if filter.is_empty() {
        return raw;
    }
    let needle = filter.to_lowercase();
    raw.into_iter()
        .filter(|(l, _)| l.to_lowercase().contains(&needle))
        .collect()
}
