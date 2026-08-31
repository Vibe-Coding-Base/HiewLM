# Changelog

All notable changes to hiewLM. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Triage screen** (`2`) and `hiewlmc triage`: one verdict from hashes
  (MD5/SHA-1/SHA-256/CRC32/ssdeep/imphash/rich/authentihash), packer and builder
  identification, structural anomalies, import capabilities, indicators and an
  entropy map. Text, JSON or Markdown output; a directory is ranked worst-first.
- **Document and archive analysis** as a fourth view mode: OLE2, OOXML, RTF, PDF
  and ZIP, with a navigable structure tree, decompressed VBA macro source, and
  the findings that decide whether a file is a lure. Also `hiewlmc office`.
- **YARA scanning** via yara-x (`--features yara`), feeding the triage verdict.
- **Encoded-data recovery**: single-byte key hunting (`Alt+X`), repeating-XOR key
  recovery (`Alt+K`), and a view lens (`L`) that decodes hex, text and
  disassembly without modifying the file.
- **Stack-string reconstruction** (`Alt+S`) and disassembly annotated with the
  imported API a call reaches and the string a data reference points at.
- **Notes that survive**: comments, bookmarks, slots and markers keyed by the
  sample's SHA-256, so they follow the file through renames and moves.
- **ELF and Mach-O structural checks** on a par with the PE ones.
- **Detection rules as data** — 359 API, 83 packer, 283 indicator and 210
  document rules in text files, overridable from the config directory.
  `hiewlmc rules` shows what is loaded.
- **Findings drill-down**: a document finding backed by many hits shows
  `[Enter: N matches]`, and opens the list with the text each one matched — the
  1874 URLs in a PDF, not just the count. Also `hiewlmc office --matches`.
- **About screen** (`V`): version, author, license, build features, loaded rule
  counts and the paths in use.
- Command palette (`:`), folder triage (`F`), open-another-file (`O`),
  system-clipboard copy over OSC 52 (`Y`), case-insensitive search, search
  history, list-all-matches, and a context-sensitive Fn-bar.

### Changed

- **The sample is read-only until unlocked** (`Ctrl+W` or `--rw`). Previously the
  read-only indicator was cosmetic and paste/delete modified the buffer while the
  status line still claimed "RO".
- PDF and ZIP moved out of the container plugin registry into the document
  analyser, which gives them a structure view instead of a flat member list.
  `--plugin pdf|zip` is still accepted so existing scripts do not break.
- Heavy dependencies (YARA, Rhai, wasmtime) are opt-in: `hiewlmc` is 8.8 MB
  instead of 15 MB by default, `--features full` for everything.
- Popups scroll sideways; long strings are no longer truncated at the panel edge.
- Build artifacts are named `os-arch` rather than `host`.
- Repository standardised: `assets/` for samples and templates, license texts
  present, lockfile committed, rustfmt-clean, CI on three platforms.

### Fixed

- A folder pass read and hashed every file in full: the six largest files in a
  Downloads directory cost forty seconds between them, during which the UI had
  not started and keystrokes queued up — so `q` appeared to hang. Files over
  64 MB are now listed as `not scanned` instead of being hashed in full, the
  pass uses fewer bytes than a single-file report, and `hiewlm_fmt::detect_bytes`
  removed a redundant multi-megabyte read per file. 86 files: 40 s → 3.2 s.
- PDF analysis lowercased a copy of the whole file and then searched it once per
  rule; a 23 MB PDF took 2.5 s. One case-insensitive pass over the file for the
  whole rule table takes 250 ms.
- `q` inside a filterable popup types into the filter, which is correct but left
  no way to quit from the folder queue. `Ctrl+Q` and `F10` now quit from
  anywhere.
- PDF name markers matched inside longer names: `/AA` matched 278 times inside
  `/AAAAAA+ArialMT` in one real document, reporting auto-run actions that were
  not there. A name must now end at a delimiter.

- `N` (one Shift away from the `n` used while searching) overwrote bytes with
  NOPs; it now means "find previous" and NOP moved to `Alt+F2`.
- The block menu navigated only the first four of its eight entries.
- `Doc` mode was unreachable from the mode menu, whose list and wrap-around were
  still written for three modes.
- `m` was documented as the mode-menu alias but never mapped.
- Jumpable lists (strings, names, xrefs) had no filter and no paging — a 20,000
  entry list was navigable one line at a time.
- PE `TimeDateStamp` was read from the wrong COFF offset.
- `.bss` was reported as packer-filled without checking
  `IMAGE_SCN_CNT_UNINITIALIZED_DATA`.
- A product name appearing in a file was treated as evidence of a packer; hiewLM
  identified itself as Themida-protected from its own rule table.
- Ubiquitous CRT APIs were scored as strong signals, making every Rust and MSVC
  binary look armed.
