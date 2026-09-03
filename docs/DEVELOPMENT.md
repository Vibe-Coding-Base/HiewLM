# Developer guide

How hiewLM is put together, how to extend it, and why it is shaped the way it is.
For the long-form design, see [DESIGN.md](DESIGN.md); for what the tool does, see
[USAGE.md](USAGE.md).

- [Getting started](#getting-started)
- [Architecture](#architecture)
- [Adding things](#adding-things)
- [The three pillars](#the-three-pillars)
- [Testing](#testing)
- [Decisions and non-goals](#decisions-and-non-goals)
- [Releasing](#releasing)

---

## Getting started

```sh
cargo build --workspace                  # both binaries
cargo test  --workspace                  # ~350 tests, all fast
cargo clippy --workspace --all-targets
cargo fmt --all
```

The tree is rustfmt-clean and clippy-clean; CI enforces both. `unwrap_used` is a
warning rather than an error, and is expected in tests.

The heavy optional features are slow to compile, so they are off by default:

```sh
cargo build --release --features hiewlm-cli/full
cargo test --workspace --features hiewlm-cli/full,hiewlm-tui/yara
```

## Architecture

Eight crates. The rule is one direction of dependency and no UI below the UI
layer: `hiewlm-core` knows nothing about terminals, and everything that produces
a verdict is reusable from the command line.

```
hiewlm-tui ──┐                     hiewlm-cli ──┐
             ├──► hiewlm-triage ───┤            │
             │        │            │            │
             │        ├──► hiewlm-fmt ──────────┤
             │        ├──► hiewlm-office ───────┤
             │        └──► hiewlm-core ◄────────┘
             └──► hiewlm-asm ──► hiewlm-core
                                 hiewlm-plugin (optional)
```

| Crate | Responsibility |
|---|---|
| `hiewlm-core` | Buffer (memmap + piece table + undo journal), addressing, search, string/IOC extraction, import scoring, ssdeep, XOR key recovery, crypt engine, struct templates, the rule-data loader, the container-plugin trait. No UI, no I/O beyond reading the target. |
| `hiewlm-fmt` | Executable formats: PE/ELF/Mach-O (including fat), COFF, ar, NE/LE/LX/TE/NLM → arch, bits, entry point, offset↔VA map, imports, exports, header fields. Plus the structural detail each format needs for triage (`pe_extra`, `elf_extra`, `macho_extra`). |
| `hiewlm-office` | Documents and archives: OLE2/CFB, OOXML, RTF, PDF, ZIP, and MS-OVBA macro decompression. One `Document` model for all of them. |
| `hiewlm-asm` | Disassembly (iced-x86 and Capstone, plus a WASM decoder) and an x86 text assembler. |
| `hiewlm-triage` | Assembles the verdict from everything above and renders it as panes, text, JSON or Markdown — shared by both front-ends so they cannot disagree. |
| `hiewlm-tui` | The `hiewlm` binary: ratatui/crossterm, state machine, keymap, themes, notes. |
| `hiewlm-cli` | The `hiewlmc` binary. |
| `hiewlm-plugin` | Optional WASM plugin host (wasmtime), fuel-bounded, no filesystem or network. |

### Inside the TUI

`crates/hiewlm-tui/src/app/` is a module directory, not one file. Each concern
adds methods to the same `App` type through `impl super::App` from its own file;
Rust lets a module's descendants see its private items, so this needed no
widening of visibility. Cross-file methods are `pub(super)`.

| File | |
|---|---|
| `mod.rs` | state, `App::open`, navigation, editing, command dispatch |
| `dialogs.rs` | key handling for every dialog, in one place |
| `hunt.rs` | folder triage, search-all, YARA, the view lens |
| `triageview.rs` | building and rendering the triage screen |
| `docview.rs` | the document view |
| `analysis.rs` | stack strings, disassembly annotation |
| `help.rs` | help text and command palette, together so they cannot drift |
| `tests.rs` | the tests |

Every state change goes through `App::apply(Command)`. That is what lets macros
replay, and what makes a test able to drive the editor without a terminal.

## Adding things

### A packer, an API, an indicator, a document signature

Edit a file in `crates/hiewlm-core/data/`. No code change, no rebuild needed by
your users — they can drop the same file in `$XDG_CONFIG_HOME/hiewlm/rules/`.

| File | Format |
|---|---|
| `apis.txt` | `behaviour \| api \| strong\|weak \| note` |
| `packers.txt` | `sig\|section\|marker \| kind \| name \| value` |
| `indicators.txt` | `kind \| value` |
| `documents.txt` | `ole\|ooxml\|rtf\|pdf\|vba-* \| value \| severity \| note` |

Two rules learned the hard way, both worth keeping:

- **A product name is not a signature.** hiewLM once identified *itself* as
  Themida-protected, because its own embedded rule table contains the word. A
  claim about structure ("this is packed") needs structural evidence — an entry
  signature or a section name. Markers answer the identity question instead
  ("what built this").
- **`strong` means "would this alone make me look twice".** `CreateToolhelp32-
  Snapshot` and `SetFileTime` were `strong` until a plain Rust binary turned out
  to import both. Weak entries are still listed, still feed the combination
  rules, and do not raise the score on their own.

### An executable format

Implement the parse in `hiewlm-fmt` returning an `ExecutableModel` (format, arch,
bits, address space, entry, imports, exports, header fields), and add the
structural checks in a `*_extra` module returning `Finding`s with file offsets.
`hiewlm-triage` picks them up automatically.

### A document or archive format

Add a module to `hiewlm-office` and a branch in `parse()`. Produce the shared
`Document`: `nodes` (the structure tree, each with a file offset so `Enter` can
navigate), `findings`, `metadata`, `macros`, `external`. The TUI view and the CLI
command then work with no further changes.

### A command

Add a `Command` variant, handle it in `App::apply`, bind it in `keymap.rs`, and
add a line to `PALETTE` in `app/help.rs` so it is reachable by name. The letter
keyspace is nearly full; the palette is why that is no longer a problem.

### A view

Add a `Mode` variant and update `MODES`, `mode_at`, `mode_index`, the mode menu's
list, and the Fn-bar. A test walks the menu for exactly this reason: `Doc` once
shipped unreachable because the menu was still written for three modes.

## The three pillars

These are constraints, not aspirations, and each has a test.

**Security.** The target file is passive data. `crates/hiewlm-core/tests/no_exec.rs`
scans the source for `Command::new`, `process::Command`, `libloading`, `dlopen`
and `LoadLibrary` and fails the build if any appears in executable code. Comments
and string literals are stripped first, so prose may name a banned API to explain
why it is banned. `unsafe_code = "deny"` workspace-wide; the memory-mapping
exception carries a local allow and a SAFETY note.

If you need a capability that would breach this — reading another process's
memory on Windows, for instance — it goes behind a feature flag with an explicit,
audited exception, and the decision belongs in DESIGN.md.

**HIEW faithfulness.** The keymap, layout and default theme follow HIEW. Where
hiewLM deviates, the deviation is deliberate and documented (see DESIGN.md §23.4).
Removing a key HIEW has is a design decision, not a cleanup.

**Extensibility.** Formats, architectures and containers are traits with
registries. Detection rules are data. The point is that the common extensions
need no compiler.

## Testing

Everything is a unit or integration test in-crate; there is no fixture corpus and
no network. Guidance that has earned its place:

- **Test against reality, not against your fixtures.** The API scoring, the
  packer rules and the document parsers all had false positives that only
  appeared when run against real binaries — including hiewLM's own.
- **Say what actually holds.** Repeating-key recovery is statistical: the tests
  assert exact recovery at the size a real configuration blob is, the right key
  *length* with near-exact bytes for a long key, and only "it decodes to text"
  for a 64-byte block. Tuning a test until it passes hides the limit instead of
  documenting it.
- **Parallel tests share the process.** Anything reading an environment variable
  or a fixed temp path will race. The notes store resolves to a per-process
  directory under `cfg(test)`; the rule loader takes an explicit directory in
  tests rather than reading the environment.
- **Bound every parser.** Cyclic FAT chains, absurd sector counts, sizes past
  EOF, decompression ratios — a crafted file will contain all of them, and there
  is a test for each.

## Decisions and non-goals

Recorded so they are not relitigated:

| Decision | Why |
|---|---|
| No `.dll`/`.dylib` split | Measured: 9.5 MB and 8.8 MB, not "hundreds of MB". The workspace is already eight library crates, which *is* the standard Rust organisation. Shipping dynamic libraries and loading them at run time would breach the security model and save nothing. Feature-gating heavy dependencies is what actually reduces size. |
| Folder-wide replace is CLI-only | It was one Shift away from keys pressed all day. Rewriting a folder of samples should be something you typed out (`hiewlmc replace <dir> --recursive`). |
| Single-letter block ops (`y`/`p`/`d`) stay | The original argument was key pressure plus accident risk; neither holds now that the palette reaches everything by name and the write lock blocks accidents. |
| Both Rhai and WASM extension paths stay | They work and are tested. Neither is being extended. |
| No mouse support | Deliberate — it is a HIEW/FAR-shaped tool. |
| No TLSH alongside ssdeep | ssdeep is enough for clustering at triage time; TLSH would add a dependency without changing a decision. |
| HEM (native DLL) compatibility shim | Incompatible with the security model. Permanently deferred. |
| Windows live process memory | Needs `unsafe` and the `windows` crate. It is a real gap, and it needs a deliberate, audited exception rather than a quiet one. |

## Releasing

```sh
cargo test --workspace --release
cargo clippy --workspace --all-targets --release
cargo fmt --all --check
FEATURES=full ./scripts/build-release.sh all   # dist/hiewlm-<os>-<arch>
```

Artifacts are named `os-arch` (`hiewlm-macos-arm64`, `hiewlmc-windows-x64.exe`).
Cross-compiling to Windows needs mingw-w64; the script installs the Rust target
if it is missing and picks up a rustup toolchain when one is available, because a
distro Rust ships std for the host only.

Update [CHANGELOG.md](../CHANGELOG.md) with anything a user would notice.

GitHub does the same work on its own: `.github/workflows/release.yml` builds all
four targets with the full feature set on every push to `main` (artifacts, kept
14 days) and, on a `v*` tag, attaches them to a release together with SHA-256
sums. It smoke-tests each binary before publishing — a build that cannot answer
`--version`, or that reports no YARA support when it was meant to have it, is
not worth shipping. Releasing is therefore:

```sh
git tag -a v0.1.0 -m "hiewLM 0.1.0"
git push origin v0.1.0
```
