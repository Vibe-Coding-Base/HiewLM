# hiewLM — Overall Design

> **hiewLM** brings the essentials of **HIEW (Hacker's View)** by Eugene
> Suslikov to Linux and macOS — hence the name — and to Windows alongside them.
> It is an independent reimplementation inspired by HIEW, not a copy of it and
> not a competitor to it.
> This document is the detailed design: from research on the original HIEW → design
> philosophy → tech stack → architecture → feature list → keymap → roadmap.

- **Status:** Draft v1 (2026-07-14)
- **Project code:** `hiewLM`
- **Distribution:** a single static binary per platform, no runtime required.

---

## Table of contents

1. [Goals & scope](#1-goals--scope)
2. [Research on the original HIEW](#2-research-on-the-original-hiew)
3. [Philosophy & design principles](#3-philosophy--design-principles)
4. [Tech stack](#4-tech-stack)
5. [Software architecture](#5-software-architecture)
6. [Data model & large-file handling](#6-data-model--large-file-handling)
7. [The three view modes](#7-the-three-view-modes)
8. [Addressing model](#8-addressing-model)
9. [Feature list by milestone](#9-feature-list-by-milestone)
10. [Keymap](#10-keymap)
11. [UI/UX layout](#11-uiux-layout)
12. [Assembler & Disassembler](#12-assembler--disassembler)
13. [Executable format parsers](#13-executable-format-parsers)
14. [Block operations & Crypt engine](#14-block-operations--crypt-engine)
15. [Search / Replace](#15-search--replace)
16. [Plugin system](#16-plugin-system)
17. [Configuration & data files](#17-configuration--data-files)
18. [Testing strategy](#18-testing-strategy)
19. [Roadmap](#19-roadmap)
20. [Risks & challenges](#20-risks--challenges)
21. [References](#21-references)
22. [Security model — viewing malware safely](#22-security-model--viewing-malware-safely) ⭐
23. [Faithfulness to the original HIEW UI](#23-faithfulness-to-the-original-hiew-ui) ⭐
24. [Clean code & extensibility principles](#24-clean-code--extensibility-principles) ⭐

> ⭐ **Sections 22–24 are three mandatory pillars** per requirements: (1) faithful
> to HIEW, (2) absolutely safe when viewing malware, (3) scientific, extensible
> code. They govern every decision in the sections above.

---

## 1. Goals & scope

### 1.1 Goals

Build a keyboard-driven binary viewer/editor that keeps HIEW's "soul" but runs well
on all three platforms and remains extensible:

- **Truly cross-platform:** Windows, macOS (Intel + Apple Silicon), Linux — one
  codebase, the same UX.
- **Keep HIEW's "killer features":**
  1. Instant mode switching Hex ↔ Code ↔ Text via `Enter`.
  2. **Assemble-at-cursor**: edit a disassembled instruction in place and rewrite
     the bytes.
  3. A Norton-Commander-style function-key bar at the bottom of the screen, 100%
     keyboard-operable.
  4. Parallel **file-offset ↔ virtual address** (VA) when opening an executable.
  5. The block "crypt interpreter" (custom XOR/rotate/add).
- **Modernize HIEW's weak spots** (see [§2.7](#27-hiew-limitations-to-fix)): open
  architecture, modern CPU architectures (ARM64, RISC-V…), binary diff, a
  struct/template system, recursive analysis, open source.

### 1.2 Out of scope for v1

- Not aiming to be a full decompiler / IDA killer. An interactive disassembler plus
  best-effort xrefs is enough for v1.
- No graphical GUI in the early stages — **TUI-first** (see
  [§4.1](#41-the-big-decision-tui-first)). The core is separated so a GUI can wrap it later.
- No dynamic debugger/emulator in v1 (left to plugins).

### 1.3 Target users

Reverse engineers, malware analysts, CTF players, exploit writers, systems
programmers — people already used to HIEW/BIEW/radare2 and working over SSH/tmux on
isolated analysis machines.

---

## 2. Research on the original HIEW

*(Summarized from the official docs mirror at `taviso.github.io/hiewdocs`, hiew.ru,
and the SDK header `hem.h`. Full keymap in [§10](#10-keymap).)*

### 2.1 Three modes

HIEW has 3 view modes: **Text**, **Hex**, **Decode/Code (disassembler)**.

- `Enter` — **cycles** Hex → Code → Text → Hex, keeping the cursor offset across
  switches.
- `F4` — a menu to select a mode **directly** (NOT a cycle).
- The **read** vs **edit** state is orthogonal to the view mode: `F3` enters edit in
  both Hex and Code.

> ⚠️ Many web tutorials wrongly say "F4 cycles modes." Per the official help: `Enter`
> cycles, `F4` is the menu.

### 2.2 Core features

| Group | Details |
|---|---|
| **In-place assembler** | x86, x86-64 (AVX), ARMv6 — edit the disassembly and reassemble over the bytes. HIEW's #1 signature feature. |
| **Disassembler** | x86 / x86-64 / ARMv6 (linear + interactive, not a true recursive-traversal analyzer). |
| **EXE header parsing** | NE, LE, LX, PE/PE32+, ELF/ELF64, Mach-O/Mach-O64, TE/TE64, COFF, NLM. `F8` views the header; imports `F7`, exports `F9`, sections `F6`, entry point `F8 F5`. |
| **Block ops** | mark (`*`), read/write file, fill, copy, move, insert, delete, crypt. |
| **Search/replace** | hex, ASCII, Unicode (even/odd UTF-16), search by instruction, single-char wildcard (`Alt ?`), directional, file/block scope, **multi-file search**; rewriting a folder is CLI-only (`hiewlmc replace <dir> --recursive`). |
| **Crypt engine** | `Alt F3` — a small x86-subset interpreter that runs a loop over each byte/word/dword/qword (XOR/add/rotate…). |
| **Calculator** | `Alt =`, 64-bit, full C operator set, multiple bases. |
| **Disk access** | view/edit physical & logical drives directly. |
| **Navigation** | goto (`F5`), 8-slot bookmarks (`+`/`-`/`Alt 1-8`), return stack (`BkSp`), xref (`F6`), string refs (`Alt F6`), follow branch (number keys `1-9,A`), names/symbols (`F12`). |
| **File resize** | grow (`Shift F3` insert), truncate (delete block), append. |
| **Macros** | record/play (`Ctrl .`, `Ctrl -`, `Ctrl 0-8`). |
| **HEM plugin** | a `.hem` DLL invoked from the `F11` menu. |
| **Color markers** | per-file block coloring, saved to `.cmarkers`. |

### 2.3 Read vs Edit

- `F3` enters edit mode (shows `EDITMODE`, cursor becomes a caret).
- In hex: `Tab` switches between the hex input column and the char input column.
- In code: `Tab` switches between typing opcode (hex) and typing assembler.
- Exit: `Esc` = discard, `F9` = save. `F10` exits updating the timestamp; `Esc`
  exits without updating.

### 2.4 Addressing model

- **Local offset** (within the current object/section) vs **global offset** (whole
  file). The calculator uses `@o` (local) / `@O` (global). The SDK has
  `Local2Global`/`Global2Local`.
- `Alt F1` — changes the address display mode (local / global / virtual address).
- `F5` Goto: absolute `n`; relative `+n`/`-n`; **VA with a leading dot** `.401B14`.
  Hex base by default; suffix `t` = decimal.

### 2.5 UI layout

- **Top status line:** filename, current offset/address, mode, file size; on the
  right a state indicator (bookmark diamond, `EDITMODE`, insert/overwrite, opcode
  size 16/32/64).
- **Bottom function-key bar:** F1–F10 in Norton Commander style, changes per
  mode/dialog; Shift/Alt/Ctrl change the bar contents.
- **Hex overlay:** offset column │ hex byte columns │ ASCII column. `Tab` switches
  columns while editing.
- **Code:** offset/VA │ bytes │ mnemonic+operand, with branch arrows (↑/↓) and
  number keys next to branch instructions, inline comments/names.

### 2.6 HEM plugin (summary)

A DLL exports `Hem_Load`, receives a `HIEWINFO_TAG` (the HiewGate pointer + a
handle), and returns a `HEMINFO_TAG` (version, `hemFlag` declaring applicable
modes/formats, `EntryPoint`, `Unload`, name, about). Through **HiewGate** a plugin
can: read/write the file, get the cursor/block/filename, search, add
names/comments/colors, translate local↔global offsets, and build menu/window/input
UI. It renders through HIEW's console primitives (no arbitrary graphics).

### 2.7 HIEW limitations to fix

- Windows-only, closed-source, paid (Linux/macOS must run it via Wine).
- DOS-era UX: 16 colors, low discoverability, no real mouse workflow.
- ARM is only ARMv6 — **no ARM64/AArch64**, no MIPS/RISC-V/PPC, no .NET/CIL/Java/WASM.
- Linear disassembler, not recursive-traversal; best-effort xrefs; no function/CFG
  recovery.
- Only 8 bookmarks; a single active block; limited search pattern (HEM `Find` ≤20 bytes).
- No generic unpacker, no packer-detection DB; structs require plugins.
- **No first-class binary diff / compare**, no split view/panes.
- Encoding is `hiew.xlt` table-based rather than fully Unicode-aware.

### 2.8 Other reference tools

**BIEW/BEYE** (the closest FOSS clone, multi-arch), **HT Editor** (strong format
parsers), **radare2/Cutter** (recursive disasm + Capstone + graphs), **ImHex**
(pattern language, diffing, modern UI), **HxD** (disk/RAM edit, compare,
performance), **wxHexEditor** (huge files + devices), **hexyl** (terminal color
scheme), **010 Editor / Kaitai Struct** (the binary-template gold standard).

---

## 3. Philosophy & design principles

> **Three inviolable principles** (highest priority; detailed in
> [§22](#22-security-model--viewing-malware-safely),
> [§23](#23-faithfulness-to-the-original-hiew-ui),
> [§24](#24-clean-code--extensibility-principles)):
> - **A. HIEW faithfulness:** the UI, keymap, and workflow must give a HIEW user a
>   "coming home" feeling.
> - **B. Absolute safety:** hiewLM only **reads/displays data**; it NEVER executes,
>   loads, or triggers any behavior of the target file. Viewing a malware sample must
>   be as safe as opening it with `xxd`.
> - **C. Scientific & extensible code:** trait-based, layered, documented, no "god
>   object", add arch/format/plugin without modifying the core.

1. **The keyboard is a first-class citizen.** Everything is doable without a mouse.
   The Fn-bar always shows which key does what in the current context (fixing HIEW's
   "hard to discover" issue).
2. **Muscle-memory compatibility with HIEW.** The default keymap closely follows
   HIEW ([§10](#10-keymap)); a HIEW user can sit down and use it immediately. There
   are alternative keymap presets (vim-like) for newcomers.
3. **Core separated from UI.** All logic (buffer, edit journal, disasm, parser,
   search) lives in a core crate with no terminal dependency → it can be wrapped in a
   TUI, a GUI, or CLI/scripting later.
4. **Safe file editing.** Files open **read-only** by default; edits live in a
   separate "edit journal" until the user actively commits (`F9`). Undo/redo exists.
   Optional `.bak` backup.
5. **Large files are not fully loaded into RAM.** Use memory-map + rope/piece-table
   to handle GB-scale files and O(log n) insert/delete.
6. **Extend via safe plugins.** Don't mimic HIEW's DLLs; use a **WASM sandbox** +
   Lua/Rhai scripting (see [§16](#16-plugin-system)) so plugins can't crash the host
   and run cross-platform.
7. **Multi-arch CPU from day one** via Capstone (disasm) + Keystone (asm):
   x86/x64, ARM/ARM64, MIPS, RISC-V, PPC…
8. **Beautiful and clear in a modern terminal:** 24-bit truecolor, light/dark
   themes, hexyl-style byte-category coloring, with a 16-color fallback.

---

## 4. Tech stack

### 4.1 The big decision: TUI-first

**Choose a TUI (terminal UI) as the primary interface**, not a graphical GUI. Reasons:

- HIEW is fundamentally a console app; the Fn-bar, the half-screen layout, the key
  workflow — all of it *is* the terminal experience. A GUI clone would lose the soul.
- Reverse engineers often work over SSH/tmux on isolated analysis machines → a TUI
  runs there, a GUI does not.
- One static binary, instant startup, no heavy graphics toolkit.
- The separated core ([§3.3](#3-philosophy--design-principles)) lets us add a GUI
  (egui/Tauri) later without rewriting the logic.

### 4.2 Language: Rust

**Rust** is the optimal choice for this tool:

| Criterion | Why Rust |
|---|---|
| Cross-platform | One codebase builds for Win/macOS/Linux, easy cross-compile. |
| Static binary | No runtime; ship one file. |
| Binary-analysis ecosystem | `goblin`, `capstone`, `keystone`, `iced-x86`, `object`, `memmap2` — mature and fit for purpose. |
| Safety & speed | Handle GB files, parse untrusted binaries (malware) with memory safety. |
| Great TUI | `ratatui` + `crossterm` is the leading TUI stack. |
| WASM plugins | `wasmtime` is mature. |

> **Alternatives considered:** Go (weaker disasm ecosystem, GC pauses on large
> files), C++ (fast but less safe, harder cross-platform builds — though this is
> HIEW/BIEW's original language), Zig (ecosystem not ready yet). → **Rust** wins.

### 4.3 Key crates

| Area | Crate | Notes |
|---|---|---|
| TUI framework | **`ratatui`** | Widgets, layout, rendering. |
| Terminal backend | **`crossterm`** | Cross-platform key/mouse/color, raw mode. |
| Memory-map | **`memmap2`** | Read-only map of large files. |
| Edit buffer | **hand-written piece-table/rope** or `ropey`-inspired | O(log n) insert/delete on the overlay (see [§6](#6-data-model--large-file-handling)). |
| Disassembler | **`capstone`** (Capstone binding) | x86/x64/ARM/ARM64/MIPS/RISC-V/PPC/SPARC… |
| Detailed x86 disasm (optional) | **`iced-x86`** | Pure-Rust, precise x86/x64 encode+decode, AVX-512 support. |
| Assembler | **`keystone`** (Keystone binding) | Multi-arch assemble; fallback `iced-x86` for x86. |
| EXE parser | **`goblin`** | PE/ELF/Mach-O/archive; add custom parsers for NE/LE/LX/TE. |
| Secondary format parser | **`object`** | Unified symbol/section abstraction. |
| Plugin sandbox | **`wasmtime`** | Run WASM plugins. |
| Embedded scripting | **`mlua`** (Lua) or **`rhai`** | Lightweight macros/plugins. |
| Struct/template | **Kaitai Struct runtime** or a custom DSL | Structure viewer (see [§16.3](#163-structure-viewer--template)). |
| Regex/search | **`memchr`**, **`aho-corasick`**, **`regex`** | Fast + multi-pattern search. |
| Hash/crypto (core plugin) | **`sha2`, `md-5`, `crc32fast`, `blake3`** | Block checksums. |
| Config | **`serde` + `toml`** | `hiewlm.toml`. |
| Session serialize | **`serde` + `bincode`/`toml`** | Bookmarks, names, markers. |
| CLI args | **`clap`** | Command-line flags. |
| Errors | **`anyhow` + `thiserror`** | |
| Logging | **`tracing`** | Local debug/telemetry. |
| Unicode | **`unicode-width`, `unicode-segmentation`** | Text-mode rendering. |
| Disk access | **`sysinfo`** + per-OS syscalls | Enumerate drives; raw device reads. |

### 4.4 Build & distribution

- A multi-crate Cargo workspace (see [§5](#5-software-architecture)).
- CI (GitHub Actions) build matrix: `x86_64`/`aarch64` × `windows-msvc`/`apple-darwin`/`linux-gnu`
  + `linux-musl` (fully static binary).
- Capstone/Keystone: vendored via build script (built from source) to avoid system
  dependencies; or feature-gated to build "core-only" without them.
- Packaging: Homebrew tap (macOS), `.deb`/`.rpm` + AUR (Linux), Scoop/winget
  (Windows), release binaries on GitHub.

---

## 5. Software architecture

### 5.1 Layer diagram

```
┌───────────────────────────────────────────────────────────┐
│  hiewlm-tui   (ratatui/crossterm)   ← a future GUI wraps here │
│  - render 3 modes, Fn-bar, dialogs, status line              │
│  - input mapping → Command                                   │
├───────────────────────────────────────────────────────────┤
│  hiewlm-app   (state machine, no terminal dependency)        │
│  - Editor state, mode, cursor, selection, edit journal       │
│  - Command dispatch, undo/redo, keymap, macros               │
├───────────────────────────────────────────────────────────┤
│  hiewlm-core  (pure library, no UI I/O)                      │
│  ├ buffer:   memmap + piece-table + edit journal             │
│  ├ address:  offset ↔ VA, local/global, section map          │
│  ├ search:   hex/ascii/unicode/regex/instruction             │
│  ├ block:    mark/copy/move/fill/crypt                        │
│  └ names:    symbol/comment/bookmark store                    │
├───────────────────────────────────────────────────────────┤
│ hiewlm-fmt      │ hiewlm-asm        │ hiewlm-plugin           │
│ PE/ELF/MachO/…  │ capstone+keystone │ wasmtime + lua + HEM    │
│ headers,imports │ disasm/asm/xref   │ compat shim (optional)  │
└───────────────────────────────────────────────────────────┘
```

### 5.2 Workspace crates

| Crate | Responsibility |
|---|---|
| `hiewlm-core` | Buffer, addressing, search, block, names — pure logic, testable without UI. |
| `hiewlm-fmt` | Detect & parse executable/container formats; return a common model (sections, symbols, imports, exports, entry, VA map). |
| `hiewlm-asm` | Wrap Capstone/Keystone/iced-x86; disassemble, assemble-at-cursor, xref analysis, follow branch. |
| `hiewlm-plugin` | WASM plugin runtime + Lua/Rhai scripting; host API; (optional) HEM compat shim. |
| `hiewlm-app` | Editor state machine, command model, keymap, macros, session/undo. |
| `hiewlm-tui` | ratatui frontend; render + input; the `hiewlm` binary. |
| `hiewlm-cli` (optional) | Batch/scripting mode (patch from scripts, hex dump) without a TUI. |

### 5.3 Command pattern

Every user action → a `Command` (enum) flowing through `hiewlm-app`. Benefits:

- Undo/redo: each mutating command has `apply`/`revert`.
- A macro = a recorded list of Commands.
- The keymap = a mapping (mode, key) → Command; easy to reconfigure.
- Scripting/plugins emit Commands through the same path → consistency.

```rust
enum Command {
    SwitchMode(ModeTarget),        // Enter cycle / F4 menu
    Goto(AddrExpr),                // F5
    EnterEdit, CommitEdit, CancelEdit,
    ToggleInsert,                  // Ins
    MarkBlockToggle,               // *
    BlockWriteFile(PathBuf),       // F2
    BlockCopyToCursor,             // Shift F5
    BlockFill(Pattern),            // Alt F2
    BlockCrypt(CryptProgram),      // Alt F3
    Search(SearchSpec), FindNext,  // F7 / Ctrl+Enter
    FollowBranch(u8),              // 1-9,A
    ViewHeader,                    // F8
    XrefHere,                      // F6
    AddBookmark, RestoreBookmark(u8),
    RunPlugin(PluginId),           // F11
    Calc(String),                  // Alt+=
    // ...
}
```

---

## 6. Data model & large-file handling

### 6.1 Requirements

- Open GB-scale files instantly (don't read it all).
- Support insert/delete bytes that **change the file size** (HIEW: `Shift F3`, delete
  block) → a flat array won't do.
- Read-only by default; edits kept separate until committed.
- Undo/redo.

### 6.2 Design: base memmap + piece-table overlay

```
FileBuffer
 ├ base:   Mmap (read-only, whole original file)   ── via memmap2
 ├ added:  Vec<u8>   (bytes the user typed/inserted)
 └ pieces: Vec<Piece>                               ── piece-table
             Piece { source: Original|Added, start, len }
```

- **Read** a byte at a virtual offset → look up the piece-table (tree/skiplist for
  O(log n)).
- **Overwrite** (in-place edit): append bytes to `added`, split a piece.
- **Insert** (`Shift F3`): insert a new piece → file length grows.
- **Delete block** (`Shift F2`): drop/trim pieces → length shrinks.
- **Undo/redo:** journal the piece operations (or lightweight piece-list snapshots).
- **Commit (`F9`):** write to a new file then atomically replace (rename), or write
  in-place if the edit is same-size overwrite (fast, safe for devices/disks).

### 6.3 Data source modes

The buffer abstracts the source so everything reuses it:

| Source | Notes |
|---|---|
| Regular file | memmap read + overlay. |
| Physical/logical disk | sector-based read/write; overlay only for edited regions; a strong warning on commit. |
| Process memory (future) | read `/proc/pid/mem`, `mach_vm_read`, `ReadProcessMemory`. |
| Stdin/pipe | read everything into `added` (can't memmap). |

---

## 7. The three view modes

### 7.1 Hex mode

- Layout: `OFFSET │ 16 hex bytes │ ASCII`. The byte column count scales with the
  terminal width (8/16/32).
- Byte cursor; `Tab` (while editing) switches the hex column ↔ ASCII column.
- hexyl-style byte-category coloring (null / ascii-printable / whitespace / control /
  non-ascii), respecting the theme.
- Shows offset and VA together if the file is a mapped executable.

### 7.2 Code (Decode) mode

- Layout: `ADDR │ bytes │ mnemonic  operands  ; comment`.
- Disassembly from Capstone; branch arrows ↑/↓; number keys `1-9,A` next to jump
  instructions to follow.
- `/` resyncs the disassembly from the cursor offset (forces the cursor offset to be
  an instruction start).
- `Ctrl+F1` changes bit-size 16/32/64; `Shift+F1` changes architecture.
- Edit (`F3`): edit the mnemonic column → assemble (Keystone) → overwrite bytes;
  `Tab` switches between typing opcode-hex ↔ assembler.

### 7.3 Text mode

- Render text with a selectable encoding table (ASCII, CP437, UTF-8, UTF-16, custom
  `.xlt`).
- Unicode-aware (unicode-width) — fixing HIEW's static-table limitation.
- Wrap by width; show non-printable bytes with a symbol.

### 7.4 Switching modes

- `Enter`: cycle Hex → Code → Text → Hex (keeping the offset).
- `F4`: menu to select directly.
- The cursor state (offset) is canonical, shared across modes.

---

## 8. Addressing model

This is the subtlest part of cloning HIEW correctly.

### 8.1 Concepts

- **File offset**: byte position in the file (0-based).
- **Virtual Address (VA)**: the address when the executable is mapped (based on image
  base + section RVA).
- **Local offset**: offset within the current object/section.
- **Global offset**: offset within the whole file.

`AddressSpace` holds a two-way mapping table from the format parser
([§13](#13-executable-format-parsers)):

```rust
struct SectionMap { file_off: u64, va: u64, size: u64, name: String, flags: SecFlags }
struct AddressSpace { image_base: u64, sections: Vec<SectionMap> }
// file_off ↔ va, and local(section-relative) ↔ global(file)
```

### 8.2 Display & input

- `Alt+F1`: cycle the address display mode **local / global / VA** (like HIEW).
- Goto (`F5`) expression parser:
  - `1B40` → absolute offset (hex by default).
  - `+100` / `-40` → relative to the cursor.
  - `.401B14` → **VA** (leading dot, exactly like HIEW).
  - `123t` → decimal; `0x`, `0..`(octal), `..i`(binary) base prefixes/suffixes.
  - Supports small arithmetic expressions shared with the calculator.
- The status line shows offset + VA together when a mapping exists.

### 8.3 Calculator (`Alt+=`)

64-bit, full C operator set (`+ - * / % ~ & ^ | ! && || << >> == != < > >= <=`),
multiple bases, and HIEW-style read-from-file operands: `@b/@B` (char s/u),
`@w/@W`, `@d/@D`, `@q/@Q`, `@o` (local off), `@O` (global off).

---

## 9. Feature list by milestone

Legend: **M0** = usable MVP; **M1** = HIEW parity; **M2** = beyond HIEW; **M3** = ecosystem.

### 9.1 M0 — MVP (view & edit hex)

- [x] Open file (CLI arg, memmap), read-only + edit journal.
- [x] Hex mode: render, scroll, PgUp/PgDn, Home/End, Ctrl+Home/End.
- [x] Basic Text mode (ASCII/UTF-8).
- [x] In-place hex editing (`F3`/`Tab` hex↔ascii), overwrite, undo/redo, commit `F9`.
- [x] Goto `F5` (absolute/relative/decimal offset).
- [x] Search hex + ASCII (`F7`), find next.
- [x] Bottom Fn-bar + top status line.
- [x] Insert/overwrite toggle (`Ins`), basic file resizing.
- [x] Save-as, `.bak` backup.

### 9.2 M1 — HIEW parity

- [x] Code mode: disassemble x86/x64/ARM/ARM64/MIPS/RISC-V/PPC/SPARC (iced-x86 + Capstone).
- [x] Assemble-at-cursor x86/x64 (`iced-x86` `code_asm`; Keystone unbuildable), overwrite bytes.
- [x] `Enter` cycle mode, `F4` mode menu.
- [x] Addressing: offset↔VA, `Alt+F1` cycle, goto `.VA`.
- [x] PE/ELF/Mach-O header parser: `F8` view; imports/exports/sections; entry point `F8 F5`.
- [x] Block ops: mark, write-to-file, read-file-in, fill, zero, delete, copy, move, insert
      (all reachable from the `b` block menu; copy/move target the `+` bookmark).
- [x] Crypt engine (`C`, `hiewlmc crypt`) — XOR/ADD/SUB/AND/OR/ROL/ROR/NOT/NEG pipeline,
      repeating hex or ASCII keys, reports whether a recipe is invertible.
- [x] Bookmark stack (`+`/`-`), numbered slots (`K`+digit sets, `Alt+1..8` jumps),
      return stack `BkSp`, browsable history (`H`).
- [x] Advanced search: `??` wildcard, UTF-16 ("Unicode") text, backward search (`Alt+N`),
      block-scoped search when a block is marked, and search-by-instruction (assembles
      the typed instruction, then searches for its encoding).
- [x] Calculator `Alt+=`.
- [x] Names/symbols + comments (`F12`, `;`), save/load.
- [x] Xref `F6`, follow branch `1-9,A`, string list `Alt+F6`.
- [x] Macro record/play (`Ctrl+.`, `Ctrl+0-8`).
- [x] Per-block color markers, saved to a sidecar file.
- [~] Disk access — a raw block device can be opened by path where the OS permits it
      (`FileSource`); no dedicated device picker, and no raw writes. Deliberately left
      there: whole-disk writes are the one operation whose blast radius exceeds anything
      else in the tool, and hiewLM's audience opens images far more often than devices.

### 9.3 M2 — Beyond HIEW

- [x] **Binary diff/compare** — inline highlight + `>`/`<` jumps, plus a **split 2-pane view**
      (`S`) showing both files at the same offsets, with `--` past the shorter file's end.
- [x] Recursive-traversal disassembly + function list + trustworthy xrefs.
- [x] **Structure viewer** via a Kaitai-flavoured template DSL: `meta endian be|le`, per-field
      `le`/`be` suffixes, `char[N]`/`bytes[N]`/`TYPE[N]` arrays where `N` may name an earlier
      field, `enum { v=NAME }` maps, and `= value` validation. (Full Kaitai — YAML, an
      expression language, nested user types — remains out of scope.)
- [x] Extended architectures: x86/x64/ARM/ARM64/MIPS/RISC-V/PPC/SPARC, plus a **WASM
      bytecode** decoder (LEB128 immediates, block types, `0xFC` saturating conversions).
- [x] More parsers: NE/LE/LX/TE/COFF/**NLM**, .NET metadata, ar. ZIP moved to a
      container plugin (§9.5); PDF added as one.
- [x] Block checksum/hash (CRC32/MD5/SHA-256/BLAKE3).
- [x] Multi-file search & replace across a directory (.bak backups).
- [x] Light/dark/classic theme, truecolor, config file (`config.toml`).
- [x] Unlimited named bookmarks + browsable jump history.
- [x] Data inspector (int/float, both endians).
- [x] Encoding: ASCII/CP437/Latin-1/UTF-16LE + auto-detect.

### 9.3b HIEW-parity items still open (from the lock.cmpxchg8b.com review)

Most HIEW features are covered. Remaining gaps vs. the original:

- [x] **Text assemble-at-cursor** (`A` in Code mode, `hiewlmc asm`) — built on `iced-x86`'s
      `CodeAssembler` (`code_asm` feature) rather than Keystone, which will not compile.
      Covers the patching subset (mov/arith/logic/stack/branches/zero-operand) with
      reg/imm/`[base+index*scale+disp]` operands; live encoding preview, NOP-padded to the
      replaced instruction, and refuses to write if the encoding does not fit. Branches that
      would need an indirect trampoline are rejected rather than silently expanded.
- [x] **Colored block markers** (`M` / `Alt+M`, saved to a `.markers` sidecar) — 8-color palette +
      random + clear; `]`/`[` / `Alt+N` jump between them; rendered in hex & text.
- [x] **Standalone calculator** (`=` / `Alt+=`) — recursive-descent 64-bit evaluator, C precedence,
      `@o/@b/@w/@d/@q` operands, live multi-base result (hex/dec/i64/oct/bin).
- [x] **Macro loop / stop-on-search-fail** (`Ctrl+L`) — replays until a search inside fails, the
      state stops changing, or a hard cap; find-and-replace loops work.

Done from the review: strings list (`s`), one-key NOP (`N`), relative/decimal goto, block
save-to-file, names/comments, bookmarks, structure templates, calculator, colored markers,
macro loop, **text assembler**. No HIEW-parity gaps remain open.

### 9.4 M3 — Ecosystem

- [x] **WASM plugins** (`wasmtime`, `hiewlm-plugin`) + host ABI (`len/read/write/find/log`),
      fuel-bounded sandbox (no fs/network/syscalls); run via `hiewlmc plugin`.
- [x] **Rhai scripting** for automated inspection/patching (`hiewlmc script`, pure Rust).
- [x] **CLI batch mode** (`hiewlm-cli` / `hiewlmc`): info/hex/disasm/search/replace/patch/hash/
      strings/entropy/packer/script/plugin — CI-friendly exit codes.
- [x] **Read process memory** (Linux `/proc/<pid>/mem`, `pid:N`); clean error elsewhere.
- [x] **Packer detection** — entry-point signatures + section-name/entropy/import heuristics.
- [x] **CFG view** — basic-block graph of the current function in the TUI (`G`).
- [ ] **HEM compat shim** — intentionally **not** implemented: it loads native `.hem` DLLs
      (`LoadLibrary`), which our security model forbids (§22, the no-exec guard bans
      `LoadLibrary`/`dlopen`/`libloading`). WASM plugins are the safe cross-platform replacement.
- [ ] **GUI wrapper** (egui/Tauri) — deferred. The core is already UI-free and reusable
      (`hiewlm-core`/`fmt`/`asm`), so a GUI can wrap it, but it needs a display to develop/test
      against and is a separate milestone; not committing untested GUI code.

### 9.4b Build & distribution

- [x] **Cross-platform binaries.** `scripts/build-release.sh [host|windows|macos|linux|all]`
      produces `dist/hiewlm-<label>` for each target. Windows cross-builds from a Unix host
      use mingw-w64 (`x86_64-pc-windows-gnu`); linker settings live in `.cargo/config.toml`.
      A native Windows build with the MSVC toolchain needs no configuration.
- Portability notes: the whole workspace, tests included, compiles clean for
  `x86_64-pc-windows-gnu` with no `cfg`-gating beyond the Linux-only `pid:N`
  process-memory source, which reports a clear error on other platforms.
- The Windows binaries import **no** `CreateProcess`/`LoadLibrary`/`WinExec`/`ShellExecute`,
  so the no-exec pillar (§22.1) holds at the binary level and not only in source.
- Not built here: **arm64 Windows** (needs `aarch64-w64-mingw32-clang`) and the MSVC-ABI
  targets. Both are configuration, not code changes.

### 9.5 Container-format plugins

Container formats (files that hold *members* rather than one code image) live outside
`hiewlm-fmt` in their own crates, behind the `ContainerParser` trait in
`hiewlm-core::container`:

```rust
trait ContainerParser {
    fn name(&self) -> &'static str;         // activation name: "zip", "pdf"
    fn description(&self) -> &'static str;
    fn sniff(&self, bytes: &[u8]) -> bool;  // cheap magic check
    fn parse(&self, bytes: &[u8]) -> Option<Container>;
}
```

A `Container` carries a `kind`, a key/value `summary`, `members` (name + **file offset** +
size + detail), and `findings` — `Info` or `Suspicious` notes with an optional offset.

**Why static registration, not `.so`/`.dll` loading.** The security model (§22.1) forbids
`dlopen`/`LoadLibrary`/`libloading`, and the `no_exec` test enforces it across the workspace.
So plugins are separate *crates* linked at build time and switched on **by name at runtime**;
they never start enabled by accident. This keeps real module isolation (a plugin cannot reach
the buffer, filesystem or network — it only receives `&[u8]` and returns a description) while
giving up nothing the security pillar requires. WASM plugins (`hiewlm-plugin`) remain the
mechanism for *untrusted, user-supplied* extensions.

- [x] ZIP moved out of the plugin registry into `hiewlm-office` (M6), where it gets the
      document view: EOCD/ZIP64 central directory walk; per-member method, sizes, CRC,
      DOS timestamp, encryption scheme; local-header offset so Enter jumps into the member;
      each member's real content type read from its magic rather than its extension.
      Flags path traversal, disguised names, directory/local-header mismatches,
      dropper extensions, zip-bomb ratios, SFX/appended-ZIP stubs,
      members whose local header is missing or past EOF.
- [x] PDF moved out of the plugin registry into `hiewlm-office` (M6), where it gets the
      document view instead of a member list: header (including data prepended before
      `%PDF-`, a polyglot trick), indirect-object map with `/Type`, incremental updates,
      `#hex`-escaped name obfuscation, and the active-content names from the rule table.
      Streams are **not** decompressed, so objects inside `/ObjStm` are not enumerated —
      reported explicitly
      rather than left as a silent blind spot.

Activation: `hiewlmc --plugin zip|pdf|all …` (off unless named), `hiewlmc plugins` to list,
`hiewlmc container <file>` to dump structure, `--fail-on-suspicious` for CI. The TUI enables
all of them by default (they are read-only parsers) via `plugins = [...]` in `config.toml`.

---

## 10. Keymap

> The defaults **closely follow HIEW** to preserve muscle memory. Everything is
> reconfigurable in `keymap.toml`. The "Mode" column indicates the applicable context.

### 10.1 Mode switching & viewing

| Key | Mode | Action |
|---|---|---|
| `Enter` | hex/code/text | Cycle Hex→Code→Text |
| `F4` | any | Menu to select a mode directly |
| `F3` | hex/code | Enter edit mode |
| `Shift+F3` | hex/code | Insert bytes (grow the file) |
| `Tab` (editing) | hex/code | Hex↔ASCII (hex) / opcode↔asm (code) |
| `Esc` | any | Cancel op / exit without updating the timestamp |
| `F9` | edit | Save changes |
| `F10` | any | Exit + update timestamp |
| `F1` | any | Context help |

### 10.2 Navigation

| Key | Action |
|---|---|
| `F5` | Goto offset/VA (`+n`/`-n`/`n`/`.VA`/`nt`) |
| `↑↓←→ PgUp PgDn` | Move cursor/scroll |
| `Ctrl+Home` / `Ctrl+End` | Start / end of file |
| `+` / `-` | Push / pop bookmark |
| `Alt+1..8` | Jump to numbered bookmark |
| `Alt+0` | Clear all bookmarks; `Alt+-` delete current |
| `BkSp` | Return to previous location (return stack) |
| `Tab` (not editing) | Next file in history |
| `Ctrl+BkSp` | Manage open files |
| `Ctrl+F11`/`Ctrl+F12` | Previous/next file in the arg list |
| `Alt+F1` | Cycle address mode (local/global/VA) |

### 10.3 Block

| Key | Action |
|---|---|
| `*` | Toggle block marking |
| `Ctrl+*` | Select whole file |
| `Alt+*` | Reset block start at cursor |
| `[` / `]` | Jump to block start / end |
| `Ins` | Toggle insert/overwrite |
| `F2` | Write block to file |
| `Ctrl+F2` | Read block from file at cursor |
| `Alt+F2` | Fill block (in code with no block → NOP the instruction) |
| `Shift+F2` | Delete block (truncate the file) |
| `Shift+F5` | Copy block to cursor |
| `Shift+F6` | Move block to cursor |
| `Shift+F4` | Dump/print block (text) |
| `Alt+F3` | Crypt block (mini-interpreter) |
| `Alt+M` / `Shift+Alt+M` | Color block / random color |
| `Alt+N` / `Shift+Alt+N` | Next / previous colored block |

### 10.4 Search / refs

| Key | Action |
|---|---|
| `F7` | Search (hex/ASCII/Unicode/instruction) |
| `Ctrl+Enter` / `Shift+F7` | Find next |
| `Alt+F7` | Change search direction |
| `Alt+F8` | Translation/encoding table |
| `F6` | Xref to the current location; `Ctrl+F6` next |
| `Alt+F6` | List strings |
| `1`–`9`,`A` | Follow branch (code mode) |
| `/` | Resync disassembly (code) |

### 10.5 Header / names / plugin / misc

| Key | Action |
|---|---|
| `F8` | View/edit EXE header (imports `F7`, exports `F9`, sections `F6`, entry `F8 F5`) |
| `F12` | Names/symbols window |
| `Shift+F12` | Name the location / export names |
| `;` | Add a comment at the cursor |
| `F11` | Plugin menu |
| `Ctrl+F1` | Change opcode size 16/32/64 (code) |
| `Shift+F1` | Change architecture (code) |
| `Alt+=` | 64-bit calculator |
| `Ctrl+.` | Record/stop macro; `Ctrl+-` manage macros; `Ctrl+0..8` play macro |
| `Alt+P` | Text screenshot |

> **Cross-platform note:** some combos (`Alt+Fx`, `Ctrl+Fx`, `Shift+Fx`) are eaten by
> the terminal/emulator or the WM. hiewLM will (a) use `crossterm` + the Kitty
> keyboard protocol where available to receive full modifiers, (b) provide a
> **command palette** (`:` or `Ctrl+P`) and **leader-key sequences** as alternatives
> for every command, (c) allow remapping in `keymap.toml`.

---

## 11. UI/UX layout

### 11.1 Screen layout

```
┌─ status ────────────────────────────────────────────────────────────┐
│ malware.exe   .00401B14  off:1B14  hex  RW  ▲ovr  x64   size:24576   │  ← status line
├──────────────────────────────────────────────────────────────────────┤
│ 00001B14: 55                push rbp                                  │
│ 00001B15: 48 89 E5          mov  rbp, rsp                             │  ← content area
│ 00001B18: E8 12 00 00 00  1 call sub_1B2F        ; follow: key 1      │     (current mode)
│ ...                                                                   │
├──────────────────────────────────────────────────────────────────────┤
│1Help 2Write 3Edit 4Mode 5Goto 6Ref 7Srch 8Hdr 9Save 10Quit          │  ← Fn-bar
└──────────────────────────────────────────────────────────────────────┘
```

- **Status line:** filename · address (VA if available) · offset · mode · RO/RW ·
  insert/overwrite · arch/bitness · size · an EDITMODE/macro-recording indicator.
- **Fn-bar:** changes per mode and per held modifier (pressing/holding
  `Shift`/`Alt`/`Ctrl` updates the labels instantly — fixing HIEW's discoverability).
- **Dialogs** (goto, search, header, names, calc, plugin menu) open as centered
  overlays/popups, each with its own Fn-bar.
- **Split view** (M2): binary diff or hex+struct side by side.

### 11.2 Color & theme

- 24-bit truecolor, falling back to 256/16 colors.
- Dark theme (default) + light; hexyl-style byte-category coloring
  (null/printable/control/non-ascii).
- User color markers (`Alt+M`) overlay onto bytes.
- Configured in `theme.toml`.

### 11.3 Mouse (optional, not required)

- Click to place the cursor, drag to select a block, click the Fn-bar to trigger,
  scroll to scroll. All just conveniences — everything is still doable via keyboard.

---

## 12. Assembler & Disassembler

### 12.1 Disassembler (`hiewlm-asm`)

- **Engine:** Capstone (multi-arch) by default; `iced-x86` for x86/x64 when precise
  encode/decode and detailed info (flags, operand access) are needed.
- **Modes:** linear sweep (default, like HIEW) + recursive traversal (M2) for
  function/CFG recovery.
- **Architectures:** x86/x64, ARM/Thumb, ARM64, MIPS, RISC-V, PPC, SPARC (toggle via
  Capstone).
- **Bitness/arch switch:** `Ctrl+F1` (16/32/64), `Shift+F1` (change arch).
- **Resync `/`:** force the cursor offset to be an instruction start and disassemble
  again from there.
- **Follow branch:** parse the jump/call operand → compute the target (offset/VA) →
  assign hotkeys `1-9,A`; `BkSp` returns.
- **Xref (`F6`):** scan the file for instructions referencing the current address; M1
  best-effort, M2 uses the CFG for reliability.

### 12.2 Assemble-at-cursor (HIEW's signature feature)

Flow:
1. `F3` enters edit in code mode → the current instruction line becomes a text input.
2. The user types a new asm instruction (or `Tab` to type opcode hex).
3. **Keystone** assembles with the current arch/bitness → produces bytes.
4. Check the length:
   - Equal to the old instruction length → overwrite directly.
   - Shorter → overwrite + auto-pad with `NOP` (optional) or ask.
   - Longer → warn (it will overwrite the following instruction) or switch to insert
     (`Shift+F3` semantics), changing the file size.
5. `F9` commits to the edit journal; `Esc` cancels.

Fallback: if Keystone is unavailable (core-only build), use the `iced-x86` encoder
for x86/x64.

---

## 13. Executable format parsers

### 13.1 Common model

`hiewlm-fmt` returns a unified `ExecutableModel` regardless of format:

```rust
struct ExecutableModel {
    format: Format,                 // PE, ELF, MachO, NE, LE, LX, TE, COFF, NLM, Raw
    arch: Arch, bits: u8, endian: Endian,
    image_base: u64, entry: u64,    // entry for F8 F5
    sections: Vec<Section>,         // name, file_off, va, size, flags
    imports: Vec<Import>,           // lib, name/ordinal, iat_va
    exports: Vec<Export>,
    symbols: Vec<Symbol>,
    relocations: Vec<Reloc>,
    extra: FormatSpecific,          // header fields to display/edit
}
```

### 13.2 Parser sources

| Format | Source |
|---|---|
| PE/PE32+ | `goblin::pe` (add: rich header, .NET COR20 directory read) |
| ELF/ELF64 | `goblin::elf` |
| Mach-O/64, fat | `goblin::mach` |
| Archive (ar) | `goblin::archive` |
| COFF | `object` / custom parser |
| NE / LE / LX / TE / NLM | **hand-written parser** (goblin doesn't support these) — DOS/OS-2/EFI legacy |
| Raw/unknown | no mapping; offset only |

### 13.3 Header features (`F8`)

- Show a browsable header field tree; `F3` to edit a field (written back into the
  buffer).
- Imports (`F7`), exports (`F9`), sections (`F6`) tables.
- `F8 F5` jumps to the entry point.
- Provides the `AddressSpace` ([§8](#8-addressing-model)) for the whole app so VA↔offset works.

---

## 14. Block operations & Crypt engine

### 14.1 Block

- **A single active block** (like HIEW) at M1; **multiple named colored blocks** at M2.
- Mark with `*` + movement keys; `Ctrl+*` selects the whole file; `Alt+*` changes the
  start anchor.
- Operations: write file `F2`, read file `Ctrl+F2` (insert/overwrite per `Ins`), fill
  `Alt+F2`, delete `Shift+F2`, copy `Shift+F5`, move `Shift+F6`, dump text `Shift+F4`.
- Everything goes through the edit journal → undoable.

### 14.2 Crypt engine (`Alt+F3`)

Recreates HIEW's "mini x86 interpreter" but safe & cross-platform:

- The user enters a small program operating on an "accumulator register"
  (AL/AX/EAX/RAX) read from each block element, processes it, and writes it back; the
  engine loops over the whole block automatically.
- Element size: byte/word/dword/qword (`F2` in the dialog).
- Syntax: a small safe DSL (no JIT), supporting `xor add sub rol ror shl shr and or
  not neg` + positional variables (index `i`, key…).
- Extras: built-in presets (XOR key, ADD/SUB, ROL, base64 decode/encode, RC4)
  selectable from a menu.
- Reusable while editing via a shortcut (like HIEW's `Ctrl+F7`).

---

## 15. Search / Replace

### 15.1 Search kinds (`F7`)

| Kind | Notes |
|---|---|
| Hex bytes | enter hex pairs, `Tab` switches to ASCII input |
| ASCII / text | auto-switches when >3 non-hex chars |
| Unicode UTF-16 | even/odd (`F6` in the dialog) |
| Instruction | invokes the assembler to search by instruction pattern |
| Wildcard | `?` single char (mask) |
| Regex (M2) | on bytes or text |

- Direction (`Alt+F7`), file/block scope (`F4` in the dialog), find next
  (`Ctrl+Enter`/`Shift+F7`).
- Engine: `memchr`/`memmem` for literals, `aho-corasick` for multi-pattern,
  hand-written mask-search for wildcards, `regex` for M2.
- **Multi-file search & replace** (M2): scan a directory by glob, bulk-replace with
  confirmation.

### 15.2 Replace

- Replace at a position (same length → overwrite; different length → insert/delete via
  the journal).
- Replace-all in file/block/directory with counts & undo.

---

## 16. Plugin system

### 16.1 Why not copy HEM

HEM is a Windows-only, native DLL that can crash the host and won't run on
macOS/Linux. hiewLM needs **cross-platform + safe** plugins.

### 16.2 Three-tier plugin architecture

| Tier | Technology | Used for |
|---|---|---|
| **Script** | Lua (`mlua`) or Rhai | Advanced macros, automated patching, quick tasks; lightweight sandbox. |
| **WASM** | `wasmtime` | Compiled plugins (Rust/C/Zig→WASM); strong sandbox, cross-platform, can't crash the host. |
| **HEM shim** (optional, Windows-only) | load `.hem` native | Backward compatibility with old HIEW plugins. |

### 16.3 Host API (stable, versioned)

Maps HiewGate's spirit but safely:

- `get_context()` → filename, size, cursor, block, mode, arch.
- `read(off, len)` / `write(off, bytes)` / `insert` / `delete` (via the edit journal →
  undoable).
- `search(pattern, mask, dir)` / `find_next()`.
- `names`: add/del/get symbols & comments; `bookmark`.
- `addr`: `local↔global`, `off↔va`.
- `ui`: `menu()`, `window(text, keys)`, `input()`, `input_dual()`, `message()`,
  `progress()`.
- `color_marker(range, color)`.
- The plugin declares applicable modes/formats (like `hemFlag`).

### 16.4 Structure viewer / template

- Allows declaratively describing a binary structure and overlaying it onto hex (a gap
  in HIEW).
- Options: embed the **Kaitai Struct** runtime (a rich .ksy ecosystem already exists,
  and HIEW had a kiewtai plugin) or an ImHex-pattern-style DSL.
- Result: a typed field tree, jump to a field, color a region, read values.

---

## 17. Configuration & data files

| File | Format | Contents |
|---|---|---|
| `hiewlm.toml` | TOML | General config (default mode, hex column count, backup, default arch). |
| `keymap.toml` | TOML | Key → command mapping; `hiew`, `vim` presets. |
| `theme.toml` | TOML | Colors, byte-category, light/dark theme. |
| `<file>.hiewlm/names` | TOML/bincode | Per-file symbols + comments. |
| `<file>.hiewlm/bookmarks` | TOML | Bookmarks (unlimited, named). |
| `<file>.hiewlm/markers` | TOML | Color markers (equivalent to `.cmarkers`). |
| `macros/` | script | Recorded macros (Lua/Rhai). |
| `plugins/` | `.wasm`, `.lua` | Plugins. |
| `xlt/*.xlt` | table | Custom encoding translation tables (the `hiew.xlt` idea). |

- Location: OS conventions (`$XDG_CONFIG_HOME/hiewlm`,
  `~/Library/Application Support/hiewlm`, `%APPDATA%\hiewlm`) via the `directories` crate.
- Per-file sidecars placed next to the file or in the config dir (optional) to avoid
  cluttering the directory.

---

## 18. Testing strategy

- **Unit tests** for `hiewlm-core`: piece-table (insert/delete/overwrite/undo fuzz),
  addressing (off↔va round-trip), search (all kinds + edges), calculator.
- **Golden tests** for parsers: a set of small PE/ELF/Mach-O samples, compare header
  fields to known values.
- **Round-trip asm/disasm:** disassemble → reassemble → compare bytes for a sample
  instruction set per arch.
- **Property/fuzz:** `cargo-fuzz` for format parsers (malicious/hostile input) — must
  not panic.
- **UI snapshot tests:** render ratatui into a text buffer, compare snapshots (insta)
  for each mode/dialog.
- **Integration:** end-to-end key scenarios (open → goto → edit → commit → verify the
  byte on disk) via a fake terminal backend.
- **Cross-platform CI:** run tests on all three OSes.

---

## 19. Roadmap

| Milestone | Contents | Outcome |
|---|---|---|
| **M0** (MVP) | Hex/Text view+edit, goto, search, Fn-bar, journal, save | A usable cross-platform hex editor. |
| **M1** (HIEW-parity) | Code mode + asm-at-cursor, PE/ELF/MachO headers, block ops, crypt, bookmark/xref/names, macros, VA addressing | "HIEW but cross-platform and open source". |
| **M2** (beyond) | Binary diff, recursive disasm, structure viewer, extended archs, hash, multi-file search/replace, themes, data inspector | Beyond HIEW in analysis & convenience. |
| **M3** (ecosystem) | WASM/Lua plugins, CLI batch, HEM shim, GUI wrapper, process memory, packer detect, CFG view | An extensible, community platform. |
| **M4** (triage-first) | Triage screen + `hiewlmc triage`, strings/IOC extraction, import capability scoring, PE anomalies (overlay/TLS/debug/Authenticode), ssdeep, YARA, XOR lens & key hunt, annotated disassembly, folder queue, command palette, real write lock | Fast initial malware classification, not just inspection. |
| **M5** (keep the work) | Notes keyed by content hash, ELF/Mach-O structural checks, repeating-XOR key recovery, stack-string reconstruction, Markdown reports | Analysis survives the session, and non-Windows samples get the same scrutiny. |
| **M6** (documents & packaging) | Office analysis (OLE2/OOXML/RTF + VBA decompression) as a fourth view mode, detection rules in overridable data files, opt-in heavy dependencies, `app.rs` split by concern, popups that scroll sideways | Documents get the same treatment as executables, and the rules are maintainable by an analyst rather than only by a compiler. |

Principle: each milestone is a usable release; the core is always separated from the
UI to avoid technical debt when adding a GUI.

### 19.1 M4 in one paragraph

M0–M3 answered "what is in this file?". M4 answers "**is this file worth my next
hour, and why?**" — the question that actually starts a malware investigation. The
design consequence is a new pure crate, `hiewlm-triage`, that turns the existing
parsers into a single scored verdict and renders it as panes the TUI and the CLI
both consume, so the interactive screen and the JSON a pipeline reads can never
disagree. Two rules kept it honest: every signal is *listed* but only strong
signals *score* (otherwise every compiled program looks armed), and the sample is
locked against writing until the analyst says otherwise (evidence must not change
by accident). The decisions that came out of that milestone are recorded in
`DEVELOPMENT.md` under "Decisions and non-goals".

---

## 20. Risks & challenges

| Risk | Mitigation |
|---|---|
| **Modifier keys eaten by the terminal** (`Alt+Fx`, `Ctrl+Fx`) | Kitty keyboard protocol; command palette + leader-key alternatives; remappable. |
| **Assemble-at-cursor changes instruction length** → corrupts following code | Clear warning, optional auto-NOP, preview bytes before commit. |
| **GB files & insert/delete** performance | Piece-table O(log n) + memmap; benchmark early. |
| **Dangerous physical-disk writes** | Read-only default, multi-layer confirmation on device commit, dry-run. |
| **Keystone/Capstone are C libs** — cross-platform builds | Vendored build script; feature-gate "core-only"; or pure-Rust iced-x86 for x86. |
| **Malicious malware parsing** causing panic/OOM | Defensive parsing, resource limits, continuous fuzzing, running in safe Rust. |
| **Scope creep** (becoming IDA) | Stick to the roadmap; leave deep analysis to plugins. |
| **HIEW copyright/trademark** | An independent reimplementation: no HIEW code or assets, a distinct name, and the README credits HIEW as the inspiration rather than claiming equivalence. |

---

## 21. References

- HIEW help (structured mirror, accurate keymap): https://taviso.github.io/hiewdocs/ — source: https://github.com/taviso/hiewdocs
- Official site & feature list: https://www.hiew.ru/
- HEM SDK (the actual C header): https://github.com/0xeb/hiew-sdk-cpp — `src/hiewsdk/hem.h`; HEM page: http://www.hiew.ru/hem.html
- Wikipedia HIEW: https://en.wikipedia.org/wiki/HIEW
- aldeid HIEW wiki: https://www.aldeid.com/wiki/Hiew
- yurisk HIEW tutorial series: https://yurisk.info/2017/05/24/HIEW-hex-editor-tutorials-series-part-2-basics/
- Reference tools: BIEW/BEYE (https://sourceforge.net/projects/beye/), HT Editor, radare2/Cutter, ImHex, HxD, wxHexEditor, hexyl, 010 Editor, Kaitai Struct.
- Rust libraries: ratatui, crossterm, goblin, capstone, keystone, iced-x86, memmap2, wasmtime, mlua/rhai.

---

## 22. Security model — viewing malware safely

> **Foundational principle:** hiewLM is a tool for malware analysts. Opening a
> ransomware/trojan sample to view **must be absolutely harmless** — no different from
> `cat`/`xxd`. Security is not an add-on feature; it is an architectural constraint
> throughout.

### 22.1 The "data-only, never behavior" principle

hiewLM treats **every byte of the target file as PASSIVE DATA**, never as code to run:

| Operation | What hiewLM DOES | What hiewLM ABSOLUTELY DOES NOT do |
|---|---|---|
| Open file | `open()` + read-only `mmap`, or read into a buffer | ❌ No `LoadLibrary`/`dlopen`/`exec`/`CreateProcess` on the target file |
| Disassemble | **Decode** bytes → mnemonic text (Capstone only decodes) | ❌ No emulation, no JIT, no running instructions |
| Assemble-at-cursor | Keystone **encodes** text → bytes in the buffer | ❌ No executing the produced bytes |
| View EXE header | Passively parse fields | ❌ No calling the entry point, no resolving/running imports, no real mapping into an address space to "try running it" |
| Follow branch/xref | Compute the target offset then **move the display cursor** | ❌ No moving the real execution flow |
| Structure/template | Parse data per a declarative description | ❌ Templates are not runnable machine code (see 22.4) |
| Crypt engine | Interpret a safe DSL over the buffer | ❌ No native code, no JIT |

**Architectural consequence:** across all of `hiewlm-core`, `hiewlm-fmt`,
`hiewlm-asm` **there is no code path** that calls `std::process::Command`,
`libloading`, `dlopen`, or any API that loads/runs code from file content. This is
**enforced by automated tests** (CI grep + `#![forbid]` lint, see 22.7).

### 22.2 The real attack vectors & how they're blocked

The paradox: the very tool that *analyzes* malware is itself an attack surface (many
historical CVEs are in analyzer parsers). The vectors and mitigations:

| # | Vector | Risk | Mitigation in hiewLM |
|---|---|---|---|
| 1 | **Parser vulnerabilities** (deliberately malformed PE/ELF/Mach-O) | Buffer overflow, integer overflow → RCE inside hiewLM itself | Written in **memory-safe Rust**; **defensive** parsers (every offset/size bound-checked, `checked_add`, no `unwrap` on external data); **`#![forbid(unsafe_code)]`** in the parser crate; **continuous fuzzing** (`cargo-fuzz`) — a panic = a merge-blocking bug |
| 2 | **Resource bombs** (headers declaring 4GB sections, self-referential import loops, deep recursion) | OOM, hang, DoS | **Hard limits**: max sections/imports/symbols, max recursion depth, parse timeout, lazy-parse (only parse what's on screen); loop detection via a visited-set |
| 3 | **mmap file changing/truncated** underneath us | `SIGBUS`/crash reading a region that vanished | Catch `SIGBUS` (or use checked reads instead of mmap for untrusted sources); open with an appropriate share mode; snapshot the length at open time |
| 4 | **Path traversal / symlink** in sidecars (`.hiewlm/names`…) or "write block to file" | Overwrite system files, escape the directory | Normalize & validate paths; don't follow symlinks when writing; atomic write via temp + rename; confirm the write path |
| 5 | **Malicious file/section/symbol names** (ANSI escape, control chars) rendered to the terminal | **Terminal injection** → running commands via escape sequences | **Sanitize every string from the file** before rendering: strip/escape control chars & ESC (`\x1b`), never print raw file bytes to the terminal |
| 6 | **Malicious plugin** | Arbitrary code execution on the analyst's machine | Plugins run in a **WASM sandbox** (`wasmtime`) — no FS/network/syscalls unless the host explicitly grants; Lua/Rhai scripts are API-restricted (see 22.5) |
| 7 | **Malicious structure template** (a `.ksy`/pattern from an untrusted source) | If the template were a Turing-complete language with side effects | The template runtime is **data-only, no I/O, with step/memory limits** (see 22.4) |
| 8 | **Accidentally committing writes to the sample/disk** | Corrupt evidence, trigger the sample's integrity-based logic | **Read-only by default**; edits stay in the journal; commit requires an explicit action; **DOES NOT update the timestamp** unless the user opts in (unlike HIEW `F10` — see note 23.4); multi-layer warnings when writing to a physical/logical disk |
| 9 | **Network leak / telemetry** while analyzing on an air-gapped machine | Leak the sample, inadvertently call home to a C2 | **Zero network by default**: hiewLM opens no sockets; no auto-update, no telemetry; any future network feature must be explicit opt-in |
| 10 | **Auto-loading embedded content** (icon, resource, overlay, embedded PE) | Inadvertently handing a secondary payload to a system handler | Only display as bytes/hex; never hand it to an external app; "open embedded object" = open it as a new buffer in hiewLM, not via the OS |

### 22.3 Process sandbox (defense in depth, M2+)

Beyond Rust's memory safety, add an OS isolation layer for the untrusted-data parsing:

- **Linux:** `seccomp-bpf` restricting syscalls (read/write already-open fds only,
  forbid `execve`, `socket`, `ptrace`), optionally Landlock for the filesystem.
- **macOS:** a restrictive sandbox profile; consider a separate parser process.
- **Windows:** a job object + restricted token; forbid child-process creation.
- **"Privilege separation" architecture (optional):** the format parser runs in a
  minimal-privilege child process, talking to the UI over IPC — a parser vulnerability
  still can't escape. Placed at M2 because it's complex, but `hiewlm-fmt` is designed
  from the start to be pushable into a separate process.

### 22.4 Structure/Template engine safety

The structure viewer ([§16.4](#163-structure-viewer--template)) reads descriptions
from possibly untrusted sources → it must be non-executable:

- A **purely declarative** runtime: read fields by type/offset, limited
  arithmetic/conditional expressions — **no I/O, no system calls, no native code**.
- **Resource limits:** a cap on computation steps, memory, and depth; on exhaustion,
  stop safely with a message.
- If embedding Kaitai: use the runtime to interpret data, **not** generate + compile +
  run generated code.

### 22.5 Crypt engine & scripting safety

- **Crypt DSL** (`Alt+F3`): a pure interpreter over the buffer (xor/add/rol/…); no
  FS/network/OS access; with a loop cap.
- **Macro/script Lua/Rhai:** run with an **allowlist** host API — only editor commands
  (read/write buffer, search, navigate). **By default NO** `io`, `os`, `require`, or
  network. Expanding privileges requires a declaration and user consent.

### 22.6 Secure open & write handling

- Open: read-only, no side effects, no file creation, no modifying the sample's
  timestamp/atime (open with flags to avoid updating atime if the OS supports it).
- Write: via the edit journal → an explicit commit (`F9`) → an **atomic write**
  (temp + fsync + rename) with an optional `.bak`; in-place write only for same-size
  edits the user chose.
- Clipboard/screenshot (`Alt+P`): contains only data the user actively selected; warns
  when copying a large region.

### 22.7 Enforcing & verifying security (turning principles into constraints)

1. **Mandatory lints:** `#![forbid(unsafe_code)]` in
   `hiewlm-core`/`hiewlm-fmt`/`hiewlm-asm` (unsafe is only allowed, reviewed, at the
   Capstone/Keystone FFI and mmap layers — isolated in small documented modules).
2. **"No-exec" test:** a CI test greps the whole source to ensure there's no
   `Command::new`, `exec*`, `dlopen`, `LoadLibrary`, `libloading` outside the plugin
   sandbox layer; a violation fails the build.
3. **Fuzzing:** a corpus of malformed binaries for every parser; run in CI + OSS-Fuzz
   if public.
4. **Dependency audit:** `cargo-deny`/`cargo-audit` block crates with CVEs; minimize
   dependencies.
5. **A documented threat model** with each release; terminal-sanitize has snapshot
   tests with ESC-containing input.
6. **Least privilege:** hiewLM neither needs nor asks for admin/root to view a normal
   file.

---

## 23. Faithfulness to the original HIEW UI

> Goal: a HIEW user opens hiewLM and **operates it immediately without relearning**.
> "Faithful" means the layout, key rhythm, and visual feel match — not just look
> similar.

### 23.1 Screen layout matching part for part

HIEW has a very distinctive structure to reproduce exactly:

```
┌─ Title/status line (1 line, inverse color) ──────────────────────────┐
│ C:\sample.exe        ФL  RW  a32  00000400  ... .00401000    24576    │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│                 CONTENT AREA (Text / Hex / Decode)                    │
│                                                                       │
├───────────────────────────────────────────────────────────────────────┤
│ 1Global 2FnHdr 3Crypt 4ReLoad 5    6String 7Direct 8Table 9  10Quit   │  ← Fn bar
└───────────────────────────────────────────────────────────────────────┘
```

Things that must match:
- **Top status line, inverse color (bright background),** field order: file path ·
  state indicator (mode/RO-RW/arch-bitness) · current offset · VA (`.xxxxxxxx`) · file
  size. Offset formatted as **8 hex digits** like HIEW.
- **Bottom function-key bar** as `<number><label>` written together (like `1Global
  2FnHdr`), **inverse color**, contents changing per mode and per held modifier.
- **Hex area:** 8-hex offset column, hex byte block, `│`, ASCII column — HIEW's exact
  spacing.
- **Decode area:** `offset/VA │ bytes-hex │ mnemonic operands`, branch arrows, hotkey
  numbers next to jump instructions.

### 23.2 The default "HIEW Classic" theme

- The default theme reproduces the classic palette: **dark blue background, gray/white
  text, status bar & Fn-bar with a cyan background and black text** — a Norton
  Commander/DOS feel.
- Truecolor & modern dark/light themes are allowed as options, but **the first open is
  HIEW Classic**.
- Block cursor `█` in view mode, caret `▏` in edit mode — like HIEW.

### 23.3 Key rhythm & feel

- `Enter` cycles Hex→Code→Text; `F4` menu; `F3` edit; `F5` goto; exactly the map in
  [§10](#10-keymap).
- Dialogs open as **framed, centered popups** with their own Fn-bar (goto, search,
  header, calc) — HIEW's style.
- Number entry defaults to **hex base**, suffix `t` = decimal; VA entered with a `.`
  prefix — keeping the muscle-memory syntax.
- Instant feedback, no gratuitous animation; everything "responds" to the key
  immediately.

### 23.4 Deliberate differences from HIEW (and why)

Still "faithful" but fixing a few things for safety/modernity — **stated clearly so
there are no surprises**:

| Original HIEW | hiewLM | Reason |
|---|---|---|
| `F10` exit **does** update the file timestamp | hiewLM **does not** change the timestamp by default; changing it is opt-in | Evidence safety when analyzing malware ([§22.6](#226-secure-open--write-handling)) |
| Editable immediately on open | **Read-only by default**, `F3` to enable editing | Avoid accidentally writing to the sample |
| 8 bookmarks | Keep `Alt+1..8` like HIEW, but also allow named bookmarks (M2) | Compatible + extended |
| 16 fixed colors | HIEW Classic default + optional truecolor themes | Keep the feel, add choices |

Principle: **every difference must be a superset** — HIEW keys/workflows still work;
new things only add.

### 23.5 "Strict HIEW" mode

Provide a `--compat=hiew` preset (and in `keymap.toml`) that locks the keymap + Fn-bar
labels to exactly HIEW 100% for purists who want absolute muscle memory.

---

## 24. Clean code & extensibility principles

> Goal: add a **CPU architecture**, a **file format**, a **view type**, or a
> **plugin** **without modifying the core** — just register it.

### 24.1 Trait abstractions (clear extension points)

Every axis of change sits behind a trait; adding a new one = implement the trait +
register it in the registry:

```rust
/// A data source (file / disk / process / stdin)
trait DataSource {
    fn len(&self) -> u64;
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize>;
    fn writable(&self) -> bool;
}

/// An executable-format detector + parser
trait FormatParser {
    fn probe(&self, data: &dyn DataSource) -> Option<Confidence>; // detection
    fn parse(&self, data: &dyn DataSource) -> Result<ExecutableModel>;
}

/// A disassembler/assembler backend for one architecture
trait Architecture {
    fn disasm(&self, bytes: &[u8], addr: u64, bits: Bits) -> Vec<Insn>;
    fn asm(&self, text: &str, addr: u64, bits: Bits) -> Result<Vec<u8>>;
    fn branch_target(&self, insn: &Insn) -> Option<u64>;
}

/// A view mode (Hex/Text/Code/… or added by a plugin)
trait ViewMode {
    fn render(&self, ctx: &ViewCtx, area: Rect, buf: &mut Frame);
    fn handle(&mut self, key: Key, ctx: &mut ViewCtx) -> Option<Command>;
}
```

- **Registry pattern:** `FormatRegistry`, `ArchRegistry`, `ViewRegistry`,
  `PluginRegistry` hold the list of implementers; the core iterates over the registry,
  not hard-coding each type. → adding a new ELF variant or a RISC-V arch is a
  one-line registration.

### 24.2 Strict layering (already noted in [§5](#5-software-architecture))

- `hiewlm-core` knows **nothing** about the terminal, ratatui, or Capstone → purely
  testable, reusable for a GUI/CLI.
- Dependencies flow **only downward** (tui → app → core/fmt/asm); reverse dependencies
  are forbidden, enforced by the crate architecture (Cargo forbids cycles).
- The UI **contains no business logic**; it translates keys → `Command` and renders
  `State`. All mutation goes through Command ([§5.3](#53-command-pattern)) → a single
  point for undo/macro/script/test.

### 24.3 Code conventions

- **No "god object":** `Editor` coordinates, but buffer/search/asm/format are
  independent modules with narrow APIs.
- **Strong types for domain concepts:** `FileOffset(u64)`, `Va(u64)`, `LocalOff`,
  `GlobalOff` are distinct newtypes → the compiler blocks offset/VA confusion (a
  classic hex-editor bug class).
- **Explicit errors:** `Result` + `thiserror` in libraries, `anyhow` at the edges; **no
  `panic!`/`unwrap` on file data** (only for internal invariants).
- **Document the public API** (`#![warn(missing_docs)]` in library crates); every
  extension trait has an example.
- **Feature flags:** `capstone`, `keystone`, `wasm-plugins`, `disk-access` toggleable
  → a lightweight "core-only" build, or a full build.
- **Consistent formatting:** `rustfmt` + `clippy` (deny warnings) in CI.

### 24.4 User extensibility (no rebuild required)

- Add an **architecture/decoder** via a WASM plugin registering an `Architecture`.
- Add a **format/struct** via a Kaitai/DSL template — no Rust required.
- Add **commands/operations** via Lua/Rhai macros/scripts mapped to `Command`.
- A **versioned host API** (semver) so old plugins don't break as the core evolves.

### 24.5 Long-term project health

- ADRs (Architecture Decision Records) in `docs/adr/` for each major decision
  (choosing TUI, choosing the piece-table, choosing WASM…).
- The public API has **compatibility checks** (cargo-semver-checks) before a release.
- Each crate has a README stating its responsibility boundary; the dependency diagram
  is kept up to date per milestone.

---

*This is a living design document — updated each milestone. Suggested next step:
scaffold the Cargo workspace (`hiewlm-core` + `hiewlm-tui`) and implement M0, with the
three pillars [§22–§24] pre-wired from the first commit (forbid-unsafe, no-exec test,
HIEW Classic theme, trait registry).*
