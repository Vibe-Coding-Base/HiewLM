# hiewLM

A cross-platform (Windows · macOS · Linux) binary viewer/editor in the spirit of
**HIEW**. Keyboard-driven, Norton-Commander-style function-key bar, and absolutely
safe for viewing malware (it only reads data — the target file is never executed).

Full design: [docs/develop/00-overall-design.md](docs/develop/00-overall-design.md).

## Status — M0–M4 done (except HEM shim & GUI)

M4 (triage-first — make initial malware classification fast):

- **Triage screen** (`2` / `T` / F2): one keystroke for the whole verdict —
  score and badges, MD5/SHA-1/SHA-256/CRC32/**ssdeep**/imphash/rich-hash/authentihash,
  format, entropy, packer, sections with permissions and entropy, **PE anomalies**
  (RWX sections, zero raw size, 10x memory expansion, entry point outside code,
  overlay, TLS callbacks, broken checksum on a signed file), **capabilities**
  inferred from the import table, **indicators** (URL/IP/registry/LOLBin/mutex/PDB…)
  and an **entropy map**. Panes switch with ←→, typing filters, `Enter` jumps.
  The verdict then rides along on the status line.
- **`hiewlmc triage <file|dir>`**: the same report headless, `--json` for pipelines,
  `--fail-on-suspicious` for CI. A **directory** is ranked worst-first — a work queue.
- **Strings v2** (`s`): ASCII **and UTF-16LE**, each tagged with its indicator
  categories, filterable by typing (`url`, `lolbin`, `registry`…).
- **YARA** (`R`, `hiewlmc yara`): pure-Rust yara-x, so no native library is loaded.
  Matches become a jump list and feed the triage verdict. Build with `--features yara`.
- **Hidden strings**: triage brute-forces the single-byte transforms and reports
  plaintext the sample took the trouble to hide (`http://…  (lens: xor 41)`) —
  obfuscation is intent, so it also raises the score.
- **XOR lens** (`L`) and **key hunt** (`Alt+X`): find plaintext hidden behind a
  single-byte XOR/ADD/SUB/ROL, then **view the file decoded without patching it** —
  hex, text *and* disassembly go through the lens; the bytes on disk never change.
- **Annotated disassembly**: `call [rip+…]` shows the imported API it reaches
  (including through the IAT), and data references show the string they point at.
- **Copy out** (`Y`): hash, block (hex / C array / Python bytes / text), address,
  the whole indicator list or the whole report — to the *system* clipboard via
  OSC 52, so it works over SSH.
- **Folder triage** (`F`): rank the samples next to this one and open any of them.
- **Command palette** (`:`): every command by name, for the keys you don't recall.
- **Real write lock**: the sample is read-only until `Ctrl+W` (or `--rw`). Evidence
  does not get modified by a stray keystroke.

## Earlier milestones

Container plugins (ZIP · PDF):

- **ZIP** and **PDF** parsing live in their own crates behind a `ContainerParser` trait, activated by name — `hiewlmc --plugin zip|pdf|all`. They are read-only: nothing is decompressed, followed or executed.
- `hiewlmc container <file>` lists members with **real file offsets** (ZIP local file headers, PDF indirect objects) plus a structural summary; `F12` in the TUI jumps into any member.
- Both report **malware-relevant findings**: ZIP flags path traversal, dropper extensions, zip-bomb ratios, encryption and SFX/appended-ZIP stubs; PDF flags `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/JBIG2Decode`, XFA and data prepended before `%PDF-`. `--fail-on-suspicious` gives CI a non-zero exit.
- Plugins are **statically registered, never `dlopen`ed** — the security model bans runtime code loading, so isolation comes from the trait boundary (a plugin sees only `&[u8]`), not from a dynamic loader.

M3 (extensibility & automation):

- **WASM plugins** (`hiewlmc plugin <file> plugin.wasm`): sandboxed via wasmtime, fuel-bounded, host ABI `len/read/write/find/log`, no filesystem/network/syscalls.
- **Rhai scripting** (`hiewlmc script <file> script.rhai`): pure-Rust scripted patching with a buffer API (read/write/search).
- **Headless CLI** (`hiewlmc`): info/hex/disasm/search/replace/patch/hash/strings/entropy/packer for scripts & CI.
- **Process memory** (`pid:N`): read a live process on Linux via `/proc/pid/mem`.
- **Packer detection** (shown in the `8` header Info pane and the `2` triage screen; `hiewlmc packer`): signature DB + entropy/imports heuristics.
- **CFG view** (`G`): basic-block graph of the function at the cursor.
- **Text assemble-at-cursor** (`A`, x86/x86-64): type `xor eax, eax`, see the encoding live, `Enter` patches it in — NOP-padded to the instruction it replaces, and refused outright if it would not fit. Also `hiewlmc asm <file> <at> "mov rax, rbx"`.
- **Crypt engine** (`C`, `hiewlmc crypt`): XOR/ADD/SUB/AND/OR/ROL/ROR/NOT/NEG pipelines over a block — `xor dead, rol 3` — with repeating hex or ASCII keys. Tells you whether the recipe is invertible before you commit.
- **Numbered bookmark slots**: `K`+digit sets, `Alt+1..8` jumps; listed in `F12` alongside names and functions.
- **Advanced search**: `Tab` cycles hex / text / **UTF-16** / **instruction** (assembles what you type, then finds its encoding). Marking a block **scopes the search to it**; `Alt+N` searches backwards.
- **Split 2-pane diff** (`S` after `c`): both files at the same offsets side by side, differing bytes highlighted, `--` past the shorter file's end.
- **Full block ops** (`b` menu): write-to-file, read-file-in, copy, move, insert, fill, zero, delete.
- Deferred: HEM compat shim (loads native DLLs — forbidden by the `no_exec` security guard) and a GUI wrapper (needs a display; core is already UI-free and reusable).

M2 (beyond HIEW):

- **Binary diff** (`c`): compare with another file; differing bytes highlighted in Hex, `>`/`<` jump between differences.
- **Multi-architecture disassembly**: x86/x86-64 (iced-x86) + ARM/ARM64/MIPS/RISC-V/PowerPC/SPARC (Capstone) + a **WASM bytecode** decoder, in Code mode.
- **Recursive-traversal analysis**: from entry + exports, follows calls/jumps to recover a **function list** (in `F12`) and a **reliable cross-reference** index (`6`/`F6`).
- **More formats**: COFF and `ar` archives (goblin) plus NE/LE/LX/TE and **NLM** (NetWare) — shown in the header view.
- **Structure viewer** (`t`): a Kaitai-flavoured template DSL — `meta endian be`, per-field `le`/`be`, arrays (`u32[4]`), lengths that reference an earlier field (`char[namelen]`), `enum { 2=EXEC }` maps and `= value` validation. See `examples/elf_header.tpl`.
- **PEStudio-like header** (`8`/`F8`): decoded header struct fields (magic, subsystem, decoded Characteristics/DllCharacteristics flags, alignments, versions…), **file + per-section entropy**, and a **Resources** pane (type/name/lang/size) with **`Enter` to extract** a resource to a file. Panes filter as you type.
- **Data inspector** (`i`): int/float values at the cursor in both endians. **Block hashes** (`h`): CRC32/MD5/SHA-256/BLAKE3 over the selection or whole file (streamed).
- **Named bookmarks** (`k`, unlimited) and **multi-file search** (`x`) across the folder — both listed with `Enter` to jump/open.
- **Themes** (`\`): HIEW Classic / dark / light. **Text encodings** (`E`): ASCII / CP437 / Latin-1.
- File chooser: `c` (diff) and `t` (template) open a navigable **file browser**.

M0 + M1:

- **Hex** / **Text** / **Code** views, switch mode with `Enter`, `F4`/`m` menu.
- **Code mode**: multi-arch disassembly with **syntax highlighting** (mnemonic/register/number/comment colors — exact for x86/x64 via iced token kinds, heuristic for others). Navigate by instruction, follow the branch under the cursor (`f`), return (`Backspace`); **patch opcode bytes** in place (`e`/`F3`, live re-disassembly); **`o`** to choose how to disassemble (x86 / x86-64 / ARM64 / ARM / MIPS / RISC-V / PowerPC / SPARC, or auto); **`A`** to assemble an instruction from text.
- **Executable detection** (PE/ELF/Mach-O via goblin): arch/bits, entry point, real file-offset↔VA (`a`/`Alt+F1`, goto `.va`).
- **Header view** (`8`/`F8`): Info / Sections / Imports / Exports (`←→`/`Tab`/`n s i x` switch, `Enter` jump). Handles universal (fat) Mach-O.
- **Xref** (`6`/`F6`): find and jump to instructions that reference the cursor's address.
- **Names & comments**: `;` add/remove a comment (shown inline in Code mode), `F12` names list (entry, sections, comments) to jump.
- **Macros**: `Ctrl+.` record, `Ctrl+P` play (key-level).
- **Block operations** on a selection: yank `y`, paste `p`, delete `d`, and `b` menu (write-to-file, fill pattern, zero).
- **Bookmarks**: `+` push / `-` pop stack.
- In-place hex editing (`F3`/`e` -> nibbles / `Tab` to ASCII), undo/redo (`Ctrl+Z`/`Ctrl+Y`).
- Safe save `F9`/`w` (atomic write + `.bak` backup); read-only by default.
- Goto `F5`/`g` (`n` · `+n`/`-n` · `.va` · `nt`), find `F7`/`/` (hex/ASCII, `??` wildcard) with **all matches highlighted**, `n`/`Ctrl+Enter` next.
- Block selection (`*`/`v`, Shift+arrows), highlighted in Hex and Text; `Esc` clears highlight/selection (never quits).
- Insert/overwrite `Ins`, **HIEW Classic** theme, status line + Fn-bar.
- Works without function keys: every action has a letter/digit alias (see `?`/F1 help).

All HIEW-parity features are implemented; see the design doc §9.3b.

Three pillars baked in from the start (design §22–24):

- **Security:** `unsafe` is denied workspace-wide (the mmap exception carries a SAFETY note); a `no_exec` test blocks any code-loading/execution API in the source.
- **HIEW-faithful:** keymap + layout + theme follow HIEW.
- **Extensible:** trait + registry architecture (`FormatParser`, `DataSource`, `ContainerParser`), and `FileOffset`/`Va` newtypes to prevent offset↔VA mix-ups.

## Build & run

```sh
cargo build --release
./target/release/hiewlm <file>
```

### Windows / cross-compiling

On Windows, the normal MSVC toolchain needs nothing special:

```powershell
cargo build --release
.\target\release\hiewlm.exe <file>
```

To cross-compile Windows binaries from macOS or Linux, install mingw-w64 and use
the build script (it also installs the Rust std for the target if missing):

```sh
brew install mingw-w64            # macOS
# apt install gcc-mingw-w64-x86-64  # Debian/Ubuntu

./scripts/build-release.sh windows        # -> dist/hiewlm-windows-x64.exe
./scripts/build-release.sh all            # host + windows + linux
```

The linker settings live in [.cargo/config.toml](.cargo/config.toml). Note that a
distro/Homebrew Rust ships std for the host only, so cross-builds go through a
`rustup` toolchain — the script picks one up automatically when it is installed.

Basic keys: `1` help · `2` triage · `Enter` cycle mode · `3` edit · `5` goto · `7` find ·
`9` save · `q` quit · `:` command palette.

### YARA support

YARA scanning uses [yara-x](https://github.com/VirusTotal/yara-x) (pure Rust — no
libyara, nothing native is loaded at runtime). It is a heavy dependency, so it is
opt-in:

```sh
cargo build --release --features yara      # hiewlm and hiewlmc
```

Point `yara_rules` in `config.toml` at your rule file or folder and `R` scans with
it without prompting.

### Headless CLI (`hiewlmc`)

For scripts / CI (never executes the target):

```sh
hiewlmc info    <file>                       # format, arch, entry, sections, header fields
hiewlmc disasm  <file> [--at .VA] [--count N] [--arch x64]
hiewlmc hex     <file> [--at ADDR] [--count N]
hiewlmc search  <file> PATTERN [--hex]       # exit 1 if no match
hiewlmc replace <file> FIND WITH [--hex]     # writes, .bak backup
hiewlmc patch   <file> ADDR "90 90 c3"       # writes, .bak backup
hiewlmc hash    <file>                       # CRC32/MD5/SHA-256/BLAKE3
hiewlmc strings <file> [--min N] [--no-utf16] [--ioc]
hiewlmc entropy <file>                       # file + per-section
hiewlmc packer  <file>                       # packer/protector detection
hiewlmc script  <file> script.rhai           # automated patching (Rhai)
hiewlmc plugin  <file> plugin.wasm            # sandboxed WASM plugin
hiewlmc info    pid:1234                      # live process memory (Linux)

hiewlmc asm     <file> ADDR "xor eax, eax"   # assemble + patch (--dry-run to preview)
hiewlmc crypt   <file> "xor 5a, rol 3" [--at ADDR --count N]   # byte transforms
hiewlmc triage  <file> [--json] [--fail-on-suspicious]   # one-screen verdict
hiewlmc triage  <dir>  [--json]              # rank a folder of samples
hiewlmc triage  <file> --yara rules.yar      # fold a YARA scan into the verdict
hiewlmc yara    <file> rules.yar|rules_dir/  # scan only  (needs --features yara)
hiewlmc strings <file> --ioc                 # indicators only (URL/IP/registry/…)
hiewlmc plugins                              # list container plugins
hiewlmc --plugin all container <file>        # ZIP/PDF structure + findings
hiewlmc --plugin all container <f> --findings --fail-on-suspicious   # exit 1 if flagged
```
Addresses accept an offset (hex), `.va` (virtual address), or `Nt` (decimal).
File args also accept `pid:<N>` on Linux to read a live process's memory.

## Testing

```sh
cargo test        # buffer/undo, search, addressing, calc, packer, disasm, plugins, edit->save->disk, render, security
cargo clippy      # clean, no warnings
```

## Layout

| Crate | Role |
|---|---|
| `hiewlm-core` | Buffer (memmap + piece-table + journal), addressing, search, registry, crypt engine, container plugin API, struct templates, string/IOC extraction, import scoring, ssdeep, xor key hunting — pure, no UI. |
| `hiewlm-fmt` | Format detection (PE/ELF/Mach-O incl. fat, COFF, ar, NE/LE/LX/TE/NLM) → arch/bits/entry/VA map, imports/exports, header fields; PE overlay/TLS/debug/Authenticode/anomalies. |
| `hiewlm-triage` | The triage verdict: hashes, packer, capabilities, anomalies, indicators, entropy map, YARA — rendered as panes the TUI and CLI share. |
| `hiewlm-asm` | Disassembly: x86/x86-64 (iced-x86, branch targets + flow), ARM/ARM64/MIPS/RISC-V/PPC/SPARC (Capstone), WASM bytecode; plus an x86 text assembler. |
| `hiewlm-tui` | ratatui/crossterm UI, state machine, keymap, theme; the `hiewlm` binary. |
| `hiewlm-cli` | Headless batch tool (`hiewlmc`): info/hex/disasm/asm/search/replace/patch/hash/strings/entropy/packer/script/plugin/container for scripts & CI. |
| `hiewlm-plugin` | Sandboxed WASM plugin host (wasmtime): fuel-bounded, host ABI `len/read/write/find/log`, no fs/network. |
| `hiewlm-plugin-zip` | Container plugin: ZIP structure, member list, traversal/dropper/zip-bomb checks. |
| `hiewlm-plugin-pdf` | Container plugin: PDF object map + active-content (JS/launch/embedded) checks. |

## Roadmap

**M4 (done)** — triage-first: see the top of this file. Progress and the remaining
follow-ups live in [docs/develop/01-M4-triage-plan.md](docs/develop/01-M4-triage-plan.md).


M0 (done) · M1 (done) ·
M2 (done: diff + split view, multi-arch disasm incl. WASM, recursive analysis/xref,
more parsers incl. NLM, Kaitai-flavoured struct viewer, hashes, multi-file replace,
themes, data inspector, PEStudio-like header) ·
**M3 (done: WASM plugins, container plugins (ZIP/PDF), Rhai scripting, headless CLI,
process memory, packer detection, CFG view, text assembler)** — deferred: HEM native-DLL
shim (security-incompatible) and GUI wrapper. Details in design doc §9.4 / §9.5.
