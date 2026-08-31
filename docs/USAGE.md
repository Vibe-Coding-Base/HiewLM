# Usage guide

hiewLM is two programs sharing one engine: `hiewlm`, the interactive viewer, and
`hiewlmc`, the headless tool for scripts and CI. Anything one can tell you, the
other can too.

- [The viewer](#the-viewer)
  - [Triage first](#triage-first)
  - [Views](#views)
  - [Documents and archives](#documents-and-archives)
  - [Finding things](#finding-things)
  - [Reading encoded data](#reading-encoded-data)
  - [Editing, and the write lock](#editing-and-the-write-lock)
  - [Notes that survive](#notes-that-survive)
  - [Complete key reference](#complete-key-reference)
- [The command line](#the-command-line)
- [Configuration](#configuration)
- [Detection rules](#detection-rules)
- [Workflows](#workflows)

---

## The viewer

```sh
hiewlm sample.exe        # a file
hiewlm ~/samples/        # a folder: opens the queue, worst-first
hiewlm sample.exe --rw   # unlocked for editing from the start
hiewlm pid:1234          # a live process (Linux)
```

Press `1` for help at any time, and `:` for the command palette if you cannot
remember a key. `Esc` backs out of whatever you are in — a filter, a highlight, a
selection, then the jump history — and never quits. `q` quits.

### Triage first

`2` (or `T`, or `F2`) opens the triage screen. Seven panes, `←→` to switch, type
to filter, `Enter` to jump to the offset a row refers to:

| Pane | What it answers |
|---|---|
| **Overview** | verdict and badges, size, format, entry point, entropy, packer/builder, signature, overlay, PDB path, and every hash — MD5, SHA-1, SHA-256, CRC32, ssdeep, imphash, rich hash, authentihash |
| **Risk** | structural anomalies, container and document findings, import notes |
| **Sections** | offset, VA, raw and virtual size, permissions, per-section entropy |
| **Capabilities** | what the imports can do, grouped by behaviour; `*` marks the APIs that are a signal on their own |
| **IOC** | indicators — URLs, IPs, registry keys, LOLBin command lines, mutexes — and plaintext recovered from behind a single-byte key |
| **Map** | entropy per block; high plateaus are packed or encrypted regions |
| **YARA** | rule matches, when a scan has run |

The verdict and its badges then stay on the status line: `[suspicious 61 PACKED
ENT7.9 OVL+128K TLS]`.

The score orders a queue; it does not convict a file. Everything it is built from
is visible in the panes.

### Views

`Enter` cycles Hex → Code → Text → Doc. `4` or `m` opens the mode menu.

**Hex** — `Alt+A` toggles offset/virtual address, `E` cycles text encoding,
`\` cycles theme, `i` opens the data inspector, `h` hashes the file or selection.

**Code** — multi-architecture disassembly (x86/x86-64 via iced, ARM/ARM64/MIPS/
RISC-V/PowerPC/SPARC via Capstone, plus a WASM decoder). `o` chooses the
architecture, `f` follows the branch under the cursor, `Backspace` returns, `6`
lists cross-references, `G` draws the control-flow graph, `;` adds a comment,
`A` assembles an instruction at the cursor.

Instructions are annotated with what they actually touch — the imported API a
call reaches (directly or through the IAT) and the string a data reference points
at. `Alt+S` rebuilds strings the function assembles on its stack, which never
appear in `strings` output at all.

**Text** — `E` switches between ASCII, CP437, Latin-1 and UTF-16.

**Doc** — see below; only offered for files that have a structure.

### Documents and archives

`Doc` mode reads OLE2 (`.doc`, `.xls`, `.ppt`), OOXML (`.docx`, `.xlsx`,
`.pptx`), RTF, PDF and ZIP. Four panes, `←→` to switch:

- **Structure** — storages and streams, package parts, PDF objects, archive
  members. `Enter` jumps to the bytes. For archives the listing shows what each
  member *is* (its magic number), not what its extension claims.
- **Findings** — what the structure means: a remote template, an auto-updating
  embedded object, a member whose name uses a right-to-left override, a central
  directory that disagrees with the local headers. A finding backed by several
  hits says `[Enter: 1874 matches]`; `Enter` opens the list, each entry showing
  the text it matched — the URLs themselves, not just that there are 1874.
- **Macros** — VBA source, *decompressed*, with its keywords grouped by what they
  do: auto-exec, execution, download, memory, persistence, obfuscation, evasion,
  lure.
- **Info** — metadata and external references.

`<` and `>` scroll a long row sideways.

Nothing in this path executes anything: a remote template is reported, never
fetched; a macro is read, never run.

### Finding things

`/` or `7` opens find. `Tab` cycles what you are searching for: hex, text,
case-insensitive text, UTF-16, or an assembled instruction. `↑`/`↓` recall past
patterns; `Ctrl+A` lists every match at once instead of stepping. `n` and `N` go
to the next and previous match. Marking a block first scopes the search to it.

- `s` — strings, ASCII and UTF-16, each tagged with the indicator categories it
  matches. Type `url`, `lolbin`, `registry` to filter.
- `x` — search every file in the folder.
- `R` — scan with YARA rules (needs `--features yara`).
- `F` — rank every sample in the folder by triage score.
- `F12` — names, functions, bookmarks, and document parts.
- `g` or `5` — go to an address: `1000` (hex), `+20`, `-20`, `.401000` (virtual),
  `256t` (decimal).

### Reading encoded data

Malware rarely stores its configuration in the clear.

- `Alt+X` hunts for known plaintext behind a single-byte XOR, ADD, SUB or ROL.
  `Enter` on a hit jumps there **and** puts the recovering recipe on the lens.
- `Alt+K` recovers a repeating XOR key from a marked block, ranked by how much
  the result looks like real plaintext.
- `L` sets the lens by hand (`xor 5a`, `add 10`, `rol 3`, `xor deadbeef`), or
  clears it with an empty input.

The lens decodes the **view** — hex, text *and* disassembly — while the file on
disk stays untouched. The status line shows `lens:xor 5a` so you never forget you
are not looking at the real bytes. `C` is the destructive counterpart: it
rewrites the block.

### Editing, and the write lock

The sample is read-only until you say otherwise. `Ctrl+W` unlocks (or start with
`--rw`); the status line changes from `ro` to `RW!`.

`e` or `3` enters edit mode — type hex, `Tab` switches to the ASCII column,
`Ins` toggles insert/overwrite, `Ctrl+Z`/`Ctrl+Y` undo and redo, `Esc` leaves.
`w` or `9` saves atomically and keeps a `.bak`.

Block operations work on a selection (`*` or `v`, or Shift+arrows): `y` yank,
`p` paste, `d` delete, `b` for the full menu (write to file, read a file in,
copy, move, insert, fill, zero, delete, NOP). `Alt+F2` NOPs the instruction under
the cursor. `M` colours a block; `[` and `]` walk the colours.

### Notes that survive

Comments (`;`), named bookmarks (`k`), numbered slots (`K` then a digit,
`Alt+1..8` to jump) and colour markers are saved automatically — keyed by the
sample's SHA-256, not its path. Rename or move the file and the notes follow it.

They live in `$XDG_DATA_HOME/hiewlm/notes/` (or `~/.local/share/hiewlm/notes/`,
or `%APPDATA%\hiewlm\notes\`).

### Complete key reference

| | |
|---|---|
| **Triage** | |
| `2` `T` `F2` | triage screen |
| `s` | strings with indicator tags |
| `R` | YARA scan |
| `Alt+X` | hunt for a single-byte key |
| `Alt+K` | recover a repeating XOR key from the block |
| `Alt+S` | rebuild stack strings |
| `L` | view lens |
| `Y` | copy menu (hash, block, indicators, report) |
| `F` | folder triage |
| `O` | open another file |
| **Navigate** | |
| arrows, PgUp/PgDn, Home/End | move |
| `Ctrl+Home` / `Ctrl+End` | start / end of file |
| `g` `5` | goto |
| `+` / `-` | push / pop the bookmark stack |
| `k` | name a bookmark |
| `Backspace` | back (return stack) |
| `H` | jump history |
| **View** | |
| `Enter` | cycle Hex / Code / Text / Doc |
| `m` `4` | mode menu |
| `Alt+A` | offset ↔ virtual address |
| `\` | cycle theme |
| `E` | cycle text encoding |
| **Search** | |
| `/` `7` | find (Tab: hex / text / text-i / utf-16 / asm) |
| `n` / `N` | next / previous |
| `x` | search the whole folder |
| **Analysis** | |
| `8` | header view |
| `i` | data inspector |
| `=` | calculator |
| `h` | hashes |
| `c` | compare with a file; `>` `<` next/prev difference; `S` split view |
| `t` | apply a struct template |
| `6` | cross-references |
| `G` | control-flow graph |
| `o` | disassemble as… |
| `A` | assemble at cursor |
| `F12` | names, functions, parts |
| **Edit** | |
| `Ctrl+W` | unlock / lock |
| `e` `3` | edit |
| `Ins` | insert / overwrite |
| `Ctrl+Z` `Ctrl+Y` | undo / redo |
| `w` `9` | save |
| `*` `v` | mark a block |
| `y` `p` `d` `b` | yank, paste, delete, block menu |
| `C` | crypt the block (destructive) |
| `M` `[` `]` | colour a block, walk colours |
| **Misc** | |
| `:` | command palette |
| `Ctrl+.` `Ctrl+P` `Ctrl+L` | record / play / loop a macro |
| `1` `?` | help |
| `V` | about: version, author, build features, rule counts |
| `q` `0` | quit |
| `Ctrl+Q` `F10` | quit from anywhere, including inside a dialog |

`q` inside a filterable popup types into the filter, which is what you want when
you are searching for `qemu`. `Ctrl+Q` and `F10` always quit.

In any popup: type to filter, `↑↓` and PgUp/PgDn to scroll, `←→` to scroll
sideways (Shift+`←→` in the header and triage views, whose arrows switch panes),
`Enter` to act, `Esc` to close.

---

## The command line

```
hiewlmc triage  <file|dir> [--format text|json|markdown] [--yara RULES]
                           [--fail-on-suspicious] [--min-score N]
hiewlmc office  <file> [--macros] [--matches] [--fail-on-suspicious]
hiewlmc info    <file>
hiewlmc hex     <file> [--at ADDR] [--count N]
hiewlmc disasm  <file> [--at ADDR] [--count N] [--arch x64]
hiewlmc strings <file> [--min N] [--no-utf16] [--ioc]
hiewlmc search  <file> PATTERN [--hex]
hiewlmc hash    <file>
hiewlmc entropy <file>
hiewlmc packer  <file>
hiewlmc xorkey  <file> [--at ADDR] [--count N] [--max-len N]
hiewlmc yara    <file> RULES                    # needs --features yara
hiewlmc rules   [--dump apis|packers|indicators|documents]
hiewlmc replace <file> FIND WITH [--hex]
hiewlmc replace <dir>  FIND WITH --recursive
hiewlmc patch   <file> ADDR "90 90 c3"
hiewlmc asm     <file> ADDR "xor eax, eax" [--dry-run]
hiewlmc crypt   <file> "xor 5a, rol 3" [--at ADDR --count N]
hiewlmc script  <file> script.rhai              # needs --features script
hiewlmc plugin  <file> plugin.wasm              # needs --features wasm
```

Addresses accept a hex offset, `.va` for a virtual address, `+n`/`-n` relative,
or `Nt` for decimal. File arguments also accept `pid:<N>` on Linux.

Exit codes: `0` success, `1` the condition the flag asked about (no match, score
at or above the threshold), `2` an error.

Writing commands keep a `.bak` unless `--no-backup` is given. `replace` refuses a
directory without `--recursive`: rewriting a folder of samples should be
something you typed out.

---

## Configuration

`$HIEWLM_CONFIG`, else `$XDG_CONFIG_HOME/hiewlm/config.toml`, else
`~/.config/hiewlm/config.toml`, else `%APPDATA%\hiewlm\config.toml`.

```toml
theme = "classic"          # classic | dark | light
encoding = "cp437"         # ascii | cp437 | latin1 | utf16
bytes_per_row = 16
yara_rules = "~/rules"     # scanned by R without prompting
plugins = []               # container plugins to activate
```

Other locations:

| What | Where |
|---|---|
| Notes (comments, bookmarks, markers) | `$XDG_DATA_HOME/hiewlm/notes/` |
| Rule overrides | `$XDG_CONFIG_HOME/hiewlm/rules/` (or `$HIEWLM_RULES_DIR`) |

---

## Detection rules

The API, packer, indicator and document tables are plain text files compiled into
the binary and overridable at run time. Only data is ever read; no rule file can
introduce code.

```sh
hiewlmc rules                       # what is loaded, and from where
hiewlmc rules --dump apis > ~/.config/hiewlm/rules/apis.txt
```

An override *replaces* the built-in table rather than merging with it, so what
you get is exactly what you can read in one file. The format is one record per
line, fields separated by `|`, `#` starts a comment:

```
# behaviour | api | strength | note
injection | WriteProcessMemory | strong | writes into another process
```

---

## Workflows

**Sorting a folder of samples.** The folder pass is deliberately bounded: files
over 64 MB are listed as `not scanned` rather than hashed in full, and it uses
fewer bytes for strings and hashes than a single-file report does. Ranking does
not need a SHA-1 of a 1.5 GB video, and the pass runs before the UI is
interactive.

 `hiewlmc triage ~/incoming --format markdown`
gives a ranked table to paste into a ticket; `hiewlm ~/incoming` opens the same
ranking as a queue you can walk with `Enter`.

**A document arrived by email.** Open it, press `2` for the verdict, then `Enter`
to Doc mode. Findings tells you whether it fetches a remote template or runs a
macro on open, and `Enter` on a finding opens every occurrence behind it; Macros
gives you the source. Nothing is fetched or run.

**An archive arrived by email.** Doc mode lists members with what each one really
is. A `.jpg` that is a PE, a name with a right-to-left override, or a local header
missing from the central directory are all findings, not things you have to spot.

**A packed executable.** The triage screen names the packer or the builder. The
Map pane shows where the high-entropy region is; `Alt+X` and `Alt+K` recover the
key over a marked block, and `L` lets you read the decoded bytes — and
disassemble them — without patching the sample.

**Writing it up.** `Y` then `w` writes `<sample>.triage.md` beside the file, and
that works while the sample is still locked: writing up a case must not require
unlocking evidence.
