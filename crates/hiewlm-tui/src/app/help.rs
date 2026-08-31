//! The in-app help text and the command palette — the two places that
//! describe hiewLM to its user, kept together so they cannot drift apart.

use super::Command;

pub(super) const HELP_TEXT: &str = "\
Every action has a plain-key shortcut; function keys are optional
(many terminals, e.g. macOS, don't send F1-F12).  up/down to scroll.
Press : for the command palette — every command by name.

TRIAGE  (start here)
  2  or  T                      triage screen: verdict, hashes, packer,
                                anomalies, capabilities, IOCs, entropy map
  s                             strings (ASCII + UTF-16), tagged with
                                url/ip/registry/lolbin/... — type to filter
  R                             YARA scan (rule file or folder)
  Alt+X                         find plaintext hidden behind a 1-byte key
  Alt+K                         recover a repeating XOR key from the block
  Rules for the API, packer and indicator tables live in data files:
  see `hiewlmc rules` for what is loaded and how to override it.
  Alt+S                         rebuild strings this function builds on the
                                stack (mov [rbp-x], 'h' ... — invisible to
                                `strings`)
  L                             view lens: decode the VIEW, not the file
  Y                             copy hash / block / IOC list / Markdown report
                                to the clipboard, or write the report to a file
  F                             rank every sample in this folder
  O                             open another file

NAVIGATE
  arrows PgUp PgDn Home End     move / scroll
  Ctrl+Home  Ctrl+End           start / end of file
  g  or  5                      goto  (n, +n, -n, .va, nt)
  + / -                         push / pop bookmark
  k                             name a bookmark
  Backspace                     go back (return stack)
  H                             jump history

VIEW
  Enter                         cycle Hex / Code / Text / Doc
  m  or  4                      mode menu
  In every popup: type to filter, up/down to scroll, and left/right to
  scroll sideways when a line is wider than the box (Shift+arrows in the
  header and triage views, whose arrows switch panes).
  Alt+A                         toggle offset / VA
  \\                             cycle theme
  E                             cycle text encoding

SEARCH
  /  or  7                      find; Tab picks hex / text / text-i (no case)
                                / utf-16 / asm.  Up/Down recalls past patterns,
                                Ctrl+A lists every match at once
  n  /  N                       find next / previous
  x                             search across the whole folder
                                (rewriting a folder lives in the CLI:
                                 hiewlmc replace <dir> ... --recursive)

EDIT  (the sample is LOCKED until you unlock it)
  Ctrl+W                        unlock / re-lock writing (or start with --rw)
  e  or  3                      edit (Tab hex<->ascii, Esc done)
  Ins                           insert / overwrite
  Ctrl+Z   Ctrl+Y               undo / redo
  w  or  9                      save (atomic, .bak backup)

BLOCK  (select: * or v, or Shift+arrows)
  y   p   d                     yank / paste / delete
  b                             block menu (write, read, copy, move, insert,
                                fill, zero, delete, NOP)
  C                             crypt the block (MODIFIES the bytes; L only
                                changes the view)
  M                             color the block (saved to sidecar)
  ] / [                         jump to next / prev colored marker

CODE  (disassembly)
  f                             follow branch under cursor
  o                             disassemble as x86 / x64 / ARM64 / ...
  6  or  F6                     cross-references to cursor
  Alt+F2                        NOP the instruction under cursor
  G                             control-flow graph of this function
  A                             assemble at cursor (x86/x64)
  ;                             add / edit comment
  Instructions are annotated with the API they call and the string they
  point at, and are disassembled through the lens when one is set.

DOCUMENT  (Office files: OLE2 .doc/.xls/.ppt, OOXML .docx/..., RTF)
  Enter or 4                    Doc mode, when the file is a document
  arrows                        left/right switch pane, up/down move
  Enter                         jump to that part's bytes
  < / >                         scroll a long row sideways
  Panes: Structure (storages, parts, objects) · Findings · Macros
  (decompressed VBA source and its keywords) · Info (metadata,
  external references such as a remote template).

ANALYSIS
  8  or  F8                     header view (info / sections / imports /
                                exports / resources) — imports are tagged
                                with their behaviour category
  i                             data inspector (int/float, LE+BE)
  =                             calculator (@o/@b/@w/@d/@q operands)
  h                             hashes (CRC32/MD5/SHA-256/BLAKE3)
  c                             compare with a file (diff); >/< next
  S                             split 2-pane diff view (needs c first)
  t                             apply a struct template
  K then 1-8 / Alt+1..8         set / jump to a numbered slot
  F12                           names, slots & functions (members for ZIP/PDF)

MISC
  Ctrl+.  Ctrl+P  Ctrl+L       record / play / loop macro (stops on search-fail)
  ?  or  1                     this help
  q  or  0  or  F10            quit
  Esc                          clear filter/highlight/block, then go back

Comments, bookmarks, slots and markers are saved automatically, keyed by the
sample's SHA-256 — rename or move the file and they follow it.

Read-only by default.  The target file is data, never executed.";

/// Every command the palette can run: `(name, key hint, command)`.
///
/// The letter keyspace is nearly full, so this is how a command stays reachable
/// when you cannot remember which letter it landed on.
pub const PALETTE: &[(&str, &str, Command)] = &[
    ("triage screen", "2 / T", Command::OpenTriage),
    ("header / sections / imports", "8", Command::OpenHeader),
    ("strings with indicators", "s", Command::OpenStrings),
    ("yara scan", "R", Command::RunYara),
    (
        "xor search (find hidden plaintext)",
        "Alt+X",
        Command::XorSearch,
    ),
    (
        "xor key from block (repeating key)",
        "Alt+K",
        Command::XorKey,
    ),
    (
        "stack strings in this function",
        "Alt+S",
        Command::StackStrings,
    ),
    (
        "view lens (decode without patching)",
        "L",
        Command::OpenLens,
    ),
    ("copy to system clipboard", "Y", Command::OpenCopyMenu),
    ("folder triage (rank samples)", "F", Command::FolderTriage),
    ("open another file", "O", Command::OpenFile),
    ("find", "/ or 7", Command::OpenSearch),
    ("find next", "n", Command::FindNext),
    ("find previous", "N", Command::FindPrev),
    ("list all matches", "Ctrl+A in find", Command::SearchAll),
    ("search every file in the folder", "x", Command::MultiSearch),
    ("goto address", "g / 5", Command::OpenGoto),
    ("names, functions, bookmarks", "F12", Command::OpenNames),
    ("cross-references to cursor", "6", Command::Xref),
    ("control-flow graph", "G", Command::OpenCfg),
    ("disassemble as (arch/bits)", "o", Command::OpenDisasmMenu),
    ("assemble at cursor", "A", Command::OpenAssemble),
    ("data inspector", "i", Command::OpenInspector),
    ("hashes of file/block", "h", Command::OpenHashes),
    ("calculator", "=", Command::OpenCalc),
    ("compare with a file (diff)", "c", Command::OpenDiff),
    ("split diff view", "S", Command::ToggleSplitView),
    ("apply struct template", "t", Command::OpenStruct),
    ("comment at cursor", ";", Command::OpenComment),
    ("name a bookmark", "k", Command::OpenNameBookmark),
    ("jump history", "H", Command::OpenHistory),
    ("block menu", "b", Command::OpenBlockMenu),
    ("crypt block (modifies bytes)", "C", Command::OpenCrypt),
    ("toggle write lock", "Ctrl+W", Command::ToggleWritable),
    ("edit bytes", "e / 3", Command::EnterEdit),
    ("save", "w / 9", Command::Save),
    ("cycle theme", "\\", Command::ToggleTheme),
    ("cycle text encoding", "E", Command::CycleEncoding),
    (
        "toggle offset / virtual address",
        "Alt+A",
        Command::ToggleAddrMode,
    ),
    ("help", "1 / ?", Command::Help),
    ("quit", "q / 0", Command::Quit),
];

/// Palette entries matching `query`: every whitespace-separated word must appear
/// somewhere in the name or the key hint.
pub fn palette_matches(query: &str) -> Vec<&'static (&'static str, &'static str, Command)> {
    let q = query.to_lowercase();
    let words: Vec<&str> = q.split_whitespace().collect();
    PALETTE
        .iter()
        .filter(|(name, keys, _)| {
            let hay = format!("{name} {keys}").to_lowercase();
            words.iter().all(|w| hay.contains(w))
        })
        .collect()
}
