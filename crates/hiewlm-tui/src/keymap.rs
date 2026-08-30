//! Key -> [`Command`] mapping for the main view, close to HIEW (design §10).
//! Dialog text input is handled separately in [`crate::app`].
//!
//! Every function-key action also has a non-Fn alias, because many terminals
//! (notably macOS laptops, where the top row defaults to media keys) never deliver
//! F1–F12. The digits shown in the Fn-bar are directly pressable, and there are
//! vim-style letter aliases too.

use crate::app::{App, Command, EditCol, Mode};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub fn map_main(app: &App, key: KeyEvent) -> Option<Command> {
    if app.editing {
        return map_edit(app, key);
    }
    // Code-mode extras that don't collide with the global digit/letter aliases:
    // `f` follows the branch under the cursor, Backspace returns.
    if app.mode == Mode::Code && app.code_supported() {
        if let Some(cmd) = map_code_extra(key) {
            return Some(cmd);
        }
    }
    map_view(key)
}

fn map_code_extra(key: KeyEvent) -> Option<Command> {
    let plain = !key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Char('f') | KeyCode::Char('F') if plain => Some(Command::FollowBranch),
        KeyCode::Backspace => Some(Command::NavBack),
        _ => None,
    }
}

/// Keys while editing: navigation, column/insert toggles, save/cancel, and byte
/// input. Everything else is ignored so stray keys don't corrupt data.
fn map_edit(app: &App, key: KeyEvent) -> Option<Command> {
    use KeyCode::*;
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    if key.code == Tab {
        return Some(Command::ToggleEditCol);
    }
    // Byte input takes priority (a hex digit / an ASCII char in the ascii column).
    if let Some(cmd) = edit_input(app, key) {
        return Some(cmd);
    }
    match key.code {
        Esc => Some(Command::CancelEdit),
        F(3) => Some(Command::CancelEdit),
        F(9) => Some(Command::Save),
        Char('s') if ctrl => Some(Command::Save),
        // Re-locking must be reachable from inside edit mode too.
        Char('w') if ctrl => Some(Command::ToggleWritable),
        Char('z') if ctrl => Some(Command::Undo),
        Char('y') if ctrl => Some(Command::Redo),
        Insert => Some(Command::ToggleInsert),
        Up => Some(Command::StepRow(-1)),
        Down => Some(Command::StepRow(1)),
        Left => Some(Command::Step(-1)),
        Right => Some(Command::Step(1)),
        PageUp => Some(Command::Page(-1)),
        PageDown => Some(Command::Page(1)),
        Home if ctrl => Some(Command::FileStart),
        End if ctrl => Some(Command::FileEnd),
        Home => Some(Command::LineStart),
        End => Some(Command::LineEnd),
        _ => None,
    }
}

/// Keys in the main (non-editing) view. Each F-key has a bare-key alias.
fn map_view(key: KeyEvent) -> Option<Command> {
    use KeyCode::*;
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    let plain = !ctrl && !alt;

    match (key.code, ctrl, alt, shift) {
        (Enter, false, false, false) => Some(Command::CycleMode),
        (Char('m'), true, _, _) => Some(Command::CycleMode), // Ctrl+M == Enter on some terminals

        (Char('z'), true, _, _) => Some(Command::Undo),
        (Char('y'), true, _, _) => Some(Command::Redo),
        (Char('s'), true, _, _) => Some(Command::Save),
        (Char('w'), true, _, _) => Some(Command::ToggleWritable),
        (Enter, true, _, _) => Some(Command::FindNext),

        (Insert, _, _, _) => Some(Command::ToggleInsert),

        // Selection: `*` / `v` toggle the mark; Shift+arrows extend it.
        (Char('*'), _, _, _) => Some(Command::ToggleMark),
        (Char('v'), _, _, _) if plain => Some(Command::ToggleMark),

        // Colored markers (HIEW Alt+M / Alt+N).
        (Char('M'), _, _, _) => Some(Command::ColorBlock),
        (Char('m'), _, true, _) => Some(Command::ColorBlock),
        // Alt+n walks the colored markers; `[`/`]` do the same without Alt.
        // (An Alt+Shift+n arm is pointless here: Shift+n arrives as 'N'.)
        (Char('n'), _, true, _) => Some(Command::NextMarker),
        (Char(']'), _, _, _) => Some(Command::NextMarker),
        (Char('['), _, _, _) => Some(Command::PrevMarker),

        // Block operations on the selection.
        (Char('y'), _, _, _) if plain => Some(Command::BlockYank),
        (Char('p'), _, _, _) if plain => Some(Command::BlockPaste),
        (Char('d'), _, _, _) if plain => Some(Command::BlockDelete),
        (Char('b'), _, _, _) if plain => Some(Command::OpenBlockMenu),
        // Triage screen: the one keystroke that answers "what am I looking at?".
        (Char('2'), _, _, _) if plain => Some(Command::OpenTriage),
        (Char('T'), _, _, _) => Some(Command::OpenTriage),
        (F(2), false, false, _) => Some(Command::OpenTriage),
        // Alt+F2 NOPs the instruction under the cursor (HIEW). It has to be
        // matched before the bare-F2 arm further down.
        (F(2), _, true, _) => Some(Command::NopInstruction),

        // Bookmark stack.
        (Char('+'), _, _, _) => Some(Command::BookmarkPush),
        (Char('-'), _, _, _) => Some(Command::BookmarkPop),

        // Binary diff: compare with a file, jump between differences.
        (Char('c'), _, _, _) if plain => Some(Command::OpenDiff),
        (Char('>'), _, _, _) => Some(Command::NextDiff),
        (Char('<'), _, _, _) => Some(Command::PrevDiff),

        // Structure viewer: apply a template at the cursor.
        (Char('t'), _, _, _) if plain => Some(Command::OpenStruct),

        // Choose how to disassemble (x86/x64/ARM…). HIEW uses Ctrl/Shift+F1.
        (Char('o'), _, _, _) if plain => Some(Command::OpenDisasmMenu),
        (F(1), true, _, _) => Some(Command::OpenDisasmMenu),
        (F(1), _, _, true) => Some(Command::OpenDisasmMenu),

        // Analysis / navigation extras.
        (Char('i'), _, _, _) if plain => Some(Command::OpenInspector),
        (Char('h'), _, _, _) if plain => Some(Command::OpenHashes),
        (Char('k'), _, _, _) if plain => Some(Command::OpenNameBookmark),
        (Char('s'), _, _, _) if plain => Some(Command::OpenStrings),
        (Char('H'), _, _, _) => Some(Command::OpenHistory),
        // `n` finds next, `N` finds previous (Alt+N too, for HIEW muscle memory).
        // NOP lives on Alt+F2 / the `b` menu — never one Shift away from `n`.
        (Char('N'), _, _, _) => Some(Command::FindPrev),
        (Char('='), _, _, _) => Some(Command::OpenCalc),
        (Char('A'), _, _, _) => Some(Command::OpenAssemble),
        (Char('C'), _, _, _) => Some(Command::OpenCrypt),
        // `C` rewrites the block; `L` only changes how it is displayed.
        (Char('L'), _, _, _) => Some(Command::OpenLens),
        (Char('R'), _, _, _) => Some(Command::RunYara),
        (Char('O'), _, _, _) => Some(Command::OpenFile),
        (Char('F'), _, _, _) => Some(Command::FolderTriage),
        // The command palette: everything by name, for the keys you forget.
        (Char(':'), _, _, _) => Some(Command::OpenPalette),
        (Char('x'), _, true, _) => Some(Command::XorSearch),
        (Char('X'), _, true, _) => Some(Command::XorSearch),
        (Char('K'), _, _, _) => Some(Command::SetSlotPrompt),
        (Char('S'), _, _, _) => Some(Command::ToggleSplitView),
        // `y` yanks a block into hiewLM's own clipboard; `Y` yanks a fact out to
        // the system clipboard (hash, block, indicator list).
        (Char('Y'), _, _, _) => Some(Command::OpenCopyMenu),
        (Char('c'), true, _, _) => Some(Command::OpenCopyMenu),
        (Char(c @ '1'..='8'), _, true, _) => Some(Command::JumpSlot(c as u8 - b'0')),
        (Char('G'), _, _, _) => Some(Command::OpenCfg),
        (Char('x'), _, _, _) if plain => Some(Command::MultiSearch),
        (Char('X'), _, _, _) => Some(Command::OpenReplace),
        (Char('\\'), _, _, _) => Some(Command::ToggleTheme),
        (Char('E'), _, _, _) => Some(Command::CycleEncoding),
        (Left, false, false, true) => Some(Command::SelectStep(-1)),
        (Right, false, false, true) => Some(Command::SelectStep(1)),
        (Up, false, false, true) => Some(Command::SelectRow(-1)),
        (Down, false, false, true) => Some(Command::SelectRow(1)),

        (Up, false, false, _) => Some(Command::StepRow(-1)),
        (Down, false, false, _) => Some(Command::StepRow(1)),
        (Left, false, false, _) => Some(Command::Step(-1)),
        (Right, false, false, _) => Some(Command::Step(1)),
        (PageUp, _, _, _) => Some(Command::Page(-1)),
        (PageDown, _, _, _) => Some(Command::Page(1)),
        (Home, true, _, _) => Some(Command::FileStart),
        (End, true, _, _) => Some(Command::FileEnd),
        (Home, false, _, _) => Some(Command::LineStart),
        (End, false, _, _) => Some(Command::LineEnd),

        // Alt+F1 (and its alias) toggles offset/VA display.
        (F(1), _, true, _) => Some(Command::ToggleAddrMode),
        (Char('a'), false, true, _) => Some(Command::ToggleAddrMode),

        // Function keys — kept for terminals that deliver them.
        (F(1), _, _, _) => Some(Command::Help),
        (F(3), _, _, true) => Some(Command::InsertByte),
        (F(3), _, _, false) => Some(Command::EnterEdit),
        (F(4), _, _, _) => Some(Command::OpenModeMenu),
        (F(5), _, _, _) => Some(Command::OpenGoto),
        (F(6), _, _, _) => Some(Command::Xref),
        (F(7), _, _, true) => Some(Command::FindNext),
        (F(7), _, _, false) => Some(Command::OpenSearch),
        (F(8), _, _, _) => Some(Command::OpenHeader),
        (F(9), _, _, _) => Some(Command::Save),
        (F(10), _, _, _) => Some(Command::Quit),
        (F(12), _, _, _) => Some(Command::OpenNames),
        (Char(';'), _, _, _) if plain => Some(Command::OpenComment),

        // Bare-key aliases (digits mirror the Fn-bar numbers; letters are mnemonic).
        (Char('1'), _, _, _) if plain => Some(Command::Help),
        (Char('?'), _, _, _) if plain => Some(Command::Help),
        (Char('3'), _, _, _) if plain => Some(Command::EnterEdit),
        (Char('e'), _, _, _) if plain => Some(Command::EnterEdit),
        (Char('4'), _, _, _) if plain => Some(Command::OpenModeMenu),
        (Char('5'), _, _, _) if plain => Some(Command::OpenGoto),
        (Char('g'), _, _, _) if plain => Some(Command::OpenGoto),
        (Char('6'), _, _, _) if plain => Some(Command::Xref),
        (Char('7'), _, _, _) if plain => Some(Command::OpenSearch),
        (Char('/'), _, _, _) if plain => Some(Command::OpenSearch),
        (Char('n'), _, _, _) if plain => Some(Command::FindNext),
        (Char('8'), _, _, _) if plain => Some(Command::OpenHeader),
        (Char('9'), _, _, _) if plain => Some(Command::Save),
        (Char('w'), _, _, _) if plain => Some(Command::Save),
        (Char('0'), _, _, _) if plain => Some(Command::Quit),
        (Char('q'), _, _, _) if plain => Some(Command::Quit),

        (Esc, _, _, _) => Some(Command::Escape),
        _ => None,
    }
}

fn edit_input(app: &App, key: KeyEvent) -> Option<Command> {
    match app.edit_col {
        EditCol::Hex => {
            if let KeyCode::Char(c) = key.code {
                if let Some(d) = c.to_digit(16) {
                    return Some(Command::TypeHex(d as u8));
                }
            }
            None
        }
        EditCol::Ascii => {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                || key.modifiers.contains(KeyModifiers::ALT)
            {
                return None;
            }
            if let KeyCode::Char(c) = key.code {
                if c.is_ascii() {
                    return Some(Command::TypeAscii(c as u8));
                }
            }
            None
        }
    }
}
