//! Key handling for every dialog.
//!
//! One function per dialog shape, all of them in one place: the routing is
//! easier to check when the alternatives sit next to each other.

use super::*;

impl super::App {
    pub(super) fn handle_dialog_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode::*;
        let Some(dialog) = self.dialog.take() else {
            return;
        };
        match dialog {
            Dialog::Message { title, body, scroll } => match key.code {
                Esc | Enter | Char('q') => {}
                Left => {
                    self.hscroll_by(-8);
                    self.dialog = Some(Dialog::Message { title, body, scroll });
                }
                Right => {
                    self.hscroll_by(8);
                    self.dialog = Some(Dialog::Message { title, body, scroll });
                }
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
                // Ctrl+A lists every match instead of jumping to the next one.
                Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.confirm_search(&input.clone(), kind);
                    self.search_all();
                }
                Tab => {
                    let kind = kind.next();
                    self.dialog = Some(Dialog::Search { input, kind });
                }
                // Up/Down walk the patterns you have already used.
                Up => {
                    self.search_hist_pos = (self.search_hist_pos + 1).min(self.search_history.len());
                    let i = self.search_history.len().saturating_sub(self.search_hist_pos);
                    let input = self.search_history.get(i).cloned().unwrap_or(input);
                    self.dialog = Some(Dialog::Search { input, kind });
                }
                Down => {
                    self.search_hist_pos = self.search_hist_pos.saturating_sub(1);
                    let input = if self.search_hist_pos == 0 {
                        String::new()
                    } else {
                        let i = self.search_history.len().saturating_sub(self.search_hist_pos);
                        self.search_history.get(i).cloned().unwrap_or_default()
                    };
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
                Up => {
                    let n = BLOCK_MENU_CMDS.len();
                    self.dialog = Some(Dialog::BlockMenu { selected: (selected + n - 1) % n })
                }
                Down | Tab => {
                    let n = BLOCK_MENU_CMDS.len();
                    self.dialog = Some(Dialog::BlockMenu { selected: (selected + 1) % n })
                }
                Enter => self.apply(BLOCK_MENU_CMDS[selected]),
                Char('w') | Char('W') => self.apply(Command::OpenBlockWrite),
                Char('f') | Char('F') => self.apply(Command::OpenBlockFill),
                Char('z') | Char('Z') => self.apply(Command::BlockFillZero),
                Char('d') | Char('D') => self.apply(Command::BlockDelete),
                Char('r') | Char('R') => self.apply(Command::OpenBlockRead),
                Char('c') | Char('C') => self.apply(Command::BlockCopy),
                Char('m') | Char('M') => self.apply(Command::BlockMove),
                Char('i') | Char('I') => self.apply(Command::BlockInsert),
                Char('n') | Char('N') => self.apply(Command::NopInstruction),
                Esc => {}
                _ => self.dialog = Some(Dialog::BlockMenu { selected }),
            },
            Dialog::CopyMenu { selected } => {
                let n = crate::ui::COPY_MENU_LABELS.len();
                match key.code {
                    Up => self.dialog = Some(Dialog::CopyMenu { selected: (selected + n - 1) % n }),
                    Down | Tab => self.dialog = Some(Dialog::CopyMenu { selected: (selected + 1) % n }),
                    // Routed through `apply` like every other state change, so
                    // macros can replay a copy.
                    Enter => self.apply(Command::CopyItem(selected)),
                    Char(c @ '1'..='9') => self.apply(Command::CopyItem(c as usize - '1' as usize)),
                    Char('0') => self.apply(Command::CopyItem(9)),
                    Char('r') | Char('R') => self.apply(Command::CopyItem(10)),
                    Char('m') | Char('M') => self.apply(Command::CopyItem(11)),
                    Char('w') | Char('W') => self.apply(Command::CopyItem(12)),
                    Esc => {}
                    _ => self.dialog = Some(Dialog::CopyMenu { selected }),
                }
            }
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
                    self.save_notes();
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
            Dialog::Palette { mut input, sel } => {
                let matches = palette_matches(&input);
                let last = matches.len().saturating_sub(1);
                let mut sel = sel;
                let mut run = None;
                let mut close = false;
                match key.code {
                    Up => sel = sel.saturating_sub(1),
                    Down => sel = (sel + 1).min(last),
                    PageUp => sel = sel.saturating_sub(LIST_PAGE),
                    PageDown => sel = (sel + LIST_PAGE).min(last),
                    Enter => {
                        run = matches.get(sel).map(|e| e.2);
                        close = true;
                    }
                    Backspace => {
                        input.pop();
                        sel = 0;
                    }
                    Char(c) => {
                        input.push(c);
                        sel = 0;
                    }
                    Esc => close = true,
                    _ => {}
                }
                if !close {
                    self.dialog = Some(Dialog::Palette { input, sel });
                } else if let Some(cmd) = run {
                    self.apply(cmd);
                }
            }
            Dialog::Lens { mut input } => match key.code {
                Enter => self.set_lens(&input.clone()),
                Esc => {}
                Backspace => {
                    input.pop();
                    self.dialog = Some(Dialog::Lens { input });
                }
                Char(c) => {
                    input.push(c);
                    self.dialog = Some(Dialog::Lens { input });
                }
                _ => self.dialog = Some(Dialog::Lens { input }),
            },
            Dialog::XorHits { items, sel, mut filter } => {
                let view =
                    filter_indices(&items, |it: &(String, u64, String)| it.0.as_str(), &filter);
                let last = view.len().saturating_sub(1);
                let mut sel = sel;
                let mut chosen = None;
                let mut close = false;
                match key.code {
                    Up => sel = sel.saturating_sub(1),
                    Down => sel = (sel + 1).min(last),
                    PageUp => sel = sel.saturating_sub(LIST_PAGE),
                    PageDown => sel = (sel + LIST_PAGE).min(last),
                    Home => sel = 0,
                    End => sel = last,
                    Left => self.hscroll_by(-8),
                    Right => self.hscroll_by(8),
                    Enter => {
                        chosen = view.get(sel).map(|&i| {
                            let (_, off, recipe) = &items[i];
                            (*off, recipe.clone())
                        });
                        close = true;
                    }
                    Backspace => {
                        filter.pop();
                        sel = 0;
                    }
                    Char(c) => {
                        filter.push(c);
                        sel = 0;
                    }
                    Esc if !filter.is_empty() => {
                        filter.clear();
                        sel = 0;
                    }
                    Esc => close = true,
                    _ => {}
                }
                if !close {
                    self.dialog = Some(Dialog::XorHits { items, sel, filter });
                } else if let Some((off, recipe)) = chosen {
                    self.set_lens(&recipe);
                    self.goto_offset(off);
                    self.set_status(format!(
                        "Lens {recipe} at {} — the view is decoded, the file is untouched.",
                        self.display_addr(off)
                    ));
                }
            }
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
            Dialog::FileHits { title, items, sel, mut filter } => {
                let view =
                    filter_indices(&items, |it: &(String, PathBuf, u64)| it.0.as_str(), &filter);
                let last = view.len().saturating_sub(1);
                let mut sel = sel;
                let mut open = None;
                let mut close = false;
                match key.code {
                    Up => sel = sel.saturating_sub(1),
                    Down => sel = (sel + 1).min(last),
                    PageUp => sel = sel.saturating_sub(LIST_PAGE),
                    PageDown => sel = (sel + LIST_PAGE).min(last),
                    Home => sel = 0,
                    End => sel = last,
                    // Long lines are read by scrolling, not by guessing.
                    Left => self.hscroll_by(-8),
                    Right => self.hscroll_by(8),
                    Enter => {
                        open = view.get(sel).map(|&i| {
                            let (_, path, off) = &items[i];
                            (path.clone(), *off)
                        });
                        close = true;
                    }
                    Backspace => {
                        filter.pop();
                        sel = 0;
                    }
                    Char(c) => {
                        filter.push(c);
                        sel = 0;
                    }
                    Esc if !filter.is_empty() => {
                        filter.clear();
                        sel = 0;
                    }
                    Esc => close = true,
                    _ => {}
                }
                if !close {
                    self.dialog = Some(Dialog::FileHits { title, items, sel, filter });
                }
                if let Some((path, off)) = open {
                    self.reload(path, off);
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
            Dialog::JumpList { title, items, sel, mut filter } => {
                let view = filter_indices(&items, |it: &(String, u64)| it.0.as_str(), &filter);
                let last = view.len().saturating_sub(1);
                let mut sel = sel;
                let mut jump = None;
                let mut close = false;
                match key.code {
                    Up => sel = sel.saturating_sub(1),
                    Down => sel = (sel + 1).min(last),
                    PageUp => sel = sel.saturating_sub(LIST_PAGE),
                    PageDown => sel = (sel + LIST_PAGE).min(last),
                    Home => sel = 0,
                    End => sel = last,
                    // Long lines are read by scrolling, not by guessing.
                    Left => self.hscroll_by(-8),
                    Right => self.hscroll_by(8),
                    Enter => {
                        jump = view.get(sel).map(|&i| items[i].1);
                        close = true;
                    }
                    Backspace => {
                        filter.pop();
                        sel = 0;
                    }
                    // Typing filters the list — that is the only way a list of
                    // 20k strings is usable at triage speed.
                    Char(c) => {
                        filter.push(c);
                        sel = 0;
                    }
                    Esc if !filter.is_empty() => {
                        filter.clear();
                        sel = 0;
                    }
                    Esc => close = true,
                    _ => {}
                }
                if !close {
                    self.dialog = Some(Dialog::JumpList { title, items, sel, filter });
                }
                if let Some(off) = jump {
                    self.goto_offset(off);
                }
            }
            Dialog::Triage { pane, sel, mut filter } => {
                let last = self.triage_entries(pane, &filter).len().saturating_sub(1);
                let mut sel = sel;
                let mut pane = pane;
                let mut activate = false;
                let mut close = false;
                match key.code {
                    Right if key.modifiers.contains(KeyModifiers::SHIFT) => self.hscroll_by(8),
                    Left if key.modifiers.contains(KeyModifiers::SHIFT) => self.hscroll_by(-8),
                    Tab | Right => {
                        pane = pane.next();
                        sel = 0;
                    }
                    Left => {
                        pane = pane.prev();
                        sel = 0;
                    }
                    Up => sel = sel.saturating_sub(1),
                    Down => sel = (sel + 1).min(last),
                    PageUp => sel = sel.saturating_sub(LIST_PAGE),
                    PageDown => sel = (sel + LIST_PAGE).min(last),
                    Home => sel = 0,
                    End => sel = last,
                    Enter => {
                        activate = true;
                        close = true;
                    }
                    Backspace => {
                        filter.pop();
                        sel = 0;
                    }
                    Char(c) => {
                        filter.push(c);
                        sel = 0;
                    }
                    Esc if !filter.is_empty() => {
                        filter.clear();
                        sel = 0;
                    }
                    Esc => close = true,
                    _ => {}
                }
                if !close {
                    self.dialog = Some(Dialog::Triage { pane, sel, filter });
                } else if activate {
                    self.triage_activate(pane, sel, &filter);
                }
            }
            Dialog::Header { pane, sel, mut filter } => {
                let len = self.header_entries(pane, &filter).len().max(1);
                match key.code {
                    // Panes switch with arrows/Tab so letters stay free for filtering.
                    // Left/Right belong to the panes here, so Shift+arrows
                    // scroll a long row sideways.
                    Right if key.modifiers.contains(KeyModifiers::SHIFT) => {
                        self.hscroll_by(8);
                        self.dialog = Some(Dialog::Header { pane, sel, filter });
                    }
                    Left if key.modifiers.contains(KeyModifiers::SHIFT) => {
                        self.hscroll_by(-8);
                        self.dialog = Some(Dialog::Header { pane, sel, filter });
                    }
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
}
