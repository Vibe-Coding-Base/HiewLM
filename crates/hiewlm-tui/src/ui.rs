//! Rendering in the HIEW spirit: status line on top, content in the middle,
//! Fn-bar at the bottom.

use crate::app::{App, Dialog, HeaderPane, Mode};
use crate::theme::Theme;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

pub fn draw(f: &mut Frame, app: &mut App, theme: &Theme) {
    let area = f.area();
    f.render_widget(Block::default().style(theme.base()), area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    app.visible_rows = chunks[1].height.max(1) as usize;
    app.text_cols = chunks[1].width.max(1) as usize;

    draw_status(f, chunks[0], app, theme);
    if app.split_view && app.has_diff() {
        draw_split(f, chunks[1], app, theme);
        draw_fnbar(f, chunks[2], app, theme);
        if let Some(d) = &app.dialog {
            draw_dialog(f, area, d, theme);
        }
        return;
    }
    match app.mode {
        Mode::Hex => draw_hex(f, chunks[1], app, theme),
        Mode::Text => draw_text(f, chunks[1], app, theme),
        Mode::Code => draw_code(f, chunks[1], app, theme),
    }
    draw_fnbar(f, chunks[2], app, theme);

    if let Some(dialog) = &app.dialog {
        match dialog {
            Dialog::Header { pane, sel, filter } => {
                draw_header(f, area, app, *pane, *sel, filter, theme)
            }
            Dialog::Palette { input, sel } => draw_palette(f, area, input, *sel, theme),
            Dialog::XorHits { items, sel, filter } => {
                let labels: Vec<(String, u64)> =
                    items.iter().map(|(l, o, _)| (l.clone(), *o)).collect();
                draw_jump_list(
                    f,
                    area,
                    "Plaintext under a single-byte key",
                    &labels,
                    *sel,
                    filter,
                    theme,
                )
            }
            Dialog::Triage { pane, sel, filter } => {
                let entries = app.triage_entries(*pane, filter);
                let tabs: Vec<&str> =
                    hiewlm_triage::Pane::ALL.iter().map(|p| p.label()).collect();
                let title = format!(
                    " Triage — {}  [{}] ",
                    pane.label(),
                    tabs.join(" ")
                );
                draw_pane_list(f, area, &title, &entries, *sel, filter, theme)
            }
            Dialog::JumpList { title, items, sel, filter } => {
                draw_jump_list(f, area, title, items, *sel, filter, theme)
            }
            Dialog::FileHits { title, items, sel, filter } => {
                let labels: Vec<(String, u64)> =
                    items.iter().map(|(l, _, o)| (l.clone(), *o)).collect();
                draw_jump_list(f, area, title, &labels, *sel, filter, theme)
            }
            Dialog::FilePicker { dir, entries, sel, .. } => {
                draw_file_picker(f, area, dir, entries, *sel, theme)
            }
            Dialog::Message { title, body, scroll } => {
                draw_message(f, area, title, body, *scroll, theme)
            }
            Dialog::Calc { input } => draw_calc(f, area, app, input, theme),
            Dialog::Assemble { input } => draw_assemble(f, area, app, input, theme),
            _ => draw_dialog(f, area, dialog, theme),
        }
    }
}

fn draw_file_picker(
    f: &mut Frame,
    area: Rect,
    dir: &std::path::Path,
    entries: &[crate::app::PickEntry],
    sel: usize,
    theme: &Theme,
) {
    let width = 76.min(area.width.saturating_sub(2)).max(24);
    let height = 24.min(area.height.saturating_sub(2)).max(8);
    let rect = centered(area, width, height);
    f.render_widget(Clear, rect);

    let inner = height.saturating_sub(2) as usize;
    let first = if sel >= inner { sel - inner + 1 } else { 0 };
    let mut lines = Vec::with_capacity(inner);
    for (i, e) in entries.iter().enumerate().skip(first).take(inner) {
        let label = if e.is_dir { format!(" {}/", e.name) } else { format!(" {}", e.name) };
        let style = if i == sel {
            theme.selection()
        } else if e.is_dir {
            Style::default().bg(theme.dialog_bg).fg(theme.offset)
        } else {
            theme.dialog()
        };
        lines.push(Line::from(Span::styled(label, style)));
    }
    let shown = dir.to_string_lossy();
    let title = format!(" Pick file — {shown}  (↑↓ · Enter open/select · Bksp up · Esc) ");
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .style(theme.dialog());
    f.render_widget(Paragraph::new(lines).block(block).style(theme.dialog()), rect);
}

/// A centered, scrollable list of labelled entries (names, xrefs, strings).
/// Typing filters it; the title shows the live filter and the match count.
#[allow(clippy::too_many_arguments)]
fn draw_jump_list(
    f: &mut Frame,
    area: Rect,
    title: &str,
    items: &[(String, u64)],
    sel: usize,
    filter: &str,
    theme: &Theme,
) {
    let width = 92.min(area.width.saturating_sub(2)).max(24);
    let height = 26.min(area.height.saturating_sub(2)).max(6);
    let rect = centered(area, width, height);
    f.render_widget(Clear, rect);

    let view = crate::app::jump_view(items, filter);
    let inner = height.saturating_sub(2) as usize;
    let first = if sel >= inner { sel - inner + 1 } else { 0 };
    let mut lines = Vec::with_capacity(inner);
    if view.is_empty() {
        let msg = if filter.is_empty() { "  (none)" } else { "  (no match)" };
        lines.push(Line::from(Span::raw(msg)));
    }
    for (i, (label, _)) in view.iter().enumerate().skip(first).take(inner) {
        let style = if i == sel {
            theme.selection()
        } else if is_warn_row(label) {
            theme.warn()
        } else {
            theme.dialog()
        };
        lines.push(Line::from(Span::styled(format!(" {label}"), style)));
    }
    let filt = if filter.is_empty() {
        String::new()
    } else {
        format!("  [/{filter}]  {}/{}", view.len(), items.len())
    };
    let block = Block::default()
        .title(format!(" {title}{filt}  (type=filter · ↑↓ PgUp/Dn · Enter jump · Esc) "))
        .borders(Borders::ALL)
        .style(theme.dialog());
    f.render_widget(Paragraph::new(lines).block(block).style(theme.dialog()), rect);
}

/// The command palette: type words, pick a command.
fn draw_palette(f: &mut Frame, area: Rect, input: &str, sel: usize, theme: &Theme) {
    let matches = crate::app::palette_matches(input);
    let width = 76.min(area.width.saturating_sub(2)).max(30);
    let height = 20.min(area.height.saturating_sub(2)).max(6);
    let rect = centered(area, width, height);
    f.render_widget(Clear, rect);

    let mut lines = vec![Line::from(Span::styled(
        format!(" > {input}_"),
        theme.dialog(),
    ))];
    let inner = height.saturating_sub(3) as usize;
    let first = if sel >= inner { sel - inner + 1 } else { 0 };
    if matches.is_empty() {
        lines.push(Line::from(Span::raw("   (no command matches)")));
    }
    for (i, (name, keys, _)) in matches.iter().enumerate().skip(first).take(inner) {
        let style = if i == sel { theme.selection() } else { theme.dialog() };
        lines.push(Line::from(Span::styled(format!(" {name:<44} {keys}"), style)));
    }
    let block = Block::default()
        .title(" Commands  (type to filter · ↑↓ · Enter runs · Esc) ")
        .borders(Borders::ALL)
        .style(theme.dialog());
    f.render_widget(Paragraph::new(lines).block(block).style(theme.dialog()), rect);
}

/// Rows that report something worth noticing are drawn in the warning colour.
/// A leading `!` is the marker producers use (risky imports, tagged strings);
/// triage findings say it in words.
fn is_warn_row(label: &str) -> bool {
    label.starts_with('!') || label.contains("[suspicious]") || label.contains("SUSPICIOUS")
}

/// A large, scrollable, filterable list of `(label, jump target)` rows. Both the
/// header view and the triage screen are this widget with different content.
#[allow(clippy::too_many_arguments)]
fn draw_pane_list(
    f: &mut Frame,
    area: Rect,
    title: &str,
    entries: &[(String, Option<u64>)],
    sel: usize,
    filter: &str,
    theme: &Theme,
) {
    let width = 110.min(area.width.saturating_sub(2)).max(24);
    let height = 34.min(area.height.saturating_sub(2)).max(8);
    let rect = centered(area, width, height);
    f.render_widget(Clear, rect);

    let inner = height.saturating_sub(2) as usize;
    let first = if sel >= inner { sel - inner + 1 } else { 0 };
    let mut lines = Vec::with_capacity(inner);
    if entries.is_empty() {
        let msg = if filter.is_empty() { "  (none)" } else { "  (no match)" };
        lines.push(Line::from(Span::raw(msg)));
    }
    for (i, (label, jump)) in entries.iter().enumerate().skip(first).take(inner) {
        let style = if i == sel {
            theme.selection()
        } else if is_warn_row(label) {
            theme.warn()
        } else if jump.is_some() {
            theme.dialog()
        } else {
            Style::default().bg(theme.dialog_bg).fg(theme.ascii_other)
        };
        lines.push(Line::from(Span::styled(format!(" {label}"), style)));
    }
    let filt = if filter.is_empty() { String::new() } else { format!("[/{filter}] ") };
    let block = Block::default()
        .title(format!("{title}{filt} (←→ pane · type=filter · Enter jump · Esc) "))
        .borders(Borders::ALL)
        .style(theme.dialog());
    f.render_widget(Paragraph::new(lines).block(block).style(theme.dialog()), rect);
}

#[allow(clippy::too_many_arguments)]
fn draw_header(
    f: &mut Frame,
    area: Rect,
    app: &App,
    pane: HeaderPane,
    sel: usize,
    filter: &str,
    theme: &Theme,
) {
    let entries = app.header_entries(pane, filter);

    // Large: fill most of the screen so long lists and header fields are readable.
    let width = 92.min(area.width.saturating_sub(2)).max(24);
    let height = 30.min(area.height.saturating_sub(2)).max(8);
    let rect = centered(area, width, height);
    f.render_widget(Clear, rect);

    let inner = height.saturating_sub(2) as usize;
    let first = if sel >= inner { sel - inner + 1 } else { 0 };

    let mut lines = Vec::with_capacity(inner);
    if entries.is_empty() {
        let msg = if filter.is_empty() { "  (none)" } else { "  (no match)" };
        lines.push(Line::from(Span::raw(msg)));
    }
    for (i, (label, jump)) in entries.iter().enumerate().skip(first).take(inner) {
        let style = if i == sel {
            theme.selection()
        } else if is_warn_row(label) {
            theme.warn()
        } else if jump.is_some() {
            theme.dialog()
        } else {
            Style::default().bg(theme.dialog_bg).fg(theme.ascii_other)
        };
        lines.push(Line::from(Span::styled(format!(" {label}"), style)));
    }

    let filt = if filter.is_empty() {
        String::new()
    } else {
        format!(" [/{filter}]")
    };
    let counts = format!(
        "S:{} I:{} E:{}",
        app.address_space.sections().len(),
        app.imports.len(),
        app.exports.len()
    );
    let title = format!(
        " Header — {}{}  {}  (←→ pane · ↑↓ · type=filter · Enter jump · Esc) ",
        pane.label(),
        filt,
        counts
    );
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .style(theme.dialog());
    f.render_widget(Paragraph::new(lines).block(block).style(theme.dialog()), rect);
}

fn draw_status(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let name = app.path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
    // The lock is a safety property, so it is spelled out rather than abbreviated
    // away: RW means a keystroke can now change the sample.
    let rw = if app.read_only { "ro" } else { "RW!" };
    let ins = if app.insert_mode { "ins" } else { "ovr" };
    let dirty = if app.buffer.is_dirty() { " *" } else { "" };
    let edit = if app.editing { " EDIT" } else { "" };
    let sel = match app.selection() {
        Some((s, e)) => format!(" sel:{}", e - s + 1),
        None => String::new(),
    };
    let diff = if app.has_diff() { format!(" diff:{}", app.diff_name) } else { String::new() };
    let lens = match app.lens_label() {
        Some(l) => format!(" lens:{l}"),
        None => String::new(),
    };
    let asm = if app.disasm_override {
        format!(" as:{}/{}", app.disasm_arch.label(), app.disasm_bits)
    } else {
        String::new()
    };
    // Once triage has run, its verdict rides along on the status line: the two
    // facts you keep re-checking (how bad is this, and is it packed) stay visible.
    let badges = match app.triage_badges() {
        Some(b) => format!("  {b}"),
        None => String::new(),
    };
    let text = format!(
        " {name}  {fmt}/{arch}{asm}  {mode:<4} {rw} {ins}  {addr}  size:{size}{sel}{diff}{lens}{dirty}{edit}{badges}  · {status}",
        fmt = app.format.label(),
        arch = app.arch.label(),
        mode = app.mode.label(),
        addr = app.display_addr(app.cursor),
        size = app.buffer.len(),
        status = app.status,
    );
    let para = Paragraph::new(Line::from(Span::styled(pad_line(&text, area.width), theme.status())));
    f.render_widget(para, area);
}

fn draw_hex(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let bpr = app.bytes_per_row;
    let window_end = app.top + (app.visible_rows * bpr) as u64;
    let hits = app.search_hits(app.top, window_end);
    let mut lines = Vec::with_capacity(app.visible_rows);
    for row in 0..app.visible_rows {
        let row_off = app.top + (row * bpr) as u64;
        if row_off >= app.buffer.len() && !app.buffer.is_empty() {
            break;
        }
        lines.push(hex_line(app, theme, row_off, bpr, &hits));
    }
    f.render_widget(Paragraph::new(lines).style(theme.base()), area);
}

/// Two-pane diff: this file on the left, the compared file on the right, the
/// same offsets in both. Differing bytes are highlighted on both sides, and
/// bytes past the shorter file's end render as `--` rather than as zeros.
fn draw_split(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Each pane shows the offset column once plus N byte columns; pick N to fit.
    let avail = panes[0].width.saturating_sub(11) as usize;
    let bpr = (avail / 3).clamp(4, app.bytes_per_row);

    let title = |name: &str, len: u64| {
        Line::from(Span::styled(format!(" {name}  ({len} bytes)"), theme.status()))
    };

    let mut left = vec![title(
        app.path.file_name().and_then(|n| n.to_str()).unwrap_or("this file"),
        app.buffer.len(),
    )];
    let mut right = vec![title(app.diff_label(), app.diff_len())];

    let rows = app.visible_rows.saturating_sub(1);
    for row in 0..rows {
        let row_off = app.top + (row * bpr) as u64;
        if row_off >= app.buffer.len().max(app.diff_len()) {
            break;
        }
        let others = app.diff_bytes(row_off, bpr);

        let mut lspans = vec![Span::styled(format!("{row_off:08X}: "), Style::default().fg(theme.offset))];
        let mut rspans = vec![Span::styled(format!("{row_off:08X}: "), Style::default().fg(theme.offset))];
        for (i, other) in others.iter().enumerate().take(bpr) {
            let at = row_off + i as u64;
            let differs = app.byte_differs(at);
            let style = if differs { theme.diff() } else { theme.base() };

            if at < app.buffer.len() {
                let b = app.buffer.read_byte(hiewlm_core::FileOffset(at));
                lspans.push(Span::styled(format!("{b:02X} "), style));
            } else {
                lspans.push(Span::styled("-- ", theme.base()));
            }
            match other {
                Some(b) => rspans.push(Span::styled(format!("{b:02X} "), style)),
                None => rspans.push(Span::styled("-- ", theme.base())),
            }
        }
        left.push(Line::from(lspans));
        right.push(Line::from(rspans));
    }

    f.render_widget(Paragraph::new(left).style(theme.base()), panes[0]);
    f.render_widget(Paragraph::new(right).style(theme.base()), panes[1]);
}

fn in_ranges(off: u64, ranges: &[(u64, u64)]) -> bool {
    ranges.iter().any(|(s, e)| off >= *s && off <= *e)
}

fn hex_line<'a>(app: &App, theme: &Theme, row_off: u64, bpr: usize, hits: &[(u64, u64)]) -> Line<'a> {
    let sel = app.selection();
    let selected = |off: u64| sel.is_some_and(|(s, e)| off >= s && off <= e);
    let mut spans = vec![Span::styled(
        format!("{}: ", app.display_addr(row_off)),
        ratatui::style::Style::default().fg(theme.offset),
    )];

    for i in 0..bpr {
        let off = row_off + i as u64;
        if off < app.buffer.len() {
            let b = app.view_byte(off);
            let style = if off == app.cursor && app.edit_focus_hex() {
                theme.cursor()
            } else if app.byte_differs(off) {
                theme.diff()
            } else if in_ranges(off, hits) {
                theme.search()
            } else if selected(off) {
                theme.selection()
            } else if let Some(idx) = app.marker_color_at(off) {
                theme.marker(idx)
            } else {
                Style::default().fg(theme.fg)
            };
            spans.push(Span::styled(format!("{b:02X}"), style));
        } else {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::raw(if i % 8 == 7 { "  " } else { " " }));
    }

    spans.push(Span::raw("│"));
    for i in 0..bpr {
        let off = row_off + i as u64;
        if off < app.buffer.len() {
            let b = app.view_byte(off);
            let ch = if (0x20..0x7f).contains(&b) { b as char } else { '.' };
            let style = if off == app.cursor && !app.edit_focus_hex() {
                theme.cursor()
            } else if app.byte_differs(off) {
                theme.diff()
            } else if in_ranges(off, hits) {
                theme.search()
            } else if selected(off) {
                theme.selection()
            } else if let Some(idx) = app.marker_color_at(off) {
                theme.marker(idx)
            } else {
                Style::default().fg(if (0x20..0x7f).contains(&b) {
                    theme.ascii_printable
                } else {
                    theme.ascii_other
                })
            };
            spans.push(Span::styled(ch.to_string(), style));
        }
    }
    Line::from(spans)
}

fn draw_text(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let width = area.width.max(1) as usize;
    let sel = app.selection();
    let selected = |off: u64| sel.is_some_and(|(s, e)| off >= s && off <= e);
    let normal = theme.base();
    let window_end = app.top + (app.visible_rows * width) as u64;
    let hits = app.search_hits(app.top, window_end);

    let mut lines = Vec::with_capacity(app.visible_rows);
    for row in 0..app.visible_rows {
        let row_off = app.top + (row * width) as u64;
        if row_off >= app.buffer.len() {
            break;
        }
        let mut spans = Vec::with_capacity(width);
        for i in 0..width {
            let off = row_off + i as u64;
            if off >= app.buffer.len() {
                break;
            }
            let b = app.view_byte(off);
            let ch = if app.encoding.is_wide() {
                // One glyph per 2 bytes, shown at the even offset.
                if off % 2 == 0 {
                    crate::encoding::Encoding::wide_glyph(b, app.view_byte(off + 1))
                } else {
                    ' '
                }
            } else {
                app.encoding.decode(b)
            };
            let style = if off == app.cursor {
                theme.cursor()
            } else if in_ranges(off, &hits) {
                theme.search()
            } else if selected(off) {
                theme.selection()
            } else if let Some(idx) = app.marker_color_at(off) {
                theme.marker(idx)
            } else {
                normal
            };
            spans.push(Span::styled(ch.to_string(), style));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines).style(normal), area);
}

fn draw_code(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    use ratatui::style::Style;

    if !app.code_supported() {
        let lines = vec![
            Line::from(""),
            Line::from(Span::raw(format!(
                "  Decode mode: {} disassembly is not supported yet.",
                app.arch.label()
            ))),
            Line::from(Span::raw("  x86/x86-64 works now; ARM etc. come via Capstone later.")),
        ];
        f.render_widget(Paragraph::new(lines).style(theme.base()), area);
        return;
    }

    let insns = app.disasm_from(app.code_top, app.visible_rows);
    let mut lines = Vec::with_capacity(insns.len());
    for ins in &insns {
        let is_cursor = ins.offset <= app.cursor && app.cursor < ins.offset + ins.len as u64;

        let shown: String = ins
            .bytes
            .iter()
            .take(8)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let bytes = if ins.len > 8 { format!("{shown}..") } else { shown };
        // A marker on branch/call instructions ("f" follows the one under the cursor).
        let mark = if ins.target.is_some() { "»" } else { " " };
        // A user comment wins; otherwise show what the instruction resolves to
        // (an imported API, or the string it points at).
        let text = match (app.comment_at(ins.offset), app.annotate(ins)) {
            (Some(c), _) => format!("{}  ; {c}", ins.text),
            (None, Some(a)) => format!("{}  ; {a}", ins.text),
            (None, None) => ins.text.clone(),
        };

        if is_cursor && app.editing {
            // Opcode-hex editing: show each byte, highlighting the one at the cursor.
            let mut spans = vec![Span::styled(
                format!("{}: ", app.display_addr(ins.offset)),
                Style::default().fg(theme.offset),
            )];
            for (bi, b) in ins.bytes.iter().enumerate() {
                let boff = ins.offset + bi as u64;
                let st = if boff == app.cursor {
                    theme.cursor()
                } else {
                    Style::default().fg(theme.ascii_other)
                };
                spans.push(Span::styled(format!("{b:02X}"), st));
                spans.push(Span::raw(" "));
            }
            spans.push(Span::styled(
                format!("  {mark} {text}"),
                Style::default().fg(theme.ascii_printable),
            ));
            lines.push(Line::from(spans));
        } else if is_cursor {
            let line = format!("{}: {:<24} {} {}", app.display_addr(ins.offset), bytes, mark, text);
            lines.push(Line::from(Span::styled(line, theme.cursor())));
        } else {
            // Syntax-colored tokens (accurate for x86/x64, heuristic for others).
            let mut spans = vec![
                Span::styled(format!("{}: ", app.display_addr(ins.offset)), Style::default().fg(theme.offset)),
                Span::styled(format!("{bytes:<24} "), Style::default().fg(theme.ascii_other)),
                Span::styled(format!("{mark} "), Style::default().fg(theme.bar_key)),
            ];
            for (tok, kind) in &ins.tokens {
                spans.push(Span::styled(tok.clone(), Style::default().fg(theme.token(*kind))));
            }
            if let Some(c) = app.comment_at(ins.offset) {
                spans.push(Span::styled(format!("  ; {c}"), Style::default().fg(theme.tok_comment)));
            }
            lines.push(Line::from(spans));
        }
    }
    f.render_widget(Paragraph::new(lines).style(theme.base()).alignment(Alignment::Left), area);
}

/// The Fn-bar follows the mode, HIEW-style: the keys that matter where you are.
fn draw_fnbar(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    const EDIT_BAR: &[(&str, &str)] = &[
        ("1", "Help"),
        ("3", "View"),
        ("Tab", "Col"),
        ("9", "Save"),
        ("Esc", "Cancel"),
    ];
    const COMMON: &[(&str, &str)] = &[
        ("1", "Help"),
        ("2", "Triage"),
        ("3", "Edit"),
        ("4", "Mode"),
        ("5", "Goto"),
        ("7", "Srch"),
        ("8", "Hdr"),
    ];
    const CODE_EXTRA: &[(&str, &str)] = &[
        ("f", "Follow"),
        ("6", "Xref"),
        ("G", "CFG"),
        (";", "Cmnt"),
        ("A", "Asm"),
    ];
    const HEX_EXTRA: &[(&str, &str)] =
        &[("*", "Mark"), ("b", "Blk"), ("s", "Str"), ("R", "Yara"), ("Y", "Copy")];
    const TEXT_EXTRA: &[(&str, &str)] = &[("E", "Enc"), ("s", "Str"), ("*", "Mark")];
    const TAIL: &[(&str, &str)] = &[("F12", "Names"), ("q", "Quit")];

    let mut owned: Vec<(&str, &str)>;
    let items: &[(&str, &str)] = if app.editing {
        EDIT_BAR
    } else {
        owned = COMMON.to_vec();
        owned.extend_from_slice(match app.mode {
            Mode::Code => CODE_EXTRA,
            Mode::Text => TEXT_EXTRA,
            Mode::Hex => HEX_EXTRA,
        });
        owned.extend_from_slice(TAIL);
        &owned
    };
    let mut spans = Vec::new();
    for (k, label) in items {
        spans.push(Span::styled(
            (*k).to_string(),
            ratatui::style::Style::default().bg(theme.bg).fg(theme.bar_key),
        ));
        spans.push(Span::styled(format!("{label} "), theme.bar()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)).style(theme.bar()), area);
}

/// Copy-menu rows, in display order; `Enter` indexes them.
pub const COPY_MENU_LABELS: [&str; 11] = [
    "1  SHA-256 of the file",
    "2  MD5 of the file",
    "3  ssdeep fuzzy hash",
    "4  imphash",
    "5  block as hex bytes",
    "6  block as C array",
    "7  block as Python bytes",
    "8  block as text",
    "9  current address",
    "0  every indicator (kind + value)",
    "r  the whole triage report",
];

/// Block-menu rows, in display order. Enter indexes `BLOCK_MENU_CMDS` by the
/// rendered row, so the two lists must stay the same length and order.
pub const BLOCK_MENU_LABELS: [&str; 9] = [
    "w  Write block to file",
    "r  Read file in at cursor",
    "c  Copy block to bookmark (+)",
    "m  Move block to bookmark (+)",
    "i  Insert clipboard at cursor",
    "f  Fill pattern",
    "z  Zero fill",
    "d  Delete",
    "n  NOP out instruction (Alt+F2)",
];

fn draw_dialog(f: &mut Frame, area: Rect, dialog: &Dialog, theme: &Theme) {
    let (title, body, height): (String, Vec<Line>, u16) = match dialog {
        Dialog::Goto { input } => (
            "Goto".into(),
            vec![
                Line::from(format!("Address: {input}_")),
                Line::from(""),
                Line::from(Span::raw("n hex · +n/-n relative · .va · nt decimal · Enter/Esc")),
            ],
            5,
        ),
        Dialog::Search { input, kind } => {
            let k = kind.label();
            (
                format!("Find ({k})"),
                vec![
                    Line::from(format!("Pattern: {input}_")),
                    Line::from(""),
                    Line::from(Span::raw("Tab toggles hex/text · Enter search · Esc cancel")),
                ],
                5,
            )
        }
        Dialog::ModeMenu { selected } => {
            let names = ["1 Hex", "2 Code", "3 Text"];
            let lines = names
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let marker = if i == *selected { "► " } else { "  " };
                    Line::from(format!("{marker}{n}"))
                })
                .collect();
            ("Mode".into(), lines, 5)
        }
        Dialog::DisasmMenu { selected } => {
            let lines = crate::app::DISASM_OPTIONS
                .iter()
                .enumerate()
                .map(|(i, (label, _))| {
                    let marker = if i == *selected { "► " } else { "  " };
                    Line::from(format!("{marker}{}  {label}", i + 1))
                })
                .collect();
            ("Disassemble as (1-8)".into(), lines, 10)
        }
        Dialog::Replace { input, kind } => {
            let k = kind.label();
            (
                format!("Replace across folder ({k})"),
                vec![
                    Line::from(format!("Replacement: {input}_")),
                    Line::from(""),
                    Line::from(Span::raw("Tab hex/text · Enter replace-all (.bak backups) · Esc")),
                ],
                5,
            )
        }
        Dialog::ColorMenu { selected } => {
            let mut names: Vec<String> = (0..8)
                .map(|i| format!("{}  {}", i + 1, Theme::marker_name(i)))
                .collect();
            names.push("r  random".into());
            names.push("c  clear all".into());
            let lines = names
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let marker = if i == *selected { "► " } else { "  " };
                    Line::from(format!("{marker}{n}"))
                })
                .collect();
            ("Color block".into(), lines, 12)
        }
        Dialog::CopyMenu { selected } => {
            let lines = COPY_MENU_LABELS
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let marker = if i == *selected { "► " } else { "  " };
                    Line::from(format!("{marker}{n}"))
                })
                .collect();
            ("Copy to system clipboard".into(), lines, COPY_MENU_LABELS.len() as u16 + 2)
        }
        Dialog::BlockMenu { selected } => {
            let lines = BLOCK_MENU_LABELS
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let marker = if i == *selected { "► " } else { "  " };
                    Line::from(format!("{marker}{n}"))
                })
                .collect();
            ("Block".into(), lines, BLOCK_MENU_LABELS.len() as u16 + 2)
        }
        Dialog::BlockWrite { input } => (
            "Write block to file".into(),
            vec![
                Line::from(format!("Path: {input}_")),
                Line::from(""),
                Line::from(Span::raw("Enter to write · Esc cancel")),
            ],
            5,
        ),
        Dialog::BlockFill { input } => (
            "Fill block".into(),
            vec![
                Line::from(format!("Hex pattern: {input}_")),
                Line::from(""),
                Line::from(Span::raw("e.g. 90  or  00 ff · Enter fills · Esc cancel")),
            ],
            5,
        ),
        Dialog::BookmarkSlot => (
            "Set bookmark slot".into(),
            vec![
                Line::from(Span::raw("Press 1-8 to store the cursor in that slot.")),
                Line::from(""),
                Line::from(Span::raw("Alt+1..8 jumps to a slot · Esc cancel")),
            ],
            5,
        ),
        Dialog::Crypt { input } => {
            let mut lines = vec![Line::from(format!("Recipe: {input}_")), Line::from("")];
            if input.trim().is_empty() {
                lines.push(Line::from(Span::raw("xor 5a · add 10 · sub 1 · rol 3 · ror 2")));
                lines.push(Line::from(Span::raw("not · neg · and 0f · or f0")));
                lines.push(Line::from(Span::raw("chain with commas:  xor dead, rol 3")));
                lines.push(Line::from(Span::raw("keys: hex (5a, deadbeef) or \"text\"")));
            } else {
                match hiewlm_core::crypt::parse(input) {
                    Ok(r) => {
                        lines.push(Line::from(Span::raw(format!("{} step(s)", r.0.len()))));
                        lines.push(Line::from(Span::raw(if r.inverse().is_some() {
                            "reversible — applying the inverse restores the block"
                        } else {
                            "lossy (and/or) — only Ctrl+Z can undo"
                        })));
                    }
                    Err(e) => lines.push(Line::from(Span::raw(format!("{e}")))),
                }
            }
            lines.push(Line::from(Span::raw("Enter applies to the block · Esc cancel")));
            let h = lines.len() as u16 + 2;
            ("Crypt engine".into(), lines, h)
        }
        Dialog::Lens { input } => {
            let mut lines = vec![
                Line::from(format!("Recipe: {input}_")),
                Line::from(""),
                Line::from(Span::raw(
                    "Decodes the VIEW only — hex, text and disassembly. The file is untouched.",
                )),
            ];
            if input.trim().is_empty() {
                lines.push(Line::from(Span::raw("xor 5a · add 10 · rol 3 · not · xor deadbeef")));
                lines.push(Line::from(Span::raw("Alt+X hunts for the key automatically.")));
                lines.push(Line::from(Span::raw("Empty + Enter turns the lens off.")));
            } else {
                match hiewlm_core::crypt::parse(input) {
                    Ok(r) => lines.push(Line::from(Span::raw(format!("{} step(s), ok", r.0.len())))),
                    Err(e) => lines.push(Line::from(Span::raw(format!("{e}")))),
                }
            }
            lines.push(Line::from(Span::raw("Enter applies · Esc cancel")));
            let h = lines.len() as u16 + 2;
            ("View lens".into(), lines, h)
        }
        Dialog::Comment { input } => (
            "Comment (empty removes)".into(),
            vec![
                Line::from(format!("; {input}_")),
                Line::from(""),
                Line::from(Span::raw("Enter to save · Esc cancel")),
            ],
            5,
        ),
        Dialog::NameBookmark { input } => (
            "Name this bookmark".into(),
            vec![
                Line::from(format!("Name: {input}_")),
                Line::from(""),
                Line::from(Span::raw("Enter to save (blank = auto) · jump via F12 · Esc")),
            ],
            5,
        ),
        // Rendered separately (they need app data / scrolling).
        Dialog::Header { .. }
        | Dialog::Triage { .. }
        | Dialog::Palette { .. }
        | Dialog::XorHits { .. }
        | Dialog::JumpList { .. }
        | Dialog::FileHits { .. }
        | Dialog::FilePicker { .. }
        | Dialog::Message { .. }
        | Dialog::Calc { .. }
        | Dialog::Assemble { .. } => return,
    };

    let _ = height;
    // Size the box to its content, bounded by the screen; wrap anything wider.
    let content_w = body
        .iter()
        .map(|l| l.width())
        .max()
        .unwrap_or(0)
        .max(title.chars().count() + 2);
    let width = ((content_w as u16) + 4).clamp(24, area.width.saturating_sub(2));
    let inner_w = width.saturating_sub(2) as usize;
    // Account for wrapping when a line is wider than the inner width.
    let visual_lines: usize = body
        .iter()
        .map(|l| (l.width().max(1) + inner_w - 1) / inner_w.max(1))
        .sum();
    let height = ((visual_lines as u16) + 2).clamp(3, area.height.saturating_sub(2));
    let rect = centered(area, width, height);
    f.render_widget(Clear, rect);
    let block = Block::default()
        .title(format!(" {title} "))
        .borders(Borders::ALL)
        .style(theme.dialog());
    f.render_widget(
        Paragraph::new(body)
            .block(block)
            .style(theme.dialog())
            .wrap(Wrap { trim: false }),
        rect,
    );
}

/// A scrollable read-only text box (help / inspector / hashes), sized to its
/// content and clamped to the screen.
fn draw_message(f: &mut Frame, area: Rect, title: &str, body: &str, scroll: usize, theme: &Theme) {
    let lines: Vec<&str> = body.lines().collect();
    let content_w = lines
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0)
        .max(title.chars().count() + 14);
    let width = ((content_w as u16) + 4).clamp(30, area.width.saturating_sub(2));
    let height = ((lines.len() as u16) + 2).clamp(3, area.height.saturating_sub(2));
    let inner_h = height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(inner_h);
    let scroll = scroll.min(max_scroll);

    let view: Vec<Line> = lines
        .iter()
        .skip(scroll)
        .take(inner_h)
        .map(|s| Line::from(s.to_string()))
        .collect();

    let bar = if max_scroll > 0 {
        format!("  [{}/{}] ↑↓ scroll", scroll + 1, max_scroll + 1)
    } else {
        String::new()
    };
    let rect = centered(area, width, height);
    f.render_widget(Clear, rect);
    let block = Block::default()
        .title(format!(" {title}{bar}  (Esc) "))
        .borders(Borders::ALL)
        .style(theme.dialog());
    f.render_widget(Paragraph::new(view).block(block).style(theme.dialog()), rect);
}

/// The 64-bit calculator (Alt+=): live evaluation shown in hex/dec/oct/bin.
fn draw_calc(f: &mut Frame, area: Rect, app: &App, input: &str, theme: &Theme) {
    let mut lines = vec![
        Line::from(format!(" = {input}_")),
        Line::from(""),
    ];
    if input.trim().is_empty() {
        lines.push(Line::from(Span::raw(" enter an expression:")));
        lines.push(Line::from(Span::raw("   + - * / % & | ^ ~ << >>  ( )")));
        lines.push(Line::from(Span::raw("   0x.. hex · 0b.. bin · Nt decimal")));
        lines.push(Line::from(Span::raw("   @o offset · @b @w @d @q at cursor")));
    } else {
        match hiewlm_core::calc::eval(input, &app.calc_ctx()) {
            Ok(v) => {
                lines.push(Line::from(Span::styled(format!("   hex  {v:#x}"), Style::default().fg(theme.tok_number))));
                lines.push(Line::from(format!("   dec  {v}")));
                lines.push(Line::from(format!("   i64  {}", v as i64)));
                lines.push(Line::from(format!("   oct  {v:#o}")));
                lines.push(Line::from(format!("   bin  {v:#b}")));
            }
            Err(e) => lines.push(Line::from(Span::styled(format!("   {e}"), Style::default().fg(theme.diff_bg)))),
        }
    }

    let width = 56.min(area.width.saturating_sub(2)).max(30);
    let height = (lines.len() as u16 + 2).min(area.height.saturating_sub(2));
    let rect = centered(area, width, height);
    f.render_widget(Clear, rect);
    let block = Block::default()
        .title(" Calculator  (type · Esc) ")
        .borders(Borders::ALL)
        .style(theme.dialog());
    f.render_widget(Paragraph::new(lines).block(block).style(theme.dialog()), rect);
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w.min(area.width),
        height: h.min(area.height),
    }
}

/// Truncate/pad by characters (not bytes) so we never split a multi-byte UTF-8
/// char. M0 treats each char as width 1; wide (CJK) chars are handled in §7.3.
fn pad_line(s: &str, width: u16) -> String {
    let w = width as usize;
    let mut out = String::with_capacity(w);
    let mut count = 0;
    for ch in s.chars() {
        if count >= w {
            break;
        }
        out.push(ch);
        count += 1;
    }
    for _ in count..w {
        out.push(' ');
    }
    out
}

/// Assemble-at-cursor: shows the encoding live so the user sees the bytes and
/// whether they fit before committing with Enter.
fn draw_assemble(f: &mut Frame, area: Rect, app: &App, input: &str, theme: &Theme) {
    let mut lines = vec![Line::from(format!(" {input}_")), Line::from("")];
    if input.trim().is_empty() {
        lines.push(Line::from(Span::raw(" type an instruction, e.g.:")));
        lines.push(Line::from(Span::raw("   xor eax, eax    mov rax, rbx")));
        lines.push(Line::from(Span::raw("   jmp 401000      call rax")));
        lines.push(Line::from(Span::raw("   push rbp        ret")));
        lines.push(Line::from(Span::raw(" numbers are hex; use Nt for decimal")));
    } else {
        match app.assemble_preview(input) {
            Ok((bytes, slot)) => {
                let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
                lines.push(Line::from(Span::styled(
                    format!("   {}", hex.join(" ")),
                    Style::default().fg(theme.tok_number),
                )));
                if bytes.len() > slot {
                    lines.push(Line::from(Span::styled(
                        format!("   too long: {} bytes into a {slot}-byte slot", bytes.len()),
                        Style::default().fg(theme.diff_bg),
                    )));
                } else {
                    let pad = slot - bytes.len();
                    lines.push(Line::from(format!(
                        "   {} byte(s){}  — Enter to patch",
                        bytes.len(),
                        if pad > 0 { format!(" + {pad} NOP") } else { String::new() }
                    )));
                }
            }
            Err(e) => lines.push(Line::from(Span::styled(
                format!("   {e}"),
                Style::default().fg(theme.diff_bg),
            ))),
        }
    }

    let width = 60.min(area.width.saturating_sub(2)).max(30);
    let height = (lines.len() as u16 + 2).min(area.height.saturating_sub(2));
    let rect = centered(area, width, height);
    f.render_widget(Clear, rect);
    let block = Block::default()
        .title(" Assemble  (Enter patches · Esc) ")
        .borders(Borders::ALL)
        .style(theme.dialog());
    f.render_widget(Paragraph::new(lines).block(block).style(theme.dialog()), rect);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn render_to_string(app: &mut App) -> String {
        let theme = Theme::hiew_classic();
        let mut term = Terminal::new(TestBackend::new(80, 12)).unwrap();
        term.draw(|f| draw(f, app, &theme)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn render_buffer(app: &mut App) -> ratatui::buffer::Buffer {
        let theme = Theme::hiew_classic();
        let mut term = Terminal::new(TestBackend::new(80, 12)).unwrap();
        term.draw(|f| draw(f, app, &theme)).unwrap();
        term.backend().buffer().clone()
    }

    fn app_with(name: &str, data: &[u8]) -> App {
        let path = std::env::temp_dir().join(format!("hiewlm_ui_{name}.bin"));
        std::fs::write(&path, data).unwrap();
        App::open(path).unwrap()
    }

    #[test]
    fn text_mode_shows_cursor() {
        let mut app = app_with("textcur", b"Hello world");
        app.apply(crate::app::Command::SetMode(crate::app::Mode::Text));
        let buf = render_buffer(&mut app);
        // Content starts at screen row 1; cursor is at offset 0 (column 0).
        let cursor_cell = buf[(0, 1)].style();
        let other_cell = buf[(5, 1)].style();
        assert_ne!(
            cursor_cell.bg, other_cell.bg,
            "text-mode cursor cell should be highlighted differently"
        );
    }

    #[test]
    fn code_mode_renders_disassembly() {
        // push rbp; mov rbp,rsp; call +6; nops; ret — opened as raw => x64 default.
        let data = [
            0x55u8, 0x48, 0x89, 0xe5, 0xe8, 0x06, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0xc3,
        ];
        let mut app = app_with("code", &data);
        app.apply(crate::app::Command::SetMode(crate::app::Mode::Code));
        let screen = render_to_string(&mut app);
        assert!(screen.contains("push"), "missing disassembly:\n{screen}");
        assert!(screen.contains("call"), "missing call:\n{screen}");
        // The branch instruction is flagged with a follow marker.
        assert!(screen.contains('»'), "missing branch marker:\n{screen}");
    }

    #[test]
    fn code_view_is_syntax_colored() {
        // push rbp; mov rbp,rsp; ret — the mov line is non-cursor and tokenized.
        let data = [0x55u8, 0x48, 0x89, 0xe5, 0xc3];
        let mut app = app_with("syntax", &data);
        app.apply(crate::app::Command::SetMode(crate::app::Mode::Code));
        let theme = Theme::hiew_classic();
        let buf = render_buffer(&mut app);
        let mut found_reg = false;
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                if buf[(x, y)].style().fg == Some(theme.tok_register) {
                    found_reg = true;
                }
            }
        }
        assert!(found_reg, "expected register-colored tokens in the disassembly");
    }

    #[test]
    fn hex_mode_highlights_search_matches() {
        let mut app = app_with("searchhl", b"a5b5c");
        app.apply(crate::app::Command::SetMode(crate::app::Mode::Hex));
        // Search '5': first match at offset 1 (cursor lands there), second at offset 3.
        app.confirm_search("5", crate::app::SearchKind::Text);
        let buf = render_buffer(&mut app);
        let theme = Theme::hiew_classic();
        // Offset 3 hex pair: prefix 10 cols + 3 bytes * 3 cols = column 19.
        let match_cell = buf[(19, 1)].style();
        assert_eq!(match_cell.bg, Some(theme.search_bg));
    }

    #[test]
    fn hex_mode_paints_colored_marker() {
        use crate::app::Command;
        let mut app = app_with("marker", b"0123456789ABCDEF");
        app.apply(Command::ToggleMark);
        app.apply(Command::Step(2)); // select offsets 0..=2
        app.apply(Command::ColorBlock); // opens the color menu
        app.handle_key(crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('1'))); // color 0
        let buf = render_buffer(&mut app);
        let theme = Theme::hiew_classic();
        // Offset 0 hex cell (col 10) is inside the marker and not the cursor.
        assert_eq!(buf[(10, 1)].style().bg, theme.marker(0).bg);
        // cleanup the sidecar the command wrote
        let mut s = std::env::temp_dir().join("hiewlm_ui_marker.bin").into_os_string();
        s.push(".hiewlm.markers");
        std::fs::remove_file(std::path::PathBuf::from(s)).ok();
    }

    #[test]
    fn hex_mode_highlights_selection() {
        let mut app = app_with("selhl", b"0123456789ABCDEF");
        app.apply(crate::app::Command::ToggleMark);
        app.apply(crate::app::Command::Step(2)); // select offsets 0..=2
        let buf = render_buffer(&mut app);
        let theme = Theme::hiew_classic();
        // The first hex byte pair sits after the "00000000: " offset prefix (10 cols).
        let selected_cell = buf[(10, 1)].style();
        assert_eq!(selected_cell.bg, Some(theme.selection_bg));
    }

    #[test]
    fn hex_view_renders_offset_and_ascii() {
        let mut app = app_with("hexview", b"Hello, hiewLM!");
        let screen = render_to_string(&mut app);
        assert!(screen.contains("00000000:"), "missing offset column:\n{screen}");
        assert!(screen.contains("48 65 6C 6C 6F"), "missing hex for 'Hello':\n{screen}");
        assert!(screen.contains("Hello, hiewLM!"), "missing ascii column:\n{screen}");
        assert!(screen.contains("1Help"), "missing Fn-bar:\n{screen}");
        assert!(screen.contains("hex"), "missing mode in status:\n{screen}");
    }

    #[test]
    fn help_popup_fits_and_scrolls() {
        let mut app = app_with("help", b"data");
        app.apply(crate::app::Command::Help);
        let screen = render_to_string(&mut app); // 80x12 backend
        // Grouped, readable content is present — the first group is TRIAGE,
        // because that is where a malware analyst starts.
        assert!(screen.contains("TRIAGE"), "help content missing:\n{screen}");
        // …and since the help is taller than the box, a scroll indicator shows.
        assert!(screen.contains("scroll"), "expected scroll indicator:\n{screen}");
        // The box must not exceed the 80-col screen (no horizontal overflow).
        for line in screen.lines() {
            assert!(line.chars().count() <= 80, "row too wide: {line:?}");
        }
    }

    #[test]
    fn goto_dialog_renders() {
        let mut app = app_with("goto", b"abcdef");
        app.apply(crate::app::Command::OpenGoto);
        let screen = render_to_string(&mut app);
        assert!(screen.contains("Goto"), "missing dialog title:\n{screen}");
    }

    #[test]
    fn pad_line_is_utf8_safe() {
        // Truncating into the middle of a multi-byte string must not panic.
        for w in 0..12u16 {
            let out = pad_line("café·→", w);
            assert_eq!(out.chars().count(), w as usize);
        }
    }
}
