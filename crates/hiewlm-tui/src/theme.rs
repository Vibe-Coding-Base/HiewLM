//! Color palette. Default "HIEW Classic": blue background, cyan status/Fn bars
//! with black text — a DOS / Norton Commander feel (design §23.2).

use ratatui::style::{Color, Modifier, Style};

pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub bar_bg: Color,
    pub bar_fg: Color,
    pub bar_key: Color,
    pub offset: Color,
    pub cursor_bg: Color,
    pub cursor_fg: Color,
    pub selection_bg: Color,
    pub selection_fg: Color,
    pub search_bg: Color,
    pub search_fg: Color,
    pub diff_bg: Color,
    pub diff_fg: Color,
    pub ascii_printable: Color,
    pub ascii_other: Color,
    pub dialog_bg: Color,
    pub dialog_fg: Color,
    // Disassembly syntax colors.
    pub tok_mnemonic: Color,
    pub tok_register: Color,
    pub tok_number: Color,
    pub tok_punct: Color,
    pub tok_comment: Color,
}

/// Which built-in theme is active; cycled at runtime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThemeKind {
    Classic,
    Dark,
    Light,
}

impl ThemeKind {
    pub fn next(self) -> Self {
        match self {
            ThemeKind::Classic => ThemeKind::Dark,
            ThemeKind::Dark => ThemeKind::Light,
            ThemeKind::Light => ThemeKind::Classic,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ThemeKind::Classic => "classic",
            ThemeKind::Dark => "dark",
            ThemeKind::Light => "light",
        }
    }

    pub fn theme(self) -> Theme {
        match self {
            ThemeKind::Classic => Theme::hiew_classic(),
            ThemeKind::Dark => Theme::dark(),
            ThemeKind::Light => Theme::light(),
        }
    }
}

impl Theme {
    /// Modern dark theme (truecolor).
    pub fn dark() -> Self {
        Self {
            bg: Color::Rgb(24, 24, 28),
            fg: Color::Rgb(200, 200, 205),
            bar_bg: Color::Rgb(45, 48, 58),
            bar_fg: Color::Rgb(220, 220, 225),
            bar_key: Color::Rgb(120, 200, 255),
            offset: Color::Rgb(110, 180, 240),
            cursor_bg: Color::Rgb(220, 220, 225),
            cursor_fg: Color::Rgb(24, 24, 28),
            selection_bg: Color::Rgb(50, 90, 110),
            selection_fg: Color::Rgb(240, 240, 245),
            search_bg: Color::Rgb(180, 150, 40),
            search_fg: Color::Black,
            diff_bg: Color::Rgb(150, 45, 55),
            diff_fg: Color::Rgb(255, 240, 240),
            ascii_printable: Color::Rgb(230, 230, 235),
            ascii_other: Color::Rgb(110, 110, 120),
            dialog_bg: Color::Rgb(32, 34, 40),
            dialog_fg: Color::Rgb(210, 210, 215),
            tok_mnemonic: Color::Rgb(235, 235, 240),
            tok_register: Color::Rgb(130, 200, 255),
            tok_number: Color::Rgb(180, 230, 150),
            tok_punct: Color::Rgb(150, 150, 160),
            tok_comment: Color::Rgb(110, 140, 110),
        }
    }

    /// Light theme (truecolor).
    pub fn light() -> Self {
        Self {
            bg: Color::Rgb(245, 245, 240),
            fg: Color::Rgb(40, 40, 45),
            bar_bg: Color::Rgb(210, 214, 222),
            bar_fg: Color::Rgb(30, 30, 35),
            bar_key: Color::Rgb(180, 40, 40),
            offset: Color::Rgb(30, 90, 170),
            cursor_bg: Color::Rgb(60, 60, 70),
            cursor_fg: Color::Rgb(245, 245, 240),
            selection_bg: Color::Rgb(170, 205, 230),
            selection_fg: Color::Rgb(20, 20, 25),
            search_bg: Color::Rgb(240, 220, 120),
            search_fg: Color::Black,
            diff_bg: Color::Rgb(240, 180, 180),
            diff_fg: Color::Rgb(60, 0, 0),
            ascii_printable: Color::Rgb(20, 20, 25),
            ascii_other: Color::Rgb(150, 150, 155),
            dialog_bg: Color::Rgb(235, 235, 230),
            dialog_fg: Color::Rgb(40, 40, 45),
            tok_mnemonic: Color::Rgb(20, 20, 25),
            tok_register: Color::Rgb(30, 90, 170),
            tok_number: Color::Rgb(20, 120, 40),
            tok_punct: Color::Rgb(100, 100, 110),
            tok_comment: Color::Rgb(100, 140, 100),
        }
    }

    pub fn hiew_classic() -> Self {
        Self {
            bg: Color::Rgb(0, 0, 168),
            fg: Color::Rgb(170, 170, 170),
            bar_bg: Color::Rgb(0, 170, 170),
            bar_fg: Color::Black,
            bar_key: Color::Rgb(255, 255, 85),
            offset: Color::Rgb(85, 255, 255),
            cursor_bg: Color::Rgb(170, 170, 170),
            cursor_fg: Color::Black,
            selection_bg: Color::Rgb(0, 120, 120),
            selection_fg: Color::Rgb(255, 255, 255),
            search_bg: Color::Rgb(200, 160, 0),
            search_fg: Color::Black,
            diff_bg: Color::Rgb(160, 0, 0),
            diff_fg: Color::Rgb(255, 255, 255),
            ascii_printable: Color::Rgb(255, 255, 255),
            ascii_other: Color::Rgb(120, 120, 120),
            dialog_bg: Color::Rgb(0, 0, 0),
            dialog_fg: Color::Rgb(170, 170, 170),
            tok_mnemonic: Color::Rgb(255, 255, 255),
            tok_register: Color::Rgb(85, 255, 255),
            tok_number: Color::Rgb(85, 255, 85),
            tok_punct: Color::Rgb(170, 170, 170),
            tok_comment: Color::Rgb(90, 170, 90),
        }
    }

    /// Color for a disassembly token class.
    pub fn token(&self, kind: hiewlm_asm::TokenKind) -> Color {
        use hiewlm_asm::TokenKind;
        match kind {
            TokenKind::Mnemonic => self.tok_mnemonic,
            TokenKind::Register => self.tok_register,
            TokenKind::Number => self.tok_number,
            TokenKind::Punct => self.tok_punct,
            TokenKind::Text => self.fg,
        }
    }

    pub fn base(&self) -> Style {
        Style::default().bg(self.bg).fg(self.fg)
    }

    pub fn bar(&self) -> Style {
        Style::default().bg(self.bar_bg).fg(self.bar_fg)
    }

    pub fn status(&self) -> Style {
        Style::default()
            .bg(self.bar_bg)
            .fg(self.bar_fg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn cursor(&self) -> Style {
        Style::default().bg(self.cursor_bg).fg(self.cursor_fg)
    }

    pub fn selection(&self) -> Style {
        Style::default().bg(self.selection_bg).fg(self.selection_fg)
    }

    pub fn search(&self) -> Style {
        Style::default().bg(self.search_bg).fg(self.search_fg)
    }

    pub fn diff(&self) -> Style {
        Style::default().bg(self.diff_bg).fg(self.diff_fg)
    }

    /// Number of distinct marker colors.
    pub const MARKER_COLORS: u8 = 8;

    /// Background style for colored block marker `idx` (0..8), white text.
    pub fn marker(&self, idx: u8) -> Style {
        const PALETTE: [(u8, u8, u8); 8] = [
            (150, 40, 40),   // red
            (40, 110, 50),   // green
            (40, 70, 150),   // blue
            (140, 110, 30),  // yellow/olive
            (120, 50, 130),  // magenta
            (30, 110, 120),  // cyan/teal
            (160, 90, 30),   // orange
            (90, 90, 95),    // gray
        ];
        let (r, g, b) = PALETTE[(idx as usize) % 8];
        Style::default().bg(Color::Rgb(r, g, b)).fg(Color::Rgb(240, 240, 240))
    }

    pub fn marker_name(idx: u8) -> &'static str {
        ["red", "green", "blue", "yellow", "magenta", "cyan", "orange", "gray"][(idx as usize) % 8]
    }

    pub fn dialog(&self) -> Style {
        Style::default().bg(self.dialog_bg).fg(self.dialog_fg)
    }
}
