//! hiewLM — a cross-platform, HIEW-flavored binary viewer/editor.
//! See docs/DESIGN.md.

mod app;
mod clipboard;
mod config;
mod encoding;
mod keymap;
mod notes;
mod theme;
mod ui;

use anyhow::Result;
use app::App;
use clap::Parser;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::stdout;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "hiewlm",
    version,
    about = "HIEW's essentials on Linux, macOS and Windows: a keyboard-driven \
binary viewer and malware triage tool"
)]
struct Cli {
    /// File to open (treated as passive data — its contents are never executed).
    /// A directory opens the folder-triage queue instead, ranked worst-first.
    file: PathBuf,

    /// Unlock the file for editing. hiewLM is read-only by default: a sample is
    /// evidence, and no keystroke may alter it until you say so (Ctrl+W in the
    /// UI toggles the same lock).
    #[arg(long)]
    rw: bool,
}

/// Owns the terminal's raw mode and alternate screen, and gives them back on
/// the way out — including when that way out is a panic.
///
/// Restoring in `main` was not enough: the terminal was only put into raw mode
/// *after* the file was opened, so a Ctrl+C during a folder scan killed the
/// process with SIGINT and left the alternate screen behind. Owning the terminal
/// first means the program is in control from the first moment, and `Drop`
/// covers every path out of it.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<std::io::Stdout>>,
}

impl TerminalGuard {
    fn new() -> Result<Self> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        Ok(Self {
            terminal: Terminal::new(CrosstermBackend::new(stdout()))?,
        })
    }

    fn restore() {
        let _ = stdout().execute(LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }

    /// A one-line message while something slow happens before the UI exists —
    /// a folder scan reads every file in it, and a blank screen for three
    /// seconds looks like a hang.
    fn note(&mut self, text: &str) {
        let _ = self.terminal.draw(|f| {
            let area = f.area();
            f.render_widget(ratatui::widgets::Paragraph::new(text), area);
        });
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        Self::restore();
    }
}

/// Put the terminal back before printing a panic, or the message lands on the
/// alternate screen and disappears with it.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        TerminalGuard::restore();
        previous(info);
    }));
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    install_panic_hook();
    let mut guard = TerminalGuard::new()?;

    let mut app = if cli.file.is_dir() {
        guard.note(&format!(
            "Scanning {} — ranking every file in it...",
            cli.file.display()
        ));
        App::open_folder(cli.file)?
    } else {
        App::open(cli.file)?
    };
    if cli.rw {
        app.read_only = false;
        app.set_status("UNLOCKED (--rw): writes allowed · Ctrl+W re-locks.");
    }

    run(&mut guard.terminal, &mut app)
    // `guard` restores the terminal here, whichever way we leave.
}

fn run(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>, app: &mut App) -> Result<()> {
    while !app.should_quit {
        let theme = app.theme_kind.theme();
        terminal.draw(|f| ui::draw(f, app, &theme))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Release {
                    app.handle_key(key);
                }
            }
        }
    }
    Ok(())
}
