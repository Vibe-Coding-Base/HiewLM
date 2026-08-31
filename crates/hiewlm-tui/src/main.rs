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
    about = "HIEW-like hex viewer/editor, cross-platform"
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut app = if cli.file.is_dir() {
        App::open_folder(cli.file)?
    } else {
        App::open(cli.file)?
    };
    if cli.rw {
        app.read_only = false;
        app.set_status("UNLOCKED (--rw): writes allowed · Ctrl+W re-locks.");
    }

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let result = run(&mut app);
    stdout().execute(LeaveAlternateScreen)?;
    disable_raw_mode()?;
    result
}

fn run(app: &mut App) -> Result<()> {
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

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
