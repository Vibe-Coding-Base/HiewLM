//! hiewLM — a cross-platform, HIEW-flavored binary viewer/editor.
//! See docs/develop/00-overall-design.md.

mod app;
mod config;
mod encoding;
mod keymap;
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
#[command(name = "hiewlm", version, about = "HIEW-like hex viewer/editor, cross-platform")]
struct Cli {
    /// File to open (treated as passive data — its contents are never executed).
    file: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut app = App::open(cli.file)?;

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
