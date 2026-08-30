//! User configuration loaded from `config.toml` (theme, encoding, layout).
//! Location: `$HIEWLM_CONFIG`, else `$XDG_CONFIG_HOME/hiewlm/config.toml`, else
//! `~/.config/hiewlm/config.toml` (or `%APPDATA%\hiewlm\config.toml`).

use crate::encoding::Encoding;
use crate::theme::ThemeKind;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    pub theme: Option<String>,
    pub encoding: Option<String>,
    pub bytes_per_row: Option<usize>,
    /// A YARA rule file or directory scanned by `R` without prompting. Point it
    /// at your rule collection and the scan becomes one keystroke.
    pub yara_rules: Option<PathBuf>,
    /// Container plugins to activate (`["zip", "pdf"]`, or `["all"]`).
    /// Absent = all of them; they are read-only parsers, so the useful default
    /// is on. Set to `[]` to inspect containers as raw bytes only.
    pub plugins: Option<Vec<String>>,
}

impl Config {
    pub fn load() -> Config {
        config_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn theme_kind(&self) -> Option<ThemeKind> {
        match self.theme.as_deref()? {
            "classic" => Some(ThemeKind::Classic),
            "dark" => Some(ThemeKind::Dark),
            "light" => Some(ThemeKind::Light),
            _ => None,
        }
    }

    /// Names to enable in the container registry. Defaults to everything.
    pub fn plugins(&self) -> Vec<String> {
        self.plugins.clone().unwrap_or_else(|| vec!["all".to_string()])
    }

    pub fn encoding(&self) -> Option<Encoding> {
        match self.encoding.as_deref()? {
            "ascii" => Some(Encoding::Ascii),
            "cp437" => Some(Encoding::Cp437),
            "latin1" => Some(Encoding::Latin1),
            "utf16" | "utf16le" => Some(Encoding::Utf16Le),
            _ => None,
        }
    }
}

fn config_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("HIEWLM_CONFIG") {
        return Some(PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))?;
    Some(base.join("hiewlm").join("config.toml"))
}
