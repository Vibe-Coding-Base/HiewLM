//! Hunting across a folder, with YARA, and through a byte transform.
//!
//! What these have in common is that they answer "where else / what else",
//! rather than describing the file already open.

use super::*;

impl super::App {
    // -- Folder triage & search-all -------------------------------------

    /// Rank every file next to this one by triage score — the FAR-style panel
    /// that turns a folder of samples into a work queue. Enter opens one.
    pub(super) fn folder_triage(&mut self) {
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let mut files: Vec<PathBuf> = fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .map(|e| e.path())
            .collect();
        files.sort();
        // Triage hashes and scans each file, so the folder is capped: this is a
        // triage queue, not a corpus scanner (use `hiewlmc triage <dir>` for that).
        const MAX_FILES: usize = 200;
        let truncated = files.len() > MAX_FILES;
        files.truncate(MAX_FILES);

        let opts = hiewlm_triage::Options {
            // A folder pass wants to be quick; the full scan is one keystroke
            // away once a file is open.
            max_string_bytes: 8 * 1024 * 1024,
            max_xor_bytes: 4 * 1024 * 1024,
            max_indicators: 40,
            ..Default::default()
        };
        let mut rows: Vec<(u8, String, PathBuf)> = Vec::new();
        for path in files {
            let Ok(src) = FileSource::open(&path) else {
                continue;
            };
            let buf = EditBuffer::new(Arc::new(src));
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let r = hiewlm_triage::analyze(&name, &buf, None, &opts);
            rows.push((
                r.score,
                format!(
                    "{}{:>4}  {:<9} {:<28} {:<8} {}",
                    if r.score >= 40 { "!" } else { " " },
                    r.score,
                    r.verdict(),
                    truncate_label(&name, 28),
                    r.format,
                    r.badge_line()
                ),
                path,
            ));
        }
        if rows.is_empty() {
            self.set_status(format!("No readable files in {}", dir.display()));
            return;
        }
        rows.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let items: Vec<(String, PathBuf, u64)> = rows
            .into_iter()
            .map(|(_, label, path)| (label, path, 0))
            .collect();
        self.dialog = Some(Dialog::FileHits {
            title: format!(
                "Folder triage — {} ({} file(s){})",
                dir.display(),
                items.len(),
                if truncated { ", capped" } else { "" }
            ),
            items,
            sel: 0,
            filter: String::new(),
        });
        self.set_status("Worst first · Enter opens · type to filter · Esc closes");
    }

    /// Every match of the current pattern at once, as a jump list with context.
    /// Stepping with `n` is fine for three hits and useless for three hundred.
    pub(super) fn search_all(&mut self) {
        let Some((pattern, _)) = self.last_pattern.clone() else {
            self.set_status("Search first (/), then list every match.");
            return;
        };
        const MAX_HITS: usize = 5000;
        let hits = find_all(
            &self.buffer,
            &pattern,
            FileOffset(0),
            FileOffset(self.buffer.len()),
        );
        if hits.is_empty() {
            self.set_status("Not found.");
            return;
        }
        let truncated = hits.len() > MAX_HITS;
        let items: Vec<(String, u64)> = hits
            .iter()
            .take(MAX_HITS)
            .map(|h| {
                let off = h.get();
                let mut ctx = vec![0u8; 48.min((self.buffer.len() - off) as usize)];
                self.view_bytes(off, &mut ctx);
                let text: String = ctx
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7f).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                (format!("{}  {text}", self.display_addr(off)), off)
            })
            .collect();
        self.highlight = Some(pattern);
        self.dialog = Some(Dialog::JumpList {
            title: format!(
                "All matches ({}{})",
                hits.len(),
                if truncated { ", capped" } else { "" }
            ),
            items,
            sel: 0,
            filter: String::new(),
        });
    }

    // -- YARA ----------------------------------------------------------

    /// Scan the sample with the rules at `path` (a file, or a folder of rules).
    /// Matches become a jump list, and they also feed the triage screen's YARA
    /// pane and its score.
    pub(super) fn run_yara(&mut self, path: &std::path::Path) {
        self.dialog = None;
        let cap = self.buffer.len().min(256 * 1024 * 1024) as usize;
        let mut data = vec![0u8; cap];
        self.buffer.read_at(FileOffset(0), &mut data);

        let hits = match hiewlm_triage::yara::scan_path(path, &data) {
            Ok(h) => h,
            Err(e) => {
                self.set_status(format!("YARA: {e}"));
                return;
            }
        };
        if hits.is_empty() {
            self.set_status(format!("YARA: no rule in {} matched.", path.display()));
            return;
        }
        // Feed the triage screen too, so the verdict reflects the match.
        self.ensure_triage();
        if let Some(t) = &mut self.triage {
            t.set_yara(hits.clone());
        }
        let mut items: Vec<(String, u64)> = Vec::new();
        for h in &hits {
            let tags = if h.tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", h.tags.join(" "))
            };
            items.push((
                format!("!rule {}{tags}  ({} match(es))", h.rule, h.matches.len()),
                h.matches.first().map(|m| m.0).unwrap_or(0),
            ));
            for (off, len, id) in h.matches.iter().take(64) {
                items.push((
                    format!("     {}  {len:>5}  {id}", self.display_addr(*off)),
                    *off,
                ));
            }
        }
        let n = hits.len();
        self.dialog = Some(Dialog::JumpList {
            title: format!("YARA — {n} rule(s) matched"),
            items,
            sel: 0,
            filter: String::new(),
        });
        self.set_status(format!(
            "YARA: {n} rule(s) matched · 2 shows the updated verdict"
        ));
    }

    // -- View lens (non-destructive decoding) --------------------------

    /// One byte as it should be *displayed*: through the lens when one is set.
    pub fn view_byte(&self, off: u64) -> u8 {
        let raw = self.buffer.read_byte(FileOffset(off));
        match &self.lens {
            Some((recipe, _)) => {
                let mut b = [raw];
                // The key index follows the file offset, so a repeating key stays
                // aligned no matter where you scroll.
                recipe.apply(&mut b, off as usize);
                b[0]
            }
            None => raw,
        }
    }

    /// Fill `out` with the bytes at `off`, decoded through the lens.
    pub fn view_bytes(&self, off: u64, out: &mut [u8]) {
        self.buffer.read_at(FileOffset(off), out);
        if let Some((recipe, _)) = &self.lens {
            recipe.apply(out, off as usize);
        }
    }

    pub fn lens_label(&self) -> Option<&str> {
        self.lens.as_ref().map(|(_, l)| l.as_str())
    }

    pub(super) fn set_lens(&mut self, input: &str) {
        self.dialog = None;
        let text = input.trim();
        if text.is_empty() {
            self.lens = None;
            self.set_status("Lens off — showing the file's real bytes.");
            return;
        }
        match hiewlm_core::crypt::parse(text) {
            Ok(recipe) => {
                self.lens = Some((recipe, text.to_string()));
                self.set_status(format!(
                    "Lens: {text} — the view is decoded, the file is untouched (L then Enter clears)."
                ));
            }
            Err(e) => {
                self.set_status(format!("Lens: {e}"));
                self.dialog = Some(Dialog::Lens {
                    input: text.to_string(),
                });
            }
        }
    }

    /// Recover a repeating XOR key from the marked block.
    ///
    /// The single-byte hunt (`Alt+X`) finds the textbook case; a real config
    /// blob is usually behind a short repeating key, which no amount of
    /// searching for known plaintext will reveal. Here the key is *derived* from
    /// the block, and picking a candidate puts it straight on the lens.
    pub(super) fn xor_key(&mut self) {
        let Some((start, end)) = self.require_selection() else {
            return;
        };
        let len = (end - start + 1) as usize;
        if len < 16 {
            self.set_status("Mark a bigger block — key recovery needs at least a few dozen bytes.");
            return;
        }
        let mut data = vec![0u8; len.min(64 * 1024)];
        // Read raw: this derives a new key, so any active lens must not apply.
        self.buffer.read_at(FileOffset(start), &mut data);

        let cands = hiewlm_core::xorsearch::infer_repeating_key(&data, 32, 8);
        if cands.is_empty() {
            self.set_status("No repeating XOR key explains this block as plaintext.");
            return;
        }
        let items: Vec<(String, u64, String)> = cands
            .iter()
            .map(|c| {
                let key_text: String = c
                    .key
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7f).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                let preview: String = c.preview.chars().take(56).collect();
                (
                    format!(
                        "!{:>2}B  {:>3.0}%  {:<20} \"{key_text}\"  {preview}",
                        c.key.len(),
                        c.score * 100.0,
                        c.recipe().trim_start_matches("xor ")
                    ),
                    start,
                    // Rotated so the lens, which indexes by file offset, lines up
                    // with the block the key was derived from.
                    c.recipe_at(start),
                )
            })
            .collect();
        self.set_status("Enter puts that key on the lens · best-explaining first · Esc cancels");
        self.dialog = Some(Dialog::XorHits {
            items,
            sel: 0,
            filter: String::new(),
        });
    }

    /// Hunt for plaintext hidden behind a single-byte XOR/ADD/ROL.
    pub(super) fn xor_search(&mut self) {
        let hits = hiewlm_core::xorsearch::search_buffer(
            &self.buffer,
            &hiewlm_core::xorsearch::DEFAULT_NEEDLES,
            500,
            64 * 1024 * 1024,
        );
        if hits.is_empty() {
            self.set_status("No plaintext found under any single-byte xor/add/sub/rol key.");
            return;
        }
        let items: Vec<(String, u64, String)> = hits
            .iter()
            .map(|h| {
                let preview: String = h.preview.chars().take(72).collect();
                (
                    format!(
                        "!{} {:<10} {:<14} {preview}",
                        self.display_addr(h.offset),
                        h.recipe(),
                        h.needle
                    ),
                    h.offset,
                    h.recipe(),
                )
            })
            .collect();
        self.set_status("Enter jumps there AND sets the lens to that recipe · type to filter");
        self.dialog = Some(Dialog::XorHits {
            items,
            sel: 0,
            filter: String::new(),
        });
    }
}
