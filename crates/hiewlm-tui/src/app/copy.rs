//! Getting facts out of the terminal: the copy menu and the report writer.

use super::*;

impl super::App {
    // -- Clipboard ----------------------------------------------------

    /// Copy entry `idx` of the copy menu to the system clipboard.
    ///
    /// Everything here is about getting a fact out of the terminal and into a
    /// ticket, a rule or a script without retyping it.
    pub(super) fn copy_item(&mut self, idx: usize) {
        self.dialog = None;
        // Hashes and indicators come from the triage report; build it on demand.
        if idx <= 3 || idx >= 9 {
            self.ensure_triage();
        }
        // Writing the report is a file operation, not a clipboard one.
        if idx == 12 {
            self.write_report();
            return;
        }
        let sel = self.read_selection();
        let what: (String, String) = match idx {
            0 => ("SHA-256".into(), self.triage.as_ref().map(|t| t.hashes.sha256.clone()).unwrap_or_default()),
            1 => ("MD5".into(), self.triage.as_ref().map(|t| t.hashes.md5.clone()).unwrap_or_default()),
            2 => ("ssdeep".into(), self.triage.as_ref().map(|t| t.hashes.ssdeep.clone()).unwrap_or_default()),
            3 => (
                "imphash".into(),
                self.triage
                    .as_ref()
                    .and_then(|t| t.hashes.imphash.clone())
                    .unwrap_or_else(|| "(no import hash: not a PE, or no imports)".into()),
            ),
            4 => ("block as hex".into(), sel.map(|b| crate::clipboard::as_hex(&b)).unwrap_or_default()),
            5 => ("block as C array".into(), sel.map(|b| crate::clipboard::as_c_array(&b)).unwrap_or_default()),
            6 => ("block as Python".into(), sel.map(|b| crate::clipboard::as_python(&b)).unwrap_or_default()),
            7 => (
                "block as text".into(),
                sel.map(|b| b.iter().map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '.' }).collect())
                    .unwrap_or_default(),
            ),
            8 => ("address".into(), self.display_addr(self.cursor)),
            9 => (
                "indicators".into(),
                self.triage
                    .as_ref()
                    .map(|t| {
                        t.indicators
                            .iter()
                            .map(|i| format!("{}\t{}", i.kinds, i.value))
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default(),
            ),
            10 => (
                "triage report".into(),
                self.triage.as_ref().map(hiewlm_triage::render::text).unwrap_or_default(),
            ),
            _ => (
                "Markdown report".into(),
                self.triage.as_ref().map(hiewlm_triage::render::markdown).unwrap_or_default(),
            ),
        };
        let (label, text) = what;
        if text.is_empty() {
            self.set_status(format!("Nothing to copy for {label} (mark a block with * first?)"));
            return;
        }
        match crate::clipboard::copy(&text) {
            Ok(n) => self.set_status(format!("Copied {label} ({n} bytes) to the system clipboard.")),
            Err(e) => self.set_status(format!("Copy failed: {e}")),
        }
    }

    /// Write the Markdown report beside the sample as `<file>.triage.md`.
    ///
    /// This creates a *new* file and never touches the sample, so it works while
    /// the sample is locked — which is the whole point: writing up a case must
    /// not require unlocking evidence.
    pub(super) fn write_report(&mut self) {
        let Some(report) = self.triage.as_ref().map(hiewlm_triage::render::markdown) else {
            self.set_status("No triage report yet (press 2).");
            return;
        };
        let mut path = self.path.as_os_str().to_os_string();
        path.push(".triage.md");
        let path = PathBuf::from(path);
        match fs::write(&path, report) {
            Ok(()) => self.set_status(format!("Report written to {}", path.display())),
            Err(e) => self.set_status(format!("Cannot write the report: {e}")),
        }
    }

}
