//! The triage screen: building the report once and rendering its panes.

use super::*;

impl super::App {
    // -- Triage screen -----------------------------------------------

    /// Build the triage report once and keep it. It hashes and scans the whole
    /// file, so it is worth a second on a large sample but not on every redraw.
    pub(super) fn ensure_triage(&mut self) {
        if self.triage.is_some() {
            return;
        }
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.to_string_lossy().into_owned());
        let report = hiewlm_triage::analyze(
            &name,
            &self.buffer,
            self.container.as_ref(),
            &hiewlm_triage::Options::default(),
        );
        self.set_status(format!(
            "Triage: {} ({}/100) {} · ←→ pane · type=filter · Enter jump · Esc",
            report.verdict().to_uppercase(),
            report.score,
            report.badge_line()
        ));
        self.triage = Some(report);
    }

    /// Badges for the status line (`PACKED ENT7.9 OVL+128K`), once triage has run.
    pub fn triage_badges(&self) -> Option<String> {
        let r = self.triage.as_ref()?;
        let b = r.badge_line();
        Some(if b.is_empty() {
            format!("[{} {}]", r.verdict(), r.score)
        } else {
            format!("[{} {} {b}]", r.verdict(), r.score)
        })
    }

    pub fn triage_entries(&self, pane: TriagePane, filter: &str) -> Vec<(String, Option<u64>)> {
        let Some(r) = &self.triage else {
            return vec![("(analysing…)".to_string(), None)];
        };
        apply_header_filter(hiewlm_triage::render::pane_lines(r, pane), filter)
    }

    pub(super) fn triage_activate(&mut self, pane: TriagePane, sel: usize, filter: &str) {
        let entries = self.triage_entries(pane, filter);
        match entries.get(sel) {
            Some((label, Some(off))) => {
                let (off, label) = (*off, label.clone());
                self.goto_offset(off);
                self.set_status(format!("→ {}  {}", self.display_addr(off), label.trim()));
            }
            Some((_, None)) => self.set_status("Not a jump target."),
            None => {}
        }
    }

    /// Entries for a header pane after applying `filter`: label + optional jump
    /// offset. Info fields are view-only (no offset); the rest are jumpable.
    pub fn header_entries(&self, pane: HeaderPane, filter: &str) -> Vec<(String, Option<u64>)> {
        let jump = |va: u64| (va != 0).then(|| self.va_to_off(va).unwrap_or(va));
        let raw: Vec<(String, Option<u64>)> = match pane {
            HeaderPane::Info => {
                let mut v = Vec::new();
                // A plugin-parsed container has no arch/bits; show its structure
                // and findings instead of an empty executable header.
                if let Some(c) = &self.container {
                    v.push((format!("{:<18} {}", "Container", c.kind), None));
                    for (k, val) in &c.summary {
                        v.push((format!("{k:<18} {val}"), None));
                    }
                    for f in &c.findings {
                        v.push((format!("{:<18} [{}] {}", "", f.severity, f.message), f.offset));
                    }
                    return apply_header_filter(v, filter);
                }
                v.push((
                    format!("{:<18} {} / {} / {}-bit", "Format", self.format.label(), self.arch.label(), self.bits),
                    None,
                ));
                if let Some(t) = &self.file_mtime {
                    // Filesystem metadata, NOT a header value and NOT compile time.
                    v.push((format!("{:<18} {t}", "File mtime (fs)"), None));
                }
                if let Some(e) = self.file_entropy {
                    v.push((format!("{:<18} {e:.3} / 8.0", "File entropy"), None));
                }
                if let Some(h) = &self.imphash {
                    v.push((format!("{:<18} {h}", "ImpHash"), None));
                }
                if let Some(p) = &self.packer {
                    v.push((format!("{:<18} {p}", "Packer"), None));
                }
                if let Some(va) = self.entry {
                    v.push((
                        format!("{:<18} .{va:08X}   [Enter jumps]", "Entry point"),
                        (va != 0).then(|| self.va_to_off(va).unwrap_or(va)),
                    ));
                }
                for (k, val) in &self.header_fields {
                    v.extend(wrap_field(k, val));
                }
                v
            }
            HeaderPane::Sections => self
                .address_space
                .sections()
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let ent = self.section_entropy.get(i).copied().unwrap_or(0.0);
                    (
                        format!("{:<12} off:{:08X} va:.{:08X} size:{:>8X} ent:{:.2}", s.name, s.file_off, s.va, s.size, ent),
                        Some(s.file_off),
                    )
                })
                .collect(),
            // Each import carries its behaviour category, and the ones that are
            // a signal on their own are marked so the list highlights them.
            HeaderPane::Imports => self
                .imports
                .iter()
                .map(|(n, va)| {
                    let (tag, warn) = match hiewlm_core::apiscore::lookup(n) {
                        Some((cat, _, true)) => (format!("[{}] ", cat.label()), "!"),
                        Some((cat, _, false)) => (format!("[{}] ", cat.label()), ""),
                        None => (String::new(), ""),
                    };
                    (format!("{warn}{tag}{}", fmt_sym(n, *va)), jump(*va))
                })
                .collect(),
            HeaderPane::Exports => self
                .exports
                .iter()
                .map(|(n, va)| (fmt_sym(n, *va), jump(*va)))
                .collect(),
            HeaderPane::Resources => self
                .resources
                .iter()
                .map(|r| (resource_label(r), Some(r.file_off)))
                .collect(),
        };
        apply_header_filter(raw, filter)
    }

    pub(super) fn header_activate(&mut self, pane: HeaderPane, sel: usize, filter: &str) {
        if pane == HeaderPane::Resources {
            let needle = filter.to_lowercase();
            let chosen = self
                .resources
                .iter()
                .filter(|r| filter.is_empty() || resource_label(r).to_lowercase().contains(&needle))
                .nth(sel)
                .cloned();
            if let Some(r) = chosen {
                self.extract_resource(&r);
            }
            return;
        }
        let entries = self.header_entries(pane, filter);
        match entries.get(sel) {
            Some((label, Some(off))) => {
                let off = *off;
                let label = label.clone();
                self.goto_offset(off);
                self.set_status(format!("→ {}  {}", self.display_addr(off), label));
            }
            Some((_, None)) => self.set_status("This field is not a jump target."),
            None => {}
        }
    }

}
