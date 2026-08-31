//! The document view: Office structure, findings, macros and metadata.
//!
//! Split out of `app.rs` because it is a self-contained screen with its own
//! panes and selection, sharing only the buffer and the status line.

use super::*;

impl super::App {
    // -- Document view ---------------------------------------------------

    pub fn doc_supported(&self) -> bool {
        self.document.is_some()
    }

    /// The rows of the current document pane: label plus an optional offset to
    /// navigate to, the same shape every other list in hiewLM uses.
    pub fn doc_rows(&self) -> Vec<(String, Option<u64>)> {
        let Some(d) = &self.document else {
            return vec![("(not a document)".into(), None)];
        };
        match self.doc_pane {
            DocPane::Structure => {
                if d.nodes.is_empty() {
                    return vec![("(no structure)".into(), None)];
                }
                d.nodes
                    .iter()
                    .map(|n| {
                        let indent = "  ".repeat(n.depth.min(8));
                        let size = if n.size > 0 {
                            format!("{:>9}", n.size)
                        } else {
                            "         ".into()
                        };
                        let detail = if n.detail.is_empty() {
                            String::new()
                        } else {
                            format!("  {}", n.detail)
                        };
                        let warn = matches!(n.kind, "macro" | "object");
                        (
                            format!(
                                "{}{:<8} {size}  {indent}{}{detail}",
                                if warn { "!" } else { " " },
                                n.kind,
                                n.path
                            ),
                            n.file_off,
                        )
                    })
                    .collect()
            }
            DocPane::Findings => {
                if d.findings.is_empty() {
                    return vec![("(nothing flagged)".into(), None)];
                }
                d.findings
                    .iter()
                    .map(|f| {
                        let warn = f.severity == hiewlm_core::Severity::Suspicious;
                        // A finding backed by several hits says so, because
                        // Enter opens the list instead of jumping.
                        let more = match self.finding_group(f) {
                            Some(g) if g.hits.len() > 1 => {
                                format!("   [Enter: {} matches]", g.hits.len())
                            }
                            _ => String::new(),
                        };
                        (
                            format!(
                                "{}[{}] {}{more}",
                                if warn { "!" } else { " " },
                                f.severity,
                                f.message
                            ),
                            f.offset,
                        )
                    })
                    .collect()
            }
            DocPane::Macros => {
                if d.macros.is_empty() {
                    return vec![("(no VBA macros)".into(), None)];
                }
                let mut rows = Vec::new();
                for m in &d.macros {
                    rows.push((format!("── {} ──", m.path), None));
                    if !m.keywords.is_empty() {
                        rows.push((format!("!  keywords: {}", m.keywords.join(", ")), None));
                    }
                    for line in m.source.lines() {
                        rows.push((format!("   {line}"), None));
                    }
                    rows.push((String::new(), None));
                }
                rows
            }
            DocPane::Info => {
                let mut rows = vec![
                    (format!("{:<16} {}", "Format", d.format), None),
                    (format!("{:<16} {}", "Container", d.kind.label()), None),
                    (format!("{:<16} {}", "Nodes", d.nodes.len()), None),
                    (
                        format!(
                            "{:<16} {} ({} suspicious)",
                            "Findings",
                            d.findings.len(),
                            d.suspicious_count()
                        ),
                        None,
                    ),
                    (format!("{:<16} {}", "VBA modules", d.macros.len()), None),
                ];
                for (k, v) in &d.metadata {
                    rows.push((format!("{k:<16} {v}"), None));
                }
                if d.external.is_empty() {
                    rows.push((format!("{:<16} none", "External refs"), None));
                } else {
                    rows.push((format!("{:<16}", "External refs"), None));
                    for e in &d.external {
                        rows.push((format!("!  {e}"), None));
                    }
                }
                rows
            }
        }
    }

    /// Scroll sideways, in columns. Bounded so it cannot scroll into nothing.
    pub fn hscroll_by(&mut self, delta: i64) {
        const MAX: i64 = 4096;
        self.hscroll = (self.hscroll as i64 + delta).clamp(0, MAX) as usize;
        if self.hscroll == 0 && delta < 0 {
            self.set_status("Left edge.");
        }
    }

    pub(super) fn doc_move(&mut self, delta: i64) {
        let last = self.doc_rows().len().saturating_sub(1) as i64;
        self.doc_sel = (self.doc_sel as i64 + delta).clamp(0, last) as usize;
    }

    /// The match group behind a finding, when it has one.
    ///
    /// Findings are keyed by the label their message starts with (`/URI: …`),
    /// which is how the parser writes them.
    pub(super) fn finding_group(
        &self,
        f: &hiewlm_core::Finding,
    ) -> Option<&hiewlm_office::MatchGroup> {
        let d = self.document.as_ref()?;
        let label = f.message.split(':').next()?.trim();
        d.match_groups.iter().find(|g| g.label == label)
    }

    /// In the Findings pane, open a finding's matches rather than jumping to the
    /// first one: "300 occurrences" is only useful if the three hundred can be
    /// read.
    fn doc_open_matches(&mut self) -> bool {
        if self.doc_pane != DocPane::Findings {
            return false;
        }
        let Some(d) = &self.document else {
            return false;
        };
        let Some(f) = d.findings.get(self.doc_sel) else {
            return false;
        };
        let Some(group) = self.finding_group(f) else {
            return false;
        };
        if group.hits.len() < 2 {
            return false;
        }
        let title = format!("{} — {} matches", group.label, group.hits.len());
        let items: Vec<(String, u64)> = group
            .hits
            .iter()
            .map(|(off, text)| {
                let text: String = text.chars().take(160).collect();
                (format!("{}  {text}", self.display_addr(*off)), *off)
            })
            .collect();
        self.dialog = Some(Dialog::JumpList {
            title,
            items,
            sel: 0,
            filter: String::new(),
        });
        self.set_status("Type to filter · ←→ scrolls a long line · Enter jumps");
        true
    }

    pub(super) fn doc_activate(&mut self) {
        if self.doc_open_matches() {
            return;
        }
        let rows = self.doc_rows();
        match rows.get(self.doc_sel) {
            Some((label, Some(off))) => {
                let (off, label) = (*off, label.clone());
                self.record_jump();
                self.mode = Mode::Hex;
                self.move_to(off);
                self.set_status(format!("→ {}  {}", self.display_addr(off), label.trim()));
            }
            Some(_) => self.set_status("This row is not a location in the file."),
            None => {}
        }
    }
}
