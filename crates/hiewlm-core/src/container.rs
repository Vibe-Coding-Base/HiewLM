//! Container-format plugins: ZIP, PDF, and anything else that holds members
//! rather than a single code image.
//!
//! A plugin is a crate implementing [`ContainerParser`] and registered in a
//! [`ContainerRegistry`]. Registration is static (the crate is linked in) and
//! activation is by name at runtime — hiewLM never loads native code at
//! runtime, because the security model (§22) forbids `dlopen`/`LoadLibrary`.
//! Parsers are read-only: they take bytes and return a description.

use std::fmt;

/// One member inside a container: a ZIP entry, a PDF object, an `ar` member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Display name ("a.txt", "obj 12 0").
    pub name: String,
    /// File offset the member's record starts at — what a jump navigates to.
    pub offset: u64,
    /// Size in bytes, if the container records one.
    pub size: u64,
    /// Free-form extra ("deflate", "/JavaScript"), shown next to the name.
    pub detail: String,
}

impl Member {
    pub fn new(name: impl Into<String>, offset: u64, size: u64, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            detail: detail.into(),
        }
    }
}

/// Severity of a [`Finding`]. Containers are a common malware delivery vector,
/// so parsers report what they notice rather than silently ignoring it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Suspicious,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Suspicious => "SUSPICIOUS",
        })
    }
}

/// Something worth telling the analyst about — an auto-run action, an
/// embedded executable, a path that escapes the extraction directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
    /// Where in the file it was observed, when known.
    pub offset: Option<u64>,
}

impl Finding {
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            message: message.into(),
            offset: None,
        }
    }
    pub fn suspicious(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Suspicious,
            message: message.into(),
            offset: None,
        }
    }
    pub fn at(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// The parsed shape of a container file.
#[derive(Clone, Debug, Default)]
pub struct Container {
    /// Human label of the detected format ("ZIP archive", "PDF document").
    pub kind: String,
    /// Header-style key/value summary.
    pub summary: Vec<(String, String)>,
    pub members: Vec<Member>,
    pub findings: Vec<Finding>,
}

impl Container {
    pub fn suspicious(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Suspicious)
    }
}

/// A container-format plugin.
///
/// Implementations must be pure and read-only: parse bytes, return a
/// [`Container`]. No filesystem, no network, no execution of file content.
pub trait ContainerParser: Send + Sync {
    /// Short activation name used on the command line (`zip`, `pdf`).
    fn name(&self) -> &'static str;

    /// One-line description for `--list-plugins`.
    fn description(&self) -> &'static str;

    /// Cheap magic-byte check. Must not panic on short or hostile input.
    fn sniff(&self, bytes: &[u8]) -> bool;

    /// Full parse. Returns `None` if the bytes are not actually this format.
    fn parse(&self, bytes: &[u8]) -> Option<Container>;
}

/// The set of container plugins available, and which are switched on.
#[derive(Default)]
pub struct ContainerRegistry {
    parsers: Vec<Box<dyn ContainerParser>>,
    enabled: Vec<String>,
}

impl fmt::Debug for ContainerRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContainerRegistry")
            .field("available", &self.names())
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl ContainerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a plugin. Registered plugins start disabled — activation is
    /// explicit so that opening a file never runs a parser the user didn't ask for.
    pub fn register(&mut self, parser: Box<dyn ContainerParser>) -> &mut Self {
        self.parsers.push(parser);
        self
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.parsers.iter().map(|p| p.name()).collect()
    }

    pub fn descriptions(&self) -> Vec<(&'static str, &'static str)> {
        self.parsers
            .iter()
            .map(|p| (p.name(), p.description()))
            .collect()
    }

    /// Turn on plugins by name. `["all"]` enables every registered plugin.
    /// Returns the names that matched nothing.
    pub fn enable(&mut self, names: &[String]) -> Vec<String> {
        let mut unknown = Vec::new();
        for n in names {
            let n = n.trim().to_ascii_lowercase();
            if n == "all" {
                self.enabled = self.parsers.iter().map(|p| p.name().to_string()).collect();
                continue;
            }
            if self.parsers.iter().any(|p| p.name() == n) {
                if !self.enabled.contains(&n) {
                    self.enabled.push(n);
                }
            } else {
                unknown.push(n);
            }
        }
        unknown
    }

    pub fn is_enabled(&self, name: &str) -> bool {
        self.enabled.iter().any(|e| e == name)
    }

    /// Parse with the first enabled plugin that recognizes the bytes.
    pub fn parse(&self, bytes: &[u8]) -> Option<(&'static str, Container)> {
        self.parsers
            .iter()
            .filter(|p| self.is_enabled(p.name()))
            .filter(|p| p.sniff(bytes))
            .find_map(|p| p.parse(bytes).map(|c| (p.name(), c)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dummy;
    impl ContainerParser for Dummy {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn description(&self) -> &'static str {
            "test parser"
        }
        fn sniff(&self, bytes: &[u8]) -> bool {
            bytes.starts_with(b"DUM")
        }
        fn parse(&self, _bytes: &[u8]) -> Option<Container> {
            Some(Container {
                kind: "dummy".into(),
                ..Default::default()
            })
        }
    }

    fn reg() -> ContainerRegistry {
        let mut r = ContainerRegistry::new();
        r.register(Box::new(Dummy));
        r
    }

    #[test]
    fn parsers_start_disabled() {
        let r = reg();
        assert!(!r.is_enabled("dummy"));
        assert!(r.parse(b"DUMmy").is_none());
    }

    #[test]
    fn enabling_by_name_activates_parsing() {
        let mut r = reg();
        assert!(r.enable(&["dummy".into()]).is_empty());
        assert_eq!(r.parse(b"DUMmy").map(|(n, _)| n), Some("dummy"));
    }

    #[test]
    fn enable_all_and_unknown_names_reported() {
        let mut r = reg();
        assert_eq!(r.enable(&["nope".into()]), vec!["nope".to_string()]);
        r.enable(&["all".into()]);
        assert!(r.is_enabled("dummy"));
    }

    #[test]
    fn sniff_gates_parsing() {
        let mut r = reg();
        r.enable(&["all".into()]);
        assert!(r.parse(b"other").is_none());
    }
}
