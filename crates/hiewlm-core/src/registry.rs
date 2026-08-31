//! Extension points: add a file format or a CPU architecture by implementing a
//! trait and registering it, without touching the core (design §24). M0 defines
//! the contract; real parsers and disassemblers arrive in M1.

use crate::addr::AddressSpace;
use crate::buffer::EditBuffer;

/// How confident a parser is that it recognizes a buffer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Confidence {
    Weak,
    Likely,
    Strong,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Format {
    Raw,
    Pe,
    Elf,
    MachO,
    Ne,
    Le,
    Lx,
    Te,
    Coff,
    Nlm,
    Archive,
}

impl Format {
    pub fn label(&self) -> &'static str {
        match self {
            Format::Raw => "raw",
            Format::Pe => "PE",
            Format::Elf => "ELF",
            Format::MachO => "Mach-O",
            Format::Ne => "NE",
            Format::Le => "LE",
            Format::Lx => "LX",
            Format::Te => "TE",
            Format::Coff => "COFF",
            Format::Nlm => "NLM",
            Format::Archive => "archive",
        }
    }

    /// A container of members (ar/ZIP) rather than a single code image.
    /// Function recovery is meaningless here; F12 lists members instead.
    pub fn is_container(&self) -> bool {
        matches!(self, Format::Archive)
    }
}

/// CPU architecture of an executable, enough to pick a disassembler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Riscv,
    Ppc,
    Sparc,
    Wasm,
    Unknown,
}

impl Arch {
    pub fn label(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x64",
            Arch::Arm => "arm",
            Arch::Arm64 => "arm64",
            Arch::Mips => "mips",
            Arch::Riscv => "riscv",
            Arch::Ppc => "ppc",
            Arch::Sparc => "sparc",
            Arch::Wasm => "wasm",
            Arch::Unknown => "?",
        }
    }
}

/// A named symbol (import/export). `va` is 0 when the format gives no address
/// (common for imports).
#[derive(Debug, Clone)]
pub struct Sym {
    pub name: String,
    pub va: u64,
}

/// A PE resource leaf (type / name / language) with its raw data location.
#[derive(Debug, Clone)]
pub struct Resource {
    pub type_name: String,
    pub name: String,
    pub lang: u32,
    pub file_off: u64,
    pub size: u64,
}

/// The result of parsing an executable format, enough to navigate, disassemble,
/// and display the header.
#[derive(Debug, Clone)]
pub struct ExecutableModel {
    pub format: Format,
    pub arch: Arch,
    pub bits: u8,
    pub address_space: AddressSpace,
    pub entry: Option<u64>,
    pub imports: Vec<Sym>,
    pub exports: Vec<Sym>,
    /// Raw header struct fields as (name, value) pairs, for the Info pane.
    pub header_fields: Vec<(String, String)>,
    /// PE resources (empty for other formats).
    pub resources: Vec<Resource>,
}

/// Recognizes and parses a file format. Must be side-effect free: it only reads
/// the buffer and never executes its contents (design §22.1).
pub trait FormatParser: Send + Sync {
    fn name(&self) -> &'static str;
    fn probe(&self, buf: &EditBuffer) -> Option<Confidence>;
    fn parse(&self, buf: &EditBuffer) -> anyhow::Result<ExecutableModel>;
}

#[derive(Default)]
pub struct FormatRegistry {
    parsers: Vec<Box<dyn FormatParser>>,
}

impl std::fmt::Debug for FormatRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormatRegistry")
            .field(
                "parsers",
                &self.parsers.iter().map(|p| p.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl FormatRegistry {
    pub fn register(&mut self, parser: Box<dyn FormatParser>) {
        self.parsers.push(parser);
    }

    /// Pick the parser with the highest confidence; returns `None` if no parser
    /// claims the buffer.
    pub fn detect(&self, buf: &EditBuffer) -> Option<ExecutableModel> {
        let best = self
            .parsers
            .iter()
            .filter_map(|p| p.probe(buf).map(|c| (c, p)))
            .max_by_key(|(c, _)| *c)?;
        best.1.parse(buf).ok()
    }
}
