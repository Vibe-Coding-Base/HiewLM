//! hiewLM core — pure logic with no terminal dependency (design §5).
//!
//! Non-negotiable principle: every byte of the target file is **passive data**.
//! This crate has no code path that loads or runs file content (design §22).

#![warn(missing_debug_implementations)]

pub mod addr;
pub mod buffer;
pub mod calc;
pub mod container;
pub mod crypt;
pub mod packer;
pub mod registry;
pub mod search;
pub mod structdef;
pub mod timefmt;

pub use addr::{AddressSpace, FileOffset, GlobalOff, LocalOff, SectionMap, Va};
pub use buffer::{DataSource, EditBuffer, FileSource, MemSource};
pub use container::{Container, ContainerParser, ContainerRegistry, Finding, Member, Severity};
pub use crypt::{Recipe as CryptRecipe, CryptError};
pub use registry::{
    Arch, Confidence, ExecutableModel, Format, FormatParser, FormatRegistry, Resource, Sym,
};
pub use search::{find, find_all, Direction, Pattern};
pub use structdef::{apply as apply_struct, ResolvedField, Template};
pub use timefmt::format_unix;
