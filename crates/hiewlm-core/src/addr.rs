//! Distinct address types so the compiler prevents mixing up offset vs VA.

use std::fmt;

macro_rules! define_addr {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub u64);

        impl $name {
            #[inline]
            pub const fn get(self) -> u64 {
                self.0
            }

            #[inline]
            pub fn checked_add(self, delta: u64) -> Option<Self> {
                self.0.checked_add(delta).map(Self)
            }

            #[inline]
            pub fn saturating_add(self, delta: u64) -> Self {
                Self(self.0.saturating_add(delta))
            }

            #[inline]
            pub fn saturating_sub(self, delta: u64) -> Self {
                Self(self.0.saturating_sub(delta))
            }
        }

        impl From<u64> for $name {
            #[inline]
            fn from(v: u64) -> Self {
                Self(v)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:#x})", stringify!($name), self.0)
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }
    };
}

define_addr!(FileOffset);
define_addr!(Va);
define_addr!(LocalOff);
define_addr!(GlobalOff);

/// Maps file offset <-> virtual address across the sections of an executable
/// image. Empty until a format parser fills it; [`AddressSpace::flat`] treats
/// VA == offset (i.e. unmapped).
#[derive(Debug, Clone, Default)]
pub struct AddressSpace {
    image_base: u64,
    sections: Vec<SectionMap>,
}

#[derive(Debug, Clone)]
pub struct SectionMap {
    pub file_off: u64,
    pub va: u64,
    pub size: u64,
    pub name: String,
}

impl AddressSpace {
    pub fn flat() -> Self {
        Self::default()
    }

    pub fn new(image_base: u64, sections: Vec<SectionMap>) -> Self {
        Self {
            image_base,
            sections,
        }
    }

    pub fn is_mapped(&self) -> bool {
        !self.sections.is_empty()
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn sections(&self) -> &[SectionMap] {
        &self.sections
    }

    pub fn va_of(&self, off: FileOffset) -> Option<Va> {
        let o = off.get();
        self.sections
            .iter()
            .find(|s| o >= s.file_off && o < s.file_off + s.size)
            .map(|s| Va(s.va + (o - s.file_off)))
    }

    pub fn offset_of(&self, va: Va) -> Option<FileOffset> {
        let v = va.get();
        self.sections
            .iter()
            .find(|s| v >= s.va && v < s.va + s.size)
            .map(|s| FileOffset(s.file_off + (v - s.va)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn va_offset_roundtrip() {
        let space = AddressSpace {
            image_base: 0x400000,
            sections: vec![SectionMap {
                file_off: 0x400,
                va: 0x401000,
                size: 0x1000,
                name: ".text".into(),
            }],
        };
        let off = FileOffset(0x450);
        let va = space.va_of(off).unwrap();
        assert_eq!(va, Va(0x401050));
        assert_eq!(space.offset_of(va), Some(off));
    }

    #[test]
    fn unmapped_offset_has_no_va() {
        let space = AddressSpace::flat();
        assert_eq!(space.va_of(FileOffset(0x10)), None);
    }
}
