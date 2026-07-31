//! Detection on a real OS binary (fat Mach-O on macOS, ELF on Linux). Lenient:
//! if a binary is recognized it must expose sections — this guards the fat Mach-O
//! slice-offset handling.

use hiewlm_core::{EditBuffer, FileSource};
use std::sync::Arc;

#[test]
fn recognized_binary_has_sections() {
    for p in ["/bin/cat", "/bin/ls", "/usr/bin/true"] {
        if let Ok(src) = FileSource::open(p) {
            let buf = EditBuffer::new(Arc::new(src));
            if let Some(m) = hiewlm_fmt::detect(&buf) {
                assert!(
                    !m.address_space.sections().is_empty(),
                    "{p} detected as {:?} but has no sections",
                    m.format
                );
                return;
            }
        }
    }
}
