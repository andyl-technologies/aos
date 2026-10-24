//! Exact SELinux object-label comparison for held descriptors.

use std::os::fd::BorrowedFd;
use crate::{Error, Result};

const MAXIMUM_CONTEXT_BYTES: usize = 256;


/// Requires the exact SELinux label on the same held object.
///
/// # Errors
/// Returns the original native xattr error or exact-label mismatch.
pub fn require_object_context(fd: BorrowedFd<'_>, expected: &str) -> Result<()> {
    let mut context = [0; MAXIMUM_CONTEXT_BYTES];
    let length = rustix::fs::fgetxattr(fd, "security.selinux", &mut context)
        .map_err(|source| Error::Syscall { operation: "read worker object SID", source: source.into() })?;
    if !context_matches(&context[..length], expected.as_bytes()) {
        return Err(Error::invalid("worker object SID", "unexpected label"));
    }
    Ok(())
}



/// Compares exact context bytes, allowing only one trailing kernel NUL.
#[must_use]
pub fn context_matches(observed: &[u8], expected: &[u8]) -> bool {
    observed == expected
        || (observed.len() == expected.len() + 1
            && observed.starts_with(expected)
            && observed.last() == Some(&0))
}
