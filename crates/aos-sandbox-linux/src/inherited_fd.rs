//! Safe duplication of unowned numeric descriptors inherited at process start.
//!
//! Environment protocols such as systemd descriptor activation identify an
//! already-open file description by number. Constructing an [`OwnedFd`] from
//! that number would assume ownership which a safe library caller may already
//! hold. This module instead applies `F_DUPFD_CLOEXEC`: the original table
//! entry is only observed, and a distinct newly allocated descriptor is owned.

use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};

use crate::{Error, Result};

/// Duplicates one currently open numeric descriptor into new owned storage.
///
/// The original descriptor remains open and untouched. Callers admitting an
/// environment-described descriptor set must separately prevent descriptor
/// table races and validate every duplicated kernel object and access mode.
///
/// # Errors
///
/// Returns an error when `raw` is negative, closed, or cannot be duplicated.
pub fn duplicate_inherited_descriptor(raw: RawFd) -> Result<OwnedFd> {
    if raw < 0 {
        return Err(Error::invalid(
            "inherited descriptor",
            "number must be non-negative",
        ));
    }

    // SAFETY: `F_DUPFD_CLOEXEC` only observes the numeric table entry and
    // returns a distinct descriptor on success. It neither closes nor assumes
    // ownership of `raw`, so a caller-owned `File` cannot be double-owned.
    let duplicated = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(Error::syscall("fcntl(F_DUPFD_CLOEXEC)"));
    }
    // SAFETY: successful F_DUPFD_CLOEXEC returned this fresh descriptor and no
    // other safe owner has been constructed for it.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;

    use super::*;

    #[test]
    fn duplication_never_takes_the_callers_original_ownership() {
        let original = std::fs::File::open("/proc/self/exe")
            .unwrap_or_else(|error| panic!("test executable failed: {error}"));
        let raw = original.as_raw_fd();
        let duplicate = duplicate_inherited_descriptor(raw)
            .unwrap_or_else(|error| panic!("descriptor duplication failed: {error}"));
        drop(duplicate);

        let mut original = original;
        let mut byte = [0_u8; 1];
        original
            .read_exact(&mut byte)
            .unwrap_or_else(|error| panic!("original descriptor was invalidated: {error}"));
    }

    #[test]
    fn invalid_descriptor_is_rejected_without_assuming_ownership() {
        assert!(duplicate_inherited_descriptor(i32::MAX).is_err());
    }
}
