//! Checks the inherited kernel prohibition on creating set-ID files.
//!
//! The systemd service child installs the guard before executing a protected
//! process. The process checks the inherited state before opening any protected
//! authority or accepting descriptors. An older kernel has no query operation
//! and therefore cannot satisfy this contract.

use std::ffi::OsStr;
use std::fs;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::os::unix::ffi::OsStrExt as _;

use crate::{Error, Result, uapi};

/// Requires the calling thread to have the AOS no-set-ID guard installed.
///
/// # Errors
///
/// Returns an error when the kernel does not implement the query, the query
/// fails, or the inherited guard is not set. The check is thread-local and
/// must run before the caller creates other threads or opens protected state.
pub fn require_inherited_no_setid() -> Result<()> {
    require_guard_value(uapi::get_aos_no_setid()?)
}

/// Requires the inherited guard and rejects every inherited io_uring ring.
///
/// The caller must run this before opening protected state or claiming a
/// descriptor role. A pre-existing SQPOLL ring can execute through its shared
/// mapping without another io_uring syscall, so seccomp alone is insufficient.
/// Protocol-specific admission must also validate later transferred FDs.
///
/// # Errors
///
/// Returns an error when the guard is absent or unsupported, procfs cannot be
/// scanned completely, or an io_uring ring was inherited.
pub fn require_guarded_startup() -> Result<()> {
    require_inherited_no_setid()?;

    let entries = fs::read_dir("/proc/self/fd").map_err(|source| Error::Syscall {
        operation: "read process startup descriptor table",
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| Error::Syscall {
            operation: "enumerate startup descriptor table",
            source,
        })?;
        let target = fs::read_link(entry.path()).map_err(|source| Error::Syscall {
            operation: "inspect startup descriptor",
            source,
        })?;
        if is_io_uring_link(target.as_os_str()) {
            return Err(Error::invalid(
                "inherited descriptor table",
                "io_uring ring descriptor is forbidden",
            ));
        }
    }

    Ok(())
}

/// Rejects an io_uring ring received after process startup.
///
/// Call this on each descriptor admitted from `SCM_RIGHTS`, pidfd duplication,
/// or another external FD source before assigning it a role or mapping it.
///
/// # Errors
///
/// Returns an error when procfs cannot identify the descriptor or when the
/// descriptor is an io_uring ring.
pub fn reject_io_uring_descriptor(descriptor: BorrowedFd<'_>) -> Result<()> {
    let path = format!("/proc/self/fd/{}", descriptor.as_raw_fd());
    let target = fs::read_link(path).map_err(|source| Error::Syscall {
        operation: "inspect received descriptor",
        source,
    })?;
    if is_io_uring_link(target.as_os_str()) {
        return Err(Error::invalid(
            "received descriptor",
            "io_uring ring descriptor is forbidden",
        ));
    }

    Ok(())
}

fn require_guard_value(value: i32) -> Result<()> {
    if value != 1 {
        return Err(Error::MalformedKernelResponse {
            object: "PR_GET_AOS_NO_SETID",
            message: format!("expected installed guard value 1, observed {value}"),
        });
    }

    Ok(())
}

fn is_io_uring_link(target: &OsStr) -> bool {
    matches!(
        target.as_bytes(),
        b"anon_inode:[io_uring]" | b"anon_inode:io_uring"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_installed_guard_is_accepted() {
        assert!(require_guard_value(1).is_ok());
        assert!(require_guard_value(0).is_err());
        assert!(require_guard_value(2).is_err());
    }

    #[test]
    fn inherited_ring_links_are_rejected() {
        assert!(is_io_uring_link(OsStr::new("anon_inode:[io_uring]")));
        assert!(is_io_uring_link(OsStr::new("anon_inode:io_uring")));
        assert!(!is_io_uring_link(OsStr::new("anon_inode:[eventfd]")));
        assert!(!is_io_uring_link(OsStr::new("socket:[123]")));
    }
}
