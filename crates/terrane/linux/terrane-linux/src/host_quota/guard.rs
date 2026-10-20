//! Serializes explicit host provisioning against native domain factory lifetimes.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

/// Retains an advisory lock on the actual domain-layout root inode.
///
/// Native allocation and publication factories retain shared guards throughout
/// their lifetimes. Host administration requires exclusive guards before quota
/// or project mutations. The lock is released when this value is dropped.
pub struct DomainProvisioningGuard {
    directory: File,
}

impl DomainProvisioningGuard {
    fn acquire(layout_root: &File, operation: libc::c_int) -> io::Result<Self> {
        // Open an independent description: dup would share flock state with the
        // supplied descriptor and could convert another owner's existing lock.
        // SAFETY: the borrowed descriptor remains live and the fixed terminated
        // dot component opens precisely the retained directory, including O_PATH.
        let descriptor = unsafe {
            libc::openat(
                layout_root.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a newly owned descriptor.
        let directory = unsafe { File::from_raw_fd(descriptor) };
        // SAFETY: flock has no pointer arguments; this independent description
        // owns the lock until its final close.
        if unsafe { libc::flock(directory.as_raw_fd(), operation | libc::LOCK_NB) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { directory })
    }

    /// Acquires a shared guard for a native factory's complete lifetime.
    ///
    /// # Errors
    /// Returns an error when provisioning has exclusive custody, or the retained
    /// descriptor does not permit opening and locking its actual directory.
    pub fn shared(layout_root: &File) -> io::Result<Self> {
        Self::acquire(layout_root, libc::LOCK_SH)
    }

    /// Acquires exclusive custody for explicit quiescent host administration.
    ///
    /// # Errors
    /// Returns an error while any native factory retains its shared guard, or
    /// when the descriptor or filesystem cannot support the directory lock.
    pub fn exclusive(layout_root: &File) -> io::Result<Self> {
        Self::acquire(layout_root, libc::LOCK_EX)
    }

    /// Reports the actual retained layout-root device and inode.
    ///
    /// # Errors
    /// Returns native metadata errors.
    pub fn identity(&self) -> io::Result<(u64, u64)> {
        let metadata = self.directory.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
}
