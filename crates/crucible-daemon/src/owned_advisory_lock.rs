//! Process-local ownership for advisory file locks.
//!
//! Linux `flock` ownership follows the open file description. A fork or
//! descriptor duplication can therefore keep a lock alive after Rust drops the
//! original [`File`]. This guard explicitly unlocks before closing its file so
//! the logical owner's lifetime remains authoritative.

use std::fs::File;

use rustix::fs::{FlockOperation, flock};

/// Exclusive advisory lock whose Rust owner explicitly releases the lease.
#[derive(Debug)]
pub(crate) struct OwnedAdvisoryLock {
    file: File,
}

impl OwnedAdvisoryLock {
    /// Acquires a nonblocking exclusive lock over `file`.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when the lock is held or cannot be
    /// acquired.
    pub(crate) fn try_exclusive(file: File) -> Result<Self, rustix::io::Errno> {
        flock(&file, FlockOperation::NonBlockingLockExclusive)?;
        Ok(Self { file })
    }

    /// Acquires a blocking exclusive lock over `file`.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when the lock cannot be acquired.
    pub(crate) fn exclusive(file: File) -> Result<Self, rustix::io::Errno> {
        flock(&file, FlockOperation::LockExclusive)?;
        Ok(Self { file })
    }

    /// Borrows the locked file for descriptor-lifetime regressions.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn file(&self) -> &File {
        &self.file
    }
}

impl Drop for OwnedAdvisoryLock {
    fn drop(&mut self) {
        // Unlocking the shared open-file description prevents a forked or
        // duplicated descriptor from extending this logical owner's lease.
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixture failures use exact panic locations.
#[allow(clippy::expect_used)]
mod tests {
    use std::fs::OpenOptions;

    use super::*;

    #[test]
    fn owner_drop_unlocks_a_retained_duplicate_file_description() {
        let directory = tempfile::tempdir().expect("lock directory");
        let path = directory.path().join("owner.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .expect("open first lock descriptor");
        let owner = OwnedAdvisoryLock::try_exclusive(file).expect("acquire first owner");
        let competing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open competing lock descriptor");
        assert_eq!(
            OwnedAdvisoryLock::try_exclusive(competing_file)
                .expect_err("live logical owner excludes an independent owner"),
            rustix::io::Errno::WOULDBLOCK
        );
        let retained_duplicate = owner.file().try_clone().expect("duplicate lock descriptor");

        drop(owner);

        let next = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open next lock descriptor");
        let next_owner = OwnedAdvisoryLock::try_exclusive(next)
            .expect("logical owner drop releases retained description");
        drop(next_owner);
        drop(retained_duplicate);
    }
}
