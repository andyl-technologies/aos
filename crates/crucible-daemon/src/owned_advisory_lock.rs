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
    authority: Option<crate::anchored_fs::AnchoredFile>,
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
        Ok(Self {
            file,
            authority: None,
        })
    }

    /// Acquires a blocking exclusive lock over `file`.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when the lock cannot be acquired.
    pub(crate) fn exclusive(file: File) -> Result<Self, rustix::io::Errno> {
        flock(&file, FlockOperation::LockExclusive)?;
        Ok(Self {
            file,
            authority: None,
        })
    }

    pub(crate) fn try_exclusive_bound(
        authority: crate::anchored_fs::AnchoredFile,
    ) -> Result<Self, crate::anchored_fs::AnchoredFsError> {
        let file = authority.try_clone()?;
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
            crate::anchored_fs::AnchoredFsError::Io {
                operation: "lock-anchored-file",
                path: authority.path().to_owned(),
                source: std::io::Error::from_raw_os_error(source.raw_os_error()),
            }
        })?;
        #[cfg(test)]
        run_lock_race_hook();
        authority.verify_path_binding()?;
        Ok(Self {
            file,
            authority: Some(authority),
        })
    }

    pub(crate) fn verify_path_binding(&self) -> Result<(), crate::anchored_fs::AnchoredFsError> {
        if let Some(authority) = &self.authority {
            authority.verify_path_binding()
        } else {
            Ok(())
        }
    }

    /// Borrows the locked file for descriptor-lifetime regressions.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn file(&self) -> &File {
        &self.file
    }
}

#[cfg(test)]
thread_local! {
    static LOCK_RACE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn install_lock_race_hook(hook: impl FnOnce() + 'static) {
    LOCK_RACE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_lock_race_hook() {
    LOCK_RACE_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
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
