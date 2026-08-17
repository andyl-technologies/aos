//! Advisory filesystem lock helpers for cache roots.
//!
//! Cross-process cache coordination needs a filesystem lock substrate before
//! pack and sidecar writers can participate in a common protocol. This module
//! owns a small Unix `flock` wrapper that creates its lock file, acquires shared
//! or exclusive advisory locks, and releases them when dropped. It is advisory
//! substrate only: callers must still arrange for every writer they care about
//! to use the same lock path.

use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Advisory lock mode for a cache lock file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvisoryFileLockMode {
    /// A shared reader lock.
    Shared,
    /// An exclusive writer lock.
    Exclusive,
}

impl AdvisoryFileLockMode {
    const fn operation(self) -> libc::c_int {
        match self {
            Self::Shared => libc::LOCK_SH,
            Self::Exclusive => libc::LOCK_EX,
        }
    }
}

/// A held advisory filesystem lock.
#[derive(Debug)]
pub struct AdvisoryFileLock {
    file: fs::File,
    path: PathBuf,
    mode: AdvisoryFileLockMode,
}

impl AdvisoryFileLock {
    /// Acquires `mode` on `path`, blocking until the lock is available.
    ///
    /// The lock file and its parent directories are created when missing.
    ///
    /// # Errors
    ///
    /// Returns [`AdvisoryFileLockError`] if a parent directory cannot be
    /// created, the lock file cannot be opened, or the platform lock operation
    /// fails.
    pub fn lock(
        path: impl Into<PathBuf>,
        mode: AdvisoryFileLockMode,
    ) -> Result<Self, AdvisoryFileLockError> {
        Self::acquire(path.into(), mode, false)
    }

    /// Attempts to acquire `mode` on `path` without blocking.
    ///
    /// The lock file and its parent directories are created when missing.
    ///
    /// # Errors
    ///
    /// Returns [`AdvisoryFileLockError`] if a parent directory cannot be
    /// created, the lock file cannot be opened, the lock is currently held by
    /// an incompatible lock, or the platform lock operation fails.
    pub fn try_lock(
        path: impl Into<PathBuf>,
        mode: AdvisoryFileLockMode,
    ) -> Result<Self, AdvisoryFileLockError> {
        Self::acquire(path.into(), mode, true)
    }

    /// Returns the lock file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the held lock mode.
    pub const fn mode(&self) -> AdvisoryFileLockMode {
        self.mode
    }

    fn acquire(
        path: PathBuf,
        mode: AdvisoryFileLockMode,
        nonblocking: bool,
    ) -> Result<Self, AdvisoryFileLockError> {
        ensure_lock_parent(&path)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| AdvisoryFileLockError::Open {
                path: path.clone(),
                source,
            })?;
        lock_file(&file, &path, mode, nonblocking)?;
        Ok(Self { file, path, mode })
    }
}

impl Drop for AdvisoryFileLock {
    fn drop(&mut self) {
        let result = unsafe {
            // SAFETY: `self.file` owns a live file descriptor for the lifetime
            // of this lock guard. Unlocking in Drop releases the advisory lock
            // and does not invalidate Rust references.
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN)
        };
        debug_assert_eq!(result, 0);
    }
}

/// An advisory lock operation failed.
#[derive(Debug, Error)]
pub enum AdvisoryFileLockError {
    /// A parent directory for the lock file could not be created.
    #[error("failed to create advisory lock parent directory {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// The lock file could not be opened.
    #[error("failed to open advisory lock file {path:?}")]
    Open {
        /// The lock file path.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// The advisory lock operation failed.
    #[error("failed to acquire {mode:?} advisory lock on {path:?}")]
    Lock {
        /// The lock file path.
        path: PathBuf,
        /// The requested lock mode.
        mode: AdvisoryFileLockMode,
        /// The underlying platform error.
        #[source]
        source: io::Error,
    },
}

fn ensure_lock_parent(path: &Path) -> Result<(), AdvisoryFileLockError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| AdvisoryFileLockError::CreateParent {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn lock_file(
    file: &fs::File,
    path: &Path,
    mode: AdvisoryFileLockMode,
    nonblocking: bool,
) -> Result<(), AdvisoryFileLockError> {
    let mut operation = mode.operation();
    if nonblocking {
        operation |= libc::LOCK_NB;
    }
    loop {
        let result = unsafe {
            // SAFETY: `file` owns a live file descriptor for this call, and
            // `flock` does not outlive or alias Rust references. The returned
            // lock is advisory and attached to this opened descriptor.
            libc::flock(file.as_raw_fd(), operation)
        };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(AdvisoryFileLockError::Lock {
            path: path.to_path_buf(),
            mode,
            source,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> PathBuf {
        let nonce = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ratchet-cache-file-lock-{name}-{}-{nonce}.lock",
            std::process::id()
        ))
    }

    fn assert_would_block(error: AdvisoryFileLockError) {
        assert!(matches!(
            error,
            AdvisoryFileLockError::Lock { source, .. }
                if source.kind() == ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn advisory_file_lock_creates_parent_and_lock_file() {
        let path = temp_path("creates-parent").join("nested").join("root.lock");

        let lock = AdvisoryFileLock::lock(&path, AdvisoryFileLockMode::Exclusive)
            .expect("exclusive lock acquires");

        assert_eq!(lock.path(), path.as_path());
        assert_eq!(lock.mode(), AdvisoryFileLockMode::Exclusive);
        assert!(path.is_file());

        drop(lock);
        let _ = fs::remove_dir_all(path.parent().and_then(Path::parent).expect("root parent"));
    }

    #[test]
    fn advisory_file_lock_exclusive_blocks_second_exclusive_try_lock() {
        let path = temp_path("exclusive-blocks-exclusive");
        let first = AdvisoryFileLock::lock(&path, AdvisoryFileLockMode::Exclusive)
            .expect("first exclusive lock acquires");

        let error = AdvisoryFileLock::try_lock(&path, AdvisoryFileLockMode::Exclusive)
            .expect_err("second exclusive lock is blocked");

        assert_would_block(error);
        drop(first);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn advisory_file_lock_shared_allows_second_shared_try_lock() {
        let path = temp_path("shared-allows-shared");
        let first = AdvisoryFileLock::lock(&path, AdvisoryFileLockMode::Shared)
            .expect("first shared lock acquires");

        let second = AdvisoryFileLock::try_lock(&path, AdvisoryFileLockMode::Shared)
            .expect("second shared lock acquires");

        assert_eq!(second.mode(), AdvisoryFileLockMode::Shared);
        drop(second);
        drop(first);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn advisory_file_lock_shared_blocks_exclusive_try_lock() {
        let path = temp_path("shared-blocks-exclusive");
        let shared = AdvisoryFileLock::lock(&path, AdvisoryFileLockMode::Shared)
            .expect("shared lock acquires");

        let error = AdvisoryFileLock::try_lock(&path, AdvisoryFileLockMode::Exclusive)
            .expect_err("exclusive lock is blocked");

        assert_would_block(error);
        drop(shared);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn advisory_file_lock_releases_on_drop() {
        let path = temp_path("drop-releases");
        let first = AdvisoryFileLock::lock(&path, AdvisoryFileLockMode::Exclusive)
            .expect("first exclusive lock acquires");
        drop(first);

        let second = AdvisoryFileLock::try_lock(&path, AdvisoryFileLockMode::Exclusive)
            .expect("second exclusive lock acquires after drop");

        drop(second);
        let _ = fs::remove_file(path);
    }
}
