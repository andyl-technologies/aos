//! Reports failures from the actual Target dispatcher retirement path.
//!
//! The dispatcher retains physical ownership and first/post history separately.
//! This report preserves its existing path and I/O cause without carrying the
//! unrelated admission variants of the general cgroup error.

use std::io;
use std::path::{Path, PathBuf};

/// Preserves the path and I/O cause of actual Target dispatcher maintenance.
///
/// This diagnostic grants no retry authority and proves no physical return.
#[derive(Debug, thiserror::Error)]
#[error("maintain actual Target dispatcher failed for {path}: {source}", path = path.display())]
pub struct LinuxQemuTargetDispatcherError {
    path: PathBuf,
    #[source]
    source: io::Error,
}

impl LinuxQemuTargetDispatcherError {
    pub(crate) fn new(path: PathBuf, source: io::Error) -> Self {
        Self { path, source }
    }

    /// Borrows the diagnostic path of the retained dispatcher.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Borrows the original dispatcher maintenance I/O error.
    #[must_use]
    pub fn io_error(&self) -> &io::Error {
        &self.source
    }
}

impl From<LinuxQemuTargetDispatcherError> for super::LinuxQemuCgroupError {
    fn from(error: LinuxQemuTargetDispatcherError) -> Self {
        Self::Io {
            operation: "maintain actual Target dispatcher",
            path: error.path,
            source: error.source,
        }
    }
}
