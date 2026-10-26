//! Preserves closed descriptor and watcher-admission failures without custody.
//!
//! Fixed operation labels identify the actual syscall or dispatcher boundary.
//! General cgroup callers recover their original error variant by moving the
//! same path and I/O payload; these observations issue no process authority.

use super::{LinuxQemuCgroupError, duplicate_descriptor};
use rustix::fs::{Mode, OFlags, fstat, openat};
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

/// Identifies a closed operation whose diagnostic label has static storage.
#[derive(Clone, Copy, Debug)]
pub(super) enum ControlCheckOperation {
    PinDirectory,
    IdentifyPinnedDirectory,
    IdentifyNamedDirectory,
    RetainTargetCancellation,
    MaintainTargetDispatcher,
}

impl ControlCheckOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::PinDirectory => "pin QEMU attempt cgroup directory",
            Self::IdentifyPinnedDirectory => "identify pinned QEMU attempt cgroup",
            Self::IdentifyNamedDirectory => "identify named QEMU attempt cgroup",
            Self::RetainTargetCancellation => "retain pooled Target cancellation",
            Self::MaintainTargetDispatcher => "maintain actual Target dispatcher",
        }
    }
}

#[derive(Debug)]
enum ControlCheckCause {
    Io {
        operation: ControlCheckOperation,
        source: io::Error,
    },
    DirectoryIdentity,
    WatcherAlreadyStarted,
}

/// Retains only the failures emitted by descriptor checks and Target admission.
#[derive(Debug)]
pub(super) struct ControlCheckError {
    path: PathBuf,
    cause: ControlCheckCause,
}

impl ControlCheckError {
    /// Retains the actual syscall payload without rendering or reallocating it.
    pub(super) fn io(operation: ControlCheckOperation, path: PathBuf, source: io::Error) -> Self {
        Self {
            path,
            cause: ControlCheckCause::Io { operation, source },
        }
    }

    /// Retains the same pinned-directory mismatch observation.
    fn directory_identity(path: PathBuf) -> Self {
        Self {
            path,
            cause: ControlCheckCause::DirectoryIdentity,
        }
    }

    /// Retains refusal of the existing one-shot watcher state transition.
    pub(super) fn watcher_already_started(path: PathBuf) -> Self {
        Self {
            path,
            cause: ControlCheckCause::WatcherAlreadyStarted,
        }
    }
}

impl std::fmt::Display for ControlCheckError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.cause {
            ControlCheckCause::Io { operation, source } => write!(
                formatter,
                "{} failed for {}: {source}",
                operation.label(),
                self.path.display(),
            ),
            ControlCheckCause::DirectoryIdentity => write!(
                formatter,
                "QEMU cgroup path no longer names the pinned directory: {}",
                self.path.display(),
            ),
            ControlCheckCause::WatcherAlreadyStarted => write!(
                formatter,
                "QEMU cgroup watcher is already started: {}",
                self.path.display(),
            ),
        }
    }
}

impl std::error::Error for ControlCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            ControlCheckCause::Io { source, .. } => Some(source),
            ControlCheckCause::DirectoryIdentity | ControlCheckCause::WatcherAlreadyStarted => None,
        }
    }
}

impl From<ControlCheckError> for LinuxQemuCgroupError {
    fn from(error: ControlCheckError) -> Self {
        match error.cause {
            ControlCheckCause::Io { operation, source } => Self::Io {
                operation: operation.label(),
                path: error.path,
                source,
            },
            ControlCheckCause::DirectoryIdentity => Self::DirectoryIdentity { path: error.path },
            ControlCheckCause::WatcherAlreadyStarted => {
                Self::WatcherAlreadyStarted { path: error.path }
            }
        }
    }
}

/// Opens the same named directory without following links.
///
/// # Errors
/// Retains the actual open failure and its unchanged diagnostic path.
pub(super) fn open_directory_at(
    parent: &OwnedFd,
    name: &str,
    path: &Path,
) -> Result<OwnedFd, ControlCheckError> {
    openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        ControlCheckError::io(
            ControlCheckOperation::PinDirectory,
            path.to_owned(),
            source.into(),
        )
    })
}

/// Compares the same named and pinned descriptor identities in their original order.
///
/// # Errors
/// Retains open/stat failures or a changed device/inode identity.
pub(super) fn verify_directory_identity(
    parent: &OwnedFd,
    name: &str,
    expected: &OwnedFd,
    path: &Path,
) -> Result<(), ControlCheckError> {
    let named = open_directory_at(parent, name, path)?;
    let expected = fstat(expected).map_err(|source| {
        ControlCheckError::io(
            ControlCheckOperation::IdentifyPinnedDirectory,
            path.to_owned(),
            source.into(),
        )
    })?;
    let actual = fstat(&named).map_err(|source| {
        ControlCheckError::io(
            ControlCheckOperation::IdentifyNamedDirectory,
            path.to_owned(),
            source.into(),
        )
    })?;
    if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
        return Err(ControlCheckError::directory_identity(path.to_owned()));
    }
    Ok(())
}

/// Duplicates the existing Target cancellation descriptor with close-on-exec.
///
/// # Errors
/// Retains the actual descriptor duplication error with its original operation label.
pub(super) fn retain_target_cancellation(
    descriptor: i32,
    path: &Path,
) -> Result<OwnedFd, ControlCheckError> {
    duplicate_descriptor(descriptor).map_err(|source| {
        ControlCheckError::io(
            ControlCheckOperation::RetainTargetCancellation,
            path.to_owned(),
            source,
        )
    })
}

#[cfg(test)]
mod tests;
