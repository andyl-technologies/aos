//! Concrete filesystem failures from bounded private-directory cleanup.

use std::fmt;
use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Identifies the exact descriptor-relative operation that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxDirectoryCleanupOperation {
    /// Identify cleanup root.
    IdentifyRoot,
    /// Open nested artifact directory.
    OpenNestedDirectory,
    /// Synchronize cleaned artifact directory.
    SynchronizeDirectory,
    /// Reopen artifact parent directory.
    ReopenParentDirectory,
    /// Remove nested artifact directory.
    RemoveNestedDirectory,
    /// Identify artifact directory.
    IdentifyDirectory,
    /// Open artifact directory for cleanup.
    OpenDirectoryScan,
    /// Scan artifact directory.
    ReadDirectoryEntry,
    /// Inspect attempt artifact.
    InspectEntry,
    /// Remove attempt artifact.
    RemoveEntry,
    /// Reauthenticate artifact directory.
    ReauthenticateDirectory,
    /// Reauthenticate nested artifact directory.
    ReauthenticateChildDirectory,
    /// Identify retained artifact directory.
    IdentifyRetainedDirectory,
    /// Identify named artifact directory.
    IdentifyNamedDirectory,
}

impl fmt::Display for LinuxDirectoryCleanupOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentifyRoot => "identify cleanup root",
            Self::OpenNestedDirectory => "open nested artifact directory",
            Self::SynchronizeDirectory => "synchronize cleaned artifact directory",
            Self::ReopenParentDirectory => "reopen artifact parent directory",
            Self::RemoveNestedDirectory => "remove nested artifact directory",
            Self::IdentifyDirectory => "identify artifact directory",
            Self::OpenDirectoryScan => "open artifact directory for cleanup",
            Self::ReadDirectoryEntry => "scan artifact directory",
            Self::InspectEntry => "inspect attempt artifact",
            Self::RemoveEntry => "remove attempt artifact",
            Self::ReauthenticateDirectory => "reauthenticate artifact directory",
            Self::ReauthenticateChildDirectory => "reauthenticate nested artifact directory",
            Self::IdentifyRetainedDirectory => "identify retained artifact directory",
            Self::IdentifyNamedDirectory => "identify named artifact directory",
        })
    }
}

/// Identifies a closed structural failure in bounded directory cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxDirectoryCleanupBoundReason {
    /// The iterative traversal lost its root frame.
    RootFrameMissing,
    /// The iterative traversal lost a nested child frame.
    ChildFrameMissing,
    /// A nested directory frame omitted its retained parent name.
    ParentNameMissing,
    /// A nested directory frame omitted its parent frame.
    ParentFrameMissing,
    /// The cumulative artifact entry counter overflowed.
    EntryCountOverflow,
    /// The cumulative artifact entries exceeded the caller's ceiling.
    EntryLimitExceeded,
    /// The bounded child-name bank could not reserve another entry.
    ChildNameReservationFailed,
}

impl LinuxDirectoryCleanupBoundReason {
    /// Returns the exact existing structural diagnostic for this failure.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootFrameMissing => "artifact-cleanup traversal lost its root frame",
            Self::ChildFrameMissing => "artifact-cleanup traversal lost a child frame",
            Self::ParentNameMissing => "nested artifact directory omitted its parent name",
            Self::ParentFrameMissing => "nested artifact directory omitted its parent frame",
            Self::EntryCountOverflow => "attempt artifact entry count overflowed",
            Self::EntryLimitExceeded => "attempt artifacts exceed the cleanup-entry ceiling",
            Self::ChildNameReservationFailed => {
                "attempt artifact cleanup cannot retain bounded child names"
            }
        }
    }
}

impl fmt::Display for LinuxDirectoryCleanupBoundReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Reports a cleanup failure without claiming release of its supervising owner.
#[derive(Debug, Error)]
pub enum LinuxDirectoryCleanupError {
    /// A retained directory, named child, or filesystem identity did not match.
    #[error("directory identity changed during cleanup: {path}")]
    DirectoryIdentity {
        /// Caller-supplied diagnostic path, never opened by cleanup.
        path: PathBuf,
    },
    /// An entry bound or traversal invariant prevented completion.
    #[error("directory cleanup failed for {path}: {reason}")]
    Bound {
        /// Caller-supplied diagnostic path, never opened by cleanup.
        path: PathBuf,
        /// Closed structural failure whose display preserves the original diagnostic.
        reason: LinuxDirectoryCleanupBoundReason,
    },
    /// One filesystem operation failed, retaining its original operating-system error.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// Exact operation category for an outer compatibility adapter.
        operation: LinuxDirectoryCleanupOperation,
        /// Caller-supplied diagnostic path, never opened by cleanup.
        path: PathBuf,
        /// Original filesystem error, without string conversion or replacement.
        #[source]
        source: io::Error,
    },
}
