//! Observes real retirement-barrier descriptors without supplying acknowledgment.

use std::path::PathBuf;

/// Distinguishes captured originals from successfully synchronized descriptors.
///
/// These test observations carry no result channel or publication authority.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RetirementSyncEvent {
    /// Reports one actual opened and checked metadata file.
    FileCaptured {
        /// Names the original file.
        path: PathBuf,
        /// Identifies the original descriptor within this worker.
        descriptor: std::os::fd::RawFd,
        /// Records the actual device and inode.
        identity: (u64, u64),
    },
    /// Reports successful synchronization and adjacent checks of that file.
    FileSynced {
        /// Names the synchronized file.
        path: PathBuf,
        /// Identifies the descriptor actually synchronized.
        descriptor: std::os::fd::RawFd,
        /// Records the actual device and inode.
        identity: (u64, u64),
    },
    /// Reports one freshly checked occurrence of a scoped original directory.
    DirectoryCaptured {
        /// Names the original directory.
        path: PathBuf,
        /// Names its actual retained namespace or control boundary.
        root: PathBuf,
        /// Identifies the independently configured owner.
        owner: u32,
        /// Distinguishes protected-control and ordinary namespace policies.
        control: bool,
        /// Identifies the retained original descriptor.
        descriptor: std::os::fd::RawFd,
        /// Records the actual device and inode.
        identity: (u64, u64),
    },
    /// Reports successful synchronization and adjacent checks of a scoped directory.
    DirectorySynced {
        /// Names the synchronized directory.
        path: PathBuf,
        /// Names its actual retained namespace or control boundary.
        root: PathBuf,
        /// Identifies the independently configured owner.
        owner: u32,
        /// Distinguishes protected-control and ordinary namespace policies.
        control: bool,
        /// Identifies the original descriptor actually synchronized.
        descriptor: std::os::fd::RawFd,
        /// Records the actual device and inode.
        identity: (u64, u64),
    },
}
