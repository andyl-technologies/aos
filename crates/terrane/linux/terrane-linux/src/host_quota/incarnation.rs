//! Binds native inode numbers to original descriptor-observed creation times.
//!
//! Birth times distinguish reused inode numbers without depending on mutable
//! paths, permissions or contents. Equal timestamps remain conservatively
//! excluded; privileged filesystem timestamp setters are outside the same
//! administrative boundary as project reassignment.

use super::ProjectInode;
use rustix::fs::{AtFlags, StatxFlags, major, minor, statx};
use std::{fs::File, io, os::unix::fs::MetadataExt};

/// Records a kernel inode creation timestamp, independently of presented times.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProjectInodeBirth {
    /// Signed seconds since the Unix epoch.
    pub seconds: i64,
    /// Fractional nanoseconds, strictly below one billion.
    pub nanoseconds: u32,
}

/// Binds an original native inode to optional, durably recorded creation time.
///
/// Missing creation time preserves the conservative legacy exclusion of every
/// allocation with the same device and inode number. It never permits rebinding
/// an older policy record from a currently visible replacement.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProjectInodeBinding {
    /// Original native device and inode number.
    pub identity: ProjectInode,
    /// Original creation timestamp, absent only for legacy observations.
    pub birth: Option<ProjectInodeBirth>,
}

impl ProjectInodeBirth {
    /// Observes creation time from a retained original descriptor.
    ///
    /// # Errors
    /// Refuses unsupported birth timestamps, invalid nanoseconds, mismatched
    /// native identities and descriptor inspection failures.
    pub fn observe(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        let required = StatxFlags::BTIME | StatxFlags::INO;
        let actual = statx(file, "", AtFlags::EMPTY_PATH, required)?;
        if actual.stx_mask & required.bits() != required.bits()
            || actual.stx_ino != metadata.ino()
            || actual.stx_dev_major != major(metadata.dev())
            || actual.stx_dev_minor != minor(metadata.dev())
            || actual.stx_btime.tv_nsec >= 1_000_000_000
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original inode lacks a valid native birth timestamp",
            ));
        }
        Ok(Self {
            seconds: actual.stx_btime.tv_sec,
            nanoseconds: actual.stx_btime.tv_nsec,
        })
    }
}
