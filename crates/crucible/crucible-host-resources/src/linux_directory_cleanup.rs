//! Bounded descriptor-relative removal of private directory contents.
//!
//! This leaf performs cleanup through an owned descriptor and authenticates
//! directory ancestry before removal. It neither admits a process nor proves
//! reap, releases a quota, recycles an identifier, or deletes the retained root.
//! The supervising owner must stop writers and retain its original directory,
//! quota and process authorities across partial failure and retry.

use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawDir, fstat, fsync, openat, statat, unlinkat};

#[path = "linux_directory_cleanup/error.rs"]
mod error;

pub use error::{
    LinuxDirectoryCleanupBoundReason, LinuxDirectoryCleanupError, LinuxDirectoryCleanupOperation,
};

const DIRECTORY_SCAN_BUFFER_BYTES: usize = 4096;

/// Owns a descriptor used to remove a stopped private directory's contents.
///
/// The diagnostic path is never opened as authority. The descriptor should be
/// a duplicate of the supervising owner's retained directory; completing or
/// dropping this value does not attest that any process has been reaped or
/// that the surrounding resource ownership may be released.
#[derive(Debug)]
pub struct LinuxDirectoryCleanup<'a> {
    directory: OwnedFd,
    diagnostic_path: &'a Path,
}

impl<'a> LinuxDirectoryCleanup<'a> {
    /// Takes an existing owned descriptor and a path used only in diagnostics.
    ///
    /// This records no admission or release claim and performs no I/O. The
    /// cleanup operation itself validates the descriptor through filesystem
    /// operations; callers cannot supply raw descriptor numbers or callbacks.
    #[must_use]
    pub const fn new(directory: OwnedFd, diagnostic_path: &'a Path) -> Self {
        Self {
            directory,
            diagnostic_path,
        }
    }

    /// Removes contents within the caller's admitted cumulative entry bound.
    ///
    /// The bound counts the root and each encountered entry. Traversal is
    /// iterative and keeps a bounded number of directory descriptors open;
    /// retained names and traversal frames remain bounded by encountered
    /// entries. Symlinks are unlinked rather than followed. This preserves the
    /// existing cleanup semantics: the root is counted initially, while the
    /// bound is checked before processing each non-dot child entry. A root
    /// with no children therefore completes without consulting the bound.
    ///
    /// The caller must exclude writers and retain the original root/quota
    /// authorities. This consumes only the supplied cleanup descriptor, leaves
    /// the root itself in place, and makes no process-reap or quota-release
    /// assertion. Partial removals are not rolled back.
    ///
    /// # Errors
    ///
    /// Returns a typed bound, directory-identity, or filesystem error. Directory
    /// replacement, a different filesystem, excessive entries, or failed
    /// descriptor-relative I/O refuse completion. A caller may retry through
    /// its original retained root; an error does not release that authority.
    pub fn clear_contents(self, maximum_entries: u64) -> Result<(), LinuxDirectoryCleanupError> {
        let Self {
            directory,
            diagnostic_path,
        } = self;
        cleanup_directory_contents(directory, diagnostic_path, maximum_entries)
    }
}

#[derive(Debug)]
struct CleanupDirectory {
    name_in_parent: Option<CString>,
    device: u64,
    inode: u64,
    children: Vec<CString>,
}

fn cleanup_directory_contents(
    mut directory: OwnedFd,
    path: &Path,
    maximum_inodes: u64,
) -> Result<(), LinuxDirectoryCleanupError> {
    let root_metadata = fstat(&directory)
        .map_err(|source| io_error(LinuxDirectoryCleanupOperation::IdentifyRoot, path, source))?;
    let root_device = root_metadata.st_dev;
    let mut observed_entries = 1_u64;
    let mut stack = vec![scan_cleanup_directory(
        &directory,
        None,
        path,
        root_device,
        maximum_inodes,
        &mut observed_entries,
    )?];

    loop {
        let Some(frame) = stack.last_mut() else {
            return Err(LinuxDirectoryCleanupError::Bound {
                path: path.to_owned(),
                reason: LinuxDirectoryCleanupBoundReason::RootFrameMissing,
            });
        };
        if let Some(child_name) = frame.children.pop() {
            let child = openat(
                &directory,
                child_name.as_c_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|source| {
                io_error(
                    LinuxDirectoryCleanupOperation::OpenNestedDirectory,
                    path,
                    source,
                )
            })?;
            let child_frame = scan_cleanup_directory(
                &child,
                Some(child_name),
                path,
                root_device,
                maximum_inodes,
                &mut observed_entries,
            )?;
            directory = child;
            stack.push(child_frame);
            continue;
        }

        fsync(&directory).map_err(|source| {
            io_error(
                LinuxDirectoryCleanupOperation::SynchronizeDirectory,
                path,
                source,
            )
        })?;
        if stack.len() == 1 {
            return Ok(());
        }
        let child = stack
            .pop()
            .ok_or_else(|| LinuxDirectoryCleanupError::Bound {
                path: path.to_owned(),
                reason: LinuxDirectoryCleanupBoundReason::ChildFrameMissing,
            })?;
        let child_name =
            child
                .name_in_parent
                .as_ref()
                .ok_or_else(|| LinuxDirectoryCleanupError::Bound {
                    path: path.to_owned(),
                    reason: LinuxDirectoryCleanupBoundReason::ParentNameMissing,
                })?;
        let parent = openat(
            &directory,
            "..",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| {
            io_error(
                LinuxDirectoryCleanupOperation::ReopenParentDirectory,
                path,
                source,
            )
        })?;
        let parent_frame = stack
            .last()
            .ok_or_else(|| LinuxDirectoryCleanupError::Bound {
                path: path.to_owned(),
                reason: LinuxDirectoryCleanupBoundReason::ParentFrameMissing,
            })?;
        verify_cleanup_directory_identity(&parent, parent_frame.device, parent_frame.inode, path)?;
        verify_cleanup_child_identity(&parent, child_name, &directory, path)?;
        unlinkat(&parent, child_name.as_c_str(), AtFlags::REMOVEDIR).map_err(|source| {
            io_error(
                LinuxDirectoryCleanupOperation::RemoveNestedDirectory,
                path,
                source,
            )
        })?;
        directory = parent;
    }
}

fn scan_cleanup_directory(
    directory: &OwnedFd,
    name_in_parent: Option<CString>,
    path: &Path,
    root_device: u64,
    maximum_inodes: u64,
    observed_entries: &mut u64,
) -> Result<CleanupDirectory, LinuxDirectoryCleanupError> {
    let directory_metadata = fstat(directory).map_err(|source| {
        io_error(
            LinuxDirectoryCleanupOperation::IdentifyDirectory,
            path,
            source,
        )
    })?;
    if directory_metadata.st_dev != root_device {
        return Err(LinuxDirectoryCleanupError::DirectoryIdentity {
            path: path.to_owned(),
        });
    }
    let scan = openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        io_error(
            LinuxDirectoryCleanupOperation::OpenDirectoryScan,
            path,
            source,
        )
    })?;
    let mut buffer = [MaybeUninit::uninit(); DIRECTORY_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(scan, &mut buffer);
    let mut children = Vec::new();
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|source| {
            io_error(
                LinuxDirectoryCleanupOperation::ReadDirectoryEntry,
                path,
                source,
            )
        })?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *observed_entries =
            observed_entries
                .checked_add(1)
                .ok_or_else(|| LinuxDirectoryCleanupError::Bound {
                    path: path.to_owned(),
                    reason: LinuxDirectoryCleanupBoundReason::EntryCountOverflow,
                })?;
        if *observed_entries > maximum_inodes {
            return Err(LinuxDirectoryCleanupError::Bound {
                path: path.to_owned(),
                reason: LinuxDirectoryCleanupBoundReason::EntryLimitExceeded,
            });
        }
        let metadata = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
            io_error(LinuxDirectoryCleanupOperation::InspectEntry, path, source)
        })?;
        if metadata.st_dev != root_device {
            return Err(LinuxDirectoryCleanupError::DirectoryIdentity {
                path: path.to_owned(),
            });
        }
        if FileType::from_raw_mode(metadata.st_mode) == FileType::Directory {
            children
                .try_reserve(1)
                .map_err(|_| LinuxDirectoryCleanupError::Bound {
                    path: path.to_owned(),
                    reason: LinuxDirectoryCleanupBoundReason::ChildNameReservationFailed,
                })?;
            children.push(name.to_owned());
        } else {
            unlinkat(directory, name, AtFlags::empty()).map_err(|source| {
                io_error(LinuxDirectoryCleanupOperation::RemoveEntry, path, source)
            })?;
        }
    }
    children.sort();
    Ok(CleanupDirectory {
        name_in_parent,
        device: directory_metadata.st_dev,
        inode: directory_metadata.st_ino,
        children,
    })
}

fn verify_cleanup_directory_identity(
    directory: &OwnedFd,
    expected_device: u64,
    expected_inode: u64,
    path: &Path,
) -> Result<(), LinuxDirectoryCleanupError> {
    let actual = fstat(directory).map_err(|source| {
        io_error(
            LinuxDirectoryCleanupOperation::ReauthenticateDirectory,
            path,
            source,
        )
    })?;
    if actual.st_dev != expected_device || actual.st_ino != expected_inode {
        return Err(LinuxDirectoryCleanupError::DirectoryIdentity {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn verify_cleanup_child_identity(
    parent: &OwnedFd,
    name: &CString,
    child: &OwnedFd,
    path: &Path,
) -> Result<(), LinuxDirectoryCleanupError> {
    let named = openat(
        parent,
        name.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        io_error(
            LinuxDirectoryCleanupOperation::ReauthenticateChildDirectory,
            path,
            source,
        )
    })?;
    let expected = fstat(child).map_err(|source| {
        io_error(
            LinuxDirectoryCleanupOperation::IdentifyRetainedDirectory,
            path,
            source,
        )
    })?;
    let actual = fstat(&named).map_err(|source| {
        io_error(
            LinuxDirectoryCleanupOperation::IdentifyNamedDirectory,
            path,
            source,
        )
    })?;
    if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
        return Err(LinuxDirectoryCleanupError::DirectoryIdentity {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn io_error(
    operation: LinuxDirectoryCleanupOperation,
    path: &Path,
    source: rustix::io::Errno,
) -> LinuxDirectoryCleanupError {
    LinuxDirectoryCleanupError::Io {
        operation,
        path: path.to_owned(),
        source: source.into(),
    }
}

#[cfg(test)]
#[path = "linux_directory_cleanup/tests.rs"]
mod tests;
