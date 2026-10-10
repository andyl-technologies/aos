//! Bounded descriptor-relative inventory and cooperative namespace exclusion.
//!
//! An exclusive lease is held for the catalog lifetime. The initial inventory
//! authenticates preexisting inodes; trusted subsequent creation inherits the
//! same project. Uncooperative privileged namespace mutations are outside this
//! capability's operator contract and are never prevented by advisory flock.

use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use rustix::fs::{CWD, FileType, FlockOperation, Mode, OFlags, RawDir, ResolveFlags};
use rustix::fs::{flock, fstat, mkdirat, openat2};

use crate::host_supervision::HostOperationGuard;

use super::get_project_attributes;
use super::{DIRECTORY_SCAN_BUFFER_BYTES, FS_XFLAG_PROJINHERIT, LinuxProjectQuotaError};

const MAX_DEPTH: usize = 16;
const LEASE_NAME: &str = ".crucible-physical-quota.lock";
const DESCEND: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_XDEV)
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

#[derive(Debug)]
pub(super) struct NamespaceLease {
    descriptor: OwnedFd,
    device: u64,
    inode: u64,
}

impl NamespaceLease {
    pub(super) fn acquire(
        root: &OwnedFd,
        path: &Path,
        project: u32,
    ) -> Result<Self, LinuxProjectQuotaError> {
        let descriptor = openat2(
            root,
            LEASE_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
            DESCEND,
        )
        .map_err(|error| io_error(path, "open quota namespace lease", error))?;
        if validate_inode(
            &descriptor,
            path,
            project,
            fstat(root)
                .map_err(|error| io_error(path, "inspect quota root", error))?
                .st_dev,
        )? != FileType::RegularFile
        {
            return Err(unsafe_namespace(path));
        }
        flock(&descriptor, FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| io_error(path, "acquire exclusive quota namespace lease", error))?;
        let identity = fstat(&descriptor)
            .map_err(|error| io_error(path, "inspect quota namespace lease", error))?;
        Ok(Self {
            descriptor,
            device: identity.st_dev,
            inode: identity.st_ino,
        })
    }

    pub(super) fn verify(
        &self,
        root: &OwnedFd,
        path: &Path,
        project: u32,
    ) -> Result<(), LinuxProjectQuotaError> {
        let current = openat2(
            root,
            LEASE_NAME,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            DESCEND,
        )
        .map_err(|error| io_error(path, "reopen quota namespace lease", error))?;
        validate_inode(&current, path, project, self.device)?;
        let stat = fstat(&current)
            .map_err(|error| io_error(path, "reauthenticate quota namespace lease", error))?;
        if stat.st_ino != self.inode {
            return Err(unsafe_namespace(path));
        }
        // Repeating LOCK_EX on this same open description retains rather than
        // releases the original lease. Another daemon opens a different one.
        flock(&self.descriptor, FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| io_error(path, "validate retained quota namespace lease", error))?;
        Ok(())
    }
}

pub(super) fn open_root(path: &Path) -> rustix::io::Result<OwnedFd> {
    openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
}

pub(super) fn audit(
    root: &OwnedFd,
    path: &Path,
    project: u32,
    maximum_inodes: u64,
    operation: &HostOperationGuard,
) -> Result<(), LinuxProjectQuotaError> {
    let device = fstat(root)
        .map_err(|error| io_error(path, "inspect quota inventory root", error))?
        .st_dev;
    Inventory {
        path,
        project,
        device,
        maximum: maximum_inodes,
        count: 1,
        operation,
    }
    .directory(root, 0)
}

struct Inventory<'a> {
    path: &'a Path,
    project: u32,
    device: u64,
    maximum: u64,
    count: u64,
    operation: &'a HostOperationGuard,
}

impl Inventory<'_> {
    // Each level retains one input descriptor and one independent scan OFD.
    // Reopening avoids sharing directory offsets with preceding scans.
    fn directory(
        &mut self,
        directory: &OwnedFd,
        depth: usize,
    ) -> Result<(), LinuxProjectQuotaError> {
        self.operation.wait_slice()?;
        let scan = openat2(
            directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            DESCEND,
        )
        .map_err(|error| io_error(self.path, "open quota descendant scan", error))?;
        let mut buffer = [MaybeUninit::uninit(); DIRECTORY_SCAN_BUFFER_BYTES];
        let mut entries = RawDir::new(&scan, &mut buffer);
        while let Some(entry) = entries.next() {
            self.operation.wait_slice()?;
            let entry = entry
                .map_err(|error| io_error(self.path, "read quota descendant inventory", error))?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            if self.count >= self.maximum {
                return Err(unsafe_namespace(self.path));
            }
            self.count += 1;
            if !matches!(
                entry.file_type(),
                FileType::Directory | FileType::RegularFile
            ) {
                return Err(unsafe_namespace(self.path));
            }
            let child = openat2(
                directory,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
                DESCEND,
            )
            .map_err(|error| io_error(self.path, "pin quota descendant", error))?;
            let kind = validate_inode(&child, self.path, self.project, self.device)?;
            if kind == FileType::Directory {
                if depth >= MAX_DEPTH {
                    return Err(unsafe_namespace(self.path));
                }
                self.directory(&child, depth + 1)?;
            }
            self.operation.progress(self.count)?;
        }
        Ok(())
    }
}

fn validate_inode(
    descriptor: &OwnedFd,
    path: &Path,
    project: u32,
    device: u64,
) -> Result<FileType, LinuxProjectQuotaError> {
    let stat =
        fstat(descriptor).map_err(|error| io_error(path, "inspect quota descendant", error))?;
    let kind = FileType::from_raw_mode(stat.st_mode);
    if stat.st_dev != device
        || !matches!(kind, FileType::Directory | FileType::RegularFile)
        || (kind == FileType::RegularFile && stat.st_nlink != 1)
    {
        return Err(unsafe_namespace(path));
    }
    let attributes = get_project_attributes(descriptor, path)?;
    if attributes.fsx_projid != project
        || (kind == FileType::Directory && attributes.fsx_xflags & FS_XFLAG_PROJINHERIT == 0)
    {
        return Err(LinuxProjectQuotaError::AttributeMismatch {
            path: path.to_owned(),
        });
    }
    Ok(kind)
}

pub(super) fn prepare_directory(
    root: &OwnedFd,
    root_path: &Path,
    path: &Path,
    project: u32,
    operation: &HostOperationGuard,
) -> Result<(), LinuxProjectQuotaError> {
    let relative = checked_relative_path(root_path, path)?;
    let device = fstat(root)
        .map_err(|error| io_error(path, "inspect quota creation root", error))?
        .st_dev;
    let mut current = openat2(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        DESCEND,
    )
    .map_err(|error| io_error(path, "pin quota creation root", error))?;
    let mut depth = 0;
    for component in relative.components() {
        operation.wait_slice()?;
        let Component::Normal(name) = component else {
            return Err(unsafe_namespace(path));
        };
        depth += 1;
        if depth > MAX_DEPTH || name.as_bytes().len() > 255 {
            return Err(unsafe_namespace(path));
        }
        match mkdirat(&current, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(io_error(path, "create quota descendant directory", error)),
        }
        let child = openat2(
            &current,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            DESCEND,
        )
        .map_err(|error| io_error(path, "pin created quota directory", error))?;
        if validate_inode(&child, path, project, device)? != FileType::Directory {
            return Err(unsafe_namespace(path));
        }
        current = child;
    }
    Ok(())
}

fn checked_relative_path<'a>(
    root: &Path,
    path: &'a Path,
) -> Result<&'a Path, LinuxProjectQuotaError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| unsafe_namespace(path))?;
    let mut depth = 0;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(unsafe_namespace(path));
        };
        depth += 1;
        if depth > MAX_DEPTH || name.as_bytes().len() > 255 {
            return Err(unsafe_namespace(path));
        }
    }
    Ok(relative)
}

fn unsafe_namespace(path: &Path) -> LinuxProjectQuotaError {
    LinuxProjectQuotaError::UnsafeNamespace {
        path: path.to_owned(),
    }
}

fn io_error(
    path: &Path,
    operation: &'static str,
    source: rustix::io::Errno,
) -> LinuxProjectQuotaError {
    LinuxProjectQuotaError::Io {
        operation,
        path: path.to_owned(),
        source: source.into(),
    }
}

#[cfg(test)]
mod tests {
    //! Real Linux path/lease adversaries; project-quota installation is tested
    //! separately on an operator-enabled ext4 filesystem.

    // crucible-lint: allow panic-shortcut -- These fixture panics report failed test setup or adversarial filesystem assertions, never production quota policy.
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    mod cases {
        use super::super::*;

        #[test]
        fn creation_path_rejects_escape_and_overdeep_chain_before_mutation() {
            let root = Path::new("/quota");
            assert!(checked_relative_path(root, Path::new("/quota/a/../escape")).is_err());
            assert!(checked_relative_path(root, Path::new("/quota-other/a")).is_err());
            let deep = root.join(vec!["a"; MAX_DEPTH + 1].join("/"));
            assert!(checked_relative_path(root, &deep).is_err());
            assert!(checked_relative_path(root, root).is_ok());
            assert!(checked_relative_path(root, Path::new("/quota/a/b")).is_ok());
        }

        #[test]
        fn pinned_descendant_open_refuses_symlink_and_parent_escape() {
            let fixture = tempfile::tempdir().expect("temporary root");
            let outside = tempfile::tempdir().expect("outside directory");
            std::os::unix::fs::symlink(outside.path(), fixture.path().join("alias"))
                .expect("symlink fixture");
            let root = open_root(fixture.path()).expect("pinned root");
            for target in ["alias", "../", "alias/file"] {
                assert!(
                    openat2(
                        &root,
                        target,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                        Mode::empty(),
                        DESCEND
                    )
                    .is_err()
                );
            }
        }

        #[test]
        fn exclusive_lease_uses_open_description_and_rejects_second_owner() {
            let fixture = tempfile::tempdir().expect("temporary root");
            let root = open_root(fixture.path()).expect("pinned root");
            let first = openat2(
                &root,
                LEASE_NAME,
                OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
                DESCEND,
            )
            .expect("first description");
            let second = openat2(
                &root,
                LEASE_NAME,
                OFlags::RDWR | OFlags::CLOEXEC,
                Mode::empty(),
                DESCEND,
            )
            .expect("second description");
            flock(&first, FlockOperation::NonBlockingLockExclusive).expect("exclusive lease");
            flock(&first, FlockOperation::NonBlockingLockExclusive)
                .expect("same owner retains lease");
            assert!(flock(&second, FlockOperation::NonBlockingLockExclusive).is_err());
            drop(first);
            flock(&second, FlockOperation::NonBlockingLockExclusive)
                .expect("physical release allows next owner");
        }
    }
}
