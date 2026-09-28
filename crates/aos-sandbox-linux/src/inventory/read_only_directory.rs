//! Original-descriptor facts for an attached or detached read-only directory.
//!
//! These observations contain no namespace, topology, backend, or admission
//! authority. A detached mount need not appear in a namespace's mount tree.

use std::os::fd::BorrowedFd;

use rustix::fs::{FileType, OFlags, StatVfsMountFlags};
use rustix::io::FdFlags;

use super::MountId;
use crate::boot::KernelBootId;
use crate::{Error, Result};

/// Records nonauthorizing facts sampled from one original directory descriptor.
///
/// Callers must retain the descriptor and repeat observation around their own
/// authenticated owner joins. Read-only status is not immutability or topology
/// proof, and these data do not establish namespace membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyDirectorySnapshot {
    /// Identifies the kernel sampled before and after descriptor inspection.
    pub boot_id: [u8; 16],
    /// Records the actual open-file-description status, including `O_PATH`.
    pub status_flags: OFlags,
    /// Records the actual descriptor flags, including `FD_CLOEXEC`.
    pub descriptor_flags: FdFlags,
    /// Records the directory's kernel device number.
    pub device: u64,
    /// Records the directory's kernel inode number.
    pub inode: u64,
    /// Records the directory's complete kernel mode.
    pub mode: u32,
    /// Records the kernel-lifetime unique mount ID from `statx` on this FD.
    pub mount_id: MountId,
    /// Records `fstatvfs` flags; these are not `MOUNT_ATTR_*` values.
    pub mount_flags: StatVfsMountFlags,
}

impl ReadOnlyDirectorySnapshot {
    /// Samples strict directory facts without a namespace lookup or path reopen.
    ///
    /// # Errors
    ///
    /// Rejects inspection failures, changed boot, non-`O_PATH` or non-`CLOEXEC`
    /// descriptors, nondirectories, zero device/inode, missing unique mount ID,
    /// and mounts not read-only according to the original FD's `fstatvfs`.
    pub fn capture(descriptor: BorrowedFd<'_>) -> Result<Self> {
        let boot = KernelBootId::current()?;
        let status_flags = rustix::fs::fcntl_getfl(descriptor)
            .map_err(|source| syscall("SourceRoot fcntl_getfl", source))?;
        let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
            .map_err(|source| syscall("SourceRoot fcntl_getfd", source))?;
        let stat =
            rustix::fs::fstat(descriptor).map_err(|source| syscall("SourceRoot fstat", source))?;
        let mount_id = MountId::from_fd(descriptor)?;
        let mount = rustix::fs::fstatvfs(descriptor)
            .map_err(|source| syscall("SourceRoot fstatvfs", source))?;
        let observed = Self {
            boot_id: boot.into_bytes(),
            status_flags,
            descriptor_flags,
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            mount_id,
            mount_flags: mount.f_flag,
        };
        observed.require_shape()?;
        if KernelBootId::current()? != boot {
            return Err(Error::invalid("directory snapshot", "kernel boot changed"));
        }
        Ok(observed)
    }

    fn require_shape(&self) -> Result<()> {
        if !self.status_flags.contains(OFlags::PATH)
            || !self.descriptor_flags.contains(FdFlags::CLOEXEC)
            || FileType::from_raw_mode(self.mode) != FileType::Directory
            || self.device == 0
            || self.inode == 0
            || !self.mount_flags.contains(StatVfsMountFlags::RDONLY)
        {
            return Err(Error::invalid(
                "directory snapshot",
                "invalid read-only O_PATH directory",
            ));
        }
        Ok(())
    }
}

fn syscall(operation: &'static str, source: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;

    use super::*;

    #[test]
    fn writable_directory_is_not_a_read_only_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let fd = rustix::fs::open(
            directory.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        assert!(matches!(
            ReadOnlyDirectorySnapshot::capture(fd.as_fd()),
            Err(Error::InvalidInput { .. })
        ));
    }

    #[test]
    fn every_required_descriptor_fact_is_checked() {
        // DATA-only shape checks do not claim a kernel-observed positive root.
        let valid = ReadOnlyDirectorySnapshot {
            boot_id: [1; 16],
            status_flags: OFlags::PATH,
            descriptor_flags: FdFlags::CLOEXEC,
            device: 2,
            inode: 3,
            mode: FileType::Directory.as_raw_mode(),
            mount_id: MountId::new(4).unwrap(),
            mount_flags: StatVfsMountFlags::RDONLY,
        };
        assert!(valid.require_shape().is_ok());
        for field in 0..6 {
            let mut invalid = valid.clone();
            match field {
                0 => invalid.status_flags = OFlags::empty(),
                1 => invalid.descriptor_flags = FdFlags::empty(),
                2 => invalid.mode = FileType::RegularFile.as_raw_mode(),
                3 => invalid.device = 0,
                4 => invalid.inode = 0,
                _ => invalid.mount_flags = StatVfsMountFlags::empty(),
            }
            assert!(invalid.require_shape().is_err(), "field {field}");
        }
    }
}
