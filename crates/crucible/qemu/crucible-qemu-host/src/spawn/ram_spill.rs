//! Anonymous disk-backed preservation files for managed guest RAM.
//!
//! Files are created relative to the already-pinned run directory. They have no
//! pathname to reopen or replace, and their descriptor crosses the exec boundary
//! separately from immutable checkpoint sources. Allocation and preservation run
//! inside the contained QEMU process under its original setup supervision.

use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use rustix::fs::{FileType, Mode, OFlags, fstat, fstatfs, openat};

use super::{QemuSpawnError, duplicate_cloexec_fd};

impl super::QemuPreparedRunDirectory {
    pub(crate) fn create_hot_fork_ram_spill(
        &self,
        quota_bytes: u64,
    ) -> Result<OwnedFd, QemuSpawnError> {
        create_private_spill(&self.directory, quota_bytes)
    }
}

/// Creates a fresh unlinked file without allocating the admitted disk capacity.
///
/// # Errors
///
/// Refuses invalid quotas, known memory filesystems, and unavailable anonymous
/// file support, or propagates descriptor creation and inspection failures.
pub(super) fn create_private_spill(
    directory: impl AsFd,
    quota_bytes: u64,
) -> Result<OwnedFd, QemuSpawnError> {
    if quota_bytes < 4096 || quota_bytes > i64::MAX as u64 {
        return Err(QemuSpawnError::InvalidRamSpillQuota { bytes: quota_bytes });
    }
    require_disk_filesystem(&directory)?;

    let file = openat(
        &directory,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|source| QemuSpawnError::Io {
        operation: "create private RAM spill file",
        source: source.into(),
    })?;
    require_disk_filesystem(&file)?;
    let metadata = fstat(&file).map_err(|source| QemuSpawnError::Io {
        operation: "validate private RAM spill file",
        source: source.into(),
    })?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 0
        || metadata.st_size != 0
    {
        return Err(QemuSpawnError::Io {
            operation: "validate private RAM spill file",
            source: std::io::Error::other("spill file is not fresh and anonymous"),
        });
    }

    // Relocation must precede exec-time dup2 of every fixed protocol descriptor.
    // Otherwise a low source descriptor could be overwritten by an earlier dup.
    let relocated = duplicate_cloexec_fd(file.as_raw_fd(), "relocate private RAM spill fd")?;
    Ok(relocated)
}

fn require_disk_filesystem(file: impl AsFd) -> Result<(), QemuSpawnError> {
    let filesystem = fstatfs(file).map_err(|source| QemuSpawnError::Io {
        operation: "inspect RAM spill filesystem",
        source: source.into(),
    })?;
    // tmpfs, ramfs and hugetlbfs cannot satisfy disk preservation admission.
    let filesystem_type = filesystem.f_type as i64;
    if matches!(filesystem_type, 0x0102_1994 | 0x8584_58f6 | 0x9584_58f6) {
        return Err(QemuSpawnError::RamSpillMemoryFilesystem { filesystem_type });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    use super::*;

    #[test]
    fn memory_backed_descriptors_cannot_supply_disk_preservation() {
        let memory = crate::spawn::memfd_region(4096)
            .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"));
        assert!(matches!(
            require_disk_filesystem(&memory),
            Err(QemuSpawnError::RamSpillMemoryFilesystem { .. })
        ));
    }

    #[test]
    fn private_files_have_independent_contents_and_no_reopenable_names() {
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"));
        let pinned = File::open(directory.path())
            .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"));
        let first = File::from(
            create_private_spill(&pinned, 8192)
                .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}")),
        );
        let second = File::from(
            create_private_spill(&pinned, 8192)
                .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}")),
        );

        first
            .write_all_at(b"private parent", 0)
            .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"));
        second
            .write_all_at(b"private child", 0)
            .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"));
        let mut actual = [0_u8; 14];
        first
            .read_exact_at(&mut actual, 0)
            .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"));

        assert_eq!(&actual, b"private parent");
        assert!(first.as_raw_fd() >= crate::spawn::CHILD_SOURCE_FD_MIN);
        assert!(second.as_raw_fd() >= crate::spawn::CHILD_SOURCE_FD_MIN);
        assert_eq!(
            fstat(&first)
                .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"))
                .st_nlink,
            0
        );
        assert_eq!(
            fstat(&second)
                .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"))
                .st_nlink,
            0
        );
        assert_ne!(
            fstat(&first)
                .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"))
                .st_ino,
            fstat(&second)
                .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"))
                .st_ino
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"))
                .count(),
            0
        );
    }

    #[test]
    fn backing_quota_is_validated_before_file_creation() {
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"));
        let pinned = File::open(directory.path())
            .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"));

        for bytes in [0, 4095, u64::MAX] {
            assert!(matches!(
                create_private_spill(&pinned, bytes),
                Err(QemuSpawnError::InvalidRamSpillQuota { .. })
            ));
        }
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap_or_else(|error| panic!("spill fixture failed: {error:?}"))
                .count(),
            0
        );
    }
}
