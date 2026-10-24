//! Descriptor-relative filesystem operations for attempt storage.

use super::*;
use crucible_host_resources::{
    LinuxDirectoryCleanup, LinuxDirectoryCleanupError, LinuxDirectoryCleanupOperation,
};

pub(super) fn cleanup_directory_contents(
    directory: OwnedFd,
    path: &Path,
    maximum_inodes: u64,
) -> Result<(), LinuxQemuAttemptStorageError> {
    LinuxDirectoryCleanup::new(directory, path)
        .clear_contents(maximum_inodes)
        .map_err(map_directory_cleanup_error)
}

fn map_directory_cleanup_error(error: LinuxDirectoryCleanupError) -> LinuxQemuAttemptStorageError {
    match error {
        LinuxDirectoryCleanupError::DirectoryIdentity { path } => {
            LinuxQemuAttemptStorageError::DirectoryIdentity { path }
        }
        LinuxDirectoryCleanupError::Bound { path, reason } => {
            LinuxQemuAttemptStorageError::CleanupBound {
                path,
                message: reason.as_str(),
            }
        }
        LinuxDirectoryCleanupError::Io {
            operation,
            path,
            source,
        } => LinuxQemuAttemptStorageError::Io {
            operation: qemu_cleanup_operation(operation),
            path,
            source,
        },
    }
}

fn qemu_cleanup_operation(operation: LinuxDirectoryCleanupOperation) -> &'static str {
    match operation {
        LinuxDirectoryCleanupOperation::IdentifyRoot => "identify QEMU cleanup root",
        LinuxDirectoryCleanupOperation::OpenNestedDirectory => {
            "open nested QEMU artifact directory"
        }
        LinuxDirectoryCleanupOperation::SynchronizeDirectory => {
            "synchronize cleaned QEMU artifact directory"
        }
        LinuxDirectoryCleanupOperation::ReopenParentDirectory => {
            "reopen QEMU artifact parent directory"
        }
        LinuxDirectoryCleanupOperation::RemoveNestedDirectory => {
            "remove nested QEMU artifact directory"
        }
        LinuxDirectoryCleanupOperation::IdentifyDirectory => "identify QEMU artifact directory",
        LinuxDirectoryCleanupOperation::OpenDirectoryScan => {
            "open QEMU artifact directory for cleanup"
        }
        LinuxDirectoryCleanupOperation::ReadDirectoryEntry => "scan QEMU artifact directory",
        LinuxDirectoryCleanupOperation::InspectEntry => "inspect QEMU attempt artifact",
        LinuxDirectoryCleanupOperation::RemoveEntry => "remove QEMU attempt artifact",
        LinuxDirectoryCleanupOperation::ReauthenticateDirectory => {
            "reauthenticate QEMU artifact directory"
        }
        LinuxDirectoryCleanupOperation::ReauthenticateChildDirectory => {
            "reauthenticate nested QEMU artifact directory"
        }
        LinuxDirectoryCleanupOperation::IdentifyRetainedDirectory => {
            "identify retained QEMU artifact directory"
        }
        LinuxDirectoryCleanupOperation::IdentifyNamedDirectory => {
            "identify named QEMU artifact directory"
        }
    }
}

pub(super) fn valid_attempt_namespace(namespace: &str) -> bool {
    !namespace.is_empty()
        && namespace.len() <= MAX_ATTEMPT_NAMESPACE_BYTES
        && namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn attempt_name(namespace: &str, sequence: u64) -> String {
    format!("{namespace}-{sequence:016x}")
}

pub(super) fn generation_name(generation: u64) -> String {
    format!("{GENERATION_NAME_PREFIX}{generation:016x}")
}

pub(super) fn validate_root_policy(
    root: &OwnedFd,
    path: &Path,
) -> Result<(), LinuxQemuAttemptStorageError> {
    let metadata = fstat(root)
        .map_err(|source| io_error("inspect QEMU attempt-storage root", path, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != geteuid().as_raw()
        || metadata.st_mode & 0o777 != 0o700
    {
        return Err(LinuxQemuAttemptStorageError::RootPolicy {
            path: path.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn verify_directory_policy(
    directory: &OwnedFd,
    path: &Path,
    child_user_id: u32,
    child_group_id: u32,
) -> Result<(), LinuxQemuAttemptStorageError> {
    let metadata = fstat(directory)
        .map_err(|source| io_error("inspect QEMU attempt run directory", path, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != child_user_id
        || metadata.st_gid != child_group_id
        || metadata.st_mode & 0o777 != 0o700
    {
        return Err(LinuxQemuAttemptStorageError::DirectoryPolicy {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// Creates and authenticates one monotone child below the quota-bound attempt root.
pub(super) fn create_generation_directory(
    attempt_directory: &OwnedFd,
    attempt_path: &Path,
    generation: u64,
    child_user_id: u32,
    child_group_id: u32,
) -> Result<(PathBuf, OwnedFd), LinuxQemuAttemptStorageError> {
    let name = generation_name(generation);
    let path = attempt_path.join(&name);
    mkdirat(
        attempt_directory,
        name.as_str(),
        Mode::from_bits_truncate(0o700),
    )
    .map_err(|source| io_error("create QEMU generation directory", &path, source))?;

    let directory = open_directory_at(attempt_directory, &name, &path)?;
    fchmod(&directory, Mode::from_bits_truncate(0o700))
        .map_err(|source| io_error("set QEMU generation-directory mode", &path, source))?;
    fchown(
        &directory,
        Some(Uid::from_raw(child_user_id)),
        Some(Gid::from_raw(child_group_id)),
    )
    .map_err(|source| io_error("assign QEMU generation-directory ownership", &path, source))?;
    fsync(&directory)
        .map_err(|source| io_error("synchronize QEMU generation directory", &path, source))?;
    verify_directory_policy(&directory, &path, child_user_id, child_group_id)?;
    fsync(attempt_directory)
        .map_err(|source| io_error("synchronize QEMU generation creation", &path, source))?;
    Ok((path, directory))
}

/// Creates or resumes policy installation for the empty exact-VMState destination.
///
/// Retrying an interrupted setup may reopen the same empty regular file and
/// reapply its policy. Any file with content is treated as materialization state
/// owned by another phase and is never silently reused.
pub(super) fn provision_vmstate_file(
    directory: &OwnedFd,
    directory_path: &Path,
    child_user_id: u32,
    child_group_id: u32,
) -> Result<OwnedFd, LinuxQemuAttemptStorageError> {
    let path = directory_path.join(DEFAULT_VMSTATE_FILE_NAME);
    let create_flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let vmstate = match openat(
        directory,
        DEFAULT_VMSTATE_FILE_NAME,
        create_flags,
        Mode::from_bits_truncate(0o600),
    ) {
        Ok(vmstate) => vmstate,
        Err(rustix::io::Errno::EXIST) => openat(
            directory,
            DEFAULT_VMSTATE_FILE_NAME,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| io_error("reopen exact-VMState container", &path, source))?,
        Err(source) => {
            return Err(io_error("create exact-VMState container", &path, source));
        }
    };

    let metadata = fstat(&vmstate)
        .map_err(|source| io_error("inspect exact-VMState container", &path, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile || metadata.st_size != 0 {
        return Err(LinuxQemuAttemptStorageError::VmStatePolicy { path });
    }

    fchmod(&vmstate, Mode::from_bits_truncate(0o600))
        .map_err(|source| io_error("set exact-VMState container mode", &path, source))?;
    fchown(
        &vmstate,
        Some(Uid::from_raw(child_user_id)),
        Some(Gid::from_raw(child_group_id)),
    )
    .map_err(|source| io_error("assign exact-VMState container ownership", &path, source))?;
    fsync(&vmstate)
        .map_err(|source| io_error("synchronize exact-VMState container", &path, source))?;
    fsync(directory)
        .map_err(|source| io_error("synchronize exact-VMState directory", &path, source))?;

    let metadata = fstat(&vmstate)
        .map_err(|source| io_error("verify exact-VMState container", &path, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != child_user_id
        || metadata.st_gid != child_group_id
        || metadata.st_mode & 0o777 != 0o600
        || metadata.st_size != 0
    {
        return Err(LinuxQemuAttemptStorageError::VmStatePolicy { path });
    }
    Ok(vmstate)
}

pub(super) fn validate_empty_root(
    root: &OwnedFd,
    path: &Path,
) -> Result<(), LinuxQemuAttemptStorageError> {
    let scan = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| io_error("open QEMU attempt-storage root for scan", path, source))?;
    let mut buffer = [MaybeUninit::uninit(); ROOT_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(scan, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry =
            entry.map_err(|source| io_error("scan QEMU attempt-storage root", path, source))?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Err(LinuxQemuAttemptStorageError::RootNotEmpty {
                path: path.to_owned(),
            });
        }
    }
    Ok(())
}

pub(super) fn lock_namespace(
    root: &OwnedFd,
    path: &Path,
) -> Result<(), LinuxQemuAttemptStorageError> {
    flock(root, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
        if source == rustix::io::Errno::WOULDBLOCK {
            LinuxQemuAttemptStorageError::NamespaceLocked {
                path: path.to_owned(),
            }
        } else {
            io_error("lock QEMU attempt-storage root", path, source)
        }
    })
}

pub(super) fn open_directory_at(
    parent: &OwnedFd,
    name: &str,
    path: &Path,
) -> Result<OwnedFd, LinuxQemuAttemptStorageError> {
    openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| io_error("open QEMU attempt run directory", path, source))
}

pub(super) fn duplicate_fd(
    descriptor: &OwnedFd,
    operation: &'static str,
    path: &Path,
) -> Result<OwnedFd, LinuxQemuAttemptStorageError> {
    fcntl_dupfd_cloexec(descriptor, 0).map_err(|source| io_error(operation, path, source))
}

pub(super) fn invalid_config(message: &'static str) -> LinuxQemuAttemptStorageError {
    LinuxQemuAttemptStorageError::InvalidConfig { message }
}

pub(super) fn io_error(
    operation: &'static str,
    path: &Path,
    source: rustix::io::Errno,
) -> LinuxQemuAttemptStorageError {
    LinuxQemuAttemptStorageError::Io {
        operation,
        path: path.to_owned(),
        source: source.into(),
    }
}

#[cfg(test)]
mod cleanup_error_tests {
    //! Checks exact historical QEMU error mapping from neutral cleanup failures.

    use super::*;
    use crucible_host_resources::LinuxDirectoryCleanupBoundReason;

    #[test]
    fn neutral_errors_preserve_qemu_operation_labels_paths_and_os_errors() {
        let path = PathBuf::from("/diagnostic-only");
        let operations = [
            (
                LinuxDirectoryCleanupOperation::IdentifyRoot,
                "identify QEMU cleanup root",
            ),
            (
                LinuxDirectoryCleanupOperation::OpenNestedDirectory,
                "open nested QEMU artifact directory",
            ),
            (
                LinuxDirectoryCleanupOperation::SynchronizeDirectory,
                "synchronize cleaned QEMU artifact directory",
            ),
            (
                LinuxDirectoryCleanupOperation::ReopenParentDirectory,
                "reopen QEMU artifact parent directory",
            ),
            (
                LinuxDirectoryCleanupOperation::RemoveNestedDirectory,
                "remove nested QEMU artifact directory",
            ),
            (
                LinuxDirectoryCleanupOperation::IdentifyDirectory,
                "identify QEMU artifact directory",
            ),
            (
                LinuxDirectoryCleanupOperation::OpenDirectoryScan,
                "open QEMU artifact directory for cleanup",
            ),
            (
                LinuxDirectoryCleanupOperation::ReadDirectoryEntry,
                "scan QEMU artifact directory",
            ),
            (
                LinuxDirectoryCleanupOperation::InspectEntry,
                "inspect QEMU attempt artifact",
            ),
            (
                LinuxDirectoryCleanupOperation::RemoveEntry,
                "remove QEMU attempt artifact",
            ),
            (
                LinuxDirectoryCleanupOperation::ReauthenticateDirectory,
                "reauthenticate QEMU artifact directory",
            ),
            (
                LinuxDirectoryCleanupOperation::ReauthenticateChildDirectory,
                "reauthenticate nested QEMU artifact directory",
            ),
            (
                LinuxDirectoryCleanupOperation::IdentifyRetainedDirectory,
                "identify retained QEMU artifact directory",
            ),
            (
                LinuxDirectoryCleanupOperation::IdentifyNamedDirectory,
                "identify named QEMU artifact directory",
            ),
        ];
        for (operation, expected) in operations {
            let error = map_directory_cleanup_error(LinuxDirectoryCleanupError::Io {
                operation,
                path: path.clone(),
                source: io::Error::from_raw_os_error(libc::ENOENT),
            });
            match error {
                LinuxQemuAttemptStorageError::Io {
                    operation,
                    path: actual,
                    source,
                } => {
                    assert_eq!(operation, expected);
                    assert_eq!(actual, path);
                    assert_eq!(source.raw_os_error(), Some(libc::ENOENT));
                }
                other => panic!("unexpected mapped error: {other:?}"),
            }
        }

        let reasons = [
            (
                LinuxDirectoryCleanupBoundReason::RootFrameMissing,
                "artifact-cleanup traversal lost its root frame",
            ),
            (
                LinuxDirectoryCleanupBoundReason::ChildFrameMissing,
                "artifact-cleanup traversal lost a child frame",
            ),
            (
                LinuxDirectoryCleanupBoundReason::ParentNameMissing,
                "nested artifact directory omitted its parent name",
            ),
            (
                LinuxDirectoryCleanupBoundReason::ParentFrameMissing,
                "nested artifact directory omitted its parent frame",
            ),
            (
                LinuxDirectoryCleanupBoundReason::EntryCountOverflow,
                "attempt artifact entry count overflowed",
            ),
            (
                LinuxDirectoryCleanupBoundReason::EntryLimitExceeded,
                "attempt artifacts exceed the cleanup-entry ceiling",
            ),
            (
                LinuxDirectoryCleanupBoundReason::ChildNameReservationFailed,
                "attempt artifact cleanup cannot retain bounded child names",
            ),
        ];
        for (reason, expected) in reasons {
            let error = map_directory_cleanup_error(LinuxDirectoryCleanupError::Bound {
                path: path.clone(),
                reason,
            });
            assert!(matches!(error,
                LinuxQemuAttemptStorageError::CleanupBound { path: actual, message }
                if actual == path && message == expected));
        }

        let error = map_directory_cleanup_error(LinuxDirectoryCleanupError::DirectoryIdentity {
            path: path.clone(),
        });
        assert!(
            matches!(error, LinuxQemuAttemptStorageError::DirectoryIdentity { path: actual }
            if actual == path)
        );
    }
}
