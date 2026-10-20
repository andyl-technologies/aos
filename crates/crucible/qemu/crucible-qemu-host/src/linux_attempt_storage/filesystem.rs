//! Descriptor-relative filesystem operations for attempt storage.

use super::*;

#[derive(Debug)]
struct CleanupDirectory {
    name_in_parent: Option<CString>,
    device: u64,
    inode: u64,
    children: Vec<CString>,
}

pub(super) fn cleanup_directory_contents(
    mut directory: OwnedFd,
    path: &Path,
    maximum_inodes: u64,
) -> Result<(), LinuxQemuAttemptStorageError> {
    let root_metadata =
        fstat(&directory).map_err(|source| io_error("identify QEMU cleanup root", path, source))?;
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
            return Err(LinuxQemuAttemptStorageError::CleanupBound {
                path: path.to_owned(),
                message: "artifact-cleanup traversal lost its root frame",
            });
        };
        if let Some(child_name) = frame.children.pop() {
            let child = openat(
                &directory,
                child_name.as_c_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|source| io_error("open nested QEMU artifact directory", path, source))?;
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
            io_error("synchronize cleaned QEMU artifact directory", path, source)
        })?;
        if stack.len() == 1 {
            return Ok(());
        }
        let child = stack
            .pop()
            .ok_or_else(|| LinuxQemuAttemptStorageError::CleanupBound {
                path: path.to_owned(),
                message: "artifact-cleanup traversal lost a child frame",
            })?;
        let child_name = child.name_in_parent.as_ref().ok_or_else(|| {
            LinuxQemuAttemptStorageError::CleanupBound {
                path: path.to_owned(),
                message: "nested artifact directory omitted its parent name",
            }
        })?;
        let parent = openat(
            &directory,
            "..",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| io_error("reopen QEMU artifact parent directory", path, source))?;
        let parent_frame =
            stack
                .last()
                .ok_or_else(|| LinuxQemuAttemptStorageError::CleanupBound {
                    path: path.to_owned(),
                    message: "nested artifact directory omitted its parent frame",
                })?;
        verify_cleanup_directory_identity(&parent, parent_frame.device, parent_frame.inode, path)?;
        verify_cleanup_child_identity(&parent, child_name, &directory, path)?;
        unlinkat(&parent, child_name.as_c_str(), AtFlags::REMOVEDIR)
            .map_err(|source| io_error("remove nested QEMU artifact directory", path, source))?;
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
) -> Result<CleanupDirectory, LinuxQemuAttemptStorageError> {
    let directory_metadata = fstat(directory)
        .map_err(|source| io_error("identify QEMU artifact directory", path, source))?;
    if directory_metadata.st_dev != root_device {
        return Err(LinuxQemuAttemptStorageError::DirectoryIdentity {
            path: path.to_owned(),
        });
    }
    let scan = openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| io_error("open QEMU artifact directory for cleanup", path, source))?;
    let mut buffer = [MaybeUninit::uninit(); ROOT_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(scan, &mut buffer);
    let mut children = Vec::new();
    while let Some(entry) = entries.next() {
        let entry =
            entry.map_err(|source| io_error("scan QEMU artifact directory", path, source))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *observed_entries = observed_entries.checked_add(1).ok_or_else(|| {
            LinuxQemuAttemptStorageError::CleanupBound {
                path: path.to_owned(),
                message: "attempt artifact entry count overflowed",
            }
        })?;
        if *observed_entries > maximum_inodes {
            return Err(LinuxQemuAttemptStorageError::CleanupBound {
                path: path.to_owned(),
                message: "attempt artifacts exceed the cleanup-entry ceiling",
            });
        }
        let metadata = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|source| io_error("inspect QEMU attempt artifact", path, source))?;
        if metadata.st_dev != root_device {
            return Err(LinuxQemuAttemptStorageError::DirectoryIdentity {
                path: path.to_owned(),
            });
        }
        if FileType::from_raw_mode(metadata.st_mode) == FileType::Directory {
            children
                .try_reserve(1)
                .map_err(|_| LinuxQemuAttemptStorageError::CleanupBound {
                    path: path.to_owned(),
                    message: "attempt artifact cleanup cannot retain bounded child names",
                })?;
            children.push(name.to_owned());
        } else {
            unlinkat(directory, name, AtFlags::empty())
                .map_err(|source| io_error("remove QEMU attempt artifact", path, source))?;
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
) -> Result<(), LinuxQemuAttemptStorageError> {
    let actual = fstat(directory)
        .map_err(|source| io_error("reauthenticate QEMU artifact directory", path, source))?;
    if actual.st_dev != expected_device || actual.st_ino != expected_inode {
        return Err(LinuxQemuAttemptStorageError::DirectoryIdentity {
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
) -> Result<(), LinuxQemuAttemptStorageError> {
    let named = openat(
        parent,
        name.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        io_error(
            "reauthenticate nested QEMU artifact directory",
            path,
            source,
        )
    })?;
    let expected = fstat(child)
        .map_err(|source| io_error("identify retained QEMU artifact directory", path, source))?;
    let actual = fstat(&named)
        .map_err(|source| io_error("identify named QEMU artifact directory", path, source))?;
    if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
        return Err(LinuxQemuAttemptStorageError::DirectoryIdentity {
            path: path.to_owned(),
        });
    }
    Ok(())
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
