//! Keeps the genuine descriptor-relative storage cleanup under original time.
//!
//! This private traversal preserves the ordinary inode/name/identity bounds,
//! while checking the same retained Cleanup before and after each syscall and
//! directory-read cut. It owns no replacement supervisor or namespace lock.

use super::*;
use crate::QemuVmRealizationError;
use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};
#[cfg(test)]
use std::os::fd::AsRawFd;

#[derive(Debug, Error)]
pub(super) enum OriginalStorageCleanupError {
    #[error("original storage cleanup refused: {0}")]
    Original(#[from] HostSupervisionError),
    #[error("physical storage cleanup failed: {source}; original: {original_after:?}")]
    Physical {
        #[source]
        source: LinuxQemuAttemptStorageError,
        original_after: Option<HostSupervisionError>,
    },
}

impl From<LinuxQemuAttemptStorageError> for OriginalStorageCleanupError {
    fn from(source: LinuxQemuAttemptStorageError) -> Self {
        Self::Physical {
            source,
            original_after: None,
        }
    }
}

fn after<T>(
    original: &HostOperationGuard,
    result: Result<T, LinuxQemuAttemptStorageError>,
) -> Result<T, OriginalStorageCleanupError> {
    let checked = original.wait_slice();
    match result {
        Ok(value) => {
            checked?;
            Ok(value)
        }
        Err(source) => Err(OriginalStorageCleanupError::Physical {
            source,
            original_after: checked.err(),
        }),
    }
}

// The syscall expression is evaluated only after this same-original precheck.
// Keeping its actual Result lets an error retain its separate post-refusal.
macro_rules! original_effect {
    ($original:expr, $effect:expr) => {{
        $original.wait_slice()?;
        after($original, $effect)
    }};
}

impl LinuxQemuAttemptStorageOwner {
    /// Creates only generic descriptor custody, without kernel quota admission.
    #[cfg(test)]
    pub(crate) fn unvalidated_directory_fixture(
        parent: &Path,
        name: &str,
    ) -> Result<(Self, std::os::fd::RawFd), LinuxQemuAttemptStorageError> {
        let path = parent.join(name);
        let parent_directory = open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| io_error("pin generic custody test parent", parent, source))?;
        let directory = open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| io_error("pin generic custody test child", &path, source))?;
        let descriptor = directory.as_raw_fd();
        let pool = Arc::new(ProjectIdPool::new(20_000, 1));
        let project_id = pool
            .allocate()
            .ok_or_else(|| LinuxQemuAttemptStorageError::MissingAuthority { path: path.clone() })?
            .commit();
        Ok((
            Self {
                path,
                name: name.into(),
                parent_directory: Some(parent_directory),
                directory: Some(directory),
                project_id,
                quota: None,
                child_user_id: geteuid().as_raw(),
                child_group_id: rustix::process::getegid().as_raw(),
                maximum_inodes: 16,
                next_generation: None,
                removed: false,
                released: false,
            },
            descriptor,
        ))
    }

    pub(crate) fn cleanup_under_original(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), QemuVmRealizationError> {
        self.cleanup_original_contents(original)
            .and_then(|()| self.release_original(original))
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })
    }

    fn cleanup_original_contents(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), OriginalStorageCleanupError> {
        original.wait_slice()?;
        if self.removed {
            return Ok(());
        }
        original_effect!(original, self.pin_directory())?;
        original_effect!(original, self.verify_named_directory())?;
        let directory = original_effect!(
            original,
            duplicate_fd(
                self.directory()?,
                "retain original QEMU artifact cleanup",
                &self.path,
            )
        )?;
        cleanup_directory_contents(directory, &self.path, self.maximum_inodes, original)
    }

    fn release_original(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), OriginalStorageCleanupError> {
        original.wait_slice()?;
        if self.released {
            return Ok(());
        }
        if !self.removed {
            original_effect!(original, self.pin_directory())?;
            original_effect!(original, self.verify_named_directory())?;
            if self.quota.is_some() {
                original.wait_slice()?;
                let quota = self.quota.take().ok_or_else(|| {
                    LinuxQemuAttemptStorageError::MissingAuthority {
                        path: self.path.clone(),
                    }
                })?;
                let released = quota.release();
                let result = match released {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let (source, reservation) = error.into_parts();
                        self.quota = Some(reservation);
                        Err(LinuxQemuAttemptStorageError::ProjectQuota(source))
                    }
                };
                after(original, result)?;
            }
            original.wait_slice()?;
            let removed = unlinkat(
                self.parent_directory()?,
                self.name.as_str(),
                AtFlags::REMOVEDIR,
            )
            .map_err(|source| {
                io_error("remove original QEMU attempt directory", &self.path, source)
            });
            if removed.is_ok() {
                self.removed = true;
            }
            after(original, removed)?;
        }
        original_effect!(
            original,
            fsync(self.parent_directory()?).map_err(|source| io_error(
                "synchronize original QEMU directory removal",
                &self.path,
                source
            ))
        )?;
        original_effect!(original, self.project_id.recycle())?;
        self.released = true;
        self.directory = None;
        self.parent_directory = None;
        Ok(())
    }
}

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
    original: &HostOperationGuard,
) -> Result<(), OriginalStorageCleanupError> {
    let root_metadata = original_effect!(
        original,
        fstat(&directory).map_err(|source| io_error("identify QEMU cleanup root", path, source))
    )?;
    let root_device = root_metadata.st_dev;
    let mut observed_entries = 1_u64;
    let mut stack = vec![scan_cleanup_directory(
        &directory,
        None,
        path,
        root_device,
        maximum_inodes,
        &mut observed_entries,
        original,
    )?];

    loop {
        original.wait_slice()?;
        let Some(frame) = stack.last_mut() else {
            return Err(OriginalStorageCleanupError::from(
                LinuxQemuAttemptStorageError::CleanupBound {
                    path: path.to_owned(),
                    message: "artifact-cleanup traversal lost its root frame",
                },
            ));
        };
        if let Some(child_name) = frame.children.pop() {
            let child = original_effect!(
                original,
                openat(
                    &directory,
                    child_name.as_c_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|source| io_error(
                    "open nested QEMU artifact directory",
                    path,
                    source
                ))
            )?;
            let child_frame = scan_cleanup_directory(
                &child,
                Some(child_name),
                path,
                root_device,
                maximum_inodes,
                &mut observed_entries,
                original,
            )?;
            directory = child;
            stack.push(child_frame);
            continue;
        }

        original_effect!(
            original,
            fsync(&directory).map_err(|source| {
                io_error("synchronize cleaned QEMU artifact directory", path, source)
            })
        )?;
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
        let parent = original_effect!(
            original,
            openat(
                &directory,
                "..",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|source| io_error(
                "reopen QEMU artifact parent directory",
                path,
                source
            ))
        )?;
        let parent_frame =
            stack
                .last()
                .ok_or_else(|| LinuxQemuAttemptStorageError::CleanupBound {
                    path: path.to_owned(),
                    message: "nested artifact directory omitted its parent frame",
                })?;
        verify_cleanup_directory_identity(
            &parent,
            parent_frame.device,
            parent_frame.inode,
            path,
            original,
        )?;
        verify_cleanup_child_identity(&parent, child_name, &directory, path, original)?;
        original_effect!(
            original,
            unlinkat(&parent, child_name.as_c_str(), AtFlags::REMOVEDIR)
                .map_err(|source| io_error("remove nested QEMU artifact directory", path, source))
        )?;
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
    original: &HostOperationGuard,
) -> Result<CleanupDirectory, OriginalStorageCleanupError> {
    let directory_metadata = original_effect!(
        original,
        fstat(directory).map_err(|source| io_error(
            "identify QEMU artifact directory",
            path,
            source
        ))
    )?;
    if directory_metadata.st_dev != root_device {
        return Err(OriginalStorageCleanupError::from(
            LinuxQemuAttemptStorageError::DirectoryIdentity {
                path: path.to_owned(),
            },
        ));
    }
    let scan = original_effect!(
        original,
        openat(
            directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| io_error(
            "open QEMU artifact directory for cleanup",
            path,
            source
        ))
    )?;
    let mut buffer = [MaybeUninit::uninit(); ROOT_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(scan, &mut buffer);
    let mut children = Vec::new();
    loop {
        original.wait_slice()?;
        let Some(entry) = entries.next() else {
            original.wait_slice()?;
            break;
        };
        let entry = after(
            original,
            entry.map_err(|source| io_error("scan QEMU artifact directory", path, source)),
        )?;
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
            return Err(OriginalStorageCleanupError::from(
                LinuxQemuAttemptStorageError::CleanupBound {
                    path: path.to_owned(),
                    message: "attempt artifacts exceed the cleanup-entry ceiling",
                },
            ));
        }
        let metadata = original_effect!(
            original,
            statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| io_error(
                "inspect QEMU attempt artifact",
                path,
                source
            ))
        )?;
        if metadata.st_dev != root_device {
            return Err(OriginalStorageCleanupError::from(
                LinuxQemuAttemptStorageError::DirectoryIdentity {
                    path: path.to_owned(),
                },
            ));
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
            original_effect!(
                original,
                unlinkat(directory, name, AtFlags::empty()).map_err(|source| io_error(
                    "remove QEMU attempt artifact",
                    path,
                    source
                ))
            )?;
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
    original: &HostOperationGuard,
) -> Result<(), OriginalStorageCleanupError> {
    let actual = original_effect!(
        original,
        fstat(directory).map_err(|source| io_error(
            "reauthenticate QEMU artifact directory",
            path,
            source
        ))
    )?;
    if actual.st_dev != expected_device || actual.st_ino != expected_inode {
        return Err(OriginalStorageCleanupError::from(
            LinuxQemuAttemptStorageError::DirectoryIdentity {
                path: path.to_owned(),
            },
        ));
    }
    Ok(())
}

fn verify_cleanup_child_identity(
    parent: &OwnedFd,
    name: &CString,
    child: &OwnedFd,
    path: &Path,
    original: &HostOperationGuard,
) -> Result<(), OriginalStorageCleanupError> {
    let named = original_effect!(
        original,
        openat(
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
        })
    )?;
    let expected = original_effect!(
        original,
        fstat(child).map_err(|source| io_error(
            "identify retained QEMU artifact directory",
            path,
            source
        ))
    )?;
    let actual = original_effect!(
        original,
        fstat(&named).map_err(|source| io_error(
            "identify named QEMU artifact directory",
            path,
            source
        ))
    )?;
    if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
        return Err(OriginalStorageCleanupError::from(
            LinuxQemuAttemptStorageError::DirectoryIdentity {
                path: path.to_owned(),
            },
        ));
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- these real descriptor-relative filesystem controls assert original pre-refusal and cleanup bounds; regular directories certify no ext4/project/cgroup eligibility.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    fn pin(root: &Path) -> OwnedFd {
        open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap()
    }

    #[test]
    fn original_refusal_prevents_the_first_artifact_removal() {
        let root = tempfile::tempdir().unwrap();
        let retained = root.path().join("retained");
        std::fs::write(&retained, b"original bytes").unwrap();
        let directory = pin(root.path());
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Setup).unwrap();
        supervisor.cancel().unwrap();

        let result = cleanup_directory_contents(directory, root.path(), 4, &original);

        assert!(matches!(
            result,
            Err(OriginalStorageCleanupError::Original(_))
        ));
        assert_eq!(std::fs::read(retained).unwrap(), b"original bytes");
    }

    #[test]
    fn original_cleanup_preserves_symlink_targets_and_the_inode_bound() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(root.path().join("artifact"), b"owned artifact").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("outside")).unwrap();
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let cleanup = supervisor.begin(HostOperationClass::Cleanup).unwrap();

        assert!(cleanup_directory_contents(pin(root.path()), root.path(), 1, &cleanup).is_err());
        cleanup_directory_contents(pin(root.path()), root.path(), 3, &cleanup).unwrap();

        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        assert!(outside.path().is_file());
        cleanup.complete().unwrap();
    }
}
