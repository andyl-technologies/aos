//! Retains fixed session/custody directory creation and independent name posts.
//!
//! The actual role, parent descriptor, payment and write clock remain with the
//! private installer. This native destination creates no service grant or path
//! factory and preserves each reached syscall Result before comparison.

use super::*;
use std::os::fd::AsFd as _;

#[derive(Default)]
pub(super) struct DirectoryOriginalV4 {
    pub(super) mkdir: Option<Result<(), rustix::io::Errno>>,
    pub(super) descriptor: Option<Result<OwnedFd, rustix::io::Errno>>,
    pub(super) metadata: Option<Result<Stat, rustix::io::Errno>>,
    pub(super) mount: Option<Result<MountId, aos_linux_descriptors::Error>>,
    pub(super) writable: Option<Result<(), rustix::io::Errno>>,
    pub(super) final_mode: Option<Result<(), rustix::io::Errno>>,
    pub(super) sync: Option<Result<(), rustix::io::Errno>>,
    pub(super) named: Option<Result<OwnedFd, rustix::io::Errno>>,
    pub(super) named_metadata: Option<Result<Stat, rustix::io::Errno>>,
    pub(super) named_mount: Option<Result<MountId, aos_linux_descriptors::Error>>,
    pub(super) held_after: Option<Result<Stat, rustix::io::Errno>>,
    pub(super) mount_after: Option<Result<MountId, aos_linux_descriptors::Error>>,
    pub(super) post: Option<InstallResult<()>>,
}

impl DirectoryOriginalV4 {
    pub(super) fn descriptor(&self) -> InstallResult<BorrowedFd<'_>> {
        self.descriptor
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|fd| fd.as_fd())
            .ok_or(ProductionSourceProviderCatalogInstallErrorV1::State(
                "fixed directory descriptor",
            ))
    }

    pub(super) fn open_after_mkdir(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &str,
        custody: bool,
        expected_mount: MountId,
    ) -> InstallResult<()> {
        self.mkdir = Some(rustix::fs::mkdirat(
            parent,
            name,
            Mode::from_raw_mode(0o700),
        ));
        if !matches!(
            self.mkdir,
            Some(Ok(())) | Some(Err(rustix::io::Errno::EXIST))
        ) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "fixed mkdir",
            ));
        }
        self.descriptor = Some(openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let fd = self
            .descriptor
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ProductionSourceProviderCatalogInstallErrorV1::State(
                "fixed directory descriptor",
            ))?;
        self.metadata = Some(fstat(fd));
        self.mount = Some(MountId::from_fd(fd.as_fd()));
        if !matches!(self.metadata.as_ref(), Some(Ok(stat)) if protected_directory(stat, custody))
            || !matches!(self.mount, Some(Ok(mount)) if mount == expected_mount)
        {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "fixed directory protection",
            ));
        }
        Ok(())
    }

    pub(super) fn finish_once(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &str,
        custody: bool,
        expected_mount: Option<MountId>,
    ) {
        // These independent native observations precede interpretation of any
        // earlier post result and do not consult the financial healthy gate.
        self.named = Some(openat(
            parent,
            name,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        self.named_metadata = self
            .named
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(fstat);
        self.named_mount = self
            .named
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|fd| MountId::from_fd(fd.as_fd()));
        if let Some(fd) = self
            .descriptor
            .as_ref()
            .and_then(|result| result.as_ref().ok())
        {
            self.held_after = Some(fstat(fd));
            self.mount_after = Some(MountId::from_fd(fd.as_fd()));
        }
        self.post = Some((|| {
            let Some(Ok(before)) = self.metadata.as_ref() else {
                return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                    "fixed initial directory",
                ));
            };
            for result in [&self.named_metadata, &self.held_after] {
                let Some(Ok(after)) = result.as_ref() else {
                    return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                        "fixed directory post",
                    ));
                };
                // Directory ctime/mode legitimately change during creation.
                // The fixed identity and final protection must still agree.
                if before.st_dev != after.st_dev
                    || before.st_ino != after.st_ino
                    || !protected_directory(after, custody)
                    || (custody
                        && matches!(self.final_mode, Some(Ok(())))
                        && after.st_mode & 0o7777 != 0o500)
                {
                    return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                        "fixed directory changed",
                    ));
                }
            }
            if !matches!(self.mount_after, Some(Ok(mount)) if Some(mount) == expected_mount)
                || !matches!(self.named_mount, Some(Ok(mount)) if Some(mount) == expected_mount)
            {
                return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                    "fixed directory mount changed",
                ));
            }
            Ok(())
        })());
    }

    pub(super) fn primary_failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(error)) = self.mkdir.as_ref() {
            if *error != rustix::io::Errno::EXIST {
                return Some(error);
            }
        }
        self.descriptor
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.metadata
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.mount.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.writable
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.final_mode
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.sync.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.primary_failure()
            .or_else(|| self.named.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.named_metadata
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.named_mount
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.held_after
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.mount_after
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.post.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

pub(super) fn protected_directory(stat: &Stat, custody: bool) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == 0
        && if custody {
            matches!(stat.st_mode & 0o7777, 0o500 | 0o700)
        } else {
            stat.st_mode & 0o7777 == 0o700
        }
}
