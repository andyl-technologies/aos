//! Retains the original catalog pin recipes through their exact native checks.
//!
//! Ordinary callers immediately consume their successful pins. The Launch
//! caller keeps the same recipes, partial descriptors and native causes in its
//! funded catalog owner until all independent posts complete.

use std::error::Error;
use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::pidfd::{NamespaceAdoptionFailureV2, NamespaceFd, NamespaceKind};
use rustix::fs::{Mode, OFlags, Stat, open};

use crate::{HostError, Result};

#[derive(Debug, Default)]
pub(super) struct CatalogPinOriginalV2 {
    opening: Option<rustix::io::Result<OwnedFd>>,
    namespace: Option<std::result::Result<NamespaceFd, NamespaceAdoptionFailureV2>>,
    stat: Option<rustix::io::Result<Stat>>,
    mount: Option<aos_linux_descriptors::Result<MountId>>,
    expected: Option<Result<()>>,
    host_opening: Option<rustix::io::Result<OwnedFd>>,
    host_namespace: Option<std::result::Result<NamespaceFd, NamespaceAdoptionFailureV2>>,
    host_different: Option<Result<()>>,
    outcome: Option<Result<()>>,
    entered: bool,
    closed: Option<HostError>,
}

impl CatalogPinOriginalV2 {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn workspace_once(&mut self, path: &str, device: u64, inode: u64) -> Result<()> {
        self.enter()?;
        self.outcome = Some(self.workspace_recipe(path, device, inode));
        self.require_complete()
    }

    fn workspace_recipe(&mut self, path: &str, device: u64, inode: u64) -> Result<()> {
        self.opening = Some(open(
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let fd = positive(&self.opening)?;
        self.stat = Some(rustix::fs::fstat(fd));
        let stat = positive(&self.stat)?;
        self.expected = Some(if stat.st_dev != device || stat.st_ino != inode {
            Err(HostError::Catalog(
                "workspace pin identity changed".to_owned(),
            ))
        } else {
            Ok(())
        });
        positive(&self.expected)?;
        Ok(())
    }

    pub(super) fn anchor_once(
        &mut self,
        path: &str,
        device: u64,
        inode: u64,
        mount_id: u64,
    ) -> Result<()> {
        self.enter()?;
        self.outcome = Some(self.anchor_recipe(path, device, inode, mount_id));
        self.require_complete()
    }

    fn anchor_recipe(&mut self, path: &str, device: u64, inode: u64, mount_id: u64) -> Result<()> {
        self.opening = Some(open(
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let fd = positive(&self.opening)?;
        self.stat = Some(rustix::fs::fstat(fd));
        positive(&self.stat)?;
        self.mount = Some(MountId::from_fd(positive(&self.opening)?.as_fd()));
        let actual_mount = positive(&self.mount)?;
        let stat = positive(&self.stat)?;
        self.expected = Some(
            if stat.st_uid != 0
                || stat.st_mode & 0o7777 != 0o755
                || stat.st_dev != device
                || stat.st_ino != inode
                || actual_mount.get() != mount_id
            {
                Err(HostError::Catalog(
                    "attachment-anchor pin identity or protection changed".to_owned(),
                ))
            } else {
                Ok(())
            },
        );
        positive(&self.expected)?;
        Ok(())
    }

    pub(super) fn network_once(&mut self, path: &str, device: u64, inode: u64) -> Result<()> {
        self.enter()?;
        self.outcome = Some(self.network_recipe(path, device, inode));
        self.require_complete()
    }

    fn network_recipe(&mut self, path: &str, device: u64, inode: u64) -> Result<()> {
        self.opening = Some(open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        positive(&self.opening)?;
        let Some(Ok(fd)) = self.opening.take() else {
            std::process::abort()
        };
        self.namespace = Some(NamespaceFd::from_owned_retaining_v2(
            fd,
            NamespaceKind::Network,
        ));
        let namespace = self
            .namespace
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(closed)?;
        let identity = namespace.identity();
        self.expected = Some(if identity.device != device || identity.inode != inode {
            Err(HostError::Catalog(
                "network namespace pin identity changed".to_owned(),
            ))
        } else {
            Ok(())
        });
        positive(&self.expected)?;

        self.capture_host_current()?;
        let host = self
            .host_namespace
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(closed)?;
        self.host_different = Some(if host.identity() == identity {
            Err(HostError::Catalog(
                "network pin resolves to the host network namespace".to_owned(),
            ))
        } else {
            Ok(())
        });
        positive(&self.host_different)?;
        Ok(())
    }

    // The fixed procfs magic link intentionally follows the kernel namespace
    // entry. The same NamespaceFd checker then proves nsfs and Network kind.
    pub(super) fn capture_host_current(&mut self) -> Result<()> {
        if self.host_opening.is_some() || self.host_namespace.is_some() {
            return Err(closed());
        }
        self.host_opening = Some(open(
            "/proc/self/ns/net",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        positive(&self.host_opening)?;
        let Some(Ok(fd)) = self.host_opening.take() else {
            std::process::abort()
        };
        self.host_namespace = Some(NamespaceFd::from_owned_retaining_v2(
            fd,
            NamespaceKind::Network,
        ));
        if self
            .host_namespace
            .as_ref()
            .is_some_and(|result| result.is_ok())
        {
            Ok(())
        } else {
            Err(closed())
        }
    }

    pub(super) fn current_network_identity(
        &self,
    ) -> Option<aos_sandbox_linux::pidfd::NamespaceIdentity> {
        self.host_namespace
            .as_ref()?
            .as_ref()
            .ok()
            .map(NamespaceFd::identity)
    }

    fn enter(&mut self) -> Result<()> {
        if self.entered {
            if self.failure().is_none() {
                self.closed = Some(closed());
            }
            return Err(closed());
        }
        self.entered = true;
        Ok(())
    }

    pub(super) fn entered(&self) -> bool {
        self.entered
    }

    pub(super) fn require_complete(&self) -> Result<()> {
        if self.closed.is_none() && matches!(self.outcome, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    pub(super) fn take_raw(&mut self) -> Option<OwnedFd> {
        self.require_complete().ok()?;
        match self.opening.take()? {
            Ok(fd) => Some(fd),
            Err(_) => std::process::abort(),
        }
    }

    pub(super) fn take_namespace(&mut self) -> Option<NamespaceFd> {
        self.require_complete().ok()?;
        match self.namespace.take()? {
            Ok(namespace) => Some(namespace),
            Err(_) => std::process::abort(),
        }
    }

    pub(super) fn into_ordinary_error(self) -> HostError {
        if let Some(Err(error)) = self.opening {
            return HostError::Catalog(error.to_string());
        }
        if let Some(Err(failure)) = self.namespace {
            return HostError::Catalog(failure.cause().to_string());
        }
        if let Some(Err(error)) = self.stat {
            return HostError::Catalog(error.to_string());
        }
        if let Some(Err(error)) = self.mount {
            return HostError::Catalog(error.to_string());
        }
        if let Some(Err(error)) = self.expected {
            return error;
        }
        if let Some(Err(error)) = self.host_opening {
            return HostError::Catalog(error.to_string());
        }
        if let Some(Err(failure)) = self.host_namespace {
            return HostError::Catalog(failure.cause().to_string());
        }
        if let Some(Err(error)) = self.host_different {
            return error;
        }
        self.closed.unwrap_or_else(closed)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.opening)
            .or_else(|| {
                self.namespace
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|failure| failure.cause() as _)
            })
            .or_else(|| cause(&self.stat))
            .or_else(|| cause(&self.mount))
            .or_else(|| cause(&self.expected))
            .or_else(|| cause(&self.host_opening))
            .or_else(|| {
                self.host_namespace
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|failure| failure.cause() as _)
            })
            .or_else(|| cause(&self.host_different))
            .or_else(|| cause(&self.outcome))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

pub(super) fn positive<T, E>(slot: &Option<std::result::Result<T, E>>) -> Result<&T> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or_else(closed)
}

pub(super) fn cause<T, E: Error + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|error| error as _)
}

pub(super) fn closed() -> HostError {
    HostError::Catalog("retained launch catalog original is incomplete or refused".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_workspace_identity_keeps_original_descriptor_and_native_stat() {
        let directory = tempfile::tempdir().unwrap();
        let stat = rustix::fs::stat(directory.path()).unwrap();
        let mut original = CatalogPinOriginalV2::new();

        assert!(
            original
                .workspace_once(
                    directory.path().to_str().unwrap(),
                    stat.st_dev,
                    stat.st_ino + 1
                )
                .is_err()
        );

        assert!(matches!(original.stat, Some(Ok(_))));
        let descriptor = original.opening.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(rustix::fs::fstat(descriptor).unwrap().st_ino, stat.st_ino);
        assert!(original.take_raw().is_none());
        assert!(original.failure().is_some());
    }

    #[test]
    fn rejected_namespace_keeps_the_original_file_after_type_validation() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let stat = rustix::fs::stat(file.path()).unwrap();
        let mut original = CatalogPinOriginalV2::new();

        assert!(
            original
                .network_once(file.path().to_str().unwrap(), stat.st_dev, stat.st_ino)
                .is_err()
        );

        let failure = original.namespace.as_ref().unwrap().as_ref().unwrap_err();
        assert_eq!(
            rustix::fs::fstat(failure.as_fd()).unwrap().st_ino,
            stat.st_ino
        );
        assert!(original.host_opening.is_none());
        assert!(original.host_namespace.is_none());
        assert!(original.take_namespace().is_none());
    }

    #[test]
    fn repeated_pin_entry_cannot_replace_a_successful_original() {
        let directory = tempfile::tempdir().unwrap();
        let stat = rustix::fs::stat(directory.path()).unwrap();
        let mut original = CatalogPinOriginalV2::new();
        original
            .workspace_once(directory.path().to_str().unwrap(), stat.st_dev, stat.st_ino)
            .unwrap();

        assert!(original.workspace_once("/definitely-absent", 1, 2).is_err());

        let descriptor = original.opening.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(rustix::fs::fstat(descriptor).unwrap().st_ino, stat.st_ino);
        assert!(original.take_raw().is_none());
    }
}
