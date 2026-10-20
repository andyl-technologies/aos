//! Observes the entire held namespace pin root without allocating a population.
//!
//! This observation alone grants no absence certificate: the service must also
//! join protected history, worker custody, FD-store and native bookends.

use super::*;
use aos_sandbox_linux::path::RetainedEmptyDirectoryOriginalV2;
use std::os::fd::AsFd as _;
use aos_sandbox_linux::inventory::MountId;

#[derive(Debug, thiserror::Error)]
#[error("Network pin-root current-path observation is incomplete or changed")]
pub(crate) struct NetworkPinRootCurrentClosedV2;

#[derive(Clone, Copy)]
enum First { Open, Empty, Held, HeldMount, CurrentMount, Protection, Identity, Reentry }

/// Keeps both the reopened protected pathname and its held-root comparison.
#[derive(Default)]
pub(crate) struct NetworkPinRootAbsenceOriginalV2 {
    opened: Option<Result<OwnedFd, rustix::io::Errno>>,
    empty: RetainedEmptyDirectoryOriginalV2,
    held: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    held_mount: Option<Result<MountId, aos_sandbox_linux::Error>>,
    current_mount: Option<Result<MountId, aos_sandbox_linux::Error>>,
    protection: Option<Result<(), NetworkPinRootProtectionErrorV2>>,
    identity: Option<Result<(), NetworkPinRootCurrentClosedV2>>,
    reentry: Option<NetworkPinRootCurrentClosedV2>,
    first: Option<First>,
    entered: bool,
}

impl NetworkPinRootAbsenceOriginalV2 {
    pub(crate) fn receiving_native_shape_v2() -> Option<(usize, usize)> {
        let (_, read_files, read_names) = RetainedEmptyDirectoryOriginalV2::receiving_shape_v2()?;
        Some((read_files.checked_add(1)?, read_names.checked_add(1)?))
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Open => self.opened.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Empty => self.empty.failure_v2(),
            First::Held => self.held.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::HeldMount => self.held_mount.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::CurrentMount => self.current_mount.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Protection => self.protection.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Identity => self.identity.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }

    pub(crate) fn complete_identity_v2(&self) -> Option<(u64, u64, u64)> {
        if !self.entered || self.first.is_some() || !matches!(self.identity, Some(Ok(()))) {
            return None;
        }
        let stat = self.empty.root_metadata_v2()?;
        Some((stat.st_dev as u64, stat.st_ino as u64,
            self.current_mount.as_ref()?.as_ref().ok()?.get()))
    }

    fn capture_once_v2(&mut self, root: &PinRoot) -> Result<(), NetworkPinRootCurrentClosedV2> {
        if self.entered {
            self.reentry.get_or_insert(NetworkPinRootCurrentClosedV2);
            self.first.get_or_insert(First::Reentry);
            return Err(NetworkPinRootCurrentClosedV2);
        }
        self.entered = true;
        let held = match root {
            PinRoot::Kernel(root) => root.as_fd(),
            #[cfg(test)]
            PinRoot::Filesystem { descriptor, .. } => descriptor.as_fd(),
        };
        self.opened = Some(match root {
            PinRoot::Kernel(_) => open_pin_root_candidate_v4(Path::new(NAMESPACE_PIN_ROOT)),
            #[cfg(test)]
            PinRoot::Filesystem { .. } => rustix::fs::openat(held, ".",
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty()),
        });
        if let Some(Ok(current)) = self.opened.as_ref() {
            if self.empty.capture_once_v2(current.as_fd()).is_err() {
                self.first = Some(First::Empty);
            }
            self.current_mount = Some(MountId::from_fd(current.as_fd()));
            if matches!(self.current_mount, Some(Err(_))) {
                self.first.get_or_insert(First::CurrentMount);
            }
        } else {
            self.first = Some(First::Open);
        }

        // The original held root is independently reread even when opening or
        // enumerating its current pathname failed. Every native result stays.
        self.held = Some(rustix::fs::fstat(held));
        if matches!(self.held, Some(Err(_))) { self.first.get_or_insert(First::Held); }
        self.held_mount = Some(MountId::from_fd(held));
        if matches!(self.held_mount, Some(Err(_))) { self.first.get_or_insert(First::HeldMount); }
        let expected_owner = match root {
            PinRoot::Kernel(_) => 0,
            #[cfg(test)]
            PinRoot::Filesystem { expected_owner, .. } => *expected_owner,
        };
        self.protection = Some((|| {
            let current = self.empty.root_metadata_v2().ok_or(NetworkPinRootProtectionErrorV2)?;
            require_pin_root_metadata_data_v2(current, expected_owner)
        })());
        if matches!(self.protection, Some(Err(_))) {
            self.first.get_or_insert(First::Protection);
        }
        self.identity = Some((|| {
            let current = self.empty.root_metadata_v2().ok_or(NetworkPinRootCurrentClosedV2)?;
            let held = self.held.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NetworkPinRootCurrentClosedV2)?;
            if (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_gid)
                != (held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid)
                || self.current_mount.as_ref().and_then(|result| result.as_ref().ok())
                    != self.held_mount.as_ref().and_then(|result| result.as_ref().ok()) {
                return Err(NetworkPinRootCurrentClosedV2);
            }
            if self.current_mount.as_ref().and_then(|result| result.as_ref().ok()).is_none() {
                return Err(NetworkPinRootCurrentClosedV2);
            }
            Ok(())
        })());
        if matches!(self.identity, Some(Err(_))) { self.first.get_or_insert(First::Identity); }
        if self.first.is_none() { Ok(()) } else { Err(NetworkPinRootCurrentClosedV2) }
    }
}

impl NetworkNamespaceCatalogV1 {
    pub(crate) fn has_no_namespace_history_v2(&self) -> bool {
        self.records.is_empty()
    }

    pub(crate) fn observe_empty_pin_root_v2(
        &self,
        original: &mut NetworkPinRootAbsenceOriginalV2,
    ) -> Result<(), NetworkPinRootCurrentClosedV2> {
        original.capture_once_v2(&self.pin_root)
    }
}

#[cfg(test)]
mod current_root_tests {
    use super::*;

    #[test]
    fn same_inode_permission_change_after_opening_is_not_current_protection() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let pin_root = PinRoot::open_filesystem(root.path(), rustix::process::geteuid().as_raw()).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let mut original = NetworkPinRootAbsenceOriginalV2::default();

        assert!(original.capture_once_v2(&pin_root).is_err());
        assert!(matches!(original.protection, Some(Err(_))));
        assert!(original.complete_identity_v2().is_none());
        assert!(original.held.is_some());
        assert!(original.held_mount.is_some());
    }

    #[test]
    fn unknown_pin_and_failed_primary_keep_the_original_root_refusal() {
        let root = tempfile::tempdir().unwrap();
        let pin_root = PinRoot::open_filesystem(root.path(), rustix::process::geteuid().as_raw()).unwrap();
        std::fs::write(root.path().join("unknown"), b"unregistered namespace pin").unwrap();
        let mut original = NetworkPinRootAbsenceOriginalV2::default();

        assert!(original.capture_once_v2(&pin_root).is_err());
        let first = original.failure_v2().unwrap() as *const dyn std::error::Error;
        assert!(original.held.is_some());
        assert!(original.held_mount.is_some());
        assert!(original.complete_identity_v2().is_none());
        assert!(original.capture_once_v2(&pin_root).is_err());
        assert!(std::ptr::eq(first, original.failure_v2().unwrap() as *const dyn std::error::Error));
    }
}
