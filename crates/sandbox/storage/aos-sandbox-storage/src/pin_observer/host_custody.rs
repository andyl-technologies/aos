//! Retains PID 1's fixed host-pin descriptor delivery and native validation cuts.
//!
//! Systemd supplies only the mount namespace and fixed pin subtree. This module
//! validates their kernel types and ownership without opening PID 1's procfs
//! links from the capability-empty broker or acquiring namespace-entry authority.

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

use aos_linux_descriptors::boot::KernelBootId;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};

use super::{WorkspacePinHostCustody, WorkspacePinObserverError, controlled_directory};

/// Parks every delivered descriptor and native result before validating host custody.
/// Failed attempts remain in the enclosing startup owner through its terminal post.
#[derive(Default)]
pub(crate) struct WorkspacePinHostCaptureV1 {
    delivery: Option<crate::activation::StorageHostPinDescriptorsV1>,
    boot: Option<Result<KernelBootId, aos_linux_descriptors::Error>>,
    namespace_clone: Option<Result<OwnedFd, rustix::io::Errno>>,
    namespace: Option<Result<NamespaceFd, aos_sandbox_linux::pidfd::NamespaceAdoptionFailureV2>>,
    root_clone: Option<Result<OwnedFd, rustix::io::Errno>>,
    root_original: aos_sandbox_linux::path::BeneathRootOwnedOriginalV2,
    root: Option<BeneathRoot>,
    root_metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    root_mount_id: Option<Result<MountId, aos_linux_descriptors::Error>>,
    view_original: aos_sandbox_linux::path::BeneathRootResolveOriginalV2,
    attempted: bool,
}

impl WorkspacePinHostCaptureV1 {
    /// Borrows the first failed native result without dropping its descriptor.
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.boot
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| {
                self.namespace_clone
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                self.namespace
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|failure| failure.cause() as &dyn std::error::Error)
            })
            .or_else(|| {
                self.root_clone
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                self.root_original
                    .failure()
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                self.root_metadata
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                self.view_original
                    .failure()
                    .map(|cause| cause as &dyn std::error::Error)
            })
            .or_else(|| {
                self.root_mount_id
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)
            })
    }

    /// Adopts only the closed initial systemd table's fixed host descriptors.
    pub(crate) fn capture_once(
        &mut self,
        delivery: Option<crate::activation::StorageHostPinDescriptorsV1>,
    ) -> Result<WorkspacePinHostCustody, WorkspacePinObserverError> {
        if self.attempted {
            return Err(WorkspacePinObserverError::HostScopeMismatch);
        }
        self.attempted = true;
        self.delivery = delivery;
        let delivery =
            self.delivery
                .as_ref()
                .ok_or(WorkspacePinObserverError::HostScopeObservation(
                    "missing PID 1 host descriptors",
                ))?;
        self.boot = Some(KernelBootId::current());
        if !matches!(self.boot, Some(Ok(_))) {
            return Err(WorkspacePinObserverError::HostScopeObservation(
                "kernel boot identity",
            ));
        }
        self.namespace_clone = Some(rustix::io::fcntl_dupfd_cloexec(
            delivery.mount_namespace(),
            0,
        ));
        let namespace = match self.namespace_clone.as_ref() {
            Some(Ok(_)) => match self.namespace_clone.take() {
                Some(Ok(fd)) => fd,
                _ => std::process::abort(),
            },
            _ => {
                return Err(WorkspacePinObserverError::HostScopeObservation(
                    "namespace descriptor clone",
                ));
            }
        };
        self.namespace = Some(NamespaceFd::from_owned_retaining_v2(
            namespace,
            NamespaceKind::Mount,
        ));
        if !matches!(self.namespace, Some(Ok(_))) {
            return Err(WorkspacePinObserverError::HostScopeObservation(
                "namespace descriptor kind",
            ));
        }
        self.root_clone = Some(rustix::io::fcntl_dupfd_cloexec(delivery.pin_root(), 0));
        let root = match self.root_clone.as_ref() {
            Some(Ok(_)) => match self.root_clone.take() {
                Some(Ok(fd)) => fd,
                _ => std::process::abort(),
            },
            _ => {
                return Err(WorkspacePinObserverError::HostScopeObservation(
                    "pin-root descriptor clone",
                ));
            }
        };
        self.root_original.from_owned_once(root).map_err(|_| {
            WorkspacePinObserverError::HostScopeObservation("pin-root descriptor kind")
        })?;
        self.root = self.root_original.take_completed_once();
        let root = self
            .root
            .as_ref()
            .ok_or(WorkspacePinObserverError::HostScopeMismatch)?;
        self.root_metadata = Some(rustix::fs::fstat(root.as_fd()));
        if !self
            .root_metadata
            .as_ref()
            .is_some_and(|value| value.as_ref().is_ok_and(controlled_directory))
        {
            return Err(WorkspacePinObserverError::HostScopeObservation(
                "pin-root ownership",
            ));
        }
        self.root_mount_id = Some(MountId::from_fd(root.as_fd()));
        if !matches!(self.root_mount_id, Some(Ok(_))) {
            return Err(WorkspacePinObserverError::HostScopeObservation(
                "pin-root mount identity",
            ));
        }

        // Systemd delivers O_RDONLY directories. The observer wire protocol
        // requires O_PATH; resolve only this already retained directory itself.
        self.view_original
            .resolve_once(
                root,
                Path::new("."),
                ResolveOptions {
                    no_mount_crossing: true,
                    require_directory: true,
                },
            )
            .map_err(|_| WorkspacePinObserverError::HostScopeObservation("pin-root O_PATH view"))?;
        let Some(Ok(boot)) = self.boot.take() else {
            std::process::abort()
        };
        let Some(Ok(mount_namespace)) = self.namespace.take() else {
            std::process::abort()
        };
        let Some(pin_root) = self.view_original.take_completed_once() else {
            std::process::abort()
        };
        let Some(Ok(pin_root_mount_id)) = self.root_mount_id.take() else {
            std::process::abort()
        };
        Ok(WorkspacePinHostCustody {
            kernel_boot_id: boot.into_bytes(),
            mount_namespace,
            pin_root,
            pin_root_mount_id,
            _root_carrier: self.root.take(),
        })
    }
}
