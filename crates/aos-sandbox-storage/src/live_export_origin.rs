//! Physically revalidated Storage workspace origins for LocalLive export.
//!
//! A workspace handle is only a selector. The retained Storage runtime obtains
//! the current authenticated inventory and physical mount plan, then opens the
//! fixed root pin itself. This module never accepts a caller's device, inode,
//! mount ID, assignment digest, or export publication as proof. An origin is
//! non-authorizing until a protected export producer and independent kernel
//! grant owner have completed their separate checks.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_protocol::{
    MAXIMUM_RESPONSE_BYTES, ValidatedStorageInventory, ValidatedStorageWorkspace,
    decode_storage_resource_inventory_response,
};
use rustix::fs::{FileType, Mode, OFlags};

use crate::pin_worker::boottime_now_nanoseconds;
use crate::runtime::{StorageBrokerRuntime, StorageRuntimeError, guest_root_inventory_cutoff};
use crate::workspace_catalog::encode_hex;
use crate::workspace_pin::WORKSPACE_PIN_ROOT;

/// Retains one physically verified, non-authorizing mutable workspace origin.
#[derive(Debug)]
pub struct StorageLiveExportOriginV1 {
    root: OwnedFd,
    source_assignment_digest: ObjectDigest,
    owner_sandbox: [u8; 16],
    source_incarnation: [u8; 16],
    workspace_id: [u8; 32],
    workspace_digest: ObjectDigest,
    origin_boot_id: [u8; 16],
    origin_device: u64,
    origin_inode: u64,
    origin_mount_id: u64,
}

impl StorageLiveExportOriginV1 {
    /// Returns the workspace's current authenticated assignment commitment.
    #[must_use]
    pub const fn source_assignment_digest(&self) -> ObjectDigest {
        self.source_assignment_digest
    }

    /// Returns the workspace's exact owner sandbox and incarnation.
    #[must_use]
    pub const fn owner(&self) -> ([u8; 16], [u8; 16]) {
        (self.owner_sandbox, self.source_incarnation)
    }

    /// Returns the current workspace handle and complete observation digest.
    #[must_use]
    pub const fn workspace(&self) -> ([u8; 32], ObjectDigest) {
        (self.workspace_id, self.workspace_digest)
    }

    /// Returns the current boot and descriptor-backed root identity.
    #[must_use]
    pub const fn physical_identity(&self) -> ([u8; 16], u64, u64, u64) {
        (
            self.origin_boot_id,
            self.origin_device,
            self.origin_inode,
            self.origin_mount_id,
        )
    }

    /// Borrows the exact O_PATH directory observed by protected Storage.
    #[must_use]
    pub fn root(&self) -> std::os::fd::BorrowedFd<'_> {
        self.root.as_fd()
    }

    /// Consumes the origin and yields its non-authorizing root descriptor.
    #[must_use]
    pub fn into_root(self) -> OwnedFd {
        self.root
    }
}

impl StorageBrokerRuntime {
    /// Observes one current workspace origin without issuing export authority.
    ///
    /// The caller selects only an opaque workspace handle. Both inventories
    /// come from this retained Storage runtime, and the unique mount ID comes
    /// from its authenticated physical plan and the newly opened root FD.
    /// A different catalog head, assignment, pin, boot, or descriptor closes
    /// the observation. Restart simply repeats these readbacks; no unverified
    /// origin survives process death.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError::Recovery`] for a missing or changed
    /// workspace, unsafe pin path, stale physical plan, changed boot, or kernel
    /// readback failure. An ambiguous runtime journal commit returns
    /// [`StorageRuntimeError::ReopenRequired`].
    pub fn observe_live_export_origin(
        &mut self,
        workspace_handle: [u8; 32],
        deadline_boottime_nanoseconds: u64,
    ) -> Result<StorageLiveExportOriginV1, StorageRuntimeError> {
        if workspace_handle == [0; 32] {
            return Err(StorageRuntimeError::Recovery);
        }

        let before = current_inventory(self, deadline_boottime_nanoseconds)?;
        let workspace = selected_workspace(&before, workspace_handle)?;
        let expected_mount_id = self.live_export_origin_mount_id(workspace)?;

        let root = open_current_root(workspace, expected_mount_id)?;

        let after = current_inventory(self, deadline_boottime_nanoseconds)?;
        if before != after {
            return Err(StorageRuntimeError::Recovery);
        }
        verify_descriptor(&root, workspace, expected_mount_id)?;

        Ok(StorageLiveExportOriginV1 {
            root,
            source_assignment_digest: ObjectDigest::from_bytes(
                *workspace.fence().assignment_digest(),
            ),
            owner_sandbox: *workspace.fence().sandbox_id(),
            source_incarnation: *workspace.fence().incarnation_id(),
            workspace_id: workspace_handle,
            workspace_digest: ObjectDigest::from_bytes(*workspace.resource_digest()),
            origin_boot_id: *workspace.resource_kernel_boot_id(),
            origin_device: workspace.root_device(),
            origin_inode: workspace.root_inode(),
            origin_mount_id: expected_mount_id,
        })
    }
}

fn current_inventory(
    runtime: &mut StorageBrokerRuntime,
    deadline: u64,
) -> Result<ValidatedStorageInventory, StorageRuntimeError> {
    let now = boottime_now_nanoseconds().map_err(|_| StorageRuntimeError::Recovery)?;
    let cutoff = guest_root_inventory_cutoff(now, deadline)?;
    let bytes = runtime.inventory_resources(deadline, cutoff)?;
    decode_storage_resource_inventory_response(&bytes, MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| StorageRuntimeError::Recovery)
}

fn selected_workspace(
    inventory: &ValidatedStorageInventory,
    handle: [u8; 32],
) -> Result<&ValidatedStorageWorkspace, StorageRuntimeError> {
    if inventory.kernel_boot_id()
        != &KernelBootId::current()
            .map_err(|_| StorageRuntimeError::Recovery)?
            .into_bytes()
    {
        return Err(StorageRuntimeError::Recovery);
    }
    inventory
        .workspaces()
        .iter()
        .find(|workspace| workspace.workspace_handle() == &handle)
        .ok_or(StorageRuntimeError::Recovery)
}

fn open_current_root(
    workspace: &ValidatedStorageWorkspace,
    expected_mount_id: u64,
) -> Result<OwnedFd, StorageRuntimeError> {
    let expected_path = format!(
        "{}/{}",
        WORKSPACE_PIN_ROOT,
        encode_hex(workspace.workspace_handle())
    );
    if workspace.root_directory() != expected_path {
        return Err(StorageRuntimeError::Recovery);
    }
    let root = rustix::fs::open(
        workspace.root_directory(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StorageRuntimeError::Recovery)?;
    verify_descriptor(&root, workspace, expected_mount_id)?;
    Ok(root)
}

fn verify_descriptor(
    root: &OwnedFd,
    workspace: &ValidatedStorageWorkspace,
    expected_mount_id: u64,
) -> Result<(), StorageRuntimeError> {
    verify_physical_root(
        root.as_fd(),
        PhysicalRootIdentityV1 {
            boot_id: *workspace.resource_kernel_boot_id(),
            device: workspace.root_device(),
            inode: workspace.root_inode(),
            mount_id: expected_mount_id,
        },
    )
}

#[derive(Clone, Copy)]
struct PhysicalRootIdentityV1 {
    boot_id: [u8; 16],
    device: u64,
    inode: u64,
    mount_id: u64,
}

fn verify_physical_root(
    root: BorrowedFd<'_>,
    expected: PhysicalRootIdentityV1,
) -> Result<(), StorageRuntimeError> {
    let identity = rustix::fs::fstat(root).map_err(|_| StorageRuntimeError::Recovery)?;
    let mount_id = MountId::from_fd(root).map_err(|_| StorageRuntimeError::Recovery)?;
    let boot_id = KernelBootId::current()
        .map_err(|_| StorageRuntimeError::Recovery)?
        .into_bytes();

    if FileType::from_raw_mode(identity.st_mode) != FileType::Directory
        || identity.st_dev != expected.device
        || identity.st_ino != expected.inode
        || mount_id.get() != expected.mount_id
        || boot_id != expected.boot_id
    {
        return Err(StorageRuntimeError::Recovery);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_readback_rejects_changed_descriptor_identity() {
        let directory = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let root = rustix::fs::open(
            directory.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let other_root = rustix::fs::open(
            other.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let stat = rustix::fs::fstat(&root).unwrap();
        let expected = PhysicalRootIdentityV1 {
            boot_id: KernelBootId::current().unwrap().into_bytes(),
            device: stat.st_dev,
            inode: stat.st_ino,
            mount_id: MountId::from_fd(root.as_fd()).unwrap().get(),
        };

        assert!(verify_physical_root(root.as_fd(), expected).is_ok());
        assert!(matches!(
            verify_physical_root(other_root.as_fd(), expected),
            Err(StorageRuntimeError::Recovery)
        ));
        assert!(matches!(
            verify_physical_root(
                root.as_fd(),
                PhysicalRootIdentityV1 {
                    mount_id: expected.mount_id.saturating_add(1),
                    ..expected
                }
            ),
            Err(StorageRuntimeError::Recovery)
        ));
        assert!(matches!(
            verify_physical_root(
                root.as_fd(),
                PhysicalRootIdentityV1 {
                    boot_id: [0; 16],
                    ..expected
                }
            ),
            Err(StorageRuntimeError::Recovery)
        ));
    }

    #[test]
    fn physical_readback_rejects_non_directory() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let descriptor =
            rustix::fs::open(file.path(), OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap();
        let stat = rustix::fs::fstat(&descriptor).unwrap();
        let expected = PhysicalRootIdentityV1 {
            boot_id: KernelBootId::current().unwrap().into_bytes(),
            device: stat.st_dev,
            inode: stat.st_ino,
            mount_id: MountId::from_fd(descriptor.as_fd()).unwrap().get(),
        };

        assert!(matches!(
            verify_physical_root(descriptor.as_fd(), expected),
            Err(StorageRuntimeError::Recovery)
        ));
    }
}
