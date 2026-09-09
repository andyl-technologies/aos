//! Descriptor-backed observation of protected workspace root pins.
//!
//! The observer owns no mutation primitive. A fixed single-threaded helper
//! enters the retained initial host mount namespace, reopens the fixed pin root,
//! resolves the handle-derived slot from the retained root descriptor, and
//! combines `fstat(2)`, `STATX_MNT_ID_UNIQUE`, `listmount(2)`, and
//! `statmount(2)` evidence. ZFS dataset identity is supplied only as a typed
//! result from the separate read-only ZFS observer.

use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::inventory::{MountId, MountListOrder, MountNamespace, MountObservation};
use aos_sandbox_linux::path::{BeneathRoot, FileIdentity, ResolveOptions, ResolvedPath};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use rustix::fs::{FileType, Mode, OFlags};

use crate::StorageStateError;
use crate::workspace_pin::{
    WORKSPACE_PIN_ROOT, WorkspaceDatasetObservationV1, WorkspacePinAttemptV1,
    WorkspacePinHostScopeV1, WorkspacePinObservationV1, WorkspaceRootPinProofV1,
    workspace_pin_path,
};
use crate::workspace_repair::WorkspacePinRepairProbeV1;

const MAXIMUM_HOST_MOUNTS: usize = 65_536;

struct WorkspacePinObservationTargetV1<'a> {
    host_scope: WorkspacePinHostScopeV1,
    workspace_handle: [u8; 32],
    dataset_name: &'a str,
    dataset_guid: u64,
    expected_pin: Option<&'a WorkspaceRootPinProofV1>,
    satisfied_pin: Option<&'a WorkspaceRootPinProofV1>,
}

impl<'a> TryFrom<&'a WorkspacePinAttemptV1> for WorkspacePinObservationTargetV1<'a> {
    type Error = StorageStateError;

    fn try_from(attempt: &'a WorkspacePinAttemptV1) -> Result<Self, Self::Error> {
        Ok(Self {
            host_scope: WorkspacePinHostScopeV1::new(
                attempt.host_boot_id(),
                attempt.host_mount_namespace_device(),
                attempt.host_mount_namespace_inode(),
            )?,
            workspace_handle: attempt.workspace_handle(),
            dataset_name: attempt.dataset_name(),
            dataset_guid: attempt.dataset_guid(),
            expected_pin: attempt.expected_pin(),
            satisfied_pin: attempt.satisfied_pin(),
        })
    }
}

/// Reports failure to acquire or observe the fixed host root-pin scope.
#[derive(Debug, thiserror::Error)]
pub(crate) enum WorkspacePinObserverError {
    /// A Linux descriptor, namespace, boot, or mount observation failed.
    #[error("workspace pin Linux observation failed: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A safe kernel operation failed.
    #[error("workspace pin kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    /// The retained namespace or root descriptor no longer names the fixed host scope.
    #[error("workspace pin host scope does not match the retained fixed scope")]
    HostScopeMismatch,
    /// A structurally valid observation could not form a durable proof.
    #[error("workspace pin proof construction failed: {0}")]
    State(#[from] StorageStateError),
}

/// Retains the initial host mount namespace and exact fixed root directory.
#[derive(Debug)]
pub(crate) struct WorkspacePinHostCustody {
    kernel_boot_id: [u8; 16],
    mount_namespace: NamespaceFd,
    pin_root: ResolvedPath,
}

impl WorkspacePinHostCustody {
    /// Retains the calling process's current mount namespace and root-owned pin root.
    ///
    /// This must run before the broker or any helper enters another mount
    /// namespace. The two descriptors are later transferred in fixed roles to
    /// the one-shot observer or effect worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the boot ID, current mount namespace, or exact
    /// `/run/aos/sandbox-pins/workspaces` directory cannot be securely pinned.
    pub(crate) fn retain_initial_root_owned() -> Result<Self, WorkspacePinObserverError> {
        let kernel_boot_id = KernelBootId::current()?.into_bytes();
        let mount_namespace = open_current_mount_namespace()?;
        let pin_root = open_fixed_pin_root()?;

        Ok(Self {
            kernel_boot_id,
            mount_namespace,
            pin_root,
        })
    }

    /// Returns the exact host scope bound into a fresh durable pin attempt.
    pub(crate) fn host_scope(&self) -> Result<WorkspacePinHostScopeV1, StorageStateError> {
        let identity = self.mount_namespace.identity();
        WorkspacePinHostScopeV1::new(self.kernel_boot_id, identity.device, identity.inode)
    }

    /// Borrows the retained initial host mount namespace descriptor.
    pub(crate) const fn mount_namespace(&self) -> &NamespaceFd {
        &self.mount_namespace
    }

    /// Borrows the retained exact fixed pin-root descriptor.
    pub(crate) const fn pin_root(&self) -> &ResolvedPath {
        &self.pin_root
    }
}

/// Observes one workspace slot from inside the retained host mount namespace.
///
/// The caller must be a fixed single-threaded helper that has already entered
/// `mount_namespace`. The function revalidates that current namespace and the
/// fixed root before inspecting the derived slot. It performs no filesystem or
/// mount mutation.
///
/// # Errors
///
/// Returns an error for boot/namespace/root substitution, incomplete mount
/// inventory, malformed kernel evidence, or an invalid durable proof.
pub(crate) fn observe_workspace_pin(
    attempt: &WorkspacePinAttemptV1,
    dataset: &WorkspaceDatasetObservationV1,
    mount_namespace: &NamespaceFd,
    retained_pin_root: &ResolvedPath,
) -> Result<WorkspacePinObservationV1, WorkspacePinObserverError> {
    let target = WorkspacePinObservationTargetV1::try_from(attempt)?;
    observe_workspace_pin_for_target(&target, dataset, mount_namespace, retained_pin_root)
}

/// Observes a repair target in its freshly authenticated current host scope.
pub(crate) fn observe_workspace_pin_repair(
    probe: &WorkspacePinRepairProbeV1,
    dataset: &WorkspaceDatasetObservationV1,
    mount_namespace: &NamespaceFd,
    retained_pin_root: &ResolvedPath,
) -> Result<WorkspacePinObservationV1, WorkspacePinObserverError> {
    let target = WorkspacePinObservationTargetV1 {
        host_scope: probe.current_host_scope(),
        workspace_handle: probe.workspace_handle(),
        dataset_name: probe.dataset_name(),
        dataset_guid: probe.dataset_guid(),
        expected_pin: None,
        satisfied_pin: None,
    };
    observe_workspace_pin_for_target(&target, dataset, mount_namespace, retained_pin_root)
}

fn observe_workspace_pin_for_target(
    target: &WorkspacePinObservationTargetV1<'_>,
    dataset: &WorkspaceDatasetObservationV1,
    mount_namespace: &NamespaceFd,
    retained_pin_root: &ResolvedPath,
) -> Result<WorkspacePinObservationV1, WorkspacePinObserverError> {
    validate_expected_host_scope(target.host_scope, mount_namespace, retained_pin_root)?;

    let slot = match open_workspace_slot(retained_pin_root, &target.workspace_handle)? {
        Some(slot) => slot,
        None => {
            return confirm_missing_slot_absent(target, mount_namespace, retained_pin_root);
        }
    };
    let slot_metadata = rustix::fs::fstat(slot.as_fd())?;
    if !directory_identity_is_valid(&slot_metadata) {
        return Ok(WorkspacePinObservationV1::Mismatch);
    }

    let root_mount_id = MountId::from_fd(retained_pin_root.as_fd())?;
    let slot_mount_id = MountId::from_fd(slot.as_fd())?;
    let mounted = slot_mount_id != root_mount_id;
    if !slot_attributes_are_allowed(mounted, slot_metadata.st_uid, slot_metadata.st_mode) {
        return Ok(WorkspacePinObservationV1::Mismatch);
    }
    if !mounted {
        return confirm_empty_slot_absent(
            target,
            mount_namespace,
            retained_pin_root,
            &slot,
            root_mount_id,
        );
    }

    // The namespace FD is the authority. `statmount.mnt_ns_id` occupies a
    // separate kernel ID domain from the nsfs inode and is never compared to it.
    let expected_mount_point = workspace_pin_path(&target.workspace_handle);
    let Some(observed_mount) =
        exact_mount_at_point(mount_namespace, &expected_mount_point, slot_mount_id)?
    else {
        return Ok(WorkspacePinObservationV1::Mismatch);
    };

    let classification = classify_mounted_slot(
        target,
        dataset,
        mount_namespace.identity(),
        slot.identity(),
        &observed_mount,
    )?;

    // Re-resolve the top mount and repeat the complete point inventory. This
    // rejects replacements and overmounts between the two observations. The
    // caller must still serialize namespace mutations through proof use.
    let Some(current_slot) = open_workspace_slot(retained_pin_root, &target.workspace_handle)?
    else {
        return Ok(WorkspacePinObservationV1::Mismatch);
    };
    if current_slot.identity() != slot.identity()
        || MountId::from_fd(current_slot.as_fd())? != slot_mount_id
        || exact_mount_at_point(mount_namespace, &expected_mount_point, slot_mount_id)?.is_none()
    {
        return Ok(WorkspacePinObservationV1::Mismatch);
    }
    validate_expected_host_scope(target.host_scope, mount_namespace, retained_pin_root)?;

    Ok(classification)
}

fn confirm_missing_slot_absent(
    target: &WorkspacePinObservationTargetV1<'_>,
    mount_namespace: &NamespaceFd,
    retained_pin_root: &ResolvedPath,
) -> Result<WorkspacePinObservationV1, WorkspacePinObserverError> {
    let expected_mount_point = workspace_pin_path(&target.workspace_handle);
    validate_expected_host_scope(target.host_scope, mount_namespace, retained_pin_root)?;
    if open_workspace_slot(retained_pin_root, &target.workspace_handle)?.is_some()
        || mount_count_at_point(mount_namespace, &expected_mount_point)? != 0
    {
        return Ok(WorkspacePinObservationV1::Mismatch);
    }
    validate_expected_host_scope(target.host_scope, mount_namespace, retained_pin_root)?;
    Ok(WorkspacePinObservationV1::Absent)
}

fn confirm_empty_slot_absent(
    target: &WorkspacePinObservationTargetV1<'_>,
    mount_namespace: &NamespaceFd,
    retained_pin_root: &ResolvedPath,
    initial_slot: &ResolvedPath,
    root_mount_id: MountId,
) -> Result<WorkspacePinObservationV1, WorkspacePinObserverError> {
    if !directory_is_empty(initial_slot)? {
        return Ok(WorkspacePinObservationV1::Mismatch);
    }

    let expected_mount_point = workspace_pin_path(&target.workspace_handle);
    validate_expected_host_scope(target.host_scope, mount_namespace, retained_pin_root)?;
    let Some(current_slot) = open_workspace_slot(retained_pin_root, &target.workspace_handle)?
    else {
        return Ok(WorkspacePinObservationV1::Mismatch);
    };
    if current_slot.identity() != initial_slot.identity()
        || MountId::from_fd(current_slot.as_fd())? != root_mount_id
        || !controlled_directory(&rustix::fs::fstat(current_slot.as_fd())?)
        || !directory_is_empty(&current_slot)?
        || mount_count_at_point(mount_namespace, &expected_mount_point)? != 0
    {
        return Ok(WorkspacePinObservationV1::Mismatch);
    }
    validate_expected_host_scope(target.host_scope, mount_namespace, retained_pin_root)?;
    Ok(WorkspacePinObservationV1::Absent)
}

fn exact_mount_at_point(
    mount_namespace: &NamespaceFd,
    expected_mount_point: &str,
    expected_mount_id: MountId,
) -> Result<Option<MountObservation>, WorkspacePinObserverError> {
    let inventory = MountNamespace::pinned(mount_namespace)?
        .inventory(MAXIMUM_HOST_MOUNTS, MountListOrder::Forward)?;
    let mut matching = inventory.mounts.into_iter().filter(|mount| {
        mount.mount_point.as_os_str().as_bytes() == expected_mount_point.as_bytes()
    });
    let Some(mount) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() || mount.mount_id != expected_mount_id {
        return Ok(None);
    }
    Ok(Some(mount))
}

fn mount_count_at_point(
    mount_namespace: &NamespaceFd,
    expected_mount_point: &str,
) -> Result<usize, WorkspacePinObserverError> {
    let inventory = MountNamespace::pinned(mount_namespace)?
        .inventory(MAXIMUM_HOST_MOUNTS, MountListOrder::Forward)?;
    Ok(inventory
        .mounts
        .iter()
        .filter(|mount| mount.mount_point.as_os_str().as_bytes() == expected_mount_point.as_bytes())
        .count())
}

pub(crate) fn validate_host_scope(
    attempt: &WorkspacePinAttemptV1,
    mount_namespace: &NamespaceFd,
    retained_pin_root: &ResolvedPath,
) -> Result<(), WorkspacePinObserverError> {
    let expected = WorkspacePinHostScopeV1::new(
        attempt.host_boot_id(),
        attempt.host_mount_namespace_device(),
        attempt.host_mount_namespace_inode(),
    )?;
    validate_expected_host_scope(expected, mount_namespace, retained_pin_root)
}

pub(crate) fn current_host_scope(
    mount_namespace: &NamespaceFd,
    retained_pin_root: &ResolvedPath,
) -> Result<WorkspacePinHostScopeV1, WorkspacePinObserverError> {
    let namespace = mount_namespace.identity();
    let scope = WorkspacePinHostScopeV1::new(
        KernelBootId::current()?.into_bytes(),
        namespace.device,
        namespace.inode,
    )?;
    validate_expected_host_scope(scope, mount_namespace, retained_pin_root)?;
    Ok(scope)
}

fn validate_expected_host_scope(
    expected: WorkspacePinHostScopeV1,
    mount_namespace: &NamespaceFd,
    retained_pin_root: &ResolvedPath,
) -> Result<(), WorkspacePinObserverError> {
    let namespace = mount_namespace.identity();
    if mount_namespace.kind() != NamespaceKind::Mount
        || KernelBootId::current()?.into_bytes() != expected.kernel_boot_id()
        || namespace.device != expected.mount_namespace_device()
        || namespace.inode != expected.mount_namespace_inode()
        || open_current_mount_namespace()?.identity() != namespace
    {
        return Err(WorkspacePinObserverError::HostScopeMismatch);
    }

    let current_pin_root = open_fixed_pin_root()?;
    if current_pin_root.identity() != retained_pin_root.identity()
        || MountId::from_fd(current_pin_root.as_fd())?
            != MountId::from_fd(retained_pin_root.as_fd())?
    {
        return Err(WorkspacePinObserverError::HostScopeMismatch);
    }
    Ok(())
}

fn classify_mounted_slot(
    target: &WorkspacePinObservationTargetV1<'_>,
    dataset: &WorkspaceDatasetObservationV1,
    namespace: NamespaceIdentity,
    root_identity: FileIdentity,
    mount: &MountObservation,
) -> Result<WorkspacePinObservationV1, WorkspacePinObserverError> {
    let exact_dataset = matches!(
        dataset,
        WorkspaceDatasetObservationV1::Exact { name, guid }
            if name == target.dataset_name && *guid == target.dataset_guid
    );
    let expected_mount_point = workspace_pin_path(&target.workspace_handle);
    let exact_structure = mount.root.as_os_str().as_bytes() == b"/"
        && mount.mount_point.as_os_str().as_bytes() == expected_mount_point.as_bytes()
        && mount.filesystem_type.as_os_str().as_bytes() == b"zfs"
        && mount.superblock_source.as_os_str().as_bytes() == target.dataset_name.as_bytes()
        && mount.device_major == rustix::fs::major(root_identity.device)
        && mount.device_minor == rustix::fs::minor(root_identity.device);
    if !exact_dataset || !exact_structure || root_identity.device == 0 || root_identity.inode == 0 {
        return Ok(WorkspacePinObservationV1::Mismatch);
    }

    let proof = WorkspaceRootPinProofV1::new(
        target.host_scope.kernel_boot_id(),
        namespace.device,
        namespace.inode,
        mount.mount_id.get(),
        "/".to_owned(),
        expected_mount_point,
        "zfs".to_owned(),
        target.dataset_name.to_owned(),
        target.dataset_guid,
        root_identity.device,
        root_identity.inode,
    )?;
    if target
        .expected_pin
        .is_some_and(|expected| expected != &proof)
        || target
            .satisfied_pin
            .is_some_and(|satisfied| satisfied != &proof)
    {
        return Ok(WorkspacePinObservationV1::Mismatch);
    }

    Ok(WorkspacePinObservationV1::Present(proof))
}

fn open_current_mount_namespace() -> Result<NamespaceFd, WorkspacePinObserverError> {
    let descriptor = rustix::fs::open(
        "/proc/self/ns/mnt",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(NamespaceFd::from_owned(descriptor, NamespaceKind::Mount)?)
}

fn open_fixed_pin_root() -> Result<ResolvedPath, WorkspacePinObserverError> {
    let system_root = rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let system_root = BeneathRoot::from_owned(system_root)?;
    if !controlled_directory(&rustix::fs::fstat(system_root.as_fd())?) {
        return Err(WorkspacePinObserverError::HostScopeMismatch);
    }

    let options = ResolveOptions {
        no_mount_crossing: false,
        require_directory: true,
    };
    let relative_pin_root = WORKSPACE_PIN_ROOT
        .strip_prefix('/')
        .ok_or(WorkspacePinObserverError::HostScopeMismatch)?;
    let mut pin_root = None;
    for relative in ["run", "run/aos", "run/aos/sandbox-pins", relative_pin_root] {
        let directory = system_root.resolve(Path::new(relative), options)?;
        if !controlled_directory(&rustix::fs::fstat(directory.as_fd())?) {
            return Err(WorkspacePinObserverError::HostScopeMismatch);
        }
        pin_root = Some(directory);
    }
    pin_root.ok_or(WorkspacePinObserverError::HostScopeMismatch)
}

pub(crate) fn open_workspace_slot(
    pin_root: &ResolvedPath,
    workspace_handle: &[u8; 32],
) -> Result<Option<ResolvedPath>, WorkspacePinObserverError> {
    let pin_path = workspace_pin_path(workspace_handle);
    let component = pin_path
        .rsplit_once('/')
        .map(|(_, component)| component)
        .ok_or(WorkspacePinObserverError::HostScopeMismatch)?;
    match rustix::fs::openat(
        pin_root.as_fd(),
        component,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => Ok(Some(ResolvedPath::from_inherited(descriptor)?)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn controlled_directory(metadata: &rustix::fs::Stat) -> bool {
    directory_identity_is_valid(metadata)
        && controlled_directory_attributes(metadata.st_uid, metadata.st_mode)
}

fn directory_identity_is_valid(metadata: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
        && metadata.st_dev != 0
        && metadata.st_ino != 0
}

const fn controlled_directory_attributes(owner: u32, mode: u32) -> bool {
    owner == 0 && mode & 0o022 == 0
}

const fn slot_attributes_are_allowed(mounted: bool, owner: u32, mode: u32) -> bool {
    mounted || controlled_directory_attributes(owner, mode)
}

fn directory_is_empty(slot: &ResolvedPath) -> Result<bool, WorkspacePinObserverError> {
    let readable = rustix::fs::openat(
        slot.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let entries = rustix::fs::Dir::new(readable)?;
    for entry in entries {
        let entry = entry?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ffi::OsString;

    use aos_sandbox_core::ObjectDigest;

    use super::*;
    use crate::CatalogBindingV1;
    use crate::workspace_pin::{WorkspacePinActionV1, WorkspacePinAttemptPhaseV1};

    fn attempt(expected_pin: Option<WorkspaceRootPinProofV1>) -> WorkspacePinAttemptV1 {
        WorkspacePinAttemptV1::new_ambiguous(
            [1; 16],
            1,
            WorkspacePinActionV1::Ensure,
            [2; 16],
            [3; 16],
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes([6; 32]),
            CatalogBindingV1::from_publisher(7, ObjectDigest::from_bytes([8; 32])).unwrap(),
            ObjectDigest::from_bytes([9; 32]),
            [10; 32],
            [11; 16],
            12,
            13,
            [14; 16],
            15,
            "tank/aos/project/work".to_owned(),
            16,
            100_000,
            65_536,
            expected_pin,
        )
        .unwrap()
        .with_authority_receipt(vec![17])
        .unwrap()
    }

    fn mount(mount_id: u64) -> MountObservation {
        MountObservation {
            mount_id: MountId::new(mount_id).unwrap(),
            parent_mount_id: MountId::new(20).unwrap(),
            mount_namespace_id: 13,
            device_major: 8,
            device_minor: 1,
            superblock_magic: 0,
            superblock_flags: 0,
            mount_attributes: 0,
            propagation: 0,
            supported_mask: None,
            root: OsString::from("/"),
            mount_point: OsString::from(workspace_pin_path(&[10; 32])),
            filesystem_type: OsString::from("zfs"),
            superblock_source: OsString::from("tank/aos/project/work"),
            uid_map: None,
            gid_map: None,
        }
    }

    fn root_identity() -> FileIdentity {
        FileIdentity {
            device: rustix::fs::makedev(8, 1),
            inode: 22,
            file_type: aos_sandbox_linux::path::FileType::Directory,
        }
    }

    fn exact_dataset() -> WorkspaceDatasetObservationV1 {
        WorkspaceDatasetObservationV1::Exact {
            name: "tank/aos/project/work".to_owned(),
            guid: 16,
        }
    }

    fn target(attempt: &WorkspacePinAttemptV1) -> WorkspacePinObservationTargetV1<'_> {
        WorkspacePinObservationTargetV1::try_from(attempt).unwrap()
    }

    #[test]
    fn exact_descriptor_and_mount_evidence_forms_full_proof() {
        let attempt = attempt(None);
        let observed = classify_mounted_slot(
            &target(&attempt),
            &exact_dataset(),
            NamespaceIdentity {
                device: 12,
                inode: 13,
            },
            root_identity(),
            &mount(21),
        )
        .unwrap();

        let WorkspacePinObservationV1::Present(proof) = observed else {
            panic!("exact pin was not accepted")
        };
        assert_eq!(proof.mount_id(), 21);
        assert_eq!(proof.root_device(), rustix::fs::makedev(8, 1));
        assert_eq!(proof.root_inode(), 22);
        assert_eq!(proof.mount_root(), "/");
        assert_eq!(proof.superblock_source(), "tank/aos/project/work");
    }

    #[test]
    fn same_inode_with_replaced_mount_id_is_not_the_expected_pin() {
        let baseline = attempt(None);
        let WorkspacePinObservationV1::Present(proof) = classify_mounted_slot(
            &target(&baseline),
            &exact_dataset(),
            NamespaceIdentity {
                device: 12,
                inode: 13,
            },
            root_identity(),
            &mount(21),
        )
        .unwrap() else {
            panic!("baseline proof missing")
        };
        let remove_attempt = WorkspacePinAttemptV1::new_ambiguous(
            [18; 16],
            2,
            WorkspacePinActionV1::RemoveAndDestroy,
            [19; 16],
            baseline.creation_operation_id(),
            baseline.operation_fence_digest(),
            baseline.effect_assignment_digest(),
            baseline.workspace_assignment_digest(),
            baseline.creation_result_catalog(),
            baseline.creation_result_digest(),
            baseline.workspace_handle(),
            baseline.host_boot_id(),
            baseline.host_mount_namespace_device(),
            baseline.host_mount_namespace_inode(),
            baseline.clock_provenance(),
            baseline.effect_deadline_boottime_nanoseconds(),
            baseline.dataset_name().to_owned(),
            baseline.dataset_guid(),
            baseline.identity_range_start(),
            baseline.identity_range_size(),
            Some(proof),
        )
        .unwrap()
        .with_authority_receipt(vec![20])
        .unwrap();

        let observed = classify_mounted_slot(
            &target(&remove_attempt),
            &exact_dataset(),
            NamespaceIdentity {
                device: 12,
                inode: 13,
            },
            root_identity(),
            &mount(23),
        )
        .unwrap();
        assert_eq!(observed, WorkspacePinObservationV1::Mismatch);
    }

    #[test]
    fn subtree_bind_and_source_aliases_fail_closed() {
        let attempt = attempt(None);
        let cases = [
            {
                let mut value = mount(21);
                value.root = "/subtree".into();
                value
            },
            {
                let mut value = mount(21);
                value.superblock_source = "tank/aos/project/other".into();
                value
            },
            {
                let mut value = mount(21);
                value.mount_point = "/run/aos/sandbox-pins/workspaces/other".into();
                value
            },
        ];

        for candidate in cases {
            assert_eq!(
                classify_mounted_slot(
                    &target(&attempt),
                    &exact_dataset(),
                    NamespaceIdentity {
                        device: 12,
                        inode: 13,
                    },
                    root_identity(),
                    &candidate,
                )
                .unwrap(),
                WorkspacePinObservationV1::Mismatch,
            );
        }
        assert_eq!(
            classify_mounted_slot(
                &target(&attempt),
                &WorkspaceDatasetObservationV1::Mismatch,
                NamespaceIdentity {
                    device: 12,
                    inode: 13,
                },
                root_identity(),
                &mount(21),
            )
            .unwrap(),
            WorkspacePinObservationV1::Mismatch,
        );
    }

    #[test]
    fn statmount_namespace_id_is_not_treated_as_the_nsfs_inode() {
        let attempt = attempt(None);
        let mut candidate = mount(21);
        candidate.mount_namespace_id = 99;

        assert!(matches!(
            classify_mounted_slot(
                &target(&attempt),
                &exact_dataset(),
                NamespaceIdentity {
                    device: 12,
                    inode: 13,
                },
                root_identity(),
                &candidate,
            )
            .unwrap(),
            WorkspacePinObservationV1::Present(_),
        ));
    }

    #[test]
    fn custody_attributes_apply_only_to_unmounted_slots() {
        assert!(slot_attributes_are_allowed(false, 0, 0o040755));
        assert!(!slot_attributes_are_allowed(false, 0, 0o040777));
        assert!(!slot_attributes_are_allowed(false, 992, 0o040755));

        assert!(slot_attributes_are_allowed(true, 992, 0o040755));
        assert!(slot_attributes_are_allowed(true, 100_000, 0o040777));
    }

    #[test]
    fn observer_types_carry_no_effect_phase() {
        assert_eq!(attempt(None).phase(), WorkspacePinAttemptPhaseV1::Ambiguous);
        assert!(matches!(
            exact_dataset(),
            WorkspaceDatasetObservationV1::Exact { .. }
        ));
    }
}
