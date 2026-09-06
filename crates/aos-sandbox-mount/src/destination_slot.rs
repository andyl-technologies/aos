//! Crash-recoverable broker ownership for destination-slot directories.
//!
//! The attachment anchor is a private, pre-opened filesystem owned by Mount.
//! Callers provide no pathname. A slot's catalog and payload locations are
//! derived from its validated assignment, namespace generation, and logical
//! identity:
//!
//! ```text
//! slots/<sandbox>/<incarnation>/<namespace-generation>/<slot>
//! run/aos/attachments/<slot>
//! ```
//!
//! The first path is the writable broker side of an anchor that a later launch
//! step installs read-only in the payload at the parent of the second path.
//! Materialization persists intent before `mkdirat(2)`, then records the exact
//! inode and kernel-unique anchor mount ID before exposing an `O_PATH` pin.
//! Rematerialization replaces only an exact stale-boot ready record and retains
//! its digest as the predecessor of the new physical identity.
//! Reaping persists intent before `unlinkat(2)` and keeps a permanent tombstone.
//! An interrupted operation resumes only when its operation and request digests
//! reproduce the retained record.
//!
//! This module is a node-local effect primitive, not authority. Its request
//! types prove canonical shape and portable declaration only. The root broker
//! must still authenticate a signed plan and current ownership lease, durably
//! admit that intersection, and serialize slot operations with Mount resource
//! mutations before calling it.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use aos_sandbox::journal::{Journal, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::model::SandboxSpec;
use aos_sandbox_core::{
    AttachmentSlotId, DescriptorRole, MediaType, ObjectDescriptor, ObjectDigest, OperationId,
    PortableMediaType, descriptor_for_bytes, encode_sandbox_spec, validate_descriptor_role,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::path::{BeneathRoot, FileIdentity, FileType, ResolveOptions, ResolvedPath};
use aos_sandbox_protocol::ValidatedAssignmentFence;
use sha2::{Digest as _, Sha256};

use crate::{MountError, Result};

const MAGIC: &[u8; 8] = b"AOSMSL02";
const DOMAIN: &[u8] = b"aos.sandbox.mount-destination-slot.v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.mount-destination-slot.transaction.v2\0";
const RECORD_BYTES: usize = 436;
const MAXIMUM_SLOT_RESOURCES: usize = 16_384;
const SLOT_DIRECTORY_MODE: u32 = 0o500;
const PARENT_DIRECTORY_MODE: u32 = 0o700;
const SPECIFICATION_BYTE_CEILING: usize = 1024 * 1024;
const SLOT_ROOT_COMPONENT: &str = "slots";
const PAYLOAD_SLOT_PREFIX: &str = "run/aos/attachments";

/// Binds one physical destination slot to exact declared portable semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationSlotBindingV1 {
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    namespace_generation: u64,
    sandbox_spec: ObjectDescriptor,
    slot_id: AttachmentSlotId,
}

impl DestinationSlotBindingV1 {
    /// Constructs a binding from validated assignment authority and its exact specification.
    ///
    /// The canonical specification must reproduce `sandbox_spec` and declare
    /// `slot_id`. The resulting value contains no node-local path or descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for namespace generation zero, an undeclared or zero
    /// slot, a wrong descriptor role, an oversized specification, or descriptor
    /// bytes that do not exactly identify the supplied canonical specification.
    pub fn new(
        fence: &ValidatedAssignmentFence,
        namespace_generation: u64,
        sandbox_spec: &SandboxSpec,
        sandbox_spec_descriptor: ObjectDescriptor,
        slot_id: AttachmentSlotId,
    ) -> Result<Self> {
        let spec_bytes = encode_sandbox_spec(sandbox_spec);
        let derived_descriptor = sandbox_spec_descriptor_for(&spec_bytes)?;
        if namespace_generation == 0
            || slot_id.as_bytes() == &[0; 16]
            || spec_bytes.is_empty()
            || spec_bytes.len() > SPECIFICATION_BYTE_CEILING
            || validate_descriptor_role(DescriptorRole::SnapshotSpec, &sandbox_spec_descriptor)
                .is_err()
            || sandbox_spec_descriptor != derived_descriptor
            || sandbox_spec
                .attachment_slots()
                .binary_search(&slot_id)
                .is_err()
        {
            return Err(invalid(
                "destination-slot binding is not declared by the exact sandbox specification",
            ));
        }

        Ok(Self {
            sandbox_id: *fence.sandbox_id(),
            incarnation_id: *fence.incarnation_id(),
            assignment_epoch: fence.assignment_epoch(),
            desired_generation: fence.desired_generation(),
            assignment_digest: *fence.assignment_digest(),
            namespace_generation,
            sandbox_spec: sandbox_spec_descriptor,
            slot_id,
        })
    }

    /// Returns the logical sandbox identity.
    #[must_use]
    pub const fn sandbox_id(&self) -> &[u8; 16] {
        &self.sandbox_id
    }

    /// Returns the exact sandbox incarnation identity.
    #[must_use]
    pub const fn incarnation_id(&self) -> &[u8; 16] {
        &self.incarnation_id
    }

    /// Returns the assignment epoch that owns this slot.
    #[must_use]
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }

    /// Returns the desired assignment generation that owns this slot.
    #[must_use]
    pub const fn desired_generation(&self) -> u64 {
        self.desired_generation
    }

    /// Returns the exact assignment semantics digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> &[u8; 32] {
        &self.assignment_digest
    }

    /// Returns the payload mount-namespace generation containing this slot.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.namespace_generation
    }

    /// Borrows the canonical portable specification descriptor declaring the slot.
    #[must_use]
    pub const fn sandbox_spec(&self) -> &ObjectDescriptor {
        &self.sandbox_spec
    }

    /// Returns the logical destination-slot identity.
    #[must_use]
    pub const fn slot_id(&self) -> AttachmentSlotId {
        self.slot_id
    }

    /// Returns the caller-independent path beneath Mount's private catalog root.
    #[must_use]
    pub fn catalog_relative_path(&self) -> PathBuf {
        catalog_relative_path(
            &self.sandbox_id,
            &self.incarnation_id,
            self.namespace_generation,
            self.slot_id.as_bytes(),
        )
    }

    /// Returns the fixed payload-relative destination path for this logical slot.
    #[must_use]
    pub fn payload_relative_path(&self) -> PathBuf {
        Path::new(PAYLOAD_SLOT_PREFIX).join(encode_hex(self.slot_id.as_bytes()))
    }

    /// Returns the private anchor directory installed as the payload slot parent.
    #[must_use]
    pub fn anchor_relative_path(&self) -> PathBuf {
        Path::new(SLOT_ROOT_COMPONENT)
            .join(encode_hex(&self.sandbox_id))
            .join(encode_hex(&self.incarnation_id))
            .join(format!("{:016x}", self.namespace_generation))
    }

    fn key(&self) -> SlotKey {
        SlotKey {
            sandbox_id: self.sandbox_id,
            incarnation_id: self.incarnation_id,
            namespace_generation: self.namespace_generation,
            slot_id: *self.slot_id.as_bytes(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.sandbox_id == [0; 16]
            || self.incarnation_id == [0; 16]
            || self.assignment_epoch == 0
            || self.desired_generation == 0
            || self.assignment_digest == [0; 32]
            || self.namespace_generation == 0
            || self.slot_id.as_bytes() == &[0; 16]
            || validate_descriptor_role(DescriptorRole::SnapshotSpec, &self.sandbox_spec).is_err()
            || self.sandbox_spec.digest().as_bytes() == &[0; 32]
            || self.sandbox_spec.encoded_size() == 0
            || self.sandbox_spec.encoded_size() > SPECIFICATION_BYTE_CEILING as u64
        {
            return Err(corrupt("destination-slot binding contains a sentinel"));
        }
        Ok(())
    }
}

/// Describes one idempotent materialization request after portable validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationSlotMaterializationV1 {
    binding: DestinationSlotBindingV1,
    operation_id: OperationId,
    request_digest: ObjectDigest,
}

/// Describes one exact stale-ready rematerialization request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationSlotRematerializationV1 {
    binding: DestinationSlotBindingV1,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    expected_resource: ObjectDigest,
}

impl DestinationSlotRematerializationV1 {
    /// Constructs one non-authorizing rematerialization request.
    ///
    /// # Errors
    ///
    /// Returns an error for zero operation, request, or predecessor identity.
    pub fn new(
        binding: DestinationSlotBindingV1,
        operation_id: OperationId,
        request_digest: ObjectDigest,
        expected_resource: ObjectDigest,
    ) -> Result<Self> {
        binding.validate()?;
        if operation_id.as_bytes() == &[0; 16]
            || request_digest.as_bytes() == &[0; 32]
            || expected_resource.as_bytes() == &[0; 32]
        {
            return Err(invalid(
                "destination-slot rematerialization operation is unspecified",
            ));
        }
        Ok(Self {
            binding,
            operation_id,
            request_digest,
            expected_resource,
        })
    }

    /// Borrows the exact destination-slot binding.
    #[must_use]
    pub const fn binding(&self) -> &DestinationSlotBindingV1 {
        &self.binding
    }
}

impl DestinationSlotMaterializationV1 {
    /// Constructs one non-authorizing materialization request.
    ///
    /// # Errors
    ///
    /// Returns an error for zero operation or request identity. The binding's
    /// declaration and descriptor are validated by [`DestinationSlotBindingV1::new`].
    pub fn new(
        binding: DestinationSlotBindingV1,
        operation_id: OperationId,
        request_digest: ObjectDigest,
    ) -> Result<Self> {
        binding.validate()?;
        if operation_id.as_bytes() == &[0; 16] || request_digest.as_bytes() == &[0; 32] {
            return Err(invalid(
                "destination-slot materialization operation is unspecified",
            ));
        }
        Ok(Self {
            binding,
            operation_id,
            request_digest,
        })
    }

    /// Borrows the exact destination-slot binding.
    #[must_use]
    pub const fn binding(&self) -> &DestinationSlotBindingV1 {
        &self.binding
    }
}

/// Describes one generation-fenced physical slot-reaping request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationSlotReapV1 {
    binding: DestinationSlotBindingV1,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    expected_materialization: ObjectDigest,
}

impl DestinationSlotReapV1 {
    /// Constructs one non-authorizing reap request for an exact ready resource.
    ///
    /// # Errors
    ///
    /// Returns an error for zero operation, request, or expected resource digest.
    pub fn new(
        binding: DestinationSlotBindingV1,
        operation_id: OperationId,
        request_digest: ObjectDigest,
        expected_materialization: ObjectDigest,
    ) -> Result<Self> {
        binding.validate()?;
        if operation_id.as_bytes() == &[0; 16]
            || request_digest.as_bytes() == &[0; 32]
            || expected_materialization.as_bytes() == &[0; 32]
        {
            return Err(invalid("destination-slot reap operation is unspecified"));
        }
        Ok(Self {
            binding,
            operation_id,
            request_digest,
            expected_materialization,
        })
    }

    /// Borrows the exact destination-slot binding.
    #[must_use]
    pub const fn binding(&self) -> &DestinationSlotBindingV1 {
        &self.binding
    }
}

/// Selects the durable phase of one node-local destination-slot resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DestinationSlotResourcePhaseV1 {
    /// Durable creation intent exists but its directory is not yet committed ready.
    Materializing = 1,
    /// The exact directory exists and a live broker descriptor pins it.
    Ready = 2,
    /// Durable removal intent exists and new resolution is closed.
    Reaping = 3,
    /// The physical directory is absent and the binding is a permanent tombstone.
    Released = 4,
}

impl DestinationSlotResourcePhaseV1 {
    fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Materializing),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Reaping),
            4 => Ok(Self::Released),
            _ => Err(corrupt("destination-slot phase is unknown")),
        }
    }
}

/// Reports whether an exact slot mutation was newly completed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationSlotMutationOutcomeV1 {
    /// This call completed the requested physical transition.
    Recorded,
    /// The same operation and request were already complete.
    Replay,
}

/// Describes one validated node-local destination-slot resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationSlotResourceV1 {
    record: Record,
}

impl DestinationSlotResourceV1 {
    /// Returns the durable physical lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> DestinationSlotResourcePhaseV1 {
        self.record.phase
    }

    /// Borrows the immutable logical and assignment binding.
    #[must_use]
    pub const fn binding(&self) -> &DestinationSlotBindingV1 {
        &self.record.binding
    }

    /// Returns the exact device/inode identity once materialization reached the kernel.
    #[must_use]
    pub const fn file_identity(&self) -> Option<FileIdentity> {
        if self.record.slot_device == 0 || self.record.slot_inode == 0 {
            None
        } else {
            Some(FileIdentity {
                device: self.record.slot_device,
                inode: self.record.slot_inode,
                file_type: FileType::Directory,
            })
        }
    }

    /// Returns the kernel-unique attachment-anchor mount identity, when known.
    #[must_use]
    pub fn anchor_mount_id(&self) -> Option<MountId> {
        MountId::new(self.record.anchor_mount_id).ok()
    }

    /// Returns the immutable digest used to fence the next physical transition.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    pub(crate) const fn kernel_boot_id(&self) -> &[u8; 16] {
        &self.record.kernel_boot_id
    }

    pub(crate) const fn materialization_operation(&self) -> OperationId {
        self.record.materialize_operation
    }

    pub(crate) const fn materialization_request(&self) -> ObjectDigest {
        self.record.materialize_request
    }

    pub(crate) const fn rematerialization_operation(&self) -> Option<OperationId> {
        self.record.rematerialize_operation
    }

    pub(crate) const fn rematerialization_request(&self) -> Option<ObjectDigest> {
        self.record.rematerialize_request
    }

    pub(crate) const fn rematerialization_predecessor(&self) -> Option<ObjectDigest> {
        self.record.rematerialize_predecessor
    }

    pub(crate) const fn reap_operation(&self) -> Option<OperationId> {
        self.record.reap_operation
    }

    pub(crate) const fn reap_request(&self) -> Option<ObjectDigest> {
        self.record.reap_request
    }

    pub(crate) const fn expected_materialization(&self) -> Option<ObjectDigest> {
        self.record.expected_materialization
    }
}

/// Borrows a ready broker-owned destination descriptor.
pub struct ResolvedDestinationSlotV1<'a> {
    resource: DestinationSlotResourceV1,
    pin: &'a ResolvedPath,
}

impl ResolvedDestinationSlotV1<'_> {
    /// Borrows the live close-on-exec `O_PATH` descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.pin.as_fd()
    }

    /// Returns the exact pinned device/inode/type identity.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.pin.identity()
    }

    /// Borrows the durable resource metadata reproduced by the pin.
    #[must_use]
    pub const fn resource(&self) -> &DestinationSlotResourceV1 {
        &self.resource
    }
}

/// Owns bounded destination-slot records and their live ready descriptors.
pub struct DestinationSlotStoreV1 {
    root: BeneathRoot,
    root_owner: u32,
    anchor_mount_id: MountId,
    kernel_boot_id: [u8; 16],
    records: BTreeMap<SlotKey, Record>,
    pins: BTreeMap<SlotKey, ResolvedPath>,
}

impl DestinationSlotStoreV1 {
    /// Opens the private anchor root and recovers all durable slot resources.
    ///
    /// Same-boot ready records must reproduce their exact directory and mount
    /// identity. An interrupted materialization may have either an absent or
    /// exact directory; an interrupted reap may likewise have either state.
    /// Stale-boot records retain audit identity but expose no descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error unless `path` is a real mode-0700 directory owned by
    /// `expected_owner`, or when durable records are malformed, over limit,
    /// equivocate operation identities, or disagree with same-boot filesystem
    /// state.
    pub fn recover(path: impl AsRef<Path>, expected_owner: u32, journal: &Journal) -> Result<Self> {
        let path = path.as_ref();
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| MountError::State(error.to_string()))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != expected_owner
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(corrupt(
                "destination-slot root is not an exact private directory",
            ));
        }
        let descriptor: OwnedFd = rustix::fs::open(
            path,
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(kernel_error)?;
        let descriptor_metadata = rustix::fs::fstat(&descriptor).map_err(kernel_error)?;
        if descriptor_metadata.st_uid != expected_owner
            || descriptor_metadata.st_mode & 0o7777 != PARENT_DIRECTORY_MODE
            || descriptor_metadata.st_dev != metadata.dev()
            || descriptor_metadata.st_ino != metadata.ino()
        {
            return Err(corrupt(
                "destination-slot root changed while its descriptor was opened",
            ));
        }
        let root = BeneathRoot::from_owned(descriptor).map_err(linux_error)?;
        let anchor_mount_id = MountId::from_fd(root.as_fd()).map_err(linux_error)?;
        let kernel_boot_id = KernelBootId::current().map_err(linux_error)?.into_bytes();
        let records = load_records(journal)?;
        let mut value = Self {
            root,
            root_owner: expected_owner,
            anchor_mount_id,
            kernel_boot_id,
            records,
            pins: BTreeMap::new(),
        };
        value.recover_pins()?;
        Ok(value)
    }

    /// Materializes or resumes one exact destination-slot directory.
    ///
    /// Intent is committed before the directory effect. Returning success means
    /// the ready record is durable and the exact descriptor remains pinned by
    /// this store. The caller must serialize this method with catalog publication.
    ///
    /// # Errors
    ///
    /// Returns an error for operation reuse, binding conflicts, capacity
    /// exhaustion, unsafe or substituted filesystem state, or journal failure.
    pub fn materialize(
        &mut self,
        journal: &mut Journal,
        request: &DestinationSlotMaterializationV1,
    ) -> Result<(DestinationSlotResourceV1, DestinationSlotMutationOutcomeV1)> {
        self.materialize_guarded(journal, request, || Ok(()))
    }

    /// Runs the caller's final authority guard after intent and before `mkdirat`.
    pub(crate) fn materialize_guarded<F>(
        &mut self,
        journal: &mut Journal,
        request: &DestinationSlotMaterializationV1,
        mut before_effect: F,
    ) -> Result<(DestinationSlotResourceV1, DestinationSlotMutationOutcomeV1)>
    where
        F: FnMut() -> Result<()>,
    {
        request.binding.validate()?;
        let key = request.binding.key();
        let outcome = match self.records.get(&key) {
            Some(current) if current.matches_materialization(request) => match current.phase {
                DestinationSlotResourcePhaseV1::Materializing => {
                    DestinationSlotMutationOutcomeV1::Recorded
                }
                DestinationSlotResourcePhaseV1::Ready => {
                    self.verify_ready_pin(&key, current)?;
                    return Ok((
                        DestinationSlotResourceV1 {
                            record: current.clone(),
                        },
                        DestinationSlotMutationOutcomeV1::Replay,
                    ));
                }
                DestinationSlotResourcePhaseV1::Reaping
                | DestinationSlotResourcePhaseV1::Released => {
                    return Err(conflict(
                        "released destination slot cannot be rematerialized",
                    ));
                }
            },
            Some(_) => {
                return Err(conflict(
                    "destination-slot binding already has different materialization",
                ));
            }
            None => {
                self.require_capacity()?;
                self.require_unused_operation(request.operation_id)?;
                let record = Record::materializing(
                    self.kernel_boot_id,
                    request.binding.clone(),
                    request.operation_id,
                    request.request_digest,
                )?;
                commit_record(journal, &record)?;
                self.records.insert(key, record);
                DestinationSlotMutationOutcomeV1::Recorded
            }
        };

        let mut current = self
            .records
            .get(&key)
            .cloned()
            .ok_or_else(|| corrupt("materializing destination-slot record disappeared"))?;
        if current.kernel_boot_id != self.kernel_boot_id {
            // A stale Materializing row has no physical identity and recovery
            // already proved that its path is absent. Re-admit the same exact
            // operation under this boot before crossing the mkdir boundary.
            current = Record::materializing(
                self.kernel_boot_id,
                current.binding.clone(),
                current.materialize_operation,
                current.materialize_request,
            )?;
            commit_record(journal, &current)?;
            self.records.insert(key, current.clone());
        }
        before_effect()?;
        let pin = self.materialize_directory(&current.binding)?;
        let identity = pin.identity();
        let mount_id = MountId::from_fd(pin.as_fd()).map_err(linux_error)?;
        if mount_id != self.anchor_mount_id {
            return Err(corrupt(
                "destination slot crossed the attachment-anchor mount",
            ));
        }
        let ready = current.ready(identity, mount_id)?;
        commit_record(journal, &ready)?;
        self.records.insert(key, ready.clone());
        self.pins.insert(key, pin);
        Ok((DestinationSlotResourceV1 { record: ready }, outcome))
    }

    /// Recreates an exact stale-boot ready slot under the current kernel boot.
    ///
    /// The predecessor digest is checked and retained before intent is
    /// committed. The old physical identity never grants a current descriptor.
    /// Returning success means the replacement directory, descriptor, and ready
    /// record are all current and durable.
    ///
    /// # Errors
    ///
    /// Returns an error unless the named resource is a stale ready row with the
    /// same immutable binding, no native Mount resource still names the slot,
    /// and the filesystem path remains absent around durable admission.
    pub fn rematerialize_guarded<F, U>(
        &mut self,
        journal: &mut Journal,
        request: &DestinationSlotRematerializationV1,
        mut slot_unused: U,
        mut before_effect: F,
    ) -> Result<(DestinationSlotResourceV1, DestinationSlotMutationOutcomeV1)>
    where
        F: FnMut() -> Result<()>,
        U: FnMut(&DestinationSlotBindingV1) -> Result<bool>,
    {
        request.binding.validate()?;
        let key = request.binding.key();
        let current = self
            .records
            .get(&key)
            .cloned()
            .ok_or_else(|| conflict("destination-slot resource is absent"))?;
        if !current.matches_binding(&request.binding) {
            return Err(conflict(
                "destination-slot rematerialization binding differs from creation",
            ));
        }

        let (materializing, outcome) = match current.phase {
            DestinationSlotResourcePhaseV1::Ready if current.matches_rematerialization(request) => {
                if current.kernel_boot_id != self.kernel_boot_id {
                    return Err(conflict(
                        "stale rematerialization replay did not reach current boot",
                    ));
                }
                self.verify_ready_pin(&key, &current)?;
                return Ok((
                    DestinationSlotResourceV1 { record: current },
                    DestinationSlotMutationOutcomeV1::Replay,
                ));
            }
            DestinationSlotResourcePhaseV1::Ready => {
                if current.kernel_boot_id == self.kernel_boot_id
                    || current.digest != *request.expected_resource.as_bytes()
                {
                    return Err(conflict(
                        "destination-slot rematerialization resource digest is stale",
                    ));
                }
                self.require_unused_operation(request.operation_id)?;
                if !slot_unused(&request.binding)? {
                    return Err(conflict("destination slot is still named by Mount state"));
                }
                if self
                    .resolve_optional_path(&current.binding.catalog_relative_path())?
                    .is_some()
                {
                    return Err(corrupt(
                        "stale-boot destination-slot path unexpectedly exists",
                    ));
                }
                let next = current.rematerializing(self.kernel_boot_id, request)?;
                commit_record(journal, &next)?;
                self.records.insert(key, next.clone());
                (next, DestinationSlotMutationOutcomeV1::Recorded)
            }
            DestinationSlotResourcePhaseV1::Materializing
                if current.matches_rematerialization(request) =>
            {
                if current.kernel_boot_id != self.kernel_boot_id {
                    return Err(corrupt(
                        "rematerialization intent belongs to another kernel boot",
                    ));
                }
                (current, DestinationSlotMutationOutcomeV1::Recorded)
            }
            DestinationSlotResourcePhaseV1::Materializing => {
                return Err(conflict(
                    "destination slot is bound to another materialization",
                ));
            }
            DestinationSlotResourcePhaseV1::Reaping | DestinationSlotResourcePhaseV1::Released => {
                return Err(conflict(
                    "released destination slot cannot be rematerialized",
                ));
            }
        };

        if !slot_unused(&request.binding)? {
            return Err(conflict(
                "destination slot became referenced after rematerialization admission",
            ));
        }
        before_effect()?;
        let pin = self.materialize_directory(&materializing.binding)?;
        let identity = pin.identity();
        let mount_id = MountId::from_fd(pin.as_fd()).map_err(linux_error)?;
        if mount_id != self.anchor_mount_id {
            return Err(corrupt(
                "rematerialized destination slot crossed the attachment-anchor mount",
            ));
        }
        let ready = materializing.ready(identity, mount_id)?;
        commit_record(journal, &ready)?;
        self.records.insert(key, ready.clone());
        self.pins.insert(key, pin);
        Ok((DestinationSlotResourceV1 { record: ready }, outcome))
    }

    /// Reaps or resumes removal of one exact unused destination slot.
    ///
    /// `slot_unused` is checked before and after durable reap admission. It must
    /// query Mount's complete resource table while the caller holds the same
    /// mutation serialization used for mount operations. Returning `false`
    /// leaves a newly admitted resource in `Reaping`, which safely closes new
    /// resolution and can be resumed after the resource drains.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale resource digest, operation reuse, a slot
    /// still named by Mount state, physical identity substitution, or journal
    /// and filesystem failures.
    pub fn reap<F>(
        &mut self,
        journal: &mut Journal,
        request: &DestinationSlotReapV1,
        mut slot_unused: F,
    ) -> Result<(DestinationSlotResourceV1, DestinationSlotMutationOutcomeV1)>
    where
        F: FnMut(&DestinationSlotBindingV1) -> Result<bool>,
    {
        request.binding.validate()?;
        let key = request.binding.key();
        let current = self
            .records
            .get(&key)
            .cloned()
            .ok_or_else(|| conflict("destination-slot resource is absent"))?;
        if !current.matches_binding(&request.binding) {
            return Err(conflict(
                "destination-slot reap binding differs from materialization",
            ));
        }

        let (mut reaping, outcome) = match current.phase {
            DestinationSlotResourcePhaseV1::Ready => {
                if current.digest != *request.expected_materialization.as_bytes() {
                    return Err(conflict("destination-slot reap resource digest is stale"));
                }
                self.require_unused_operation(request.operation_id)?;
                if !slot_unused(&request.binding)? {
                    return Err(conflict("destination slot is still named by Mount state"));
                }
                let next = current.reaping(request)?;
                commit_record(journal, &next)?;
                self.records.insert(key, next.clone());
                (next, DestinationSlotMutationOutcomeV1::Recorded)
            }
            DestinationSlotResourcePhaseV1::Reaping if current.matches_reap(request) => {
                (current, DestinationSlotMutationOutcomeV1::Recorded)
            }
            DestinationSlotResourcePhaseV1::Released if current.matches_reap(request) => {
                return Ok((
                    DestinationSlotResourceV1 { record: current },
                    DestinationSlotMutationOutcomeV1::Replay,
                ));
            }
            DestinationSlotResourcePhaseV1::Materializing => {
                return Err(conflict("destination slot has not reached ready state"));
            }
            DestinationSlotResourcePhaseV1::Reaping | DestinationSlotResourcePhaseV1::Released => {
                return Err(conflict(
                    "destination slot is bound to another reap operation",
                ));
            }
        };

        if !slot_unused(&request.binding)? {
            return Err(conflict(
                "destination slot became referenced after reap admission",
            ));
        }
        if reaping.kernel_boot_id == self.kernel_boot_id {
            self.remove_directory(&reaping)?;
        } else if self
            .resolve_optional_path(&reaping.binding.catalog_relative_path())?
            .is_some()
        {
            return Err(corrupt(
                "stale-boot destination-slot path unexpectedly exists",
            ));
        }
        reaping.phase = DestinationSlotResourcePhaseV1::Released;
        reaping.digest = reaping.compute_digest();
        reaping.validate()?;
        commit_record(journal, &reaping)?;
        self.records.insert(key, reaping.clone());
        self.pins.remove(&key);
        Ok((DestinationSlotResourceV1 { record: reaping }, outcome))
    }

    /// Resolves only a ready exact binding to its retained broker descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent, stale-boot, reaping, released, or
    /// differently bound resource, or when the retained pin no longer matches
    /// its durable identity.
    pub fn resolve(
        &self,
        binding: &DestinationSlotBindingV1,
    ) -> Result<ResolvedDestinationSlotV1<'_>> {
        binding.validate()?;
        let key = binding.key();
        let record = self
            .records
            .get(&key)
            .ok_or_else(|| conflict("destination-slot resource is absent"))?;
        if record.phase != DestinationSlotResourcePhaseV1::Ready
            || record.kernel_boot_id != self.kernel_boot_id
            || !record.matches_binding(binding)
        {
            return Err(conflict(
                "destination-slot resource is not ready for this binding",
            ));
        }
        self.verify_ready_pin(&key, record)?;
        let pin = self
            .pins
            .get(&key)
            .ok_or_else(|| corrupt("ready destination slot lost its descriptor"))?;
        Ok(ResolvedDestinationSlotV1 {
            resource: DestinationSlotResourceV1 {
                record: record.clone(),
            },
            pin,
        })
    }

    /// Loads one durable slot resource without granting descriptor authority.
    #[must_use]
    pub fn get(&self, binding: &DestinationSlotBindingV1) -> Option<DestinationSlotResourceV1> {
        self.records
            .get(&binding.key())
            .filter(|record| record.matches_binding(binding))
            .cloned()
            .map(|record| DestinationSlotResourceV1 { record })
    }

    /// Returns the bounded number of retained current slot records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Reports whether no destination-slot resources are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterates the complete durable table in canonical logical-key order.
    pub(crate) fn resources(&self) -> impl Iterator<Item = DestinationSlotResourceV1> + '_ {
        self.records
            .values()
            .cloned()
            .map(|record| DestinationSlotResourceV1 { record })
    }

    #[cfg(test)]
    pub(crate) fn make_ready_record_stale_for_test(
        &mut self,
        journal: &mut Journal,
        binding: &DestinationSlotBindingV1,
    ) -> Result<ObjectDigest> {
        let key = binding.key();
        let mut record = self
            .records
            .get(&key)
            .filter(|record| {
                record.matches_binding(binding)
                    && record.phase == DestinationSlotResourcePhaseV1::Ready
                    && record.kernel_boot_id == self.kernel_boot_id
            })
            .cloned()
            .ok_or_else(|| conflict("test fixture requires a current ready destination slot"))?;
        self.remove_directory(&record)?;
        self.pins.remove(&key);

        record.kernel_boot_id[0] ^= 1;
        if record.kernel_boot_id == [0; 16] {
            record.kernel_boot_id[15] = 1;
        }
        record.digest = record.compute_digest();
        record.validate()?;
        commit_record(journal, &record)?;
        self.records.insert(key, record.clone());
        Ok(ObjectDigest::from_bytes(record.digest))
    }

    fn recover_pins(&mut self) -> Result<()> {
        for (key, record) in &self.records {
            if record.kernel_boot_id != self.kernel_boot_id {
                if self
                    .resolve_optional_path(&record.binding.catalog_relative_path())?
                    .is_some()
                {
                    return Err(corrupt(
                        "stale-boot destination-slot path unexpectedly exists",
                    ));
                }
                continue;
            }
            let path = record.binding.catalog_relative_path();
            let resolved = self.resolve_optional_path(&path)?;
            match (record.phase, resolved) {
                (DestinationSlotResourcePhaseV1::Ready, Some(pin)) => {
                    self.verify_physical_record(record, &pin)?;
                    self.pins.insert(*key, pin);
                }
                (DestinationSlotResourcePhaseV1::Ready, None) => {
                    return Err(corrupt("same-boot ready destination slot is absent"));
                }
                (DestinationSlotResourcePhaseV1::Materializing, Some(pin))
                | (DestinationSlotResourcePhaseV1::Reaping, Some(pin)) => {
                    if record.phase == DestinationSlotResourcePhaseV1::Reaping {
                        self.verify_physical_record(record, &pin)?;
                        self.pins.insert(*key, pin);
                    } else {
                        self.verify_new_directory(&pin)?;
                    }
                }
                (DestinationSlotResourcePhaseV1::Released, Some(_)) => {
                    return Err(corrupt("released destination-slot directory still exists"));
                }
                (
                    DestinationSlotResourcePhaseV1::Materializing
                    | DestinationSlotResourcePhaseV1::Reaping
                    | DestinationSlotResourcePhaseV1::Released,
                    None,
                ) => {}
            }
        }
        Ok(())
    }

    fn materialize_directory(&self, binding: &DestinationSlotBindingV1) -> Result<ResolvedPath> {
        let components = [
            SLOT_ROOT_COMPONENT.to_owned(),
            encode_hex(&binding.sandbox_id),
            encode_hex(&binding.incarnation_id),
            format!("{:016x}", binding.namespace_generation),
        ];
        let root = self.root.as_fd().try_clone_to_owned().map_err(|error| {
            MountError::Worker(format!(
                "destination-slot root descriptor duplication failed: {error}"
            ))
        })?;
        let mut parent = BeneathRoot::from_owned(root).map_err(linux_error)?;
        for component in &components {
            parent = self.open_or_create_parent(parent, component)?;
        }

        let slot_name = encode_hex(binding.slot_id.as_bytes());
        match rustix::fs::mkdirat(
            parent.as_fd(),
            slot_name.as_str(),
            rustix::fs::Mode::from_raw_mode(SLOT_DIRECTORY_MODE),
        ) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(kernel_error(error)),
        }
        let pin = parent
            .resolve(Path::new(&slot_name), ResolveOptions::directory())
            .map_err(linux_error)?;
        self.verify_new_directory(&pin)?;
        sync_directory(&parent)?;
        Ok(pin)
    }

    fn open_or_create_parent(&self, parent: BeneathRoot, name: &str) -> Result<BeneathRoot> {
        match rustix::fs::mkdirat(
            parent.as_fd(),
            name,
            rustix::fs::Mode::from_raw_mode(PARENT_DIRECTORY_MODE),
        ) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(kernel_error(error)),
        }
        let child = parent
            .resolve(Path::new(name), ResolveOptions::directory())
            .map_err(linux_error)?;
        self.verify_directory(&child, PARENT_DIRECTORY_MODE)?;
        BeneathRoot::from_resolved(child).map_err(linux_error)
    }

    fn remove_directory(&self, record: &Record) -> Result<()> {
        let Some(pin) = self.resolve_optional_path(&record.binding.catalog_relative_path())? else {
            return Ok(());
        };
        self.verify_physical_record(record, &pin)?;

        let parent = self.resolve_anchor_parent(&record.binding)?;
        let slot_name = encode_hex(record.binding.slot_id.as_bytes());
        match rustix::fs::unlinkat(
            parent.as_fd(),
            slot_name.as_str(),
            rustix::fs::AtFlags::REMOVEDIR,
        ) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(kernel_error(error)),
        }
        sync_directory(&parent)?;
        Ok(())
    }

    fn resolve_anchor_parent(&self, binding: &DestinationSlotBindingV1) -> Result<BeneathRoot> {
        let resolved = self
            .root
            .resolve(&binding.anchor_relative_path(), ResolveOptions::directory())
            .map_err(linux_error)?;
        self.verify_directory(&resolved, PARENT_DIRECTORY_MODE)?;
        BeneathRoot::from_resolved(resolved).map_err(linux_error)
    }

    fn resolve_optional_path(&self, path: &Path) -> Result<Option<ResolvedPath>> {
        match self.root.resolve(path, ResolveOptions::directory()) {
            Ok(value) => Ok(Some(value)),
            Err(aos_sandbox_linux::Error::Syscall { source, .. })
                if source.raw_os_error() == Some(libc::ENOENT) =>
            {
                Ok(None)
            }
            Err(error) => Err(linux_error(error)),
        }
    }

    fn verify_new_directory(&self, pin: &ResolvedPath) -> Result<()> {
        self.verify_directory(pin, SLOT_DIRECTORY_MODE)?;
        let mount_id = MountId::from_fd(pin.as_fd()).map_err(linux_error)?;
        if mount_id != self.anchor_mount_id {
            return Err(corrupt(
                "destination slot is outside the attachment-anchor mount",
            ));
        }
        Ok(())
    }

    fn verify_directory(&self, pin: &ResolvedPath, expected_mode: u32) -> Result<()> {
        let stat = rustix::fs::fstat(pin.as_fd()).map_err(kernel_error)?;
        if pin.identity().file_type != FileType::Directory
            || stat.st_uid != self.root_owner
            || stat.st_mode & 0o7777 != expected_mode
        {
            return Err(corrupt(
                "destination-slot directory ownership or mode changed",
            ));
        }
        Ok(())
    }

    fn verify_physical_record(&self, record: &Record, pin: &ResolvedPath) -> Result<()> {
        self.verify_new_directory(pin)?;
        let identity = pin.identity();
        let mount_id = MountId::from_fd(pin.as_fd()).map_err(linux_error)?;
        if identity.device != record.slot_device
            || identity.inode != record.slot_inode
            || mount_id.get() != record.anchor_mount_id
        {
            return Err(corrupt("destination-slot physical identity changed"));
        }
        Ok(())
    }

    fn verify_ready_pin(&self, key: &SlotKey, record: &Record) -> Result<()> {
        let pin = self
            .pins
            .get(key)
            .ok_or_else(|| corrupt("ready destination slot is not pinned"))?;
        self.verify_physical_record(record, pin)
    }

    fn require_capacity(&self) -> Result<()> {
        if self.records.len() >= MAXIMUM_SLOT_RESOURCES {
            Err(invalid("destination-slot resource capacity is exhausted"))
        } else {
            Ok(())
        }
    }

    fn require_unused_operation(&self, operation_id: OperationId) -> Result<()> {
        if self.records.values().any(|record| {
            record.materialize_operation == operation_id
                || record.rematerialize_operation == Some(operation_id)
                || record.reap_operation == Some(operation_id)
        }) {
            Err(conflict("destination-slot operation identity was reused"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SlotKey {
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    namespace_generation: u64,
    slot_id: [u8; 16],
}

impl SlotKey {
    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(56);
        bytes.extend_from_slice(&self.sandbox_id);
        bytes.extend_from_slice(&self.incarnation_id);
        bytes.extend_from_slice(&self.namespace_generation.to_be_bytes());
        bytes.extend_from_slice(&self.slot_id);
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    phase: DestinationSlotResourcePhaseV1,
    kernel_boot_id: [u8; 16],
    binding: DestinationSlotBindingV1,
    materialize_operation: OperationId,
    materialize_request: ObjectDigest,
    rematerialize_operation: Option<OperationId>,
    rematerialize_request: Option<ObjectDigest>,
    rematerialize_predecessor: Option<ObjectDigest>,
    reap_operation: Option<OperationId>,
    reap_request: Option<ObjectDigest>,
    expected_materialization: Option<ObjectDigest>,
    slot_device: u64,
    slot_inode: u64,
    anchor_mount_id: u64,
    digest: [u8; 32],
}

impl Record {
    fn materializing(
        kernel_boot_id: [u8; 16],
        binding: DestinationSlotBindingV1,
        operation_id: OperationId,
        request_digest: ObjectDigest,
    ) -> Result<Self> {
        let mut value = Self {
            phase: DestinationSlotResourcePhaseV1::Materializing,
            kernel_boot_id,
            binding,
            materialize_operation: operation_id,
            materialize_request: request_digest,
            rematerialize_operation: None,
            rematerialize_request: None,
            rematerialize_predecessor: None,
            reap_operation: None,
            reap_request: None,
            expected_materialization: None,
            slot_device: 0,
            slot_inode: 0,
            anchor_mount_id: 0,
            digest: [0; 32],
        };
        value.digest = value.compute_digest();
        value.validate()?;
        Ok(value)
    }

    fn ready(mut self, identity: FileIdentity, mount_id: MountId) -> Result<Self> {
        self.phase = DestinationSlotResourcePhaseV1::Ready;
        self.slot_device = identity.device;
        self.slot_inode = identity.inode;
        self.anchor_mount_id = mount_id.get();
        self.digest = self.compute_digest();
        self.validate()?;
        Ok(self)
    }

    fn rematerializing(
        mut self,
        kernel_boot_id: [u8; 16],
        request: &DestinationSlotRematerializationV1,
    ) -> Result<Self> {
        self.phase = DestinationSlotResourcePhaseV1::Materializing;
        self.kernel_boot_id = kernel_boot_id;
        self.rematerialize_operation = Some(request.operation_id);
        self.rematerialize_request = Some(request.request_digest);
        self.rematerialize_predecessor = Some(request.expected_resource);
        self.slot_device = 0;
        self.slot_inode = 0;
        self.anchor_mount_id = 0;
        self.digest = self.compute_digest();
        self.validate()?;
        Ok(self)
    }

    fn reaping(mut self, request: &DestinationSlotReapV1) -> Result<Self> {
        self.phase = DestinationSlotResourcePhaseV1::Reaping;
        self.reap_operation = Some(request.operation_id);
        self.reap_request = Some(request.request_digest);
        self.expected_materialization = Some(request.expected_materialization);
        self.digest = self.compute_digest();
        self.validate()?;
        Ok(self)
    }

    fn matches_binding(&self, binding: &DestinationSlotBindingV1) -> bool {
        self.binding == *binding
    }

    fn matches_materialization(&self, request: &DestinationSlotMaterializationV1) -> bool {
        self.matches_binding(&request.binding)
            && self.materialize_operation == request.operation_id
            && self.materialize_request == request.request_digest
            && self.rematerialize_operation.is_none()
    }

    fn matches_rematerialization(&self, request: &DestinationSlotRematerializationV1) -> bool {
        self.matches_binding(&request.binding)
            && self.rematerialize_operation == Some(request.operation_id)
            && self.rematerialize_request == Some(request.request_digest)
            && self.rematerialize_predecessor == Some(request.expected_resource)
    }

    fn matches_reap(&self, request: &DestinationSlotReapV1) -> bool {
        self.matches_binding(&request.binding)
            && self.reap_operation == Some(request.operation_id)
            && self.reap_request == Some(request.request_digest)
            && self.expected_materialization == Some(request.expected_materialization)
    }

    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        let physical_fields = [
            self.slot_device != 0,
            self.slot_inode != 0,
            self.anchor_mount_id != 0,
        ];
        let physical = physical_fields.into_iter().all(|present| present);
        let partial_physical = physical_fields.into_iter().any(|present| present) && !physical;
        let reaping = self.reap_operation.is_some()
            && self.reap_request.is_some()
            && self.expected_materialization.is_some();
        if self.kernel_boot_id == [0; 16]
            || self.materialize_operation.as_bytes() == &[0; 16]
            || self.materialize_request.as_bytes() == &[0; 32]
            || self
                .reap_operation
                .is_some_and(|value| value.as_bytes() == &[0; 16])
            || self
                .reap_request
                .is_some_and(|value| value.as_bytes() == &[0; 32])
            || self
                .expected_materialization
                .is_some_and(|value| value.as_bytes() == &[0; 32])
            || self
                .rematerialize_operation
                .is_some_and(|value| value.as_bytes() == &[0; 16])
            || self
                .rematerialize_request
                .is_some_and(|value| value.as_bytes() == &[0; 32])
            || self
                .rematerialize_predecessor
                .is_some_and(|value| value.as_bytes() == &[0; 32])
            || partial_physical
            || (physical && MountId::new(self.anchor_mount_id).is_err())
            || (self.phase == DestinationSlotResourcePhaseV1::Materializing
                && (physical || reaping))
            || (self.phase == DestinationSlotResourcePhaseV1::Ready && (!physical || reaping))
            || (matches!(
                self.phase,
                DestinationSlotResourcePhaseV1::Reaping | DestinationSlotResourcePhaseV1::Released
            ) && (!physical || !reaping))
            || self.reap_operation.is_some() != self.reap_request.is_some()
            || self.reap_operation.is_some() != self.expected_materialization.is_some()
            || self.rematerialize_operation.is_some() != self.rematerialize_request.is_some()
            || self.rematerialize_operation.is_some() != self.rematerialize_predecessor.is_some()
            || self.reap_operation == Some(self.materialize_operation)
            || self.rematerialize_operation == Some(self.materialize_operation)
            || (reaping && self.reap_operation == self.rematerialize_operation)
            || self.compute_digest() != self.digest
        {
            return Err(corrupt("destination-slot resource record is inconsistent"));
        }
        if reaping {
            let mut ready = self.clone();
            ready.phase = DestinationSlotResourcePhaseV1::Ready;
            ready.reap_operation = None;
            ready.reap_request = None;
            ready.expected_materialization = None;
            ready.digest = ready.compute_digest();
            if self.expected_materialization != Some(ObjectDigest::from_bytes(ready.digest)) {
                return Err(corrupt(
                    "destination-slot reap does not name its exact ready record",
                ));
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(self.encode_fields());
        digest.finalize().into()
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.encode_fields());
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn encode_fields(&self) -> Vec<u8> {
        let has_reap = self.reap_operation.is_some();
        let has_rematerialization = self.rematerialize_operation.is_some();
        let mut bytes = Vec::with_capacity(RECORD_BYTES - 40);
        bytes.push(self.phase as u8);
        bytes.push(u8::from(has_reap));
        bytes.push(u8::from(has_rematerialization));
        bytes.push(0);
        bytes.extend_from_slice(&self.kernel_boot_id);
        bytes.extend_from_slice(&self.binding.sandbox_id);
        bytes.extend_from_slice(&self.binding.incarnation_id);
        bytes.extend_from_slice(&self.binding.assignment_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.binding.desired_generation.to_be_bytes());
        bytes.extend_from_slice(&self.binding.assignment_digest);
        bytes.extend_from_slice(&self.binding.namespace_generation.to_be_bytes());
        bytes.extend_from_slice(self.binding.slot_id.as_bytes());
        bytes.extend_from_slice(self.binding.sandbox_spec.digest().as_bytes());
        bytes.extend_from_slice(&self.binding.sandbox_spec.encoded_size().to_be_bytes());
        bytes.extend_from_slice(self.materialize_operation.as_bytes());
        bytes.extend_from_slice(self.materialize_request.as_bytes());
        bytes.extend_from_slice(
            self.rematerialize_operation
                .map_or([0; 16], |value| *value.as_bytes())
                .as_slice(),
        );
        bytes.extend_from_slice(
            self.rematerialize_request
                .map_or([0; 32], |value| *value.as_bytes())
                .as_slice(),
        );
        bytes.extend_from_slice(
            self.rematerialize_predecessor
                .map_or([0; 32], |value| *value.as_bytes())
                .as_slice(),
        );
        bytes.extend_from_slice(
            self.reap_operation
                .map_or([0; 16], |value| *value.as_bytes())
                .as_slice(),
        );
        bytes.extend_from_slice(
            self.reap_request
                .map_or([0; 32], |value| *value.as_bytes())
                .as_slice(),
        );
        bytes.extend_from_slice(
            self.expected_materialization
                .map_or([0; 32], |value| *value.as_bytes())
                .as_slice(),
        );
        bytes.extend_from_slice(&self.slot_device.to_be_bytes());
        bytes.extend_from_slice(&self.slot_inode.to_be_bytes());
        bytes.extend_from_slice(&self.anchor_mount_id.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RECORD_BYTES {
            return Err(corrupt("destination-slot record length is invalid"));
        }
        let mut bytes = bytes;
        if take::<8>(&mut bytes)? != *MAGIC {
            return Err(corrupt("destination-slot record magic is invalid"));
        }
        let phase = DestinationSlotResourcePhaseV1::from_byte(take::<1>(&mut bytes)?[0])?;
        let has_reap = match take::<1>(&mut bytes)?[0] {
            0 => false,
            1 => true,
            _ => return Err(corrupt("destination-slot record flags are invalid")),
        };
        let has_rematerialization = match take::<1>(&mut bytes)?[0] {
            0 => false,
            1 => true,
            _ => return Err(corrupt("destination-slot record flags are invalid")),
        };
        if take::<1>(&mut bytes)? != [0] {
            return Err(corrupt(
                "destination-slot record reserved bytes are nonzero",
            ));
        }
        let kernel_boot_id = take(&mut bytes)?;
        let sandbox_id = take(&mut bytes)?;
        let incarnation_id = take(&mut bytes)?;
        let assignment_epoch = u64::from_be_bytes(take(&mut bytes)?);
        let desired_generation = u64::from_be_bytes(take(&mut bytes)?);
        let assignment_digest = take(&mut bytes)?;
        let namespace_generation = u64::from_be_bytes(take(&mut bytes)?);
        let slot_id = AttachmentSlotId::from_bytes(take(&mut bytes)?);
        let sandbox_spec_digest = ObjectDigest::from_bytes(take(&mut bytes)?);
        let sandbox_spec_size = u64::from_be_bytes(take(&mut bytes)?);
        let materialize_operation = OperationId::from_bytes(take(&mut bytes)?);
        let materialize_request = ObjectDigest::from_bytes(take(&mut bytes)?);
        let rematerialize_operation_bytes = take(&mut bytes)?;
        let rematerialize_request_bytes = take(&mut bytes)?;
        let rematerialize_predecessor_bytes = take(&mut bytes)?;
        let reap_operation_bytes = take(&mut bytes)?;
        let reap_request_bytes = take(&mut bytes)?;
        let expected_materialization_bytes = take(&mut bytes)?;
        let slot_device = u64::from_be_bytes(take(&mut bytes)?);
        let slot_inode = u64::from_be_bytes(take(&mut bytes)?);
        let anchor_mount_id = u64::from_be_bytes(take(&mut bytes)?);
        let digest = take(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(corrupt("destination-slot record has trailing bytes"));
        }

        let reap_operation = has_reap.then(|| OperationId::from_bytes(reap_operation_bytes));
        let reap_request = has_reap.then(|| ObjectDigest::from_bytes(reap_request_bytes));
        let expected_materialization =
            has_reap.then(|| ObjectDigest::from_bytes(expected_materialization_bytes));
        let rematerialize_operation =
            has_rematerialization.then(|| OperationId::from_bytes(rematerialize_operation_bytes));
        let rematerialize_request =
            has_rematerialization.then(|| ObjectDigest::from_bytes(rematerialize_request_bytes));
        let rematerialize_predecessor = has_rematerialization
            .then(|| ObjectDigest::from_bytes(rematerialize_predecessor_bytes));
        if (!has_reap
            && (reap_operation_bytes != [0; 16]
                || reap_request_bytes != [0; 32]
                || expected_materialization_bytes != [0; 32]))
            || (!has_rematerialization
                && (rematerialize_operation_bytes != [0; 16]
                    || rematerialize_request_bytes != [0; 32]
                    || rematerialize_predecessor_bytes != [0; 32]))
            || sandbox_spec_size == 0
        {
            return Err(corrupt(
                "destination-slot optional record fields are invalid",
            ));
        }
        let media_type = MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned())
            .map_err(|_| corrupt("sandbox specification media type is unavailable"))?;
        let binding = DestinationSlotBindingV1 {
            sandbox_id,
            incarnation_id,
            assignment_epoch,
            desired_generation,
            assignment_digest,
            namespace_generation,
            sandbox_spec: ObjectDescriptor::new(media_type, sandbox_spec_digest, sandbox_spec_size),
            slot_id,
        };
        let value = Self {
            phase,
            kernel_boot_id,
            binding,
            materialize_operation,
            materialize_request,
            rematerialize_operation,
            rematerialize_request,
            rematerialize_predecessor,
            reap_operation,
            reap_request,
            expected_materialization,
            slot_device,
            slot_inode,
            anchor_mount_id,
            digest,
        };
        value.validate()?;
        Ok(value)
    }
}

fn load_records(journal: &Journal) -> Result<BTreeMap<SlotKey, Record>> {
    let mut records = BTreeMap::new();
    let mut operations = BTreeSet::new();
    for (key_bytes, value) in journal.records(RecordNamespace::MountDestinationSlot) {
        if records.len() >= MAXIMUM_SLOT_RESOURCES || key_bytes.len() != 56 {
            return Err(corrupt(
                "destination-slot resource namespace exceeds its bound",
            ));
        }
        let record = Record::decode(value)?;
        let key = record.binding.key();
        if key.encode() != key_bytes
            || !operations.insert(record.materialize_operation)
            || record
                .rematerialize_operation
                .is_some_and(|operation| !operations.insert(operation))
            || record
                .reap_operation
                .is_some_and(|operation| !operations.insert(operation))
            || records.insert(key, record).is_some()
        {
            return Err(corrupt(
                "destination-slot resource namespace is not canonical",
            ));
        }
    }
    Ok(records)
}

fn commit_record(journal: &mut Journal, record: &Record) -> Result<()> {
    record.validate()?;
    let mut transaction_id: [u8; 16] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update([record.phase as u8])
        .chain_update(record.digest)
        .finalize()[..16]
        .try_into()
        .map_err(|_| corrupt("destination-slot transaction identity is invalid"))?;
    if transaction_id == [0; 16] {
        transaction_id[15] = 1;
    }
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::MountDestinationSlot,
            record.binding.key().encode(),
            record.encode(),
        )],
    )?;
    journal.commit(&transaction)?;
    Ok(())
}

fn sandbox_spec_descriptor_for(bytes: &[u8]) -> Result<ObjectDescriptor> {
    let media_type = MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned())
        .map_err(|_| corrupt("sandbox specification media type is unavailable"))?;
    Ok(descriptor_for_bytes(media_type, bytes))
}

pub(crate) fn catalog_relative_path(
    sandbox_id: &[u8; 16],
    incarnation_id: &[u8; 16],
    namespace_generation: u64,
    slot_id: &[u8; 16],
) -> PathBuf {
    Path::new(SLOT_ROOT_COMPONENT)
        .join(encode_hex(sandbox_id))
        .join(encode_hex(incarnation_id))
        .join(format!("{namespace_generation:016x}"))
        .join(encode_hex(slot_id))
}

fn sync_directory(directory: &BeneathRoot) -> Result<()> {
    let descriptor = rustix::fs::openat(
        directory.as_fd(),
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(kernel_error)?;
    rustix::fs::fsync(&descriptor).map_err(kernel_error)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N]> {
    let (head, tail) = bytes
        .split_at_checked(N)
        .ok_or_else(|| corrupt("destination-slot record is truncated"))?;
    *bytes = tail;
    head.try_into()
        .map_err(|_| corrupt("destination-slot fixed field has invalid length"))
}

fn invalid(message: &'static str) -> MountError {
    MountError::Worker(message.to_owned())
}

fn conflict(message: &'static str) -> MountError {
    MountError::Fence(message)
}

fn corrupt(message: &'static str) -> MountError {
    MountError::State(message.to_owned())
}

fn kernel_error(error: rustix::io::Errno) -> MountError {
    MountError::Worker(format!(
        "destination-slot filesystem operation failed: {error}"
    ))
}

fn linux_error(error: aos_sandbox_linux::Error) -> MountError {
    MountError::Worker(format!(
        "destination-slot descriptor operation failed: {error}"
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::num::NonZeroU32;

    use aos_proto::aos::sandbox::local::v1::{
        ApplyMountRequest, AssignmentFence, Audience, Descriptor, MountAction, MountAttributes,
        MountSourceConsistency, RequestHeader,
    };
    use aos_sandbox::journal::JournalLimits;
    use aos_sandbox_core::model::{
        IdentityProfile, Limit, LimitDimension, LimitValue, NetworkKind, NetworkProfile,
        ResourceProfile, UnmappableIdentityPolicy,
    };
    use aos_sandbox_core::{FeatureRef, ViewId};
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_mount_request};
    use buffa::Message as _;
    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        directory: TempDir,
        journal: Journal,
        store: DestinationSlotStoreV1,
        binding: DestinationSlotBindingV1,
        materialization: DestinationSlotMaterializationV1,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            std::fs::set_permissions(
                directory.path(),
                std::fs::Permissions::from_mode(PARENT_DIRECTORY_MODE),
            )
            .unwrap();
            let (journal, _) = Journal::open(
                directory.path().join("slot.journal"),
                JournalLimits::default(),
            )
            .unwrap();
            let store = DestinationSlotStoreV1::recover(
                directory.path(),
                rustix::process::getuid().as_raw(),
                &journal,
            )
            .unwrap();
            let slot_id = AttachmentSlotId::from_bytes([4; 16]);
            let spec = sandbox_spec(vec![slot_id]);
            let descriptor = sandbox_spec_descriptor_for(&encode_sandbox_spec(&spec)).unwrap();
            let binding =
                DestinationSlotBindingV1::new(&fence(), 7, &spec, descriptor, slot_id).unwrap();
            let materialization = DestinationSlotMaterializationV1::new(
                binding.clone(),
                OperationId::from_bytes([10; 16]),
                ObjectDigest::from_bytes([11; 32]),
            )
            .unwrap();
            Self {
                directory,
                journal,
                store,
                binding,
                materialization,
            }
        }

        fn reopen(self) -> Self {
            let Self {
                directory,
                journal,
                store,
                binding,
                materialization,
            } = self;
            drop(store);
            drop(journal);
            let (journal, _) = Journal::open(
                directory.path().join("slot.journal"),
                JournalLimits::default(),
            )
            .unwrap();
            let store = DestinationSlotStoreV1::recover(
                directory.path(),
                rustix::process::getuid().as_raw(),
                &journal,
            )
            .unwrap();
            Self {
                directory,
                journal,
                store,
                binding,
                materialization,
            }
        }

        fn reap(&self, expected: ObjectDigest, byte: u8) -> DestinationSlotReapV1 {
            DestinationSlotReapV1::new(
                self.binding.clone(),
                OperationId::from_bytes([byte; 16]),
                ObjectDigest::from_bytes([byte.wrapping_add(1); 32]),
                expected,
            )
            .unwrap()
        }
    }

    #[test]
    fn exact_specification_declaration_derives_only_fixed_paths() {
        let slot_id = AttachmentSlotId::from_bytes([4; 16]);
        let spec = sandbox_spec(vec![slot_id]);
        let descriptor = sandbox_spec_descriptor_for(&encode_sandbox_spec(&spec)).unwrap();
        let binding =
            DestinationSlotBindingV1::new(&fence(), 7, &spec, descriptor.clone(), slot_id).unwrap();

        assert_eq!(
            binding.catalog_relative_path(),
            PathBuf::from(format!(
                "slots/{}/{}/{}/{}",
                "02".repeat(16),
                "03".repeat(16),
                "0000000000000007",
                "04".repeat(16)
            ))
        );
        assert_eq!(
            binding.payload_relative_path(),
            PathBuf::from(format!("run/aos/attachments/{}", "04".repeat(16)))
        );

        let undeclared = sandbox_spec(vec![AttachmentSlotId::from_bytes([5; 16])]);
        let undeclared_descriptor =
            sandbox_spec_descriptor_for(&encode_sandbox_spec(&undeclared)).unwrap();
        assert!(
            DestinationSlotBindingV1::new(
                &fence(),
                7,
                &undeclared,
                undeclared_descriptor,
                slot_id,
            )
                .is_err()
        );
        assert!(
            DestinationSlotBindingV1::new(&fence(), 7, &spec, descriptor, slot_id)
                .map(|mut value| {
                    value.sandbox_spec = object_descriptor(PortableMediaType::View, 9);
                    value
                })
                .and_then(|value| DestinationSlotMaterializationV1::new(
                    value,
                    OperationId::from_bytes([1; 16]),
                    ObjectDigest::from_bytes([2; 32]),
                ))
                .is_err()
        );
    }

    #[test]
    fn materialization_persists_exact_identity_and_replays_with_a_live_pin() {
        let mut fixture = Fixture::new();
        let (ready, outcome) = fixture
            .store
            .materialize(&mut fixture.journal, &fixture.materialization)
            .unwrap();
        assert_eq!(outcome, DestinationSlotMutationOutcomeV1::Recorded);
        assert_eq!(ready.phase(), DestinationSlotResourcePhaseV1::Ready);
        assert_eq!(ready.binding(), &fixture.binding);
        assert!(ready.file_identity().is_some());
        assert!(ready.anchor_mount_id().is_some());

        let path = fixture
            .directory
            .path()
            .join(fixture.binding.catalog_relative_path());
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.permissions().mode() & 0o7777, SLOT_DIRECTORY_MODE);
        let resolved = fixture.store.resolve(&fixture.binding).unwrap();
        assert_eq!(resolved.identity(), ready.file_identity().unwrap());
        assert_eq!(resolved.resource().record_digest(), ready.record_digest());

        let fixture = fixture.reopen();
        let recovered = fixture.store.resolve(&fixture.binding).unwrap();
        assert_eq!(recovered.identity(), ready.file_identity().unwrap());
        let mut fixture = fixture;
        let (replayed, outcome) = fixture
            .store
            .materialize(&mut fixture.journal, &fixture.materialization)
            .unwrap();
        assert_eq!(outcome, DestinationSlotMutationOutcomeV1::Replay);
        assert_eq!(replayed.record_digest(), ready.record_digest());
    }

    #[test]
    fn operation_and_binding_equivocation_fail_without_new_directories() {
        let mut fixture = Fixture::new();
        fixture
            .store
            .materialize(&mut fixture.journal, &fixture.materialization)
            .unwrap();

        let different_request = DestinationSlotMaterializationV1::new(
            fixture.binding.clone(),
            OperationId::from_bytes([10; 16]),
            ObjectDigest::from_bytes([12; 32]),
        )
        .unwrap();
        assert!(matches!(
            fixture
                .store
                .materialize(&mut fixture.journal, &different_request),
            Err(MountError::Fence(_))
        ));

        let other_slot = AttachmentSlotId::from_bytes([5; 16]);
        let spec = sandbox_spec(vec![other_slot]);
        let descriptor = sandbox_spec_descriptor_for(&encode_sandbox_spec(&spec)).unwrap();
        let other_binding =
            DestinationSlotBindingV1::new(&fence(), 7, &spec, descriptor, other_slot).unwrap();
        let reused_operation = DestinationSlotMaterializationV1::new(
            other_binding.clone(),
            OperationId::from_bytes([10; 16]),
            ObjectDigest::from_bytes([13; 32]),
        )
        .unwrap();
        assert!(matches!(
            fixture
                .store
                .materialize(&mut fixture.journal, &reused_operation),
            Err(MountError::Fence(_))
        ));
        assert!(
            !fixture
                .directory
                .path()
                .join(other_binding.catalog_relative_path())
                .exists()
        );
    }

    #[test]
    fn reaping_requires_exact_ready_digest_and_two_unused_observations() {
        let mut fixture = Fixture::new();
        let (ready, _) = fixture
            .store
            .materialize(&mut fixture.journal, &fixture.materialization)
            .unwrap();
        let stale = fixture.reap(ObjectDigest::from_bytes([90; 32]), 20);
        assert!(matches!(
            fixture
                .store
                .reap(&mut fixture.journal, &stale, |_| Ok(true)),
            Err(MountError::Fence(_))
        ));

        let reap = fixture.reap(ready.record_digest(), 20);
        let mut observations = [true, false].into_iter();
        assert!(matches!(
            fixture.store.reap(&mut fixture.journal, &reap, |_| {
                Ok(observations.next().unwrap())
            }),
            Err(MountError::Fence(_))
        ));
        assert_eq!(
            fixture.store.get(&fixture.binding).unwrap().phase(),
            DestinationSlotResourcePhaseV1::Reaping
        );
        assert!(fixture.store.resolve(&fixture.binding).is_err());

        let (released, outcome) = fixture
            .store
            .reap(&mut fixture.journal, &reap, |_| Ok(true))
            .unwrap();
        assert_eq!(outcome, DestinationSlotMutationOutcomeV1::Recorded);
        assert_eq!(released.phase(), DestinationSlotResourcePhaseV1::Released);
        assert!(
            !fixture
                .directory
                .path()
                .join(fixture.binding.catalog_relative_path())
                .exists()
        );
        assert!(fixture.store.resolve(&fixture.binding).is_err());

        let (replayed, outcome) = fixture
            .store
            .reap(&mut fixture.journal, &reap, |_| {
                panic!("replay performed usage I/O")
            })
            .unwrap();
        assert_eq!(outcome, DestinationSlotMutationOutcomeV1::Replay);
        assert_eq!(replayed.record_digest(), released.record_digest());
        assert!(matches!(
            fixture
                .store
                .materialize(&mut fixture.journal, &fixture.materialization),
            Err(MountError::Fence(_))
        ));
    }

    #[test]
    fn interrupted_materialization_resumes_before_and_after_mkdir() {
        for directory_exists in [false, true] {
            let mut fixture = Fixture::new();
            let record = Record::materializing(
                fixture.store.kernel_boot_id,
                fixture.binding.clone(),
                fixture.materialization.operation_id,
                fixture.materialization.request_digest,
            )
            .unwrap();
            commit_record(&mut fixture.journal, &record).unwrap();
            fixture.store.records.insert(fixture.binding.key(), record);
            if directory_exists {
                let _pin = fixture
                    .store
                    .materialize_directory(&fixture.binding)
                    .unwrap();
            }

            let mut fixture = fixture.reopen();
            assert_eq!(
                fixture.store.get(&fixture.binding).unwrap().phase(),
                DestinationSlotResourcePhaseV1::Materializing
            );
            let (ready, outcome) = fixture
                .store
                .materialize(&mut fixture.journal, &fixture.materialization)
                .unwrap();
            assert_eq!(outcome, DestinationSlotMutationOutcomeV1::Recorded);
            assert_eq!(ready.phase(), DestinationSlotResourcePhaseV1::Ready);
            fixture.store.resolve(&fixture.binding).unwrap();
        }
    }

    #[test]
    fn stale_boot_materializing_restarts_the_exact_operation() {
        let mut fixture = Fixture::new();
        let mut stale = Record::materializing(
            fixture.store.kernel_boot_id,
            fixture.binding.clone(),
            fixture.materialization.operation_id,
            fixture.materialization.request_digest,
        )
        .unwrap();
        stale.kernel_boot_id[0] ^= 1;
        stale.digest = stale.compute_digest();
        stale.validate().unwrap();
        commit_record(&mut fixture.journal, &stale).unwrap();
        fixture.store.records.insert(fixture.binding.key(), stale);

        let mut fixture = fixture.reopen();
        let (ready, outcome) = fixture
            .store
            .materialize(&mut fixture.journal, &fixture.materialization)
            .unwrap();

        assert_eq!(outcome, DestinationSlotMutationOutcomeV1::Recorded);
        assert_eq!(ready.phase(), DestinationSlotResourcePhaseV1::Ready);
        assert_eq!(ready.kernel_boot_id(), &fixture.store.kernel_boot_id);
        assert_eq!(
            ready.materialization_operation(),
            fixture.materialization.operation_id
        );
        assert_eq!(
            ready.materialization_request(),
            fixture.materialization.request_digest
        );
        fixture.store.resolve(&fixture.binding).unwrap();
    }

    #[test]
    fn interrupted_reap_resumes_after_directory_removal() {
        let mut fixture = Fixture::new();
        let (ready, _) = fixture
            .store
            .materialize(&mut fixture.journal, &fixture.materialization)
            .unwrap();
        let reap = fixture.reap(ready.record_digest(), 20);
        let current = fixture
            .store
            .records
            .get(&fixture.binding.key())
            .cloned()
            .unwrap();
        let reaping = current.reaping(&reap).unwrap();
        commit_record(&mut fixture.journal, &reaping).unwrap();
        fixture
            .store
            .records
            .insert(fixture.binding.key(), reaping.clone());
        fixture.store.remove_directory(&reaping).unwrap();

        let mut fixture = fixture.reopen();
        assert_eq!(
            fixture.store.get(&fixture.binding).unwrap().phase(),
            DestinationSlotResourcePhaseV1::Reaping
        );
        let (released, outcome) = fixture
            .store
            .reap(&mut fixture.journal, &reap, |_| Ok(true))
            .unwrap();
        assert_eq!(outcome, DestinationSlotMutationOutcomeV1::Recorded);
        assert_eq!(released.phase(), DestinationSlotResourcePhaseV1::Released);
    }

    #[test]
    fn same_boot_missing_or_replaced_ready_directory_blocks_recovery() {
        for replacement in [false, true] {
            let mut fixture = Fixture::new();
            fixture
                .store
                .materialize(&mut fixture.journal, &fixture.materialization)
                .unwrap();
            let path = fixture
                .directory
                .path()
                .join(fixture.binding.catalog_relative_path());
            std::fs::remove_dir(&path).unwrap();
            if replacement {
                std::fs::create_dir(&path).unwrap();
                std::fs::set_permissions(
                    &path,
                    std::fs::Permissions::from_mode(SLOT_DIRECTORY_MODE),
                )
                .unwrap();
            }

            let Fixture {
                directory,
                journal,
                store,
                ..
            } = fixture;
            drop(store);
            drop(journal);
            let (journal, _) = Journal::open(
                directory.path().join("slot.journal"),
                JournalLimits::default(),
            )
            .unwrap();
            assert!(
                DestinationSlotStoreV1::recover(
                    directory.path(),
                    rustix::process::getuid().as_raw(),
                    &journal,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn stale_boot_record_exposes_no_pin_and_can_be_tombstoned() {
        let mut fixture = Fixture::new();
        let (ready, _) = fixture
            .store
            .materialize(&mut fixture.journal, &fixture.materialization)
            .unwrap();
        let path = fixture
            .directory
            .path()
            .join(fixture.binding.catalog_relative_path());
        std::fs::remove_dir(&path).unwrap();
        let mut stale = fixture
            .store
            .records
            .get(&fixture.binding.key())
            .cloned()
            .unwrap();
        stale.kernel_boot_id[0] ^= 1;
        stale.digest = stale.compute_digest();
        stale.validate().unwrap();
        commit_record(&mut fixture.journal, &stale).unwrap();
        fixture
            .store
            .records
            .insert(fixture.binding.key(), stale.clone());

        let mut fixture = fixture.reopen();
        assert!(fixture.store.resolve(&fixture.binding).is_err());
        let reap = fixture.reap(ObjectDigest::from_bytes(stale.digest), 20);
        let (released, _) = fixture
            .store
            .reap(&mut fixture.journal, &reap, |_| Ok(true))
            .unwrap();
        assert_eq!(released.phase(), DestinationSlotResourcePhaseV1::Released);
        assert_eq!(released.file_identity(), ready.file_identity());
    }

    #[test]
    fn stale_ready_rematerialization_is_exact_replayable_and_chainable() {
        let mut fixture = Fixture::new();
        let (original, _) = fixture
            .store
            .materialize(&mut fixture.journal, &fixture.materialization)
            .unwrap();
        let path = fixture
            .directory
            .path()
            .join(fixture.binding.catalog_relative_path());
        std::fs::remove_dir(&path).unwrap();

        let mut stale = fixture
            .store
            .records
            .get(&fixture.binding.key())
            .cloned()
            .unwrap();
        stale.kernel_boot_id[0] ^= 1;
        stale.digest = stale.compute_digest();
        stale.validate().unwrap();
        commit_record(&mut fixture.journal, &stale).unwrap();
        fixture
            .store
            .records
            .insert(fixture.binding.key(), stale.clone());

        let mut fixture = fixture.reopen();
        let request = DestinationSlotRematerializationV1::new(
            fixture.binding.clone(),
            OperationId::from_bytes([30; 16]),
            ObjectDigest::from_bytes([31; 32]),
            ObjectDigest::from_bytes(stale.digest),
        )
        .unwrap();
        let mut unused_checks = 0;
        let interrupted = fixture.store.rematerialize_guarded(
            &mut fixture.journal,
            &request,
            |_| {
                unused_checks += 1;
                Ok(true)
            },
            || Err(conflict("simulated interruption after durable admission")),
        );
        assert!(interrupted.is_err());
        assert_eq!(unused_checks, 2);
        assert!(!path.exists());
        assert_eq!(
            fixture.store.get(&fixture.binding).unwrap().phase(),
            DestinationSlotResourcePhaseV1::Materializing
        );

        let (recovered, outcome) = fixture
            .store
            .rematerialize_guarded(
                &mut fixture.journal,
                &request,
                |_| {
                    unused_checks += 1;
                    Ok(true)
                },
                || Ok(()),
            )
            .unwrap();

        assert_eq!(outcome, DestinationSlotMutationOutcomeV1::Recorded);
        assert_eq!(unused_checks, 3);
        assert_eq!(recovered.phase(), DestinationSlotResourcePhaseV1::Ready);
        assert_eq!(recovered.kernel_boot_id(), &fixture.store.kernel_boot_id);
        assert_eq!(
            recovered.materialization_operation(),
            original.materialization_operation()
        );
        assert_eq!(
            recovered.rematerialization_operation(),
            Some(OperationId::from_bytes([30; 16]))
        );
        assert_eq!(
            recovered.rematerialization_predecessor(),
            Some(ObjectDigest::from_bytes(stale.digest))
        );
        fixture.store.resolve(&fixture.binding).unwrap();

        let (replayed, outcome) = fixture
            .store
            .rematerialize_guarded(
                &mut fixture.journal,
                &request,
                |_| panic!("replay performed usage I/O"),
                || panic!("replay performed filesystem I/O"),
            )
            .unwrap();
        assert_eq!(outcome, DestinationSlotMutationOutcomeV1::Replay);
        assert_eq!(replayed.record_digest(), recovered.record_digest());

        std::fs::remove_dir(&path).unwrap();
        let mut stale_again = fixture
            .store
            .records
            .get(&fixture.binding.key())
            .cloned()
            .unwrap();
        stale_again.kernel_boot_id[0] ^= 1;
        stale_again.digest = stale_again.compute_digest();
        stale_again.validate().unwrap();
        commit_record(&mut fixture.journal, &stale_again).unwrap();
        fixture
            .store
            .records
            .insert(fixture.binding.key(), stale_again.clone());

        let mut fixture = fixture.reopen();
        let next = DestinationSlotRematerializationV1::new(
            fixture.binding.clone(),
            OperationId::from_bytes([32; 16]),
            ObjectDigest::from_bytes([33; 32]),
            ObjectDigest::from_bytes(stale_again.digest),
        )
        .unwrap();
        let (recovered_again, _) = fixture
            .store
            .rematerialize_guarded(&mut fixture.journal, &next, |_| Ok(true), || Ok(()))
            .unwrap();
        assert_eq!(
            recovered_again.materialization_operation(),
            original.materialization_operation()
        );
        assert_eq!(
            recovered_again.rematerialization_operation(),
            Some(OperationId::from_bytes([32; 16]))
        );
        assert_eq!(
            recovered_again.rematerialization_predecessor(),
            Some(ObjectDigest::from_bytes(stale_again.digest))
        );
    }

    #[test]
    fn record_codec_rejects_every_fixed_field_tamper() {
        let fixture = Fixture::new();
        let materializing = Record::materializing(
            fixture.store.kernel_boot_id,
            fixture.binding,
            fixture.materialization.operation_id,
            fixture.materialization.request_digest,
        )
        .unwrap();
        let encoded = materializing.encode();
        assert_eq!(encoded.len(), RECORD_BYTES);
        assert_eq!(Record::decode(&encoded).unwrap(), materializing);

        for index in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(Record::decode(&changed).is_err(), "accepted byte {index}");
        }
    }

    fn fence() -> ValidatedAssignmentFence {
        *decode_mount_request(
            &mount_request(),
            PeerCredentials {
                uid: 811,
                gid: 811,
                pid: Some(42),
            },
            PeerPolicy {
                uid: 811,
                gid: Some(811),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            1,
        )
        .unwrap()
        .fence()
    }

    fn mount_request() -> Vec<u8> {
        ApplyMountRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 2,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 4096,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16],
                incarnation_id: vec![3; 16],
                assignment_epoch: 4,
                desired_generation: 5,
                assignment_digest: vec![6; 32],
                ..Default::default()
            })
            .into(),
            action: MountAction::MOUNT_ACTION_CREATE_DETACHED.into(),
            attachment_id: vec![7; 16],
            destination_slot_id: vec![4; 16],
            view_revision: Some(Descriptor {
                media_type: PortableMediaType::View.as_str().to_owned(),
                sha256: vec![8; 32],
                encoded_size: 9,
                ..Default::default()
            })
            .into(),
            attributes: Some(MountAttributes {
                read_only: true,
                no_exec: true,
                no_suid: true,
                no_device: true,
                no_atime: true,
                mutation_mode: 0,
                ..Default::default()
            })
            .into(),
            source_generation: 1,
            namespace_generation: 7,
            desired_attachment_generation: 1,
            resource_attachment_generation: 1,
            source_view_id: ViewId::from_bytes([9; 16]).as_bytes().to_vec(),
            source_consistency: MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
                .into(),
            attachment_lease_id: vec![10; 16],
            attachment_lease_issued_seconds: 10,
            attachment_lease_expires_seconds: 20,
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn sandbox_spec(slots: Vec<AttachmentSlotId>) -> SandboxSpec {
        SandboxSpec::new(
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            IdentityProfile::PrivateUserns {
                id_range_size: NonZeroU32::new(65_536).unwrap(),
                unmappable_policy: UnmappableIdentityPolicy::Reject,
                required_features: Vec::new(),
            },
            ResourceProfile::new(vec![Limit::new(
                LimitDimension::Memory,
                LimitValue::Bounded(1 << 20),
                FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0).unwrap(),
            )])
            .unwrap(),
            object_descriptor(PortableMediaType::Environment, 1),
            object_descriptor(PortableMediaType::View, 2),
            slots,
            NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(),
            Vec::new(),
        )
        .unwrap()
    }

    fn object_descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([byte; 32]),
            1,
        )
    }
}
