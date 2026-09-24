//! Bounded private protocol for complete workspace-catalog observation.
//!
//! The broker composes this request only from authenticated transaction state,
//! a structurally validated workspace catalog, and retained host descriptors.
//! The fixed observer receives those descriptors on frame zero and validates
//! two complete ZFS inventories around two complete pin-root inventories. Raw
//! ZFS output and mount records never return to the broker.
//!
//! ```text
//! request = AOSZCAO1 | version:u16 | reserved:u16 | fixed-bindings
//!           | root-count:u32 | object-count:u32 | target-count:u32
//!           | roots | allowed-objects | targets
//! version 2 appends one canonical AOSGRP01 proof selecting an exact present
//! target for detached-root export; version 1 never carries a descriptor back.
//! result  = AOSZCAR1 | version:u16 | reserved:u16 | request-digest
//!           | nonce | deadline | custody | counts | five digests | matched:u8
//! frame   = AOSZCFR1 | version:u16 | flags:u16 | transfer-digest
//!           | total:u32 | offset:u32 | content-length:u16 | content
//! ```

use std::collections::BTreeSet;
use std::os::fd::OwnedFd;

use aos_sandbox_agent::guest_root_publication::{
    CONCRETE_GUEST_FEATURE_MASK_V1, GuestRootPublicationProofV1,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject;
use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;
use sha2::{Digest as _, Sha256};

use crate::ZfsWorkerError;
use crate::catalog::valid_dataset_name;
use crate::pin_worker::verify_same_live_subject;

const REQUEST_MAGIC: &[u8; 8] = b"AOSZCAO1";
const RESULT_MAGIC: &[u8; 8] = b"AOSZCAR1";
const FRAME_MAGIC: &[u8; 8] = b"AOSZCFR1";
const WIRE_VERSION: u16 = 1;
const ROOT_EXPORT_WIRE_VERSION: u16 = 2;
const REQUEST_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.storage.workspace-catalog-observation-request.v1\0";
const PHYSICAL_PLAN_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.storage.workspace-catalog-activation-plan.v1\0";
const COMBINED_OBSERVATION_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.storage.workspace-catalog-combined-observation.v1\0";
const FRAME_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.storage.workspace-catalog-observation-transfer.v1\0";
const FRAME_FIRST: u16 = 1;
const FRAME_LAST: u16 = 1 << 1;
const FRAME_KNOWN_FLAGS: u16 = FRAME_FIRST | FRAME_LAST;
const FRAME_HEADER_BYTES: usize = 8 + 2 + 2 + 32 + 4 + 4 + 2;
const MAXIMUM_FRAME_CONTENT_BYTES: usize =
    MAXIMUM_CATALOG_OBSERVATION_PACKET_BYTES - FRAME_HEADER_BYTES;
const REQUEST_FIXED_BYTES: usize = 368;
const RESULT_BYTES: usize = 313;
const MAXIMUM_ROOT_NAME_BYTES: usize = 253;
const MAXIMUM_DATASET_NAME_BYTES: usize = 255;
const MAXIMUM_CATALOG_ROWS: usize = 16_384;

pub(crate) const MAXIMUM_CATALOG_OBSERVATION_REQUEST_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const MAXIMUM_CATALOG_OBSERVATION_PACKET_BYTES: usize = 4096;
pub(crate) const MAXIMUM_CATALOG_OBSERVATION_RESULT_BYTES: usize = RESULT_BYTES;
pub(crate) const CATALOG_OBSERVATION_DESCRIPTOR_COUNT: usize = 2;

/// Binds a request to the exact retained initial host scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkspaceCatalogCustodyBindingV1 {
    kernel_boot_id: [u8; 16],
    mount_namespace_device: u64,
    mount_namespace_inode: u64,
    pin_root_mount_id: u64,
    pin_root_device: u64,
    pin_root_inode: u64,
}

impl WorkspaceCatalogCustodyBindingV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        kernel_boot_id: [u8; 16],
        mount_namespace_device: u64,
        mount_namespace_inode: u64,
        pin_root_mount_id: u64,
        pin_root_device: u64,
        pin_root_inode: u64,
    ) -> Result<Self, ZfsWorkerError> {
        let binding = Self {
            kernel_boot_id,
            mount_namespace_device,
            mount_namespace_inode,
            pin_root_mount_id,
            pin_root_device,
            pin_root_inode,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(self) -> Result<(), ZfsWorkerError> {
        if self.kernel_boot_id == [0; 16]
            || self.mount_namespace_device == 0
            || self.mount_namespace_inode == 0
            || self.pin_root_mount_id == 0
            || self.pin_root_device == 0
            || self.pin_root_inode == 0
        {
            return Err(protocol("catalog observation custody binding is invalid"));
        }
        Ok(())
    }

    pub(crate) const fn kernel_boot_id(self) -> [u8; 16] {
        self.kernel_boot_id
    }

    pub(crate) const fn mount_namespace_device(self) -> u64 {
        self.mount_namespace_device
    }

    pub(crate) const fn mount_namespace_inode(self) -> u64 {
        self.mount_namespace_inode
    }

    pub(crate) const fn pin_root_mount_id(self) -> u64 {
        self.pin_root_mount_id
    }

    pub(crate) const fn pin_root_device(self) -> u64 {
        self.pin_root_device
    }

    pub(crate) const fn pin_root_inode(self) -> u64 {
        self.pin_root_inode
    }
}

/// Names one authenticated managed root exactly once in the request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkspaceCatalogObservationRootV1 {
    name: String,
    guid: u64,
}

/// Classifies one authenticated object inside a protected managed root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceCatalogObservationObjectKindV1 {
    /// The authenticated object is a ZFS filesystem.
    Filesystem,
    /// The authenticated object is a ZFS volume.
    Volume,
}

/// Allows one exact authenticated object beneath a protected managed root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkspaceCatalogObservationObjectV1 {
    root_index: u16,
    name: String,
    kind: WorkspaceCatalogObservationObjectKindV1,
    guid: u64,
}

impl WorkspaceCatalogObservationObjectV1 {
    pub(crate) fn new(
        root_index: u16,
        name: String,
        kind: WorkspaceCatalogObservationObjectKindV1,
        guid: u64,
    ) -> Result<Self, ZfsWorkerError> {
        if name.len() > MAXIMUM_DATASET_NAME_BYTES || !valid_dataset_name(&name) || guid == 0 {
            return Err(protocol("catalog observation allowed object is invalid"));
        }
        Ok(Self {
            root_index,
            name,
            kind,
            guid,
        })
    }

    pub(crate) const fn root_index(&self) -> u16 {
        self.root_index
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn kind(&self) -> WorkspaceCatalogObservationObjectKindV1 {
        self.kind
    }

    pub(crate) const fn guid(&self) -> u64 {
        self.guid
    }
}

impl WorkspaceCatalogObservationRootV1 {
    pub(crate) fn new(name: String, guid: u64) -> Result<Self, ZfsWorkerError> {
        if name.len() > MAXIMUM_ROOT_NAME_BYTES || !valid_dataset_name(&name) || guid == 0 {
            return Err(protocol("catalog observation root is invalid"));
        }
        Ok(Self { name, guid })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn guid(&self) -> u64 {
        self.guid
    }
}

/// Selects the exact terminal physical state required for one workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceCatalogObservationExpectationV1 {
    /// The exact dataset and full-filesystem mount must both exist.
    Present {
        mount_id: u64,
        root_device: u64,
        root_inode: u64,
    },
    /// Neither the exact dataset nor a mount at the handle-derived slot may exist.
    Absent,
}

/// Binds one terminal workspace to its derived ZFS and pin-root identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkspaceCatalogObservationTargetV1 {
    workspace_handle: [u8; 32],
    creation_operation_id: [u8; 16],
    root_index: u16,
    dataset_name: String,
    dataset_guid: u64,
    expectation: WorkspaceCatalogObservationExpectationV1,
}

impl WorkspaceCatalogObservationTargetV1 {
    pub(crate) fn new(
        workspace_handle: [u8; 32],
        creation_operation_id: [u8; 16],
        root_index: u16,
        dataset_name: String,
        dataset_guid: u64,
        expectation: WorkspaceCatalogObservationExpectationV1,
    ) -> Result<Self, ZfsWorkerError> {
        let target = Self {
            workspace_handle,
            creation_operation_id,
            root_index,
            dataset_name,
            dataset_guid,
            expectation,
        };
        target.validate_shape()?;
        Ok(target)
    }

    fn validate_shape(&self) -> Result<(), ZfsWorkerError> {
        let present_identity_valid = match self.expectation {
            WorkspaceCatalogObservationExpectationV1::Present {
                mount_id,
                root_device,
                root_inode,
            } => mount_id != 0 && root_device != 0 && root_inode != 0,
            WorkspaceCatalogObservationExpectationV1::Absent => true,
        };
        if self.workspace_handle == [0; 32]
            || self.creation_operation_id == [0; 16]
            || self.dataset_name.len() > MAXIMUM_DATASET_NAME_BYTES
            || !valid_dataset_name(&self.dataset_name)
            || self.dataset_guid == 0
            || !present_identity_valid
        {
            return Err(protocol("catalog observation target is invalid"));
        }
        Ok(())
    }

    pub(crate) const fn workspace_handle(&self) -> [u8; 32] {
        self.workspace_handle
    }

    pub(crate) const fn creation_operation_id(&self) -> [u8; 16] {
        self.creation_operation_id
    }

    pub(crate) const fn root_index(&self) -> u16 {
        self.root_index
    }

    pub(crate) fn dataset_name(&self) -> &str {
        &self.dataset_name
    }

    pub(crate) const fn dataset_guid(&self) -> u64 {
        self.dataset_guid
    }

    pub(crate) const fn expectation(&self) -> WorkspaceCatalogObservationExpectationV1 {
        self.expectation
    }
}

/// Carries fixed authenticated bindings that precede the physical plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkspaceCatalogObservationBindingsV1 {
    runtime_binding: ObjectDigest,
    broker_instance_id: [u8; 16],
    transaction_sequence: u64,
    transaction_snapshot_digest: ObjectDigest,
    logical_plan_digest: ObjectDigest,
    physical_head_generation: u64,
    physical_head_digest: ObjectDigest,
    workspace_journal_sequence: u64,
    workspace_snapshot_digest: ObjectDigest,
    workspace_catalog_generation: u64,
    identity_pool_start: u32,
    identity_pool_size: u32,
}

impl WorkspaceCatalogObservationBindingsV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        runtime_binding: ObjectDigest,
        broker_instance_id: [u8; 16],
        transaction_sequence: u64,
        transaction_snapshot_digest: ObjectDigest,
        logical_plan_digest: ObjectDigest,
        physical_head_generation: u64,
        physical_head_digest: ObjectDigest,
        workspace_journal_sequence: u64,
        workspace_snapshot_digest: ObjectDigest,
        workspace_catalog_generation: u64,
        identity_pool_start: u32,
        identity_pool_size: u32,
    ) -> Result<Self, ZfsWorkerError> {
        let bindings = Self {
            runtime_binding,
            broker_instance_id,
            transaction_sequence,
            transaction_snapshot_digest,
            logical_plan_digest,
            physical_head_generation,
            physical_head_digest,
            workspace_journal_sequence,
            workspace_snapshot_digest,
            workspace_catalog_generation,
            identity_pool_start,
            identity_pool_size,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    fn validate(self) -> Result<(), ZfsWorkerError> {
        if self.runtime_binding.as_bytes() == &[0; 32]
            || self.broker_instance_id == [0; 16]
            || self.transaction_sequence == 0
            || self.transaction_snapshot_digest.as_bytes() == &[0; 32]
            || self.logical_plan_digest.as_bytes() == &[0; 32]
            || self.physical_head_generation == 0
            || self.physical_head_digest.as_bytes() == &[0; 32]
            || self.workspace_journal_sequence == 0
            || self.workspace_snapshot_digest.as_bytes() == &[0; 32]
            || self.workspace_catalog_generation == 0
            || self.identity_pool_start == 0
            || self.identity_pool_size == 0
            || self
                .identity_pool_start
                .checked_add(self.identity_pool_size)
                .is_none()
        {
            return Err(protocol(
                "catalog observation authority bindings are invalid",
            ));
        }
        Ok(())
    }

    pub(crate) const fn runtime_binding(self) -> ObjectDigest {
        self.runtime_binding
    }

    pub(crate) const fn broker_instance_id(self) -> [u8; 16] {
        self.broker_instance_id
    }

    pub(crate) const fn transaction_sequence(self) -> u64 {
        self.transaction_sequence
    }

    pub(crate) const fn transaction_snapshot_digest(self) -> ObjectDigest {
        self.transaction_snapshot_digest
    }

    pub(crate) const fn logical_plan_digest(self) -> ObjectDigest {
        self.logical_plan_digest
    }

    pub(crate) const fn physical_head(self) -> (u64, ObjectDigest) {
        (self.physical_head_generation, self.physical_head_digest)
    }

    pub(crate) const fn workspace_journal_sequence(self) -> u64 {
        self.workspace_journal_sequence
    }

    pub(crate) const fn workspace_snapshot_digest(self) -> ObjectDigest {
        self.workspace_snapshot_digest
    }

    pub(crate) const fn workspace_catalog_generation(self) -> u64 {
        self.workspace_catalog_generation
    }

    pub(crate) const fn identity_pool(self) -> (u32, u32) {
        (self.identity_pool_start, self.identity_pool_size)
    }
}

/// Owns one complete compact observation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkspaceCatalogObservationRequestV1 {
    nonce: [u8; 32],
    deadline_boottime_nanoseconds: u64,
    bindings: WorkspaceCatalogObservationBindingsV1,
    custody: WorkspaceCatalogCustodyBindingV1,
    physical_plan_digest: ObjectDigest,
    roots: Vec<WorkspaceCatalogObservationRootV1>,
    allowed_objects: Vec<WorkspaceCatalogObservationObjectV1>,
    targets: Vec<WorkspaceCatalogObservationTargetV1>,
    root_export: Option<GuestRootPublicationProofV1>,
}

impl WorkspaceCatalogObservationRequestV1 {
    pub(crate) fn new(
        nonce: [u8; 32],
        deadline_boottime_nanoseconds: u64,
        bindings: WorkspaceCatalogObservationBindingsV1,
        custody: WorkspaceCatalogCustodyBindingV1,
        roots: Vec<WorkspaceCatalogObservationRootV1>,
        allowed_objects: Vec<WorkspaceCatalogObservationObjectV1>,
        targets: Vec<WorkspaceCatalogObservationTargetV1>,
    ) -> Result<Self, ZfsWorkerError> {
        let physical_plan_digest = physical_plan_digest(&roots, &allowed_objects, &targets)?;
        let request = Self {
            nonce,
            deadline_boottime_nanoseconds,
            bindings,
            custody,
            physical_plan_digest,
            roots,
            allowed_objects,
            targets,
            root_export: None,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), ZfsWorkerError> {
        self.bindings.validate()?;
        self.custody.validate()?;
        if self.nonce == [0; 32]
            || self.deadline_boottime_nanoseconds == 0
            || self
                .roots
                .len()
                .checked_add(self.allowed_objects.len())
                .is_none_or(|rows| rows > MAXIMUM_CATALOG_ROWS)
            || self.targets.len() > MAXIMUM_CATALOG_ROWS
            || (self.roots.is_empty()
                && (!self.allowed_objects.is_empty() || !self.targets.is_empty()))
            || physical_plan_digest(&self.roots, &self.allowed_objects, &self.targets)?
                != self.physical_plan_digest
        {
            return Err(protocol("catalog observation request is invalid"));
        }

        let mut physical_names = BTreeSet::new();
        let mut physical_guids = BTreeSet::new();
        let mut root_names = BTreeSet::new();
        let mut prior_root_name: Option<&[u8]> = None;
        for root in &self.roots {
            if prior_root_name.is_some_and(|prior| prior >= root.name.as_bytes())
                || !physical_names.insert(root.name.as_bytes())
                || !physical_guids.insert(root.guid)
                || has_dataset_ancestor(root.name(), &root_names)
            {
                return Err(protocol(
                    "catalog observation root table is overlapping or not unique",
                ));
            }
            prior_root_name = Some(root.name.as_bytes());
            root_names.insert(root.name.as_str());
        }

        let mut allowed_by_name = std::collections::BTreeMap::new();
        let mut prior_object_name: Option<&[u8]> = None;
        for object in &self.allowed_objects {
            let root = self
                .roots
                .get(usize::from(object.root_index))
                .ok_or(protocol("catalog observation object root index is invalid"))?;
            if !strict_descendant_of(object.name(), root.name())
                || prior_object_name.is_some_and(|prior| prior >= object.name.as_bytes())
                || !physical_names.insert(object.name.as_bytes())
                || !physical_guids.insert(object.guid)
                || allowed_by_name.insert(object.name(), object).is_some()
            {
                return Err(protocol(
                    "catalog observation allowed objects are not canonical",
                ));
            }
            prior_object_name = Some(object.name.as_bytes());
        }

        let mut prior_handle = None;
        let mut operation_ids = BTreeSet::new();
        let mut target_names = BTreeSet::new();
        let mut target_guids = BTreeSet::new();
        for target in &self.targets {
            target.validate_shape()?;
            let root = self
                .roots
                .get(usize::from(target.root_index))
                .ok_or(protocol("catalog observation target root index is invalid"))?;
            if !strict_descendant_of(target.dataset_name(), root.name())
                || prior_handle.is_some_and(|prior| prior >= target.workspace_handle)
                || !operation_ids.insert(target.creation_operation_id)
                || !target_names.insert(target.dataset_name.as_bytes())
                || !target_guids.insert(target.dataset_guid)
            {
                return Err(protocol("catalog observation targets are not canonical"));
            }
            let allowed = allowed_by_name.get(target.dataset_name()).copied();
            match target.expectation {
                WorkspaceCatalogObservationExpectationV1::Present { .. }
                    if allowed.is_some_and(|object| {
                        object.root_index == target.root_index
                            && object.kind == WorkspaceCatalogObservationObjectKindV1::Filesystem
                            && object.guid == target.dataset_guid
                    }) => {}
                WorkspaceCatalogObservationExpectationV1::Absent
                    if allowed.is_none() && !physical_guids.contains(&target.dataset_guid) => {}
                _ => {
                    return Err(protocol(
                        "catalog observation target conflicts with allowed objects",
                    ));
                }
            }
            prior_handle = Some(target.workspace_handle);
        }
        if let Some(proof) = self.root_export {
            let target = self
                .targets
                .iter()
                .find(|target| target.workspace_handle == proof.workspace_handle)
                .ok_or(protocol("root export is absent from the physical catalog"))?;
            if target.creation_operation_id != proof.creation_operation
                || target.dataset_guid != proof.dataset_guid
                || !matches!(
                    target.expectation,
                    WorkspaceCatalogObservationExpectationV1::Present { .. }
                )
                || proof.feature_mask != CONCRETE_GUEST_FEATURE_MASK_V1
                || proof.encode().is_err()
            {
                return Err(protocol("root export differs from the physical catalog"));
            }
        }
        if encode_request(self)?.len() > MAXIMUM_CATALOG_OBSERVATION_REQUEST_BYTES {
            return Err(protocol("catalog observation request exceeds its ceiling"));
        }
        Ok(())
    }

    pub(crate) const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub(crate) const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    pub(crate) const fn bindings(&self) -> WorkspaceCatalogObservationBindingsV1 {
        self.bindings
    }

    pub(crate) const fn custody(&self) -> WorkspaceCatalogCustodyBindingV1 {
        self.custody
    }

    pub(crate) const fn physical_plan_digest(&self) -> ObjectDigest {
        self.physical_plan_digest
    }

    pub(crate) fn roots(&self) -> &[WorkspaceCatalogObservationRootV1] {
        &self.roots
    }

    pub(crate) fn allowed_objects(&self) -> &[WorkspaceCatalogObservationObjectV1] {
        &self.allowed_objects
    }

    pub(crate) fn targets(&self) -> &[WorkspaceCatalogObservationTargetV1] {
        &self.targets
    }

    /// Selects one published root from the already authenticated inventory.
    pub(crate) fn with_root_export(
        mut self,
        proof: GuestRootPublicationProofV1,
    ) -> Result<Self, ZfsWorkerError> {
        self.root_export = Some(proof);
        self.validate()?;
        Ok(self)
    }

    pub(crate) const fn root_export(&self) -> Option<GuestRootPublicationProofV1> {
        self.root_export
    }

    pub(crate) fn digest(&self) -> Result<ObjectDigest, ZfsWorkerError> {
        digest_domain(REQUEST_DIGEST_DOMAIN, &encode_request(self)?)
    }
}

/// Carries the fixed observer's complete two-pass evidence summary.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WorkspaceCatalogObservationResultV1 {
    request_digest: ObjectDigest,
    nonce: [u8; 32],
    deadline_boottime_nanoseconds: u64,
    custody: WorkspaceCatalogCustodyBindingV1,
    root_count: u32,
    allowed_object_count: u32,
    target_count: u32,
    zfs_before_digest: ObjectDigest,
    pin_before_digest: ObjectDigest,
    pin_after_digest: ObjectDigest,
    zfs_after_digest: ObjectDigest,
    combined_observation_digest: ObjectDigest,
}

impl WorkspaceCatalogObservationResultV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn matched(
        request: &WorkspaceCatalogObservationRequestV1,
        zfs_before_digest: ObjectDigest,
        pin_before_digest: ObjectDigest,
        pin_after_digest: ObjectDigest,
        zfs_after_digest: ObjectDigest,
    ) -> Result<Self, ZfsWorkerError> {
        let result = Self {
            request_digest: request.digest()?,
            nonce: request.nonce,
            deadline_boottime_nanoseconds: request.deadline_boottime_nanoseconds,
            custody: request.custody,
            root_count: count_u32(request.roots.len())?,
            allowed_object_count: count_u32(request.allowed_objects.len())?,
            target_count: count_u32(request.targets.len())?,
            zfs_before_digest,
            pin_before_digest,
            pin_after_digest,
            zfs_after_digest,
            combined_observation_digest: combined_observation_digest(
                request.physical_plan_digest,
                zfs_before_digest,
                pin_before_digest,
                pin_after_digest,
                zfs_after_digest,
            )?,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), ZfsWorkerError> {
        self.custody.validate()?;
        if self.request_digest.as_bytes() == &[0; 32]
            || self.nonce == [0; 32]
            || self.deadline_boottime_nanoseconds == 0
            || self.zfs_before_digest.as_bytes() == &[0; 32]
            || self.pin_before_digest.as_bytes() == &[0; 32]
            || self.pin_after_digest.as_bytes() == &[0; 32]
            || self.zfs_after_digest.as_bytes() == &[0; 32]
            || self.zfs_before_digest != self.zfs_after_digest
            || self.pin_before_digest != self.pin_after_digest
            || self.combined_observation_digest.as_bytes() == &[0; 32]
        {
            return Err(protocol("catalog observation result is invalid"));
        }
        Ok(())
    }

    pub(crate) fn matches_request(
        &self,
        request: &WorkspaceCatalogObservationRequestV1,
    ) -> Result<bool, ZfsWorkerError> {
        Ok(self.request_digest == request.digest()?
            && self.nonce == request.nonce
            && self.deadline_boottime_nanoseconds == request.deadline_boottime_nanoseconds
            && self.custody == request.custody
            && self.root_count == count_u32(request.roots.len())?
            && self.allowed_object_count == count_u32(request.allowed_objects.len())?
            && self.target_count == count_u32(request.targets.len())?
            && self.combined_observation_digest
                == combined_observation_digest(
                    request.physical_plan_digest,
                    self.zfs_before_digest,
                    self.pin_before_digest,
                    self.pin_after_digest,
                    self.zfs_after_digest,
                )?)
    }
}

pub(crate) fn encode_request(
    request: &WorkspaceCatalogObservationRequestV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    let mut bytes = Vec::with_capacity(REQUEST_FIXED_BYTES);
    bytes.extend_from_slice(REQUEST_MAGIC);
    let version = if request.root_export.is_some() {
        ROOT_EXPORT_WIRE_VERSION
    } else {
        WIRE_VERSION
    };
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&request.nonce);
    bytes.extend_from_slice(&request.deadline_boottime_nanoseconds.to_be_bytes());
    encode_bindings(&mut bytes, request.bindings);
    bytes.extend_from_slice(&encode_custody(request.custody));
    bytes.extend_from_slice(request.physical_plan_digest.as_bytes());
    bytes.extend_from_slice(&count_u32(request.roots.len())?.to_be_bytes());
    bytes.extend_from_slice(&count_u32(request.allowed_objects.len())?.to_be_bytes());
    bytes.extend_from_slice(&count_u32(request.targets.len())?.to_be_bytes());

    for root in &request.roots {
        encode_text_u16(&mut bytes, &root.name)?;
        bytes.extend_from_slice(&root.guid.to_be_bytes());
    }
    for object in &request.allowed_objects {
        bytes.extend_from_slice(&object.root_index.to_be_bytes());
        bytes.push(match object.kind {
            WorkspaceCatalogObservationObjectKindV1::Filesystem => 0,
            WorkspaceCatalogObservationObjectKindV1::Volume => 1,
        });
        encode_text_u16(&mut bytes, &object.name)?;
        bytes.extend_from_slice(&object.guid.to_be_bytes());
    }
    for target in &request.targets {
        bytes.extend_from_slice(&target.workspace_handle);
        bytes.extend_from_slice(&target.creation_operation_id);
        bytes.extend_from_slice(&target.root_index.to_be_bytes());
        encode_text_u16(&mut bytes, &target.dataset_name)?;
        bytes.extend_from_slice(&target.dataset_guid.to_be_bytes());
        match target.expectation {
            WorkspaceCatalogObservationExpectationV1::Absent => bytes.push(0),
            WorkspaceCatalogObservationExpectationV1::Present {
                mount_id,
                root_device,
                root_inode,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&mount_id.to_be_bytes());
                bytes.extend_from_slice(&root_device.to_be_bytes());
                bytes.extend_from_slice(&root_inode.to_be_bytes());
            }
        }
    }
    if let Some(proof) = request.root_export {
        bytes.extend_from_slice(
            &proof
                .encode()
                .map_err(|_| protocol("root export proof is invalid"))?,
        );
    }
    if bytes.len() > MAXIMUM_CATALOG_OBSERVATION_REQUEST_BYTES {
        return Err(protocol("catalog observation request exceeds its ceiling"));
    }
    Ok(bytes)
}

pub(crate) fn decode_request(
    bytes: &[u8],
) -> Result<WorkspaceCatalogObservationRequestV1, ZfsWorkerError> {
    if bytes.len() < REQUEST_FIXED_BYTES || bytes.len() > MAXIMUM_CATALOG_OBSERVATION_REQUEST_BYTES
    {
        return Err(protocol("catalog observation request length is invalid"));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != REQUEST_MAGIC {
        return Err(protocol("catalog observation request header is invalid"));
    }
    let version = decoder.u16()?;
    if !matches!(version, WIRE_VERSION | ROOT_EXPORT_WIRE_VERSION) || decoder.u16()? != 0 {
        return Err(protocol("catalog observation request header is invalid"));
    }
    let nonce = decoder.array()?;
    let deadline = decoder.u64()?;
    let bindings = decode_bindings(&mut decoder)?;
    let custody = decode_custody(&mut decoder)?;
    let encoded_plan_digest = ObjectDigest::from_bytes(decoder.array()?);
    let root_count = bounded_count(decoder.u32()?)?;
    let allowed_object_count = bounded_count(decoder.u32()?)?;
    let target_count = bounded_count(decoder.u32()?)?;

    let mut roots = Vec::with_capacity(root_count);
    for _ in 0..root_count {
        roots.push(WorkspaceCatalogObservationRootV1::new(
            decoder.text_u16(MAXIMUM_ROOT_NAME_BYTES)?,
            decoder.u64()?,
        )?);
    }
    let mut allowed_objects = Vec::with_capacity(allowed_object_count);
    for _ in 0..allowed_object_count {
        let root_index = decoder.u16()?;
        let kind = match decoder.u8()? {
            0 => WorkspaceCatalogObservationObjectKindV1::Filesystem,
            1 => WorkspaceCatalogObservationObjectKindV1::Volume,
            _ => return Err(protocol("catalog observation object kind is invalid")),
        };
        allowed_objects.push(WorkspaceCatalogObservationObjectV1::new(
            root_index,
            decoder.text_u16(MAXIMUM_DATASET_NAME_BYTES)?,
            kind,
            decoder.u64()?,
        )?);
    }
    let mut targets = Vec::with_capacity(target_count);
    for _ in 0..target_count {
        let workspace_handle = decoder.array()?;
        let creation_operation_id = decoder.array()?;
        let root_index = decoder.u16()?;
        let dataset_name = decoder.text_u16(MAXIMUM_DATASET_NAME_BYTES)?;
        let dataset_guid = decoder.u64()?;
        let expectation = match decoder.u8()? {
            0 => WorkspaceCatalogObservationExpectationV1::Absent,
            1 => WorkspaceCatalogObservationExpectationV1::Present {
                mount_id: decoder.u64()?,
                root_device: decoder.u64()?,
                root_inode: decoder.u64()?,
            },
            _ => return Err(protocol("catalog observation expectation is invalid")),
        };
        targets.push(WorkspaceCatalogObservationTargetV1::new(
            workspace_handle,
            creation_operation_id,
            root_index,
            dataset_name,
            dataset_guid,
            expectation,
        )?);
    }
    let root_export = if version == ROOT_EXPORT_WIRE_VERSION {
        Some(
            GuestRootPublicationProofV1::decode(decoder.take(266)?)
                .map_err(|_| protocol("root export proof is invalid"))?,
        )
    } else {
        None
    };
    decoder.finish()?;
    let mut request = WorkspaceCatalogObservationRequestV1::new(
        nonce,
        deadline,
        bindings,
        custody,
        roots,
        allowed_objects,
        targets,
    )?;
    if let Some(proof) = root_export {
        request = request.with_root_export(proof)?;
    }
    if request.physical_plan_digest != encoded_plan_digest || encode_request(&request)? != bytes {
        return Err(protocol("catalog observation request is not canonical"));
    }
    Ok(request)
}

pub(crate) fn encode_result(
    result: &WorkspaceCatalogObservationResultV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    result.validate()?;
    let mut bytes = Vec::with_capacity(RESULT_BYTES);
    bytes.extend_from_slice(RESULT_MAGIC);
    bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(result.request_digest.as_bytes());
    bytes.extend_from_slice(&result.nonce);
    bytes.extend_from_slice(&result.deadline_boottime_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(&encode_custody(result.custody));
    bytes.extend_from_slice(&result.root_count.to_be_bytes());
    bytes.extend_from_slice(&result.allowed_object_count.to_be_bytes());
    bytes.extend_from_slice(&result.target_count.to_be_bytes());
    bytes.extend_from_slice(result.zfs_before_digest.as_bytes());
    bytes.extend_from_slice(result.pin_before_digest.as_bytes());
    bytes.extend_from_slice(result.pin_after_digest.as_bytes());
    bytes.extend_from_slice(result.zfs_after_digest.as_bytes());
    bytes.extend_from_slice(result.combined_observation_digest.as_bytes());
    bytes.push(1);
    debug_assert_eq!(bytes.len(), RESULT_BYTES);
    Ok(bytes)
}

pub(crate) fn decode_result(
    bytes: &[u8],
) -> Result<WorkspaceCatalogObservationResultV1, ZfsWorkerError> {
    if bytes.len() != RESULT_BYTES {
        return Err(protocol("catalog observation result length is invalid"));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != RESULT_MAGIC || decoder.u16()? != WIRE_VERSION || decoder.u16()? != 0 {
        return Err(protocol("catalog observation result header is invalid"));
    }
    let result = WorkspaceCatalogObservationResultV1 {
        request_digest: ObjectDigest::from_bytes(decoder.array()?),
        nonce: decoder.array()?,
        deadline_boottime_nanoseconds: decoder.u64()?,
        custody: decode_custody(&mut decoder)?,
        root_count: decoder.u32()?,
        allowed_object_count: decoder.u32()?,
        target_count: decoder.u32()?,
        zfs_before_digest: ObjectDigest::from_bytes(decoder.array()?),
        pin_before_digest: ObjectDigest::from_bytes(decoder.array()?),
        pin_after_digest: ObjectDigest::from_bytes(decoder.array()?),
        zfs_after_digest: ObjectDigest::from_bytes(decoder.array()?),
        combined_observation_digest: ObjectDigest::from_bytes(decoder.array()?),
    };
    if decoder.u8()? != 1 {
        return Err(protocol("catalog observation result status is invalid"));
    }
    decoder.finish()?;
    result.validate()?;
    if encode_result(&result)? != bytes {
        return Err(protocol("catalog observation result is not canonical"));
    }
    Ok(result)
}

/// Streams a catalog request through the separate 10 MiB transfer profile.
pub(crate) struct WorkspaceCatalogObservationFrameEncoder<'a> {
    request: &'a [u8],
    digest: [u8; 32],
    offset: usize,
}

impl<'a> WorkspaceCatalogObservationFrameEncoder<'a> {
    pub(crate) fn new(request: &'a [u8]) -> Result<Self, ZfsWorkerError> {
        if request.is_empty() || request.len() > MAXIMUM_CATALOG_OBSERVATION_REQUEST_BYTES {
            return Err(protocol(
                "catalog observation framed request length is invalid",
            ));
        }
        Ok(Self {
            request,
            digest: digest_array(FRAME_DIGEST_DOMAIN, request),
            offset: 0,
        })
    }

    pub(crate) fn next_frame(&mut self) -> Option<Vec<u8>> {
        if self.offset == self.request.len() {
            return None;
        }
        let content_length = (self.request.len() - self.offset).min(MAXIMUM_FRAME_CONTENT_BYTES);
        let end = self.offset + content_length;
        let mut flags = 0_u16;
        if self.offset == 0 {
            flags |= FRAME_FIRST;
        }
        if end == self.request.len() {
            flags |= FRAME_LAST;
        }
        let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + content_length);
        frame.extend_from_slice(FRAME_MAGIC);
        frame.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        frame.extend_from_slice(&flags.to_be_bytes());
        frame.extend_from_slice(&self.digest);
        frame.extend_from_slice(&(self.request.len() as u32).to_be_bytes());
        frame.extend_from_slice(&(self.offset as u32).to_be_bytes());
        frame.extend_from_slice(&(content_length as u16).to_be_bytes());
        frame.extend_from_slice(&self.request[self.offset..end]);
        self.offset = end;
        Some(frame)
    }
}

/// Owns one reassembled catalog request and its frame-zero capabilities.
pub(crate) struct ReceivedWorkspaceCatalogObservationRequest {
    pub(crate) bytes: Vec<u8>,
    pub(crate) subject: KernelAuthorizedRecordSubject,
    pub(crate) descriptors: Vec<OwnedFd>,
}

/// Reassembles only canonical catalog frames and fails terminally on error.
#[derive(Default)]
pub(crate) struct WorkspaceCatalogObservationRequestAssembler {
    digest: Option<[u8; 32]>,
    total_length: usize,
    next_offset: usize,
    bytes: Vec<u8>,
    subject: Option<KernelAuthorizedRecordSubject>,
    descriptors: Vec<OwnedFd>,
    frame_count: usize,
    terminal: bool,
}

impl WorkspaceCatalogObservationRequestAssembler {
    pub(crate) fn accept(
        &mut self,
        record: ReceivedDescriptorRecord,
    ) -> Result<Option<ReceivedWorkspaceCatalogObservationRequest>, ZfsWorkerError> {
        if self.terminal {
            return Err(protocol("catalog observation transfer is already terminal"));
        }
        let result = self.accept_inner(record);
        if result.is_err() || result.as_ref().is_ok_and(Option::is_some) {
            self.terminal = true;
        }
        result
    }

    fn accept_inner(
        &mut self,
        record: ReceivedDescriptorRecord,
    ) -> Result<Option<ReceivedWorkspaceCatalogObservationRequest>, ZfsWorkerError> {
        let (payload, subject, descriptors) = record.into_parts();
        let frame = decode_frame(&payload)?;
        self.frame_count = self
            .frame_count
            .checked_add(1)
            .filter(|count| *count <= maximum_frame_count())
            .ok_or(protocol(
                "catalog observation fragment count exceeded its ceiling",
            ))?;
        if self.digest.is_none() {
            if !frame.first || descriptors.len() != CATALOG_OBSERVATION_DESCRIPTOR_COUNT {
                return Err(protocol(
                    "catalog observation first frame descriptors are invalid",
                ));
            }
            if !subject.is_alive()? {
                return Err(ZfsWorkerError::PeerMismatch);
            }
            self.digest = Some(frame.digest);
            self.total_length = frame.total_length;
            self.bytes = Vec::with_capacity(frame.total_length);
            self.subject = Some(subject);
            self.descriptors = descriptors;
        } else {
            if frame.first || !descriptors.is_empty() {
                return Err(protocol(
                    "catalog observation continuation descriptors are invalid",
                ));
            }
            verify_same_live_subject(
                self.subject
                    .as_ref()
                    .ok_or(protocol("catalog observation subject is missing"))?,
                &subject,
            )?;
        }
        if Some(frame.digest) != self.digest
            || frame.total_length != self.total_length
            || frame.offset != self.next_offset
        {
            return Err(protocol(
                "catalog observation frame sequence was substituted",
            ));
        }
        self.bytes.extend_from_slice(frame.content);
        self.next_offset = self
            .next_offset
            .checked_add(frame.content.len())
            .ok_or(protocol("catalog observation frame offset overflow"))?;
        if !frame.last {
            return Ok(None);
        }
        if self.next_offset != self.total_length
            || digest_array(FRAME_DIGEST_DOMAIN, &self.bytes) != self.digest.unwrap_or([0; 32])
        {
            return Err(protocol(
                "catalog observation transfer digest does not match",
            ));
        }
        let subject = self
            .subject
            .take()
            .ok_or(protocol("catalog observation subject is missing"))?;
        if !subject.is_alive()? {
            return Err(ZfsWorkerError::PeerMismatch);
        }
        Ok(Some(ReceivedWorkspaceCatalogObservationRequest {
            bytes: std::mem::take(&mut self.bytes),
            subject,
            descriptors: std::mem::take(&mut self.descriptors),
        }))
    }
}

pub(crate) fn is_catalog_observation_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(FRAME_MAGIC)
}

const fn maximum_frame_count() -> usize {
    MAXIMUM_CATALOG_OBSERVATION_REQUEST_BYTES.div_ceil(MAXIMUM_FRAME_CONTENT_BYTES)
}

struct DecodedFrame<'a> {
    first: bool,
    last: bool,
    digest: [u8; 32],
    total_length: usize,
    offset: usize,
    content: &'a [u8],
}

fn decode_frame(bytes: &[u8]) -> Result<DecodedFrame<'_>, ZfsWorkerError> {
    if bytes.len() < FRAME_HEADER_BYTES || bytes.len() > MAXIMUM_CATALOG_OBSERVATION_PACKET_BYTES {
        return Err(protocol("catalog observation frame length is invalid"));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != FRAME_MAGIC || decoder.u16()? != WIRE_VERSION {
        return Err(protocol("catalog observation frame header is invalid"));
    }
    let flags = decoder.u16()?;
    if flags & !FRAME_KNOWN_FLAGS != 0 {
        return Err(protocol("catalog observation frame flags are invalid"));
    }
    let digest = decoder.array()?;
    let total_length = usize::try_from(decoder.u32()?)
        .map_err(|_| protocol("catalog observation total length does not fit usize"))?;
    let offset = usize::try_from(decoder.u32()?)
        .map_err(|_| protocol("catalog observation offset does not fit usize"))?;
    let content_length = usize::from(decoder.u16()?);
    let content = decoder.take(content_length)?;
    decoder.finish()?;
    let end = offset
        .checked_add(content_length)
        .ok_or(protocol("catalog observation frame content overflow"))?;
    let first = flags & FRAME_FIRST != 0;
    let last = flags & FRAME_LAST != 0;
    if total_length == 0
        || total_length > MAXIMUM_CATALOG_OBSERVATION_REQUEST_BYTES
        || content_length == 0
        || content_length > MAXIMUM_FRAME_CONTENT_BYTES
        || end > total_length
        || first != (offset == 0)
        || last != (end == total_length)
        || (!last && content_length != MAXIMUM_FRAME_CONTENT_BYTES)
    {
        return Err(protocol(
            "catalog observation frame fields are not canonical",
        ));
    }
    Ok(DecodedFrame {
        first,
        last,
        digest,
        total_length,
        offset,
        content,
    })
}

fn physical_plan_digest(
    roots: &[WorkspaceCatalogObservationRootV1],
    allowed_objects: &[WorkspaceCatalogObservationObjectV1],
    targets: &[WorkspaceCatalogObservationTargetV1],
) -> Result<ObjectDigest, ZfsWorkerError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&count_u32(roots.len())?.to_be_bytes());
    bytes.extend_from_slice(&count_u32(allowed_objects.len())?.to_be_bytes());
    bytes.extend_from_slice(&count_u32(targets.len())?.to_be_bytes());
    for root in roots {
        encode_text_u16(&mut bytes, &root.name)?;
        bytes.extend_from_slice(&root.guid.to_be_bytes());
    }
    for object in allowed_objects {
        bytes.extend_from_slice(&object.root_index.to_be_bytes());
        bytes.push(match object.kind {
            WorkspaceCatalogObservationObjectKindV1::Filesystem => 0,
            WorkspaceCatalogObservationObjectKindV1::Volume => 1,
        });
        encode_text_u16(&mut bytes, &object.name)?;
        bytes.extend_from_slice(&object.guid.to_be_bytes());
    }
    for target in targets {
        bytes.extend_from_slice(&target.workspace_handle);
        bytes.extend_from_slice(&target.creation_operation_id);
        bytes.extend_from_slice(&target.root_index.to_be_bytes());
        encode_text_u16(&mut bytes, &target.dataset_name)?;
        bytes.extend_from_slice(&target.dataset_guid.to_be_bytes());
        match target.expectation {
            WorkspaceCatalogObservationExpectationV1::Absent => bytes.push(0),
            WorkspaceCatalogObservationExpectationV1::Present {
                mount_id,
                root_device,
                root_inode,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&mount_id.to_be_bytes());
                bytes.extend_from_slice(&root_device.to_be_bytes());
                bytes.extend_from_slice(&root_inode.to_be_bytes());
            }
        }
    }
    digest_domain(PHYSICAL_PLAN_DIGEST_DOMAIN, &bytes)
}

fn strict_descendant_of(name: &str, root: &str) -> bool {
    name.strip_prefix(root)
        .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
}

fn has_dataset_ancestor(name: &str, roots: &BTreeSet<&str>) -> bool {
    let mut candidate = name;
    while let Some((parent, _)) = candidate.rsplit_once('/') {
        if roots.contains(parent) {
            return true;
        }
        candidate = parent;
    }
    false
}

fn combined_observation_digest(
    physical_plan_digest: ObjectDigest,
    zfs_before_digest: ObjectDigest,
    pin_before_digest: ObjectDigest,
    pin_after_digest: ObjectDigest,
    zfs_after_digest: ObjectDigest,
) -> Result<ObjectDigest, ZfsWorkerError> {
    let mut bytes = Vec::with_capacity(5 * 32);
    bytes.extend_from_slice(physical_plan_digest.as_bytes());
    bytes.extend_from_slice(zfs_before_digest.as_bytes());
    bytes.extend_from_slice(pin_before_digest.as_bytes());
    bytes.extend_from_slice(pin_after_digest.as_bytes());
    bytes.extend_from_slice(zfs_after_digest.as_bytes());
    digest_domain(COMBINED_OBSERVATION_DIGEST_DOMAIN, &bytes)
}

fn encode_bindings(bytes: &mut Vec<u8>, bindings: WorkspaceCatalogObservationBindingsV1) {
    bytes.extend_from_slice(bindings.runtime_binding.as_bytes());
    bytes.extend_from_slice(&bindings.broker_instance_id);
    bytes.extend_from_slice(&bindings.transaction_sequence.to_be_bytes());
    bytes.extend_from_slice(bindings.transaction_snapshot_digest.as_bytes());
    bytes.extend_from_slice(bindings.logical_plan_digest.as_bytes());
    bytes.extend_from_slice(&bindings.physical_head_generation.to_be_bytes());
    bytes.extend_from_slice(bindings.physical_head_digest.as_bytes());
    bytes.extend_from_slice(&bindings.workspace_journal_sequence.to_be_bytes());
    bytes.extend_from_slice(bindings.workspace_snapshot_digest.as_bytes());
    bytes.extend_from_slice(&bindings.workspace_catalog_generation.to_be_bytes());
    bytes.extend_from_slice(&bindings.identity_pool_start.to_be_bytes());
    bytes.extend_from_slice(&bindings.identity_pool_size.to_be_bytes());
}

fn decode_bindings(
    decoder: &mut Decoder<'_>,
) -> Result<WorkspaceCatalogObservationBindingsV1, ZfsWorkerError> {
    WorkspaceCatalogObservationBindingsV1::new(
        ObjectDigest::from_bytes(decoder.array()?),
        decoder.array()?,
        decoder.u64()?,
        ObjectDigest::from_bytes(decoder.array()?),
        ObjectDigest::from_bytes(decoder.array()?),
        decoder.u64()?,
        ObjectDigest::from_bytes(decoder.array()?),
        decoder.u64()?,
        ObjectDigest::from_bytes(decoder.array()?),
        decoder.u64()?,
        decoder.u32()?,
        decoder.u32()?,
    )
}

fn encode_custody(binding: WorkspaceCatalogCustodyBindingV1) -> [u8; 56] {
    let mut bytes = [0_u8; 56];
    bytes[..16].copy_from_slice(&binding.kernel_boot_id);
    for (index, value) in [
        binding.mount_namespace_device,
        binding.mount_namespace_inode,
        binding.pin_root_mount_id,
        binding.pin_root_device,
        binding.pin_root_inode,
    ]
    .into_iter()
    .enumerate()
    {
        let start = 16 + index * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
    }
    bytes
}

fn decode_custody(
    decoder: &mut Decoder<'_>,
) -> Result<WorkspaceCatalogCustodyBindingV1, ZfsWorkerError> {
    WorkspaceCatalogCustodyBindingV1::new(
        decoder.array()?,
        decoder.u64()?,
        decoder.u64()?,
        decoder.u64()?,
        decoder.u64()?,
        decoder.u64()?,
    )
}

fn encode_text_u16(bytes: &mut Vec<u8>, value: &str) -> Result<(), ZfsWorkerError> {
    let length = u16::try_from(value.len())
        .map_err(|_| protocol("catalog observation text length does not fit u16"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn count_u32(count: usize) -> Result<u32, ZfsWorkerError> {
    u32::try_from(count).map_err(|_| protocol("catalog observation count does not fit u32"))
}

fn bounded_count(count: u32) -> Result<usize, ZfsWorkerError> {
    usize::try_from(count)
        .ok()
        .filter(|count| *count <= MAXIMUM_CATALOG_ROWS)
        .ok_or(protocol("catalog observation count exceeds its ceiling"))
}

fn digest_domain(domain: &[u8], bytes: &[u8]) -> Result<ObjectDigest, ZfsWorkerError> {
    let digest = ObjectDigest::from_bytes(digest_array(domain, bytes));
    if digest.as_bytes() == &[0; 32] {
        Err(protocol("catalog observation digest is reserved"))
    } else {
        Ok(digest)
    }
}

fn digest_array(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    digest.finalize().into()
}

const fn protocol(message: &'static str) -> ZfsWorkerError {
    ZfsWorkerError::Protocol(message)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ZfsWorkerError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(protocol("catalog observation record is truncated"))?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ZfsWorkerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| protocol("catalog observation fixed field is truncated"))
    }

    fn u8(&mut self) -> Result<u8, ZfsWorkerError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ZfsWorkerError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ZfsWorkerError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ZfsWorkerError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn text_u16(&mut self, maximum: usize) -> Result<String, ZfsWorkerError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum {
            return Err(protocol("catalog observation text length is invalid"));
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| protocol("catalog observation text is not UTF-8"))?;
        Ok(value.to_owned())
    }

    fn finish(self) -> Result<(), ZfsWorkerError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(protocol("catalog observation record has trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn bindings() -> WorkspaceCatalogObservationBindingsV1 {
        WorkspaceCatalogObservationBindingsV1::new(
            ObjectDigest::from_bytes([1; 32]),
            [2; 16],
            3,
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            6,
            ObjectDigest::from_bytes([7; 32]),
            8,
            ObjectDigest::from_bytes([9; 32]),
            10,
            65_536,
            65_536,
        )
        .unwrap()
    }

    fn custody() -> WorkspaceCatalogCustodyBindingV1 {
        WorkspaceCatalogCustodyBindingV1::new([11; 16], 12, 13, 14, 15, 16).unwrap()
    }

    fn request(
        expectation: WorkspaceCatalogObservationExpectationV1,
    ) -> WorkspaceCatalogObservationRequestV1 {
        let allowed_objects = match expectation {
            WorkspaceCatalogObservationExpectationV1::Present { .. } => vec![
                WorkspaceCatalogObservationObjectV1::new(
                    0,
                    "tank/aos/work".to_owned(),
                    WorkspaceCatalogObservationObjectKindV1::Filesystem,
                    22,
                )
                .unwrap(),
            ],
            WorkspaceCatalogObservationExpectationV1::Absent => Vec::new(),
        };
        WorkspaceCatalogObservationRequestV1::new(
            [17; 32],
            18,
            bindings(),
            custody(),
            vec![WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 19).unwrap()],
            allowed_objects,
            vec![
                WorkspaceCatalogObservationTargetV1::new(
                    [20; 32],
                    [21; 16],
                    0,
                    "tank/aos/work".to_owned(),
                    22,
                    expectation,
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn compact_wire_has_frozen_sizes_and_round_trips_canonically() {
        let absent = request(WorkspaceCatalogObservationExpectationV1::Absent);
        let absent_bytes = encode_request(&absent).unwrap();
        assert_eq!(absent_bytes.len(), REQUEST_FIXED_BYTES + 18 + 74);
        assert_eq!(decode_request(&absent_bytes).unwrap(), absent);

        let present = request(WorkspaceCatalogObservationExpectationV1::Present {
            mount_id: 23,
            root_device: 24,
            root_inode: 25,
        });
        let present_bytes = encode_request(&present).unwrap();
        assert_eq!(present_bytes.len(), absent_bytes.len() + 50);
        assert_eq!(decode_request(&present_bytes).unwrap(), present);

        let digest = ObjectDigest::from_bytes([26; 32]);
        let result =
            WorkspaceCatalogObservationResultV1::matched(&present, digest, digest, digest, digest)
                .unwrap();
        let result_bytes = encode_result(&result).unwrap();
        assert_eq!(result_bytes.len(), RESULT_BYTES);
        assert_eq!(decode_result(&result_bytes).unwrap(), result);
        assert!(result.matches_request(&present).unwrap());
    }

    #[test]
    fn root_export_v2_binds_published_assignment_to_present_physical_target() {
        let present = request(WorkspaceCatalogObservationExpectationV1::Present {
            mount_id: 23,
            root_device: 24,
            root_inode: 25,
        });
        let proof = GuestRootPublicationProofV1 {
            sandbox: [1; 16],
            incarnation: [2; 16],
            assignment_epoch: 3,
            assignment_digest: [4; 32],
            creation_operation: [21; 16],
            workspace_handle: [20; 32],
            dataset_guid: 22,
            root_image_digest: [5; 32],
            package_binding: [6; 32],
            root_tree_digest: [7; 32],
            feature_mask: CONCRETE_GUEST_FEATURE_MASK_V1,
        };

        let export = present.clone().with_root_export(proof).unwrap();
        let encoded = encode_request(&export).unwrap();
        assert_eq!(&encoded[8..10], &ROOT_EXPORT_WIRE_VERSION.to_be_bytes());
        assert_eq!(decode_request(&encoded).unwrap(), export);
        assert!(
            present
                .clone()
                .with_root_export(GuestRootPublicationProofV1 {
                    dataset_guid: 99,
                    ..proof
                })
                .is_err()
        );
        assert!(
            request(WorkspaceCatalogObservationExpectationV1::Absent)
                .with_root_export(proof)
                .is_err()
        );

        let mut downgraded = encoded;
        downgraded[8..10].copy_from_slice(&WIRE_VERSION.to_be_bytes());
        assert!(decode_request(&downgraded).is_err());
    }

    #[test]
    fn initialized_empty_catalog_is_exactly_the_fixed_request() {
        let request = WorkspaceCatalogObservationRequestV1::new(
            [17; 32],
            18,
            bindings(),
            custody(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let bytes = encode_request(&request).unwrap();

        assert_eq!(bytes.len(), REQUEST_FIXED_BYTES);
        assert_eq!(decode_request(&bytes).unwrap(), request);
    }

    #[test]
    fn activation_and_combined_digests_use_the_exact_approved_domains() {
        let request = WorkspaceCatalogObservationRequestV1::new(
            [17; 32],
            18,
            bindings(),
            custody(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let mut physical_preimage = Vec::new();
        physical_preimage.extend_from_slice(&0_u32.to_be_bytes());
        physical_preimage.extend_from_slice(&0_u32.to_be_bytes());
        physical_preimage.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            request.physical_plan_digest(),
            ObjectDigest::from_bytes(digest_array(
                b"aos.sandbox.storage.workspace-catalog-activation-plan.v1\0",
                &physical_preimage,
            ))
        );

        let observation = ObjectDigest::from_bytes([26; 32]);
        let result = WorkspaceCatalogObservationResultV1::matched(
            &request,
            observation,
            observation,
            observation,
            observation,
        )
        .unwrap();
        let encoded = encode_result(&result).unwrap();
        let mut combined_preimage = Vec::new();
        combined_preimage.extend_from_slice(request.physical_plan_digest().as_bytes());
        for _ in 0..4 {
            combined_preimage.extend_from_slice(observation.as_bytes());
        }
        let expected = digest_array(
            b"aos.sandbox.storage.workspace-catalog-combined-observation.v1\0",
            &combined_preimage,
        );
        assert_eq!(&encoded[RESULT_BYTES - 33..RESULT_BYTES - 1], &expected);
    }

    #[test]
    fn worst_case_profile_fits_ten_mib_and_uses_2595_ceiling_frames() {
        let root_bytes = 10 + MAXIMUM_ROOT_NAME_BYTES;
        let allowed_object_bytes = 13 + MAXIMUM_DATASET_NAME_BYTES;
        let present_target_bytes = 85 + MAXIMUM_DATASET_NAME_BYTES;
        let worst_scope_row_bytes = root_bytes.max(allowed_object_bytes);
        let worst_case = REQUEST_FIXED_BYTES
            + MAXIMUM_CATALOG_ROWS * (worst_scope_row_bytes + present_target_bytes);

        assert_eq!(worst_case, 9_961_840);
        assert!(worst_case <= MAXIMUM_CATALOG_OBSERVATION_REQUEST_BYTES);
        assert_eq!(maximum_frame_count(), 2595);
        assert_eq!(MAXIMUM_FRAME_CONTENT_BYTES, 4042);
    }

    #[test]
    fn request_rejects_noncanonical_tables_and_cross_root_targets() {
        let duplicate_roots = WorkspaceCatalogObservationRequestV1::new(
            [17; 32],
            18,
            bindings(),
            custody(),
            vec![
                WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 19).unwrap(),
                WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 20).unwrap(),
            ],
            Vec::new(),
            vec![
                WorkspaceCatalogObservationTargetV1::new(
                    [20; 32],
                    [21; 16],
                    0,
                    "tank/aos/work".to_owned(),
                    22,
                    WorkspaceCatalogObservationExpectationV1::Absent,
                )
                .unwrap(),
            ],
        );
        assert!(duplicate_roots.is_err());

        let cross_root = WorkspaceCatalogObservationRequestV1::new(
            [17; 32],
            18,
            bindings(),
            custody(),
            vec![WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 19).unwrap()],
            Vec::new(),
            vec![
                WorkspaceCatalogObservationTargetV1::new(
                    [20; 32],
                    [21; 16],
                    0,
                    "other/aos/work".to_owned(),
                    22,
                    WorkspaceCatalogObservationExpectationV1::Absent,
                )
                .unwrap(),
            ],
        );
        assert!(cross_root.is_err());
    }

    #[test]
    fn request_rejects_nested_roots_and_root_object_collisions() {
        let nested_roots = WorkspaceCatalogObservationRequestV1::new(
            [17; 32],
            18,
            bindings(),
            custody(),
            vec![
                WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 19).unwrap(),
                WorkspaceCatalogObservationRootV1::new("tank/aos/nested".to_owned(), 20).unwrap(),
            ],
            Vec::new(),
            Vec::new(),
        );
        assert!(nested_roots.is_err());

        let root_name_collision = WorkspaceCatalogObservationRequestV1::new(
            [17; 32],
            18,
            bindings(),
            custody(),
            vec![WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 19).unwrap()],
            vec![
                WorkspaceCatalogObservationObjectV1::new(
                    0,
                    "tank/aos".to_owned(),
                    WorkspaceCatalogObservationObjectKindV1::Filesystem,
                    20,
                )
                .unwrap(),
            ],
            Vec::new(),
        );
        assert!(root_name_collision.is_err());

        let root_guid_collision = WorkspaceCatalogObservationRequestV1::new(
            [17; 32],
            18,
            bindings(),
            custody(),
            vec![WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 19).unwrap()],
            vec![
                WorkspaceCatalogObservationObjectV1::new(
                    0,
                    "tank/aos/project".to_owned(),
                    WorkspaceCatalogObservationObjectKindV1::Filesystem,
                    19,
                )
                .unwrap(),
            ],
            Vec::new(),
        );
        assert!(root_guid_collision.is_err());
    }

    #[test]
    fn request_rejects_cross_table_name_and_guid_collisions() {
        let cross_name = WorkspaceCatalogObservationRequestV1::new(
            [17; 32],
            18,
            bindings(),
            custody(),
            vec![WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 19).unwrap()],
            vec![
                WorkspaceCatalogObservationObjectV1::new(
                    0,
                    "tank/aos/project".to_owned(),
                    WorkspaceCatalogObservationObjectKindV1::Filesystem,
                    22,
                )
                .unwrap(),
            ],
            vec![
                WorkspaceCatalogObservationTargetV1::new(
                    [20; 32],
                    [21; 16],
                    0,
                    "tank/aos/project".to_owned(),
                    22,
                    WorkspaceCatalogObservationExpectationV1::Absent,
                )
                .unwrap(),
            ],
        );
        assert!(cross_name.is_err());

        let cross_guid = WorkspaceCatalogObservationRequestV1::new(
            [17; 32],
            18,
            bindings(),
            custody(),
            vec![WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 19).unwrap()],
            Vec::new(),
            vec![
                WorkspaceCatalogObservationTargetV1::new(
                    [20; 32],
                    [21; 16],
                    0,
                    "tank/aos/work".to_owned(),
                    19,
                    WorkspaceCatalogObservationExpectationV1::Absent,
                )
                .unwrap(),
            ],
        );
        assert!(cross_guid.is_err());
    }

    #[test]
    fn result_rejects_substitution_and_changed_between_passes() {
        let observed_request = request(WorkspaceCatalogObservationExpectationV1::Absent);
        let other = request(WorkspaceCatalogObservationExpectationV1::Present {
            mount_id: 23,
            root_device: 24,
            root_inode: 25,
        });
        let digest = ObjectDigest::from_bytes([26; 32]);
        let result = WorkspaceCatalogObservationResultV1::matched(
            &observed_request,
            digest,
            digest,
            digest,
            digest,
        )
        .unwrap();

        assert!(!result.matches_request(&other).unwrap());
        assert!(
            WorkspaceCatalogObservationResultV1::matched(
                &observed_request,
                digest,
                digest,
                ObjectDigest::from_bytes([27; 32]),
                digest,
            )
            .is_err()
        );

        let mut substituted = encode_result(&result).unwrap();
        substituted[RESULT_BYTES - 2] ^= 1;
        let substituted = decode_result(&substituted).unwrap();
        assert!(!substituted.matches_request(&observed_request).unwrap());
    }

    #[test]
    fn frame_profile_is_distinct_and_commits_the_complete_request() {
        let logical = vec![0x5a; MAXIMUM_FRAME_CONTENT_BYTES + 1];
        let mut encoder = WorkspaceCatalogObservationFrameEncoder::new(&logical).unwrap();
        let first = encoder.next_frame().unwrap();
        let last = encoder.next_frame().unwrap();

        assert!(is_catalog_observation_frame(&first));
        assert_eq!(first.len(), MAXIMUM_CATALOG_OBSERVATION_PACKET_BYTES);
        assert_eq!(last.len(), FRAME_HEADER_BYTES + 1);
        assert!(encoder.next_frame().is_none());

        let first = decode_frame(&first).unwrap();
        let last = decode_frame(&last).unwrap();
        assert!(first.first && !first.last);
        assert!(!last.first && last.last);
        assert_eq!(first.digest, last.digest);
        assert_eq!(first.total_length, logical.len());
        assert_eq!(last.offset, MAXIMUM_FRAME_CONTENT_BYTES);
    }

    #[test]
    fn decoders_reject_reserved_trailing_and_noncanonical_bytes() {
        let request = request(WorkspaceCatalogObservationExpectationV1::Absent);
        let bytes = encode_request(&request).unwrap();
        let mut reserved = bytes.clone();
        reserved[10] = 1;
        assert!(decode_request(&reserved).is_err());

        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());

        let digest = ObjectDigest::from_bytes([26; 32]);
        let result =
            WorkspaceCatalogObservationResultV1::matched(&request, digest, digest, digest, digest)
                .unwrap();
        let mut result_bytes = encode_result(&result).unwrap();
        *result_bytes.last_mut().unwrap() = 0;
        assert!(decode_result(&result_bytes).is_err());
    }
}
