//! Durable Storage root-pin attempts and observation-only crash classification.
//!
//! Root-pin materialization is a distinct privileged effect from the ZFS
//! mutation that creates or destroys a dataset. An authenticated attempt is
//! made ambiguous before dispatch and is never dispatched again. Recovery may
//! only classify exact dataset and mount observations; an absent required pin
//! demands a separately authorized repair attempt.
//!
//! The authenticated record is a canonical binary format:
//!
//! ```text
//! AOSSPA01 | version:u16 | key-id:16 | attempt-id:16
//! ordinal:u8 | action:u8 | phase:u8
//! effect-operation:16 | creation-operation:16
//! operation-fence-digest:32 | effect-assignment-digest:32
//! workspace-assignment-digest:32
//! creation-result-catalog:(generation:u64,digest:32) | result-digest:32
//! workspace-handle:32 | host-boot-id:16 | host-mount-namespace:(dev:u64,ino:u64)
//! clock-provenance:16 | exclusive-effect-deadline-boottime:u64
//! dataset-name:(len:u16,utf8) | dataset-guid:u64 | uid-range:(start:u32,size:u32)
//! authority-receipt:(len:u16,opaque-authenticated-record)
//! expected-pin:(presence:u8,payload?) | satisfied-pin:(presence:u8,payload?)
//! hmac-sha256:32
//! ```

use std::collections::BTreeMap;

use aos_sandbox::{Journal, JournalRecord, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{CatalogBindingV1, StorageStateError};

type HmacSha256 = Hmac<Sha256>;

pub(crate) const MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE: u8 = 4;

const MAGIC: &[u8; 8] = b"AOSSPA01";
const VERSION: u16 = 1;
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-pin-attempt.v1\0";
const ATTEMPT_ID_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-pin-attempt-id.v1\0";
const ATTEMPT_AUTHORITY_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-pin-authority.v1\0";
const MAXIMUM_STRING_BYTES: usize = 512;
const MAXIMUM_AUTHORITY_RECEIPT_BYTES: usize = 16 * 1024;
const MAC_BYTES: usize = 32;
pub(crate) const WORKSPACE_PIN_ROOT: &str = "/run/aos/sandbox-pins/workspaces";
const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const U64_BYTES: usize = 8;
const U32_BYTES: usize = 4;
const STRING_LENGTH_BYTES: usize = 2;
const MINIMUM_STRING_CONTENT_BYTES: usize = 1;
const PRESENCE_BYTES: usize = 1;
const MINIMUM_ATTEMPT_BODY_BYTES: usize =
    // Header and attempt discriminator.
    MAGIC.len() + 2 + ID_BYTES + ID_BYTES + 3
    // Effect/creation IDs and authority commitments.
    + ID_BYTES + ID_BYTES + DIGEST_BYTES * 3
    // Exact committed creation result and workspace handle.
    + U64_BYTES + DIGEST_BYTES + DIGEST_BYTES + DIGEST_BYTES
    // Host boot and initial mount-namespace identity.
    + ID_BYTES + U64_BYTES * 2 + ID_BYTES + U64_BYTES
    // Shortest dataset name, GUID, reserved identity range, and absent proofs.
    + STRING_LENGTH_BYTES + MINIMUM_STRING_CONTENT_BYTES + U64_BYTES + U32_BYTES * 2
    + STRING_LENGTH_BYTES + MINIMUM_STRING_CONTENT_BYTES
    + PRESENCE_BYTES * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspacePinActionV1 {
    Ensure,
    RemoveAndDestroy,
}

impl WorkspacePinActionV1 {
    const fn wire(self) -> u8 {
        match self {
            Self::Ensure => 1,
            Self::RemoveAndDestroy => 2,
        }
    }

    fn from_wire(value: u8) -> Result<Self, StorageStateError> {
        match value {
            1 => Ok(Self::Ensure),
            2 => Ok(Self::RemoveAndDestroy),
            _ => Err(StorageStateError::CorruptRecord),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspacePinAttemptPhaseV1 {
    Ambiguous,
    Satisfied,
}

impl WorkspacePinAttemptPhaseV1 {
    const fn wire(self) -> u8 {
        match self {
            Self::Ambiguous => 1,
            Self::Satisfied => 2,
        }
    }

    fn from_wire(value: u8) -> Result<Self, StorageStateError> {
        match value {
            1 => Ok(Self::Ambiguous),
            2 => Ok(Self::Satisfied),
            _ => Err(StorageStateError::CorruptRecord),
        }
    }
}

/// Identifies one exact full-filesystem mount at a protected workspace slot.
///
/// `mount_id` is the non-reused `STATX_MNT_ID_UNIQUE` identity accepted by
/// `statmount(2)`, not the recyclable mountinfo ID. Construction is kept
/// crate-private because a trusted descriptor-backed observer must prove that
/// the reported mount is current and occupies the protected slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceRootPinProofV1 {
    kernel_boot_id: [u8; 16],
    mount_namespace_device: u64,
    mount_namespace_inode: u64,
    mount_id: u64,
    mount_root: String,
    mount_point: String,
    filesystem_type: String,
    superblock_source: String,
    dataset_guid: u64,
    root_device: u64,
    root_inode: u64,
}

impl WorkspaceRootPinProofV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        kernel_boot_id: [u8; 16],
        mount_namespace_device: u64,
        mount_namespace_inode: u64,
        mount_id: u64,
        mount_root: String,
        mount_point: String,
        filesystem_type: String,
        superblock_source: String,
        dataset_guid: u64,
        root_device: u64,
        root_inode: u64,
    ) -> Result<Self, StorageStateError> {
        let proof = Self {
            kernel_boot_id,
            mount_namespace_device,
            mount_namespace_inode,
            mount_id,
            mount_root,
            mount_point,
            filesystem_type,
            superblock_source,
            dataset_guid,
            root_device,
            root_inode,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub(crate) fn validate(&self) -> Result<(), StorageStateError> {
        if self.kernel_boot_id == [0; 16]
            || self.mount_namespace_device == 0
            || self.mount_namespace_inode == 0
            || self.mount_id == 0
            || self.mount_root != "/"
            || !valid_string(&self.mount_point)
            || self.filesystem_type != "zfs"
            || !valid_string(&self.superblock_source)
            || self.dataset_guid == 0
            || self.root_device == 0
            || self.root_inode == 0
        {
            return Err(StorageStateError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) const fn kernel_boot_id(&self) -> [u8; 16] {
        self.kernel_boot_id
    }

    pub(crate) const fn mount_namespace_device(&self) -> u64 {
        self.mount_namespace_device
    }

    pub(crate) const fn mount_namespace_inode(&self) -> u64 {
        self.mount_namespace_inode
    }

    pub(crate) const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    pub(crate) fn mount_root(&self) -> &str {
        &self.mount_root
    }

    pub(crate) fn mount_point(&self) -> &str {
        &self.mount_point
    }

    pub(crate) fn filesystem_type(&self) -> &str {
        &self.filesystem_type
    }

    pub(crate) fn superblock_source(&self) -> &str {
        &self.superblock_source
    }

    pub(crate) const fn dataset_guid(&self) -> u64 {
        self.dataset_guid
    }

    pub(crate) const fn root_device(&self) -> u64 {
        self.root_device
    }

    pub(crate) const fn root_inode(&self) -> u64 {
        self.root_inode
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceDatasetObservationV1 {
    Exact { name: String, guid: u64 },
    Absent,
    Mismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkspacePinObservationV1 {
    Present(WorkspaceRootPinProofV1),
    Absent,
    Mismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspacePinRecoveryDispositionV1 {
    CompletePublication,
    CompleteRetirement,
    AwaitFreshRepair,
    ObserveOnly,
    Mismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkspacePinHostScopeV1 {
    kernel_boot_id: [u8; 16],
    mount_namespace_device: u64,
    mount_namespace_inode: u64,
}

impl WorkspacePinHostScopeV1 {
    pub(crate) fn new(
        kernel_boot_id: [u8; 16],
        mount_namespace_device: u64,
        mount_namespace_inode: u64,
    ) -> Result<Self, StorageStateError> {
        if kernel_boot_id == [0; 16] || mount_namespace_device == 0 || mount_namespace_inode == 0 {
            return Err(StorageStateError::InvalidValue);
        }
        Ok(Self {
            kernel_boot_id,
            mount_namespace_device,
            mount_namespace_inode,
        })
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BeginWorkspacePinAttemptV1 {
    Dispatch(WorkspacePinAttemptV1),
    ObserveOnly(WorkspacePinAttemptV1),
    Satisfied(WorkspacePinAttemptV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkspacePinAttemptV1 {
    attempt_id: [u8; 16],
    attempt_ordinal: u8,
    action: WorkspacePinActionV1,
    phase: WorkspacePinAttemptPhaseV1,
    effect_operation_id: [u8; 16],
    creation_operation_id: [u8; 16],
    operation_fence_digest: ObjectDigest,
    effect_assignment_digest: ObjectDigest,
    workspace_assignment_digest: ObjectDigest,
    creation_result_catalog: CatalogBindingV1,
    creation_result_digest: ObjectDigest,
    workspace_handle: [u8; 32],
    host_boot_id: [u8; 16],
    host_mount_namespace_device: u64,
    host_mount_namespace_inode: u64,
    clock_provenance: [u8; 16],
    effect_deadline_boottime_nanoseconds: u64,
    dataset_name: String,
    dataset_guid: u64,
    identity_range_start: u32,
    identity_range_size: u32,
    authority_receipt: Vec<u8>,
    expected_pin: Option<WorkspaceRootPinProofV1>,
    satisfied_pin: Option<WorkspaceRootPinProofV1>,
}

impl WorkspacePinAttemptV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_ambiguous(
        attempt_id: [u8; 16],
        attempt_ordinal: u8,
        action: WorkspacePinActionV1,
        effect_operation_id: [u8; 16],
        creation_operation_id: [u8; 16],
        operation_fence_digest: ObjectDigest,
        effect_assignment_digest: ObjectDigest,
        workspace_assignment_digest: ObjectDigest,
        creation_result_catalog: CatalogBindingV1,
        creation_result_digest: ObjectDigest,
        workspace_handle: [u8; 32],
        host_boot_id: [u8; 16],
        host_mount_namespace_device: u64,
        host_mount_namespace_inode: u64,
        clock_provenance: [u8; 16],
        effect_deadline_boottime_nanoseconds: u64,
        dataset_name: String,
        dataset_guid: u64,
        identity_range_start: u32,
        identity_range_size: u32,
        expected_pin: Option<WorkspaceRootPinProofV1>,
    ) -> Result<Self, StorageStateError> {
        let attempt = Self {
            attempt_id,
            attempt_ordinal,
            action,
            phase: WorkspacePinAttemptPhaseV1::Ambiguous,
            effect_operation_id,
            creation_operation_id,
            operation_fence_digest,
            effect_assignment_digest,
            workspace_assignment_digest,
            creation_result_catalog,
            creation_result_digest,
            workspace_handle,
            host_boot_id,
            host_mount_namespace_device,
            host_mount_namespace_inode,
            clock_provenance,
            effect_deadline_boottime_nanoseconds,
            dataset_name,
            dataset_guid,
            identity_range_start,
            identity_range_size,
            authority_receipt: Vec::new(),
            expected_pin,
            satisfied_pin: None,
        };
        attempt.validate()?;
        Ok(attempt)
    }

    fn validate(&self) -> Result<(), StorageStateError> {
        if self.attempt_id == [0; 16]
            || !(1..=MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE).contains(&self.attempt_ordinal)
            || self.effect_operation_id == [0; 16]
            || self.creation_operation_id == [0; 16]
            || self.operation_fence_digest.as_bytes() == &[0; 32]
            || self.effect_assignment_digest.as_bytes() == &[0; 32]
            || self.workspace_assignment_digest.as_bytes() == &[0; 32]
            || self.creation_result_digest.as_bytes() == &[0; 32]
            || self.workspace_handle == [0; 32]
            || self.host_boot_id == [0; 16]
            || self.host_mount_namespace_device == 0
            || self.host_mount_namespace_inode == 0
            || self.clock_provenance == [0; 16]
            || self.effect_deadline_boottime_nanoseconds == 0
            || !valid_string(&self.dataset_name)
            || self.dataset_guid == 0
            || self.identity_range_start == 0
            || self.identity_range_size == 0
            || self
                .identity_range_start
                .checked_add(self.identity_range_size)
                .is_none()
            || self.authority_receipt.len() > MAXIMUM_AUTHORITY_RECEIPT_BYTES
        {
            return Err(StorageStateError::InvalidValue);
        }
        if self.creation_result_catalog.generation() == 0
            || self.creation_result_catalog.digest().as_bytes() == &[0; 32]
        {
            return Err(StorageStateError::InvalidValue);
        }
        if self
            .expected_pin
            .as_ref()
            .is_some_and(|pin| !self.matches_pin(pin))
            || self
                .satisfied_pin
                .as_ref()
                .is_some_and(|pin| !self.matches_pin(pin))
        {
            return Err(StorageStateError::InvalidValue);
        }
        match (
            self.action,
            self.phase,
            &self.expected_pin,
            &self.satisfied_pin,
        ) {
            (WorkspacePinActionV1::Ensure, WorkspacePinAttemptPhaseV1::Ambiguous, None, None)
            | (
                WorkspacePinActionV1::Ensure,
                WorkspacePinAttemptPhaseV1::Satisfied,
                None,
                Some(_),
            )
            | (
                WorkspacePinActionV1::RemoveAndDestroy,
                WorkspacePinAttemptPhaseV1::Ambiguous,
                Some(_),
                None,
            )
            | (
                WorkspacePinActionV1::RemoveAndDestroy,
                WorkspacePinAttemptPhaseV1::Satisfied,
                Some(_),
                None,
            ) => Ok(()),
            _ => Err(StorageStateError::InvalidValue),
        }
    }

    pub(crate) fn classify(
        &self,
        dataset: &WorkspaceDatasetObservationV1,
        pin: &WorkspacePinObservationV1,
    ) -> WorkspacePinRecoveryDispositionV1 {
        let exact_dataset = matches!(
            dataset,
            WorkspaceDatasetObservationV1::Exact { name, guid }
                if name == &self.dataset_name && *guid == self.dataset_guid
        );
        let exact_pin = matches!(
            pin,
            WorkspacePinObservationV1::Present(proof)
                if self.matches_pin(proof)
                    && self.expected_pin.as_ref().is_none_or(|expected| expected == proof)
                    && self.satisfied_pin.as_ref().is_none_or(|satisfied| satisfied == proof)
        );
        let dataset_absent = matches!(dataset, WorkspaceDatasetObservationV1::Absent);
        let pin_absent = matches!(pin, WorkspacePinObservationV1::Absent);

        match self.action {
            WorkspacePinActionV1::Ensure if exact_dataset && exact_pin => {
                WorkspacePinRecoveryDispositionV1::CompletePublication
            }
            WorkspacePinActionV1::Ensure
                if self.phase == WorkspacePinAttemptPhaseV1::Ambiguous
                    && exact_dataset
                    && pin_absent =>
            {
                WorkspacePinRecoveryDispositionV1::AwaitFreshRepair
            }
            WorkspacePinActionV1::RemoveAndDestroy if dataset_absent && pin_absent => {
                WorkspacePinRecoveryDispositionV1::CompleteRetirement
            }
            WorkspacePinActionV1::RemoveAndDestroy
                if self.phase == WorkspacePinAttemptPhaseV1::Ambiguous
                    && exact_dataset
                    && exact_pin =>
            {
                WorkspacePinRecoveryDispositionV1::ObserveOnly
            }
            WorkspacePinActionV1::RemoveAndDestroy
                if self.phase == WorkspacePinAttemptPhaseV1::Ambiguous
                    && exact_dataset
                    && pin_absent =>
            {
                WorkspacePinRecoveryDispositionV1::AwaitFreshRepair
            }
            _ => WorkspacePinRecoveryDispositionV1::Mismatch,
        }
    }

    pub(crate) fn satisfy(
        &self,
        observed_pin: Option<WorkspaceRootPinProofV1>,
    ) -> Result<Self, StorageStateError> {
        if self.phase != WorkspacePinAttemptPhaseV1::Ambiguous {
            return Err(StorageStateError::InvalidTransition);
        }
        let mut satisfied = self.clone();
        satisfied.phase = WorkspacePinAttemptPhaseV1::Satisfied;
        satisfied.satisfied_pin = observed_pin;
        satisfied.validate()?;
        Ok(satisfied)
    }

    pub(crate) const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    pub(crate) const fn attempt_ordinal(&self) -> u8 {
        self.attempt_ordinal
    }

    pub(crate) const fn action(&self) -> WorkspacePinActionV1 {
        self.action
    }

    pub(crate) const fn phase(&self) -> WorkspacePinAttemptPhaseV1 {
        self.phase
    }

    pub(crate) const fn effect_operation_id(&self) -> [u8; 16] {
        self.effect_operation_id
    }

    pub(crate) const fn creation_operation_id(&self) -> [u8; 16] {
        self.creation_operation_id
    }

    pub(crate) const fn operation_fence_digest(&self) -> ObjectDigest {
        self.operation_fence_digest
    }

    pub(crate) const fn effect_assignment_digest(&self) -> ObjectDigest {
        self.effect_assignment_digest
    }

    pub(crate) const fn workspace_assignment_digest(&self) -> ObjectDigest {
        self.workspace_assignment_digest
    }

    pub(crate) const fn creation_result_catalog(&self) -> CatalogBindingV1 {
        self.creation_result_catalog
    }

    pub(crate) const fn creation_result_digest(&self) -> ObjectDigest {
        self.creation_result_digest
    }

    pub(crate) const fn workspace_handle(&self) -> [u8; 32] {
        self.workspace_handle
    }

    pub(crate) const fn host_boot_id(&self) -> [u8; 16] {
        self.host_boot_id
    }

    pub(crate) const fn host_mount_namespace_device(&self) -> u64 {
        self.host_mount_namespace_device
    }

    pub(crate) const fn host_mount_namespace_inode(&self) -> u64 {
        self.host_mount_namespace_inode
    }

    pub(crate) const fn clock_provenance(&self) -> [u8; 16] {
        self.clock_provenance
    }

    pub(crate) const fn effect_deadline_boottime_nanoseconds(&self) -> u64 {
        self.effect_deadline_boottime_nanoseconds
    }

    pub(crate) fn dataset_name(&self) -> &str {
        &self.dataset_name
    }

    pub(crate) const fn dataset_guid(&self) -> u64 {
        self.dataset_guid
    }

    pub(crate) const fn identity_range_start(&self) -> u32 {
        self.identity_range_start
    }

    pub(crate) const fn identity_range_size(&self) -> u32 {
        self.identity_range_size
    }

    pub(crate) fn expected_pin(&self) -> Option<&WorkspaceRootPinProofV1> {
        self.expected_pin.as_ref()
    }

    pub(crate) fn authority_receipt(&self) -> &[u8] {
        &self.authority_receipt
    }

    pub(crate) fn satisfied_pin(&self) -> Option<&WorkspaceRootPinProofV1> {
        self.satisfied_pin.as_ref()
    }

    pub(crate) fn authority_digest(&self) -> Result<ObjectDigest, StorageStateError> {
        // The receipt authorizes the immutable effect, not its later journaled
        // observation. Every receipt is minted for the initial Ambiguous/None
        // shape, so normalize those two mutable fields for verification after
        // a durable Satisfied transition. The journal MAC continues to bind
        // the complete phase and observed pin proof.
        let mut unsealed = self.clone();
        unsealed.phase = WorkspacePinAttemptPhaseV1::Ambiguous;
        unsealed.satisfied_pin = None;
        unsealed.authority_receipt.clear();
        let canonical = encode_attempt(&unsealed, [0x5a; 16], &[0xa5; 32])?;
        let mut digest = Sha256::new();
        digest.update(ATTEMPT_AUTHORITY_DOMAIN);
        digest.update(canonical);
        Ok(ObjectDigest::from_bytes(digest.finalize().into()))
    }

    pub(crate) fn same_authorized_effect(&self, other: &Self) -> bool {
        self.attempt_id == other.attempt_id
            && self.attempt_ordinal == other.attempt_ordinal
            && self.action == other.action
            && self.effect_operation_id == other.effect_operation_id
            && self.creation_operation_id == other.creation_operation_id
            && self.operation_fence_digest == other.operation_fence_digest
            && self.effect_assignment_digest == other.effect_assignment_digest
            && self.workspace_assignment_digest == other.workspace_assignment_digest
            && self.creation_result_catalog == other.creation_result_catalog
            && self.creation_result_digest == other.creation_result_digest
            && self.workspace_handle == other.workspace_handle
            && self.host_boot_id == other.host_boot_id
            && self.host_mount_namespace_device == other.host_mount_namespace_device
            && self.host_mount_namespace_inode == other.host_mount_namespace_inode
            && self.clock_provenance == other.clock_provenance
            && self.effect_deadline_boottime_nanoseconds
                == other.effect_deadline_boottime_nanoseconds
            && self.dataset_name == other.dataset_name
            && self.dataset_guid == other.dataset_guid
            && self.identity_range_start == other.identity_range_start
            && self.identity_range_size == other.identity_range_size
            && self.expected_pin == other.expected_pin
    }

    pub(crate) fn with_authority_receipt(
        &self,
        authority_receipt: Vec<u8>,
    ) -> Result<Self, StorageStateError> {
        if authority_receipt.is_empty() || authority_receipt.len() > MAXIMUM_AUTHORITY_RECEIPT_BYTES
        {
            return Err(StorageStateError::InvalidValue);
        }
        let mut authorized = self.clone();
        authorized.authority_receipt = authority_receipt;
        authorized.validate()?;
        Ok(authorized)
    }

    pub(crate) fn capacity_completion(&self) -> Result<Self, StorageStateError> {
        match self.action {
            WorkspacePinActionV1::Ensure => self.satisfy(Some(WorkspaceRootPinProofV1::new(
                self.host_boot_id,
                self.host_mount_namespace_device,
                self.host_mount_namespace_inode,
                u64::MAX,
                "/".to_owned(),
                workspace_pin_path(&self.workspace_handle),
                "zfs".to_owned(),
                self.dataset_name.clone(),
                self.dataset_guid,
                u64::MAX,
                u64::MAX,
            )?)),
            WorkspacePinActionV1::RemoveAndDestroy => self.satisfy(None),
        }
    }

    fn matches_pin(&self, proof: &WorkspaceRootPinProofV1) -> bool {
        proof.kernel_boot_id == self.host_boot_id
            && proof.mount_namespace_device == self.host_mount_namespace_device
            && proof.mount_namespace_inode == self.host_mount_namespace_inode
            && proof.mount_root == "/"
            && proof.mount_point == workspace_pin_path(&self.workspace_handle)
            && proof.filesystem_type == "zfs"
            && proof.superblock_source == self.dataset_name
            && proof.dataset_guid == self.dataset_guid
    }
}

pub(crate) fn derive_attempt_id(
    secret: &[u8; 32],
    effect_operation_id: [u8; 16],
    workspace_handle: [u8; 32],
    action: WorkspacePinActionV1,
    ordinal: u8,
) -> Result<[u8; 16], StorageStateError> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(ATTEMPT_ID_DOMAIN);
    mac.update(&effect_operation_id);
    mac.update(&workspace_handle);
    mac.update(&[action.wire(), ordinal]);
    let digest = mac.finalize().into_bytes();
    let mut attempt_id = [0; 16];
    attempt_id.copy_from_slice(&digest[..16]);
    if attempt_id == [0; 16] {
        attempt_id[15] = 1;
    }
    Ok(attempt_id)
}

pub(crate) fn load_attempts(
    journal: &Journal,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<BTreeMap<[u8; 16], WorkspacePinAttemptV1>, StorageStateError> {
    let mut attempts = BTreeMap::new();
    for (record_key, bytes) in journal.records(RecordNamespace::StorageWorkspacePinAttempt) {
        let attempt = decode_attempt(bytes, key_id, secret)?;
        if record_key != attempt.attempt_id()
            || attempts.insert(attempt.attempt_id(), attempt).is_some()
        {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    Ok(attempts)
}

pub(crate) fn attempt_record(
    attempt: &WorkspacePinAttemptV1,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<JournalRecord, StorageStateError> {
    if attempt.authority_receipt.is_empty() {
        return Err(StorageStateError::MissingAuthorityLink);
    }
    Ok(JournalRecord::put(
        RecordNamespace::StorageWorkspacePinAttempt,
        attempt.attempt_id().to_vec(),
        encode_attempt(attempt, key_id, secret)?,
    ))
}

fn encode_attempt(
    attempt: &WorkspacePinAttemptV1,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<Vec<u8>, StorageStateError> {
    attempt.validate()?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&key_id);
    bytes.extend_from_slice(&attempt.attempt_id);
    bytes.push(attempt.attempt_ordinal);
    bytes.push(attempt.action.wire());
    bytes.push(attempt.phase.wire());
    bytes.extend_from_slice(&attempt.effect_operation_id);
    bytes.extend_from_slice(&attempt.creation_operation_id);
    bytes.extend_from_slice(attempt.operation_fence_digest.as_bytes());
    bytes.extend_from_slice(attempt.effect_assignment_digest.as_bytes());
    bytes.extend_from_slice(attempt.workspace_assignment_digest.as_bytes());
    bytes.extend_from_slice(&attempt.creation_result_catalog.generation().to_be_bytes());
    bytes.extend_from_slice(attempt.creation_result_catalog.digest().as_bytes());
    bytes.extend_from_slice(attempt.creation_result_digest.as_bytes());
    bytes.extend_from_slice(&attempt.workspace_handle);
    bytes.extend_from_slice(&attempt.host_boot_id);
    bytes.extend_from_slice(&attempt.host_mount_namespace_device.to_be_bytes());
    bytes.extend_from_slice(&attempt.host_mount_namespace_inode.to_be_bytes());
    bytes.extend_from_slice(&attempt.clock_provenance);
    bytes.extend_from_slice(&attempt.effect_deadline_boottime_nanoseconds.to_be_bytes());
    put_string(&mut bytes, &attempt.dataset_name)?;
    bytes.extend_from_slice(&attempt.dataset_guid.to_be_bytes());
    bytes.extend_from_slice(&attempt.identity_range_start.to_be_bytes());
    bytes.extend_from_slice(&attempt.identity_range_size.to_be_bytes());
    put_bytes(&mut bytes, &attempt.authority_receipt)?;
    put_optional_proof(&mut bytes, attempt.expected_pin.as_ref())?;
    put_optional_proof(&mut bytes, attempt.satisfied_pin.as_ref())?;
    let tag = record_tag(secret, &attempt.attempt_id, &bytes)?;
    bytes.extend_from_slice(&tag);
    Ok(bytes)
}

pub(crate) fn decode_attempt(
    bytes: &[u8],
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<WorkspacePinAttemptV1, StorageStateError> {
    if bytes.len() < MINIMUM_ATTEMPT_BODY_BYTES + MAC_BYTES {
        return Err(StorageStateError::CorruptRecord);
    }
    let (body, supplied_tag) = bytes.split_at(bytes.len() - MAC_BYTES);
    let mut decoder = Decoder::new(body);
    if decoder.array::<8>()? != *MAGIC
        || decoder.u16()? != VERSION
        || decoder.array::<16>()? != key_id
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let attempt_id = decoder.array::<16>()?;
    let expected_tag = record_tag(secret, &attempt_id, body)?;
    if !constant_time_eq(supplied_tag, &expected_tag) {
        return Err(StorageStateError::CorruptRecord);
    }
    let attempt = WorkspacePinAttemptV1 {
        attempt_id,
        attempt_ordinal: decoder.u8()?,
        action: WorkspacePinActionV1::from_wire(decoder.u8()?)?,
        phase: WorkspacePinAttemptPhaseV1::from_wire(decoder.u8()?)?,
        effect_operation_id: decoder.array()?,
        creation_operation_id: decoder.array()?,
        operation_fence_digest: ObjectDigest::from_bytes(decoder.array()?),
        effect_assignment_digest: ObjectDigest::from_bytes(decoder.array()?),
        workspace_assignment_digest: ObjectDigest::from_bytes(decoder.array()?),
        creation_result_catalog: CatalogBindingV1::from_publisher(
            decoder.u64()?,
            ObjectDigest::from_bytes(decoder.array()?),
        )
        .map_err(|_| StorageStateError::CorruptRecord)?,
        creation_result_digest: ObjectDigest::from_bytes(decoder.array()?),
        workspace_handle: decoder.array()?,
        host_boot_id: decoder.array()?,
        host_mount_namespace_device: decoder.u64()?,
        host_mount_namespace_inode: decoder.u64()?,
        clock_provenance: decoder.array()?,
        effect_deadline_boottime_nanoseconds: decoder.u64()?,
        dataset_name: decoder.string()?,
        dataset_guid: decoder.u64()?,
        identity_range_start: decoder.u32()?,
        identity_range_size: decoder.u32()?,
        authority_receipt: decoder.bytes()?,
        expected_pin: decoder.optional_proof()?,
        satisfied_pin: decoder.optional_proof()?,
    };
    if !decoder.is_empty() {
        return Err(StorageStateError::CorruptRecord);
    }
    attempt
        .validate()
        .map_err(|_| StorageStateError::CorruptRecord)?;
    if attempt.authority_receipt.is_empty() {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(attempt)
}

fn put_optional_proof(
    bytes: &mut Vec<u8>,
    proof: Option<&WorkspaceRootPinProofV1>,
) -> Result<(), StorageStateError> {
    let Some(proof) = proof else {
        bytes.push(0);
        return Ok(());
    };
    proof.validate()?;
    bytes.push(1);
    bytes.extend_from_slice(&proof.kernel_boot_id);
    bytes.extend_from_slice(&proof.mount_namespace_device.to_be_bytes());
    bytes.extend_from_slice(&proof.mount_namespace_inode.to_be_bytes());
    bytes.extend_from_slice(&proof.mount_id.to_be_bytes());
    put_string(bytes, &proof.mount_root)?;
    put_string(bytes, &proof.mount_point)?;
    put_string(bytes, &proof.filesystem_type)?;
    put_string(bytes, &proof.superblock_source)?;
    bytes.extend_from_slice(&proof.dataset_guid.to_be_bytes());
    bytes.extend_from_slice(&proof.root_device.to_be_bytes());
    bytes.extend_from_slice(&proof.root_inode.to_be_bytes());
    Ok(())
}

fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), StorageStateError> {
    if !valid_string(value) {
        return Err(StorageStateError::InvalidValue);
    }
    let length = u16::try_from(value.len()).map_err(|_| StorageStateError::InvalidValue)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), StorageStateError> {
    if value.len() > MAXIMUM_AUTHORITY_RECEIPT_BYTES {
        return Err(StorageStateError::InvalidValue);
    }
    let length = u16::try_from(value.len()).map_err(|_| StorageStateError::InvalidValue)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn valid_string(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAXIMUM_STRING_BYTES && !value.as_bytes().contains(&0)
}

pub(crate) fn workspace_pin_path(workspace_handle: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut path = String::with_capacity(WORKSPACE_PIN_ROOT.len() + 1 + 64);
    path.push_str(WORKSPACE_PIN_ROOT);
    path.push('/');
    for byte in workspace_handle {
        let _ = write!(path, "{byte:02x}");
    }
    path
}

fn record_tag(
    secret: &[u8; 32],
    attempt_id: &[u8; 16],
    body: &[u8],
) -> Result<[u8; MAC_BYTES], StorageStateError> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(RECORD_DOMAIN);
    mac.update(&[RecordNamespace::StorageWorkspacePinAttempt as u8]);
    mac.update(attempt_id);
    mac.update(body);
    Ok(mac.finalize().into_bytes().into())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StorageStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StorageStateError::CorruptRecord)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StorageStateError::CorruptRecord)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StorageStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)
    }

    fn u8(&mut self) -> Result<u8, StorageStateError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(StorageStateError::CorruptRecord)
    }

    fn u16(&mut self) -> Result<u16, StorageStateError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, StorageStateError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, StorageStateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn string(&mut self) -> Result<String, StorageStateError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > MAXIMUM_STRING_BYTES {
            return Err(StorageStateError::CorruptRecord);
        }
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| StorageStateError::CorruptRecord)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, StorageStateError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > MAXIMUM_AUTHORITY_RECEIPT_BYTES {
            return Err(StorageStateError::CorruptRecord);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn optional_proof(&mut self) -> Result<Option<WorkspaceRootPinProofV1>, StorageStateError> {
        match self.u8()? {
            0 => Ok(None),
            1 => WorkspaceRootPinProofV1::new(
                self.array()?,
                self.u64()?,
                self.u64()?,
                self.u64()?,
                self.string()?,
                self.string()?,
                self.string()?,
                self.string()?,
                self.u64()?,
                self.u64()?,
                self.u64()?,
            )
            .map(Some)
            .map_err(|_| StorageStateError::CorruptRecord),
            _ => Err(StorageStateError::CorruptRecord),
        }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn catalog() -> CatalogBindingV1 {
        CatalogBindingV1::from_publisher(8, ObjectDigest::from_bytes([8; 32])).unwrap()
    }

    fn proof(name: &str, guid: u64) -> WorkspaceRootPinProofV1 {
        WorkspaceRootPinProofV1::new(
            [1; 16],
            2,
            3,
            4,
            "/".to_owned(),
            workspace_pin_path(&[8; 32]),
            "zfs".to_owned(),
            name.to_owned(),
            guid,
            5,
            6,
        )
        .unwrap()
    }

    fn attempt(action: WorkspacePinActionV1) -> WorkspacePinAttemptV1 {
        WorkspacePinAttemptV1::new_ambiguous(
            [1; 16],
            1,
            action,
            [2; 16],
            [3; 16],
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes([6; 32]),
            catalog(),
            ObjectDigest::from_bytes([7; 32]),
            [8; 32],
            [1; 16],
            2,
            3,
            [10; 16],
            1_000,
            "tank/aos/work".to_owned(),
            9,
            100_000,
            65_536,
            (action == WorkspacePinActionV1::RemoveAndDestroy).then(|| proof("tank/aos/work", 9)),
        )
        .unwrap()
        .with_authority_receipt(vec![0xa5])
        .unwrap()
    }

    #[test]
    fn codec_authenticates_location_and_content() {
        let key_id = [10; 16];
        let secret = [11; 32];
        let attempt = attempt(WorkspacePinActionV1::RemoveAndDestroy);
        let record = attempt_record(&attempt, key_id, &secret).unwrap();
        let bytes = record.value().unwrap();

        assert_eq!(decode_attempt(bytes, key_id, &secret).unwrap(), attempt);

        let mut changed = bytes.to_vec();
        changed[70] ^= 1;
        assert!(decode_attempt(&changed, key_id, &secret).is_err());
        assert!(decode_attempt(bytes, [12; 16], &secret).is_err());
        assert!(decode_attempt(bytes, key_id, &[13; 32]).is_err());
    }

    #[test]
    fn codec_roundtrips_every_legal_shape_at_minimum_name_length() {
        let key_id = [10; 16];
        let secret = [11; 32];
        let mut ensure = attempt(WorkspacePinActionV1::Ensure);
        ensure.dataset_name = "x".to_owned();
        let ensure_pin = WorkspaceRootPinProofV1::new(
            [1; 16],
            2,
            3,
            4,
            "/".to_owned(),
            workspace_pin_path(&[8; 32]),
            "zfs".to_owned(),
            "x".to_owned(),
            9,
            5,
            6,
        )
        .unwrap();
        let ensure_satisfied = ensure.satisfy(Some(ensure_pin)).unwrap();
        let remove = attempt(WorkspacePinActionV1::RemoveAndDestroy);
        let remove_satisfied = remove.satisfy(None).unwrap();

        for candidate in [&ensure, &ensure_satisfied, &remove, &remove_satisfied] {
            let encoded = encode_attempt(candidate, key_id, &secret).unwrap();
            assert!(encoded.len() >= MINIMUM_ATTEMPT_BODY_BYTES + MAC_BYTES);
            assert_eq!(
                decode_attempt(&encoded, key_id, &secret).unwrap(),
                *candidate
            );
        }
    }

    #[test]
    fn authority_digest_survives_satisfaction_but_binds_immutable_effect() {
        let ensure = attempt(WorkspacePinActionV1::Ensure);
        let satisfied = ensure.satisfy(Some(proof("tank/aos/work", 9))).unwrap();

        assert_eq!(
            ensure.authority_digest().unwrap(),
            satisfied.authority_digest().unwrap()
        );

        let mut substituted = satisfied;
        substituted.dataset_guid += 1;
        assert_ne!(
            ensure.authority_digest().unwrap(),
            substituted.authority_digest().unwrap()
        );
    }

    #[test]
    fn ensure_recovery_never_hides_a_remount() {
        let attempt = attempt(WorkspacePinActionV1::Ensure);
        let exact_dataset = WorkspaceDatasetObservationV1::Exact {
            name: "tank/aos/work".to_owned(),
            guid: 9,
        };

        assert_eq!(
            attempt.classify(
                &exact_dataset,
                &WorkspacePinObservationV1::Present(proof("tank/aos/work", 9))
            ),
            WorkspacePinRecoveryDispositionV1::CompletePublication
        );
        assert_eq!(
            attempt.classify(&exact_dataset, &WorkspacePinObservationV1::Absent),
            WorkspacePinRecoveryDispositionV1::AwaitFreshRepair
        );
        assert_eq!(
            attempt.classify(
                &exact_dataset,
                &WorkspacePinObservationV1::Present(proof("tank/aos/other", 9))
            ),
            WorkspacePinRecoveryDispositionV1::Mismatch
        );

        let wrong_namespace = WorkspaceRootPinProofV1::new(
            [1; 16],
            20,
            3,
            4,
            "/".to_owned(),
            workspace_pin_path(&[8; 32]),
            "zfs".to_owned(),
            "tank/aos/work".to_owned(),
            9,
            5,
            6,
        )
        .unwrap();
        assert_eq!(
            attempt.classify(
                &exact_dataset,
                &WorkspacePinObservationV1::Present(wrong_namespace)
            ),
            WorkspacePinRecoveryDispositionV1::Mismatch
        );

        let wrong_slot = WorkspaceRootPinProofV1::new(
            [1; 16],
            2,
            3,
            4,
            "/".to_owned(),
            workspace_pin_path(&[9; 32]),
            "zfs".to_owned(),
            "tank/aos/work".to_owned(),
            9,
            5,
            6,
        )
        .unwrap();
        assert_eq!(
            attempt.classify(
                &exact_dataset,
                &WorkspacePinObservationV1::Present(wrong_slot)
            ),
            WorkspacePinRecoveryDispositionV1::Mismatch
        );

        assert!(
            WorkspaceRootPinProofV1::new(
                [1; 16],
                2,
                3,
                4,
                "/subtree".to_owned(),
                workspace_pin_path(&[8; 32]),
                "zfs".to_owned(),
                "tank/aos/work".to_owned(),
                9,
                5,
                6,
            )
            .is_err()
        );
    }

    #[test]
    fn remove_recovery_distinguishes_no_effect_partial_and_completion() {
        let attempt = attempt(WorkspacePinActionV1::RemoveAndDestroy);
        let exact_dataset = WorkspaceDatasetObservationV1::Exact {
            name: "tank/aos/work".to_owned(),
            guid: 9,
        };
        let exact_pin = WorkspacePinObservationV1::Present(proof("tank/aos/work", 9));

        assert_eq!(
            attempt.classify(&exact_dataset, &exact_pin),
            WorkspacePinRecoveryDispositionV1::ObserveOnly
        );
        assert_eq!(
            attempt.classify(&exact_dataset, &WorkspacePinObservationV1::Absent),
            WorkspacePinRecoveryDispositionV1::AwaitFreshRepair
        );
        assert_eq!(
            attempt.classify(
                &WorkspaceDatasetObservationV1::Absent,
                &WorkspacePinObservationV1::Absent
            ),
            WorkspacePinRecoveryDispositionV1::CompleteRetirement
        );
        assert_eq!(
            attempt.classify(&WorkspaceDatasetObservationV1::Absent, &exact_pin),
            WorkspacePinRecoveryDispositionV1::Mismatch
        );
    }
}
