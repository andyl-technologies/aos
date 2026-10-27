//! Authoritative Storage workspace-inventory validation.
//!
//! Storage reports current launchable workspace roots plus an optional complete
//! lifecycle catalog extension produced by the protected Storage runtime. Each
//! launch row binds an exact assignment and portable
//! root image to a current-boot root pin, ZFS dataset GUID, subordinate identity
//! range, and broker observation digest. Paths are derived locally from opaque
//! handles:
//!
//! ```text
//! /run/aos/sandbox-pins/workspaces/<64 lowercase hexadecimal digits>
//! ```
//!
//! The complete response is bounded. Launch rows are strictly handle ordered;
//! lifecycle rows and transitions have their own strict canonical order.
//! Identity ranges, physical pins, and dataset GUIDs must be unique across the
//! launch snapshot.

use std::collections::BTreeSet;

mod capture;
pub(crate) use capture::InventoryResponseCaptureV1;
use aos_sandbox_model::retained::CaptureValueV1;
use crate::capture::decode_message_v1;

use aos_sandbox_api::aos::sandbox::local::v1::{
    InventoryStorageRequest, InventoryStorageResourcesResponse, RecoverStorageInventoryRequestV1,
    RecoverStorageInventoryResponseV1, StorageAtomicSnapshotCheckpoint,
    StorageInventoryRecoveryDispositionV1, StorageLifecycleInventoryRecord,
    StorageLifecycleTransitionRecord, StorageOperatorRepairCommitRecordV1,
    StorageWorkspaceInventoryRecord,
};
use aos_sandbox_guest_protocol::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_model::{DescriptorRole, ObjectDescriptor, ProtocolId, ProtocolVersion};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, MINIMUM_HOST_IDENTITY_RANGE,
    MINIMUM_RESPONSE_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    ValidatedAssignmentFence, ValidatedHeader, WORKSPACE_PIN_PREFIX, exact_nonzero,
    validate_descriptor, validate_fence, validate_request_header,
};

/// Maximum current workspaces accepted in one complete Storage snapshot.
pub const MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS: usize = 16_384;
const STORAGE_RESOURCE_INVENTORY_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

/// Carries one complete validated Storage resource snapshot.
#[derive(Clone, Debug)]
pub struct ValidatedStorageInventory {
    encoded_response_digest: [u8; 32],
    kernel_boot_id: [u8; 16],
    broker_instance_id: [u8; 16],
    journal_sequence: u64,
    catalog_generation: u64,
    workspaces: Vec<ValidatedStorageWorkspace>,
    operator_repair_commits: Vec<ValidatedStorageOperatorRepairCommitV1>,
}

// The added wire commitment is provenance DATA. Ordinary semantic inventory
// equality preserves its existing field comparison, independent of wire order.
impl PartialEq for ValidatedStorageInventory {
    fn eq(&self, other: &Self) -> bool {
        self.kernel_boot_id == other.kernel_boot_id
            && self.broker_instance_id == other.broker_instance_id
            && self.journal_sequence == other.journal_sequence
            && self.catalog_generation == other.catalog_generation
            && self.workspaces == other.workspaces
            && self.operator_repair_commits == other.operator_repair_commits
    }
}

impl Eq for ValidatedStorageInventory {}

impl ValidatedStorageInventory {
    /// Returns SHA-256 of the exact response bytes decoded by the sole validator.
    ///
    /// This immutable comparison value does not authenticate a Session or grant
    /// native currentness. A genuine consumer separately joins the exact signed
    /// terminal body and its actual native receiver before using this model.
    #[must_use]
    pub const fn encoded_response_digest_v1(&self) -> [u8; 32] {
        self.encoded_response_digest
    }

    /// Returns the current Linux boot identifier.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> &[u8; 16] {
        &self.kernel_boot_id
    }

    /// Returns the process identity of the broker that emitted this snapshot.
    #[must_use]
    pub const fn broker_instance_id(&self) -> &[u8; 16] {
        &self.broker_instance_id
    }

    /// Returns the next durable journal boundary after this snapshot.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns the protected Storage catalog generation used for observation.
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    /// Returns current launchable workspaces in strict handle order.
    #[must_use]
    pub fn workspaces(&self) -> &[ValidatedStorageWorkspace] {
        &self.workspaces
    }

    /// Returns independently broker-authenticated durable Repair commits.
    #[must_use]
    pub fn operator_repair_commits(&self) -> &[ValidatedStorageOperatorRepairCommitV1] {
        &self.operator_repair_commits
    }
}

/// Binds one satisfied Repair attempt to its exact request and durable record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedStorageOperatorRepairCommitV1 {
    operation_id: [u8; 16],
    workspace_handle: [u8; 32],
    request_digest: [u8; 32],
    effect_commit_digest: [u8; 32],
}

impl ValidatedStorageOperatorRepairCommitV1 {
    /// Returns the unique Repair operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &[u8; 16] {
        &self.operation_id
    }

    /// Returns the exact repaired workspace handle.
    #[must_use]
    pub const fn workspace_handle(&self) -> &[u8; 32] {
        &self.workspace_handle
    }

    /// Returns SHA-256 of the exact authorized Storage request body.
    #[must_use]
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    /// Returns the domain-separated digest of the durable attempt record.
    #[must_use]
    pub const fn effect_commit_digest(&self) -> &[u8; 32] {
        &self.effect_commit_digest
    }
}

/// Carries immutable creation identity and a separately authenticated current publication.
#[derive(Clone, Debug)]
pub struct ValidatedStorageWorkspace {
    workspace_handle: [u8; 32],
    fence: ValidatedAssignmentFence,
    root_image: ObjectDescriptor,
    resource_kernel_boot_id: [u8; 16],
    root_directory: String,
    root_device: u64,
    root_inode: u64,
    dataset_guid: u64,
    creation_operation_id: [u8; 16],
    guest_root_publication_proof: Option<GuestRootPublicationProofV1>,
    current_guest_root_publication_v2: Option<crate::semantics::storage_guest_root::StorageGuestRootCurrentPublicationDataV2>,
    uid_range_start: u32,
    uid_range_size: u32,
    resource_digest: [u8; 32],
}

// Historical Create equality retains its exact creation/physical meaning.
// Current assignment consumers compare the explicit V2 publication through
// its shared typed relation and their actual new manifest/lease; Eq is no grant.
impl PartialEq for ValidatedStorageWorkspace {
    fn eq(&self, other: &Self) -> bool {
        self.workspace_handle == other.workspace_handle && self.fence == other.fence
            && self.root_image == other.root_image && self.resource_kernel_boot_id == other.resource_kernel_boot_id
            && self.root_directory == other.root_directory && self.root_device == other.root_device
            && self.root_inode == other.root_inode && self.dataset_guid == other.dataset_guid
            && self.creation_operation_id == other.creation_operation_id
            && self.guest_root_publication_proof == other.guest_root_publication_proof
            && self.uid_range_start == other.uid_range_start && self.uid_range_size == other.uid_range_size
            && self.resource_digest == other.resource_digest
    }
}

impl Eq for ValidatedStorageWorkspace {}

impl ValidatedStorageWorkspace {
    /// Returns the opaque workspace handle.
    #[must_use]
    pub const fn workspace_handle(&self) -> &[u8; 32] {
        &self.workspace_handle
    }

    /// Returns the exact assignment owning the workspace.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the portable root image bound to the workspace.
    #[must_use]
    pub const fn root_image(&self) -> &ObjectDescriptor {
        &self.root_image
    }

    /// Returns the boot in which the root pin was observed.
    #[must_use]
    pub const fn resource_kernel_boot_id(&self) -> &[u8; 16] {
        &self.resource_kernel_boot_id
    }

    /// Returns the fixed root-owned pin derived from the opaque handle.
    #[must_use]
    pub fn root_directory(&self) -> &str {
        &self.root_directory
    }

    /// Returns the observed root-directory device identity.
    #[must_use]
    pub const fn root_device(&self) -> u64 {
        self.root_device
    }

    /// Returns the observed root-directory inode identity.
    #[must_use]
    pub const fn root_inode(&self) -> u64 {
        self.root_inode
    }

    /// Returns the non-recycled ZFS dataset GUID behind this workspace.
    #[must_use]
    pub const fn dataset_guid(&self) -> u64 {
        self.dataset_guid
    }

    /// Returns the operation that originally created this dataset and handle.
    #[must_use]
    pub const fn creation_operation_id(&self) -> &[u8; 16] {
        &self.creation_operation_id
    }

    /// Returns protected Storage's physically read-back guest-root proof, if published.
    ///
    /// Absence is not launch readiness. Callers must compare this proof to the
    /// current assignment and their independently pinned package binding.
    #[must_use]
    pub const fn guest_root_publication_proof(&self) -> Option<GuestRootPublicationProofV1> {
        self.guest_root_publication_proof
    }

    /// Borrows the current signed publication separately from its creation root.
    ///
    /// This remains comparison DATA; genuine signed Inventory/currentness and
    /// the new Root/lease originals must establish its live provenance.
    #[must_use]
    pub const fn current_guest_root_publication_v2(&self)
        -> Option<&crate::semantics::storage_guest_root::StorageGuestRootCurrentPublicationDataV2> {
        self.current_guest_root_publication_v2.as_ref()
    }

    /// Returns the first host identity mapped to guest identity zero.
    #[must_use]
    pub const fn uid_range_start(&self) -> u32 {
        self.uid_range_start
    }

    /// Returns the number of subordinate identities assigned to the workspace.
    #[must_use]
    pub const fn uid_range_size(&self) -> u32 {
        self.uid_range_size
    }

    /// Returns the commitment to the broker's complete current observation.
    #[must_use]
    pub const fn resource_digest(&self) -> &[u8; 32] {
        &self.resource_digest
    }
}

/// Decodes the sole Storage authoritative-inventory request.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed request,
/// invalid peer/header semantics, unknown fields, or a protocol version other
/// than the exact Storage baseline.
pub fn decode_storage_resource_inventory_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    decode_storage_resource_inventory_request_engine(bytes, peer, policy, now_boottime_nanoseconds, None)
}

pub(crate) fn decode_storage_resource_inventory_request_engine(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
    capture: Option<(&mut InventoryStorageRequest, &mut Option<Result<(), buffa::DecodeError>>)>,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let (raw, outcome) = match capture {
        Some((raw, outcome)) => (Some(raw), Some(outcome)),
        None => (None, None),
    };
    let request = crate::capture::decode_message_v1(bytes, raw, outcome)?;
    reject_unknown(&request.__buffa_unknown_fields)?;
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::StorageBroker,
        now_boottime_nanoseconds,
    )?;
    if header.protocol_version() != STORAGE_RESOURCE_INVENTORY_VERSION {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    Ok(header)
}

/// Binds one recovery-only query to the original signed post-group inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedStorageInventoryRecoveryRequestV1 {
    header: ValidatedHeader,
    group_request_id: [u8; 16],
    group_request_digest: [u8; 32],
    inventory_request_id: [u8; 16],
    inventory_request_digest: [u8; 32],
    client_original_head: [u8; 32],
}

impl ValidatedStorageInventoryRecoveryRequestV1 {
    /// Returns the authenticated request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact original grouped-snapshot request identity.
    #[must_use]
    pub const fn group_request_id(&self) -> [u8; 16] {
        self.group_request_id
    }

    /// Returns the original grouped-snapshot authority-envelope digest.
    #[must_use]
    pub const fn group_request_digest(&self) -> [u8; 32] {
        self.group_request_digest
    }

    /// Returns the exact original inventory request identity.
    #[must_use]
    pub const fn inventory_request_id(&self) -> [u8; 16] {
        self.inventory_request_id
    }

    /// Returns the digest of the original signed inventory request packet.
    #[must_use]
    pub const fn inventory_request_digest(&self) -> [u8; 32] {
        self.inventory_request_digest
    }

    /// Returns the original protected client journal head.
    #[must_use]
    pub const fn client_original_head(&self) -> [u8; 32] {
        self.client_original_head
    }
}

/// Decodes the recovery-only control request without permitting an inventory read.
///
/// # Errors
///
/// Returns an error for malformed, oversized, unknown, zero, or mismatched
/// request fields or an invalid Storage peer/header.
pub fn decode_storage_inventory_recovery_request_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedStorageInventoryRecoveryRequestV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = RecoverStorageInventoryRequestV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&request.__buffa_unknown_fields)?;
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::StorageBroker,
        now_boottime_nanoseconds,
    )?;
    if header.protocol_version() != STORAGE_RESOURCE_INVENTORY_VERSION {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    Ok(ValidatedStorageInventoryRecoveryRequestV1 {
        header,
        group_request_id: exact_nonzero(&request.group_request_id, "group_request_id")?,
        group_request_digest: exact_nonzero(&request.group_request_digest, "group_request_digest")?,
        inventory_request_id: exact_nonzero(&request.inventory_request_id, "inventory_request_id")?,
        inventory_request_digest: exact_nonzero(
            &request.inventory_request_digest,
            "inventory_request_digest",
        )?,
        client_original_head: exact_nonzero(&request.client_original_head, "client_original_head")?,
    })
}

/// Distinguishes a reauthenticated old terminal from protected read-only abandonment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatedStorageInventoryRecoveryResponseV1 {
    /// The broker retained the exact original signed terminal packet.
    OriginalTerminal {
        /// Exact original signed response bytes, not a newly minted status.
        packet: Vec<u8>,
        /// Original protected broker history head.
        broker_head: [u8; 32],
        /// Digest of the broker's immutable original-history archive.
        archive_digest: [u8; 32],
    },
    /// Both the old broker request and its journal head were still nonterminal.
    AbandonedReadOnly {
        /// Original protected broker history head.
        broker_head: [u8; 32],
        /// Digest of the broker's immutable original-history archive.
        archive_digest: [u8; 32],
        /// Digest of its exact protected abandonment record.
        abandonment_digest: [u8; 32],
    },
}

/// Validates the signed control exchange's body without interpreting old traffic.
///
/// The broker-session recovery owner must separately reauthenticate an embedded
/// original terminal packet against the archived old signed hello/transcript.
///
/// # Errors
///
/// Returns an error for malformed, oversized, unknown, zero, or contradictory
/// disposition fields.
pub fn decode_storage_inventory_recovery_response_v1(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<ValidatedStorageInventoryRecoveryResponseV1, ProtocolValidationError> {
    validate_response_bounds(bytes, maximum_response_bytes)?;
    let response = RecoverStorageInventoryResponseV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&response.__buffa_unknown_fields)?;
    let broker_head = exact_nonzero(&response.broker_original_head, "broker_original_head")?;
    let archive_digest = exact_nonzero(&response.broker_archive_digest, "broker_archive_digest")?;
    match response.disposition.as_known() {
        Some(StorageInventoryRecoveryDispositionV1::STORAGE_INVENTORY_RECOVERY_DISPOSITION_ORIGINAL_TERMINAL)
            if !response.original_terminal_packet.is_empty()
                && response.broker_abandonment_digest.is_empty() =>
        {
            Ok(ValidatedStorageInventoryRecoveryResponseV1::OriginalTerminal {
                packet: response.original_terminal_packet,
                broker_head,
                archive_digest,
            })
        }
        Some(StorageInventoryRecoveryDispositionV1::STORAGE_INVENTORY_RECOVERY_DISPOSITION_ABANDONED_READ_ONLY)
            if response.original_terminal_packet.is_empty() =>
        {
            Ok(ValidatedStorageInventoryRecoveryResponseV1::AbandonedReadOnly {
                broker_head,
                archive_digest,
                abandonment_digest: exact_nonzero(&response.broker_abandonment_digest,
                    "broker_abandonment_digest")?,
            })
        }
        _ => Err(ProtocolValidationError::InvalidField("storage inventory recovery disposition")),
    }
}

/// Decodes and validates one complete Storage resource snapshot.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] when bounds, protobuf structure,
/// snapshot metadata, launch or lifecycle row fields, ordering, boot identity,
/// physical identity, dataset identity, or subordinate-range isolation is invalid.
pub fn decode_storage_resource_inventory_response(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<ValidatedStorageInventory, ProtocolValidationError> {
    decode_storage_resource_inventory_response_with_model(bytes, maximum_response_bytes)
        .map(|(validated, _)| validated)
}

/// Decodes one Storage snapshot and retains its same validated protobuf model.
///
/// This shares the complete existing bound and semantic validation with
/// [`decode_storage_resource_inventory_response`]. The returned protobuf model
/// is comparison DATA; it grants no authenticated Session or currentness.
/// Canonical wire equality remains the caller's independent requirement.
///
/// # Errors
/// Returns the same bound, protobuf, unknown-field, snapshot, workspace,
/// lifecycle or operator-repair validation error as the snapshot-only adapter.
pub fn decode_storage_resource_inventory_response_with_model(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<(ValidatedStorageInventory, InventoryStorageResourcesResponse), ProtocolValidationError> {
    decode_inventory_response_engine(bytes, maximum_response_bytes, None)
}

fn decode_inventory_response_engine(
    bytes: &[u8],
    maximum_response_bytes: u32,
    capture: Option<&mut InventoryResponseCaptureV1>,
) -> Result<(ValidatedStorageInventory, InventoryStorageResourcesResponse), ProtocolValidationError> {
    validate_response_bounds(bytes, maximum_response_bytes)?;

    let (message, decode, workspace_capture, completed_workspaces, lifecycle, repairs) = match capture {
        Some(capture) => (
            Some(&mut capture.message), Some(&mut capture.decode), Some(&mut capture.workspaces),
            Some(&mut capture.completed_workspaces), Some(&mut capture.lifecycle), Some(&mut capture.repairs),
        ),
        None => (None, None, None, None, None, None),
    };
    let response = decode_message_v1::<InventoryStorageResourcesResponse>(bytes, message, decode)?;
    reject_unknown(&response.__buffa_unknown_fields)?;
    if response.journal_sequence == 0 || response.catalog_generation == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "storage inventory generation",
        ));
    }
    if response.workspaces.len() > MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "storage inventory workspaces",
            maximum: MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS,
        });
    }

    let kernel_boot_id = exact_nonzero::<16>(&response.kernel_boot_id, "kernel_boot_id")?;
    let broker_instance_id =
        exact_nonzero::<16>(&response.broker_instance_id, "broker_instance_id")?;
    let workspaces = CaptureValueV1::new(
        validate_workspaces_engine(&response.workspaces, kernel_boot_id, workspace_capture)?,
        completed_workspaces,
    );
    validate_lifecycle_inventory_engine(&response, lifecycle)?;
    let operator_repair_commits = validate_operator_repair_commits_engine(&response, repairs)?;

    let validated = ValidatedStorageInventory {
        encoded_response_digest: Sha256::digest(bytes).into(),
        kernel_boot_id,
        broker_instance_id,
        journal_sequence: response.journal_sequence,
        catalog_generation: response.catalog_generation,
        workspaces: workspaces.take(),
        operator_repair_commits,
    };
    Ok((validated, response.take()))
}

fn validate_operator_repair_commits_engine(
    response: &InventoryStorageResourcesResponse,
    capture: Option<&mut Vec<ValidatedStorageOperatorRepairCommitV1>>,
) -> Result<Vec<ValidatedStorageOperatorRepairCommitV1>, ProtocolValidationError> {
    if response.operator_repair_commits.len() > MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "storage operator repair commits",
            maximum: MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS,
        });
    }
    if !response.operator_repair_commits.is_empty() && response.lifecycle_source_version != 3 {
        return Err(ProtocolValidationError::InvalidField(
            "storage operator repair commit source",
        ));
    }
    if !response
        .operator_repair_commits
        .windows(2)
        .all(|pair| pair[0].operation_id < pair[1].operation_id)
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage operator repair commit order",
        ));
    }

    match capture {
        None => response.operator_repair_commits.iter().map(validate_operator_repair_commit).collect(),
        Some(capture) => {
            for record in &response.operator_repair_commits {
                capture.push(validate_operator_repair_commit(record)?);
            }
            Ok(std::mem::take(capture))
        }
    }
}

fn validate_operator_repair_commit(
    record: &StorageOperatorRepairCommitRecordV1,
) -> Result<ValidatedStorageOperatorRepairCommitV1, ProtocolValidationError> {
    let validated = ValidatedStorageOperatorRepairCommitV1 {
        operation_id: exact_nonzero::<16>(&record.operation_id, "operator repair operation")?,
        workspace_handle: exact_nonzero::<32>(
            &record.workspace_handle,
            "operator repair workspace",
        )?,
        request_digest: exact_nonzero::<32>(&record.request_digest, "operator repair request")?,
        effect_commit_digest: exact_nonzero::<32>(
            &record.effect_commit_digest,
            "operator repair durable attempt",
        )?,
    };
    reject_unknown(&record.__buffa_unknown_fields)?;
    Ok(validated)
}

fn validate_lifecycle_inventory_engine(
    response: &InventoryStorageResourcesResponse,
    capture: Option<&mut capture::LifecycleCaptureV1>,
) -> Result<(), ProtocolValidationError> {
    let absent = response.lifecycle_source.is_empty()
        && response.lifecycle_resources.is_empty()
        && response.lifecycle_transitions.is_empty()
        && response.lifecycle_source_version == 0
        && response.lifecycle_catalog_head.is_empty()
        && response.lifecycle_catalog_generation == 0
        && response.atomic_snapshot_checkpoints.is_empty();
    if absent {
        return Ok(());
    }
    exact_nonzero::<32>(&response.lifecycle_source, "storage lifecycle source")?;
    match response.lifecycle_source_version {
        0 if response.lifecycle_catalog_head.is_empty()
            && response.lifecycle_catalog_generation == 0
            && response.atomic_snapshot_checkpoints.is_empty() => {}
        3 => {
            exact_nonzero::<32>(&response.lifecycle_catalog_head, "storage lifecycle head")?;
            if response.lifecycle_catalog_generation == 0 {
                return Err(ProtocolValidationError::InvalidField(
                    "storage lifecycle catalog generation",
                ));
            }
        }
        _ => {
            return Err(ProtocolValidationError::InvalidField(
                "storage lifecycle source version",
            ));
        }
    }
    if response.lifecycle_resources.len() > MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS
        || response.lifecycle_transitions.len() > MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS
        || response.atomic_snapshot_checkpoints.len() > MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS
    {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "storage lifecycle inventory",
            maximum: MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS,
        });
    }
    if !response
        .lifecycle_resources
        .windows(2)
        .all(|pair| lifecycle_resource_key(&pair[0]) < lifecycle_resource_key(&pair[1]))
        || !response
            .lifecycle_transitions
            .windows(2)
            .all(|pair| lifecycle_transition_key(&pair[0]) < lifecycle_transition_key(&pair[1]))
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage lifecycle inventory order",
        ));
    }
    for record in &response.lifecycle_resources {
        validate_lifecycle_resource(record)?;
    }
    for record in &response.lifecycle_transitions {
        validate_lifecycle_transition(record)?;
    }
    if !response
        .atomic_snapshot_checkpoints
        .windows(2)
        .all(|pair| pair[0].operation_id < pair[1].operation_id)
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage atomic checkpoint order",
        ));
    }
    let mut request_ids = capture::CheckpointRequestsV1::new(capture);
    for checkpoint in &response.atomic_snapshot_checkpoints {
        validate_atomic_snapshot_checkpoint(checkpoint, response)?;
        if !request_ids.insert(&checkpoint.request_id)? {
            return Err(ProtocolValidationError::InvalidField(
                "storage atomic checkpoint request",
            ));
        }
    }
    Ok(())
}

fn validate_atomic_snapshot_checkpoint(
    checkpoint: &StorageAtomicSnapshotCheckpoint,
    inventory: &InventoryStorageResourcesResponse,
) -> Result<(), ProtocolValidationError> {
    let source = exact_nonzero::<32>(&checkpoint.catalog_source, "atomic catalog source")?;
    let pre_head = exact_nonzero::<32>(&checkpoint.pre_catalog_head, "atomic pre-head")?;
    let post_head = exact_nonzero::<32>(&checkpoint.post_catalog_head, "atomic post-head")?;
    exact_nonzero::<16>(&checkpoint.operation_id, "atomic operation")?;
    exact_nonzero::<16>(&checkpoint.request_id, "atomic request")?;
    exact_nonzero::<32>(&checkpoint.request_digest, "atomic request digest")?;
    exact_nonzero::<32>(&checkpoint.program, "atomic program")?;
    exact_nonzero::<32>(&checkpoint.observation, "atomic observation")?;
    if inventory.lifecycle_source_version != 3
        || source != inventory.lifecycle_source.as_slice()
        || checkpoint.pre_catalog_generation == 0
        || checkpoint.pre_catalog_generation.checked_add(1)
            != Some(checkpoint.post_catalog_generation)
        || checkpoint.post_catalog_generation > inventory.lifecycle_catalog_generation
        || pre_head == post_head
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage atomic checkpoint chain",
        ));
    }
    reject_unknown(&checkpoint.__buffa_unknown_fields)
}

fn validate_lifecycle_resource(
    record: &StorageLifecycleInventoryRecord,
) -> Result<(), ProtocolValidationError> {
    if !(1..=5).contains(&record.kind) || !(1..=9).contains(&record.resource_kind) {
        return Err(ProtocolValidationError::InvalidField(
            "storage lifecycle resource kind",
        ));
    }
    exact_nonzero::<16>(&record.resource_id, "storage lifecycle resource")?;
    exact_nonzero::<32>(&record.effect_subject, "storage lifecycle effect subject")?;
    exact_nonzero::<32>(&record.effect_request, "storage lifecycle effect request")?;
    exact_nonzero::<32>(&record.identity, "storage lifecycle identity")?;
    optional_nonzero::<16>(&record.lifecycle_operation, "storage lifecycle operation")?;
    optional_nonzero::<16>(&record.hold_id, "storage lifecycle hold")?;
    reject_unknown(&record.__buffa_unknown_fields)
}

fn validate_lifecycle_transition(
    record: &StorageLifecycleTransitionRecord,
) -> Result<(), ProtocolValidationError> {
    if !(1..=8).contains(&record.kind) || !(1..=9).contains(&record.resource_kind) {
        return Err(ProtocolValidationError::InvalidField(
            "storage lifecycle transition kind",
        ));
    }
    exact_nonzero::<16>(&record.resource_id, "storage lifecycle transition resource")?;
    exact_nonzero::<32>(
        &record.effect_subject,
        "storage lifecycle transition subject",
    )?;
    exact_nonzero::<32>(
        &record.effect_request,
        "storage lifecycle transition request",
    )?;
    exact_nonzero::<32>(&record.identity, "storage lifecycle transition identity")?;
    optional_nonzero::<16>(&record.hold_id, "storage lifecycle transition hold")?;
    reject_unknown(&record.__buffa_unknown_fields)
}

fn optional_nonzero<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<(), ProtocolValidationError> {
    if bytes.is_empty() {
        return Ok(());
    }
    exact_nonzero::<N>(bytes, field).map(|_| ())
}

fn lifecycle_resource_key(record: &StorageLifecycleInventoryRecord) -> (u32, &[u8], &[u8]) {
    (record.kind, &record.resource_id, &record.identity)
}

fn lifecycle_transition_key(record: &StorageLifecycleTransitionRecord) -> (u32, &[u8], &[u8]) {
    (record.kind, &record.resource_id, &record.identity)
}

fn validate_workspaces_engine(
    records: &[StorageWorkspaceInventoryRecord],
    kernel_boot_id: [u8; 16],
    capture: Option<&mut capture::WorkspaceCollectionCaptureV1>,
) -> Result<Vec<ValidatedStorageWorkspace>, ProtocolValidationError> {
    let (workspaces, physical, datasets, ranges, mut current, mut row) = match capture {
        Some(capture) => (
            Some(&mut capture.workspaces), Some(&mut capture.physical), Some(&mut capture.datasets),
            Some(&mut capture.ranges), Some(&mut capture.current), Some(&mut capture.row),
        ),
        None => (None, None, None, None, None, None),
    };
    let mut workspaces = CaptureValueV1::new(Vec::with_capacity(records.len()), workspaces);
    let mut physical_pins = CaptureValueV1::new(BTreeSet::new(), physical);
    let mut dataset_guids = CaptureValueV1::new(BTreeSet::new(), datasets);

    for record in records {
        let workspace = CaptureValueV1::new(
            Some(validate_workspace_engine(record, kernel_boot_id, row.as_deref_mut())?),
            current.as_deref_mut(),
        );
        let observed = workspace.as_ref().ok_or(ProtocolValidationError::InvalidField("workspace capture"))?;
        if workspaces
            .last()
            .is_some_and(|previous: &ValidatedStorageWorkspace| {
                previous.workspace_handle >= observed.workspace_handle
            })
        {
            return Err(ProtocolValidationError::InvalidField(
                "storage inventory workspace order",
            ));
        }
        if !physical_pins.insert((observed.root_device, observed.root_inode))
            || !dataset_guids.insert(observed.dataset_guid)
        {
            return Err(ProtocolValidationError::InvalidField(
                "storage inventory physical identity",
            ));
        }

        workspaces.push(workspace.take().ok_or(ProtocolValidationError::InvalidField("workspace capture"))?);
    }

    let mut ranges = CaptureValueV1::new(workspaces
        .iter()
        .map(|workspace| {
            (
                workspace.uid_range_start,
                workspace.uid_range_start + workspace.uid_range_size,
            )
        })
        .collect::<Vec<_>>(), ranges);
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(ProtocolValidationError::InvalidField(
            "storage inventory identity overlap",
        ));
    }

    Ok(workspaces.take())
}

fn validate_workspace_engine(
    record: &StorageWorkspaceInventoryRecord,
    kernel_boot_id: [u8; 16],
    capture: Option<&mut capture::WorkspaceRowCaptureV1>,
) -> Result<ValidatedStorageWorkspace, ProtocolValidationError> {
    let (fence_slot, image_slot, descriptor, proof_slot, current_slot) = match capture {
        Some(capture) => (
            Some(&mut capture.fence), Some(&mut capture.root_image),
            Some(&mut capture.descriptor), Some(&mut capture.proof), Some(&mut capture.current_publication),
        ),
        None => (None, None, None, None, None),
    };

    reject_unknown(&record.__buffa_unknown_fields)?;
    let workspace_handle = exact_nonzero::<32>(
        &record.workspace_handle,
        "storage inventory workspace_handle",
    )?;
    let fence = CaptureValueV1::new(Some(validate_fence(record.fence.as_option().ok_or(
        ProtocolValidationError::MissingField("storage inventory fence"),
    )?)?), fence_slot);
    let root_image = CaptureValueV1::new(Some(crate::validate_descriptor_engine(
        record
            .root_image
            .as_option()
            .ok_or(ProtocolValidationError::MissingField(
                "storage inventory root_image",
            ))?,
        DescriptorRole::SandboxRootView,
        descriptor,
    )?), image_slot);
    let resource_kernel_boot_id = exact_nonzero::<16>(
        &record.resource_kernel_boot_id,
        "storage inventory resource_kernel_boot_id",
    )?;
    if resource_kernel_boot_id != kernel_boot_id {
        return Err(ProtocolValidationError::InvalidField(
            "storage inventory current boot",
        ));
    }
    if record.root_device == 0
        || record.root_inode == 0
        || record.dataset_guid == 0
        || record.uid_range_start == 0
        || record.uid_range_size < MINIMUM_HOST_IDENTITY_RANGE
        || record
            .uid_range_start
            .checked_add(record.uid_range_size)
            .is_none()
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage inventory workspace identity",
        ));
    }
    let resource_digest =
        exact_nonzero::<32>(&record.resource_digest, "storage inventory resource_digest")?;
    let creation_operation_id = exact_nonzero::<16>(
        &record.creation_operation_id,
        "storage inventory creation_operation_id",
    )?;
    let guest_root_publication_proof = if record.guest_root_publication_proof.is_empty() {
        CaptureValueV1::new(None, proof_slot)
    } else {
        let proof = GuestRootPublicationProofV1::decode(&record.guest_root_publication_proof)
            .map_err(|_| {
                ProtocolValidationError::InvalidField("storage inventory guest root proof")
            })?;
        let proof = CaptureValueV1::new(Some(proof), proof_slot);
        let observed = proof.as_ref().ok_or(ProtocolValidationError::InvalidField("guest root proof capture"))?;
        let fence = fence.as_ref().ok_or(ProtocolValidationError::InvalidField("fence capture"))?;
        let root_image = root_image.as_ref().ok_or(ProtocolValidationError::InvalidField("image capture"))?;
        if observed.sandbox != *fence.sandbox_id()
            || observed.incarnation != *fence.incarnation_id()
            || observed.assignment_epoch != fence.assignment_epoch()
            || observed.assignment_digest != *fence.assignment_digest()
            || observed.creation_operation != creation_operation_id
            || observed.workspace_handle != workspace_handle
            || observed.dataset_guid != record.dataset_guid
            || observed.root_image_digest != *root_image.digest().as_bytes()
        {
            return Err(ProtocolValidationError::InvalidField(
                "storage inventory guest root binding",
            ));
        }
        proof
    };

    let current_publication = CaptureValueV1::new(
        if record.current_guest_root_publication_v2.is_empty() { None } else {
            Some(crate::semantics::storage_guest_root::StorageGuestRootCurrentPublicationDataV2::decode_v2(
                &record.current_guest_root_publication_v2)?)
        }, current_slot);

    if let Some(current) = current_publication.as_ref() {
        let creation = fence.as_ref().ok_or(ProtocolValidationError::InvalidField("fence capture"))?
            .broker_assignment().map_err(|_| ProtocolValidationError::InvalidField("publication creation"))?;
        let physical = *guest_root_publication_proof.as_ref()
            .ok_or(ProtocolValidationError::InvalidField("publication physical proof"))?;
        current.require_creation_data_v2(creation, physical, &resource_digest)?;
    }

    let workspace = ValidatedStorageWorkspace {
        workspace_handle,
        fence: fence.take().ok_or(ProtocolValidationError::InvalidField("fence capture"))?,
        root_image: root_image.take().ok_or(ProtocolValidationError::InvalidField("image capture"))?,
        resource_kernel_boot_id,
        root_directory: format!("{WORKSPACE_PIN_PREFIX}{}", encode_hex(&workspace_handle)),
        root_device: record.root_device,
        root_inode: record.root_inode,
        dataset_guid: record.dataset_guid,
        creation_operation_id,
        guest_root_publication_proof: guest_root_publication_proof.take(),
        current_guest_root_publication_v2: current_publication.take(),
        uid_range_start: record.uid_range_start,
        uid_range_size: record.uid_range_size,
        resource_digest,
    };
    Ok(workspace)
}

fn validate_response_bounds(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<(), ProtocolValidationError> {
    if !(MINIMUM_RESPONSE_BYTES..=MAXIMUM_RESPONSE_BYTES).contains(&maximum_response_bytes) {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    if bytes.len() > maximum_response_bytes as usize {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }

    Ok(())
}

fn reject_unknown(fields: &buffa::UnknownFields) -> Result<(), ProtocolValidationError> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err(ProtocolValidationError::UnknownFields)
    }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_api::aos::sandbox::local::v1::{AssignmentFence, Audience, Descriptor};

    use super::*;

    #[test]
    fn recovery_response_keeps_terminal_and_abandonment_disjoint() {
        let mut response = RecoverStorageInventoryResponseV1 {
            disposition: StorageInventoryRecoveryDispositionV1::STORAGE_INVENTORY_RECOVERY_DISPOSITION_ORIGINAL_TERMINAL.into(),
            original_terminal_packet: b"old-signed-terminal".to_vec(),
            broker_original_head: vec![5; 32],
            broker_archive_digest: vec![7; 32],
            ..Default::default()
        };
        assert!(matches!(
            decode_storage_inventory_recovery_response_v1(
                &response.encode_to_vec(),
                MAXIMUM_RESPONSE_BYTES
            ),
            Ok(ValidatedStorageInventoryRecoveryResponseV1::OriginalTerminal { .. })
        ));

        response.broker_abandonment_digest = vec![9; 32];
        assert!(
            decode_storage_inventory_recovery_response_v1(
                &response.encode_to_vec(),
                MAXIMUM_RESPONSE_BYTES
            )
            .is_err()
        );

        response.disposition = StorageInventoryRecoveryDispositionV1::STORAGE_INVENTORY_RECOVERY_DISPOSITION_ABANDONED_READ_ONLY.into();
        assert!(
            decode_storage_inventory_recovery_response_v1(
                &response.encode_to_vec(),
                MAXIMUM_RESPONSE_BYTES
            )
            .is_err()
        );
        response.original_terminal_packet.clear();
        assert!(matches!(
            decode_storage_inventory_recovery_response_v1(
                &response.encode_to_vec(),
                MAXIMUM_RESPONSE_BYTES
            ),
            Ok(ValidatedStorageInventoryRecoveryResponseV1::AbandonedReadOnly { .. })
        ));
    }

    pub(super) fn workspace(handle: u8, range_start: u32) -> StorageWorkspaceInventoryRecord {
        StorageWorkspaceInventoryRecord {
            workspace_handle: vec![handle; 32],
            fence: Some(AssignmentFence {
                sandbox_id: vec![handle; 16],
                incarnation_id: vec![handle + 1; 16],
                assignment_epoch: 2,
                desired_generation: 3,
                assignment_digest: vec![handle + 2; 32],
                ..Default::default()
            })
            .into(),
            root_image: Some(Descriptor {
                media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                sha256: vec![handle + 3; 32],
                encoded_size: 4,
                ..Default::default()
            })
            .into(),
            resource_kernel_boot_id: vec![9; 16],
            root_device: u64::from(handle),
            root_inode: u64::from(handle) + 10,
            dataset_guid: u64::from(handle) + 20,
            creation_operation_id: vec![handle + 5; 16],
            uid_range_start: range_start,
            uid_range_size: MINIMUM_HOST_IDENTITY_RANGE,
            resource_digest: vec![handle + 4; 32],
            ..Default::default()
        }
    }

    pub(super) fn response(workspaces: Vec<StorageWorkspaceInventoryRecord>) -> Vec<u8> {
        InventoryStorageResourcesResponse {
            kernel_boot_id: vec![9; 16],
            journal_sequence: 10,
            catalog_generation: 11,
            workspaces,
            broker_instance_id: vec![12; 16],
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn request_accepts_only_the_storage_baseline() {
        let mut request = InventoryStorageRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 2;
        header.maximum_response_bytes = MINIMUM_RESPONSE_BYTES;
        let peer = PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        };
        let policy = PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };

        let decoded =
            decode_storage_resource_inventory_request(&request.encode_to_vec(), peer, policy, 1)
                .unwrap();
        assert_eq!(decoded.protocol_version(), ProtocolVersion::new(1, 0));

        for minor in 1..=5 {
            request.header.get_or_insert_default().protocol_minor = minor;
            assert!(matches!(
                decode_storage_resource_inventory_request(
                    &request.encode_to_vec(),
                    peer,
                    policy,
                    1,
                ),
                Err(ProtocolValidationError::Protocol(_))
            ));
        }

        request.header.get_or_insert_default().protocol_major = 2;
        request.header.get_or_insert_default().protocol_minor = 0;
        assert!(matches!(
            decode_storage_resource_inventory_request(&request.encode_to_vec(), peer, policy, 1),
            Err(ProtocolValidationError::Protocol(_))
        ));
    }

    #[test]
    fn model_adapter_retains_complete_validation_and_original_wire_fields() {
        let encoded = response(vec![workspace(1, 65_536)]);
        let (validated, model) = decode_storage_resource_inventory_response_with_model(
            &encoded, 65_536,
        ).unwrap();

        assert_eq!(model.encode_to_vec(), encoded);
        assert_eq!(validated.journal_sequence(), model.journal_sequence);
        assert_eq!(validated.catalog_generation(), model.catalog_generation);

        let invalid = response(vec![workspace(1, 65_536), workspace(1, 65_536)]);
        assert!(decode_storage_resource_inventory_response_with_model(&invalid, 65_536).is_err());
        assert!(decode_storage_resource_inventory_response_with_model(&encoded, 4_096 - 1).is_err());
    }

    #[test]
    fn complete_snapshot_derives_fixed_workspace_pins() {
        let inventory = decode_storage_resource_inventory_response(
            &response(vec![workspace(1, 65_536), workspace(2, 131_072)]),
            65_536,
        )
        .unwrap();

        assert_eq!(inventory.catalog_generation(), 11);
        assert_eq!(inventory.workspaces().len(), 2);
        assert_eq!(
            inventory.workspaces()[0].root_directory(),
            format!("{WORKSPACE_PIN_PREFIX}{}", "01".repeat(32))
        );
    }

    #[test]
    fn snapshot_rejects_order_overlap_and_duplicate_physical_identity() {
        assert!(
            decode_storage_resource_inventory_response(
                &response(vec![workspace(2, 65_536), workspace(1, 131_072)]),
                65_536,
            )
            .is_err()
        );
        assert!(
            decode_storage_resource_inventory_response(
                &response(vec![workspace(1, 65_536), workspace(2, 98_304)]),
                65_536,
            )
            .is_err()
        );

        let first = workspace(1, 65_536);
        let mut duplicate = workspace(2, 131_072);
        duplicate.root_device = first.root_device;
        duplicate.root_inode = first.root_inode;
        assert!(
            decode_storage_resource_inventory_response(&response(vec![first, duplicate]), 65_536,)
                .is_err()
        );
    }

    #[test]
    fn snapshot_rejects_stale_boot_and_incomplete_identity() {
        let mut stale = workspace(1, 65_536);
        stale.resource_kernel_boot_id = vec![8; 16];
        assert!(
            decode_storage_resource_inventory_response(&response(vec![stale]), 65_536).is_err()
        );

        let mut incomplete = workspace(1, 65_536);
        incomplete.dataset_guid = 0;
        assert!(
            decode_storage_resource_inventory_response(&response(vec![incomplete]), 65_536)
                .is_err()
        );
    }

    #[test]
    fn lifecycle_source_version_requires_an_explicit_head() {
        let mut response =
            InventoryStorageResourcesResponse::decode_from_slice(&response(Vec::new())).unwrap();
        response.lifecycle_source = vec![13; 32];
        response.lifecycle_source_version = 3;
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );

        response.lifecycle_catalog_head = vec![14; 32];
        response.lifecycle_catalog_generation = 15;
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_ok()
        );

        response.lifecycle_source_version = 0;
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );
    }

    #[test]
    fn repair_commit_readback_requires_v3_source_and_strict_operation_order() {
        let mut response =
            InventoryStorageResourcesResponse::decode_from_slice(&response(Vec::new())).unwrap();
        let commit = StorageOperatorRepairCommitRecordV1 {
            operation_id: vec![1; 16],
            workspace_handle: vec![2; 32],
            request_digest: vec![3; 32],
            effect_commit_digest: vec![4; 32],
            ..Default::default()
        };
        response.operator_repair_commits.push(commit.clone());
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );

        response.lifecycle_source = vec![5; 32];
        response.lifecycle_source_version = 3;
        response.lifecycle_catalog_head = vec![6; 32];
        response.lifecycle_catalog_generation = 11;
        let decoded =
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).unwrap();
        assert_eq!(
            decoded.operator_repair_commits()[0].effect_commit_digest(),
            &[4; 32]
        );

        response.operator_repair_commits.push(commit);
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );
        response.operator_repair_commits.pop();
        response.operator_repair_commits[0]
            .effect_commit_digest
            .fill(0);
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );
    }

    #[test]
    fn atomic_checkpoint_requires_exact_chain_and_canonical_order() {
        let mut response =
            InventoryStorageResourcesResponse::decode_from_slice(&response(Vec::new())).unwrap();
        response.lifecycle_source = vec![13; 32];
        response.lifecycle_source_version = 3;
        response.lifecycle_catalog_head = vec![15; 32];
        response.lifecycle_catalog_generation = 17;
        let checkpoint = StorageAtomicSnapshotCheckpoint {
            operation_id: vec![1; 16],
            request_id: vec![2; 16],
            request_digest: vec![3; 32],
            program: vec![4; 32],
            observation: vec![5; 32],
            catalog_source: vec![13; 32],
            pre_catalog_generation: 15,
            pre_catalog_head: vec![14; 32],
            post_catalog_generation: 16,
            post_catalog_head: vec![15; 32],
            ..Default::default()
        };
        response
            .atomic_snapshot_checkpoints
            .push(checkpoint.clone());
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_ok()
        );

        response.atomic_snapshot_checkpoints[0].post_catalog_generation = 17;
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );
        response.atomic_snapshot_checkpoints[0] = checkpoint.clone();
        response.atomic_snapshot_checkpoints.push(checkpoint);
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );
    }
}

/// Returns the encoded bound of the closed header-only Inventory request.
///
/// The fixed producer assigns only protocol major/minor, exact16-byte request
/// ID, NodeController audience, original absolute cutoff and response maximum.
/// InventoryStorageRequest wraps that header; BrokerRequestEnvelope adds only
/// method, body and the existing fixed signed-request artifact. Each u32 field
/// and every length prefix conservatively uses its complete five-byte varint.
/// This is a representation bound, not a wire limit or a method/Session grant.
#[must_use]
pub const fn fixed_storage_inventory_request_packet_bound_v1() -> usize {
    fixed_controller_inventory_request_packet_bound_v1()
}

/// Bounds the four fixed Controller header-only inventory packet layouts.
///
/// Host, Mount, Storage and Network use their existing one-header request
/// messages and the same signed Broker envelope. This shares representation
/// geometry only; a negotiated method, current Session and genuine operation
/// owner remain mandatory before any request can be prepared or sent.
#[must_use]
pub const fn fixed_controller_inventory_request_packet_bound_v1() -> usize {
    let scalar_u32 = 1 + 5;
    let scalar_u64 = 1 + 10;
    let request_id = 1 + 1 + 16;
    let header = 3 * scalar_u32 + request_id + scalar_u64 + scalar_u32;
    let body = 1 + 5 + header;
    let authentication = 1 + 5 + aos_sandbox_broker_session_protocol::SIGNED_BROKER_REQUEST_BYTES;
    scalar_u32 + 1 + 5 + body + authentication
}

#[cfg(test)]
mod fixed_request_geometry_tests {
    use super::*;
    use super::tests::{response, workspace};
    use buffa::Message as _;
    use aos_sandbox_api::aos::sandbox::local::v1::{Audience, BrokerMethod, BrokerRequestEnvelope, RequestHeader};

    #[test]
    fn full_width_actual_encoders_fit_the_shared_inventory_recipe() {
        use aos_sandbox_api::aos::sandbox::local::v1::{
            InventoryMountsRequest, InventoryNetworksRequest, InventoryRuntimeRequest,
        };

        let header = RequestHeader {
            protocol_major: u32::MAX,
            protocol_minor: u32::MAX,
            request_id: vec![255; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: u64::MAX,
            maximum_response_bytes: u32::MAX,
            ..Default::default()
        };
        let packets = [
            (BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
                InventoryRuntimeRequest { header: Some(header.clone()).into(), ..Default::default() }.encode_to_vec()),
            (BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES,
                InventoryMountsRequest { header: Some(header.clone()).into(), ..Default::default() }.encode_to_vec()),
            (BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
                InventoryStorageRequest { header: Some(header.clone()).into(), ..Default::default() }.encode_to_vec()),
            (BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
                InventoryNetworksRequest { header: Some(header).into(), ..Default::default() }.encode_to_vec()),
        ];

        for (method, body) in packets {
            // Artifact-width DATA only: no real signature or request grant.
            let packet = BrokerRequestEnvelope {
                method: method.into(),
                body,
                signed_session_request: vec![0; aos_sandbox_broker_session_protocol::SIGNED_BROKER_REQUEST_BYTES],
                ..Default::default()
            }.encode_to_vec();

            assert!(packet.len() <= fixed_controller_inventory_request_packet_bound_v1());
            assert!(packet.len() <= fixed_storage_inventory_request_packet_bound_v1());
        }
    }

    #[test]
    fn retained_decode_keeps_actual_partial_protobuf_and_first_error_after_reentry() {
        let mut bytes = response(vec![workspace(1, 65_536)]);
        bytes.push(0x80); // Unterminated actual protobuf tag after a complete row.
        let mut original = InventoryResponseCaptureV1::default();

        assert!(original.decode_once(&bytes, 65_536).is_err());

        assert_eq!(original.message.workspaces.len(), 1);
        assert_eq!(original.message.workspaces[0].workspace_handle, vec![1; 32]);
        let first = original.decode.as_ref().unwrap().as_ref().unwrap_err() as *const buffa::DecodeError;
        assert!(std::ptr::eq(
            original.failure().unwrap().downcast_ref::<buffa::DecodeError>().unwrap(), first,
        ));
        assert!(original.decode_once(&response(Vec::new()), 65_536).is_err());
        assert_eq!(original.message.workspaces.len(), 1);
        assert!(std::ptr::eq(
            original.failure().unwrap().downcast_ref::<buffa::DecodeError>().unwrap(), first,
        ));
    }

    #[test]
    fn retained_workspace_error_keeps_prior_rows_and_reached_descriptor() {
        let mut invalid = workspace(2, 131_072);
        invalid.uid_range_start = 0;
        let bytes = response(vec![workspace(1, 65_536), invalid]);
        let mut original = InventoryResponseCaptureV1::default();

        let ordinary = decode_storage_resource_inventory_response(&bytes, 65_536).map(|_| ());
        let retained = original.decode_once(&bytes, 65_536);
        assert!(retained.is_err());
        assert_eq!(retained, ordinary);

        assert_eq!(original.workspaces.workspaces.len(), 1);
        assert_eq!(original.workspaces.physical.len(), 1);
        assert_eq!(original.workspaces.datasets.len(), 1);
        assert!(original.workspaces.row.fence.is_some());
        let descriptor = original.workspaces.row.root_image.as_ref().unwrap();
        assert_eq!(descriptor.media_type().as_str(), "application/vnd.aos.sandbox.view.v1+cbor");
        assert!(original.workspaces.ranges.is_empty());
    }

    #[test]
    fn retained_order_and_overlap_refusals_keep_actual_row_and_sorted_ranges() {
        let mut order = InventoryResponseCaptureV1::default();
        let bytes = response(vec![workspace(2, 65_536), workspace(1, 131_072)]);
        assert!(order.decode_once(&bytes, 65_536).is_err());
        assert_eq!(order.workspaces.workspaces.len(), 1);
        assert_eq!(order.workspaces.current.as_ref().unwrap().workspace_handle(), &[1; 32]);
        assert!(!order.workspaces.current.as_ref().unwrap().root_directory().is_empty());

        let mut overlap = InventoryResponseCaptureV1::default();
        let bytes = response(vec![workspace(1, 65_536), workspace(2, 98_304)]);
        assert!(overlap.decode_once(&bytes, 65_536).is_err());
        assert_eq!(overlap.workspaces.workspaces.len(), 2);
        assert_eq!(overlap.workspaces.ranges.len(), 2);
        assert!(overlap.workspaces.ranges[0].1 > overlap.workspaces.ranges[1].0);
    }

    #[test]
    fn invalid_media_type_keeps_actual_allocated_input_and_core_cause() {
        let mut row = workspace(1, 65_536);
        row.root_image.get_or_insert_default().media_type = "Invalid/TYPE".to_owned();
        let mut original = InventoryResponseCaptureV1::default();

        assert!(original.decode_once(&response(vec![row]), 65_536).is_err());

        assert_eq!(original.workspaces.row.descriptor.input.as_deref(), Some("Invalid/TYPE"));
        assert!(original.failure().unwrap()
            .downcast_ref::<aos_sandbox_model::selector::InvalidMediaType>().is_some());
        assert!(original.workspaces.row.root_image.is_none());
    }
}

#[cfg(test)]
mod encoded_response_tests {
    use super::*;

    #[test]
    fn wire_commitment_tracks_actual_bytes_while_semantic_equality_is_unchanged() {
        let canonical = super::tests::response(Vec::new());
        // The same known fields in another legal protobuf order. No unknown
        // field or synthetic parsed model bypasses the actual decoder.
        let mut reordered = vec![0x10, 10, 0x18, 11, 0x0a, 16];
        reordered.extend_from_slice(&[9; 16]);
        reordered.extend_from_slice(&[0x2a, 16]);
        reordered.extend_from_slice(&[12; 16]);
        assert_ne!(canonical, reordered);

        let first = decode_storage_resource_inventory_response(&canonical, MINIMUM_RESPONSE_BYTES).unwrap();
        let second = decode_storage_resource_inventory_response(&reordered, MINIMUM_RESPONSE_BYTES).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.encoded_response_digest_v1(), <[u8; 32]>::from(Sha256::digest(&canonical)));
        assert_eq!(second.encoded_response_digest_v1(), <[u8; 32]>::from(Sha256::digest(&reordered)));
        assert_ne!(first.encoded_response_digest_v1(), second.encoded_response_digest_v1());
    }

    #[test]
    fn ordinary_and_retained_decoders_keep_the_same_exact_wire_identity() {
        let encoded = super::tests::response(Vec::new());
        let ordinary = decode_storage_resource_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES).unwrap();
        let mut retained = InventoryResponseCaptureV1::default();

        retained.decode_once(&encoded, MINIMUM_RESPONSE_BYTES).unwrap();

        let (captured, _) = retained.value().unwrap();
        assert_eq!(ordinary, *captured);
        assert_eq!(ordinary.encoded_response_digest_v1(), captured.encoded_response_digest_v1());
    }
}
