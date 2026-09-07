//! Validated Mount destination-slot requests and durable inventory.
//!
//! Materialization requests carry the exact canonical portable sandbox
//! specification that declares the slot. Inventory carries only the proven
//! descriptor and the broker's lossless node-local lifecycle record. Mount
//! 1.5 additionally reports the exact current namespace-generation anchors
//! that contain Ready slots:
//!
//! ```text
//! assignment + namespace generation + slot + sandbox-spec descriptor
//! lifecycle + operation correlations + physical identity + record digest
//! anchor handle + sandbox/incarnation/generation + directory/mount identity
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_proto::aos::sandbox::local::v1::{
    ApplyDestinationSlotRequest, ApplyDestinationSlotResponse, AttachmentAnchorInventoryRecord,
    DestinationSlotAction, DestinationSlotInventoryRecord, DestinationSlotLifecycle,
    DestinationSlotReapCorrelation, DestinationSlotRematerializationCorrelation,
    InventoryDestinationSlotsRequest, InventoryDestinationSlotsResponse, MountOperationCorrelation,
};
use aos_sandbox_core::{
    DecodeLimits, DescriptorRole, ObjectDescriptor, ProtocolId, ProtocolVersion,
    decode_sandbox_spec, descriptor_for_bytes, encode_sandbox_spec,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, MINIMUM_RESPONSE_BYTES, PeerCredentials,
    PeerPolicy, ProtocolValidationError, ValidatedAssignmentFence, ValidatedHeader, exact_nonzero,
    validate_descriptor, validate_fence, validate_request_header,
};

/// Maximum canonical sandbox-specification bytes carried by one slot request.
pub const MAXIMUM_DESTINATION_SLOT_SPEC_BYTES: usize = 512 * 1024;
/// Maximum durable destination-slot rows accepted in one complete inventory.
pub const MAXIMUM_DESTINATION_SLOT_INVENTORY_RECORDS: usize = 16_384;
/// Maximum current attachment anchors accepted in one complete inventory.
pub const MAXIMUM_ATTACHMENT_ANCHOR_INVENTORY_RECORDS: usize = 16_384;

const ATTACHMENT_ANCHOR_HANDLE_DOMAIN: &[u8] = b"aos.sandbox.mount.attachment-anchor-handle.v1\0";
const DESTINATION_SLOT_PROTOCOL_V1_4: ProtocolVersion = ProtocolVersion::new(1, 4);
const DESTINATION_SLOT_PROTOCOL_V1_5: ProtocolVersion = ProtocolVersion::new(1, 5);

/// Carries one destination-slot effect after complete portable validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDestinationSlotRequest {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    resource_fence: Option<ValidatedAssignmentFence>,
    action: DestinationSlotAction,
    namespace_generation: u64,
    destination_slot_id: [u8; 16],
    sandbox_spec: ObjectDescriptor,
    sandbox_spec_bytes: Vec<u8>,
    sandbox_specification: aos_sandbox_core::model::SandboxSpec,
    expected_resource_digest: Option<[u8; 32]>,
}

impl ValidatedDestinationSlotRequest {
    /// Returns the validated common request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact assignment fence owning the destination slot.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the immutable creation fence carried by a reap request.
    #[must_use]
    pub const fn resource_fence(&self) -> Option<&ValidatedAssignmentFence> {
        self.resource_fence.as_ref()
    }

    /// Returns the fence that identifies the durable destination-slot binding.
    #[must_use]
    pub const fn binding_fence(&self) -> &ValidatedAssignmentFence {
        match self.resource_fence.as_ref() {
            Some(resource_fence) => resource_fence,
            None => &self.fence,
        }
    }

    /// Returns the closed physical slot action.
    #[must_use]
    pub const fn action(&self) -> DestinationSlotAction {
        self.action
    }

    /// Returns the payload mount-namespace generation containing the slot.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.namespace_generation
    }

    /// Returns the logical destination-slot identity declared by the specification.
    #[must_use]
    pub const fn destination_slot_id(&self) -> &[u8; 16] {
        &self.destination_slot_id
    }

    /// Returns the exact portable sandbox-specification descriptor.
    #[must_use]
    pub const fn sandbox_spec(&self) -> &ObjectDescriptor {
        &self.sandbox_spec
    }

    /// Returns the canonical bytes that reproduce the specification descriptor.
    #[must_use]
    pub fn sandbox_spec_bytes(&self) -> &[u8] {
        &self.sandbox_spec_bytes
    }

    /// Returns the decoded canonical specification declaring the slot.
    #[must_use]
    pub const fn sandbox_specification(&self) -> &aos_sandbox_core::model::SandboxSpec {
        &self.sandbox_specification
    }

    /// Returns the exact ready-record digest fenced by a reap request.
    #[must_use]
    pub const fn expected_resource_digest(&self) -> Option<&[u8; 32]> {
        self.expected_resource_digest.as_ref()
    }
}

/// Carries one validated idempotent destination-slot operation correlation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedDestinationSlotOperation {
    operation_id: [u8; 16],
    request_digest: [u8; 32],
}

impl ValidatedDestinationSlotOperation {
    /// Returns the exact idempotent operation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> &[u8; 16] {
        &self.operation_id
    }

    /// Returns SHA-256 over the exact operation request body.
    #[must_use]
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
}

/// Carries one validated generation-fenced destination-slot reap correlation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedDestinationSlotReap {
    operation: ValidatedDestinationSlotOperation,
    expected_resource_digest: [u8; 32],
}

/// Carries one exact stale-resource rematerialization correlation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedDestinationSlotRematerialization {
    operation: ValidatedDestinationSlotOperation,
    expected_resource_digest: [u8; 32],
}

impl ValidatedDestinationSlotRematerialization {
    /// Returns the idempotent rematerialization operation correlation.
    #[must_use]
    pub const fn operation(&self) -> ValidatedDestinationSlotOperation {
        self.operation
    }

    /// Returns the exact stale ready-record digest replaced by the operation.
    #[must_use]
    pub const fn expected_resource_digest(&self) -> &[u8; 32] {
        &self.expected_resource_digest
    }
}

impl ValidatedDestinationSlotReap {
    /// Returns the idempotent reap operation correlation.
    #[must_use]
    pub const fn operation(&self) -> ValidatedDestinationSlotOperation {
        self.operation
    }

    /// Returns the exact ready-record digest admitted for removal.
    #[must_use]
    pub const fn expected_resource_digest(&self) -> &[u8; 32] {
        &self.expected_resource_digest
    }
}

/// Carries one structurally and semantically validated durable slot row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDestinationSlotInventoryRecord {
    fence: ValidatedAssignmentFence,
    namespace_generation: u64,
    destination_slot_id: [u8; 16],
    sandbox_spec: ObjectDescriptor,
    lifecycle: DestinationSlotLifecycle,
    resource_kernel_boot_id: [u8; 16],
    materialization: ValidatedDestinationSlotOperation,
    rematerialization: Option<ValidatedDestinationSlotRematerialization>,
    reap: Option<ValidatedDestinationSlotReap>,
    slot_device: Option<u64>,
    slot_inode: Option<u64>,
    anchor_unique_mount_id: Option<u64>,
    resource_digest: [u8; 32],
}

impl ValidatedDestinationSlotInventoryRecord {
    /// Returns the assignment fence retained by the slot's original binding.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the payload mount-namespace generation containing this slot.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.namespace_generation
    }

    /// Returns the logical destination-slot identifier.
    #[must_use]
    pub const fn destination_slot_id(&self) -> &[u8; 16] {
        &self.destination_slot_id
    }

    /// Returns the exact portable specification descriptor declaring the slot.
    #[must_use]
    pub const fn sandbox_spec(&self) -> &ObjectDescriptor {
        &self.sandbox_spec
    }

    /// Returns the durable physical lifecycle phase.
    #[must_use]
    pub const fn lifecycle(&self) -> DestinationSlotLifecycle {
        self.lifecycle
    }

    /// Returns the Linux boot identity under which physical state was observed.
    #[must_use]
    pub const fn resource_kernel_boot_id(&self) -> &[u8; 16] {
        &self.resource_kernel_boot_id
    }

    /// Returns the original materialization operation correlation.
    #[must_use]
    pub const fn materialization(&self) -> ValidatedDestinationSlotOperation {
        self.materialization
    }

    /// Returns the latest stale-resource rematerialization correlation.
    #[must_use]
    pub const fn rematerialization(&self) -> Option<ValidatedDestinationSlotRematerialization> {
        self.rematerialization
    }

    /// Returns the admitted reap correlation after removal has begun.
    #[must_use]
    pub const fn reap(&self) -> Option<ValidatedDestinationSlotReap> {
        self.reap
    }

    /// Returns the retained device identity once the directory was observed.
    #[must_use]
    pub const fn slot_device(&self) -> Option<u64> {
        self.slot_device
    }

    /// Returns the retained inode identity once the directory was observed.
    #[must_use]
    pub const fn slot_inode(&self) -> Option<u64> {
        self.slot_inode
    }

    /// Returns the unique attachment-anchor mount identity once observed.
    #[must_use]
    pub const fn anchor_unique_mount_id(&self) -> Option<u64> {
        self.anchor_unique_mount_id
    }

    /// Returns the digest of the exact durable broker record.
    #[must_use]
    pub const fn resource_digest(&self) -> &[u8; 32] {
        &self.resource_digest
    }

    fn key(&self) -> ([u8; 16], [u8; 16], u64, [u8; 16]) {
        (
            *self.fence.sandbox_id(),
            *self.fence.incarnation_id(),
            self.namespace_generation,
            self.destination_slot_id,
        )
    }
}

/// Carries one validated authoritative destination-slot inventory snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDestinationSlotInventory {
    protocol_version: ProtocolVersion,
    kernel_boot_id: [u8; 16],
    journal_sequence: u64,
    slots: Vec<ValidatedDestinationSlotInventoryRecord>,
    attachment_anchors: Vec<ValidatedAttachmentAnchorInventoryRecord>,
    broker_instance_id: [u8; 16],
}

impl ValidatedDestinationSlotInventory {
    /// Returns the exact protocol version used to validate this snapshot.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the broker's current Linux boot identifier.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> &[u8; 16] {
        &self.kernel_boot_id
    }

    /// Returns the nonzero journal boundary after the complete snapshot.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns durable slots in strict logical-key order.
    #[must_use]
    pub fn slots(&self) -> &[ValidatedDestinationSlotInventoryRecord] {
        &self.slots
    }

    /// Returns current attachment anchors in strict logical-key order.
    #[must_use]
    pub fn attachment_anchors(&self) -> &[ValidatedAttachmentAnchorInventoryRecord] {
        &self.attachment_anchors
    }

    /// Returns the identity of the broker process that emitted the snapshot.
    #[must_use]
    pub const fn broker_instance_id(&self) -> &[u8; 16] {
        &self.broker_instance_id
    }
}

/// Carries one current broker-owned attachment anchor after complete validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedAttachmentAnchorInventoryRecord {
    handle: [u8; 32],
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    namespace_generation: u64,
    resource_kernel_boot_id: [u8; 16],
    directory_device: u64,
    directory_inode: u64,
    unique_mount_id: u64,
}

impl ValidatedAttachmentAnchorInventoryRecord {
    /// Returns the opaque Mount-derived handle consumed by Host launch plans.
    #[must_use]
    pub const fn handle(&self) -> &[u8; 32] {
        &self.handle
    }

    /// Returns the logical sandbox identity owning this anchor.
    #[must_use]
    pub const fn sandbox_id(&self) -> &[u8; 16] {
        &self.sandbox_id
    }

    /// Returns the exact sandbox incarnation owning this anchor.
    #[must_use]
    pub const fn incarnation_id(&self) -> &[u8; 16] {
        &self.incarnation_id
    }

    /// Returns the payload mount-namespace generation represented by the anchor.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.namespace_generation
    }

    /// Returns the Linux boot identity under which the anchor was pinned.
    #[must_use]
    pub const fn resource_kernel_boot_id(&self) -> &[u8; 16] {
        &self.resource_kernel_boot_id
    }

    /// Returns the anchor directory's device identity.
    #[must_use]
    pub const fn directory_device(&self) -> u64 {
        self.directory_device
    }

    /// Returns the anchor directory's inode identity.
    #[must_use]
    pub const fn directory_inode(&self) -> u64 {
        self.directory_inode
    }

    /// Returns the kernel-unique mount identity containing the anchor.
    #[must_use]
    pub const fn unique_mount_id(&self) -> u64 {
        self.unique_mount_id
    }

    fn key(&self) -> ([u8; 16], [u8; 16], u64) {
        (
            self.sandbox_id,
            self.incarnation_id,
            self.namespace_generation,
        )
    }
}

/// Derives the opaque Host-facing handle for one exact physical anchor.
///
/// The fixed-width inputs are already broker-private identities. The domain
/// separated digest prevents an anchor handle from aliasing another handle
/// family.
#[must_use]
pub fn attachment_anchor_handle_v1(
    sandbox_id: &[u8; 16],
    incarnation_id: &[u8; 16],
    namespace_generation: u64,
    resource_kernel_boot_id: &[u8; 16],
    directory_device: u64,
    directory_inode: u64,
    unique_mount_id: u64,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(ATTACHMENT_ANCHOR_HANDLE_DOMAIN)
        .chain_update(sandbox_id)
        .chain_update(incarnation_id)
        .chain_update(namespace_generation.to_be_bytes())
        .chain_update(resource_kernel_boot_id)
        .chain_update(directory_device.to_be_bytes())
        .chain_update(directory_inode.to_be_bytes())
        .chain_update(unique_mount_id.to_be_bytes())
        .finalize()
        .into()
}

/// Decodes and validates one hostile Mount 1.4 or 1.5 destination-slot effect body.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed message,
/// an older protocol version, unknown fields or enums, invalid assignment or
/// action shape, noncanonical specification bytes, descriptor substitution,
/// or a slot not declared by that exact specification.
pub fn decode_destination_slot_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedDestinationSlotRequest, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyDestinationSlotRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&request.__buffa_unknown_fields)?;

    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::MountBroker,
        now_boottime_nanoseconds,
    )?;
    if !matches!(
        header.protocol_version(),
        DESTINATION_SLOT_PROTOCOL_V1_4 | DESTINATION_SLOT_PROTOCOL_V1_5
    ) {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    let fence = validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let resource_fence = request
        .resource_fence
        .as_option()
        .map(validate_fence)
        .transpose()?;
    let action = request
        .action
        .as_known()
        .filter(|value| *value != DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED)
        .ok_or(ProtocolValidationError::UnknownAction)?;
    if request.namespace_generation == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "namespace_generation",
        ));
    }
    let destination_slot_id =
        exact_nonzero::<16>(&request.destination_slot_id, "destination_slot_id")?;
    let sandbox_spec = validate_descriptor(
        request
            .sandbox_spec
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("sandbox_spec"))?,
        DescriptorRole::SnapshotSpec,
    )?;
    if request.sandbox_spec_bytes.is_empty()
        || request.sandbox_spec_bytes.len() > MAXIMUM_DESTINATION_SLOT_SPEC_BYTES
    {
        return Err(ProtocolValidationError::InvalidField("sandbox_spec_bytes"));
    }
    let sandbox_specification =
        decode_sandbox_spec(&request.sandbox_spec_bytes, sandbox_spec_decode_limits())
            .map_err(|error| ProtocolValidationError::InvalidDescriptor(error.to_string()))?;
    if encode_sandbox_spec(&sandbox_specification) != request.sandbox_spec_bytes
        || descriptor_for_bytes(
            sandbox_spec.media_type().clone(),
            &request.sandbox_spec_bytes,
        ) != sandbox_spec
        || sandbox_specification
            .attachment_slots()
            .binary_search(&aos_sandbox_core::AttachmentSlotId::from_bytes(
                destination_slot_id,
            ))
            .is_err()
    {
        return Err(ProtocolValidationError::InvalidField(
            "sandbox_spec declaration",
        ));
    }
    let expected_resource_digest = optional_digest(
        &request.expected_resource_digest,
        "expected_resource_digest",
    )?;
    let action_shape_valid = match action {
        DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE => {
            expected_resource_digest.is_none() && resource_fence.is_none()
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP => {
            expected_resource_digest.is_some()
                && resource_fence
                    .as_ref()
                    .is_some_and(|resource_fence| resource_fence_precedes(&fence, resource_fence))
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REMATERIALIZE => {
            expected_resource_digest.is_some()
                && resource_fence
                    .as_ref()
                    .is_some_and(|resource_fence| resource_fence_precedes(&fence, resource_fence))
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED => false,
    };
    if !action_shape_valid {
        return Err(ProtocolValidationError::InvalidField(
            "destination_slot action shape",
        ));
    }

    Ok(ValidatedDestinationSlotRequest {
        header,
        fence,
        resource_fence,
        action,
        namespace_generation: request.namespace_generation,
        destination_slot_id,
        sandbox_spec,
        sandbox_spec_bytes: request.sandbox_spec_bytes,
        sandbox_specification,
        expected_resource_digest,
    })
}

fn resource_fence_precedes(
    authority_fence: &ValidatedAssignmentFence,
    resource_fence: &ValidatedAssignmentFence,
) -> bool {
    if authority_fence.sandbox_id() != resource_fence.sandbox_id()
        || authority_fence.incarnation_id() != resource_fence.incarnation_id()
    {
        return false;
    }

    let authority_generation = (
        authority_fence.assignment_epoch(),
        authority_fence.desired_generation(),
    );
    let resource_generation = (
        resource_fence.assignment_epoch(),
        resource_fence.desired_generation(),
    );

    resource_generation < authority_generation
        || (resource_generation == authority_generation && resource_fence == authority_fence)
}

/// Decodes one peer-authenticated destination-slot inventory request header.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed request,
/// an older protocol version, unknown fields, or an invalid common header.
pub fn decode_destination_slot_inventory_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = InventoryDestinationSlotsRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&request.__buffa_unknown_fields)?;
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::MountBroker,
        now_boottime_nanoseconds,
    )?;
    if !matches!(
        header.protocol_version(),
        DESTINATION_SLOT_PROTOCOL_V1_4 | DESTINATION_SLOT_PROTOCOL_V1_5
    ) {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    Ok(header)
}

/// Validates and encodes one broker-produced destination-slot apply response.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] if the resource row is malformed.
pub fn encode_destination_slot_response(
    resource: DestinationSlotInventoryRecord,
) -> Result<Vec<u8>, ProtocolValidationError> {
    validate_inventory_record(&resource)?;
    Ok(ApplyDestinationSlotResponse {
        resource: Some(resource).into(),
        ..Default::default()
    }
    .encode_to_vec())
}

/// Decodes and validates one destination-slot apply response.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized, malformed, unknown,
/// or lifecycle-inconsistent response.
pub fn decode_destination_slot_response(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<ValidatedDestinationSlotInventoryRecord, ProtocolValidationError> {
    validate_response_bound(bytes, maximum_response_bytes)?;
    let response = ApplyDestinationSlotResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&response.__buffa_unknown_fields)?;
    validate_inventory_record(
        response
            .resource
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("resource"))?,
    )
}

/// Validates and encodes one complete destination-slot inventory snapshot.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] when snapshot identity, bounds, row
/// order, operation uniqueness, or any nested row is invalid.
pub fn encode_destination_slot_inventory_response(
    response: InventoryDestinationSlotsResponse,
) -> Result<Vec<u8>, ProtocolValidationError> {
    encode_destination_slot_inventory_response_for_version(response, DESTINATION_SLOT_PROTOCOL_V1_4)
}

/// Validates and encodes one version-bound destination-slot inventory snapshot.
///
/// Mount 1.4 preserves the original slot-only response. Mount 1.5 requires a
/// complete anchor row for every current Ready namespace generation.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an unsupported protocol version,
/// version-incompatible fields, or any invalid snapshot identity or row.
pub fn encode_destination_slot_inventory_response_for_version(
    response: InventoryDestinationSlotsResponse,
    protocol_version: ProtocolVersion,
) -> Result<Vec<u8>, ProtocolValidationError> {
    validate_inventory_response(&response, protocol_version)?;
    Ok(response.encode_to_vec())
}

/// Decodes and validates one complete destination-slot inventory snapshot.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed response,
/// unknown fields, sentinel snapshot identity, excessive records, noncanonical
/// ordering, reused operation IDs, or an invalid lifecycle row.
pub fn decode_destination_slot_inventory_response(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<ValidatedDestinationSlotInventory, ProtocolValidationError> {
    decode_destination_slot_inventory_response_for_version(
        bytes,
        maximum_response_bytes,
        DESTINATION_SLOT_PROTOCOL_V1_4,
    )
}

/// Decodes one complete version-bound destination-slot inventory snapshot.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an unsupported version, an
/// oversized or malformed response, version-incompatible fields, sentinel
/// snapshot identity, noncanonical order, reused operations, or an invalid
/// slot/anchor cross-link.
pub fn decode_destination_slot_inventory_response_for_version(
    bytes: &[u8],
    maximum_response_bytes: u32,
    protocol_version: ProtocolVersion,
) -> Result<ValidatedDestinationSlotInventory, ProtocolValidationError> {
    validate_response_bound(bytes, maximum_response_bytes)?;
    let response = InventoryDestinationSlotsResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&response.__buffa_unknown_fields)?;
    validate_inventory_response(&response, protocol_version)
}

fn validate_inventory_response(
    response: &InventoryDestinationSlotsResponse,
    protocol_version: ProtocolVersion,
) -> Result<ValidatedDestinationSlotInventory, ProtocolValidationError> {
    if !matches!(
        protocol_version,
        DESTINATION_SLOT_PROTOCOL_V1_4 | DESTINATION_SLOT_PROTOCOL_V1_5
    ) {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    if response.journal_sequence == 0 {
        return Err(ProtocolValidationError::InvalidField("journal_sequence"));
    }
    if response.slots.len() > MAXIMUM_DESTINATION_SLOT_INVENTORY_RECORDS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "inventory.destination_slots",
            maximum: MAXIMUM_DESTINATION_SLOT_INVENTORY_RECORDS,
        });
    }
    if response.attachment_anchors.len() > MAXIMUM_ATTACHMENT_ANCHOR_INVENTORY_RECORDS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "inventory.attachment_anchors",
            maximum: MAXIMUM_ATTACHMENT_ANCHOR_INVENTORY_RECORDS,
        });
    }
    if protocol_version == DESTINATION_SLOT_PROTOCOL_V1_4 && !response.attachment_anchors.is_empty()
    {
        return Err(ProtocolValidationError::InvalidField(
            "inventory.attachment_anchors protocol version",
        ));
    }

    let kernel_boot_id = exact_nonzero::<16>(&response.kernel_boot_id, "kernel_boot_id")?;
    let broker_instance_id =
        exact_nonzero::<16>(&response.broker_instance_id, "broker_instance_id")?;
    let mut slots = Vec::with_capacity(response.slots.len());
    let mut operations = BTreeSet::new();
    let mut current_ready_anchors = BTreeMap::new();
    for source in &response.slots {
        let slot = validate_inventory_record(source)?;
        if slots
            .last()
            .is_some_and(|previous: &ValidatedDestinationSlotInventoryRecord| {
                previous.key() >= slot.key()
            })
        {
            return Err(ProtocolValidationError::InvalidField(
                "inventory.destination_slots order",
            ));
        }
        if !operations.insert(*slot.materialization.operation_id())
            || slot.rematerialization.is_some_and(|rematerialization| {
                !operations.insert(*rematerialization.operation.operation_id())
            })
            || slot
                .reap
                .is_some_and(|reap| !operations.insert(*reap.operation.operation_id()))
        {
            return Err(ProtocolValidationError::InvalidField(
                "inventory.destination_slots operations",
            ));
        }
        if slot.lifecycle == DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY
            && slot.resource_kernel_boot_id == kernel_boot_id
        {
            let key = (
                *slot.fence.sandbox_id(),
                *slot.fence.incarnation_id(),
                slot.namespace_generation,
            );
            let physical = (
                slot.anchor_unique_mount_id
                    .ok_or(ProtocolValidationError::InvalidField(
                        "inventory.current_ready_anchor physical identity",
                    ))?,
                slot.slot_device
                    .ok_or(ProtocolValidationError::InvalidField(
                        "inventory.current_ready_anchor physical identity",
                    ))?,
            );
            if current_ready_anchors
                .insert(key, physical)
                .is_some_and(|prior| prior != physical)
            {
                return Err(ProtocolValidationError::InvalidField(
                    "inventory.current_ready_anchor identity",
                ));
            }
        }
        slots.push(slot);
    }

    let mut attachment_anchors = Vec::with_capacity(response.attachment_anchors.len());
    for source in &response.attachment_anchors {
        let anchor = validate_attachment_anchor(source)?;
        if anchor.resource_kernel_boot_id != kernel_boot_id
            || attachment_anchors.last().is_some_and(
                |previous: &ValidatedAttachmentAnchorInventoryRecord| {
                    previous.key() >= anchor.key()
                },
            )
        {
            return Err(ProtocolValidationError::InvalidField(
                "inventory.attachment_anchors order or boot",
            ));
        }
        let Some((slot_mount_id, slot_device)) = current_ready_anchors.get(&anchor.key()) else {
            return Err(ProtocolValidationError::InvalidField(
                "inventory.attachment_anchor without ready slot",
            ));
        };
        if anchor.unique_mount_id != *slot_mount_id || anchor.directory_device != *slot_device {
            return Err(ProtocolValidationError::InvalidField(
                "inventory.attachment_anchor physical cross-link",
            ));
        }
        attachment_anchors.push(anchor);
    }
    if protocol_version == DESTINATION_SLOT_PROTOCOL_V1_5
        && attachment_anchors.len() != current_ready_anchors.len()
    {
        return Err(ProtocolValidationError::InvalidField(
            "inventory.attachment_anchors completeness",
        ));
    }

    Ok(ValidatedDestinationSlotInventory {
        protocol_version,
        kernel_boot_id,
        journal_sequence: response.journal_sequence,
        slots,
        attachment_anchors,
        broker_instance_id,
    })
}

fn validate_attachment_anchor(
    record: &AttachmentAnchorInventoryRecord,
) -> Result<ValidatedAttachmentAnchorInventoryRecord, ProtocolValidationError> {
    reject_unknown(&record.__buffa_unknown_fields)?;
    let handle = exact_nonzero::<32>(
        &record.attachment_anchor_handle,
        "attachment_anchor.attachment_anchor_handle",
    )?;
    let sandbox_id = exact_nonzero::<16>(&record.sandbox_id, "attachment_anchor.sandbox_id")?;
    let incarnation_id =
        exact_nonzero::<16>(&record.incarnation_id, "attachment_anchor.incarnation_id")?;
    let resource_kernel_boot_id = exact_nonzero::<16>(
        &record.resource_kernel_boot_id,
        "attachment_anchor.resource_kernel_boot_id",
    )?;
    if record.namespace_generation == 0
        || record.directory_device == 0
        || record.directory_inode == 0
        || record.unique_mount_id == 0
        || handle
            != attachment_anchor_handle_v1(
                &sandbox_id,
                &incarnation_id,
                record.namespace_generation,
                &resource_kernel_boot_id,
                record.directory_device,
                record.directory_inode,
                record.unique_mount_id,
            )
    {
        return Err(ProtocolValidationError::InvalidField(
            "attachment_anchor identity",
        ));
    }

    Ok(ValidatedAttachmentAnchorInventoryRecord {
        handle,
        sandbox_id,
        incarnation_id,
        namespace_generation: record.namespace_generation,
        resource_kernel_boot_id,
        directory_device: record.directory_device,
        directory_inode: record.directory_inode,
        unique_mount_id: record.unique_mount_id,
    })
}

fn validate_inventory_record(
    record: &DestinationSlotInventoryRecord,
) -> Result<ValidatedDestinationSlotInventoryRecord, ProtocolValidationError> {
    reject_unknown(&record.__buffa_unknown_fields)?;
    let binding = record
        .binding
        .as_option()
        .ok_or(ProtocolValidationError::MissingField(
            "destination_slot.binding",
        ))?;
    reject_unknown(&binding.__buffa_unknown_fields)?;
    let fence = validate_fence(binding.fence.as_option().ok_or(
        ProtocolValidationError::MissingField("destination_slot.binding.fence"),
    )?)?;
    if binding.namespace_generation == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "destination_slot.namespace_generation",
        ));
    }
    let destination_slot_id = exact_nonzero::<16>(
        &record.destination_slot_id,
        "destination_slot.destination_slot_id",
    )?;
    let sandbox_spec = validate_descriptor(
        record
            .sandbox_spec
            .as_option()
            .ok_or(ProtocolValidationError::MissingField(
                "destination_slot.sandbox_spec",
            ))?,
        DescriptorRole::SnapshotSpec,
    )?;
    let lifecycle = record
        .lifecycle
        .as_known()
        .filter(|value| *value != DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_UNSPECIFIED)
        .ok_or(ProtocolValidationError::InvalidField(
            "destination_slot.lifecycle",
        ))?;
    let resource_kernel_boot_id = exact_nonzero::<16>(
        &record.resource_kernel_boot_id,
        "destination_slot.resource_kernel_boot_id",
    )?;
    let materialization = validate_operation(record.materialization.as_option().ok_or(
        ProtocolValidationError::MissingField("destination_slot.materialization"),
    )?)?;
    let rematerialization = record
        .rematerialization
        .as_option()
        .map(validate_rematerialization)
        .transpose()?;
    let reap = record.reap.as_option().map(validate_reap).transpose()?;
    let slot_device = optional_nonzero(record.slot_device, "destination_slot.slot_device")?;
    let slot_inode = optional_nonzero(record.slot_inode, "destination_slot.slot_inode")?;
    let anchor_unique_mount_id = optional_nonzero(
        record.anchor_unique_mount_id,
        "destination_slot.anchor_unique_mount_id",
    )?;
    let resource_digest =
        exact_nonzero::<32>(&record.resource_digest, "destination_slot.resource_digest")?;
    let physical =
        slot_device.is_some() && slot_inode.is_some() && anchor_unique_mount_id.is_some();
    let partial_physical =
        slot_device.is_some() || slot_inode.is_some() || anchor_unique_mount_id.is_some();
    let shape_valid = match lifecycle {
        DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING => {
            !partial_physical && reap.is_none()
        }
        DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY => physical && reap.is_none(),
        DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING
        | DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED => {
            physical && reap.is_some()
        }
        DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_UNSPECIFIED => false,
    };
    if !shape_valid
        || rematerialization
            .is_some_and(|value| value.operation.operation_id == materialization.operation_id)
        || reap.is_some_and(|value| {
            value.operation.operation_id == materialization.operation_id
                || rematerialization.is_some_and(|rematerialization| {
                    value.operation.operation_id == rematerialization.operation.operation_id
                })
        })
    {
        return Err(ProtocolValidationError::InvalidField(
            "destination_slot lifecycle shape",
        ));
    }

    Ok(ValidatedDestinationSlotInventoryRecord {
        fence,
        namespace_generation: binding.namespace_generation,
        destination_slot_id,
        sandbox_spec,
        lifecycle,
        resource_kernel_boot_id,
        materialization,
        rematerialization,
        reap,
        slot_device,
        slot_inode,
        anchor_unique_mount_id,
        resource_digest,
    })
}

fn validate_rematerialization(
    rematerialization: &DestinationSlotRematerializationCorrelation,
) -> Result<ValidatedDestinationSlotRematerialization, ProtocolValidationError> {
    reject_unknown(&rematerialization.__buffa_unknown_fields)?;
    Ok(ValidatedDestinationSlotRematerialization {
        operation: validate_operation(rematerialization.operation.as_option().ok_or(
            ProtocolValidationError::MissingField("destination_slot.rematerialization.operation"),
        )?)?,
        expected_resource_digest: exact_nonzero::<32>(
            &rematerialization.expected_resource_digest,
            "destination_slot.rematerialization.expected_resource_digest",
        )?,
    })
}

fn validate_operation(
    operation: &MountOperationCorrelation,
) -> Result<ValidatedDestinationSlotOperation, ProtocolValidationError> {
    reject_unknown(&operation.__buffa_unknown_fields)?;
    Ok(ValidatedDestinationSlotOperation {
        operation_id: exact_nonzero::<16>(
            &operation.operation_id,
            "destination_slot.operation_id",
        )?,
        request_digest: exact_nonzero::<32>(
            &operation.request_digest,
            "destination_slot.request_digest",
        )?,
    })
}

fn validate_reap(
    reap: &DestinationSlotReapCorrelation,
) -> Result<ValidatedDestinationSlotReap, ProtocolValidationError> {
    reject_unknown(&reap.__buffa_unknown_fields)?;
    Ok(ValidatedDestinationSlotReap {
        operation: validate_operation(reap.operation.as_option().ok_or(
            ProtocolValidationError::MissingField("destination_slot.reap.operation"),
        )?)?,
        expected_resource_digest: exact_nonzero::<32>(
            &reap.expected_resource_digest,
            "destination_slot.reap.expected_resource_digest",
        )?,
    })
}

fn validate_response_bound(
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

fn optional_digest(
    bytes: &[u8],
    field: &'static str,
) -> Result<Option<[u8; 32]>, ProtocolValidationError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        exact_nonzero(bytes, field).map(Some)
    }
}

fn optional_nonzero(
    value: Option<u64>,
    field: &'static str,
) -> Result<Option<u64>, ProtocolValidationError> {
    value
        .map(|value| {
            if value == 0 {
                Err(ProtocolValidationError::InvalidField(field))
            } else {
                Ok(value)
            }
        })
        .transpose()
}

fn reject_unknown(fields: &buffa::UnknownFields) -> Result<(), ProtocolValidationError> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err(ProtocolValidationError::UnknownFields)
    }
}

const fn sandbox_spec_decode_limits() -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: MAXIMUM_DESTINATION_SLOT_SPEC_BYTES,
        maximum_collection_items: MAXIMUM_DESTINATION_SLOT_INVENTORY_RECORDS,
        maximum_total_items: 65_536,
        maximum_byte_string_bytes: MAXIMUM_DESTINATION_SLOT_SPEC_BYTES,
        maximum_text_bytes: 64 * 1024,
        maximum_depth: 128,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::num::NonZeroU32;

    use crate::semantics::canonical_destination_slot_semantics_v1;
    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Audience, Descriptor, MountAssignmentBinding, RequestHeader,
    };
    use aos_sandbox_core::model::{
        IdentityProfile, Limit, LimitDimension, LimitValue, NetworkKind, NetworkProfile,
        ResourceProfile, SandboxSpec, UnmappableIdentityPolicy,
    };
    use aos_sandbox_core::{
        AttachmentSlotId, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb, FeatureRef,
        MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType,
    };

    use super::*;

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 811,
            gid: 812,
            pid: Some(813),
        }
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 811,
            gid: Some(812),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([byte; 32]),
            1,
        )
    }

    fn specification(slot_id: [u8; 16]) -> (SandboxSpec, Vec<u8>, ObjectDescriptor) {
        let spec = SandboxSpec::new(
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
            descriptor(PortableMediaType::Environment, 1),
            descriptor(PortableMediaType::View, 2),
            vec![AttachmentSlotId::from_bytes(slot_id)],
            NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let bytes = encode_sandbox_spec(&spec);
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned()).unwrap(),
            &bytes,
        );
        (spec, bytes, descriptor)
    }

    fn proto_descriptor(descriptor: &ObjectDescriptor) -> Descriptor {
        Descriptor {
            media_type: descriptor.media_type().as_str().to_owned(),
            sha256: descriptor.digest().as_bytes().to_vec(),
            encoded_size: descriptor.encoded_size(),
            ..Default::default()
        }
    }

    fn request(action: DestinationSlotAction, operation_byte: u8) -> ApplyDestinationSlotRequest {
        let (_, spec_bytes, spec_descriptor) = specification([4; 16]);
        ApplyDestinationSlotRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 4,
                request_id: vec![operation_byte; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 4096,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![1; 16],
                incarnation_id: vec![2; 16],
                assignment_epoch: 3,
                desired_generation: 4,
                assignment_digest: vec![5; 32],
                ..Default::default()
            })
            .into(),
            action: action.into(),
            namespace_generation: 6,
            destination_slot_id: vec![4; 16],
            sandbox_spec: Some(proto_descriptor(&spec_descriptor)).into(),
            sandbox_spec_bytes: spec_bytes,
            expected_resource_digest: if matches!(
                action,
                DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP
                    | DestinationSlotAction::DESTINATION_SLOT_ACTION_REMATERIALIZE
            ) {
                vec![7; 32]
            } else {
                Vec::new()
            },
            resource_fence: matches!(
                action,
                DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP
                    | DestinationSlotAction::DESTINATION_SLOT_ACTION_REMATERIALIZE
            )
            .then(|| AssignmentFence {
                sandbox_id: vec![1; 16],
                incarnation_id: vec![2; 16],
                assignment_epoch: 3,
                desired_generation: 4,
                assignment_digest: vec![5; 32],
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    fn decode(request: &ApplyDestinationSlotRequest) -> ValidatedDestinationSlotRequest {
        decode_destination_slot_request(&request.encode_to_vec(), peer(), policy(), 1).unwrap()
    }

    fn inventory_record(
        slot_byte: u8,
        operation_byte: u8,
        lifecycle: DestinationSlotLifecycle,
    ) -> DestinationSlotInventoryRecord {
        let (_, _, spec_descriptor) = specification([slot_byte; 16]);
        let has_physical =
            lifecycle != DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING;
        let has_reap = matches!(
            lifecycle,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING
                | DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED
        );
        DestinationSlotInventoryRecord {
            binding: Some(MountAssignmentBinding {
                fence: Some(AssignmentFence {
                    sandbox_id: vec![1; 16],
                    incarnation_id: vec![2; 16],
                    assignment_epoch: 3,
                    desired_generation: 4,
                    assignment_digest: vec![5; 32],
                    ..Default::default()
                })
                .into(),
                namespace_generation: 6,
                ..Default::default()
            })
            .into(),
            destination_slot_id: vec![slot_byte; 16],
            sandbox_spec: Some(proto_descriptor(&spec_descriptor)).into(),
            lifecycle: lifecycle.into(),
            resource_kernel_boot_id: vec![8; 16],
            materialization: Some(MountOperationCorrelation {
                operation_id: vec![operation_byte; 16],
                request_digest: vec![operation_byte.wrapping_add(1); 32],
                ..Default::default()
            })
            .into(),
            reap: has_reap
                .then(|| DestinationSlotReapCorrelation {
                    operation: Some(MountOperationCorrelation {
                        operation_id: vec![operation_byte.wrapping_add(2); 16],
                        request_digest: vec![operation_byte.wrapping_add(3); 32],
                        ..Default::default()
                    })
                    .into(),
                    expected_resource_digest: vec![operation_byte.wrapping_add(4); 32],
                    ..Default::default()
                })
                .into(),
            slot_device: has_physical.then_some(9),
            slot_inode: has_physical.then_some(10),
            anchor_unique_mount_id: has_physical.then_some(11),
            resource_digest: vec![operation_byte.wrapping_add(5); 32],
            ..Default::default()
        }
    }

    fn with_rematerialization(
        mut record: DestinationSlotInventoryRecord,
        operation_byte: u8,
    ) -> DestinationSlotInventoryRecord {
        record.rematerialization = Some(DestinationSlotRematerializationCorrelation {
            operation: Some(MountOperationCorrelation {
                operation_id: vec![operation_byte; 16],
                request_digest: vec![operation_byte.wrapping_add(1); 32],
                ..Default::default()
            })
            .into(),
            expected_resource_digest: vec![operation_byte.wrapping_add(2); 32],
            ..Default::default()
        })
        .into();
        record
    }

    fn anchor_record(slot: &DestinationSlotInventoryRecord) -> AttachmentAnchorInventoryRecord {
        let binding = slot.binding.as_option().unwrap();
        let fence = binding.fence.as_option().unwrap();
        let sandbox_id: [u8; 16] = fence.sandbox_id.as_slice().try_into().unwrap();
        let incarnation_id: [u8; 16] = fence.incarnation_id.as_slice().try_into().unwrap();
        let resource_kernel_boot_id: [u8; 16] =
            slot.resource_kernel_boot_id.as_slice().try_into().unwrap();
        let directory_device = slot.slot_device.unwrap();
        let directory_inode = 12;
        let unique_mount_id = slot.anchor_unique_mount_id.unwrap();
        let handle = attachment_anchor_handle_v1(
            &sandbox_id,
            &incarnation_id,
            binding.namespace_generation,
            &resource_kernel_boot_id,
            directory_device,
            directory_inode,
            unique_mount_id,
        );
        AttachmentAnchorInventoryRecord {
            attachment_anchor_handle: handle.to_vec(),
            sandbox_id: sandbox_id.to_vec(),
            incarnation_id: incarnation_id.to_vec(),
            namespace_generation: binding.namespace_generation,
            resource_kernel_boot_id: resource_kernel_boot_id.to_vec(),
            directory_device,
            directory_inode,
            unique_mount_id,
            ..Default::default()
        }
    }

    fn refresh_anchor_handle(anchor: &mut AttachmentAnchorInventoryRecord) {
        let sandbox_id = anchor.sandbox_id.as_slice().try_into().unwrap();
        let incarnation_id = anchor.incarnation_id.as_slice().try_into().unwrap();
        let resource_kernel_boot_id = anchor
            .resource_kernel_boot_id
            .as_slice()
            .try_into()
            .unwrap();
        anchor.attachment_anchor_handle = attachment_anchor_handle_v1(
            &sandbox_id,
            &incarnation_id,
            anchor.namespace_generation,
            &resource_kernel_boot_id,
            anchor.directory_device,
            anchor.directory_inode,
            anchor.unique_mount_id,
        )
        .to_vec();
    }

    #[test]
    fn request_binds_exact_declaration_action_and_protocol_version() {
        let materialize = request(
            DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE,
            9,
        );
        let validated = decode(&materialize);
        assert_eq!(
            validated.action(),
            DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE
        );
        assert_eq!(validated.destination_slot_id(), &[4; 16]);
        assert!(validated.expected_resource_digest().is_none());
        assert!(validated.resource_fence().is_none());
        assert_eq!(validated.binding_fence(), validated.fence());
        assert_eq!(
            validated.sandbox_spec_bytes(),
            encode_sandbox_spec(validated.sandbox_specification())
        );

        let reap = decode(&request(
            DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP,
            10,
        ));
        assert_eq!(reap.expected_resource_digest(), Some(&[7; 32]));
        assert_eq!(reap.resource_fence(), Some(reap.binding_fence()));

        let rematerialize = decode(&request(
            DestinationSlotAction::DESTINATION_SLOT_ACTION_REMATERIALIZE,
            11,
        ));
        assert_eq!(rematerialize.expected_resource_digest(), Some(&[7; 32]));
        assert_eq!(
            rematerialize.resource_fence(),
            Some(rematerialize.binding_fence())
        );

        let mut missing_resource_fence = request(
            DestinationSlotAction::DESTINATION_SLOT_ACTION_REMATERIALIZE,
            12,
        );
        missing_resource_fence.resource_fence = Default::default();
        assert!(
            decode_destination_slot_request(
                &missing_resource_fence.encode_to_vec(),
                peer(),
                policy(),
                1
            )
            .is_err()
        );

        let mut legacy = materialize.clone();
        legacy.header.get_or_insert_default().protocol_minor = 2;
        assert_eq!(
            decode_destination_slot_request(&legacy.encode_to_vec(), peer(), policy(), 1),
            Err(ProtocolValidationError::MethodMismatch)
        );

        let mut undeclared = materialize.clone();
        undeclared.destination_slot_id = vec![12; 16];
        assert!(
            decode_destination_slot_request(&undeclared.encode_to_vec(), peer(), policy(), 1)
                .is_err()
        );

        let mut substituted = materialize.clone();
        substituted.sandbox_spec_bytes[0] ^= 1;
        assert!(
            decode_destination_slot_request(&substituted.encode_to_vec(), peer(), policy(), 1)
                .is_err()
        );

        let mut extra_resource_fence = materialize.clone();
        extra_resource_fence.resource_fence = Some(AssignmentFence {
            sandbox_id: vec![1; 16],
            incarnation_id: vec![2; 16],
            assignment_epoch: 3,
            desired_generation: 4,
            assignment_digest: vec![5; 32],
            ..Default::default()
        })
        .into();
        assert!(
            decode_destination_slot_request(
                &extra_resource_fence.encode_to_vec(),
                peer(),
                policy(),
                1
            )
            .is_err()
        );

        let mut wrong_shape = materialize;
        wrong_shape.expected_resource_digest = vec![13; 32];
        assert!(
            decode_destination_slot_request(&wrong_shape.encode_to_vec(), peer(), policy(), 1)
                .is_err()
        );
    }

    #[test]
    fn reap_separates_new_authority_from_the_immutable_resource_fence() {
        let mut advanced = request(DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP, 10);
        advanced.fence.get_or_insert_default().desired_generation = 5;
        advanced.fence.get_or_insert_default().assignment_digest = vec![6; 32];

        let validated = decode(&advanced);
        assert_eq!(validated.fence().desired_generation(), 5);
        assert_eq!(validated.binding_fence().desired_generation(), 4);
        assert_eq!(validated.binding_fence().assignment_digest(), &[5; 32]);

        let mut conflicting = advanced.clone();
        conflicting
            .resource_fence
            .get_or_insert_default()
            .desired_generation = 5;
        assert_eq!(
            decode_destination_slot_request(&conflicting.encode_to_vec(), peer(), policy(), 1),
            Err(ProtocolValidationError::InvalidField(
                "destination_slot action shape"
            ))
        );

        let mut foreign = advanced;
        foreign.resource_fence.get_or_insert_default().sandbox_id = vec![9; 16];
        assert_eq!(
            decode_destination_slot_request(&foreign.encode_to_vec(), peer(), policy(), 1),
            Err(ProtocolValidationError::InvalidField(
                "destination_slot action shape"
            ))
        );
    }

    #[test]
    fn canonical_semantics_separate_creation_from_exact_resource_mutations() {
        let materialize = decode(&request(
            DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE,
            9,
        ));
        let materialize = canonical_destination_slot_semantics_v1(&materialize).unwrap();
        assert_eq!(
            materialize.verb(),
            BrokerVerb::MountMaterializeDestinationSlot
        );
        assert_eq!(materialize.target(), BrokerGrantTarget::Assignment);

        let reap = decode(&request(
            DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP,
            10,
        ));
        let reap = canonical_destination_slot_semantics_v1(&reap).unwrap();
        assert_eq!(reap.verb(), BrokerVerb::MountReapDestinationSlot);
        assert_eq!(
            reap.target(),
            BrokerGrantTarget::Resource(BrokerResourceHandle::from_bytes([7; 32]).unwrap())
        );
        assert_ne!(materialize.commitment(), reap.commitment());
        assert_ne!(materialize.canonical_bytes(), reap.canonical_bytes());

        let rematerialize = decode(&request(
            DestinationSlotAction::DESTINATION_SLOT_ACTION_REMATERIALIZE,
            12,
        ));
        let rematerialize = canonical_destination_slot_semantics_v1(&rematerialize).unwrap();
        assert_eq!(
            rematerialize.verb(),
            BrokerVerb::MountRematerializeDestinationSlot
        );
        assert_eq!(
            rematerialize.target(),
            BrokerGrantTarget::Resource(BrokerResourceHandle::from_bytes([7; 32]).unwrap())
        );
        assert_ne!(materialize.commitment(), rematerialize.commitment());
        assert_ne!(reap.commitment(), rematerialize.commitment());

        let mut historical = request(DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP, 11);
        historical.fence.get_or_insert_default().desired_generation = 5;
        historical.fence.get_or_insert_default().assignment_digest = vec![6; 32];
        let original = canonical_destination_slot_semantics_v1(&decode(&historical)).unwrap();
        historical
            .resource_fence
            .get_or_insert_default()
            .desired_generation = 3;
        historical
            .resource_fence
            .get_or_insert_default()
            .assignment_digest = vec![4; 32];
        let substituted = canonical_destination_slot_semantics_v1(&decode(&historical)).unwrap();
        assert_ne!(original.commitment(), substituted.commitment());
        assert_ne!(original.canonical_bytes(), substituted.canonical_bytes());
    }

    #[test]
    fn inventory_round_trip_closes_every_lifecycle_shape() {
        for lifecycle in [
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED,
        ] {
            let record = inventory_record(4, lifecycle as i32 as u8 + 20, lifecycle);
            let response = encode_destination_slot_response(record.clone()).unwrap();
            let decoded = decode_destination_slot_response(&response, 4096).unwrap();
            assert_eq!(decoded.lifecycle(), lifecycle);
            assert_eq!(decoded.destination_slot_id(), &[4; 16]);
            assert_eq!(
                decoded.slot_device().is_some(),
                lifecycle != DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING
            );
            assert_eq!(
                decoded.reap().is_some(),
                matches!(
                    lifecycle,
                    DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING
                        | DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED
                )
            );

            let mut malformed = record;
            if lifecycle == DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING {
                malformed.slot_device = Some(9);
            } else {
                malformed.slot_inode = None;
            }
            assert!(encode_destination_slot_response(malformed).is_err());
        }
    }

    #[test]
    fn inventory_preserves_rematerialization_in_every_subsequent_phase() {
        for lifecycle in [
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED,
        ] {
            let record = with_rematerialization(
                inventory_record(4, lifecycle as i32 as u8 + 20, lifecycle),
                80,
            );
            let response = encode_destination_slot_response(record).unwrap();
            let decoded = decode_destination_slot_response(&response, 4096).unwrap();
            let rematerialization = decoded.rematerialization().unwrap();
            assert_eq!(rematerialization.operation().operation_id(), &[80; 16]);
            assert_eq!(rematerialization.expected_resource_digest(), &[82; 32]);
        }

        let original = inventory_record(
            4,
            30,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
        );
        let same_as_creation = with_rematerialization(original, 30);
        assert!(encode_destination_slot_response(same_as_creation).is_err());

        let reaping = inventory_record(
            4,
            30,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING,
        );
        let same_as_reap = with_rematerialization(reaping, 32);
        assert!(encode_destination_slot_response(same_as_reap).is_err());
    }

    #[test]
    fn complete_inventory_requires_order_and_global_operation_uniqueness() {
        let first = inventory_record(
            4,
            30,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
        );
        let second = inventory_record(
            5,
            40,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED,
        );
        let response = InventoryDestinationSlotsResponse {
            kernel_boot_id: vec![8; 16],
            journal_sequence: 41,
            slots: vec![first.clone(), second.clone()],
            broker_instance_id: vec![9; 16],
            ..Default::default()
        };
        let encoded = encode_destination_slot_inventory_response(response.clone()).unwrap();
        let decoded = decode_destination_slot_inventory_response(&encoded, 16 * 1024).unwrap();
        assert_eq!(decoded.slots().len(), 2);
        assert_eq!(decoded.journal_sequence(), 41);

        let mut reversed = response.clone();
        reversed.slots.reverse();
        assert!(encode_destination_slot_inventory_response(reversed).is_err());

        let mut reused = response;
        reused.slots[1]
            .materialization
            .get_or_insert_default()
            .operation_id = vec![30; 16];
        assert!(encode_destination_slot_inventory_response(reused).is_err());

        let first = with_rematerialization(first, 50);
        let second = inventory_record(
            5,
            40,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED,
        );
        let reused_rematerialization = InventoryDestinationSlotsResponse {
            kernel_boot_id: vec![8; 16],
            journal_sequence: 42,
            slots: vec![first, second],
            broker_instance_id: vec![9; 16],
            ..Default::default()
        };
        let mut reused_rematerialization = reused_rematerialization;
        reused_rematerialization.slots[1]
            .reap
            .get_or_insert_default()
            .operation
            .get_or_insert_default()
            .operation_id = vec![50; 16];
        assert!(encode_destination_slot_inventory_response(reused_rematerialization).is_err());

        let inventory_request = InventoryDestinationSlotsRequest {
            header: request(
                DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE,
                50,
            )
            .header,
            ..Default::default()
        };
        assert!(
            decode_destination_slot_inventory_request(
                &inventory_request.encode_to_vec(),
                peer(),
                policy(),
                1,
            )
            .is_ok()
        );

        let mut current = inventory_request;
        current.header.get_or_insert_default().protocol_minor = 5;
        assert!(
            decode_destination_slot_inventory_request(
                &current.encode_to_vec(),
                peer(),
                policy(),
                1,
            )
            .is_ok()
        );
        current.header.get_or_insert_default().protocol_minor = 6;
        assert!(matches!(
            decode_destination_slot_inventory_request(
                &current.encode_to_vec(),
                peer(),
                policy(),
                1,
            ),
            Err(ProtocolValidationError::Protocol(_))
        ));
    }

    #[test]
    fn mount_one_five_inventory_requires_exact_complete_current_anchors() {
        let ready = inventory_record(
            4,
            30,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
        );
        let anchor = anchor_record(&ready);
        let response = InventoryDestinationSlotsResponse {
            kernel_boot_id: vec![8; 16],
            journal_sequence: 41,
            slots: vec![ready],
            broker_instance_id: vec![9; 16],
            attachment_anchors: vec![anchor.clone()],
            ..Default::default()
        };
        let encoded = encode_destination_slot_inventory_response_for_version(
            response.clone(),
            DESTINATION_SLOT_PROTOCOL_V1_5,
        )
        .unwrap();
        let decoded = decode_destination_slot_inventory_response_for_version(
            &encoded,
            16 * 1024,
            DESTINATION_SLOT_PROTOCOL_V1_5,
        )
        .unwrap();
        assert_eq!(decoded.protocol_version(), DESTINATION_SLOT_PROTOCOL_V1_5);
        assert_eq!(decoded.attachment_anchors().len(), 1);
        assert_eq!(
            decoded.attachment_anchors()[0].handle().as_slice(),
            anchor.attachment_anchor_handle.as_slice()
        );

        let mut missing = response.clone();
        missing.attachment_anchors.clear();
        assert!(
            encode_destination_slot_inventory_response_for_version(
                missing,
                DESTINATION_SLOT_PROTOCOL_V1_5,
            )
            .is_err()
        );
        assert!(
            encode_destination_slot_inventory_response_for_version(
                response.clone(),
                DESTINATION_SLOT_PROTOCOL_V1_4,
            )
            .is_err()
        );

        let mut substituted = response;
        substituted.attachment_anchors[0].directory_inode += 1;
        assert!(
            encode_destination_slot_inventory_response_for_version(
                substituted.clone(),
                DESTINATION_SLOT_PROTOCOL_V1_5,
            )
            .is_err()
        );

        let mut cross_link_substitution = substituted;
        cross_link_substitution.attachment_anchors[0].unique_mount_id += 1;
        refresh_anchor_handle(&mut cross_link_substitution.attachment_anchors[0]);
        assert!(
            encode_destination_slot_inventory_response_for_version(
                cross_link_substitution,
                DESTINATION_SLOT_PROTOCOL_V1_5,
            )
            .is_err()
        );

        let stale_ready = inventory_record(
            4,
            30,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
        );
        assert!(
            encode_destination_slot_inventory_response_for_version(
                InventoryDestinationSlotsResponse {
                    kernel_boot_id: vec![9; 16],
                    journal_sequence: 42,
                    slots: vec![stale_ready],
                    broker_instance_id: vec![10; 16],
                    ..Default::default()
                },
                DESTINATION_SLOT_PROTOCOL_V1_5,
            )
            .is_ok()
        );
    }

    #[test]
    fn attachment_anchor_handle_derivation_is_stable() {
        assert_eq!(
            attachment_anchor_handle_v1(&[2; 16], &[3; 16], 4, &[8; 16], 40, 43, 42),
            [
                0xbe, 0x43, 0x67, 0xc1, 0xc1, 0x34, 0x0e, 0x01, 0x83, 0x7d, 0x60, 0x63, 0x9b, 0x3f,
                0x9c, 0x28, 0x5c, 0x9d, 0x05, 0x2e, 0x77, 0xef, 0xd9, 0x93, 0xad, 0x34, 0x38, 0xb2,
                0x4f, 0xa3, 0xf8, 0xac,
            ]
        );
    }
}
