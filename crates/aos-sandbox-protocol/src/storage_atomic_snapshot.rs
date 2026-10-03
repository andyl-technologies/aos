//! Bounded node-local request and committed response for a grouped Storage snapshot.
//!
//! This layer checks the protobuf envelope and cheap wire bounds. The Storage
//! owner must decode the complete typed lifecycle plan and reread its protected
//! physical catalog before invoking the grouped backend transaction.

use aos_proto::aos::sandbox::local::v1::{
    ApplyAtomicStorageSnapshotRequest, AtomicStorageSnapshotResponse,
};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerVerb, ProtocolId, ProtocolVersion,
};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, PeerCredentials, PeerPolicy,
    ProtocolValidationError, ValidatedHeader, validate_request_header,
};

/// Largest canonical lifecycle plan accepted inside the ordinary local packet.
pub const MAXIMUM_ATOMIC_STORAGE_SNAPSHOT_PLAN_BYTES: usize = 600_000;
const MINIMUM_ATOMIC_STORAGE_SNAPSHOT_PLAN_BYTES: usize = 540;
const PLAN_MAGIC: &[u8; 8] = b"AOSASP02";

// The target follows the V2 prefix, operation, transaction, and effect fields
// preceding `target`; a changed plan layout must use a different magic.
const PLAN_ROOT_TARGET_OFFSET: usize = 158;

/// Retains a canonical bounded request, without granting mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAtomicStorageSnapshotRequestV1 {
    header: ValidatedHeader,
    fence: crate::ValidatedAssignmentFence,
    canonical_plan: Vec<u8>,
    operation: [u8; 16],
}

impl ValidatedAtomicStorageSnapshotRequestV1 {
    /// Returns the peer-bound local request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact root assignment carried by this grouped request.
    #[must_use]
    pub const fn fence(&self) -> &crate::ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the complete plan bytes for typed Storage-side verification.
    #[must_use]
    pub fn canonical_plan(&self) -> &[u8] {
        &self.canonical_plan
    }

    /// Returns the operation identity encoded by the plan.
    #[must_use]
    pub const fn operation(&self) -> [u8; 16] {
        self.operation
    }

    /// Returns the distinct grouped-snapshot authorization verb.
    #[must_use]
    pub const fn broker_verb(&self) -> BrokerVerb {
        BrokerVerb::StorageAtomicSnapshot
    }

    /// Returns the root assignment grant scope; plan bytes name every member.
    #[must_use]
    pub const fn grant_target(&self) -> BrokerGrantTarget {
        BrokerGrantTarget::Assignment
    }

    /// Commits the complete group plan as one indivisible signed argument.
    #[must_use]
    pub fn argument_commitment(&self) -> BrokerArgumentCommitment {
        BrokerArgumentCommitment::for_canonical_bytes(&self.canonical_plan)
    }
}

/// Retains one committed grouped transaction and its physical observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedAtomicStorageSnapshotResponseV1 {
    program: [u8; 32],
    observation: [u8; 32],
}

impl ValidatedAtomicStorageSnapshotResponseV1 {
    /// Returns the exact durable grouped-program commitment.
    #[must_use]
    pub const fn program(self) -> [u8; 32] {
        self.program
    }

    /// Returns the committed complete-group physical observation.
    #[must_use]
    pub const fn observation(self) -> [u8; 32] {
        self.observation
    }
}

/// Decodes the canonical local envelope without interpreting plan authority.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for a malformed or oversized message,
/// invalid peer/header, unknown fields, or a plan outside its versioned bounds.
pub fn decode_atomic_storage_snapshot_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedAtomicStorageSnapshotRequestV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyAtomicStorageSnapshotRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if request.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::InvalidField("canonical request"));
    }
    let header = request
        .header
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("header"))?;
    let header = validate_request_header(
        header,
        peer,
        policy,
        ProtocolId::StorageBroker,
        now_boottime_nanoseconds,
    )?;
    if header.protocol_version() != ProtocolVersion::new(1, 0) {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    let fence = crate::validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let plan = request.canonical_plan;
    if !(MINIMUM_ATOMIC_STORAGE_SNAPSHOT_PLAN_BYTES..=MAXIMUM_ATOMIC_STORAGE_SNAPSHOT_PLAN_BYTES)
        .contains(&plan.len())
        || plan.get(..8) != Some(PLAN_MAGIC.as_slice())
    {
        return Err(ProtocolValidationError::InvalidField("canonical_plan"));
    }
    let operation: [u8; 16] = plan[8..24]
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("canonical_plan"))?;
    if operation == [0; 16]
        || plan.get(PLAN_ROOT_TARGET_OFFSET..PLAN_ROOT_TARGET_OFFSET + 16)
            != Some(fence.sandbox_id().as_slice())
    {
        return Err(ProtocolValidationError::InvalidField("canonical_plan"));
    }
    Ok(ValidatedAtomicStorageSnapshotRequestV1 {
        header,
        fence,
        canonical_plan: plan,
        operation,
    })
}

/// Decodes only an unambiguous committed grouped snapshot result.
///
/// Ambiguous post-mutation state is an error outcome, not a successful result.
/// The Storage owner must then recover through protected inventory without
/// redispatching the backend transaction.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed, noncanonical, unknown,
/// ambiguous, or incomplete committed responses.
pub fn decode_atomic_storage_snapshot_response(
    bytes: &[u8],
) -> Result<ValidatedAtomicStorageSnapshotResponseV1, ProtocolValidationError> {
    let maximum = usize::try_from(MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| ProtocolValidationError::ResponseTooLarge)?;
    if bytes.len() > maximum {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = AtomicStorageSnapshotResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if response.encode_to_vec() != bytes || response.observation_required {
        return Err(ProtocolValidationError::InvalidField(
            "atomic snapshot response",
        ));
    }
    let program: [u8; 32] = response
        .program_digest
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("program_digest"))?;
    let observation: [u8; 32] = response
        .observation_digest
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("observation_digest"))?;
    if program == [0; 32] || observation == [0; 32] {
        return Err(ProtocolValidationError::InvalidField(
            "atomic snapshot response",
        ));
    }
    Ok(ValidatedAtomicStorageSnapshotResponseV1 {
        program,
        observation,
    })
}
