//! Validates Mount 2.0 source-acquisition requests and derives stable identities.
//!
//! The controller supplies only portable source and prospective Mount semantics.
//! Provider identity, routing, trust, session, sequence, revocation, node, and
//! boot inputs remain protected Mount state and never enter these messages.
//!
//! Acquisition identity has this exact preimage:
//!
//! ```text
//! aos.sandbox.mount.source-acquisition-id.v1\0 ||
//! acquire-operation-id[16] || SHA256(exact AcquireMountSourceRequest body)[32]
//! ```

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{
    AcquireMountSourceRequest, AcquireMountSourceResponse, InventoryMountSourceAcquisitionsRequest,
    InventoryMountSourceAcquisitionsResponse, MountSourceAcquisitionPhase,
    MountSourceAcquisitionRecord, MountSourceProofClass, ReleaseMountSourceAcquisitionRequest,
    ReleaseMountSourceAcquisitionResponse,
};
use aos_sandbox_core::{ObjectDigest, ProtocolId, ProtocolVersion, encode_view_source};
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_SOURCE_LEASE_SECONDS, MAXIMUM_SOURCE_SUBMOUNTS, SourceRootObservationV1,
    digest_logical_binding_bytes, prospective_mount_apply_template_digest_v1,
    source_root_descriptor_commitment_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    SourceRealizationBindingV1, ValidatedAssignmentFence, ValidatedHeader, exact_nonzero,
    validate_fence, validate_request_header,
};

const ACQUISITION_ID_DOMAIN: &[u8] = b"aos.sandbox.mount.source-acquisition-id.v1\0";
const MOUNT_SEMANTICS_MAGIC: &[u8; 8] = b"AOSMSEM1";
const MOUNT_SEMANTICS_VERSION: u16 = 1;
const MOUNT_SEMANTICS_FIELDS: usize = 27;
/// Maximum rows in one Mount source-acquisition inventory.
pub const MAXIMUM_MOUNT_SOURCE_ACQUISITION_RECORDS: usize = 1_024;

mod correlation;
#[cfg(test)]
mod tests;

use correlation::{
    record_acquisition_id_is_exact, record_matches_fence, record_proof_matches_binding,
    release_fence_dominates_record,
};

/// Carries the shared time-independent fields of one source Acquire request.
///
/// This DTO is nonauthorizing. Live peer-policy and deadline validation is
/// represented only by [`LiveValidatedAcquireMountSourceRequest`], while
/// durable recovery receives [`HistoricalValidatedAcquireMountSourceRequest`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAcquireMountSourceRequest {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    acquisition_id: ObjectDigest,
    request_digest: ObjectDigest,
    prospective_mount_template: Vec<u8>,
    prospective_mount_template_digest: ObjectDigest,
    prospective_namespace_generation: u64,
    source_binding: SourceRealizationBindingV1,
    requested_lease_seconds: u64,
    requested_maximum_submounts: u32,
    recursive: bool,
    kernel_coupled: bool,
}

/// Carries a time-independent Acquire request decoded from durable history.
///
/// The wrapper proves canonical wire shape and semantic cross-links only. It
/// deliberately cannot satisfy a live Mount admission API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalValidatedAcquireMountSourceRequest {
    request: ValidatedAcquireMountSourceRequest,
}

impl HistoricalValidatedAcquireMountSourceRequest {
    /// Borrows the shared nonauthorizing request DTO.
    #[must_use]
    pub const fn request(&self) -> &ValidatedAcquireMountSourceRequest {
        &self.request
    }
}

impl std::ops::Deref for HistoricalValidatedAcquireMountSourceRequest {
    type Target = ValidatedAcquireMountSourceRequest;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

/// Carries an Acquire request after live peer-policy and deadline validation.
///
/// Construction is private to [`decode_acquire_mount_source_request`]. Later
/// admission still rechecks its exact body, current protected clock, signed
/// authority, ownership lease, and protected assignment fence.
#[derive(Debug, Eq, PartialEq)]
pub struct LiveValidatedAcquireMountSourceRequest {
    request: ValidatedAcquireMountSourceRequest,
}

impl LiveValidatedAcquireMountSourceRequest {
    /// Borrows the shared nonauthorizing request DTO.
    #[must_use]
    pub const fn request(&self) -> &ValidatedAcquireMountSourceRequest {
        &self.request
    }
}

impl std::ops::Deref for LiveValidatedAcquireMountSourceRequest {
    type Target = ValidatedAcquireMountSourceRequest;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

impl ValidatedAcquireMountSourceRequest {
    /// Returns the validated Mount request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact assignment fence authorized by the signed plan and lease.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the Mount-minted deterministic acquisition identity.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns SHA-256 over the complete exact protobuf request body.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the exact deadline-free `AOSMSEM1` prospective Create semantics.
    #[must_use]
    pub fn prospective_mount_template(&self) -> &[u8] {
        &self.prospective_mount_template
    }

    /// Returns the SourceProvider-defined prospective-template digest.
    #[must_use]
    pub const fn prospective_mount_template_digest(&self) -> ObjectDigest {
        self.prospective_mount_template_digest
    }

    /// Returns the payload namespace generation fixed by the prospective Create.
    #[must_use]
    pub const fn prospective_namespace_generation(&self) -> u64 {
        self.prospective_namespace_generation
    }

    /// Returns the exact canonical logical source binding.
    #[must_use]
    pub const fn source_binding(&self) -> &SourceRealizationBindingV1 {
        &self.source_binding
    }

    /// Returns the requested provider lease duration.
    #[must_use]
    pub const fn requested_lease_seconds(&self) -> u64 {
        self.requested_lease_seconds
    }

    /// Returns the requested recursive submount ceiling.
    #[must_use]
    pub const fn requested_maximum_submounts(&self) -> u32 {
        self.requested_maximum_submounts
    }

    /// Reports whether the prospective mount traverses provider submounts.
    #[must_use]
    pub const fn recursive(&self) -> bool {
        self.recursive
    }

    /// Reports whether the source requires a kernel-coupled provider grant.
    #[must_use]
    pub const fn kernel_coupled(&self) -> bool {
        self.kernel_coupled
    }
}

/// Carries the shared fields of one source-acquisition Release request.
///
/// This DTO is nonauthorizing. Only
/// [`LiveValidatedReleaseMountSourceAcquisitionRequest`] proves that live peer
/// and deadline validation ran.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReleaseMountSourceAcquisitionRequest {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    acquisition_id: ObjectDigest,
    expected_revision: u64,
    expected_record_digest: ObjectDigest,
    request_digest: ObjectDigest,
}

/// Carries a Release request after live peer-policy and deadline validation.
///
/// Construction is private to
/// [`decode_release_mount_source_acquisition_request`]. Admission still binds
/// the exact carrier envelope and rechecks protected authority and time.
#[derive(Debug, Eq, PartialEq)]
pub struct LiveValidatedReleaseMountSourceAcquisitionRequest {
    request: ValidatedReleaseMountSourceAcquisitionRequest,
}

impl LiveValidatedReleaseMountSourceAcquisitionRequest {
    /// Borrows the shared nonauthorizing request DTO.
    #[must_use]
    pub const fn request(&self) -> &ValidatedReleaseMountSourceAcquisitionRequest {
        &self.request
    }
}

impl std::ops::Deref for LiveValidatedReleaseMountSourceAcquisitionRequest {
    type Target = ValidatedReleaseMountSourceAcquisitionRequest;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

/// Carries stable correlation fields from one validated acquisition record.
#[derive(Clone, Debug)]
pub struct ValidatedMountSourceAcquisitionRecord {
    record: MountSourceAcquisitionRecord,
    acquisition_id: [u8; 32],
    revision: u64,
    phase: MountSourceAcquisitionPhase,
    acquire_operation_id: [u8; 16],
    acquire_request_digest: [u8; 32],
    release_operation_id: Option<[u8; 16]>,
    release_request_digest: Option<[u8; 32]>,
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    namespace_generation: u64,
    record_digest: [u8; 32],
}

impl ValidatedMountSourceAcquisitionRecord {
    /// Returns the complete validated lossless wire projection.
    #[must_use]
    pub const fn wire_record(&self) -> &MountSourceAcquisitionRecord {
        &self.record
    }

    /// Returns the Mount-minted acquisition ID.
    #[must_use]
    pub const fn acquisition_id(&self) -> &[u8; 32] {
        &self.acquisition_id
    }

    /// Returns the monotonic AOSMSA02 row revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the closed acquisition lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> MountSourceAcquisitionPhase {
        self.phase
    }

    /// Returns the exact original Acquire operation ID.
    #[must_use]
    pub const fn acquire_operation_id(&self) -> &[u8; 16] {
        &self.acquire_operation_id
    }

    /// Returns the exact original Acquire body digest.
    #[must_use]
    pub const fn acquire_request_digest(&self) -> &[u8; 32] {
        &self.acquire_request_digest
    }

    /// Returns the optional Release operation ID.
    #[must_use]
    pub const fn release_operation_id(&self) -> Option<&[u8; 16]> {
        self.release_operation_id.as_ref()
    }

    /// Returns the optional Release body digest.
    #[must_use]
    pub const fn release_request_digest(&self) -> Option<&[u8; 32]> {
        self.release_request_digest.as_ref()
    }

    /// Returns the assignment sandbox ID.
    #[must_use]
    pub const fn sandbox_id(&self) -> &[u8; 16] {
        &self.sandbox_id
    }

    /// Returns the assignment incarnation ID.
    #[must_use]
    pub const fn incarnation_id(&self) -> &[u8; 16] {
        &self.incarnation_id
    }

    /// Returns the assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }

    /// Returns the desired assignment generation.
    #[must_use]
    pub const fn desired_generation(&self) -> u64 {
        self.desired_generation
    }

    /// Returns the exact assignment semantics digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> &[u8; 32] {
        &self.assignment_digest
    }

    /// Returns the prospective payload namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.namespace_generation
    }

    /// Returns the broker-authenticated AOSMSA02 row digest.
    #[must_use]
    pub const fn record_digest(&self) -> &[u8; 32] {
        &self.record_digest
    }
}

/// Carries one complete validated Mount source-acquisition inventory snapshot.
#[derive(Clone, Debug)]
pub struct ValidatedMountSourceAcquisitionInventory {
    kernel_boot_id: [u8; 16],
    journal_sequence: u64,
    acquisitions: Vec<ValidatedMountSourceAcquisitionRecord>,
    broker_instance_id: [u8; 16],
}

impl ValidatedMountSourceAcquisitionInventory {
    /// Returns the kernel boot claimed by Mount.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> &[u8; 16] {
        &self.kernel_boot_id
    }

    /// Returns the next-frame journal snapshot boundary.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns acquisitions in strict acquisition-ID order.
    #[must_use]
    pub fn acquisitions(&self) -> &[ValidatedMountSourceAcquisitionRecord] {
        &self.acquisitions
    }

    /// Returns the Mount process instance ID.
    #[must_use]
    pub const fn broker_instance_id(&self) -> &[u8; 16] {
        &self.broker_instance_id
    }
}

impl ValidatedReleaseMountSourceAcquisitionRequest {
    /// Returns the validated Mount request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the current teardown-authority fence supplied by the controller.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the exact acquisition row being released.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the exact expected row revision.
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    /// Returns the exact expected authenticated row digest.
    #[must_use]
    pub const fn expected_record_digest(&self) -> ObjectDigest {
        self.expected_record_digest
    }

    /// Returns SHA-256 over the complete exact protobuf request body.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }
}

/// Derives SHA-256 over the exact protobuf body without another semantic domain.
#[must_use]
pub fn mount_source_acquisition_request_digest_v1(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

/// Derives the deterministic Mount acquisition ID for one exact Acquire body.
#[must_use]
pub fn mount_source_acquisition_id_v1(
    operation_id: [u8; 16],
    request_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ACQUISITION_ID_DOMAIN);
    digest.update(operation_id);
    digest.update(request_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Decodes and validates one hostile Mount source-acquisition effect body.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed or oversized bytes,
/// unknown fields, an invalid exact Mount 2.0 header or fence, a noncanonical
/// binding, an invalid SourceProvider template digest, or any mismatch between
/// the binding, fence, recursive request, and prospective Create semantics.
pub fn decode_acquire_mount_source_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<LiveValidatedAcquireMountSourceRequest, ProtocolValidationError> {
    let historical = decode_historical_acquire_mount_source_request(bytes)?;
    let mut validated = historical.request;
    let request = AcquireMountSourceRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    validated.header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::MountBroker,
        now_boottime_nanoseconds,
    )?;
    Ok(LiveValidatedAcquireMountSourceRequest { request: validated })
}

/// Decodes one exact historical Mount Acquire body without claiming live authority.
///
/// This applies the complete time-independent Mount 2.0, canonical binding, and
/// pre-catalog Create semantic contract. It deliberately does not authenticate a
/// Unix peer or establish deadline currentness; callers may use it only to
/// reproduce an already-journaled request before protected recovery checks.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed, noncanonical, oversized,
/// or semantically inconsistent request bytes.
pub fn decode_historical_acquire_mount_source_request(
    bytes: &[u8],
) -> Result<HistoricalValidatedAcquireMountSourceRequest, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = AcquireMountSourceRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let raw_header = request
        .header
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("header"))?;
    if !raw_header.__buffa_unknown_fields.is_empty()
        || raw_header.protocol_major != 2
        || raw_header.protocol_minor != 0
        || raw_header.audience.as_known()
            != Some(aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER)
        || raw_header.deadline_boottime_nanoseconds == 0
        || !(crate::MINIMUM_RESPONSE_BYTES..=crate::MAXIMUM_RESPONSE_BYTES)
            .contains(&raw_header.maximum_response_bytes)
    {
        return Err(ProtocolValidationError::InvalidField("header"));
    }
    let header = ValidatedHeader {
        protocol_version: ProtocolVersion::new(2, 0),
        audience: aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER,
        request_id: exact_nonzero::<16>(&raw_header.request_id, "header.request_id")?,
        deadline_boottime_nanoseconds: raw_header.deadline_boottime_nanoseconds,
        maximum_response_bytes: raw_header.maximum_response_bytes,
    };
    let fence = validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let source_binding = SourceRealizationBindingV1::from_canonical_bytes(&request.source_binding)
        .map_err(|_| ProtocolValidationError::InvalidField("source_binding"))?;
    let source_binding_digest =
        exact_nonzero::<32>(&request.source_binding_digest, "source_binding_digest")?;
    if digest_logical_binding_bytes(&request.source_binding).as_bytes() != &source_binding_digest {
        return Err(ProtocolValidationError::InvalidField(
            "source_binding_digest",
        ));
    }
    let prospective_mount_template_digest = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &request.prospective_mount_template_digest,
        "prospective_mount_template_digest",
    )?);
    let derived_template_digest =
        prospective_mount_apply_template_digest_v1(&request.prospective_mount_template)
            .map_err(|_| ProtocolValidationError::InvalidField("prospective_mount_template"))?;
    if prospective_mount_template_digest != derived_template_digest {
        return Err(ProtocolValidationError::InvalidField(
            "prospective_mount_template_digest",
        ));
    }
    if request.requested_lease_seconds == 0
        || request.requested_lease_seconds > MAXIMUM_SOURCE_LEASE_SECONDS
        || request.requested_maximum_submounts > MAXIMUM_SOURCE_SUBMOUNTS
    {
        return Err(ProtocolValidationError::InvalidField(
            "source acquisition lease or topology bound",
        ));
    }
    let recursive = validate_prospective_create(
        &request.prospective_mount_template,
        &fence,
        &source_binding,
        request.requested_maximum_submounts,
        request.kernel_coupled,
    )?;
    let prospective_namespace_generation =
        decode_u64(&decode_semantic_fields(&request.prospective_mount_template)?[11])?;

    let request_digest = mount_source_acquisition_request_digest_v1(bytes);
    let acquisition_id = mount_source_acquisition_id_v1(*header.request_id(), request_digest);
    Ok(HistoricalValidatedAcquireMountSourceRequest {
        request: ValidatedAcquireMountSourceRequest {
            header,
            fence,
            acquisition_id,
            request_digest,
            prospective_mount_template: request.prospective_mount_template,
            prospective_mount_template_digest,
            prospective_namespace_generation,
            source_binding,
            requested_lease_seconds: request.requested_lease_seconds,
            requested_maximum_submounts: request.requested_maximum_submounts,
            recursive,
            kernel_coupled: request.kernel_coupled,
        },
    })
}

/// Decodes and validates one hostile source-acquisition release effect body.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed or oversized bytes,
/// unknown fields, invalid exact Mount 2.0 header or fence, or sentinel row
/// identity, revision, or digest fields.
pub fn decode_release_mount_source_acquisition_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<LiveValidatedReleaseMountSourceAcquisitionRequest, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ReleaseMountSourceAcquisitionRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
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
    let fence = validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    if request.expected_revision == 0 {
        return Err(ProtocolValidationError::InvalidField("expected_revision"));
    }
    Ok(LiveValidatedReleaseMountSourceAcquisitionRequest {
        request: ValidatedReleaseMountSourceAcquisitionRequest {
            header,
            fence,
            acquisition_id: ObjectDigest::from_bytes(exact_nonzero::<32>(
                &request.acquisition_id,
                "acquisition_id",
            )?),
            expected_revision: request.expected_revision,
            expected_record_digest: ObjectDigest::from_bytes(exact_nonzero::<32>(
                &request.expected_record_digest,
                "expected_record_digest",
            )?),
            request_digest: mount_source_acquisition_request_digest_v1(bytes),
        },
    })
}

/// Decodes an acquisition-inventory request header.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed bytes, unknown fields, or
/// an invalid exact Mount 2.0 request header.
pub fn decode_mount_source_acquisition_inventory_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = InventoryMountSourceAcquisitionsRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::MountBroker,
        now_boottime_nanoseconds,
    )
}

/// Decodes one exact source-acquisition effect response record.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed bytes, unknown fields, or
/// an invalid record/presence shape.
pub fn decode_acquire_mount_source_response(
    bytes: &[u8],
    request: &ValidatedAcquireMountSourceRequest,
) -> Result<ValidatedMountSourceAcquisitionRecord, ProtocolValidationError> {
    if bytes.len() > request.header().maximum_response_bytes() as usize {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = AcquireMountSourceResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let record = validate_inventory_record(
        response
            .record
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("record"))?,
    )?;
    if record.acquisition_id() != request.acquisition_id().as_bytes()
        || record.acquire_operation_id() != request.header().request_id()
        || record.acquire_request_digest() != request.request_digest().as_bytes()
        || record.wire_record().prospective_mount_template_digest
            != request.prospective_mount_template_digest().as_bytes()
        || record.wire_record().source_binding_digest
            != request.source_binding().digest().as_bytes()
        || record.namespace_generation() != request.prospective_namespace_generation()
        || !record_matches_fence(&record, request.fence())
        || !record_proof_matches_binding(&record, request.source_binding())
    {
        return Err(ProtocolValidationError::InvalidField(
            "Acquire response correlation",
        ));
    }
    Ok(record)
}

/// Decodes one exact source-acquisition release response record.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed bytes, unknown fields, or
/// an invalid record/presence shape.
pub fn decode_release_mount_source_acquisition_response(
    bytes: &[u8],
    request: &ValidatedReleaseMountSourceAcquisitionRequest,
) -> Result<ValidatedMountSourceAcquisitionRecord, ProtocolValidationError> {
    if bytes.len() > request.header().maximum_response_bytes() as usize {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = ReleaseMountSourceAcquisitionResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let record = validate_inventory_record(
        response
            .record
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("record"))?,
    )?;
    if record.acquisition_id() != request.acquisition_id().as_bytes()
        || record.release_operation_id() != Some(request.header().request_id())
        || record.release_request_digest() != Some(request.request_digest().as_bytes())
        || record.revision() <= request.expected_revision()
        || !release_fence_dominates_record(&record, request.fence())
        || !matches!(
            record.phase(),
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
        )
    {
        return Err(ProtocolValidationError::InvalidField(
            "Release response correlation",
        ));
    }
    Ok(record)
}

/// Decodes one bounded, strictly ordered acquisition inventory.
///
/// This authenticates the AOSMSA02 evidence shape and exact row correlation,
/// but not the broker response syscall writer. Production currentness still
/// requires Broker Session Authentication and deployment confinement.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed or oversized bytes,
/// unknown fields, sentinel snapshot identities, unordered/duplicate rows, or
/// a phase-inexact acquisition record.
pub fn decode_mount_source_acquisition_inventory_response(
    bytes: &[u8],
    request: &ValidatedHeader,
) -> Result<ValidatedMountSourceAcquisitionInventory, ProtocolValidationError> {
    if bytes.len() > request.maximum_response_bytes() as usize {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = InventoryMountSourceAcquisitionsResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if response.acquisitions.len() > MAXIMUM_MOUNT_SOURCE_ACQUISITION_RECORDS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "source acquisitions",
            maximum: MAXIMUM_MOUNT_SOURCE_ACQUISITION_RECORDS,
        });
    }
    if response.journal_sequence == 0 {
        return Err(ProtocolValidationError::InvalidField("journal_sequence"));
    }
    let kernel_boot_id = exact_nonzero::<16>(&response.kernel_boot_id, "kernel_boot_id")?;
    let broker_instance_id =
        exact_nonzero::<16>(&response.broker_instance_id, "broker_instance_id")?;
    let acquisitions = response
        .acquisitions
        .iter()
        .map(validate_inventory_record)
        .collect::<Result<Vec<_>, _>>()?;
    if acquisitions
        .windows(2)
        .any(|rows| rows[0].acquisition_id >= rows[1].acquisition_id)
    {
        return Err(ProtocolValidationError::InvalidField(
            "source acquisition inventory order",
        ));
    }
    validate_inventory_relations(&response.acquisitions, kernel_boot_id)?;
    Ok(ValidatedMountSourceAcquisitionInventory {
        kernel_boot_id,
        journal_sequence: response.journal_sequence,
        acquisitions,
        broker_instance_id,
    })
}

fn validate_inventory_relations(
    rows: &[MountSourceAcquisitionRecord],
    kernel_boot_id: [u8; 16],
) -> Result<(), ProtocolValidationError> {
    let mut physical = BTreeMap::<([u8; 16], u64, u64), Vec<u8>>::new();
    let mut unique_mounts = BTreeMap::<([u8; 16], u64), (u64, u64)>::new();
    let mut handles = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut route_generations = BTreeMap::<(Vec<u8>, u64), Vec<u8>>::new();
    let mut route_scopes = BTreeMap::<Vec<u8>, (Vec<u8>, Vec<u8>)>::new();
    let mut authority_generations = BTreeMap::<(Vec<u8>, u64), Vec<u8>>::new();
    let mut key_generations = BTreeMap::<(Vec<u8>, u64), (Vec<u8>, Vec<u8>)>::new();
    let mut resource_generations = BTreeMap::<(Vec<u8>, Vec<u8>, u64), (Vec<u8>, Vec<u8>)>::new();
    let mut catalog_generations = BTreeMap::<(Vec<u8>, u64), Vec<u8>>::new();
    let mut selection_generations = BTreeMap::<(Vec<u8>, u64), Vec<u8>>::new();
    let mut selection_targets = BTreeMap::<(Vec<u8>, u64, Vec<u8>), (Vec<u8>, Vec<u8>)>::new();
    let mut provider_history = Vec::new();
    let mut operation_ids = std::collections::BTreeSet::new();

    for row in rows {
        let acquire_operation_id = row
            .acquire
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("acquire"))?
            .operation_id
            .clone();
        if !operation_ids.insert(acquire_operation_id)
            || row
                .release
                .as_option()
                .is_some_and(|release| !operation_ids.insert(release.operation_id.clone()))
        {
            return Err(ProtocolValidationError::InvalidField(
                "source acquisition operation ID uniqueness",
            ));
        }
        insert_equal(
            &mut route_generations,
            (row.provider_route_id.clone(), row.provider_route_generation),
            row.provider_route_digest.clone(),
            "provider route generation equivocation",
        )?;
        insert_equal(
            &mut route_scopes,
            row.provider_route_id.clone(),
            (
                row.provider_authority_id.clone(),
                row.resource_namespace_digest.clone(),
            ),
            "provider route scope equivocation",
        )?;
        insert_equal(
            &mut authority_generations,
            (
                row.provider_authority_id.clone(),
                row.provider_authority_generation,
            ),
            row.provider_authority_digest.clone(),
            "provider authority generation equivocation",
        )?;
        insert_equal(
            &mut key_generations,
            (
                row.provider_authority_id.clone(),
                row.provider_key_generation,
            ),
            (
                row.provider_key_id.clone(),
                row.provider_public_key_digest.clone(),
            ),
            "provider key generation equivocation",
        )?;
        if !resource_group_is_present(row) {
            continue;
        }
        let phase = row
            .phase
            .as_known()
            .ok_or(ProtocolValidationError::InvalidField(
                "source acquisition phase",
            ))?;
        let is_live = phase != MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED;
        if is_live && row.source_kernel_boot_id != kernel_boot_id {
            return Err(ProtocolValidationError::InvalidField(
                "source acquisition snapshot boot",
            ));
        }
        let (Some(device), Some(inode), Some(unique_mount_id)) = (
            row.source_device,
            row.source_inode,
            row.source_unique_mount_id,
        ) else {
            return Err(ProtocolValidationError::InvalidField(
                "source acquisition physical identity",
            ));
        };
        let source_boot_id =
            exact_nonzero::<16>(&row.source_kernel_boot_id, "source_kernel_boot_id")?;
        if is_live {
            insert_equal(
                &mut physical,
                (source_boot_id, device, inode),
                row.source_realization_handle.clone(),
                "source acquisition physical alias",
            )?;
            insert_equal(
                &mut unique_mounts,
                (source_boot_id, unique_mount_id),
                (device, inode),
                "source acquisition unique mount alias",
            )?;
        }
        let evidence_digest = acquisition_evidence_digest(row);
        insert_equal(
            &mut handles,
            row.source_realization_handle.clone(),
            evidence_digest,
            "source realization evidence equivocation",
        )?;
        insert_equal(
            &mut resource_generations,
            (
                row.provider_authority_id.clone(),
                row.provider_resource_id.clone(),
                row.provider_resource_generation,
            ),
            (
                row.provider_resource_digest.clone(),
                row.provider_proof_digest.clone(),
            ),
            "provider resource generation equivocation",
        )?;
        insert_equal(
            &mut catalog_generations,
            (
                row.provider_authority_id.clone(),
                row.provider_catalog_generation,
            ),
            row.provider_catalog_digest.clone(),
            "provider catalog generation equivocation",
        )?;
        insert_equal(
            &mut selection_generations,
            (
                row.provider_route_id.clone(),
                row.provider_selection_generation,
            ),
            row.provider_selection_digest.clone(),
            "provider selection generation equivocation",
        )?;
        insert_equal(
            &mut selection_targets,
            (
                row.provider_route_id.clone(),
                row.provider_selection_generation,
                row.provider_selection_digest.clone(),
            ),
            (
                row.provider_resource_id.clone(),
                row.provider_resource_digest.clone(),
            ),
            "provider selection target equivocation",
        )?;
        provider_history.push(crate::MountSourceProviderHistoryV1 {
            authority_id: exact_nonzero::<16>(&row.provider_authority_id, "provider_authority_id")?,
            authority_generation: row.provider_authority_generation,
            authority_digest: exact_nonzero::<32>(
                &row.provider_authority_digest,
                "provider_authority_digest",
            )?,
            resource_id: exact_nonzero::<32>(&row.provider_resource_id, "provider_resource_id")?,
            resource_generation: row.provider_resource_generation,
            resource_digest: exact_nonzero::<32>(
                &row.provider_resource_digest,
                "provider_resource_digest",
            )?,
            catalog_generation: row.provider_catalog_generation,
            catalog_digest: exact_nonzero::<32>(
                &row.provider_catalog_digest,
                "provider_catalog_digest",
            )?,
            physical_proof_digest: exact_nonzero::<32>(
                &row.source_physical_proof_digest,
                "source_physical_proof_digest",
            )?,
        });
    }
    if !crate::mount_source_provider_history_is_valid_v1(&provider_history) {
        return Err(ProtocolValidationError::InvalidField(
            "source acquisition provider history",
        ));
    }
    Ok(())
}

fn insert_equal<K: Ord, V: Eq>(
    values: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    field: &'static str,
) -> Result<(), ProtocolValidationError> {
    match values.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(value);
        }
        std::collections::btree_map::Entry::Occupied(entry) if entry.get() != &value => {
            return Err(ProtocolValidationError::InvalidField(field));
        }
        std::collections::btree_map::Entry::Occupied(_) => {}
    }
    Ok(())
}

fn acquisition_evidence_digest(row: &MountSourceAcquisitionRecord) -> Vec<u8> {
    let mut digest = Sha256::new();
    for bytes in [
        &row.provider_authority_digest,
        &row.provider_resource_id,
        &row.provider_resource_digest,
        &row.provider_catalog_digest,
        &row.provider_selection_digest,
        &row.provider_proof_digest,
        &row.signed_lease_digest,
        &row.source_physical_proof_digest,
        &row.descriptor_commitment,
    ] {
        digest.update(bytes);
    }
    digest.update(row.provider_resource_generation.to_be_bytes());
    digest.update(row.provider_catalog_generation.to_be_bytes());
    digest.update(row.provider_selection_generation.to_be_bytes());
    digest.update(row.source_device.unwrap_or_default().to_be_bytes());
    digest.update(row.source_inode.unwrap_or_default().to_be_bytes());
    digest.update(row.source_unique_mount_id.unwrap_or_default().to_be_bytes());
    digest.finalize().to_vec()
}

fn validate_inventory_record(
    record: &MountSourceAcquisitionRecord,
) -> Result<ValidatedMountSourceAcquisitionRecord, ProtocolValidationError> {
    if !record.__buffa_unknown_fields.is_empty() || record.revision == 0 {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let phase = record
        .phase
        .as_known()
        .filter(|phase| {
            *phase != MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_UNSPECIFIED
        })
        .ok_or(ProtocolValidationError::UnknownState)?;
    let acquire = record
        .acquire
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("acquire"))?;
    let assignment = record
        .assignment
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("assignment"))?;
    let fence = assignment
        .fence
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("assignment.fence"))?;
    if !acquire.__buffa_unknown_fields.is_empty()
        || !assignment.__buffa_unknown_fields.is_empty()
        || assignment.namespace_generation == 0
    {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let validated_fence = validate_fence(fence)?;
    let (release_operation_id, release_request_digest) = match record.release.as_option() {
        Some(release) if release.__buffa_unknown_fields.is_empty() => (
            Some(exact_nonzero::<16>(
                &release.operation_id,
                "release.operation_id",
            )?),
            Some(exact_nonzero::<32>(
                &release.request_digest,
                "release.request_digest",
            )?),
        ),
        Some(_) => return Err(ProtocolValidationError::UnknownFields),
        None => (None, None),
    };
    validate_record_presence(record, phase, release_operation_id.is_some())?;
    let acquire_operation_id = exact_nonzero::<16>(&acquire.operation_id, "acquire.operation_id")?;
    let acquire_request_digest =
        exact_nonzero::<32>(&acquire.request_digest, "acquire.request_digest")?;
    if !record_acquisition_id_is_exact(
        &record.acquisition_id,
        acquire_operation_id,
        acquire_request_digest,
    ) {
        return Err(ProtocolValidationError::InvalidField("acquisition_id"));
    }
    Ok(ValidatedMountSourceAcquisitionRecord {
        record: record.clone(),
        acquisition_id: exact_nonzero::<32>(&record.acquisition_id, "acquisition_id")?,
        revision: record.revision,
        phase,
        acquire_operation_id,
        acquire_request_digest,
        release_operation_id,
        release_request_digest,
        sandbox_id: *validated_fence.sandbox_id(),
        incarnation_id: *validated_fence.incarnation_id(),
        assignment_epoch: validated_fence.assignment_epoch(),
        desired_generation: validated_fence.desired_generation(),
        assignment_digest: *validated_fence.assignment_digest(),
        namespace_generation: assignment.namespace_generation,
        record_digest: exact_nonzero::<32>(&record.record_digest, "record_digest")?,
    })
}

fn validate_record_presence(
    record: &MountSourceAcquisitionRecord,
    phase: MountSourceAcquisitionPhase,
    has_release: bool,
) -> Result<(), ProtocolValidationError> {
    for (bytes, field) in [
        (
            &record.prospective_mount_template_digest,
            "prospective_mount_template_digest",
        ),
        (&record.source_binding_digest, "source_binding_digest"),
        (&record.provider_route_digest, "provider_route_digest"),
        (
            &record.provider_authority_digest,
            "provider_authority_digest",
        ),
        (
            &record.provider_public_key_digest,
            "provider_public_key_digest",
        ),
        (
            &record.resource_namespace_digest,
            "resource_namespace_digest",
        ),
        (
            &record.provider_acquire_request_digest,
            "provider_acquire_request_digest",
        ),
    ] {
        exact_nonzero::<32>(bytes, field)?;
    }
    exact_nonzero::<16>(&record.provider_route_id, "provider_route_id")?;
    exact_nonzero::<16>(&record.provider_authority_id, "provider_authority_id")?;
    exact_nonzero::<16>(&record.provider_key_id, "provider_key_id")?;
    if record.provider_route_generation == 0
        || record.provider_authority_generation == 0
        || record.provider_key_generation == 0
    {
        return Err(ProtocolValidationError::InvalidField("provider generation"));
    }
    let faulted = phase == MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED;
    let effective_phase = match record.fault.as_option() {
        Some(fault) => {
            let from = fault.from.as_known().filter(|from| {
                *from != MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_UNSPECIFIED
                    && *from
                        != MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
                    && *from != MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
                    && *from != MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
            });
            if !fault.__buffa_unknown_fields.is_empty()
                || !(faulted
                    || matches!(
                        phase,
                        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
                            | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
                    ))
                || from.is_none()
                || exact_nonzero::<32>(&fault.failure_digest, "fault.failure_digest").is_err()
            {
                return Err(ProtocolValidationError::InvalidField("fault"));
            }
            let from = from.ok_or(ProtocolValidationError::UnknownState)?;
            if faulted { from } else { phase }
        }
        None if faulted => return Err(ProtocolValidationError::MissingField("fault")),
        None => phase,
    };
    let requires_release = matches!(
        effective_phase,
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
            | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
    );
    if has_release != requires_release {
        return Err(ProtocolValidationError::InvalidField("release correlation"));
    }
    let has_resource = resource_group_is_present(record);
    let requires_resource = matches!(
        effective_phase,
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED
            | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE
            | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
            | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
            | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
    );
    if requires_resource && !has_resource {
        return Err(ProtocolValidationError::InvalidField(
            "provider resource presence",
        ));
    }
    if has_resource {
        validate_complete_resource_group(record)?;
    } else if !resource_group_is_empty(record) {
        return Err(ProtocolValidationError::InvalidField(
            "partial provider resource evidence",
        ));
    }
    let has_acquire_status = !record.provider_acquire_status_digest.is_empty();
    if has_acquire_status {
        exact_nonzero::<32>(
            &record.provider_acquire_status_digest,
            "provider_acquire_status_digest",
        )?;
    }
    let acquire_status_required = has_resource
        || effective_phase
            != MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY;
    if acquire_status_required && !has_acquire_status {
        return Err(ProtocolValidationError::InvalidField(
            "provider Acquire status presence",
        ));
    }
    let has_release_request = !record.provider_release_request_digest.is_empty();
    let has_release_status = !record.provider_release_status_digest.is_empty();
    let has_inventory = !record.provider_inventory_digest.is_empty();
    for (present, bytes, field) in [
        (
            has_release_request,
            &record.provider_release_request_digest,
            "provider_release_request_digest",
        ),
        (
            has_release_status,
            &record.provider_release_status_digest,
            "provider_release_status_digest",
        ),
        (
            has_inventory,
            &record.provider_inventory_digest,
            "provider_inventory_digest",
        ),
    ] {
        if present {
            exact_nonzero::<32>(bytes, field)?;
        }
    }
    if has_release_request != requires_release
        || !requires_release
            && (has_release_status || has_inventory || record.release_generation != 0)
        || !has_release_status && record.release_generation != 0
    {
        return Err(ProtocolValidationError::InvalidField(
            "provider Release evidence presence",
        ));
    }
    if effective_phase == MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
        && !(has_release_status && record.release_generation != 0 || has_inventory)
    {
        return Err(ProtocolValidationError::InvalidField(
            "provider terminal evidence",
        ));
    }
    Ok(())
}

fn resource_group_is_present(record: &MountSourceAcquisitionRecord) -> bool {
    !record.provider_resource_id.is_empty()
}

fn resource_group_is_empty(record: &MountSourceAcquisitionRecord) -> bool {
    record.provider_resource_id.is_empty()
        && record.provider_resource_generation == 0
        && record.provider_resource_digest.is_empty()
        && record.provider_catalog_generation == 0
        && record.provider_catalog_digest.is_empty()
        && record.provider_selection_generation == 0
        && record.provider_selection_digest.is_empty()
        && record.proof_class.as_known()
            == Some(
                aos_proto::aos::sandbox::local::v1::MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_UNSPECIFIED,
            )
        && record.provider_proof_digest.is_empty()
        && record.lease_id.is_empty()
        && record.signed_lease_digest.is_empty()
        && record.lease_issued_seconds == 0
        && record.lease_expires_seconds == 0
        && record.source_realization_handle.is_empty()
        && record.source_physical_proof_digest.is_empty()
        && record.source_kernel_boot_id.is_empty()
        && record.source_device.is_none()
        && record.source_inode.is_none()
        && record.source_unique_mount_id.is_none()
        && record.descriptor_commitment.is_empty()
}

fn validate_complete_resource_group(
    record: &MountSourceAcquisitionRecord,
) -> Result<(), ProtocolValidationError> {
    for (bytes, field) in [
        (&record.provider_resource_id, "provider_resource_id"),
        (&record.provider_resource_digest, "provider_resource_digest"),
        (&record.provider_catalog_digest, "provider_catalog_digest"),
        (
            &record.provider_selection_digest,
            "provider_selection_digest",
        ),
        (&record.provider_proof_digest, "provider_proof_digest"),
        (&record.signed_lease_digest, "signed_lease_digest"),
        (
            &record.source_realization_handle,
            "source_realization_handle",
        ),
        (
            &record.source_physical_proof_digest,
            "source_physical_proof_digest",
        ),
        (&record.descriptor_commitment, "descriptor_commitment"),
    ] {
        exact_nonzero::<32>(bytes, field)?;
    }
    exact_nonzero::<16>(&record.lease_id, "lease_id")?;
    exact_nonzero::<16>(&record.source_kernel_boot_id, "source_kernel_boot_id")?;
    if record.provider_resource_generation == 0
        || record.provider_catalog_generation == 0
        || record.provider_selection_generation == 0
        || record.lease_issued_seconds < 0
        || record.lease_expires_seconds <= record.lease_issued_seconds
        || record.source_device.is_none_or(|value| value == 0)
        || record.source_inode.is_none_or(|value| value == 0)
        || record.source_unique_mount_id.is_none_or(|value| value == 0)
        || record.proof_class.as_known().is_none_or(|value| {
            value
                == aos_proto::aos::sandbox::local::v1::MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_UNSPECIFIED
        })
    {
        return Err(ProtocolValidationError::InvalidField(
            "provider resource evidence",
        ));
    }
    let proof_class = match record.proof_class.as_known() {
        Some(MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE) => {
            crate::MountSourceProofClassV1::ImmutableTree
        }
        Some(MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE) => {
            crate::MountSourceProofClassV1::LocalLive
        }
        Some(MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA) => {
            crate::MountSourceProofClassV1::BestEffortReplica
        }
        _ => {
            return Err(ProtocolValidationError::InvalidField(
                "provider resource evidence",
            ));
        }
    };
    let binding_digest =
        exact_nonzero::<32>(&record.source_binding_digest, "source_binding_digest")?;
    let physical_proof =
        crate::mount_source_physical_proof_digest_v1(crate::MountSourcePhysicalProofV1 {
            binding_digest,
            proof_class,
            provider_authority_id: exact_nonzero::<16>(
                &record.provider_authority_id,
                "provider_authority_id",
            )?,
            provider_authority_generation: record.provider_authority_generation,
            provider_authority_digest: exact_nonzero::<32>(
                &record.provider_authority_digest,
                "provider_authority_digest",
            )?,
            provider_resource_id: exact_nonzero::<32>(
                &record.provider_resource_id,
                "provider_resource_id",
            )?,
            provider_resource_generation: record.provider_resource_generation,
            provider_resource_digest: exact_nonzero::<32>(
                &record.provider_resource_digest,
                "provider_resource_digest",
            )?,
            provider_catalog_generation: record.provider_catalog_generation,
            provider_catalog_digest: exact_nonzero::<32>(
                &record.provider_catalog_digest,
                "provider_catalog_digest",
            )?,
            kernel_boot_id: exact_nonzero::<16>(
                &record.source_kernel_boot_id,
                "source_kernel_boot_id",
            )?,
            device: record.source_device.unwrap_or_default(),
            inode: record.source_inode.unwrap_or_default(),
            unique_mount_id: record.source_unique_mount_id.unwrap_or_default(),
        });
    let source_root = SourceRootObservationV1::new(
        exact_nonzero::<16>(&record.source_kernel_boot_id, "source_kernel_boot_id")?,
        record.source_device.unwrap_or_default(),
        record.source_inode.unwrap_or_default(),
        record.source_unique_mount_id.unwrap_or_default(),
        true,
        true,
        true,
    )
    .map_err(|_| ProtocolValidationError::InvalidField("descriptor_commitment"))?;
    let descriptor_commitment = source_root_descriptor_commitment_v1(&source_root);
    if record.source_physical_proof_digest != physical_proof
        || record.source_realization_handle
            != crate::mount_source_realization_handle_v1(binding_digest, physical_proof)
        || record.descriptor_commitment != descriptor_commitment.as_bytes()
    {
        return Err(ProtocolValidationError::InvalidField(
            "source realization evidence",
        ));
    }
    Ok(())
}

fn validate_prospective_create(
    bytes: &[u8],
    fence: &ValidatedAssignmentFence,
    binding: &SourceRealizationBindingV1,
    requested_maximum_submounts: u32,
    kernel_coupled: bool,
) -> Result<bool, ProtocolValidationError> {
    let fields = decode_semantic_fields(bytes)?;
    let expected_descriptor = encode_descriptor(binding);
    let expected_source = encode_view_source(binding.source());
    let expected_incarnation = binding
        .source_incarnation_id()
        .map_or(&[][..], <[u8; 16]>::as_slice);
    let recursive = fields[14].get(5).copied();
    let attributes_are_canonical = fields[14].len() == 7
        && fields[14][..6].iter().all(|value| *value <= 1)
        && fields[14][2] == 1
        && fields[14][3] == 1
        && fields[14][6] <= 4
        && (fields[14][0] == 1) == (fields[14][6] == 0);

    if fields[0].as_slice() != MOUNT_SEMANTICS_MAGIC
        || fields[1].as_slice() != MOUNT_SEMANTICS_VERSION.to_be_bytes()
        || fields[2].as_slice() != [1]
        || fields[3].as_slice() != fence.sandbox_id()
        || fields[4].as_slice() != fence.incarnation_id()
        || fields[5].as_slice() != fence.assignment_epoch().to_be_bytes()
        || fields[6].as_slice() != fence.desired_generation().to_be_bytes()
        || fields[7].as_slice() != fence.assignment_digest()
        || fields[10].as_slice() != binding.source_view_revision().to_be_bytes()
        || !fields[12].is_empty()
        || fields[13] != expected_descriptor
        || !attributes_are_canonical
        || !fields[15].is_empty()
        || !fields[16].is_empty()
        || fields[17].as_slice() != [0, 0]
        || fields[18].as_slice() != fields[19].as_slice()
        || fields[20].as_slice() != binding.source_view_id()
        || fields[21].as_slice() != expected_incarnation
        || fields[22].as_slice() != [source_consistency_code(binding.consistency())]
        || fields[26] != expected_source
        || recursive.is_none_or(|value| value > 1)
        || (recursive == Some(0) && requested_maximum_submounts != 0)
        || kernel_coupled
            != (binding.consistency()
                == aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE)
    {
        return Err(ProtocolValidationError::InvalidField(
            "prospective_mount_template cross-link",
        ));
    }
    for index in [8, 9, 23] {
        if fields[index].len() != 16 || fields[index].iter().all(|byte| *byte == 0) {
            return Err(ProtocolValidationError::InvalidField(
                "prospective_mount_template identity",
            ));
        }
    }
    for index in [11, 18, 19] {
        if decode_u64(&fields[index])? == 0 {
            return Err(ProtocolValidationError::InvalidField(
                "prospective_mount_template generation",
            ));
        }
    }
    let issued = decode_i64(&fields[24])?;
    let expires = decode_i64(&fields[25])?;
    if expires <= issued {
        return Err(ProtocolValidationError::InvalidField(
            "prospective_mount_template lease",
        ));
    }
    Ok(recursive == Some(1))
}

fn decode_semantic_fields(
    bytes: &[u8],
) -> Result<[Vec<u8>; MOUNT_SEMANTICS_FIELDS], ProtocolValidationError> {
    let mut fields: [Vec<u8>; MOUNT_SEMANTICS_FIELDS] = std::array::from_fn(|_| Vec::new());
    let mut cursor = 0usize;
    for (index, field) in fields.iter_mut().enumerate() {
        let expected_tag = u8::try_from(index + 1)
            .map_err(|_| ProtocolValidationError::InvalidField("prospective_mount_template"))?;
        if bytes.get(cursor).copied() != Some(expected_tag) {
            return Err(ProtocolValidationError::InvalidField(
                "prospective_mount_template",
            ));
        }
        cursor = cursor
            .checked_add(1)
            .ok_or(ProtocolValidationError::InvalidField(
                "prospective_mount_template",
            ))?;
        let length_bytes =
            bytes
                .get(cursor..cursor + 4)
                .ok_or(ProtocolValidationError::InvalidField(
                    "prospective_mount_template",
                ))?;
        let length =
            usize::try_from(u32::from_be_bytes(length_bytes.try_into().map_err(
                |_| ProtocolValidationError::InvalidField("prospective_mount_template"),
            )?))
            .map_err(|_| ProtocolValidationError::InvalidField("prospective_mount_template"))?;
        cursor += 4;
        let end = cursor
            .checked_add(length)
            .ok_or(ProtocolValidationError::InvalidField(
                "prospective_mount_template",
            ))?;
        *field = bytes
            .get(cursor..end)
            .ok_or(ProtocolValidationError::InvalidField(
                "prospective_mount_template",
            ))?
            .to_vec();
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(ProtocolValidationError::InvalidField(
            "prospective_mount_template",
        ));
    }
    Ok(fields)
}

fn encode_descriptor(binding: &SourceRealizationBindingV1) -> Vec<u8> {
    let descriptor = binding.view_descriptor();
    let media = descriptor.media_type().as_str().as_bytes();
    let mut bytes = Vec::with_capacity(2 + media.len() + 40);
    bytes.extend_from_slice(&u16::try_from(media.len()).unwrap_or(u16::MAX).to_be_bytes());
    bytes.extend_from_slice(media);
    bytes.extend_from_slice(descriptor.digest().as_bytes());
    bytes.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
    bytes
}

fn decode_u64(bytes: &[u8]) -> Result<u64, ProtocolValidationError> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| ProtocolValidationError::InvalidField("prospective_mount_template integer"))
}

fn decode_i64(bytes: &[u8]) -> Result<i64, ProtocolValidationError> {
    bytes
        .try_into()
        .map(i64::from_be_bytes)
        .map_err(|_| ProtocolValidationError::InvalidField("prospective_mount_template integer"))
}

const fn source_consistency_code(
    consistency: aos_proto::aos::sandbox::local::v1::MountSourceConsistency,
) -> u8 {
    use aos_proto::aos::sandbox::local::v1::MountSourceConsistency;

    match consistency {
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => 1,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE => 2,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_TRANSACTIONAL_SERVICE => 3,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => 4,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_UNSPECIFIED => 0,
    }
}
