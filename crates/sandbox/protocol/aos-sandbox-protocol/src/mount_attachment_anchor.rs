//! Canonical no-slot ownership of Mount's payload attachment namespace.
//!
//! Empty portable attachment declarations still need a real, pinned namespace
//! directory. This DATA codec contains no path, descriptor, native receiver or
//! writer constructor. The actual Mount role separately authenticates, pays,
//! durably admits and retains every effect before publishing inventory.
//!
//! ```text
//! request = header + current fence + action + namespace-generation + exact Spec
//! reap    = request + original creation fence + exact Ready resource digest
//! record  = AOSMNA01 + canonical resource protobuf with a domain-separated digest
//! ```

use aos_sandbox_api::aos::sandbox::local::v1::{
    ApplyAttachmentAnchorRequestV1, ApplyAttachmentAnchorResponseV1,
    AssignmentFence, AttachmentAnchorActionV1, AttachmentAnchorResourceRecordV1,
    Descriptor, RequestHeader,
};
use aos_sandbox_model::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb,
    ObjectDescriptor, ProtocolId,
};
use buffa::Message as _;

use crate::{PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedAssignmentFence,
    ValidatedHeader, MAXIMUM_REQUEST_BYTES, exact_nonzero, validate_fence, validate_request_header};
use crate::mount_destination_slot::{resource_fence_precedes, validate_destination_specification_v1};

mod resource;
mod delete_reap;
pub use delete_reap::prepare_delete_mount_reap_request_data_v4;
pub use resource::{ValidatedAttachmentAnchorResourceV1,
    decode_attachment_anchor_resource_v1, encode_attachment_anchor_resource_v1,
    seal_attachment_anchor_resource_v1, validate_attachment_anchor_resource_v1,
    MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1};

/// Carries one canonical no-slot namespace request without native authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAttachmentAnchorRequestV1 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    resource_fence: Option<ValidatedAssignmentFence>,
    action: AttachmentAnchorActionV1,
    namespace_generation: u64,
    sandbox_spec: ObjectDescriptor,
    specification: aos_sandbox_model::model::SandboxSpec,
    expected_resource_digest: Option<[u8; 32]>,
}

impl ValidatedAttachmentAnchorRequestV1 {
    /// Encodes the same canonical request with an unarmed zero deadline.
    ///
    /// # Errors
    /// Refuses a zero request identity. Native admission is separately required
    /// before a real signed request may acquire a live absolute deadline.
    pub fn deadline_free_request_body_v1(&self, request_id: [u8; 16])
        -> Result<Vec<u8>, ProtocolValidationError> {
        if request_id == [0; 16] { return Err(ProtocolValidationError::InvalidField("request_id")); }
        let version = self.header.protocol_version();
        Ok(ApplyAttachmentAnchorRequestV1 {
            header: Some(RequestHeader {
                protocol_major: u32::from(version.major()), protocol_minor: u32::from(version.minor()),
                request_id: request_id.to_vec(), audience: self.header.audience().into(),
                deadline_boottime_nanoseconds: 0,
                maximum_response_bytes: self.header.maximum_response_bytes(),
                ..Default::default()
            }).into(),
            fence: Some(wire_fence(&self.fence)).into(), action: self.action.into(),
            namespace_generation: self.namespace_generation,
            sandbox_spec: Some(wire_descriptor(&self.sandbox_spec)).into(),
            sandbox_spec_bytes: aos_sandbox_model::encode_sandbox_spec(&self.specification),
            expected_resource_digest: self.expected_resource_digest.map_or_else(Vec::new, |digest| digest.to_vec()),
            resource_fence: self.resource_fence.as_ref().map(wire_fence).into(),
            ..Default::default()
        }.encode_to_vec())
    }

    /// Returns the validated transport coordinates.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader { &self.header }

    /// Returns the current assignment authorizing this operation.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence { &self.fence }

    /// Returns the immutable creation fence for retirement, when present.
    #[must_use]
    pub const fn resource_fence(&self) -> Option<&ValidatedAssignmentFence> {
        self.resource_fence.as_ref()
    }

    /// Returns the exact fence that owns the namespace resource.
    #[must_use]
    pub const fn binding_fence(&self) -> &ValidatedAssignmentFence {
        match self.resource_fence.as_ref() { Some(fence) => fence, None => &self.fence }
    }

    /// Returns the closed namespace action.
    #[must_use]
    pub const fn action(&self) -> AttachmentAnchorActionV1 { self.action }

    /// Returns the nonzero namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 { self.namespace_generation }

    /// Returns the exact canonical portable specification descriptor.
    #[must_use]
    pub const fn sandbox_spec(&self) -> &ObjectDescriptor { &self.sandbox_spec }

    /// Returns the complete validated specification, whose slots are empty.
    #[must_use]
    pub const fn specification(&self) -> &aos_sandbox_model::model::SandboxSpec {
        &self.specification
    }

    /// Returns the exact Ready digest admitted for retirement.
    #[must_use]
    pub const fn expected_resource_digest(&self) -> Option<&[u8; 32]> {
        self.expected_resource_digest.as_ref()
    }
}

/// Decodes one exact empty-attachment namespace effect.
///
/// # Errors
/// Refuses malformed or oversized protobufs, unknown fields/actions, foreign
/// request coordinates, a substituted or nonempty Spec, and an invalid reap
/// predecessor shape. It does not authenticate a signature or create custody.
pub fn decode_attachment_anchor_request_v1(
    bytes: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
) -> Result<ValidatedAttachmentAnchorRequestV1, ProtocolValidationError> {
    decode_attachment_anchor_request_inner_v2(bytes, AnchorHeaderInputV2::Peer(peer, policy), now)
}

// Comparison DATA validates the same canonical bytes without inventing a peer.
// Actual native callers retain their separate kernel credential prerequisite.
pub(crate) fn decode_attachment_anchor_request_data_v2(
    bytes: &[u8], audience: aos_sandbox_api::aos::sandbox::local::v1::Audience, now: u64,
) -> Result<ValidatedAttachmentAnchorRequestV1, ProtocolValidationError> {
    decode_attachment_anchor_request_inner_v2(bytes, AnchorHeaderInputV2::Data(audience), now)
}

enum AnchorHeaderInputV2 {
    Peer(PeerCredentials, PeerPolicy),
    Data(aos_sandbox_api::aos::sandbox::local::v1::Audience),
}

fn decode_attachment_anchor_request_inner_v2(
    bytes: &[u8], header_input: AnchorHeaderInputV2, now: u64,
) -> Result<ValidatedAttachmentAnchorRequestV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES { return Err(ProtocolValidationError::RequestTooLarge); }
    let request = ApplyAttachmentAnchorRequestV1::decode_from_slice(bytes)
        .map_err(|cause| ProtocolValidationError::MalformedWire(cause.to_string()))?;
    reject_unknown(&request.__buffa_unknown_fields)?;
    let raw_header = request.header.as_option().ok_or(ProtocolValidationError::MissingField("header"))?;
    let header = match header_input {
        AnchorHeaderInputV2::Peer(peer, policy) =>
            validate_request_header(raw_header, peer, policy, ProtocolId::MountBroker, now)?,
        AnchorHeaderInputV2::Data(audience) =>
            crate::validate_request_header_data_v2(raw_header, audience, ProtocolId::MountBroker, now)?,
    };
    let fence = validate_fence(request.fence.as_option()
        .ok_or(ProtocolValidationError::MissingField("fence"))?)?;
    let resource_fence = request.resource_fence.as_option().map(validate_fence).transpose()?;
    let action = request.action.as_known()
        .filter(|action| *action != AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_UNSPECIFIED)
        .ok_or(ProtocolValidationError::UnknownAction)?;
    if request.namespace_generation == 0 {
        return Err(ProtocolValidationError::InvalidField("namespace_generation"));
    }
    let (sandbox_spec, specification) = validate_destination_specification_v1(
        request.sandbox_spec.as_option().ok_or(ProtocolValidationError::MissingField("sandbox_spec"))?,
        &request.sandbox_spec_bytes,
    )?;
    if !specification.attachment_slots().is_empty() {
        return Err(ProtocolValidationError::InvalidField("namespace anchor requires empty attachment declaration"));
    }
    let expected_resource_digest = if request.expected_resource_digest.is_empty() { None }
        else { Some(exact_nonzero::<32>(&request.expected_resource_digest, "expected_resource_digest")?) };
    let valid = match action {
        AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_MATERIALIZE =>
            expected_resource_digest.is_none() && resource_fence.is_none(),
        AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP =>
            expected_resource_digest.is_some() && resource_fence.as_ref()
                .is_some_and(|original| resource_fence_precedes(&fence, original)),
        AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_UNSPECIFIED => false,
    };
    if !valid { return Err(ProtocolValidationError::InvalidField("namespace action predecessor")); }
    Ok(ValidatedAttachmentAnchorRequestV1 { header, fence, resource_fence, action,
        namespace_generation: request.namespace_generation, sandbox_spec, specification,
        expected_resource_digest })
}

/// Encodes the single request body used by Root normalization and Controller.
///
/// This is DATA construction only; the receiver still runs the sole hostile
/// decoder, signed admission, same-role funding and native currentness gates.
#[must_use]
pub fn attachment_anchor_request_body_v1(request: &ApplyAttachmentAnchorRequestV1) -> Vec<u8> {
    request.encode_to_vec()
}

/// Carries the exact portable grant tuple without a signature or effect grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalAttachmentAnchorSemanticsV1 {
    bytes: Vec<u8>,
    commitment: BrokerArgumentCommitment,
    verb: BrokerVerb,
    target: BrokerGrantTarget,
}

impl CanonicalAttachmentAnchorSemanticsV1 {
    /// Borrows the finite canonical portable representation.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] { &self.bytes }

    /// Returns the domain-separated argument commitment.
    #[must_use]
    pub const fn commitment(&self) -> BrokerArgumentCommitment { self.commitment }

    /// Returns the distinct namespace verb.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb { self.verb }

    /// Returns the assignment or exact predecessor resource target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget { self.target }
}

/// Normalizes the exact no-slot namespace grant for both Root and Mount.
///
/// # Errors
/// Refuses a malformed target or a finite canonical encoding overflow. No
/// portable bytes can establish native role currentness or replace Root signing.
pub fn canonical_attachment_anchor_semantics_v1(
    request: &ValidatedAttachmentAnchorRequestV1,
) -> Result<CanonicalAttachmentAnchorSemanticsV1,
    crate::semantics::destination_slot::DestinationSlotSemanticError> {
    use crate::semantics::destination_slot::{DestinationSlotSemanticError as E, Encoder};
    let (verb, target, code) = match request.action {
        AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_MATERIALIZE =>
            (BrokerVerb::MountMaterializeAttachmentAnchor, BrokerGrantTarget::Assignment, 1),
        AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP => {
            let digest = request.expected_resource_digest.ok_or(E::InvalidTarget)?;
            let handle = BrokerResourceHandle::from_bytes(digest).map_err(|_| E::InvalidTarget)?;
            (BrokerVerb::MountReapAttachmentAnchor, BrokerGrantTarget::Resource(handle), 2)
        }
        AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_UNSPECIFIED => return Err(E::InvalidTarget),
    };
    let mut encoder = Encoder::new();
    encoder.field(1, b"AOSNSEM1")?;
    encoder.field(2, &1_u16.to_be_bytes())?;
    encoder.field(3, &[code])?;
    encode_fence(&mut encoder, 4, request.fence())?;
    encoder.field(9, &request.namespace_generation.to_be_bytes())?;
    encoder.descriptor(10, request.sandbox_spec())?;
    encoder.field(11, request.expected_resource_digest().map_or(&[][..], <[u8;32]>::as_slice))?;
    encoder.field(12, &[u8::from(request.resource_fence.is_some())])?;
    if let Some(original) = request.resource_fence() { encode_fence(&mut encoder, 13, original)?; }
    let bytes = encoder.finish();
    Ok(CanonicalAttachmentAnchorSemanticsV1 {
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes), bytes, verb, target,
    })
}

fn encode_fence(
    encoder: &mut crate::semantics::destination_slot::Encoder, tag: u8,
    fence: &ValidatedAssignmentFence,
) -> Result<(), crate::semantics::destination_slot::DestinationSlotSemanticError> {
    encoder.field(tag, fence.sandbox_id())?;
    encoder.field(tag + 1, fence.incarnation_id())?;
    encoder.field(tag + 2, &fence.assignment_epoch().to_be_bytes())?;
    encoder.field(tag + 3, &fence.desired_generation().to_be_bytes())?;
    encoder.field(tag + 4, fence.assignment_digest())
}

/// Decodes the same actual native result without adopting a resource owner.
///
/// # Errors
/// Refuses malformed/trailing or unknown result data, wrong request/binding,
/// a changed operation digest, or a phase inconsistent with the requested verb.
pub fn validate_attachment_anchor_apply_response_v1(
    bytes: &[u8], maximum: u32, request: &ValidatedAttachmentAnchorRequestV1,
    exact_request_body: &[u8],
) -> Result<ValidatedAttachmentAnchorResourceV1, ProtocolValidationError> {
    if bytes.len() > maximum as usize { return Err(ProtocolValidationError::ResponseTooLarge); }
    let response = ApplyAttachmentAnchorResponseV1::decode_from_slice(bytes)
        .map_err(|cause| ProtocolValidationError::MalformedWire(cause.to_string()))?;
    reject_unknown(&response.__buffa_unknown_fields)?;
    let row = validate_attachment_anchor_resource_v1(response.resource.as_option()
        .ok_or(ProtocolValidationError::MissingField("resource"))?)?;
    row.require_request_v1(request, exact_request_body)?;
    Ok(row)
}

pub(crate) fn reject_unknown(fields: &buffa::UnknownFields) -> Result<(), ProtocolValidationError> {
    if !fields.is_empty() { return Err(ProtocolValidationError::InvalidField("unknown namespace fields")); }
    Ok(())
}

pub(crate) fn wire_fence(fence: &ValidatedAssignmentFence) -> AssignmentFence {
    AssignmentFence { sandbox_id: fence.sandbox_id().to_vec(), incarnation_id: fence.incarnation_id().to_vec(),
        assignment_epoch: fence.assignment_epoch(), desired_generation: fence.desired_generation(),
        assignment_digest: fence.assignment_digest().to_vec(), ..Default::default() }
}

pub(crate) fn wire_descriptor(descriptor: &ObjectDescriptor) -> Descriptor {
    Descriptor { media_type: descriptor.media_type().as_str().to_owned(),
        sha256: descriptor.digest().as_bytes().to_vec(), encoded_size: descriptor.encoded_size(),
        ..Default::default() }
}

#[cfg(test)]
mod tests;

/// Bounds complete protobuf and nested portable-Spec decoding before allocation.
///
/// The returned vector contains representation DATA only. The genuine Mount
/// receiving original must admit it before invoking the request decoder.
///
/// # Errors
/// Rejects an excessive body extent or checked representation overflow.
pub fn attachment_anchor_request_decoding_demand_v4(body_bytes: usize)
    -> Result<aos_sandbox_model::ResourceVector, ProtocolValidationError> {
    use aos_sandbox_model::{ResourceDimension, ResourceVector};
    use std::mem::size_of;
    let overflow = || ProtocolValidationError::InvalidField("attachment_anchor_decoding_geometry");
    if body_bytes > MAXIMUM_REQUEST_BYTES { return Err(ProtocolValidationError::RequestTooLarge); }

    let unknown = protobuf_unknown_decoding_memory_v4(body_bytes).ok_or_else(overflow)?;
    let known = size_of::<ApplyAttachmentAnchorRequestV1>()
        .checked_add(size_of::<RequestHeader>())
        .and_then(|bytes| bytes.checked_add(size_of::<AssignmentFence>().checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(size_of::<Descriptor>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ValidatedAttachmentAnchorRequestV1>()))
        .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(overflow)?;
    let specification = aos_sandbox_model::format::sandbox_spec_decoding_memory_bound_v4(
        body_bytes.min(crate::mount_destination_slot::MAXIMUM_DESTINATION_SLOT_SPEC_BYTES),
        crate::mount_destination_slot::sandbox_spec_decode_limits()).ok_or_else(overflow)?;
    // Raw protobuf byte/text ownership, canonical output old/new allocation,
    // and semantic byte copying are disjoint from the nested decoded Spec.
    let bytes = body_bytes.checked_mul(4).and_then(|bytes| bytes.checked_add(unknown))
        .and_then(|bytes| bytes.checked_add(known))
        .and_then(|bytes| bytes.checked_add(specification)).ok_or_else(overflow)?;
    Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes,
        u64::try_from(bytes).map_err(|_| overflow())?))
}

// Same concrete locals retained by recursive Buffa unknown/group decoding.
#[allow(dead_code)]
struct AttachmentAnchorUnknownFrameV4 {
    context: buffa::DecodeContext<'static>,
    tag: buffa::encoding::Tag,
    input: &'static [u8],
    group: buffa::UnknownFields,
    field: Result<buffa::UnknownField, buffa::DecodeError>,
    length: usize,
}

// Shared by the request and durable-resource decoders, whose Buffa recursion
// and unknown-field Vec engine is identical. No message is decoded here.
fn protobuf_unknown_decoding_memory_v4(input_bytes: usize) -> Option<usize> {
    use std::mem::size_of;
    // Every completed unknown field occupies at least tag+value. Four slots
    // per field dominate all nonempty Vec capacities, including nested groups.
    let unknown = (input_bytes / 2).min(buffa::DEFAULT_UNKNOWN_FIELD_LIMIT)
        .checked_mul(4)?.checked_mul(size_of::<buffa::UnknownField>())?;
    let depth = input_bytes.min(buffa::RECURSION_LIMIT as usize).checked_add(2)?;
    unknown.checked_add(depth.checked_mul(2)?.checked_mul(size_of::<AttachmentAnchorUnknownFrameV4>())?)
}

/// Bounds one complete durable namespace row's protobuf decode and typed model.
///
/// Includes bounded unknown-group recursion even for a malformed row; the
/// native startup owner pays this before parsing the protected table.
///
/// # Errors
/// Refuses an excessive row extent or checked representation overflow.
pub fn attachment_anchor_resource_decoding_memory_v4(input_bytes: usize)
    -> Result<usize, ProtocolValidationError> {
    use aos_sandbox_api::aos::sandbox::local::v1::{MountAssignmentBinding,
        MountOperationCorrelation, DestinationSlotReapCorrelation};
    use std::mem::size_of;
    let overflow = || ProtocolValidationError::InvalidField("attachment_anchor_resource_geometry");
    if input_bytes > MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let fixed = size_of::<AttachmentAnchorResourceRecordV1>()
        .checked_add(size_of::<MountAssignmentBinding>())
        .and_then(|bytes| bytes.checked_add(size_of::<MountOperationCorrelation>()))
        .and_then(|bytes| bytes.checked_add(size_of::<DestinationSlotReapCorrelation>()))
        .and_then(|bytes| bytes.checked_add(size_of::<Descriptor>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ValidatedAttachmentAnchorResourceV1>()))
        .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(overflow)?;
    protobuf_unknown_decoding_memory_v4(input_bytes)
        .and_then(|bytes| bytes.checked_add(fixed))
        // Current strings/bytes, typed copies and canonical output old/new.
        .and_then(|bytes| bytes.checked_add(input_bytes.checked_mul(4)?))
        .ok_or_else(overflow)
}
