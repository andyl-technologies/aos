//! Normalizes unsigned Start resource plans from exact original input DATA.
//!
//! Root and Controller independently authenticate their actual Start, policy,
//! assignment, fresh lease and clock before using this shared recipe. Neither
//! a parsed request nor successful plan preparation grants dispatch authority.
//! Native lenders and signed Session admission remain with their real owners.

mod mount;
mod storage;
pub use storage::{compare_historical_start_storage_guest_root_plan_v2, prepare_start_storage_guest_root_plan_v2,
    prepare_admitted_start_storage_guest_root_plan_v2};
pub use mount::{start_mount_request_body_data_v2, prepare_admitted_start_mount_plan_v2,
    start_mount_request_receiving_demand_v2, prepare_start_mount_plan_v2};

use std::error::Error;

use aos_proto::aos::sandbox::local::v1::{
    ApplyNetworkRequest, AssignmentFence, Audience, NetworkAction, RequestHeader,
};
use aos_sandbox_core::model::SandboxSpec;
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
    BrokerGrantTarget, BrokerVerb, CanonicalAssignmentManifestV1, DecodeLimits, FeatureRef,
    ObjectDigest, PortableMediaType, ProtocolId, ProtocolVersion, RawPairedClockSample,
    RevocationScopeId,
};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use buffa::Message as _;

use super::storage_create_plan::{plan_expiry_v1, require_admitted_clock_v1};
use super::{BrokerPlanPreparation, SigningAuthority};
use crate::dispatch_template::inject_deadline;
use crate::semantics::network::canonical_network_preparation_argument_v2;
use crate::semantics::network::preparation_content::{
    NetworkPreparationContentReferenceV2, NetworkPreparationContentV2,
    canonical_network_preparation_specification_v2,
};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug, thiserror::Error)]
#[error("the original Start Network request, scope or signed preparation changed")]
struct Changed;

/// Holds unsigned resource-plan DATA and the exact admitted request body.
pub struct StartResourcePlanPreparationDataV1 {
    /// Retains the canonical unsigned plan and exact public signing statement.
    pub preparation: BrokerPlanPreparation,
    /// Retains the original body with only its admitted deadline inserted.
    pub request_body: Vec<u8>,
    /// Retains exact header DATA from the same canonical request normalization.
    pub request_header: StartResourceRequestHeaderDataV2,
}

/// Carries normalized Network header DATA without a peer or dispatch grant.
///
/// The fields are copied from the sole canonical template decoder. The
/// deadline is the exact cutoff inserted by the existing request framer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartResourceRequestHeaderDataV2 {
    /// Identifies the original protocol major version.
    pub protocol_major: u32,
    /// Identifies the original protocol minor version.
    pub protocol_minor: u32,
    /// Identifies the exact known sender audience.
    pub audience: Audience,
    /// Identifies the original nonzero request.
    pub request_id: [u8; 16],
    /// Holds the absolute admitted request cutoff.
    pub deadline_boottime_nanoseconds: u64,
    /// Holds the exact original response-byte ceiling.
    pub maximum_response_bytes: u32,
}

/// Prepares the sole Network plan for the original Start acquisition interval.
///
/// The caller must fund complete input/model/encoding growth before entry.
/// This checks the full sealed manifest/specification bytes and exact endpoint
/// selection, then uses the same original-cutoff expiry recipe as Create.
/// It never changes a previous signed cap or supplies a fresh relative window.
///
/// # Errors
/// Rejects a noncanonical or non-Prepare body, changed originals, lease/fence
/// mismatch, expired original interval, or plan/signing-statement refusal.
#[allow(clippy::too_many_arguments)]
pub fn prepare_start_network_plan_v2(
    deadline_free_body: &[u8],
    sealed_content: &[u8],
    manifest: &CanonicalAssignmentManifestV1,
    specification: &SandboxSpec,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
) -> Result<StartResourcePlanPreparationDataV1> {
    let expires = plan_expiry_v1(
        sample,
        cutoff,
        policy_expires,
        lease.authority_expires_seconds(),
    )?;
    let (semantics, request_body, request_header) = network_inputs_v2(
        deadline_free_body,
        sealed_content,
        manifest,
        specification,
        lease,
        sample,
        cutoff,
    )?;
    let plan = network_plan_v2(
        &semantics,
        manifest,
        policy_digest,
        lease,
        sample.wall_seconds(),
        expires,
        revocation_scope,
        request_body.len(),
    )?;

    Ok(StartResourcePlanPreparationDataV1 {
        preparation: BrokerPlanPreparation::new(plan, authority)?,
        request_body,
        request_header,
    })
}

/// Reconstructs an admitted Network plan and exact signing statement once.
///
/// Only the genuine Root Network stage may lend the admitted artifacts to its
/// signer. This pure comparison cannot manufacture that loan from supplied
/// bytes. Root and Controller run the same request and grant normalizers.
///
/// # Errors
/// Rejects changed inputs, plan/statement bytes, validity, scope or authority.
#[allow(clippy::too_many_arguments)]
pub fn prepare_admitted_start_network_plan_v2(
    deadline_free_body: &[u8],
    sealed_content: &[u8],
    manifest: &CanonicalAssignmentManifestV1,
    specification: &SandboxSpec,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
    canonical_plan: &[u8],
    canonical_statement: &[u8],
) -> Result<StartResourcePlanPreparationDataV1> {
    let plan = aos_sandbox_core::format::decode_broker_authorization_plan(
        canonical_plan,
        DecodeLimits::default(),
    )?;
    require_admitted_clock_v1(
        sample,
        cutoff,
        plan.issued_seconds(),
        plan.expires_seconds(),
        lease.authority_issued_seconds(),
        lease.authority_expires_seconds(),
    )?;
    if plan.expires_seconds()
        > plan_expiry_v1(
            sample,
            cutoff,
            policy_expires,
            lease.authority_expires_seconds(),
        )?
    {
        return Err(Box::new(Changed));
    }
    let (semantics, request_body, request_header) = network_inputs_v2(
        deadline_free_body,
        sealed_content,
        manifest,
        specification,
        lease,
        sample,
        cutoff,
    )?;
    let expected = network_plan_v2(
        &semantics,
        manifest,
        policy_digest,
        lease,
        plan.issued_seconds(),
        plan.expires_seconds(),
        revocation_scope,
        request_body.len(),
    )?;
    if plan != expected {
        return Err(Box::new(Changed));
    }
    let preparation = BrokerPlanPreparation::new(plan, authority)?;
    if preparation.canonical_plan() != canonical_plan
        || preparation.signing_request().canonical_statement() != canonical_statement
    {
        return Err(Box::new(Changed));
    }

    Ok(StartResourcePlanPreparationDataV1 {
        preparation,
        request_body,
        request_header,
    })
}

#[allow(clippy::too_many_arguments)]
fn network_inputs_v2(
    deadline_free_body: &[u8],
    sealed_content: &[u8],
    manifest: &CanonicalAssignmentManifestV1,
    specification: &SandboxSpec,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
) -> Result<(BrokerArgumentCommitment, Vec<u8>, StartResourceRequestHeaderDataV2)> {
    if deadline_free_body.len() > crate::MAXIMUM_REQUEST_BYTES {
        return Err(Box::new(Changed));
    }
    // The canonical template permits no unknown fields. Refuse them before
    // materializing their trees, including unknown groups in either child.
    let request: ApplyNetworkRequest = buffa::DecodeOptions::new()
        .with_max_message_size(crate::MAXIMUM_REQUEST_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice(deadline_free_body)?;
    if request.encode_to_vec() != deadline_free_body
        || request
            .header
            .as_option()
            .ok_or(Changed)?
            .deadline_boottime_nanoseconds
            != 0
        || request.action.as_known() != Some(NetworkAction::NETWORK_ACTION_PREPARE)
    {
        return Err(Box::new(Changed));
    }
    let assignment = manifest.broker_assignment()?;
    require_resource_lease_v2(manifest, lease)?;
    let content = NetworkPreparationContentV2::decode(sealed_content)?;
    let specification_bytes =
        canonical_network_preparation_specification_v2(manifest, specification)?;
    if content.manifest_bytes() != manifest.canonical_bytes()
        || content.specification_bytes() != specification_bytes
    {
        return Err(Box::new(Changed));
    }

    let reference = NetworkPreparationContentReferenceV2::for_content(sealed_content)?;
    let request_id = crate::exact_nonzero::<16>(
        &request.header.as_option().ok_or(Changed)?.request_id,
        "request_id",
    )?;
    let endpoints = specification.network_profile().endpoint_ids();
    if reference.deadline_free_request_body_v2(assignment, request_id, endpoints)?
        != deadline_free_body
        || sample.boottime_nanoseconds() >= cutoff
    {
        return Err(Box::new(Changed));
    }
    let request_body = inject_deadline(deadline_free_body, cutoff)?;
    let commitment = canonical_network_preparation_argument_v2(assignment, endpoints, reference)?;
    let header = request.header.as_option().ok_or(Changed)?;
    let request_header = StartResourceRequestHeaderDataV2 {
        protocol_major: header.protocol_major,
        protocol_minor: header.protocol_minor,
        audience: header.audience.as_known().ok_or(Changed)?,
        request_id,
        deadline_boottime_nanoseconds: cutoff,
        maximum_response_bytes: header.maximum_response_bytes,
    };

    Ok((commitment, request_body, request_header))
}

#[allow(clippy::too_many_arguments)]
fn require_resource_lease_v2(
    manifest: &CanonicalAssignmentManifestV1,
    lease: &SignedOwnershipLease,
) -> Result<()> {
    let assignment = manifest.broker_assignment()?;
    let original = lease.assignment();
    if original.sandbox() != assignment.sandbox()
        || original.incarnation() != assignment.incarnation()
        || original.epoch() != assignment.epoch()
        || original.digest() != assignment.digest()
        || lease.desired_generation() != assignment.desired_generation()
        || lease.node() != manifest.manifest().node()
    {
        return Err(Box::new(Changed));
    }
    Ok(())
}

fn network_plan_v2(
    commitment: &BrokerArgumentCommitment,
    manifest: &CanonicalAssignmentManifestV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    issued: i64,
    expires: i64,
    revocation_scope: RevocationScopeId,
    request_bytes: usize,
) -> Result<BrokerAuthorizationPlan> {
    resource_plan_v2(
        StartResourcePlanPurposeV2::Network,
        commitment,
        manifest,
        policy_digest,
        lease,
        issued,
        expires,
        revocation_scope,
        request_bytes,
    )
}

#[derive(Clone, Copy)]
enum StartResourcePlanPurposeV2 {
    Network,
    StorageGuestRoot,
}

#[allow(clippy::too_many_arguments)]
fn resource_plan_v2(
    purpose: StartResourcePlanPurposeV2,
    commitment: &BrokerArgumentCommitment,
    manifest: &CanonicalAssignmentManifestV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    issued: i64,
    expires: i64,
    revocation_scope: RevocationScopeId,
    request_bytes: usize,
) -> Result<BrokerAuthorizationPlan> {
    let (verb, audience, protocol, descriptors) = match purpose {
        StartResourcePlanPurposeV2::Network => (
            BrokerVerb::NetworkPrepare,
            BrokerAudience::Network,
            ProtocolId::NetworkBroker,
            1,
        ),
        StartResourcePlanPurposeV2::StorageGuestRoot => (
            BrokerVerb::StoragePopulateGuestRoot,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
            0,
        ),
    };
    let grant = BrokerGrant::new(
        verb,
        BrokerGrantTarget::Assignment,
        *commitment,
        u32::try_from(request_bytes)?,
        descriptors,
    )?;
    Ok(BrokerAuthorizationPlan::new(
        audience,
        protocol,
        ProtocolVersion::new(1, 0),
        manifest.broker_assignment()?,
        lease.node(),
        lease.signer().clone(),
        vec![grant],
        policy_digest,
        revocation_scope,
        issued,
        expires,
        vec![FeatureRef::new(
            "aos.sandbox.authorization.signed-plan-lease",
            1,
            0,
        )?],
    )?)
}

/// Prices the initial canonical content and request without constructing them.
///
/// The genuine owner supplies widths from its held manifest and specification.
/// This covers specification encoding, the AOSNPC02 buffer, concrete protobuf
/// model backing and the encoded request. Native sealing, its descriptor and
/// the owner's retained slots have separate suppliers. No named entry is
/// created by these model fields or vectors.
#[must_use]
pub fn start_network_content_receiving_demand_v2(
    manifest_bytes: usize,
    specification_bytes: usize,
    endpoint_count: usize,
) -> Option<aos_sandbox_core::ResourceVector> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

    let maximum = DecodeLimits::default().maximum_bytes;
    if manifest_bytes == 0
        || specification_bytes == 0
        || manifest_bytes > maximum
        || specification_bytes > maximum
        || endpoint_count > crate::semantics::network::MAXIMUM_NETWORK_ENDPOINTS
    {
        return None;
    }

    let content = 16usize
        .checked_add(manifest_bytes)?
        .checked_add(specification_bytes)?;
    let body = network_template_encoding_bound_v2(content, endpoint_count)?;
    if body > crate::MAXIMUM_REQUEST_BYTES {
        return None;
    }

    let endpoints = endpoint_count.checked_mul(std::mem::size_of::<Vec<u8>>().checked_add(16)?)?;
    // Five fixed byte fields: request, sandbox, incarnation, assignment digest
    // and content digest. Endpoint payloads and headers are separate above.
    let fields = 16usize
        .checked_mul(3)?
        .checked_add(32usize.checked_mul(2)?)?;
    let memory = content
        .checked_add(encoding_growth_bytes_v2(specification_bytes)?)?
        .checked_add(network_proto_fixed_bytes_v2()?)?
        .checked_add(endpoints)?
        .checked_add(fields)?
        .checked_add(body)?;

    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?))
}

/// Prices admitted normalization and its retained signing representation.
///
/// Raw inputs remain with their genuine owners. The bound covers the actual
/// protobuf element layouts, untrusted Core plan decoder and validator, the
/// one-grant expected plan, public authority copies, canonical encoders and
/// signing messages. The native owner separately prices its slots and actual
/// protected key-construction carrier. These values confer no admission.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn start_network_normalization_receiving_demand_v2(
    body_bytes: usize,
    content_bytes: usize,
    specification_bytes: usize,
    root_plan_bytes: usize,
    root_statement_bytes: usize,
    lease: &SignedOwnershipLease,
    authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    resource_normalization_receiving_demand_v2(
        StartResourceGeometryV2::Network,
        body_bytes, content_bytes, specification_bytes, root_plan_bytes,
        root_statement_bytes, lease, authority,
    )
}

/// Prices the complete method31 normalization without native or named entries.
///
/// Returns `None` for malformed widths or overflow. The actual request model,
/// canonical plan/statement decoders and encoders use the same shared bound as
/// Network; only the finite protobuf layout and absent Spec plane differ.
#[must_use]
pub fn start_storage_guest_root_normalization_receiving_demand_v2(
    body_bytes: usize,
    root_plan_bytes: usize,
    root_statement_bytes: usize,
    lease: &SignedOwnershipLease,
    authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    resource_normalization_receiving_demand_v2(
        StartResourceGeometryV2::StorageGuestRoot,
        body_bytes, 0, 0, root_plan_bytes, root_statement_bytes, lease, authority,
    )
}

#[derive(Clone, Copy)]
enum StartResourceGeometryV2 { Network, StorageGuestRoot, Mount, Host }

/// Prices the exact Mount request decoder and shared plan/signing encoders.
///
/// Returns `None` for invalid widths or overflow. Native and named objects are
/// priced separately by the genuine resource owner before their entry.
#[must_use]
pub fn start_mount_unsigned_receiving_demand_v2(
    body_bytes: usize, specification_bytes: usize,
    lease: &SignedOwnershipLease, authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    resource_normalization_receiving_demand_v2(StartResourceGeometryV2::Mount,
        body_bytes, 0, specification_bytes, resource_plan_encoding_bound_v2(lease.signer())?,
        resource_statement_encoding_bound_v2(authority)?, lease, authority)
}

#[allow(clippy::too_many_arguments)]
fn resource_normalization_receiving_demand_v2(
    purpose: StartResourceGeometryV2,
    body_bytes: usize,
    content_bytes: usize,
    specification_bytes: usize,
    root_plan_bytes: usize,
    root_statement_bytes: usize,
    lease: &SignedOwnershipLease,
    authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

    let limits = DecodeLimits::default();
    if body_bytes == 0
        || body_bytes > crate::MAXIMUM_REQUEST_BYTES
        || match purpose {
            StartResourceGeometryV2::Network => {
                content_bytes > NetworkPreparationContentV2::maximum_encoded_bytes()
                    || specification_bytes == 0
                    || specification_bytes > limits.maximum_bytes
            }
            StartResourceGeometryV2::StorageGuestRoot | StartResourceGeometryV2::Host => {
                content_bytes != 0 || specification_bytes != 0
            }
            StartResourceGeometryV2::Mount => {
                content_bytes != 0 || specification_bytes == 0
                    || specification_bytes > limits.maximum_bytes
            }
        }
        || root_plan_bytes == 0
        || root_plan_bytes > limits.maximum_bytes
        || root_statement_bytes == 0
        || root_statement_bytes > limits.maximum_bytes
    {
        return None;
    }

    let (plan_decoder, _) = aos_sandbox_core::format::authorization_capture::
        authorization_artifact_dynamic_footprint_v1(root_plan_bytes)?;
    let validation = aos_sandbox_core::format::canonical_cbor_validation_receiving_bytes_v1(
        root_plan_bytes,
        limits,
    )?;
    let plan_bytes = resource_plan_encoding_bound_v2(lease.signer())?;
    let statement_bytes = resource_statement_encoding_bound_v2(authority)?;
    let message_bytes =
        aos_sandbox_core::crypto::signature_signing_message_bytes_v1(statement_bytes)?;

    // Input validation, the sole canonical template and deadline injection can
    // overlap. Each two-byte wire element can occupy a Vec header; all backing
    // and geometric reallocation are bounded before either protobuf decoder.
    let element_width = match purpose {
        StartResourceGeometryV2::Host => std::mem::size_of::<aos_proto::aos::sandbox::local::v1::Feature>()
            .max(std::mem::size_of::<aos_proto::aos::sandbox::local::v1::ResourceLimit>())
            .max(std::mem::size_of::<aos_sandbox_core::FeatureRef>()),
        _ => std::mem::size_of::<Vec<u8>>(),
    };
    let element_slots = body_bytes.checked_div(2)?.checked_mul(element_width)?;
    let proto_fixed = match purpose {
        StartResourceGeometryV2::Network => network_proto_fixed_bytes_v2()?,
        StartResourceGeometryV2::StorageGuestRoot => {
            std::mem::size_of::<aos_proto::aos::sandbox::local::v1::PopulateStorageGuestRootRequestV1>()
                .checked_add(std::mem::size_of::<RequestHeader>())?
                .checked_add(std::mem::size_of::<AssignmentFence>())?
                .checked_add(crate::semantics::storage_guest_root::
                    CanonicalStorageGuestRootArgumentsV1::deadline_free_request_receiving_bytes_v2()?)?
        }
        StartResourceGeometryV2::Host => {
            use aos_proto::aos::sandbox::local::v1::{ApplyRuntimeRequest, RuntimePlan, GuardianArmCompanionV1, Descriptor};
            std::mem::size_of::<ApplyRuntimeRequest>()
                .checked_add(std::mem::size_of::<RequestHeader>())?
                .checked_add(std::mem::size_of::<AssignmentFence>())?
                .checked_add(std::mem::size_of::<RuntimePlan>())?
                .checked_add(std::mem::size_of::<GuardianArmCompanionV1>())?
                .checked_add(std::mem::size_of::<Descriptor>())?
                .checked_add(std::mem::size_of::<crate::ValidatedRuntimeRequest>())?
                .checked_add(std::mem::size_of::<crate::ValidatedRuntimePlan>())?
        }
        StartResourceGeometryV2::Mount => {
            std::mem::size_of::<aos_proto::aos::sandbox::local::v1::ApplyAttachmentAnchorRequestV1>()
                .checked_add(std::mem::size_of::<RequestHeader>())?
                .checked_add(std::mem::size_of::<AssignmentFence>())?
                .checked_add(std::mem::size_of::<aos_proto::aos::sandbox::local::v1::Descriptor>())?
        }
    };
    let proto_model = proto_fixed
        .checked_add(encoding_growth_bytes_v2(body_bytes)?)?
        .checked_add(element_slots.checked_mul(3)?)?
        .checked_add(std::mem::size_of::<Vec<u8>>().checked_mul(4)?)?;
    let proto = proto_model
        .checked_mul(3)?
        .checked_add(body_bytes.checked_add(11)?.checked_mul(5)?)?;

    let feature = "aos.sandbox.authorization.signed-plan-lease";
    let plan_model = std::mem::size_of::<aos_sandbox_core::BrokerGrant>()
        .checked_add(std::mem::size_of::<aos_sandbox_core::FeatureRef>())?
        .checked_add(lease.signer().stable_key_id().as_str().len())?
        .checked_add(feature.len())?;
    let policy_media = authority.policy_descriptor().media_type().as_str().len();
    let signer_text = authority.signer().stable_key_id().as_str().len();
    let authority_backing = authority
        .canonical_policy
        .len()
        .checked_add(policy_media)?
        .checked_add(signer_text)?;
    let statement_backing = PortableMediaType::BrokerAuthorizationPlan
        .as_str()
        .len()
        .checked_add(policy_media)?
        .checked_add(signer_text)?;
    let models = plan_model
        .checked_add(authority_backing)?
        .checked_add(statement_backing)?
        .checked_mul(3)?;
    let encodings = encoding_growth_bytes_v2(plan_bytes)?
        .checked_mul(2)?
        .checked_add(encoding_growth_bytes_v2(statement_bytes)?.checked_mul(4)?)?
        .checked_add(message_bytes.checked_mul(3)?)?;
    let fixed = std::mem::size_of::<StartResourcePlanPreparationDataV1>()
        .checked_add(std::mem::size_of::<BrokerAuthorizationPlan>())?
        .checked_add(std::mem::size_of::<BrokerPlanPreparation>())?
        .checked_add(std::mem::size_of::<SigningAuthority>())?
        .checked_add(std::mem::size_of::<sha2::Sha256>())?
        .checked_mul(3)?;
    let specification_encoding = match purpose {
        StartResourceGeometryV2::Network => encoding_growth_bytes_v2(specification_bytes)?,
        StartResourceGeometryV2::StorageGuestRoot | StartResourceGeometryV2::Host => 0,
        StartResourceGeometryV2::Mount => crate::mount_attachment_anchor::attachment_anchor_request_decoding_demand_v4(body_bytes).ok()?
            .get(D::MemoryBytes).try_into().ok()?,
    };
    let memory = u64::try_from(
        proto
            .checked_add(models)?
            .checked_add(encodings)?
            .checked_add(fixed)?
            .checked_add(validation)?
            .checked_add(specification_encoding)?,
    )
    .ok()?
    .checked_add(plan_decoder)?;

    Some(ResourceVector::ZERO.with(D::MemoryBytes, memory))
}

/// Prices the same unsigned Network normalizer before Root constructs its plan.
///
/// This derives both canonical output bounds from the actual lease signer and
/// retained public signing authority, then delegates the existing full recipe.
/// It conveys representation DATA only and returns `None` on overflow.
#[must_use]
pub fn start_network_unsigned_receiving_demand_v2(
    body_bytes: usize, content_bytes: usize, specification_bytes: usize,
    lease: &SignedOwnershipLease, authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    start_network_normalization_receiving_demand_v2(body_bytes, content_bytes,
        specification_bytes, resource_plan_encoding_bound_v2(lease.signer())?,
        resource_statement_encoding_bound_v2(authority)?, lease, authority)
}

/// Prices unsigned method31 construction through the same complete normalizer.
///
/// Returns `None` for malformed request widths or checked arithmetic overflow.
#[must_use]
pub fn start_storage_guest_root_unsigned_receiving_demand_v2(
    body_bytes: usize,
    lease: &SignedOwnershipLease,
    authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    start_storage_guest_root_normalization_receiving_demand_v2(
        body_bytes,
        resource_plan_encoding_bound_v2(lease.signer())?,
        resource_statement_encoding_bound_v2(authority)?,
        lease,
        authority,
    )
}

fn network_proto_fixed_bytes_v2() -> Option<usize> {
    std::mem::size_of::<ApplyNetworkRequest>()
        .checked_add(std::mem::size_of::<RequestHeader>())?
        .checked_add(std::mem::size_of::<AssignmentFence>())
}

// Vec growth may keep the old and doubled new allocations simultaneously.
// Include its minimum byte allocation for very small canonical encodings.
fn encoding_growth_bytes_v2(bytes: usize) -> Option<usize> {
    bytes.checked_mul(3)?.checked_add(16)
}

fn protobuf_varint_bytes_v2(mut value: u64) -> usize {
    let mut bytes = 1;
    while value >= 128 {
        bytes += 1;
        value >>= 7;
    }
    bytes
}

fn protobuf_bytes_field_bound_v2(bytes: usize) -> Option<usize> {
    1usize
        .checked_add(protobuf_varint_bytes_v2(u64::try_from(bytes).ok()?))?
        .checked_add(bytes)
}

fn network_template_encoding_bound_v2(content: usize, endpoints: usize) -> Option<usize> {
    // Header: version, request, audience and response ceiling. Fence: two
    // identities, two widest generation values and the assignment digest.
    let header = 2usize
        .checked_add(protobuf_bytes_field_bound_v2(16)?)?
        .checked_add(2)?
        .checked_add(1 + protobuf_varint_bytes_v2(u64::from(crate::MINIMUM_RESPONSE_BYTES)))?;
    let fence = protobuf_bytes_field_bound_v2(16)?
        .checked_mul(2)?
        .checked_add(22)?
        .checked_add(protobuf_bytes_field_bound_v2(32)?)?;
    protobuf_bytes_field_bound_v2(header)?
        .checked_add(protobuf_bytes_field_bound_v2(fence)?)?
        .checked_add(2)? // Prepare action.
        .checked_add(protobuf_bytes_field_bound_v2(16)?.checked_mul(endpoints)?)?
        .checked_add(2)? // Content version.
        .checked_add(1 + protobuf_varint_bytes_v2(u64::try_from(content).ok()?))?
        .checked_add(protobuf_bytes_field_bound_v2(32)?)
}

fn resource_plan_encoding_bound_v2(signer: &aos_sandbox_core::model::KeyReference) -> Option<usize> {
    // The sole plan recipe above has 35 CBOR heads, including nested arrays,
    // and fixed assignment/node/key/commitment/policy/scope payloads (192 B).
    // Every head uses at most nine bytes, including signed time endpoints.
    35usize
        .checked_mul(9)?
        .checked_add(192)?
        .checked_add(signer.stable_key_id().as_str().len())?
        .checked_add("aos.sandbox.authorization.signed-plan-lease".len())
}

/// Bounds one Stop cleanup normalization through the existing Host recipe.
///
/// The Host protobuf and canonical plan suppliers cover the same request,
/// fence, semantic commitment and signing statement. Cleanup has no Guardian
/// plan or descriptor. Its inline subject and returned preparation carriers
/// are added here; raw received artifacts remain the transport owner's debt.
/// Returns `None` for invalid widths or checked accounting overflow.
#[must_use]
pub fn host_stop_cleanup_normalization_receiving_demand_v1(
    body_bytes: usize,
    root_plan_bytes: usize,
    root_statement_bytes: usize,
    lease: &SignedOwnershipLease,
    authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

    let common = resource_normalization_receiving_demand_v2(
        StartResourceGeometryV2::Host, body_bytes, 0, 0,
        root_plan_bytes, root_statement_bytes, lease, authority,
    )?;
    let extra = std::mem::size_of::<super::host_stop_cleanup_plan::StopCleanupPlanPreparationDataV1>()
        .checked_add(std::mem::size_of::<crate::host_stop_cleanup::HostStopCleanupSubjectDataV1>())?
        .checked_mul(3)?;
    common.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(extra).ok()?)).ok()
}

/// Bounds unsigned Stop cleanup construction before either decoder grows.
///
/// Returns `None` for an invalid request width or checked accounting overflow.
#[must_use]
pub fn host_stop_cleanup_unsigned_receiving_demand_v1(
    body_bytes: usize,
    lease: &SignedOwnershipLease,
    authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    host_stop_cleanup_normalization_receiving_demand_v1(body_bytes,
        resource_plan_encoding_bound_v2(lease.signer())?,
        resource_statement_encoding_bound_v2(authority)?, lease, authority)
}

fn resource_statement_encoding_bound_v2(authority: &SigningAuthority) -> Option<usize> {
    // SignatureStatement has 20 CBOR heads including its two descriptors and
    // signer, plus three digests and a trust scope (112 fixed payload bytes).
    20usize
        .checked_mul(9)?
        .checked_add(112)?
        .checked_add(PortableMediaType::BrokerAuthorizationPlan.as_str().len())?
        .checked_add(authority.policy_descriptor().media_type().as_str().len())?
        .checked_add(authority.signer().stable_key_id().as_str().len())
}

#[cfg(test)]
mod receiving_tests {
    use super::*;
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, NetworkEndpointId,
        NodeId, SandboxId, TrustScopeId, descriptor_for_bytes,
    };

    fn assignment() -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(u64::MAX),
            DesiredGeneration::new(u64::MAX),
            ObjectDigest::from_bytes([3; 32]),
        )
        .unwrap()
    }

    #[test]
    fn content_bound_covers_the_real_encoder_at_all_endpoint_counts() {
        let encoded = NetworkPreparationContentV2::new(b"manifest", b"specification")
            .unwrap()
            .encode()
            .unwrap();
        let reference = NetworkPreparationContentReferenceV2::for_content(&encoded).unwrap();
        let maximum = crate::semantics::network::MAXIMUM_NETWORK_ENDPOINTS;

        for count in [0, 1, maximum] {
            let endpoints: Vec<_> = (1..=count)
                .map(|index| {
                    let mut id = [0; 16];
                    id[14..].copy_from_slice(&u16::try_from(index).unwrap().to_be_bytes());
                    NetworkEndpointId::from_bytes(id)
                })
                .collect();
            let body = reference
                .deadline_free_request_body_v2(assignment(), [4; 16], &endpoints)
                .unwrap();
            let bound = network_template_encoding_bound_v2(encoded.len(), count).unwrap();
            let demand = start_network_content_receiving_demand_v2(
                b"manifest".len(),
                b"specification".len(),
                count,
            )
            .unwrap();

            assert!(body.len() <= bound);
            assert!(
                demand.get(aos_sandbox_core::ResourceDimension::MemoryBytes)
                    >= u64::try_from(encoded.len() + body.len()).unwrap()
            );
            assert_eq!(
                demand.get(aos_sandbox_core::ResourceDimension::MetadataEntries),
                0
            );
        }

        assert!(start_network_content_receiving_demand_v2(1, 1, maximum + 1).is_none());
        assert!(start_network_content_receiving_demand_v2(usize::MAX, 1, 0).is_none());
        assert!(start_network_content_receiving_demand_v2(1, usize::MAX, 0).is_none());
    }

    #[test]
    fn plan_and_statement_bounds_cover_the_real_widest_field_encoders() {
        use sha2::Digest as _;

        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let public_key = key.verifying_key().to_bytes();
        let signer = KeyReference::new(
            StableKeyId::new("s".repeat(255)).unwrap(),
            u64::MAX,
            ObjectDigest::from_bytes(sha2::Sha256::digest(public_key).into()),
            KeyUsage::BrokerAuthorization,
        );
        let scope = TrustScopeId::from_bytes([5; 16]);
        let policy = TrustPolicy::new(
            scope,
            SignaturePurpose::BrokerAuthorization,
            vec![signer.clone()],
            vec![],
        )
        .unwrap();
        let policy_bytes = aos_sandbox_core::format::encode_trust_policy(&policy);
        let descriptor = descriptor_for_bytes(
            aos_sandbox_core::MediaType::new(PortableMediaType::TrustPolicy.as_str()).unwrap(),
            &policy_bytes,
        );
        let authority = SigningAuthority::new(
            policy_bytes,
            descriptor,
            scope,
            signer,
            public_key,
            SignaturePurpose::BrokerAuthorization,
            DecodeLimits::default(),
        )
        .unwrap();
        let ownership_signer = KeyReference::new(
            StableKeyId::new("o".repeat(255)).unwrap(),
            u64::MAX,
            ObjectDigest::from_bytes([6; 32]),
            KeyUsage::OwnershipLease,
        );
        let grant = BrokerGrant::new(
            BrokerVerb::NetworkPrepare,
            BrokerGrantTarget::Assignment,
            BrokerArgumentCommitment::from_digest(ObjectDigest::from_bytes([7; 32])).unwrap(),
            16 * 1024 * 1024,
            16,
        )
        .unwrap();
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Network,
            ProtocolId::NetworkBroker,
            ProtocolVersion::new(1, 0),
            assignment(),
            NodeId::from_bytes([8; 16]),
            ownership_signer.clone(),
            vec![grant],
            ObjectDigest::from_bytes([10; 32]),
            RevocationScopeId::from_bytes([11; 16]),
            i64::MIN,
            i64::MAX,
            vec![FeatureRef::new("aos.sandbox.authorization.signed-plan-lease", 1, 0).unwrap()],
        )
        .unwrap();

        let preparation = BrokerPlanPreparation::new(plan, authority.clone()).unwrap();
        let request = preparation.signing_request();

        assert!(
            preparation.canonical_plan().len()
                <= resource_plan_encoding_bound_v2(&ownership_signer).unwrap()
        );
        assert!(
            request.canonical_statement().len()
                <= resource_statement_encoding_bound_v2(&authority).unwrap()
        );
        assert_eq!(
            request.signing_message().len(),
            aos_sandbox_core::crypto::signature_signing_message_bytes_v1(
                request.canonical_statement().len(),
            )
            .unwrap()
        );
        assert!(aos_sandbox_core::crypto::signature_signing_message_bytes_v1(usize::MAX).is_none());
    }
}


/// Bounds both Host and Guardian normalization through the same finite recipe.
///
/// The genuine Host native owner prepays this DATA before constructing models
/// or lending either signing preparation. Descriptor/native/named objects stay
/// with their actual owners; the Rust model fields create no Metadata entries.
/// Returns `None` on invalid widths or checked arithmetic overflow.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn host_launch_pair_normalization_receiving_demand_v2(
    body_bytes: usize,
    host_plan_bytes: usize,
    host_statement_bytes: usize,
    guardian_plan_bytes: usize,
    guardian_statement_bytes: usize,
    lease: &SignedOwnershipLease,
    authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
    let host = resource_normalization_receiving_demand_v2(StartResourceGeometryV2::Host,
        body_bytes, 0, 0, host_plan_bytes, host_statement_bytes, lease, authority)?;
    let guardian = resource_normalization_receiving_demand_v2(StartResourceGeometryV2::Host,
        body_bytes, 0, 0, guardian_plan_bytes, guardian_statement_bytes, lease, authority)?;
    let paired = std::mem::size_of::<super::host_launch_plan::HostLaunchPlanPreparationDataV2>()
        .checked_add(std::mem::size_of::<aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope>())?
        .checked_add(std::mem::size_of::<aos_sandbox_core::model::Signature>().checked_mul(2)?)?
        .checked_mul(3).and_then(|bytes| u64::try_from(bytes).ok())?;
    // The signature envelope is a two-element CBOR array containing the
    // existing statement and the canonical 64-byte Ed25519 byte string.
    let statement = resource_statement_encoding_bound_v2(authority)?;
    let signature = statement.checked_add(1 + 2 + 64)?;
    let plan = resource_plan_encoding_bound_v2(lease.signer())?;
    let live = body_bytes.checked_add(11)?
        .checked_add(plan)?.checked_add(signature)?
        .checked_add(3_usize.checked_mul(11)?)?;
    let envelope = live.checked_add(plan)?.checked_add(signature)?
        .checked_add(lease.canonical_lease().len())?
        .checked_add(lease.canonical_signature().len())?
        .checked_add(aos_sandbox_broker_session_protocol::SIGNED_BROKER_REQUEST_BYTES)?
        .checked_add(10_usize.checked_mul(11)?)?;
    // Composite body, first envelope, decoded envelope backing, session field
    // replacement and final request shape can overlap with both preparations.
    let framing = u64::try_from(encoding_growth_bytes_v2(envelope)?.checked_mul(6)?).ok()?;
    host.checked_add(guardian).ok()?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, paired.checked_add(framing)?)).ok()
}

/// Bounds the same paired unsigned construction before Root's native entry.
///
/// Returns `None` for invalid input width or unrepresentable exact codec bounds.
#[must_use]
pub fn host_launch_pair_unsigned_receiving_demand_v2(
    body_bytes: usize,
    lease: &SignedOwnershipLease,
    authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    let plan = resource_plan_encoding_bound_v2(lease.signer())?;
    let statement = resource_statement_encoding_bound_v2(authority)?;
    host_launch_pair_normalization_receiving_demand_v2(
        body_bytes, plan, statement, plan, statement, lease, authority,
    )
}

/// Prices the actual received Host reply beside canonical Guardian construction.
///
/// The raw reply remains separately funded by its stream owner. This prices
/// the decoder's actual Host input width before equality with the expected
/// canonical plan; an enlarged or malformed reply cannot borrow the unsigned
/// expected-width bound. Guardian construction uses the same format-owned
/// canonical plan and statement bounds as the unsigned pair recipe.
///
/// Returns `None` for invalid actual widths or checked accounting overflow.
#[must_use]
pub fn host_launch_pair_admitted_receiving_demand_v2(
    body_bytes: usize,
    host_plan_bytes: usize,
    host_statement_bytes: usize,
    lease: &SignedOwnershipLease,
    authority: &SigningAuthority,
) -> Option<aos_sandbox_core::ResourceVector> {
    let guardian_plan = resource_plan_encoding_bound_v2(lease.signer())?;
    let guardian_statement = resource_statement_encoding_bound_v2(authority)?;
    host_launch_pair_normalization_receiving_demand_v2(body_bytes,
        host_plan_bytes, host_statement_bytes, guardian_plan, guardian_statement,
        lease, authority)
}
