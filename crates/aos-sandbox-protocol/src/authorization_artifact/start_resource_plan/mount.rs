//! Reuses the canonical Mount62 request and unsigned plan normalizer for Start.
//!
//! The caller supplies actual current assignment/Spec/lease comparisons and
//! funds all models before entry. These pure recipes create no native loan,
//! signature, Session association or resource-completion authority.

use super::*;
use crate::mount_attachment_anchor::{
    attachment_anchor_request_body_v1, decode_attachment_anchor_request_data_v2, wire_descriptor,
};
use aos_proto::aos::sandbox::local::v1::{
    ApplyAttachmentAnchorRequestV1, AttachmentAnchorActionV1,
};
use aos_sandbox_core::ObjectDescriptor;

/// Constructs the exact deadline-free empty namespace request from current DATA.
///
/// # Errors
/// Refuses a zero request, nonempty attachment declaration, substituted Spec
/// descriptor/encoding, invalid assignment or a request beyond the fixed bound.
pub fn start_mount_request_body_data_v2(
    manifest: &CanonicalAssignmentManifestV1,
    descriptor: &ObjectDescriptor,
    specification: &SandboxSpec,
    request_id: [u8; 16],
) -> Result<Vec<u8>> {
    if request_id == [0; 16] || !specification.attachment_slots().is_empty() {
        return Err(Box::new(Changed));
    }
    let assignment = manifest.broker_assignment()?;
    let encoded = aos_sandbox_core::encode_sandbox_spec(specification);
    if encoded.len() > crate::MAXIMUM_DESTINATION_SLOT_SPEC_BYTES {
        return Err(Box::new(Changed));
    }
    if aos_sandbox_core::descriptor_for_bytes(descriptor.media_type().clone(), &encoded)
        != *descriptor
        || descriptor.media_type().as_str()
            != aos_sandbox_core::sandbox_spec_media_type(specification).as_str()
    {
        return Err(Box::new(Changed));
    }
    let body = attachment_anchor_request_body_v1(&ApplyAttachmentAnchorRequestV1 {
        header: Some(RequestHeader {
            protocol_major: 2,
            protocol_minor: 0,
            request_id: request_id.to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            maximum_response_bytes: crate::MINIMUM_RESPONSE_BYTES,
            ..Default::default()
        })
        .into(),
        fence: Some(AssignmentFence {
            sandbox_id: assignment.sandbox().as_bytes().to_vec(),
            incarnation_id: assignment.incarnation().as_bytes().to_vec(),
            assignment_epoch: assignment.epoch().get(),
            desired_generation: assignment.desired_generation().get(),
            assignment_digest: assignment.digest().as_bytes().to_vec(),
            ..Default::default()
        })
        .into(),
        action: AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_MATERIALIZE.into(),
        namespace_generation: manifest.manifest().namespace_generation().get(),
        sandbox_spec: Some(wire_descriptor(descriptor)).into(),
        sandbox_spec_bytes: encoded,
        ..Default::default()
    });
    if body.len() > crate::MAXIMUM_REQUEST_BYTES {
        return Err(Box::new(Changed));
    }
    Ok(body)
}

/// Reconstructs the admitted Mount62 plan through its sole existing normalizer.
///
/// # Errors
/// Refuses changed canonical body, assignment, Spec, lease, clock, policy,
/// signed-plan or signing-statement DATA. Native currentness remains mandatory.
#[allow(clippy::too_many_arguments)]
pub fn prepare_admitted_start_mount_plan_v2(
    deadline_free_body: &[u8],
    request_id: [u8; 16],
    manifest: &CanonicalAssignmentManifestV1,
    descriptor: &ObjectDescriptor,
    specification: &SandboxSpec,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    scope: RevocationScopeId,
    canonical_plan: &[u8],
    canonical_statement: &[u8],
) -> Result<StartResourcePlanPreparationDataV1> {
    let (request, request_body, request_header) = mount_inputs_v2(
        deadline_free_body,
        manifest,
        descriptor,
        specification,
        lease,
        sample,
        cutoff,
    )?;
    if request_header.request_id != request_id {
        return Err(Box::new(Changed));
    }
    let preparation = super::super::prepare_admitted_attachment_anchor_plan_v1(
        &request,
        manifest.manifest().policy().digest(),
        lease,
        sample,
        cutoff,
        authority,
        scope,
        canonical_plan,
        canonical_statement,
    )?;
    if preparation.plan_data_v1().expires_seconds() > policy_expires {
        return Err(Box::new(Changed));
    }
    Ok(StartResourcePlanPreparationDataV1 {
        preparation,
        request_body,
        request_header,
    })
}

/// Prepares the unsigned Mount62 plan from Root's independently rebuilt inputs.
///
/// # Errors
/// Refuses changed canonical request, assignment, Spec, lease, policy or clock.
/// This produces unsigned DATA and supplies no peer or native permission.
#[allow(clippy::too_many_arguments)]
pub fn prepare_start_mount_plan_v2(
    deadline_free_body: &[u8],
    manifest: &CanonicalAssignmentManifestV1,
    descriptor: &ObjectDescriptor,
    specification: &SandboxSpec,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    scope: RevocationScopeId,
) -> Result<StartResourcePlanPreparationDataV1> {
    let (request, request_body, request_header) = mount_inputs_v2(
        deadline_free_body,
        manifest,
        descriptor,
        specification,
        lease,
        sample,
        cutoff,
    )?;
    let prepared = super::super::prepare_attachment_anchor_plan_v1(
        &request,
        manifest.manifest().policy().digest(),
        lease,
        sample,
        cutoff,
        policy_expires,
        authority,
        scope,
    )?;
    Ok(StartResourcePlanPreparationDataV1 {
        preparation: prepared.into_preparation_v2(),
        request_body,
        request_header,
    })
}

#[allow(clippy::too_many_arguments)]
fn mount_inputs_v2(
    deadline_free_body: &[u8],
    manifest: &CanonicalAssignmentManifestV1,
    descriptor: &ObjectDescriptor,
    specification: &SandboxSpec,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
) -> Result<(
    crate::mount_attachment_anchor::ValidatedAttachmentAnchorRequestV1,
    Vec<u8>,
    StartResourceRequestHeaderDataV2,
)> {
    let request_body = inject_deadline(deadline_free_body, cutoff)?;
    let request = decode_attachment_anchor_request_data_v2(
        &request_body,
        Audience::AUDIENCE_NODE_CONTROLLER,
        sample.boottime_nanoseconds(),
    )?;
    let request_id = *request.header().request_id();
    let assignment = manifest.broker_assignment()?;
    let leased = lease.assignment();
    if start_mount_request_body_data_v2(manifest, descriptor, specification, request_id)?
        != deadline_free_body
        || leased.sandbox() != assignment.sandbox()
        || leased.incarnation() != assignment.incarnation()
        || leased.epoch() != assignment.epoch()
        || leased.digest() != assignment.digest()
        || lease.desired_generation() != assignment.desired_generation()
        || lease.node() != manifest.manifest().node()
        || sample.boottime_nanoseconds() >= cutoff
    {
        return Err(Box::new(Changed));
    }
    let header = request.header();
    let request_header = StartResourceRequestHeaderDataV2 {
        protocol_major: u32::from(header.protocol_version().major()),
        protocol_minor: u32::from(header.protocol_version().minor()),
        audience: header.audience(),
        request_id: *header.request_id(),
        deadline_boottime_nanoseconds: cutoff,
        maximum_response_bytes: header.maximum_response_bytes(),
    };
    Ok((request, request_body, request_header))
}

/// Prices the concrete request construction and sole hostile Spec decoder.
///
/// Returns `None` for an invalid bound or checked arithmetic overflow. The
/// caller joins actual signing/Root/native/Session owners separately.
#[must_use]
pub fn start_mount_request_receiving_demand_v2(
    specification_bytes: usize,
) -> Option<aos_sandbox_core::ResourceVector> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
    if specification_bytes == 0 || specification_bytes > DecodeLimits::default().maximum_bytes {
        return None;
    }
    // One canonical Spec encoding, one protobuf field and one retained request;
    // each encoder can overlap its previous backing during capacity growth.
    let spec_wire = specification_bytes.checked_mul(6)?;
    let request_fixed = std::mem::size_of::<ApplyAttachmentAnchorRequestV1>()
        .checked_add(std::mem::size_of::<RequestHeader>())?
        .checked_add(std::mem::size_of::<AssignmentFence>())?
        .checked_add(std::mem::size_of::<
            aos_proto::aos::sandbox::local::v1::Descriptor,
        >())?
        .checked_mul(2)?;
    let specification = aos_sandbox_core::format::sandbox_spec_decoding_receiving_bytes_v2(
        specification_bytes,
        DecodeLimits::default(),
    )?;
    Some(
        ResourceVector::ZERO.with(
            D::MemoryBytes,
            u64::try_from(
                request_fixed
                    .checked_add(spec_wire)?
                    .checked_add(specification)?,
            )
            .ok()?,
        ),
    )
}
