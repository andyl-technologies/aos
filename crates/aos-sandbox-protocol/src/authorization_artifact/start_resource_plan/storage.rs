//! Normalizes Start's current-assignment publication into its existing workspace.
//!
//! Actual Root and Controller lenders establish the paid native Start, verified
//! lease and immutable creation workspace. These DATA recipes use the sole
//! method31 argument and request encoders; they issue no peer or permission.

use aos_proto::aos::sandbox::local::v1::PopulateStorageGuestRootRequestV1;
use crate::semantics::storage_guest_root::CanonicalStorageGuestRootArgumentsV1;
use super::*;

/// Prepares a current-assignment publication plan for an existing workspace.
///
/// The caller prepays complete request, model and encoding backing. The original
/// acquisition cutoff remains unchanged, independently of the resident lease.
///
/// # Errors
/// Refuses changed canonical input, assignment, lease, policy or an expired
/// original interval, and retains the underlying plan-preparation failure.
#[allow(clippy::too_many_arguments)]
pub fn prepare_start_storage_guest_root_plan_v2(
    deadline_free_body: &[u8],
    arguments: &CanonicalStorageGuestRootArgumentsV1,
    manifest: &CanonicalAssignmentManifestV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
) -> Result<StartResourcePlanPreparationDataV1> {
    let expires = plan_expiry_v1(
        sample, cutoff, policy_expires, lease.authority_expires_seconds(),
    )?;
    let (request_body, request_header) = storage_inputs_v2(
        deadline_free_body, arguments, manifest, lease, sample, cutoff,
    )?;
    let plan = resource_plan_v2(
        StartResourcePlanPurposeV2::StorageGuestRoot,
        &arguments.argument_commitment(), manifest, policy_digest, lease,
        sample.wall_seconds(), expires, revocation_scope, request_body.len(),
    )?;

    Ok(StartResourcePlanPreparationDataV1 {
        preparation: BrokerPlanPreparation::new(plan, authority)?,
        request_body,
        request_header,
    })
}

/// Reconstructs the admitted current-publication plan and signing statement.
///
/// Both actual lenders use the same full argument, lease and plan recipes.
/// Comparison does not replace native currentness or authenticated outcomes.
///
/// # Errors
/// Refuses substituted input, assignment, lease, policy, grant, authority,
/// statement, request deadline or validity outside the original interval.
#[allow(clippy::too_many_arguments)]
pub fn prepare_admitted_start_storage_guest_root_plan_v2(
    deadline_free_body: &[u8],
    arguments: &CanonicalStorageGuestRootArgumentsV1,
    manifest: &CanonicalAssignmentManifestV1,
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
        canonical_plan, DecodeLimits::default(),
    )?;
    require_admitted_clock_v1(
        sample, cutoff, plan.issued_seconds(), plan.expires_seconds(),
        lease.authority_issued_seconds(), lease.authority_expires_seconds(),
    )?;
    let maximum_expiry = plan_expiry_v1(
        sample, cutoff, policy_expires, lease.authority_expires_seconds(),
    )?;
    if plan.expires_seconds() > maximum_expiry {
        return Err(Box::new(Changed));
    }
    admitted_storage_preparation_v2(
        plan, deadline_free_body, arguments, manifest, policy_digest, lease,
        cutoff, authority, revocation_scope, canonical_plan, canonical_statement,
    )
}

/// Compares an authenticated historical publication with its original grant.
///
/// The request's original deadline and the signed plan's original validity are
/// comparison data. This function samples no clock and grants no current use of
/// an expired plan; the enclosing reader independently establishes its current
/// authorization, native interval and fresh Inventory observation.
///
/// # Errors
/// Refuses changed canonical arguments, request deadline, assignment, lease,
/// policy, grant or signature statement, including a plan outside its original
/// lease or policy ceiling.
#[allow(clippy::too_many_arguments)]
pub fn compare_historical_start_storage_guest_root_plan_v2(
    deadline_free_body: &[u8],
    arguments: &CanonicalStorageGuestRootArgumentsV1,
    manifest: &CanonicalAssignmentManifestV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    original_deadline: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
    canonical_plan: &[u8],
    canonical_statement: &[u8],
) -> Result<StartResourcePlanPreparationDataV1> {
    let plan = aos_sandbox_core::format::decode_broker_authorization_plan(
        canonical_plan, DecodeLimits::default(),
    )?;
    if plan.issued_seconds() < lease.authority_issued_seconds()
        || plan.expires_seconds() <= plan.issued_seconds()
        || plan.expires_seconds() > lease.authority_expires_seconds()
        || plan.expires_seconds() > policy_expires
    {
        return Err(Box::new(Changed));
    }

    admitted_storage_preparation_v2(
        plan, deadline_free_body, arguments, manifest, policy_digest, lease,
        original_deadline, authority, revocation_scope, canonical_plan,
        canonical_statement,
    )
}

#[allow(clippy::too_many_arguments)]
fn admitted_storage_preparation_v2(
    plan: BrokerAuthorizationPlan,
    deadline_free_body: &[u8],
    arguments: &CanonicalStorageGuestRootArgumentsV1,
    manifest: &CanonicalAssignmentManifestV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    cutoff: u64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
    canonical_plan: &[u8],
    canonical_statement: &[u8],
) -> Result<StartResourcePlanPreparationDataV1> {
    let (request_body, request_header) = storage_body_v2(
        deadline_free_body, arguments, manifest, lease, cutoff,
    )?;
    let expected = resource_plan_v2(
        StartResourcePlanPurposeV2::StorageGuestRoot,
        &arguments.argument_commitment(), manifest, policy_digest, lease,
        plan.issued_seconds(), plan.expires_seconds(), revocation_scope,
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

fn storage_inputs_v2(
    deadline_free_body: &[u8],
    arguments: &CanonicalStorageGuestRootArgumentsV1,
    manifest: &CanonicalAssignmentManifestV1,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
) -> Result<(Vec<u8>, StartResourceRequestHeaderDataV2)> {
    if sample.boottime_nanoseconds() >= cutoff {
        return Err(Box::new(Changed));
    }
    storage_body_v2(deadline_free_body, arguments, manifest, lease, cutoff)
}

fn storage_body_v2(
    deadline_free_body: &[u8],
    arguments: &CanonicalStorageGuestRootArgumentsV1,
    manifest: &CanonicalAssignmentManifestV1,
    lease: &SignedOwnershipLease,
    cutoff: u64,
) -> Result<(Vec<u8>, StartResourceRequestHeaderDataV2)> {
    if deadline_free_body.len() > crate::MAXIMUM_REQUEST_BYTES
        || cutoff == 0
        || arguments.assignment_data_v1()? != manifest.broker_assignment()?
    {
        return Err(Box::new(Changed));
    }
    require_resource_lease_v2(manifest, lease)?;

    // This decoder checks canonical DATA only. Actual peer credentials remain
    // exclusively with the native Session admission, with no synthetic peer.
    let request: PopulateStorageGuestRootRequestV1 = buffa::DecodeOptions::new()
        .with_max_message_size(crate::MAXIMUM_REQUEST_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice(deadline_free_body)?;
    let header = request.header.as_option().ok_or(Changed)?;
    let request_id = crate::exact_nonzero::<16>(&header.request_id, "request_id")?;
    if arguments.deadline_free_request_body_v2(request_id)? != deadline_free_body {
        return Err(Box::new(Changed));
    }
    let request_header = StartResourceRequestHeaderDataV2 {
        protocol_major: header.protocol_major,
        protocol_minor: header.protocol_minor,
        audience: header.audience.as_known().ok_or(Changed)?,
        request_id,
        deadline_boottime_nanoseconds: cutoff,
        maximum_response_bytes: header.maximum_response_bytes,
    };
    let request_body = inject_deadline(deadline_free_body, cutoff)?;
    Ok((request_body, request_header))
}
