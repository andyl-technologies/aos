//! Prepares unsigned, catalog-bound Create Apply plans for independent issuers.
//!
//! Root and Controller use the same pure recipe with their own original
//! policy, verified lease, protected public trust and actual clock. This module
//! contains no key, native owner, callback, receiving grant or signed artifact.

use std::error::Error;

use aos_sandbox_api::aos::sandbox::local::v1::ApplyStorageRequest;
use aos_sandbox_model::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, BrokerGrantTarget,
    BrokerVerb, FeatureRef, ObjectDigest, ProtocolId, ProtocolVersion,
    RawPairedClockSample, RevocationScopeId,
};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use buffa::Message as _;

use super::{BrokerPlanPreparation, SigningAuthority, StorageCreatePlanPreparationDataV1};
use crate::semantics::ProtectedStorageCreateApplyDataV1;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug, thiserror::Error)]
#[error("the original Create Apply plan or unchanged validity differs")]
struct Changed;

/// Prepares the separate Create Apply plan and complete catalog-bound wire shape.
///
/// The caller independently validates its current policy and the actual signed
/// Prepare/catalog association, and funds all model and encoding construction.
/// A successful return supplies unsigned DATA only. The unchanged Prepare
/// cutoff, policy expiry and verified lease jointly limit the new plan.
///
/// # Errors
/// Rejects an exhausted cutoff, expired policy/lease, invalid public signing
/// authority or an encoding/grant bound that exceeds the existing schema.
#[allow(clippy::too_many_arguments)]
pub fn prepare_storage_create_apply_plan_v1(
    protected: &ProtectedStorageCreateApplyDataV1<'_>,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
) -> Result<StorageCreatePlanPreparationDataV1> {
    if cutoff > protected.preparation_expires_boottime_nanoseconds() {
        return Err(Box::new(Changed));
    }
    let expires = super::storage_create_plan::plan_expiry_v1(
        sample, cutoff, policy_expires, lease.authority_expires_seconds(),
    )?;
    let (body, template_request_bytes) = deadline_body_v1(protected, cutoff)?;
    let plan = plan_from_body_v1(
        protected, policy_digest, lease, sample.wall_seconds(), expires,
        revocation_scope, template_request_bytes,
    )?;
    let (signature_shape, request_shape) = super::storage_create_apply_request_shape_v1(
        &plan, &authority, &body, protected.catalog(),
        lease.canonical_lease(), lease.canonical_signature(),
    )?;
    let preparation = BrokerPlanPreparation::new(plan.clone(), authority)?;
    Ok(StorageCreatePlanPreparationDataV1 {
        plan, preparation, signature_shape, request_shape,
    })
}

/// Compares the exact independently admitted Apply plan and signing statement.
///
/// This performs no signing or native admission. A genuine purpose-specific
/// Root/Controller owner must remain held through the later sign and posts;
/// historical bytes, this successful comparison or its public trust cannot
/// construct that loan or convert the old Prepare grant into Apply authority.
///
/// # Errors
/// Rejects a changed method/argument commitment, catalog, assignment, lease,
/// public signing statement, validity window, policy, scope or wire bound.
#[allow(clippy::too_many_arguments)]
pub fn prepare_admitted_storage_create_apply_plan_v1(
    protected: &ProtectedStorageCreateApplyDataV1<'_>,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
    canonical_plan: &[u8],
    canonical_statement: &[u8],
) -> Result<BrokerPlanPreparation> {
    if cutoff > protected.preparation_expires_boottime_nanoseconds() {
        return Err(Box::new(Changed));
    }
    let plan = aos_sandbox_model::format::decode_broker_authorization_plan(
        canonical_plan, aos_sandbox_model::DecodeLimits::default(),
    )?;
    super::storage_create_plan::require_admitted_clock_v1(
        sample, cutoff, plan.issued_seconds(), plan.expires_seconds(),
        lease.authority_issued_seconds(), lease.authority_expires_seconds(),
    )?;
    let (body, template_request_bytes) = deadline_body_v1(protected, cutoff)?;
    drop(body);
    let expected = plan_from_body_v1(
        protected, policy_digest, lease, plan.issued_seconds(), plan.expires_seconds(),
        revocation_scope, template_request_bytes,
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
    Ok(preparation)
}

fn deadline_body_v1(
    protected: &ProtectedStorageCreateApplyDataV1<'_>,
    cutoff: u64,
) -> Result<(Vec<u8>, usize)> {
    // Fixed identity is used only for sizing. Actual dispatch retains its
    // separately committed request identity and unchanged admission deadline.
    let deadline_free = protected.deadline_free_request_body_v1([1; 16])?;
    let template_request_bytes = usize::try_from(
        crate::dispatch_template::deadline_free_template_request_bytes_v1(&deadline_free)?,
    )?;
    let mut request = ApplyStorageRequest::decode_from_slice(&deadline_free)?;
    drop(deadline_free);
    request.header.as_option_mut().ok_or(Changed)?.deadline_boottime_nanoseconds = cutoff;
    Ok((request.encode_to_vec(), template_request_bytes))
}

#[allow(clippy::too_many_arguments)]
fn plan_from_body_v1(
    protected: &ProtectedStorageCreateApplyDataV1<'_>,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    issued: i64,
    expires: i64,
    revocation_scope: RevocationScopeId,
    body_bytes: usize,
) -> Result<BrokerAuthorizationPlan> {
    let grant = BrokerGrant::new(
        BrokerVerb::StorageCreateWorkspace, BrokerGrantTarget::Assignment,
        protected.argument_commitment(), u32::try_from(body_bytes)?, 0,
    )?;
    Ok(BrokerAuthorizationPlan::new(
        BrokerAudience::Storage, ProtocolId::StorageBroker, ProtocolVersion::new(1, 0),
        protected.assignment(), lease.node(), lease.signer().clone(), vec![grant],
        policy_digest, revocation_scope, issued, expires,
        vec![FeatureRef::new("aos.sandbox.authorization.signed-plan-lease", 1, 0)?],
    )?)
}
