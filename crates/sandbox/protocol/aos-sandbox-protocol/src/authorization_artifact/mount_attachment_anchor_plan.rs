//! Shares the unsigned Mount namespace-anchor plan recipe between both issuers.
//!
//! The caller funds construction and independently holds its genuine Root or
//! Controller native admission. These unsigned models supply no native grant.

use std::error::Error;
use aos_sandbox_model::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, FeatureRef, ObjectDigest,
    ProtocolId, RawPairedClockSample, RevocationScopeId,
};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use crate::mount_attachment_anchor::{
    ValidatedAttachmentAnchorRequestV1, canonical_attachment_anchor_semantics_v1,
};
use super::{BrokerPlanPreparation, SigningAuthority};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Retains one unsigned exact-purpose canonical plan and its signing statement.
pub struct AttachmentAnchorPlanPreparationDataV1 {
    plan: BrokerAuthorizationPlan,
    preparation: BrokerPlanPreparation,
}

impl AttachmentAnchorPlanPreparationDataV1 {
    /// Borrows the complete independently reproducible plan DATA.
    #[must_use]
    pub const fn plan_v1(&self) -> &BrokerAuthorizationPlan { &self.plan }

    pub(in crate::authorization_artifact) fn into_preparation_v2(self) -> BrokerPlanPreparation {
        self.preparation
    }

    /// Borrows the same unsigned signing preparation.
    #[must_use]
    pub const fn preparation_v1(&self) -> &BrokerPlanPreparation { &self.preparation }
}

/// Prepares the sole unsigned attachment-anchor plan from current input DATA.
///
/// # Errors
/// Refuses expired policy/lease/cutoff, a noncanonical request or invalid public
/// signing authority, grant target, schema length or assignment coordinates.
#[allow(clippy::too_many_arguments)]
pub fn prepare_attachment_anchor_plan_v1(
    request: &ValidatedAttachmentAnchorRequestV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
) -> Result<AttachmentAnchorPlanPreparationDataV1> {
    let expires = super::storage_create_plan::plan_expiry_v1(
        sample, cutoff, policy_expires, lease.authority_expires_seconds(),
    )?;
    let plan = plan_v1(request, policy_digest, lease, sample.wall_seconds(), expires, revocation_scope)?;
    let preparation = BrokerPlanPreparation::new(plan.clone(), authority)?;
    Ok(AttachmentAnchorPlanPreparationDataV1 { plan, preparation })
}

/// Compares the exact new Root admission without adopting its parsed bytes.
///
/// # Errors
/// Refuses another plan/statement/lease/policy/target, or validity outside the
/// unchanged actual caller horizon. No signature or native owner is created.
#[allow(clippy::too_many_arguments)]
pub fn prepare_admitted_attachment_anchor_plan_v1(
    request: &ValidatedAttachmentAnchorRequestV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
    canonical_plan: &[u8],
    canonical_statement: &[u8],
) -> Result<BrokerPlanPreparation> {
    let plan = aos_sandbox_model::format::decode_broker_authorization_plan(
        canonical_plan, aos_sandbox_model::DecodeLimits::default(),
    )?;
    super::storage_create_plan::require_admitted_clock_v1(
        sample, cutoff, plan.issued_seconds(), plan.expires_seconds(),
        lease.authority_issued_seconds(), lease.authority_expires_seconds(),
    )?;
    let expected = plan_v1(request, policy_digest, lease, plan.issued_seconds(), plan.expires_seconds(), revocation_scope)?;
    if expected != plan { return Err(Box::new(Changed)); }
    let preparation = BrokerPlanPreparation::new(plan, authority)?;
    if preparation.canonical_plan() != canonical_plan
        || preparation.signing_request().canonical_statement() != canonical_statement
    {
        return Err(Box::new(Changed));
    }
    Ok(preparation)
}

fn plan_v1(
    request: &ValidatedAttachmentAnchorRequestV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    issued: i64,
    expires: i64,
    revocation_scope: RevocationScopeId,
) -> Result<BrokerAuthorizationPlan> {
    let body = request.deadline_free_request_body_v1([1; 16])?;
    let encoded = crate::dispatch_template::deadline_free_template_request_bytes_v1(&body)?;
    let canonical = canonical_attachment_anchor_semantics_v1(request)?;
    let grant = BrokerGrant::new(canonical.verb(), canonical.target(), canonical.commitment(),
        u32::try_from(encoded)?, 0)?;
    Ok(BrokerAuthorizationPlan::new(
        BrokerAudience::Mount, ProtocolId::MountBroker, request.header().protocol_version(),
        request.fence().broker_assignment()?, lease.node(), lease.signer().clone(), vec![grant],
        policy_digest, revocation_scope, issued, expires,
        vec![FeatureRef::new("aos.sandbox.authorization.signed-plan-lease", 1, 0)?],
    )?)
}

#[derive(Debug, thiserror::Error)]
#[error("the original Mount attachment-anchor admission differs")]
struct Changed;
