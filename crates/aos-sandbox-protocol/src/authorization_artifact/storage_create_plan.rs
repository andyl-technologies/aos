//! Shares the nonissuing Create Prepare plan, expiry and normalized byte shape.
//!
//! Protected Root and Controller owners independently supply their own current
//! proposal, policy digest, verified lease, public signing authority and clock.
//! This pure constructor returns unsigned DATA. It opens no file, holds no
//! payer, signs no statement and creates no permission to dispatch Prepare.

use std::error::Error;
use aos_proto::aos::sandbox::local::v1::PrepareStorageCatalogRequest;
use buffa::Message as _;
use aos_sandbox_core::{BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
    BrokerGrantTarget, BrokerVerb, FeatureRef, ObjectDigest, ProtocolId,
    ProtocolVersion, RawPairedClockSample, RevocationScopeId};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use crate::semantics::ProtectedStorageCreatePreparationV1;
use super::{BrokerPlanPreparation, SigningAuthority};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug, thiserror::Error)]
#[error("the original Create Storage plan or unchanged expiry is invalid")]
struct Changed;

/// Retains an unsigned preparation and its nonissuing normalized wire shape.
pub struct StorageCreatePlanPreparationDataV1 {
    /// The actual unsigned plan with its original validity interval.
    pub plan: BrokerAuthorizationPlan,
    /// The same canonical plan and public-authority signing preparation.
    pub preparation: BrokerPlanPreparation,
    /// A zero signature envelope used solely for byte sizing.
    pub signature_shape: Vec<u8>,
    /// A complete zero-authentication request used solely for byte sizing.
    pub request_shape: Vec<u8>,
}

/// Prepares one common Create plan and conservative normalized request shape.
///
/// The caller remains responsible for independently proving every supplied
/// original and paying before construction. The actual plan keeps its sampled
/// validity; only the separate sizing artifact normalizes CBOR time widths.
///
/// # Errors
/// Rejects an exhausted unchanged cutoff, expired lease/policy, malformed
/// proposal/header/grant, public signing authority or encoding overflow.
#[allow(clippy::too_many_arguments)]
pub fn prepare_storage_create_plan_v1(
    protected: &ProtectedStorageCreatePreparationV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
) -> Result<StorageCreatePlanPreparationDataV1> {
    let expires = plan_expiry_v1(
        sample, cutoff, policy_expires, lease.authority_expires_seconds(),
    )?;

    // This ID has fixed width only. The real request ID is derived from the
    // completed signature after genuine U admission; these bytes cannot be
    // dispatched or used to construct a signed request model.
    let mut body = PrepareStorageCatalogRequest::decode_from_slice(
        &protected.deadline_free_request_body([1; 16])?,
    )?;
    body.header.as_option_mut().ok_or(Changed)?.deadline_boottime_nanoseconds = cutoff;
    let body = body.encode_to_vec();
    let plan = plan_from_body_v1(
        protected, policy_digest, lease, sample.wall_seconds(), expires,
        revocation_scope, body.len(),
    )?;

    // Normalize only the two variable-width validity fields for sizing.
    // The actual unsigned signing preparation retains its original times.
    let (signature_shape, request_shape) = super::storage_create_prepare_request_shape_v1(
        &plan, &authority, &body, lease.canonical_lease(), lease.canonical_signature(),
    )?;
    let preparation = BrokerPlanPreparation::new(plan.clone(), authority)?;
    Ok(StorageCreatePlanPreparationDataV1 {
        plan, preparation, signature_shape, request_shape,
    })
}

// Both the original proposal and the actual admitted signing check use one
// exact grant/plan constructor, including features and request-byte bound.
fn plan_from_body_v1(
    protected: &ProtectedStorageCreatePreparationV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    issued: i64,
    expires: i64,
    revocation_scope: RevocationScopeId,
    body_bytes: usize,
) -> Result<BrokerAuthorizationPlan> {
    let grant = BrokerGrant::new(
        BrokerVerb::StoragePrepareCatalog, BrokerGrantTarget::Assignment,
        protected.argument_commitment(), u32::try_from(body_bytes)?, 0,
    )?;
    let required = FeatureRef::new("aos.sandbox.authorization.signed-plan-lease", 1, 0)?;
    Ok(BrokerAuthorizationPlan::new(
        BrokerAudience::Storage, ProtocolId::StorageBroker, ProtocolVersion::new(1, 0),
        protected.assignment(), lease.node(), lease.signer().clone(), vec![grant],
        policy_digest, revocation_scope, issued, expires, vec![required],
    )?)
}

/// Checks the original admitted Create plan and exact public signing statement.
///
/// This is pure semantic DATA validation. Its caller must first borrow the
/// genuine completed Root8/U original, admit all construction and supply its
/// own protected proposal, live lease, public signer/scope and actual clock.
/// No parsed bytes or successful return can construct a native signing loan.
///
/// # Errors
/// Rejects noncanonical or changed Root plan/statement, a different grant,
/// assignment/node/lease/policy/scope/key, stale time or exhausted fixed cutoff.
#[allow(clippy::too_many_arguments)]
pub fn prepare_admitted_storage_create_plan_v1(
    protected: &ProtectedStorageCreatePreparationV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
    canonical_plan: &[u8],
    canonical_statement: &[u8],
) -> Result<BrokerPlanPreparation> {
    let plan = aos_sandbox_core::format::decode_broker_authorization_plan(
        canonical_plan, aos_sandbox_core::DecodeLimits::default(),
    )?;
    require_admitted_clock_v1(
        sample, cutoff, plan.issued_seconds(), plan.expires_seconds(),
        lease.authority_issued_seconds(), lease.authority_expires_seconds(),
    )?;

    let mut body = PrepareStorageCatalogRequest::decode_from_slice(
        &protected.deadline_free_request_body([1; 16])?,
    )?;
    body.header.as_option_mut().ok_or(Changed)?.deadline_boottime_nanoseconds = cutoff;
    let expected = plan_from_body_v1(
        protected, policy_digest, lease, plan.issued_seconds(), plan.expires_seconds(),
        revocation_scope, body.encode_to_vec().len(),
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

pub(super) fn require_admitted_clock_v1(
    sample: RawPairedClockSample,
    cutoff: u64,
    issued: i64,
    expires: i64,
    lease_issued: i64,
    lease_expires: i64,
) -> Result<()> {
    if sample.boottime_nanoseconds() >= cutoff
        || sample.wall_seconds() < issued
        || sample.wall_seconds() >= expires
        || issued < lease_issued
        || expires > lease_expires
    {
        return Err(Box::new(Changed));
    }
    Ok(())
}

pub(super) fn plan_expiry_v1(sample: RawPairedClockSample, cutoff: u64,
    policy_expires: i64, lease_expires: i64,
) -> Result<i64> {
    // Drop the fractional second rather than extending the unchanged original
    // monotonic cutoff when converting it to the plan's integer wall validity.
    let seconds = cutoff.checked_sub(sample.boottime_nanoseconds())
        .and_then(|remaining| remaining.checked_div(1_000_000_000))
        .and_then(|seconds| seconds.checked_sub(1)).ok_or(Changed)?;
    let original_expiry = sample.wall_seconds().checked_add(i64::try_from(seconds)?)
        .ok_or(Changed)?;
    let expires = original_expiry.min(policy_expires).min(lease_expires);
    if expires <= sample.wall_seconds() { return Err(Box::new(Changed)); }
    Ok(expires)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    fn sample() -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(), [2; 16],
            100, 10_500_000_000,
        ).unwrap()
    }

    #[test]
    fn admitted_signing_requires_both_real_clock_and_original_lease_window() {
        let current = sample();

        assert!(require_admitted_clock_v1(current, 20_000_000_000, 99, 109, 90, 110).is_ok());
        assert!(require_admitted_clock_v1(current, current.boottime_nanoseconds(), 99, 109, 90, 110).is_err());
        assert!(require_admitted_clock_v1(current, 20_000_000_000, 101, 109, 90, 110).is_err());
        assert!(require_admitted_clock_v1(current, 20_000_000_000, 99, 100, 90, 110).is_err());
        assert!(require_admitted_clock_v1(current, 20_000_000_000, 89, 109, 90, 110).is_err());
        assert!(require_admitted_clock_v1(current, 20_000_000_000, 99, 111, 90, 110).is_err());
    }

    #[test]
    fn prospective_plan_never_renews_the_original_monotonic_or_signed_expiry() {
        let sample = sample();

        assert_eq!(plan_expiry_v1(sample, 20_900_000_000, 500, 500).unwrap(), 109);
        assert_eq!(plan_expiry_v1(sample, 20_900_000_000, 107, 500).unwrap(), 107);
        assert_eq!(plan_expiry_v1(sample, 20_900_000_000, 500, 106).unwrap(), 106);
        assert!(plan_expiry_v1(sample, 11_400_000_000, 500, 500).is_err());
        assert!(plan_expiry_v1(sample, 20_900_000_000, 100, 500).is_err());
    }
}
