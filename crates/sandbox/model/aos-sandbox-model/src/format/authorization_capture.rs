//! Retains complete canonical authorization DATA and original parse failures.
//!
//! These destinations share the ordinary Core codecs. Canonical prevalidation
//! still precedes schema collection allocation. No captured model is a trusted
//! key, verified signature, lease admission or permission to perform effects.

use std::error::Error;
use crate::{BrokerAuthorizationPlan, BrokerGrant, FeatureRef, ObjectDescriptor, OwnershipLease};
use crate::broker_authorization::InvalidBrokerAuthorizationPlan;
use crate::model::{InvalidTrustModel, KeyReference, Signature, SignatureStatement};
use super::decode_attempt::{DecodeAttempt, DecodeFailure};
use super::{CanonicalCborError, DecodeLimits};

/// Retains the final BrokerPlan or its exact canonical and typed refusal.
#[derive(Default)]
pub struct BrokerAuthorizationPlanDecodeCaptureV1 {
    attempt: DecodeAttempt<BrokerAuthorizationPlan>,
}

/// Retains the final detached signature or its exact typed refusal.
#[derive(Default)]
pub struct SignatureDecodeCaptureV1 {
    attempt: DecodeAttempt<Signature>,
}

/// Retains the final OwnershipLease or its exact canonical and typed refusal.
#[derive(Default)]
pub struct OwnershipLeaseDecodeCaptureV1 {
    attempt: DecodeAttempt<OwnershipLease>,
}

impl BrokerAuthorizationPlanDecodeCaptureV1 {
    /// Constructs inert fixed destinations without allocation or verification.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the original returned canonical refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&CanonicalCborError> {
        self.attempt.failure()
    }

    /// Borrows the reached typed constructor or registry cause before projection.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn Error + 'static)> {
        self.attempt.cause()
    }

    /// Borrows completed unverified model DATA without retaining rejected local prefixes.
    #[must_use]
    pub fn model(&self) -> Option<&BrokerAuthorizationPlan> {
        self.attempt.model()
    }

    /// Transfers completed model DATA to its actual caller at most once.
    ///
    /// # Errors
    /// Refuses failed, incomplete, repeated or already transferred capture.
    pub fn take_model_once(&mut self) -> Result<BrokerAuthorizationPlan, CanonicalCborError> {
        self.attempt.take_model_once()
    }
}

impl SignatureDecodeCaptureV1 {
    /// Counts actual fixed subject/key/policy/constructor and once destinations.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize { 22 }

    /// Bounds raw/typed/error text backing from the actual signature extent.
    ///
    /// Excludes embedded capsule storage and the caller's original bytes.
    #[must_use]
    pub fn receiving_dynamic_bytes_v1(actual_bytes: usize) -> Option<usize> {
        // Raw text, completed descriptor/key strings, registry-owned text and
        // canonical error projection/move overlap are separate actual lanes.
        actual_bytes.checked_mul(8)
    }

    /// Constructs inert fixed destinations without allocation or verification.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the original returned canonical refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&CanonicalCborError> {
        self.attempt.failure()
    }

    /// Borrows the reached typed constructor or registry cause before projection.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn Error + 'static)> {
        self.attempt.cause()
    }

    /// Borrows completed unverified model DATA without retaining rejected local prefixes.
    #[must_use]
    pub fn model(&self) -> Option<&Signature> {
        self.attempt.model()
    }

    /// Transfers completed model DATA to its actual caller at most once.
    ///
    /// # Errors
    /// Refuses failed, incomplete, repeated or already transferred capture.
    pub fn take_model_once(&mut self) -> Result<Signature, CanonicalCborError> {
        self.attempt.take_model_once()
    }
}

impl OwnershipLeaseDecodeCaptureV1 {
    /// Constructs inert fixed destinations without allocation or verification.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the original returned canonical refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&CanonicalCborError> {
        self.attempt.failure()
    }

    /// Borrows the reached typed constructor or registry cause before projection.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn Error + 'static)> {
        self.attempt.cause()
    }

    /// Borrows completed unverified model DATA without retaining rejected local prefixes.
    #[must_use]
    pub fn model(&self) -> Option<&OwnershipLease> {
        self.attempt.model()
    }

    /// Transfers completed model DATA to its actual caller at most once.
    ///
    /// # Errors
    /// Refuses failed, incomplete, repeated or already transferred capture.
    pub fn take_model_once(&mut self) -> Result<OwnershipLease, CanonicalCborError> {
        self.attempt.take_model_once()
    }
}

/// Decodes a BrokerPlan into its once-only complete result.
///
/// # Errors
/// Preserves ordinary canonical/schema/registry/constructor failures and reentry.
pub fn decode_broker_authorization_plan_retaining_v1(
    bytes: &[u8],
    limits: DecodeLimits,
    capture: &mut BrokerAuthorizationPlanDecodeCaptureV1,
) -> Result<(), CanonicalCborError> {
    capture.attempt.begin()?;
    let result = super::broker_authorization::decode_plan_engine(bytes, limits);
    capture.attempt.finish(result)
}

/// Decodes a detached signature into its once-only complete result.
///
/// # Errors
/// Preserves ordinary canonical/schema/usage/time refusals and repeated entry.
pub fn decode_signature_retaining_v1(
    bytes: &[u8],
    limits: DecodeLimits,
    capture: &mut SignatureDecodeCaptureV1,
) -> Result<(), CanonicalCborError> {
    capture.attempt.begin()?;
    let result = super::trust::decode_signature_engine(bytes, limits);
    capture.attempt.finish(result)
}

/// Retains the sole fixed-field OwnershipLease decoder's actual whole Result.
///
/// # Errors
/// Preserves its complete canonical/lease model refusal or repeated capture.
pub fn decode_ownership_lease_retaining_v1(
    bytes: &[u8],
    limits: DecodeLimits,
    capture: &mut OwnershipLeaseDecodeCaptureV1,
) -> Result<(), CanonicalCborError> {
    capture.attempt.begin()?;
    let result = super::ownership_lease::decode_lease_engine(bytes, limits);
    capture.attempt.finish(result)
}


/// Prices reached Core authorization representation, without an account or grant.
///
/// P must bound the actual complete canonical artifact bytes already held by
/// the payer. Complete canonical prevalidation precedes every collection
/// allocation: even schema-invalid array elements occupy at least one byte.
/// Announced truncated arrays therefore do not enter this bound as allocations.
/// Returns dynamic bytes and metadata cells, excluding embedded capsule storage.
#[must_use]
pub fn authorization_artifact_dynamic_footprint_v1(actual_bytes: usize) -> Option<(u64, u64)> {
    authorization_artifact_plan_set_dynamic_footprint_v1(actual_bytes, 1)
}

/// Bounds co-resident plans from the actual aggregate bytes and closed plan count.
///
/// Each plan keeps the same 1024-grant/64-feature decoder ceilings. Aggregate
/// byte prevalidation still bounds all actual element/text bytes. This passive
/// supplier constructs no model or authority; `None` reports checked overflow.
#[must_use]
pub fn authorization_artifact_plan_set_dynamic_footprint_v1(
    actual_bytes: usize, plan_count: usize,
) -> Option<(u64, u64)> {
    let plans = u64::try_from(plan_count).ok()?;
    let p = u64::try_from(actual_bytes).ok()?;
    let grants = p.min(1_024_u64.checked_mul(plans)?);
    let features = p.min(64_u64.checked_mul(plans)?);
    let grant_bytes = grants.checked_mul(u64::try_from(std::mem::size_of::<BrokerGrant>()).ok()?)?;
    let feature_bytes = features.checked_mul(u64::try_from(std::mem::size_of::<FeatureRef>()).ok()?)?;
    // Exact-capacity collection prefixes, constructor/move carriers, and their
    // simultaneous backing are paid dominantly. Raw text, typed registry error
    // text and canonical-error projection backing retain separate copies.
    let backing = p.checked_mul(12)?.checked_add(grant_bytes.checked_mul(3)?)?
        .checked_add(feature_bytes.checked_mul(3)?)?;
    // Two signature lanes each hold subject/key/policy strings and error text.
    // Their actual encoded lengths together are bounded by the same P; the
    // extra copies above also cover the plan's current feature/key strings.
    let cells = grants.checked_mul(3)?.checked_add(features.checked_mul(9)?)?;
    let temporary = std::mem::size_of::<DecoderTemporariesV1>();
    Some((backing.checked_add(u64::try_from(temporary).ok()?)?, cells))
}

// Actual non-embedded decoder return/current-field carriers. This structure is
// only a compiled-layout supplier; it is never constructed or used as authority.
#[allow(dead_code)]
struct DecoderTemporariesV1 {
    plan_return: BrokerAuthorizationPlan,
    plan_constructor: Result<BrokerAuthorizationPlan, InvalidBrokerAuthorizationPlan>,
    current_key: KeyReference,
    current_feature: FeatureRef,
    current_descriptor: ObjectDescriptor,
    signature_return: Signature,
    statement_return: SignatureStatement,
    statement_constructor: Result<SignatureStatement, InvalidTrustModel>,
    lease_return: OwnershipLease,
    canonical_return: DecodeFailure,
}

/// Counts fixed embedded artifact destinations plus transient decoder controls.
#[must_use]
pub fn authorization_artifact_metadata_cells_v1() -> Option<usize> {
    // Plan: key3 + authority1 + vectors2 + feature4 + constructor1 + attempt3.
    // Each signature: descriptor5*2 + key3 + parts3 + role1 + constructor1
    // + statement1 + attempt3. Lease: assignment/constructor results, returned result and two once controls.
    // The ten named temporary fields above coexist with the embedded capsules.
    14usize.checked_add(22usize.checked_mul(2)?)?.checked_add(5)?.checked_add(10)
}


#[cfg(test)]
mod tests {
    use crate::format::cbor::Decoder;
    use super::*;
    use crate::{AssignmentEpoch, IncarnationId, NodeId, ObjectDigest, SandboxId};
    use crate::ownership_lease::{InvalidOwnershipLease, LeaseAssignment};

    #[test]
    fn lease_constructor_refusal_keeps_actual_typed_result() {
        let assignment = LeaseAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            ObjectDigest::from_bytes([4; 32]),
        )
        .unwrap();
        let lease = OwnershipLease::new(
            assignment,
            NodeId::from_bytes([5; 16]),
            1,
            100,
            200,
            1,
            [6; 16],
        )
        .unwrap();
        let mut bytes = super::super::encode_ownership_lease(&lease);
        let mut decoder = Decoder::new(&bytes, DecodeLimits::default()).unwrap();
        decoder.array(8).unwrap();
        decoder.exact("version", 1).unwrap();
        decoder.array(4).unwrap();
        decoder.bytes(16).unwrap();
        decoder.bytes(16).unwrap();
        decoder.unsigned().unwrap();
        decoder.bytes(32).unwrap();
        decoder.bytes(16).unwrap();
        let generation = decoder.position();
        drop(decoder);
        assert_eq!(bytes[generation], 1);
        bytes[generation] = 0;
        let mut capture = OwnershipLeaseDecodeCaptureV1::new();

        let retained =
            decode_ownership_lease_retaining_v1(&bytes, DecodeLimits::default(), &mut capture)
                .unwrap_err();
        let ordinary =
            super::super::decode_ownership_lease(&bytes, DecodeLimits::default()).unwrap_err();

        assert_eq!(retained, ordinary);
        let cause = capture
            .cause()
            .unwrap()
            .downcast_ref::<InvalidOwnershipLease>()
            .unwrap();
        assert_eq!(*cause, InvalidOwnershipLease::Unspecified);
        assert!(std::ptr::eq(
            cause,
            capture
                .cause()
                .unwrap()
                .downcast_ref::<InvalidOwnershipLease>()
                .unwrap()
        ));
    }
}

#[cfg(test)]
mod plan_set_receiving_tests {
    use super::*;

    #[test]
    fn separate_plans_do_not_share_a_single_grant_vector_ceiling() {
        let one = authorization_artifact_dynamic_footprint_v1(32 * 1024).unwrap().0;
        let two = authorization_artifact_plan_set_dynamic_footprint_v1(32 * 1024, 2).unwrap().0;

        assert!(two > one);
        assert_eq!(authorization_artifact_plan_set_dynamic_footprint_v1(32 * 1024, 1).unwrap().0, one);
        assert!(authorization_artifact_plan_set_dynamic_footprint_v1(usize::MAX, usize::MAX).is_none());
    }
}
