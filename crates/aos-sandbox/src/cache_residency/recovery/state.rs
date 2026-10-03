//! Shared validation for opaque pending-effect terminal state.

use super::*;

pub(super) fn validate_pending_cancellation(
    cancellation: PendingCancellationV1,
    target: ObjectDigest,
    target_valid_until: Option<u64>,
) -> Result<(), RecoveryError> {
    if cancellation.target != target
        || cancellation.observed_at == 0
        || cancellation.target_valid_until == 0
        || target_valid_until.is_some_and(|deadline| deadline != cancellation.target_valid_until)
        || cancellation.authority.as_bytes() == &[0; 32]
        || cancellation.evidence.as_bytes() == &[0; 32]
        || cancellation.digest != pending_cancellation_digest(&cancellation)
        || (cancellation.outcome == PendingCancellationOutcomeV1::ExpiredNoEffectObserved
            && cancellation.observed_at < cancellation.target_valid_until)
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}

/// Selects why an incomplete effect may terminate without a receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PendingCancellationOutcomeV1 {
    /// A trusted observation proved the effect was never installed.
    NoEffectObserved = 1,
    /// The target deadline passed and a trusted observation proved no effect.
    ExpiredNoEffectObserved = 2,
}

/// Carries opaque current authority for one observed pending-effect cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingCancellationV1 {
    pub(super) target: ObjectDigest,
    pub(super) outcome: PendingCancellationOutcomeV1,
    pub(super) observed_at: u64,
    pub(super) target_valid_until: u64,
    pub(super) authority: ObjectDigest,
    pub(super) evidence: ObjectDigest,
    pub(super) digest: ObjectDigest,
}

impl PendingCancellationV1 {
    /// Issues cancellation from a fresh exact protected observation capability.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for stale authority, sentinel evidence, or an
    /// expiry outcome observed before the target deadline.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        target: ObjectDigest,
        operation: Option<OperationId>,
        root_custody: ObjectDigest,
        generation: u64,
        target_valid_until: u64,
        outcome: PendingCancellationOutcomeV1,
        observed_at: u64,
        evidence: ObjectDigest,
    ) -> Result<Self, RecoveryError> {
        if target.as_bytes() == &[0; 32]
            || observed_at == 0
            || target_valid_until == 0
            || evidence.as_bytes() == &[0; 32]
            || (outcome == PendingCancellationOutcomeV1::ExpiredNoEffectObserved
                && observed_at < target_valid_until)
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        let subject = pending_cancellation_subject(
            target,
            operation,
            outcome,
            observed_at,
            target_valid_until,
            evidence,
        );
        let scope = CacheAuthorityScopeV1::new(
            partition,
            subject,
            operation,
            target,
            root_custody,
            generation,
            capability.scope().valid_until(),
        )?;
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::PendingCancellation,
            scope,
            observed_at,
        )?;
        let mut cancellation = Self {
            target,
            outcome,
            observed_at,
            target_valid_until,
            authority: capability.record_digest(),
            evidence,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        cancellation.digest = pending_cancellation_digest(&cancellation);
        Ok(cancellation)
    }
}

pub(super) fn pending_cancellation_subject(
    target: ObjectDigest,
    operation: Option<OperationId>,
    outcome: PendingCancellationOutcomeV1,
    observed_at: u64,
    target_valid_until: u64,
    evidence: ObjectDigest,
) -> ObjectDigest {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.pending-cancellation-subject.v1\0");
    hasher.update(target.as_bytes());
    hasher.update(operation.map_or([0; 16], |value| value.into_bytes()));
    hasher.update([outcome as u8]);
    hasher.update(observed_at.to_be_bytes());
    hasher.update(target_valid_until.to_be_bytes());
    hasher.update(evidence.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn pending_cancellation_digest(cancellation: &PendingCancellationV1) -> ObjectDigest {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.pending-cancellation.v1\0");
    hasher.update(cancellation.target.as_bytes());
    hasher.update([cancellation.outcome as u8]);
    hasher.update(cancellation.observed_at.to_be_bytes());
    hasher.update(cancellation.target_valid_until.to_be_bytes());
    hasher.update(cancellation.authority.as_bytes());
    hasher.update(cancellation.evidence.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
