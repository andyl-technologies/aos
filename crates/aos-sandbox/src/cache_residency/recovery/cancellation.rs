//! Fresh Native pending-effect cancellation issuance over historical DATA.

use super::*;

/// Retains the actual fresh cancellation capability join.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingCancellationV1(data::PendingCancellationDataV1);

impl std::ops::Deref for PendingCancellationV1 {
    type Target = data::PendingCancellationDataV1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PendingCancellationV1 {
    /// Issues cancellation from the same fresh protected observation capability.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for invalid historical facts or stale authority.
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
        let subject = data::pending_cancellation_subject_data_v1(
            target,
            operation,
            outcome,
            observed_at,
            target_valid_until,
            evidence,
        );
        let scope = crate::cache_residency::domain::new_cache_authority_scope_v1(
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
        let mut cancellation = data::PendingCancellationDataV1 {
            target,
            outcome,
            observed_at,
            target_valid_until,
            authority: capability.record_digest(),
            evidence,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        cancellation.digest = data::pending_cancellation_digest_data_v1(&cancellation);
        Ok(Self(cancellation))
    }
}
