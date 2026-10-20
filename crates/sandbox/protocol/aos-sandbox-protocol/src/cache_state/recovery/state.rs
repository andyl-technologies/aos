//! Shared validation for opaque pending-effect terminal state.

use super::*;

pub(crate) fn validate_pending_cancellation(
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

/// Records historical pending-effect cancellation DATA without current authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingCancellationV1 {
    /// Exact historical pending-effect commitment.
    pub target: ObjectDigest,
    /// Historical reason for cancellation.
    pub outcome: PendingCancellationOutcomeV1,
    /// Recorded observation time.
    pub observed_at: u64,
    /// Recorded deadline of the pending effect.
    pub target_valid_until: u64,
    /// Historical authority-record commitment.
    pub authority: ObjectDigest,
    /// Historical native-observation commitment.
    pub evidence: ObjectDigest,
    /// Canonical cancellation commitment.
    pub digest: ObjectDigest,
}

#[doc(hidden)]
pub fn pending_cancellation_subject(
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

#[doc(hidden)]
pub fn pending_cancellation_digest(cancellation: &PendingCancellationV1) -> ObjectDigest {
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
