//! Owns the actual partial payload and durable envelope of one auxiliary decode.

use super::*;
use aos_sandbox_protocol::domain_ledger::lifecycle_model::{LifecycleDependencyEdgeV1, LifecycleResourceV1};
use crate::lifecycle::coordination::LifecycleSnapshotAdmittedSourceV2;
use crate::lifecycle::{
    LifecycleBootInventoryV1, LifecycleCancelOutcomeV1, LifecycleCoordinationTransactionV1,
    LifecycleOperationDecodeOriginalV1, LifecycleOperationV1,
    LifecycleRetentionLedgerEntryV1,
};

/// Retains one auxiliary decoder's reached graph and original failure.
///
/// Positive models may move only after the complete envelope validates. Failed
/// partials remain resident, and reentry never replaces their original cause.
#[derive(Default)]
pub struct LifecycleAuxiliaryDecodeOriginalV1 {
    pub(in crate::lifecycle) model_failure: Option<LifecycleModelError>,
    pub(in crate::lifecycle) length_failure: Option<std::num::TryFromIntError>,
    pub(in crate::lifecycle) entered: bool,
    pub(in crate::lifecycle) returned: Option<Result<(), LifecycleModelError>>,
    pub(in crate::lifecycle) reentry: Option<LifecycleModelError>,
    pub(in crate::lifecycle) nested: LifecycleOperationDecodeOriginalV1,
    pub(in crate::lifecycle) operation: Option<LifecycleOperationV1>,
    pub(in crate::lifecycle) outcome: Option<LifecycleCancelOutcomeV1>,
    pub(in crate::lifecycle) dependencies: Vec<LifecycleResourceV1>,
    pub(in crate::lifecycle) edges: Vec<LifecycleDependencyEdgeV1>,
    pub(in crate::lifecycle) postorder: Vec<LifecycleResourceV1>,
    pub(in crate::lifecycle) coordination: Option<LifecycleCoordinationTransactionV1>,
    pub(in crate::lifecycle) source: Option<LifecycleSnapshotAdmittedSourceV2>,
    pub(in crate::lifecycle) entries: Vec<LifecycleRetentionLedgerEntryV1>,
    pub(in crate::lifecycle) resources: Vec<LifecycleResourceV1>,
    pub(in crate::lifecycle) payload: Option<LifecycleAuxiliaryPayloadV1>,
    pub(in crate::lifecycle) record: Option<LifecycleAuxiliaryRecordV1>,
}

impl LifecycleAuxiliaryDecodeOriginalV1 {
    /// Constructs an inert auxiliary decode destination.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes the protected envelope through the ordinary auxiliary engine.
    ///
    /// # Errors
    ///
    /// Returns the actual format/model error, or `InvalidTransition` on reentry.
    pub fn decode_from_protected_envelope_once(
        &mut self,
        encoded: &[u8],
        verification: &LifecycleReplayVerificationV1,
    ) -> Result<(), LifecycleModelError> {
        self.decode_once(encoded, verification, false)
    }

    pub(in crate::lifecycle) fn decode_once(
        &mut self,
        encoded: &[u8],
        verification: &LifecycleReplayVerificationV1,
        require_previously_accepted_digest: bool,
    ) -> Result<(), LifecycleModelError> {
        if self.entered {
            self.reentry.get_or_insert(LifecycleModelError::InvalidTransition);
            return Err(LifecycleModelError::InvalidTransition);
        }
        self.entered = true;
        let result = super::decode_lifecycle_auxiliary_record_into(
            encoded, verification, require_previously_accepted_digest, self,
        );
        self.returned = Some(result);
        result
    }

    /// Borrows the first actual auxiliary decode refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&LifecycleModelError> {
        self.nested.failure().or(self.model_failure.as_ref())
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err()))
            .or(self.reentry.as_ref())
    }

    /// Borrows the first refusal, including its original integer conversion cause.
    #[must_use]
    pub fn failure_view_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.nested.failure_view_v1()
            .or_else(|| self.model_failure.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.length_failure.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.failure().map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    /// Borrows the actual successful envelope.
    #[must_use]
    pub fn completed(&self) -> Option<&LifecycleAuxiliaryRecordV1> {
        (self.returned == Some(Ok(())) && self.reentry.is_none())
            .then_some(self.record.as_ref()).flatten()
    }

    /// Moves the successful envelope once without disposing any refused prefix.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<LifecycleAuxiliaryRecordV1> {
        if self.returned != Some(Ok(())) || self.reentry.is_some() {
            return None;
        }
        self.record.take()
    }
}

#[cfg(test)]
mod tests;
