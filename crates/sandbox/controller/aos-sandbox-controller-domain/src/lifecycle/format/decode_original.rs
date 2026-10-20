//! Retains the single operation decoder's partially reconstructed semantic graph.

use super::*;
use crate::lifecycle::LifecycleSemanticEvidenceV1;
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleDependencyEdgeV1;
use aos_sandbox_protocol::domain_ledger::delete_batch::LifecycleDeleteBatchRecordV1;

#[derive(Default)]
pub(in crate::lifecycle) struct SemanticDecodeParts {
    pub(in crate::lifecycle) model_failure: Option<LifecycleModelError>,
    pub(in crate::lifecycle) batch: Option<LifecycleDeleteBatchRecordV1>,
    pub(in crate::lifecycle) edges: Vec<LifecycleDependencyEdgeV1>,
    pub(in crate::lifecycle) postorder: Vec<LifecycleResourceV1>,
    pub(in crate::lifecycle) cascade: Option<(SandboxId, LifecycleCascadeTombstonePlanV1)>,
    pub(in crate::lifecycle) reads: Vec<LifecycleReadCommitFactV1>,
    pub(in crate::lifecycle) writes: Vec<LifecycleCommittedResourceV1>,
    pub(in crate::lifecycle) assignments: Vec<LifecycleAssignmentCommitFactV1>,
    pub(in crate::lifecycle) reservations: Vec<LifecycleReservationCommitFactV1>,
    pub(in crate::lifecycle) retention: Vec<LifecycleRetentionAcknowledgementV1>,
}

/// Owns the actual partial model and original result of one operation decode.
///
/// This is a decoder destination, not admission or a currentness proof. A refused
/// decode cannot be retried or taken; its reached graph remains resident.
#[derive(Default)]
pub struct LifecycleOperationDecodeOriginalV1 {
    pub(in crate::lifecycle) start_origin_failure: Option<aos_sandbox_protocol::domain_ledger::public_operation::PublicOperationDataError>,
    pub(in crate::lifecycle) model_failure: Option<LifecycleModelError>,
    pub(in crate::lifecycle) entered: bool,
    pub(in crate::lifecycle) returned: Option<Result<(), LifecycleModelError>>,
    pub(in crate::lifecycle) reentry: Option<LifecycleModelError>,
    pub(in crate::lifecycle) semantic: SemanticDecodeParts,
    pub(in crate::lifecycle) fact: Option<(LifecycleSemanticCommitFactV1, LifecycleSemanticEvidenceV1)>,
    pub(in crate::lifecycle) expectations: Vec<ResourceExpectationV1>,
    pub(in crate::lifecycle) steps: Vec<LifecycleStepV1>,
    pub(in crate::lifecycle) forward: Vec<LifecycleEffectAttemptV1>,
    pub(in crate::lifecycle) compensation: Vec<LifecycleEffectAttemptV1>,
    pub(in crate::lifecycle) commit: Option<LifecycleMethodSemanticCommitV1>,
    pub(in crate::lifecycle) failed_commit: Option<LifecycleMethodSemanticCommitV1>,
    pub(in crate::lifecycle) operation: Option<LifecycleOperationV1>,
}

impl LifecycleOperationDecodeOriginalV1 {
    /// Constructs an inert destination without parsing or allocating a graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes one record through the ordinary decoder's sole parsing engine.
    ///
    /// # Errors
    ///
    /// Returns the actual decoding error, or `InvalidTransition` on reentry.
    pub fn decode_once(&mut self, encoded: &[u8]) -> Result<(), LifecycleModelError> {
        if self.entered {
            self.reentry.get_or_insert(LifecycleModelError::InvalidTransition);
            return Err(LifecycleModelError::InvalidTransition);
        }
        self.entered = true;
        let result = super::decode_operation_record_into(encoded, self);
        self.returned = Some(result);
        result
    }

    /// Borrows the first actual decoding refusal before a later reentry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&LifecycleModelError> {
        self.semantic.model_failure.as_ref()
            .or(self.model_failure.as_ref())
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err()))
            .or(self.reentry.as_ref())
    }

    /// Borrows the selected original DATA refusal before its model projection.
    #[must_use]
    pub fn failure_view_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.start_origin_failure.as_ref().map(|cause| cause as _)
            .or_else(|| self.failure().map(|cause| cause as _))
    }

    /// Borrows the whole successful model without moving any partial graph.
    #[must_use]
    pub fn completed(&self) -> Option<&LifecycleOperationV1> {
        (self.returned == Some(Ok(())) && self.reentry.is_none())
            .then_some(self.operation.as_ref()).flatten()
    }

    /// Moves the actual successful model once; refused graphs remain owned here.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<LifecycleOperationV1> {
        if self.returned != Some(Ok(())) || self.reentry.is_some() {
            return None;
        }
        self.operation.take()
    }
}

#[cfg(test)]
mod tests;
