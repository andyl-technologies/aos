//! Exact post-commit Stop progress with incomplete physical Capture cleanup.
//!
//! The authenticated Runtime result proves containment, not durable output.
//! Its complete semantic commitment is retained as the dependency-held detail;
//! its strict native quiescence receipt supplies post-effect evidence without
//! claiming an ordinary complete Host inventory. This
//! refines the existing lifecycle record and grants no retry or deletion scope.

use super::*;
use crate::lifecycle::{
    LifecycleFailureClassV1, LifecycleFailureDigestV1, LifecycleFailureV1,
    LifecycleMethodV1, LifecycleRetryV1, LifecycleStepDomainV1,
    LifecycleSuspensionActionV1,
};

impl LifecycleProtectedJournalOwnerV1<'_> {
    pub(super) fn prepare_runtime_stop_residual_progress_v4(
        &self,
        current_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        observation: LifecycleEffectObservationV1,
        observed_at: LifecycleTimeV1,
        source: Option<crate::controller_resource_reservation::SourceAppendBoundaryV1<'_>>,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        self.prepare_runtime_stop_residual_progress_with_stop_selection_v4(
            current_key, transaction_id, observation, observed_at, source, None)
    }

    pub(super) fn prepare_runtime_stop_residual_progress_with_stop_selection_v4(
        &self,
        current_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        observation: LifecycleEffectObservationV1,
        observed_at: LifecycleTimeV1,
        source: Option<crate::controller_resource_reservation::SourceAppendBoundaryV1<'_>>,
        stop: Option<&crate::controller_lifecycle_stop::source::StopSourceAuthorizationV4<'_>>,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        let current = self.current_operation_with_stop_selection_v4(current_key, stop)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let successor = stop_residual_successor_v4(
            current.operation(), current.record(), observation, observed_at,
        )?;

        // The common writer rechecks the latest operation/key, immutable intent,
        // exact predecessor and Source bookend before planning the same CAS.
        self.prepare_operation_progress_with_stop_selection_v4(
            current_key, transaction_id, successor, source, stop,
        )
    }
}

fn stop_residual_successor_v4(
    operation: &LifecycleOperationV1,
    record: LifecycleRecordDigestV1,
    observation: LifecycleEffectObservationV1,
    observed_at: LifecycleTimeV1,
) -> Result<LifecycleOperationV1, LifecycleProtectedJournalErrorV1> {
    let request = observation.request();
    let step = operation.steps().first()
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    if observation.capture_stop_residual_v4().is_none()
        || operation.intent().method() != LifecycleMethodV1::Stop
        || operation.phase() != LifecyclePhaseV1::Completing
        || operation.semantic_commit().is_none()
        || operation.steps().len() != 1
        || operation.forward_progress() != 0
        || operation.compensation_progress() != 0
        || request.operation() != operation.operation_id()
        || request.operation_revision() != operation.record_revision()
        || request.domain() != LifecycleEffectDomainV1::Runtime
        || request.ordinal() != LifecycleSuspensionActionV1::StopRuntime as u32
        || request.step() != 0
        || request.direction() != LifecycleEffectDirectionV1::Forward
        || step.class() != LifecycleStepClassV1::PostCommitForward
        || step.domain() != LifecycleStepDomainV1::Host
    {
        return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
    }

    let previous = step.forward_attempts().last().copied()
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    if step.state() != LifecycleStepStateV1::Applying
        || previous.state() != LifecycleAttemptStateV1::Reserved
        || previous.number() != request.attempt()
        || previous.direction() != request.direction()
        || previous.request() != request.logical_request()
        || previous.body() != step.request_body()
        || previous.plan().digest() != request.plan()
        || previous.admission().digest() != request.admission()
        || observed_at < previous.started_at()
    {
        return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
    }

    let failure = LifecycleFailureV1::new(
        LifecycleFailureClassV1::DependencyHeld,
        LifecycleFailureDigestV1::commit(observation.result().as_bytes()),
        observed_at,
    );
    // This is the existing bounded deferred cursor, not a newly admitted
    // effect. Recovery must still obtain its genuine current retry authority.
    let next_attempt = previous.number().checked_add(1)
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let retry = LifecycleRetryV1::new(next_attempt, observed_at)
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let inventory = LifecycleInventoryDigestV1::commit(observation.inventory().as_bytes());
    let attempt = LifecycleEffectAttemptV1::new(
        previous.number(), previous.direction(), previous.request(),
        previous.body(), previous.plan(), previous.admission(), previous.started_at(),
        LifecycleAttemptStateV1::Failed, None, Some(failure), Some(inventory),
        Some(retry), Some(observed_at),
    ).map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let mut attempts = step.forward_attempts().to_vec();
    let last = attempts.last_mut()
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    *last = attempt;

    let residual_step = LifecycleStepV1::new(
        step.index(), step.class(), step.domain(), step.request(), step.request_body(),
        step.plan(), step.compensation_request(), step.compensation_body(),
        step.compensation_plan(), LifecycleStepStateV1::Residual, attempts,
        step.compensation_attempts().to_vec(), None, step.compensation_result(),
        Some(inventory), Some(failure), Some(retry),
    ).map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    operation.successor(
        record, LifecyclePhaseV1::Residual, operation.forward_progress(),
        operation.compensation_progress(), vec![residual_step],
        operation.method_semantic_commit().cloned(), Some(failure), Some(retry), None, None,
    ).map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
}
