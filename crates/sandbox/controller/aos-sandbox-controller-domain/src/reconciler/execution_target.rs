//! Selects the current Requested execution projection of an accepted operation.
//!
//! This is the sole existing Runtime selector, shared with Root's independent
//! accepted-input comparison. Its values do not grant a native effect.

use aos_sandbox_api::aos::sandbox::v1::ExecutionPhase;
use aos_sandbox_model::{ExecutionId, OperationId, SandboxId};
use aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1;
use aos_sandbox_protocol::public_api::projection::PublicProjectionResourceV1;
use crate::controller_service::public_projection::PublicProjectionStoreV1;
use crate::Journal;
use super::EffectFailure;

/// Reads the exact current Requested execution target for the accepted context.
///
/// # Errors
/// Returns the existing retryable refusal for absent or changed projection
/// custody, or the existing permanent refusal for another resource kind.
pub fn accepted_execution_target_from_journal_v1(
    controller: &Journal,
    operation: OperationId,
    context: &PublicMutationEffectHistoryV1,
) -> Result<(SandboxId, ExecutionId), EffectFailure> {
    let mut original = AcceptedExecutionTargetOriginalV2::new();
    let _selected = original.observe_once_v2(controller, operation, context);
    match original.result {
        Some(result) => result,
        None => Err(retryable("accepted execution target was not selected")),
    }
}

/// Retains the sole existing target selector's actual models and outcome.
pub(crate) struct AcceptedExecutionTargetOriginalV2 {
    projections: Option<Result<Vec<aos_sandbox_protocol::public_api::projection::PublicProjectionRecordV1>,
        aos_sandbox_protocol::public_api::projection::PublicProjectionError>>,
    result: Option<Result<(SandboxId, ExecutionId), EffectFailure>>,
}

impl AcceptedExecutionTargetOriginalV2 {
    pub(crate) fn new() -> Self { Self { projections: None, result: None } }

    pub(crate) fn observe_once_v2(&mut self, controller: &Journal, operation: OperationId,
        context: &PublicMutationEffectHistoryV1,
    ) -> Result<(), ()> {
        if self.projections.is_some() || self.result.is_some() { return Err(()); }
        self.projections = Some(PublicProjectionStoreV1::new(controller).list_operation(operation));
        self.result = Some(self.select_target_v2(operation, context));
        self.target_v2().map(|_| ())
    }

    fn select_target_v2(&self, operation: OperationId, context: &PublicMutationEffectHistoryV1)
        -> Result<(SandboxId, ExecutionId), EffectFailure>
    {
        let projections = match self.projections.as_ref() {
            Some(Ok(projections)) => projections,
            Some(Err(cause)) => return Err(retryable(cause.to_string())),
            None => return Err(retryable("accepted execution projection is unavailable")),
        };
        let [projection] = projections.as_slice() else {
            return Err(retryable("accepted execution projection is unavailable"));
        };
        let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
            return Err(EffectFailure::Permanent(
                "Create operation has another projection kind".to_owned(),
            ));
        };
        if projection.project() != context.project()
            || projection.operation() != operation
            || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_REQUESTED)
        {
            return Err(retryable(
                "accepted execution projection is no longer current",
            ));
        }
        let sandbox: [u8; 16] = execution
            .sandbox_id
            .as_slice()
            .try_into()
            .map_err(|_| retryable("accepted execution sandbox ID is invalid"))?;
        let execution_id: [u8; 16] = execution
            .execution_id
            .as_slice()
            .try_into()
            .map_err(|_| retryable("accepted execution ID is invalid"))?;
        Ok((
            SandboxId::from_bytes(sandbox),
            ExecutionId::from_bytes(execution_id),
        ))
    }

    pub(crate) fn target_v2(&self) -> Result<(SandboxId, ExecutionId), ()> {
        match self.result.as_ref() {
            Some(Ok(target)) => Ok(*target),
            _ => Err(()),
        }
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.projections.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.result.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
    }
}


fn retryable(message: impl Into<String>) -> EffectFailure {
    EffectFailure::Retryable(message.into())
}
