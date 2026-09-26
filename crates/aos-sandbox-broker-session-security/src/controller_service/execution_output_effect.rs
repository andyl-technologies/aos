//! Advances accepted Create operations through provisional Host output custody.
//!
//! The public endpoint remains closed. A historical accepted operation can
//! reserve its original Host output claim once, or query that same attempt
//! after a lost response. Settlement is not physical Storage backing and never
//! completes Create or publishes `RUNNING`.

use aos_proto::aos::sandbox::v1::ExecutionPhase;
use aos_sandbox::controller_execution_output_settlement::read_current_controller_output_settlement_v1;
use aos_sandbox::controller_execution_preissue::{
    load_controller_execution_output_attempt_v1, preissue_accepted_execution_source_v1,
    revalidate_historical_execution_preissue_source_v1,
};
use aos_sandbox::controller_service::public_projection::{
    PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use aos_sandbox::environment::EnvironmentProtectedEvidenceOwnerV1;
use aos_sandbox::execution_parent_resource::current_execution_parent_resource_from_journal_v1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::{EffectFailure, Journal, PublicMutationEffectV1};
use aos_sandbox_core::{ExecutionId, OperationId, SandboxId};

use super::attachment_target::ControllerAttachmentTargetInputsV1;
use super::execution_output_reserve::sign_current_host_output_reserve_v1;
use super::{ProductionEffectExecutor, sample_ownership_clock};

/// Recovers the original Host output attempt without issuing a new reserve.
///
/// # Errors
///
/// Returns a retryable failure when current protected sources, Host custody,
/// or authenticated settlement cannot be verified.
pub(super) fn observe(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    context: &PublicMutationEffectV1,
    controller: &mut Journal,
) -> Result<(), EffectFailure> {
    advance(executor, operation, context, controller, true)
}

/// Makes or recovers the one provisional Host output reservation for Create.
///
/// # Errors
///
/// Returns a retryable failure when any current source, signed Host exchange,
/// or protected Controller settlement remains unavailable.
pub(super) fn apply(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    context: &PublicMutationEffectV1,
    controller: &mut Journal,
) -> Result<(), EffectFailure> {
    advance(executor, operation, context, controller, false)
}

fn advance(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    context: &PublicMutationEffectV1,
    controller: &mut Journal,
    observing: bool,
) -> Result<(), EffectFailure> {
    let (sandbox, execution) = accepted_target(controller, operation, context)?;
    let attempt = load_controller_execution_output_attempt_v1(controller, execution)
        .map_err(|error| retryable(error.to_string()))?;
    if observing && attempt.is_none() {
        return Ok(());
    }

    let host_identity = executor
        .attachment_host
        .as_ref()
        .ok_or_else(|| retryable("trusted Host service identity is unavailable"))?;
    let inputs = ControllerAttachmentTargetInputsV1::from_protected_configuration(
        host_identity,
        executor.node,
    )
    .map_err(|error| retryable(error.to_string()))?;
    let assignment = inputs
        .acquire_source(controller, sandbox)
        .map_err(|error| retryable(error.to_string()))?
        .into_assignment_target();
    let parent = current_execution_parent_resource_from_journal_v1(
        controller,
        context.project(),
        sandbox,
        executor.node,
    )
    .map_err(|error| retryable(error.to_string()))?;
    let (mut evidence, _) = EnvironmentProtectedEvidenceOwnerV1::open_fixed_protected()
        .map_err(|error| retryable(error.to_string()))?;
    let mut environment = evidence
        .claim_environment(&mut executor.source_domains)
        .map_err(|error| retryable(error.to_string()))?;
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);

    let settled = if attempt.is_some() {
        read_current_controller_output_settlement_v1(
            controller,
            &assignment,
            execution,
            operation,
            &mut clock,
        )
        .map_err(|error| retryable(error.to_string()))?
        .is_some()
    } else {
        false
    };
    if settled {
        return Ok(());
    }

    let (observation, preissue, mismatched_reply) = if let Some(attempt) = attempt {
        let preissue = attempt.source().preissue().clone();
        revalidate_historical_execution_preissue_source_v1(
            controller,
            &assignment,
            &mut environment,
            &parent,
            &preissue,
            &mut clock,
        )
        .map_err(|error| retryable(error.to_string()))?;
        let signer = executor
            .broker_plan_signer
            .as_ref()
            .ok_or_else(|| retryable("Controller broker signer is unavailable"))?;
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        let host = sessions
            .host
            .as_mut()
            .ok_or_else(|| retryable("Host session is unavailable"))?;
        let observation = match host.drain_execution_output_for(&attempt)? {
            Some(observation) => observation,
            None => host.query_execution_output(controller, &attempt, signer)?,
        };
        drop(sessions);

        (
            observation,
            preissue,
            retryable("another execution owns the retained Host output reply"),
        )
    } else {
        let preissue = preissue_accepted_execution_source_v1(
            controller,
            &assignment,
            &mut environment,
            &parent,
            execution,
            operation,
            &mut clock,
        )
        .map_err(|error| retryable(error.to_string()))?;
        let signer = executor
            .broker_plan_signer
            .as_ref()
            .ok_or_else(|| retryable("Controller broker signer is unavailable"))?;
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        let host = sessions
            .host
            .as_mut()
            .ok_or_else(|| retryable("Host session is unavailable"))?;
        let observation = host.reserve_execution_output(|coordinates| {
            sign_current_host_output_reserve_v1(
                controller,
                &assignment,
                &mut environment,
                &parent,
                &preissue,
                signer,
                coordinates,
                &mut clock,
            )
        })?;
        drop(sessions);

        (
            observation,
            preissue,
            EffectFailure::Permanent(
                "Host output reply differs from the accepted Create".to_owned(),
            ),
        )
    };

    if !observation.matches(execution, operation) {
        return Err(mismatched_reply);
    }
    revalidate_historical_execution_preissue_source_v1(
        controller,
        &assignment,
        &mut environment,
        &parent,
        &preissue,
        &mut clock,
    )
    .map_err(|error| retryable(error.to_string()))?;
    let settlement = observation
        .settle(controller, &assignment, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    if settlement.is_none() {
        return Err(retryable("original Host output attempt is not committed"));
    }
    Ok(())
}

fn accepted_target(
    controller: &Journal,
    operation: OperationId,
    context: &PublicMutationEffectV1,
) -> Result<(SandboxId, ExecutionId), EffectFailure> {
    let projections = PublicProjectionStoreV1::new(controller)
        .list_operation(operation)
        .map_err(|error| retryable(error.to_string()))?;
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

fn retryable(message: impl Into<String>) -> EffectFailure {
    EffectFailure::Retryable(message.into())
}
