//! Selects protected old Execution DATA for a fresh authenticated Recover.
//!
//! The old Create and its exact execution remain the cleanup target even if
//! the current sandbox incarnation has advanced on the same node. The current
//! owner is checked independently; this decoder neither revives an old native
//! owner nor grants cleanup, Apply, Source, or Controller mutation authority.

use super::*;
use crate::runtime_authority::{RuntimeAuthorityLimits, RuntimeAuthorityStateV1};
use aos_sandbox_api::aos::sandbox::v1::ExecutionPhase;
use aos_sandbox_model::{NodeId, SandboxId};
use aos_sandbox_protocol::domain_ledger::effect_history::{EffectState, decode_effect};
use aos_sandbox_protocol::domain_ledger::operation::{decode_operation, effect_key};
use aos_sandbox_protocol::domain_ledger::public_operation::OperationState;
use aos_sandbox_protocol::host_execution_no_apply::closed_controller::ClosedCreateFailurePrepareDataV2;
use sha2::{Digest as _, Sha256};

/// Retains an exact protected target comparison, without a native capability.
pub(crate) struct ExecutionNoApplyRecoveryTargetDataV1 {
    operation: OperationId,
    version: [u8; 32],
    current_digest: [u8; 32],
}

impl ExecutionNoApplyRecoveryTargetDataV1 {
    /// Quotes the actual shared decoder suppliers before any target decoding.
    ///
    /// Native readers and resident namespace counts remain on the caller's
    /// existing receiving owner. This supplier prices only additional models.
    pub(crate) fn receiving_bytes_v1(controller: HistoricalObservationV1<'_>) -> Option<usize> {
        use aos_sandbox_model::ResourceDimension;

        let rows =
            crate::reconciler::closed_create_failure_receiving_demand_from_observation_v2(controller)
                .ok()?;
        let binding =
            crate::runtime_authority::current_publication_observed_receiving_demand_v2(controller)?;
        let memory = rows
            .get(ResourceDimension::MemoryBytes)
            .checked_add(binding.get(ResourceDimension::MemoryBytes))?;
        usize::try_from(memory)
            .ok()?
            .checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Sha256>().checked_mul(2)?)
    }

    pub(crate) const fn operation_v1(&self) -> OperationId {
        self.operation
    }

    pub(crate) const fn version_v1(&self) -> &[u8; 32] {
        &self.version
    }

    /// Rechecks the entire old target and its actual current owner.
    pub(crate) fn require_current_v1(
        &self,
        controller: HistoricalObservationV1<'_>,
        project: ProjectId,
        node: NodeId,
        request: &OperatorRecoveryRequestV1,
    ) -> Result<(), OperationCompilationError> {
        let current =
            require_execution_no_apply_recovery_target_v1(controller, project, node, request)?;
        if self.operation != current.operation
            || self.version != current.version
            || self.current_digest != current.current_digest
        {
            return Err(OperationCompilationError::Rejected);
        }
        Ok(())
    }
}

/// Shares the protected graph and canonical closed-terminal validators.
///
/// Host39 and Root78 history are independently required by the native issuer.
/// An Applying target alone therefore supplies no evidence that NoApply exists.
pub(crate) fn require_execution_no_apply_recovery_target_v1(
    controller: HistoricalObservationV1<'_>,
    project: ProjectId,
    node: NodeId,
    request: &OperatorRecoveryRequestV1,
) -> Result<ExecutionNoApplyRecoveryTargetDataV1, OperationCompilationError> {
    let rejected = || OperationCompilationError::Rejected;
    controller
        .ensure_protected_authority()
        .map_err(|_| rejected())?;
    if request.action() != OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY as i32 {
        return Err(rejected());
    }
    let target = resolve_recovery_target(controller, project, request.resource_id())?;
    if target.resource_kind != ResourceKind::Operation
        || !target.current.validates_closed_recovery_fence_v2(request)
    {
        return Err(rejected());
    }

    let operation = OperationId::from_bytes(request.resource_id());
    let operation_bytes = controller
        .get(crate::RecordNamespace::Operation, operation.as_bytes())
        .ok_or_else(rejected)?;
    let record = decode_operation(operation_bytes).map_err(|_| rejected())?;
    let effect_bytes = controller
        .get(crate::RecordNamespace::Effect, &effect_key(operation, 0))
        .ok_or_else(rejected)?;
    let effect = decode_effect(effect_bytes).map_err(|_| rejected())?;
    if !matches!(
        record.state(),
        OperationState::Applying | OperationState::FailedBeforeCommit
    ) || record.effect_count() != 1
        || record.ownership_gated()
        || record.runtime_intent_digest().is_some()
        || record
            .public_operation()
            .is_none_or(|public| public.method() != PublicOperationMethodV1::CreateExecution)
        || effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
        || effect.dispatch().is_some()
    {
        return Err(rejected());
    }
    let context = effect
        .plan()
        .public_mutation_context()
        .map_err(|_| rejected())?
        .ok_or_else(rejected)?;
    let DormantSandboxRequestKindV1::Exec(accepted) =
        context.validated_request().map_err(|_| rejected())?
    else {
        return Err(rejected());
    };
    if context.project() != project {
        return Err(rejected());
    }

    let projections =
        crate::controller_service::public_projection::list_operation_from_observation_v2(
            controller, operation,
        )
        .map_err(|_| rejected())?;
    let [projection] = projections.as_slice() else {
        return Err(rejected());
    };
    let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
        return Err(rejected());
    };
    if projection.operation() != operation
        || projection.project() != project
        || execution.audit_id.as_slice() != operation.as_bytes()
        || execution.sandbox_id != accepted.sandbox_id
        || execution.command.as_option() != accepted.command.as_option()
        || accepted.mutation.as_option().is_none_or(|mutation| {
            execution.sandbox_incarnation_id != mutation.expected_incarnation_id
        })
        || execution.result.as_option().is_some()
    {
        return Err(rejected());
    }

    // A changed local incarnation is permitted only as a current-owner fact.
    // The old execution's incarnation remains in its immutable accepted graph.
    let sandbox_bytes: [u8; 16] = execution
        .sandbox_id
        .as_slice()
        .try_into()
        .map_err(|_| rejected())?;
    if sandbox_bytes == [0; 16] {
        return Err(rejected());
    }
    let binding = crate::runtime_authority::current_observed_v2(
        controller,
        RuntimeAuthorityLimits::default(),
        SandboxId::from_bytes(sandbox_bytes),
    )
    .map_err(|_| rejected())?
    .ok_or_else(rejected)?;
    let manifest = binding.manifest().manifest();
    if binding.state() != RuntimeAuthorityStateV1::Bound
        || binding.holder().is_none()
        || manifest.project() != project
        || manifest.node() != node
        || manifest.sandbox().as_bytes() != &sandbox_bytes
    {
        return Err(rejected());
    }

    let prepared = controller
        .get(
            crate::RecordNamespace::ControllerCreateFailurePrepare,
            operation.as_bytes(),
        )
        .map(|bytes| {
            ClosedCreateFailurePrepareDataV2::decode_canonical(operation.as_bytes(), bytes)
                .map_err(|_| rejected())
        })
        .transpose()?;
    match record.state() {
        OperationState::Applying => {
            if !matches!(effect.state(), EffectState::Applying { attempt: 1.., .. })
                || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_REQUESTED)
            {
                return Err(rejected());
            }
        }
        OperationState::FailedBeforeCommit if prepared.is_some() => {}
        _ => return Err(rejected()),
    }
    if let Some(prepared) = prepared {
        let source = prepared.identity.marker.fields().source.fields();
        if source.create_operation != operation.into_bytes()
            || execution.execution_id.as_slice() != source.execution
            || execution.sandbox_id.as_slice() != source.sandbox
            || execution.sandbox_incarnation_id.as_slice() != source.incarnation
        {
            return Err(rejected());
        }
        let plan = crate::reconciler::plan_closed_create_failure_rows_from_observation_v2(
            controller,
            prepared.identity.marker,
            prepared.identity.terminal_archive,
            prepared.identity.signed_terminal,
            prepared.wall_seconds,
        )
        .map_err(|_| rejected())?;
        if plan.settled_data_v2() != (record.state() == OperationState::FailedBeforeCommit) {
            return Err(rejected());
        }
    }

    // Length framing commits to the exact canonical graph and current owner;
    // none of these comparison bytes can manufacture the captured native cut.
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.execution-no-apply-recovery-target.v1\0");
    for bytes in [
        operation_bytes,
        effect_bytes,
        projection.revision().as_bytes(),
        binding.digest().as_bytes(),
        request.expected_resource_version(),
    ] {
        digest.update(
            u64::try_from(bytes.len())
                .map_err(|_| rejected())?
                .to_be_bytes(),
        );
        digest.update(bytes);
    }
    if let Some(bytes) = controller.get(
        crate::RecordNamespace::ControllerCreateFailurePrepare,
        operation.as_bytes(),
    ) {
        digest.update(bytes);
    }
    Ok(ExecutionNoApplyRecoveryTargetDataV1 {
        operation,
        version: request
            .expected_resource_version()
            .try_into()
            .map_err(|_| rejected())?,
        current_digest: digest.finalize().into(),
    })
}
