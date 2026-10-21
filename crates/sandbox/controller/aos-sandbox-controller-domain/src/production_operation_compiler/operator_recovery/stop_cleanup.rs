//! Selects one exact pending public Stop as nonauthorizing recovery DATA.
//!
//! The same canonical public graph and protected recovery fence decoders are
//! shared with existing admission. No ordinary Stop plan, old native owner,
//! Session, funding receipt or effect permission is constructed here.

use super::*;
use crate::runtime_authority::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityLimits, RuntimeAuthorityStateV1,
};
use aos_sandbox_api::aos::sandbox::v1::DesiredLifecycle;
use aos_sandbox_model::{NodeId, SandboxId};
use aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1;

/// Retains exact protected target comparison models under the new Recover.
pub(crate) struct StopRecoveryTargetDataV1 {
    operation: OperationId,
    version: [u8; 32],
    context: PublicMutationEffectHistoryV1,
    binding: RuntimeAuthorityBindingV1,
    desired_generation: u64,
}

impl StopRecoveryTargetDataV1 {
    pub(crate) const fn operation_v1(&self) -> OperationId {
        self.operation
    }

    pub(crate) const fn version_v1(&self) -> &[u8; 32] {
        &self.version
    }

    pub(crate) const fn context_v1(&self) -> &PublicMutationEffectHistoryV1 {
        &self.context
    }

    pub(crate) const fn binding_v1(&self) -> &RuntimeAuthorityBindingV1 {
        &self.binding
    }

    pub(crate) const fn desired_generation_v1(&self) -> u64 {
        self.desired_generation
    }

    /// Joins only the actual same-interval Source's pending Stop selection.
    ///
    /// The caller retains its funded native Source reader, Controller and
    /// current authorization. The returned record digest is comparison DATA;
    /// it creates no mutable Source cursor or old SDK request.
    pub(crate) fn source_parent_data_v1(
        &self,
        controller: HistoricalObservationV1<'_>,
        source: &crate::lifecycle::LifecycleHistoricalReadOriginalV1,
    ) -> Result<crate::lifecycle::LifecycleRecordDigestV1, OperationCompilationError> {
        let rejected = || OperationCompilationError::Rejected;
        let request = self.context.validated_request().map_err(|_| rejected())?;
        let manifest = self.binding.manifest().manifest();
        let admission = crate::lifecycle::lifecycle_public_mutation_admission_from_observation_v2(
            controller,
            self.operation,
            self.context.project(),
            manifest.node(),
            &request,
        )
        .map_err(|_| rejected())?;
        let expected = crate::lifecycle::lifecycle_operation_from_public_mutation_v1(
            self.operation,
            self.context.caller(),
            self.context.project(),
            self.context.accepted_wall_seconds(),
            self.context.canonical_request(),
            &request,
            admission,
        )
        .map_err(|_| rejected())?;
        let (operation, record) = source.operation_v1().map_err(|_| rejected())?;
        crate::lifecycle::require_same_lifecycle_admission_v1(&expected, operation)
            .map_err(|_| rejected())?;
        if !matches!(
            operation.phase(),
            crate::lifecycle::LifecyclePhaseV1::Completing
                | crate::lifecycle::LifecyclePhaseV1::Residual
        ) || operation.terminal_result().is_some()
            || !matches!(
                operation.intent(),
                crate::lifecycle::LifecycleIntentV1::Stop { .. }
            )
        {
            return Err(rejected());
        }
        // Selection has already proved the immutable A7 pair and its exact
        // direct residual ancestry. A residual has no new old-Stop effect to
        // derive, so never feed that failed cursor into next_effect.
        let dispatch = source.stop_dispatch_data_v1().map_err(|_| rejected())?;
        if dispatch.operation() != self.operation {
            return Err(rejected());
        }
        if operation.phase() == crate::lifecycle::LifecyclePhaseV1::Residual {
            return Ok(record);
        }
        let (projection, _) = source.projection_ready_v1().map_err(|_| rejected())?;
        let current = crate::lifecycle::CurrentLifecycleOperationV1::from_protected_current(
            operation.clone(),
            record,
            projection.root(),
        );
        crate::lifecycle::LifecycleSuspensionPlanV1::stop(&current)
            .and_then(|plan| plan.next_effect(&current))
            .map_err(|_| rejected())?;
        Ok(record)
    }

    // All source/currentness checks use the complete target again. A target
    // selected before a later public mutation cannot survive on its ID alone.
    pub(crate) fn require_current_v1(
        &self,
        journal: HistoricalObservationV1<'_>,
        project: ProjectId,
        node: NodeId,
        request: &OperatorRecoveryRequestV1,
    ) -> Result<(), OperationCompilationError> {
        let current = require_stop_recovery_target_v1(journal, project, node, request)?;
        if current.operation != self.operation
            || current.version != self.version
            || current.context.canonical_request() != self.context.canonical_request()
            || current.context.caller() != self.context.caller()
            || current.binding.digest() != self.binding.digest()
            || current.desired_generation != self.desired_generation
        {
            return Err(OperationCompilationError::Rejected);
        }
        Ok(())
    }
}

pub(crate) fn require_stop_recovery_target_v1(
    journal: HistoricalObservationV1<'_>,
    project: ProjectId,
    node: NodeId,
    request: &OperatorRecoveryRequestV1,
) -> Result<StopRecoveryTargetDataV1, OperationCompilationError> {
    let rejected = || OperationCompilationError::Rejected;
    if request.action() != OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY as i32 {
        return Err(rejected());
    }
    let target = resolve_recovery_target(journal, project, request.resource_id())?;
    if target.resource_kind != ResourceKind::Operation
        || !target.current.validates_closed_recovery_fence_v2(request)
    {
        return Err(rejected());
    }
    let operation = OperationId::from_bytes(request.resource_id());
    let row = journal
        .get(crate::RecordNamespace::Operation, operation.as_bytes())
        .ok_or_else(rejected)?;
    let record = aos_sandbox_protocol::domain_ledger::operation::decode_operation(row)
        .map_err(|_| rejected())?;
    let effect_key = aos_sandbox_protocol::domain_ledger::operation::effect_key(operation, 0);
    let effect = aos_sandbox_protocol::domain_ledger::effect_history::decode_effect(
        journal
            .get(crate::RecordNamespace::Effect, &effect_key)
            .ok_or_else(rejected)?,
    )
    .map_err(|_| rejected())?;
    if record.state()
        != aos_sandbox_protocol::domain_ledger::public_operation::OperationState::Applying
        || record.effect_count() != 1
        || record
            .public_operation()
            .is_none_or(|public| public.method() != PublicOperationMethodV1::StopSandbox)
        || !matches!(
            effect.state(),
            aos_sandbox_protocol::domain_ledger::effect_history::EffectState::Applying {
                attempt: 1..,
                ..
            }
        )
    {
        return Err(rejected());
    }
    let context = crate::reconciler::accepted_stop_effect_from_observation_v4(journal, operation)
        .map_err(|_| rejected())?
        .ok_or_else(rejected)?;
    if context.project() != project {
        return Err(rejected());
    }
    let validated = context.validated_request().map_err(|_| rejected())?;
    let DormantSandboxRequestKindV1::Stop(stop) = validated else {
        return Err(rejected());
    };
    let sandbox_bytes: [u8; 16] = stop
        .sandbox_id
        .as_slice()
        .try_into()
        .map_err(|_| rejected())?;
    if sandbox_bytes == [0; 16] {
        return Err(rejected());
    }
    let sandbox = SandboxId::from_bytes(sandbox_bytes);
    let projection = crate::controller_service::public_projection::get_from_observation_v2(
        journal,
        PublicProjectionKindV1::Sandbox,
        sandbox_bytes,
    )
    .map_err(|_| rejected())?
    .ok_or_else(rejected)?;
    let PublicProjectionResourceV1::Sandbox(public) = projection.resource() else {
        return Err(rejected());
    };
    let desired = public.desired.as_option().ok_or_else(rejected)?;
    let observed = public.observed.as_option().ok_or_else(rejected)?;
    if projection.project() != project
        || projection.operation() != operation
        || public.project_id.as_slice() != project.as_bytes()
        || desired.lifecycle.as_known() != Some(DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED)
        || desired.generation == 0
    {
        return Err(rejected());
    }
    let binding = crate::runtime_authority::current_observed_v2(
        journal,
        RuntimeAuthorityLimits::default(),
        sandbox,
    )
    .map_err(|_| rejected())?
    .ok_or_else(rejected)?;
    let manifest = binding.manifest().manifest();
    if binding.state() != RuntimeAuthorityStateV1::Bound
        || binding.holder().is_none()
        || manifest.project() != project
        || manifest.sandbox() != sandbox
        || manifest.node() != node
        || observed.incarnation_id.as_slice() != manifest.incarnation().as_bytes()
        || observed.assignment_epoch != manifest.epoch().get()
        || observed.desired_generation != manifest.desired_generation().get()
    {
        return Err(rejected());
    }
    let version = request
        .expected_resource_version()
        .try_into()
        .map_err(|_| rejected())?;
    Ok(StopRecoveryTargetDataV1 {
        operation,
        version,
        context,
        binding,
        desired_generation: desired.generation,
    })
}
