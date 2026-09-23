//! Production admission for non-capability public mutations.
//!
//! Each request commits its accepted desired projection together with one
//! method-typed controller effect. The effect retains the exact canonical
//! public envelope; controller orchestration may then lower it into lifecycle,
//! ownership, and broker-domain work without confusing a public RPC with a
//! privileged broker request.

use aos_proto::aos::sandbox::v1::{
    Attachment, AttachmentPhase, DesiredLifecycle, Execution, ExecutionIoMode, ExecutionPhase,
    FilesystemView, Sandbox, SandboxDesiredState, SandboxObservedState, SandboxPhase, Snapshot,
    SnapshotPhase, Timestamp, ViewPhase,
};
use aos_sandbox_core::runtime_backend::EffectOperationV1;
use aos_sandbox_core::{
    AttachmentId, ExecutionId, ObjectDescriptor, OperationId, ProjectId, SandboxId, SnapshotId,
    ViewId,
};
use sha2::{Digest as _, Sha256};

use crate::cli_model::DormantSandboxRequestKindV1 as Request;
use crate::controller_query::PublicOperationMethodV1;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionPlanV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1,
};
use crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1;
use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};
use crate::{
    EffectPlan, IdempotencyOutcome, Journal, OperationCompilationError, OperationPlan,
    PublicMutationEffectV1,
};

use super::{PublicExecutionControlDispatchV1, lower_public_execution_control_v1};

const PUBLIC_MUTATION_INTENT_KEY: &[u8] = b"aos.public.mutation-intent.v1\0";
const PUBLIC_MUTATION_INTENT_MAGIC: &[u8; 8] = b"AOSPMI01";
const PUBLIC_RESOURCE_VERSION_DOMAIN: &[u8] = b"aos.sandbox.public-resource-version.v1\0";

pub(super) fn compile_public_mutation(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    authorized: &AuthorizedPublicMutationRequestV1,
    canonical_request: &[u8],
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    let request = authorized.request();
    match journal.check_idempotency(request.idempotency_key(), request_digest) {
        IdempotencyOutcome::Replay(operation_id) => {
            return replay_public_mutation(
                journal,
                authorized,
                canonical_request,
                request_digest,
                operation_id,
            );
        }
        IdempotencyOutcome::Conflict => return Err(OperationCompilationError::Rejected),
        IdempotencyOutcome::Vacant => {}
    }

    let operation_id = OperationId::new();
    let desired = match request.request() {
        Request::Create(value) => create_sandbox_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::UpdatePolicy(value) => update_sandbox_policy_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::Start(value) => lifecycle_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
            PublicOperationMethodV1::StartSandbox,
            DesiredLifecycle::DESIRED_LIFECYCLE_RUNNING,
            false,
        )?,
        Request::Stop(value) => lifecycle_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
            PublicOperationMethodV1::StopSandbox,
            DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED,
            true,
        )?,
        Request::Suspend(value) => lifecycle_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
            PublicOperationMethodV1::SuspendSandbox,
            DesiredLifecycle::DESIRED_LIFECYCLE_SUSPENDED_MEMORY,
            true,
        )?,
        Request::Resume(value) => lifecycle_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
            PublicOperationMethodV1::ResumeSandbox,
            DesiredLifecycle::DESIRED_LIFECYCLE_RUNNING,
            true,
        )?,
        Request::Delete(value) => delete_sandbox_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::Exec(value) => create_execution_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::ExecutionControl(value) => control_execution_projection(
            journal,
            peer.project(),
            operation_id,
            request_digest,
            value,
        )?,
        Request::CancelExec(value) => execution_mutation_intent(
            journal,
            peer.project(),
            operation_id,
            request.operation_method(),
            canonical_request,
            &value.execution_id,
            value.mutation.as_option(),
        )?,
        Request::CachePin(value) => cache_consumer_mutation_intent(
            journal,
            peer.project(),
            operation_id,
            request.operation_method(),
            canonical_request,
            &value.view_id,
            &value.attachment_id,
            value.mutation.as_option(),
            CacheConsumerMutationV1::Acquire,
        )?,
        Request::CacheUnpin(value) => cache_consumer_mutation_intent(
            journal,
            peer.project(),
            operation_id,
            request.operation_method(),
            canonical_request,
            &value.view_id,
            &value.attachment_id,
            value.mutation.as_option(),
            CacheConsumerMutationV1::Release,
        )?,
        Request::CancelOperation(value) => cancel_operation_intent(
            journal,
            peer.project(),
            operation_id,
            canonical_request,
            value,
        )?,
        Request::ViewCreate(value) => create_view_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::ViewAttach(value) => attach_view_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::ViewReplace(value) => replace_attachment_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::ViewDetach(value) => detach_view_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::ViewRelease(value) => release_view_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::Snapshot(value) => create_snapshot_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::Restore(value) => restore_snapshot_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::DeleteSnapshot(value) => delete_snapshot_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::Fork(value) => fork_snapshot_projection(
            journal,
            peer.project(),
            operation_id,
            authorized.accepted_wall_seconds(),
            request_digest,
            value,
        )?,
        Request::CapabilityAttenuate(_)
        | Request::CapabilityRenew(_)
        | Request::CapabilityRevoke(_)
        | Request::PlanCreate(_)
        | Request::GetSandbox(_)
        | Request::GetExecution(_)
        | Request::GetView(_)
        | Request::GetAttachment(_)
        | Request::GetSnapshot(_)
        | Request::GetOperation(_)
        | Request::ListSandboxes(_)
        | Request::ListExecutions(_)
        | Request::ListSnapshots(_)
        | Request::Tree(_)
        | Request::Children(_)
        | Request::Ancestors(_)
        | Request::PlanPolicy(_)
        | Request::Events(_)
        | Request::ViewList(_)
        | Request::CacheStatus(_)
        | Request::CapabilitiesPublicApi(_)
        | Request::CapabilitiesNode(_)
        | Request::CapabilityInspect(_)
        | Request::OperatorRecover(_)
        | Request::Completions(_) => return Err(OperationCompilationError::Rejected),
    };
    operation_plan(
        authorized,
        peer.project(),
        operation_id,
        request_digest,
        canonical_request,
        desired,
    )
}

fn replay_public_mutation(
    journal: &mut Journal,
    authorized: &AuthorizedPublicMutationRequestV1,
    canonical_request: &[u8],
    request_digest: [u8; 32],
    operation_id: OperationId,
) -> Result<OperationPlan, OperationCompilationError> {
    let projections = PublicProjectionStoreV1::new(journal)
        .list_operation(operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let desired = match projections.as_slice() {
        [] => mutation_intent(
            operation_id,
            authorized.request().operation_method(),
            canonical_request,
        ),
        [projection] => PublicProjectionPlanV1::new(
            projection.project(),
            operation_id,
            projection.resource().clone(),
        )
        .map(PublicProjectionPlanV1::into_desired_state)
        .map_err(|_| OperationCompilationError::Rejected)?,
        _ => return Err(OperationCompilationError::Rejected),
    };
    let public = crate::reconciler::recovered_public_operation_admission_v1(journal, operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    let effect = EffectPlan::authorized_public_mutation(
        authorized.request().operation_method(),
        PublicMutationEffectV1::new(
            authorized.caller(),
            authorized.project(),
            authorized.accepted_wall_seconds(),
            canonical_request.to_vec(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?,
    )
    .map_err(|_| OperationCompilationError::Rejected)?;

    OperationPlan::new(
        operation_id,
        authorized.request().idempotency_key().clone(),
        request_digest,
        desired.0,
        desired.1,
        vec![effect],
    )
    .map_err(|_| OperationCompilationError::Rejected)?
    .with_public_operation(public)
    .map_err(|_| OperationCompilationError::Rejected)
}

fn operation_plan(
    authorized: &AuthorizedPublicMutationRequestV1,
    project: ProjectId,
    operation_id: OperationId,
    request_digest: [u8; 32],
    canonical_request: &[u8],
    desired: (Vec<u8>, Vec<u8>),
) -> Result<OperationPlan, OperationCompilationError> {
    let effect = EffectPlan::authorized_public_mutation(
        authorized.request().operation_method(),
        PublicMutationEffectV1::new(
            authorized.caller(),
            project,
            authorized.accepted_wall_seconds(),
            canonical_request.to_vec(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?,
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let plan = OperationPlan::new(
        operation_id,
        authorized.request().idempotency_key().clone(),
        request_digest,
        desired.0,
        desired.1,
        vec![effect],
    )
    .map_err(|_| OperationCompilationError::Rejected)?;

    super::attach_public_operation(plan, authorized, project, operation_id)
}

fn create_sandbox_projection(
    journal: &mut Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::CreateSandboxRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    if request.project_id.as_slice() != project.as_bytes() {
        return Err(OperationCompilationError::Rejected);
    }
    validate_project_version(journal, project, &request.expected_project_resource_version)?;
    let policy = request
        .requested_policy
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?
        .clone();
    super::policy_plan::validate_current_requested_policy(journal, project, &policy)
        .map_err(|_| OperationCompilationError::Rejected)?;
    if !request.parent_sandbox_id.is_empty() {
        let parent = load_sandbox(journal, exact_id(&request.parent_sandbox_id)?)?;
        if parent.project_id.as_slice() != project.as_bytes()
            || parent.resource_version != request.expected_parent_resource_version
            || parent.effective_policy.as_option() != Some(&policy)
        {
            return Err(OperationCompilationError::Rejected);
        }
    }
    let specification = request
        .specification
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?
        .clone();
    let sandbox_id = aos_sandbox_core::SandboxId::new().into_bytes();
    let sandbox = Sandbox {
        sandbox_id: sandbox_id.to_vec(),
        project_id: project.into_bytes().to_vec(),
        parent_sandbox_id: request.parent_sandbox_id.clone(),
        resource_version: resource_version(
            operation,
            PublicOperationMethodV1::CreateSandbox,
            1,
            request_digest,
        ),
        desired: Some(SandboxDesiredState {
            specification: Some(specification).into(),
            requested_policy: Some(policy.clone()).into(),
            lifecycle: DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED.into(),
            generation: 1,
            ..Default::default()
        })
        .into(),
        observed: Some(SandboxObservedState {
            phase: SandboxPhase::SANDBOX_PHASE_REQUESTED.into(),
            desired_generation: 1,
            observation_sequence: 1,
            last_successful_reconciliation_time: Some(timestamp(accepted_at)).into(),
            ..Default::default()
        })
        .into(),
        effective_policy: Some(policy).into(),
        created_at: Some(timestamp(accepted_at)).into(),
        updated_at: Some(timestamp(accepted_at)).into(),
        ..Default::default()
    };
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Sandbox(sandbox),
    )
}

fn update_sandbox_policy_projection(
    journal: &mut Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::UpdateSandboxPolicyRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let mut sandbox = load_sandbox(journal, exact_id(&request.sandbox_id)?)?;
    ensure_sandbox_project(&sandbox, project)?;
    let mutation = request
        .mutation
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    validate_sandbox_mutation(&sandbox, mutation, false)?;
    let desired = sandbox
        .desired
        .as_option()
        .ok_or(OperationCompilationError::Rejected)?;
    let generation = desired
        .generation
        .checked_add(1)
        .ok_or(OperationCompilationError::Rejected)?;
    let requested_policy = request
        .requested_policy
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?
        .clone();
    let expected_plan_digest = super::policy_plan::expected_update_plan_digest(
        journal,
        exact_id(&request.sandbox_id)?,
        &mutation.expected_resource_version,
        &requested_policy,
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    if request.expected_plan_digest != expected_plan_digest {
        return Err(OperationCompilationError::Rejected);
    }
    let mut next_desired = desired.clone();
    next_desired.requested_policy = Some(requested_policy.clone()).into();
    next_desired.generation = generation;
    sandbox.desired = Some(next_desired).into();
    sandbox.effective_policy = Some(requested_policy).into();
    sandbox.resource_version = resource_version(
        operation,
        PublicOperationMethodV1::UpdatePolicy,
        generation,
        request_digest,
    );
    sandbox.updated_at = Some(timestamp(accepted_at)).into();
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Sandbox(sandbox),
    )
}

#[allow(clippy::too_many_arguments)]
fn lifecycle_projection(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::SandboxLifecycleRequest,
    method: PublicOperationMethodV1,
    lifecycle: DesiredLifecycle,
    require_incarnation: bool,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let mut sandbox = load_sandbox(journal, exact_id(&request.sandbox_id)?)?;
    ensure_sandbox_project(&sandbox, project)?;
    let mutation = request
        .mutation
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    validate_sandbox_mutation(&sandbox, mutation, require_incarnation)?;
    let desired = sandbox
        .desired
        .as_option()
        .ok_or(OperationCompilationError::Rejected)?;
    // An invalid transition must fail before its new desired generation is durable.
    let valid_predecessor = matches!(
        (method, desired.lifecycle.as_known()),
        (
            PublicOperationMethodV1::StartSandbox,
            Some(DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED)
        ) | (
            PublicOperationMethodV1::StopSandbox,
            Some(
                DesiredLifecycle::DESIRED_LIFECYCLE_RUNNING
                    | DesiredLifecycle::DESIRED_LIFECYCLE_SUSPENDED_MEMORY
            )
        ) | (
            PublicOperationMethodV1::SuspendSandbox,
            Some(DesiredLifecycle::DESIRED_LIFECYCLE_RUNNING)
        ) | (
            PublicOperationMethodV1::ResumeSandbox,
            Some(
                DesiredLifecycle::DESIRED_LIFECYCLE_SUSPENDED_MEMORY
                    | DesiredLifecycle::DESIRED_LIFECYCLE_HIBERNATED
            )
        )
    );
    if !valid_predecessor {
        return Err(OperationCompilationError::Rejected);
    }
    let generation = desired
        .generation
        .checked_add(1)
        .ok_or(OperationCompilationError::Rejected)?;
    let mut next_desired = desired.clone();
    next_desired.lifecycle = lifecycle.into();
    next_desired.generation = generation;
    sandbox.desired = Some(next_desired).into();
    sandbox.resource_version = resource_version(operation, method, generation, request_digest);
    sandbox.updated_at = Some(timestamp(accepted_at)).into();
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Sandbox(sandbox),
    )
}

fn delete_sandbox_projection(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::DeleteSandboxRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let mut sandbox = load_sandbox(journal, exact_id(&request.sandbox_id)?)?;
    ensure_sandbox_project(&sandbox, project)?;
    let mutation = request
        .mutation
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    validate_sandbox_mutation(&sandbox, mutation, false)?;
    let desired = sandbox
        .desired
        .as_option()
        .ok_or(OperationCompilationError::Rejected)?;
    let generation = desired
        .generation
        .checked_add(1)
        .ok_or(OperationCompilationError::Rejected)?;
    let mut next_desired = desired.clone();
    next_desired.lifecycle = DesiredLifecycle::DESIRED_LIFECYCLE_DELETED.into();
    next_desired.generation = generation;
    sandbox.desired = Some(next_desired).into();
    sandbox.resource_version = resource_version(
        operation,
        PublicOperationMethodV1::DeleteSandbox,
        generation,
        request_digest,
    );
    sandbox.updated_at = Some(timestamp(accepted_at)).into();
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Sandbox(sandbox),
    )
}

fn create_execution_projection(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::CreateExecutionRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let sandbox = load_sandbox(journal, exact_id(&request.sandbox_id)?)?;
    ensure_sandbox_project(&sandbox, project)?;
    let mutation = request
        .mutation
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    validate_sandbox_mutation(&sandbox, mutation, true)?;
    let observed = sandbox
        .observed
        .as_option()
        .ok_or(OperationCompilationError::Rejected)?;
    let incarnation_id = exact_id(&observed.incarnation_id)?;
    if observed.assignment_epoch == 0 {
        return Err(OperationCompilationError::Rejected);
    }
    let command = request
        .command
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?
        .clone();
    let execution = Execution {
        execution_id: ExecutionId::new().into_bytes().to_vec(),
        sandbox_id: sandbox.sandbox_id.clone(),
        sandbox_incarnation_id: incarnation_id.to_vec(),
        resource_version: resource_version(
            operation,
            PublicOperationMethodV1::CreateExecution,
            1,
            request_digest,
        ),
        command: Some(command).into(),
        phase: ExecutionPhase::EXECUTION_PHASE_REQUESTED.into(),
        audit_id: operation.into_bytes().to_vec(),
        desired_generation: 1,
        observation_sequence: 1,
        assignment_epoch: observed.assignment_epoch,
        last_successful_reconciliation_time: Some(timestamp(accepted_at)).into(),
        ..Default::default()
    };
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Execution(execution),
    )
}

fn execution_mutation_intent(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    method: PublicOperationMethodV1,
    canonical_request: &[u8],
    execution_id: &[u8],
    mutation: Option<&aos_proto::aos::sandbox::v1::MutationContext>,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    load_execution_for_mutation(journal, project, execution_id, mutation)?;

    Ok(mutation_intent(operation, method, canonical_request))
}

fn control_execution_projection(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::ExecutionControlRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let execution = load_execution_for_mutation(
        journal,
        project,
        &request.execution_id,
        request.mutation.as_option(),
    )?;
    validate_execution_control(&execution, request)?;
    let execution = next_controlled_execution(execution, operation, request_digest)?;

    projection(
        project,
        operation,
        PublicProjectionResourceV1::Execution(execution),
    )
}

fn load_execution_for_mutation(
    journal: &Journal,
    project: ProjectId,
    execution_id: &[u8],
    mutation: Option<&aos_proto::aos::sandbox::v1::MutationContext>,
) -> Result<Execution, OperationCompilationError> {
    let record = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Execution, exact_id(execution_id)?)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    if record.project() != project {
        return Err(OperationCompilationError::Rejected);
    }
    let PublicProjectionResourceV1::Execution(execution) = record.resource() else {
        return Err(OperationCompilationError::Rejected);
    };
    validate_execution_mutation(execution, mutation)?;

    Ok(execution.clone())
}

fn validate_execution_mutation(
    execution: &Execution,
    mutation: Option<&aos_proto::aos::sandbox::v1::MutationContext>,
) -> Result<(), OperationCompilationError> {
    validate_resource_mutation(&execution.resource_version, mutation)?;
    let mutation = mutation.ok_or(OperationCompilationError::Malformed)?;
    if mutation.expected_incarnation_id != execution.sandbox_incarnation_id {
        return Err(OperationCompilationError::Rejected);
    }
    Ok(())
}

fn validate_execution_control(
    execution: &Execution,
    request: &aos_proto::aos::sandbox::v1::ExecutionControlRequest,
) -> Result<(), OperationCompilationError> {
    if matches!(
        execution.phase.as_known(),
        Some(
            ExecutionPhase::EXECUTION_PHASE_EXITED
                | ExecutionPhase::EXECUTION_PHASE_CANCELED
                | ExecutionPhase::EXECUTION_PHASE_FAILED
                | ExecutionPhase::EXECUTION_PHASE_LOST
        )
    ) {
        return Err(OperationCompilationError::Rejected);
    }

    let dispatch = lower_public_execution_control_v1(request)?;
    // Guest control effects cannot target an execution before its process exists.
    if matches!(dispatch, PublicExecutionControlDispatchV1::Effect(_))
        && execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_RUNNING)
    {
        return Err(OperationCompilationError::Rejected);
    }

    match dispatch {
        PublicExecutionControlDispatchV1::Attach
        | PublicExecutionControlDispatchV1::Effect(EffectOperationV1::Signal { .. }) => {}
        PublicExecutionControlDispatchV1::Effect(EffectOperationV1::ResizeTerminal { .. }) => {
            let command = execution
                .command
                .as_option()
                .ok_or(OperationCompilationError::Rejected)?;
            if command.io_mode.as_known() != Some(ExecutionIoMode::EXECUTION_IO_MODE_PTY) {
                return Err(OperationCompilationError::Rejected);
            }
        }
        PublicExecutionControlDispatchV1::Effect(_) => {
            return Err(OperationCompilationError::Malformed);
        }
    }
    Ok(())
}

fn next_controlled_execution(
    mut execution: Execution,
    operation: OperationId,
    request_digest: [u8; 32],
) -> Result<Execution, OperationCompilationError> {
    // The admitted command and observed phase stay unchanged until the effect settles.
    let generation = next_generation(execution.desired_generation)?;
    execution.desired_generation = generation;
    execution.resource_version = resource_version(
        operation,
        PublicOperationMethodV1::ControlExecution,
        generation,
        request_digest,
    );
    Ok(execution)
}

fn create_view_projection(
    journal: &mut Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::CreateViewRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    if request.project_id.as_slice() != project.as_bytes() {
        return Err(OperationCompilationError::Rejected);
    }
    validate_project_version(journal, project, &request.expected_project_resource_version)?;
    let revision = request
        .revision
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?
        .clone();
    let view = FilesystemView {
        view_id: ViewId::new().into_bytes().to_vec(),
        project_id: project.into_bytes().to_vec(),
        resource_version: resource_version(
            operation,
            PublicOperationMethodV1::CreateView,
            1,
            request_digest,
        ),
        revision: Some(revision).into(),
        phase: ViewPhase::VIEW_PHASE_REQUESTED.into(),
        desired_generation: 1,
        observation_sequence: 1,
        last_successful_reconciliation_time: Some(timestamp(accepted_at)).into(),
        ..Default::default()
    };
    projection(
        project,
        operation,
        PublicProjectionResourceV1::FilesystemView(view),
    )
}

fn attach_view_projection(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::AttachViewRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let sandbox = load_sandbox(journal, exact_id(&request.sandbox_id)?)?;
    ensure_sandbox_project(&sandbox, project)?;
    let mutation = request
        .mutation
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    validate_sandbox_mutation(&sandbox, mutation, true)?;
    let observed = sandbox
        .observed
        .as_option()
        .ok_or(OperationCompilationError::Rejected)?;
    if observed.assignment_epoch == 0 {
        return Err(OperationCompilationError::Rejected);
    }

    let view = load_view(journal, exact_id(&request.view_id)?)?;
    ensure_view_project(&view, project)?;
    let revision = request
        .view_revision
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    if view.revision.as_option() != Some(revision) || view.desired_generation == 0 {
        return Err(OperationCompilationError::Rejected);
    }
    let attachment = Attachment {
        attachment_id: AttachmentId::new().into_bytes().to_vec(),
        sandbox_id: sandbox.sandbox_id.clone(),
        source_view_id: view.view_id.clone(),
        destination_slot_id: exact_id(&request.destination_slot_id)?.to_vec(),
        resource_version: resource_version(
            operation,
            PublicOperationMethodV1::AttachView,
            1,
            request_digest,
        ),
        view_revision: Some(revision.clone()).into(),
        mutation: request.mutation_mode,
        phase: AttachmentPhase::ATTACHMENT_PHASE_REQUESTED.into(),
        desired_generation: 1,
        source_generation: view.desired_generation,
        observation_sequence: 1,
        assignment_epoch: observed.assignment_epoch,
        last_successful_reconciliation_time: Some(timestamp(accepted_at)).into(),
        ..Default::default()
    };
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Attachment(attachment),
    )
}

fn replace_attachment_projection(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::ReplaceAttachmentRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let mut attachment = load_attachment(journal, exact_id(&request.attachment_id)?)?;
    let sandbox = load_sandbox(journal, exact_id(&attachment.sandbox_id)?)?;
    ensure_sandbox_project(&sandbox, project)?;
    validate_resource_mutation(&attachment.resource_version, request.mutation.as_option())?;

    let view = load_view(journal, exact_id(&request.new_view_id)?)?;
    ensure_view_project(&view, project)?;
    let revision = request
        .new_view_revision
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    if view.revision.as_option() != Some(revision) || view.desired_generation == 0 {
        return Err(OperationCompilationError::Rejected);
    }
    let generation = next_generation(attachment.desired_generation)?;
    attachment.view_revision = Some(revision.clone()).into();
    attachment.source_view_id = view.view_id.clone();
    attachment.phase = AttachmentPhase::ATTACHMENT_PHASE_REPLACING.into();
    attachment.desired_generation = generation;
    attachment.source_generation = view.desired_generation;
    attachment.resource_version = resource_version(
        operation,
        PublicOperationMethodV1::ReplaceAttachment,
        generation,
        request_digest,
    );
    attachment.last_successful_reconciliation_time = Some(timestamp(accepted_at)).into();
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Attachment(attachment),
    )
}

fn detach_view_projection(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::DetachViewRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let mut attachment = load_attachment(journal, exact_id(&request.attachment_id)?)?;
    let sandbox = load_sandbox(journal, exact_id(&attachment.sandbox_id)?)?;
    ensure_sandbox_project(&sandbox, project)?;
    validate_resource_mutation(&attachment.resource_version, request.mutation.as_option())?;
    let generation = next_generation(attachment.desired_generation)?;
    attachment.phase = AttachmentPhase::ATTACHMENT_PHASE_DETACHING.into();
    attachment.desired_generation = generation;
    attachment.resource_version = resource_version(
        operation,
        PublicOperationMethodV1::DetachView,
        generation,
        request_digest,
    );
    attachment.last_successful_reconciliation_time = Some(timestamp(accepted_at)).into();
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Attachment(attachment),
    )
}

fn release_view_projection(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::ReleaseViewRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let mut view = load_view(journal, exact_id(&request.view_id)?)?;
    ensure_view_project(&view, project)?;
    validate_resource_mutation(&view.resource_version, request.mutation.as_option())?;
    if view.active_attachment_count != 0 {
        return Err(OperationCompilationError::Rejected);
    }
    let generation = next_generation(view.desired_generation)?;
    view.phase = ViewPhase::VIEW_PHASE_RELEASING.into();
    view.desired_generation = generation;
    view.resource_version = resource_version(
        operation,
        PublicOperationMethodV1::ReleaseView,
        generation,
        request_digest,
    );
    view.last_successful_reconciliation_time = Some(timestamp(accepted_at)).into();
    projection(
        project,
        operation,
        PublicProjectionResourceV1::FilesystemView(view),
    )
}

fn create_snapshot_projection(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::CreateSnapshotRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let sandbox = load_sandbox(journal, exact_id(&request.sandbox_id)?)?;
    ensure_sandbox_project(&sandbox, project)?;
    let mutation = request
        .mutation
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    validate_sandbox_mutation(&sandbox, mutation, true)?;
    let snapshot = Snapshot {
        snapshot_id: SnapshotId::new().into_bytes().to_vec(),
        source_sandbox_id: sandbox.sandbox_id.clone(),
        project_id: project.into_bytes().to_vec(),
        resource_version: resource_version(
            operation,
            PublicOperationMethodV1::CreateSnapshot,
            1,
            request_digest,
        ),
        phase: SnapshotPhase::SNAPSHOT_PHASE_REQUESTED.into(),
        availability: request.requested_availability,
        created_at: Some(timestamp(accepted_at)).into(),
        desired_generation: 1,
        observation_sequence: 1,
        last_successful_reconciliation_time: Some(timestamp(accepted_at)).into(),
        ..Default::default()
    };
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Snapshot(snapshot),
    )
}

fn restore_snapshot_projection(
    journal: &mut Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::RestoreSnapshotRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let snapshot = load_snapshot(journal, exact_id(&request.snapshot_id)?)?;
    ensure_snapshot_ready(&snapshot, project)?;
    let target = exact_id(&request.target_sandbox_id)?;
    if PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Sandbox, target)
        .map_err(|_| OperationCompilationError::Rejected)?
        .is_some()
    {
        return Err(OperationCompilationError::Rejected);
    }
    let mutation = request
        .mutation
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    validate_project_version(journal, project, &mutation.expected_resource_version)?;
    let policy = request
        .requested_policy
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?
        .clone();
    super::policy_plan::validate_current_requested_policy(journal, project, &policy)
        .map_err(|_| OperationCompilationError::Rejected)?;

    // Restore creates a fresh logical sandbox. The committed source snapshot
    // supplies its portable specification until manifest lowering binds the
    // exact immutable restore inputs.
    let source = load_sandbox(journal, exact_id(&snapshot.source_sandbox_id)?)?;
    ensure_sandbox_project(&source, project)?;
    let specification = source
        .desired
        .as_option()
        .and_then(|desired| desired.specification.as_option())
        .ok_or(OperationCompilationError::Rejected)?
        .clone();
    let sandbox = Sandbox {
        sandbox_id: target.to_vec(),
        project_id: project.into_bytes().to_vec(),
        resource_version: resource_version(
            operation,
            PublicOperationMethodV1::RestoreSnapshot,
            1,
            request_digest,
        ),
        desired: Some(SandboxDesiredState {
            specification: Some(specification).into(),
            requested_policy: Some(policy.clone()).into(),
            lifecycle: DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED.into(),
            generation: 1,
            ..Default::default()
        })
        .into(),
        observed: Some(SandboxObservedState {
            phase: SandboxPhase::SANDBOX_PHASE_REQUESTED.into(),
            desired_generation: 1,
            observation_sequence: 1,
            last_successful_reconciliation_time: Some(timestamp(accepted_at)).into(),
            ..Default::default()
        })
        .into(),
        effective_policy: Some(policy).into(),
        created_at: Some(timestamp(accepted_at)).into(),
        updated_at: Some(timestamp(accepted_at)).into(),
        ..Default::default()
    };
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Sandbox(sandbox),
    )
}

fn delete_snapshot_projection(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::DeleteSnapshotRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let mut snapshot = load_snapshot(journal, exact_id(&request.snapshot_id)?)?;
    ensure_snapshot_project(&snapshot, project)?;
    validate_resource_mutation(&snapshot.resource_version, request.mutation.as_option())?;
    let generation = next_generation(snapshot.desired_generation)?;
    snapshot.phase = SnapshotPhase::SNAPSHOT_PHASE_DELETING.into();
    snapshot.desired_generation = generation;
    snapshot.resource_version = resource_version(
        operation,
        PublicOperationMethodV1::DeleteSnapshot,
        generation,
        request_digest,
    );
    snapshot.last_successful_reconciliation_time = Some(timestamp(accepted_at)).into();
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Snapshot(snapshot),
    )
}

fn fork_snapshot_projection(
    journal: &mut Journal,
    project: ProjectId,
    operation: OperationId,
    accepted_at: i64,
    request_digest: [u8; 32],
    request: &aos_proto::aos::sandbox::v1::ForkSnapshotRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    if request.target_project_id.as_slice() != project.as_bytes() {
        return Err(OperationCompilationError::Rejected);
    }
    validate_project_version(journal, project, &request.expected_project_resource_version)?;
    let snapshot = load_snapshot(journal, exact_id(&request.snapshot_id)?)?;
    ensure_snapshot_ready(&snapshot, project)?;
    let policy = request
        .requested_policy
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?
        .clone();
    super::policy_plan::validate_current_requested_policy(journal, project, &policy)
        .map_err(|_| OperationCompilationError::Rejected)?;
    if !request.parent_sandbox_id.is_empty() {
        let parent = load_sandbox(journal, exact_id(&request.parent_sandbox_id)?)?;
        if parent.project_id.as_slice() != project.as_bytes()
            || parent.resource_version != request.expected_parent_resource_version
            || parent.effective_policy.as_option() != Some(&policy)
        {
            return Err(OperationCompilationError::Rejected);
        }
    }

    // The portable snapshot points at its immutable manifest; until lowering
    // reads that manifest, the current source projection supplies the public
    // specification committed by the admitted child.
    let source = load_sandbox(journal, exact_id(&snapshot.source_sandbox_id)?)?;
    ensure_sandbox_project(&source, project)?;
    let specification = source
        .desired
        .as_option()
        .and_then(|desired| desired.specification.as_option())
        .ok_or(OperationCompilationError::Rejected)?
        .clone();
    let sandbox = Sandbox {
        sandbox_id: SandboxId::new().into_bytes().to_vec(),
        project_id: project.into_bytes().to_vec(),
        parent_sandbox_id: request.parent_sandbox_id.clone(),
        resource_version: resource_version(
            operation,
            PublicOperationMethodV1::ForkSnapshot,
            1,
            request_digest,
        ),
        desired: Some(SandboxDesiredState {
            specification: Some(specification).into(),
            requested_policy: Some(policy.clone()).into(),
            lifecycle: DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED.into(),
            generation: 1,
            ..Default::default()
        })
        .into(),
        observed: Some(SandboxObservedState {
            phase: SandboxPhase::SANDBOX_PHASE_REQUESTED.into(),
            desired_generation: 1,
            observation_sequence: 1,
            last_successful_reconciliation_time: Some(timestamp(accepted_at)).into(),
            ..Default::default()
        })
        .into(),
        effective_policy: Some(policy).into(),
        created_at: Some(timestamp(accepted_at)).into(),
        updated_at: Some(timestamp(accepted_at)).into(),
        ..Default::default()
    };
    projection(
        project,
        operation,
        PublicProjectionResourceV1::Sandbox(sandbox),
    )
}

fn validate_sandbox_mutation(
    sandbox: &Sandbox,
    mutation: &aos_proto::aos::sandbox::v1::MutationContext,
    require_incarnation: bool,
) -> Result<(), OperationCompilationError> {
    if mutation.expected_resource_version != sandbox.resource_version {
        return Err(OperationCompilationError::Rejected);
    }
    if require_incarnation {
        let observed = sandbox
            .observed
            .as_option()
            .ok_or(OperationCompilationError::Rejected)?;
        if observed.incarnation_id.is_empty()
            || mutation.expected_incarnation_id != observed.incarnation_id
        {
            return Err(OperationCompilationError::Rejected);
        }
    }
    Ok(())
}

fn validate_project_version(
    journal: &mut Journal,
    project: ProjectId,
    expected: &[u8],
) -> Result<(), OperationCompilationError> {
    let policy = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())
        .map_err(|_| OperationCompilationError::Rejected)?
        .current_policy(project)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    if expected != policy.descriptor().digest().as_bytes() {
        return Err(OperationCompilationError::Rejected);
    }
    Ok(())
}

fn load_sandbox(journal: &Journal, id: [u8; 16]) -> Result<Sandbox, OperationCompilationError> {
    let record = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Sandbox, id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    let PublicProjectionResourceV1::Sandbox(sandbox) = record.resource() else {
        return Err(OperationCompilationError::Rejected);
    };
    Ok(sandbox.clone())
}

fn load_view(journal: &Journal, id: [u8; 16]) -> Result<FilesystemView, OperationCompilationError> {
    let record = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::FilesystemView, id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    let PublicProjectionResourceV1::FilesystemView(view) = record.resource() else {
        return Err(OperationCompilationError::Rejected);
    };
    Ok(view.clone())
}

fn load_attachment(
    journal: &Journal,
    id: [u8; 16],
) -> Result<Attachment, OperationCompilationError> {
    let record = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Attachment, id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    let PublicProjectionResourceV1::Attachment(attachment) = record.resource() else {
        return Err(OperationCompilationError::Rejected);
    };
    Ok(attachment.clone())
}

fn load_snapshot(journal: &Journal, id: [u8; 16]) -> Result<Snapshot, OperationCompilationError> {
    let record = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Snapshot, id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    let PublicProjectionResourceV1::Snapshot(snapshot) = record.resource() else {
        return Err(OperationCompilationError::Rejected);
    };
    Ok(snapshot.clone())
}

fn ensure_sandbox_project(
    sandbox: &Sandbox,
    project: ProjectId,
) -> Result<(), OperationCompilationError> {
    if sandbox.project_id.as_slice() == project.as_bytes() {
        Ok(())
    } else {
        Err(OperationCompilationError::Rejected)
    }
}

fn ensure_view_project(
    view: &FilesystemView,
    project: ProjectId,
) -> Result<(), OperationCompilationError> {
    if view.project_id.as_slice() == project.as_bytes() {
        Ok(())
    } else {
        Err(OperationCompilationError::Rejected)
    }
}

fn ensure_snapshot_project(
    snapshot: &Snapshot,
    project: ProjectId,
) -> Result<(), OperationCompilationError> {
    if snapshot.project_id.as_slice() == project.as_bytes() {
        Ok(())
    } else {
        Err(OperationCompilationError::Rejected)
    }
}

fn ensure_snapshot_ready(
    snapshot: &Snapshot,
    project: ProjectId,
) -> Result<(), OperationCompilationError> {
    ensure_snapshot_project(snapshot, project)?;
    if snapshot.phase.as_known() != Some(SnapshotPhase::SNAPSHOT_PHASE_READY)
        || snapshot.manifest.as_option().is_none()
    {
        return Err(OperationCompilationError::Rejected);
    }
    Ok(())
}

fn validate_resource_mutation(
    resource_version: &[u8],
    mutation: Option<&aos_proto::aos::sandbox::v1::MutationContext>,
) -> Result<(), OperationCompilationError> {
    let mutation = mutation.ok_or(OperationCompilationError::Malformed)?;
    if mutation.expected_resource_version == resource_version {
        Ok(())
    } else {
        Err(OperationCompilationError::Rejected)
    }
}

#[derive(Clone, Copy)]
enum CacheConsumerMutationV1 {
    Acquire,
    Release,
}

/// Retains the exact public cache consumer checked against current desired state.
///
/// This is not source-object membership, protected pin authority, or physical
/// residency evidence. It only carries the consumer identity needed to select
/// retained obligations after project and resource-version validation.
pub struct RecheckedCacheConsumerV1 {
    object: ObjectDescriptor,
    project: ProjectId,
    view: ViewId,
    attachment: Option<AttachmentId>,
}

impl RecheckedCacheConsumerV1 {
    /// Returns the exact immutable object selected by the public request.
    #[must_use]
    pub const fn object(&self) -> &ObjectDescriptor {
        &self.object
    }

    /// Returns the project charged for this logical dependency.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the checked consuming view identity.
    #[must_use]
    pub const fn view(&self) -> ViewId {
        self.view
    }

    /// Returns the checked attached consumer, when one was named.
    #[must_use]
    pub const fn attachment(&self) -> Option<AttachmentId> {
        self.attachment
    }
}

#[allow(clippy::too_many_arguments)]
fn cache_consumer_mutation_intent(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    method: PublicOperationMethodV1,
    canonical_request: &[u8],
    view_id: &[u8],
    attachment_id: &[u8],
    mutation: Option<&aos_proto::aos::sandbox::v1::MutationContext>,
    mutation_kind: CacheConsumerMutationV1,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    validate_cache_consumer_projection(
        journal,
        project,
        view_id,
        attachment_id,
        mutation,
        mutation_kind,
    )?;
    Ok(mutation_intent(operation, method, canonical_request))
}

/// Rechecks the projected consumer and resource-version fence before a cache effect.
///
/// This is a desired-state currentness check, not physical cache authority or
/// proof that an object belongs to the view. The protected Cache owner must
/// independently establish those facts when it performs the effect.
///
/// # Errors
///
/// Rejects a non-cache request, a missing or cross-project consumer, a stale
/// resource version, or acquisition against a non-current view or attachment.
/// Release may name an older attachment source; the protected Cache owner must
/// still match the exact retained pin before it can change physical state.
pub fn recheck_cache_consumer_projection_v1(
    journal: &Journal,
    project: ProjectId,
    request: &crate::cli_model::DormantSandboxRequestKindV1,
) -> Result<RecheckedCacheConsumerV1, OperationCompilationError> {
    let (object, view_id, attachment_id, mutation, mutation_kind) = match request {
        Request::CachePin(value) => (
            value.object.as_option(),
            value.view_id.as_slice(),
            value.attachment_id.as_slice(),
            value.mutation.as_option(),
            CacheConsumerMutationV1::Acquire,
        ),
        Request::CacheUnpin(value) => (
            value.object.as_option(),
            value.view_id.as_slice(),
            value.attachment_id.as_slice(),
            value.mutation.as_option(),
            CacheConsumerMutationV1::Release,
        ),
        _ => return Err(OperationCompilationError::Rejected),
    };
    validate_cache_consumer_projection(
        journal,
        project,
        view_id,
        attachment_id,
        mutation,
        mutation_kind,
    )?;

    let object = crate::public_mutation_compiler::object_descriptor(
        object.ok_or(OperationCompilationError::Malformed)?,
    )
    .map_err(|_| OperationCompilationError::Malformed)?;
    let attachment = if attachment_id.is_empty() {
        None
    } else {
        Some(AttachmentId::from_bytes(exact_id(attachment_id)?))
    };

    Ok(RecheckedCacheConsumerV1 {
        object,
        project,
        view: ViewId::from_bytes(exact_id(view_id)?),
        attachment,
    })
}

fn validate_cache_consumer_projection(
    journal: &Journal,
    project: ProjectId,
    view_id: &[u8],
    attachment_id: &[u8],
    mutation: Option<&aos_proto::aos::sandbox::v1::MutationContext>,
    mutation_kind: CacheConsumerMutationV1,
) -> Result<(), OperationCompilationError> {
    let view = load_view(journal, exact_id(view_id)?)?;
    ensure_view_project(&view, project)?;
    // Release remains possible after the consumer starts draining.
    if matches!(mutation_kind, CacheConsumerMutationV1::Acquire)
        && (view.revision.as_option().is_none()
            || view.desired_generation == 0
            || !matches!(
                view.phase.as_known(),
                Some(ViewPhase::VIEW_PHASE_READY | ViewPhase::VIEW_PHASE_DEGRADED)
            ))
    {
        return Err(OperationCompilationError::Rejected);
    }

    if attachment_id.is_empty() {
        validate_resource_mutation(&view.resource_version, mutation)?;
    } else {
        let attachment = load_attachment(journal, exact_id(attachment_id)?)?;
        let sandbox = load_sandbox(journal, exact_id(&attachment.sandbox_id)?)?;
        ensure_sandbox_project(&sandbox, project)?;
        if matches!(mutation_kind, CacheConsumerMutationV1::Acquire) {
            let observed = sandbox
                .observed
                .as_option()
                .ok_or(OperationCompilationError::Rejected)?;
            // An older ready attachment may drain, but cannot acquire new pins.
            if attachment.source_view_id != view_id
                || attachment.view_revision.as_option() != view.revision.as_option()
                || attachment.source_generation != view.desired_generation
                || attachment.phase.as_known() != Some(AttachmentPhase::ATTACHMENT_PHASE_READY)
                || attachment.assignment_epoch == 0
                || attachment.assignment_epoch != observed.assignment_epoch
                || exact_id(&observed.incarnation_id).is_err()
                || exact_id(&observed.node_id).is_err()
            {
                return Err(OperationCompilationError::Rejected);
            }
        }
        // A replacement can change the attachment's current source before an old pin drains.
        validate_resource_mutation(&attachment.resource_version, mutation)?;
    }

    Ok(())
}

fn cancel_operation_intent(
    journal: &Journal,
    project: ProjectId,
    operation: OperationId,
    canonical_request: &[u8],
    request: &aos_proto::aos::sandbox::v1::CancelOperationRequest,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    let target = OperationId::from_bytes(exact_id(&request.operation_id)?);
    let target_operation =
        crate::reconciler::recovered_public_operation_resource_v1(journal, target)
            .map_err(|_| OperationCompilationError::Rejected)?
            .ok_or(OperationCompilationError::Rejected)?;
    let authorization =
        crate::reconciler::recovered_public_operation_authorization_v1(journal, target)
            .map_err(|_| OperationCompilationError::Rejected)?
            .ok_or(OperationCompilationError::Rejected)?;
    if authorization.project() != project {
        return Err(OperationCompilationError::Rejected);
    }
    validate_resource_mutation(
        &target_operation.resource_version,
        request.mutation.as_option(),
    )?;

    Ok(mutation_intent(
        operation,
        PublicOperationMethodV1::CancelOperation,
        canonical_request,
    ))
}

fn next_generation(current: u64) -> Result<u64, OperationCompilationError> {
    current
        .checked_add(1)
        .filter(|generation| *generation > 1)
        .ok_or(OperationCompilationError::Rejected)
}

fn projection(
    project: ProjectId,
    operation: OperationId,
    resource: PublicProjectionResourceV1,
) -> Result<(Vec<u8>, Vec<u8>), OperationCompilationError> {
    PublicProjectionPlanV1::new(project, operation, resource)
        .map(PublicProjectionPlanV1::into_desired_state)
        .map_err(|_| OperationCompilationError::Rejected)
}

pub(super) fn mutation_intent(
    operation: OperationId,
    method: PublicOperationMethodV1,
    canonical_request: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut key = Vec::with_capacity(PUBLIC_MUTATION_INTENT_KEY.len() + 16);
    key.extend_from_slice(PUBLIC_MUTATION_INTENT_KEY);
    key.extend_from_slice(operation.as_bytes());

    let mut value = Vec::with_capacity(8 + 2 + 1 + 5 + 16 + 4 + canonical_request.len() + 32);
    value.extend_from_slice(PUBLIC_MUTATION_INTENT_MAGIC);
    value.extend_from_slice(&1_u16.to_be_bytes());
    value.push(method.record_code());
    value.extend_from_slice(&[0; 5]);
    value.extend_from_slice(operation.as_bytes());
    value.extend_from_slice(&(canonical_request.len() as u32).to_be_bytes());
    value.extend_from_slice(canonical_request);
    value.extend_from_slice(Sha256::digest(&value).as_slice());
    (key, value)
}

fn resource_version(
    operation: OperationId,
    method: PublicOperationMethodV1,
    generation: u64,
    request_digest: [u8; 32],
) -> Vec<u8> {
    Sha256::new()
        .chain_update(PUBLIC_RESOURCE_VERSION_DOMAIN)
        .chain_update(operation.as_bytes())
        .chain_update([method.record_code()])
        .chain_update(generation.to_be_bytes())
        .chain_update(request_digest)
        .finalize()
        .to_vec()
}

fn exact_id(bytes: &[u8]) -> Result<[u8; 16], OperationCompilationError> {
    let id = bytes
        .try_into()
        .map_err(|_| OperationCompilationError::Malformed)?;
    if id == [0; 16] {
        Err(OperationCompilationError::Malformed)
    } else {
        Ok(id)
    }
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp {
        seconds,
        nanoseconds: 0,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::v1::{
        Command, Execution, ExecutionControlAction, ExecutionControlRequest, ExecutionIoMode,
        ExecutionPhase, MutationContext,
    };
    use aos_sandbox_core::OperationId;

    use super::{
        OperationCompilationError, next_controlled_execution, validate_execution_control,
        validate_execution_mutation,
    };

    #[test]
    fn execution_mutation_requires_current_version_and_incarnation() {
        let execution = Execution {
            resource_version: vec![0x31; 32],
            sandbox_incarnation_id: vec![0x42; 16],
            ..Default::default()
        };
        let mutation = MutationContext {
            expected_resource_version: execution.resource_version.clone(),
            expected_incarnation_id: execution.sandbox_incarnation_id.clone(),
            ..Default::default()
        };

        assert_eq!(
            validate_execution_mutation(&execution, Some(&mutation)),
            Ok(())
        );
        assert_eq!(
            validate_execution_mutation(&execution, None),
            Err(OperationCompilationError::Malformed)
        );

        let mut stale_version = mutation.clone();
        stale_version.expected_resource_version[0] ^= 1;
        assert_eq!(
            validate_execution_mutation(&execution, Some(&stale_version)),
            Err(OperationCompilationError::Rejected)
        );

        let mut stale_incarnation = mutation;
        stale_incarnation.expected_incarnation_id[0] ^= 1;
        assert_eq!(
            validate_execution_mutation(&execution, Some(&stale_incarnation)),
            Err(OperationCompilationError::Rejected)
        );
    }

    #[test]
    fn execution_control_advances_only_desired_identity() {
        let command = Command {
            io_mode: ExecutionIoMode::EXECUTION_IO_MODE_PTY.into(),
            allocate_terminal: true,
            terminal_rows: 24,
            terminal_columns: 80,
            ..Default::default()
        };
        let execution = Execution {
            resource_version: vec![0x31; 32],
            desired_generation: 7,
            observation_sequence: 5,
            phase: ExecutionPhase::EXECUTION_PHASE_RUNNING.into(),
            command: Some(command.clone()).into(),
            ..Default::default()
        };
        let request = ExecutionControlRequest {
            action: ExecutionControlAction::EXECUTION_CONTROL_ACTION_RESIZE.into(),
            terminal_rows: 40,
            terminal_columns: 120,
            ..Default::default()
        };

        assert_eq!(validate_execution_control(&execution, &request), Ok(()));
        let next = next_controlled_execution(
            execution.clone(),
            OperationId::from_bytes([0x44; 16]),
            [0x55; 32],
        )
        .unwrap();
        assert_eq!(next.desired_generation, 8);
        assert_ne!(next.resource_version, execution.resource_version);
        assert_eq!(next.observation_sequence, execution.observation_sequence);
        assert_eq!(next.phase, execution.phase);
        assert_eq!(next.command.as_option(), Some(&command));

        let mut stream_execution = execution.clone();
        stream_execution.command = Some(Command {
            io_mode: ExecutionIoMode::EXECUTION_IO_MODE_STREAM.into(),
            ..Default::default()
        })
        .into();
        assert_eq!(
            validate_execution_control(&stream_execution, &request),
            Err(OperationCompilationError::Rejected)
        );

        let mut terminal_execution = execution;
        terminal_execution.phase = ExecutionPhase::EXECUTION_PHASE_EXITED.into();
        assert_eq!(
            validate_execution_control(&terminal_execution, &request),
            Err(OperationCompilationError::Rejected)
        );
    }
}
