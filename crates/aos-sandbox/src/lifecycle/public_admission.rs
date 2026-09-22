//! Public mutation to protected lifecycle admission joins.
//!
//! Public request compilation persists requested projections before the
//! controller effect runs. This module reconstructs only identities generated
//! by that same accepted operation. Present-state fences come from either the
//! request's already-validated predecessor version or the protected current
//! runtime assignment; they are never inferred from a successor projection.

use aos_proto::aos::sandbox::v1::MutationContext;
use aos_sandbox_core::{
    DesiredGeneration, ExecutionId, NodeId, OperationId, ProjectId, ResourceId, Revision,
    SandboxId, SnapshotId, ViewId,
};

use crate::Journal;
use crate::cli_model::DormantSandboxRequestKindV1;
use crate::controller_service::public_projection::{
    PublicProjectionError, PublicProjectionKindV1, PublicProjectionRecordV1,
    PublicProjectionResourceV1, PublicProjectionStoreV1,
};

use super::{
    DesiredStateFenceV1, LifecycleIntentV1, LifecycleModelError, LifecycleResourceStateDigestV1,
    LifecycleResourceV1, LifecycleResumeSourceV1, LifecycleRuntimeAdmissionErrorV1,
    LifecycleRuntimeAdmissionFenceV1, LifecycleTargetFenceV1, ResourceExpectationV1,
    ResourceExpectedStateV1, lifecycle_runtime_admission_fence_from_journal_v1,
};

/// Retains one method-specific intent and its exact canonical expectations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecyclePublicMutationAdmissionV1 {
    intent: LifecycleIntentV1,
    expectations: Vec<ResourceExpectationV1>,
}

impl LifecyclePublicMutationAdmissionV1 {
    /// Borrows the method-specific protected lifecycle intent.
    #[must_use]
    pub const fn intent(&self) -> &LifecycleIntentV1 {
        &self.intent
    }

    /// Borrows expectations in canonical resource order.
    #[must_use]
    pub fn expectations(&self) -> &[ResourceExpectationV1] {
        &self.expectations
    }
}

/// Reports why an accepted public mutation cannot form a protected intent.
#[derive(Debug, thiserror::Error)]
pub enum LifecyclePublicMutationAdmissionErrorV1 {
    /// The public method belongs to a non-lifecycle effect family.
    #[error("public mutation does not map to a lifecycle intent")]
    UnsupportedMethod,
    /// An accepted operation has no unique generated projection of the required kind.
    #[error("accepted operation projection is unavailable")]
    MissingOperationProjection,
    /// A referenced public resource is absent or belongs to another project.
    #[error("current public resource is unavailable")]
    MissingCurrentProjection,
    /// A stable identity or predecessor version is malformed.
    #[error("public lifecycle admission identity is invalid")]
    InvalidIdentity,
    /// A successor projection cannot prove the predecessor generation named by the request.
    #[error("public lifecycle predecessor fence is invalid")]
    InvalidPredecessor,
    /// The public projection namespace is malformed.
    #[error(transparent)]
    PublicProjection(#[from] PublicProjectionError),
    /// The protected runtime join is absent, stale, or malformed.
    #[error(transparent)]
    Runtime(#[from] LifecycleRuntimeAdmissionErrorV1),
    /// The resulting lifecycle fence violates the closed model.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleModelError),
}

/// Compiles one accepted public request into protected lifecycle intent.
///
/// Generated target identities are read only from projections atomically
/// admitted by `operation`. Existing-resource predecessor fences use the exact
/// resource version validated by public admission. Runtime-bound methods join
/// the public observation to protected assignment state and therefore retain
/// the real namespace generation.
///
/// # Errors
///
/// Returns [`LifecyclePublicMutationAdmissionErrorV1`] when the method is not
/// a lifecycle operation, an identity or projection is missing, or any public
/// and protected current-state join fails closed.
pub fn lifecycle_public_mutation_admission_v1(
    journal: &mut Journal,
    operation: OperationId,
    project: ProjectId,
    node: NodeId,
    request: &DormantSandboxRequestKindV1,
) -> Result<LifecyclePublicMutationAdmissionV1, LifecyclePublicMutationAdmissionErrorV1> {
    use DormantSandboxRequestKindV1 as Request;

    let (intent, mut expectations) = match request {
        Request::Create(_) => {
            let sandbox = generated_sandbox(journal, operation, project)?;
            let resource = LifecycleResourceV1::Sandbox(sandbox);
            (
                LifecycleIntentV1::Create { sandbox },
                vec![ResourceExpectationV1::absent(resource)?],
            )
        }
        Request::UpdatePolicy(request) => {
            let sandbox = exact_sandbox(&request.sandbox_id)?;
            let (expectation, fence) = predecessor_fence(
                operation_projection(journal, operation, project, PublicProjectionKindV1::Sandbox)?,
                LifecycleResourceV1::Sandbox(sandbox),
                mutation(request.mutation.as_option())?,
            )?;
            (
                LifecycleIntentV1::UpdatePolicy { sandbox, fence },
                vec![expectation],
            )
        }
        Request::Start(request) => {
            let sandbox = exact_sandbox(&request.sandbox_id)?;
            let (expectation, fence) = predecessor_fence(
                operation_projection(journal, operation, project, PublicProjectionKindV1::Sandbox)?,
                LifecycleResourceV1::Sandbox(sandbox),
                mutation(request.mutation.as_option())?,
            )?;
            (
                LifecycleIntentV1::Start { sandbox, fence },
                vec![expectation],
            )
        }
        Request::Stop(request) => {
            let sandbox = exact_sandbox(&request.sandbox_id)?;
            let runtime = runtime_fence(journal, project, sandbox, node)?;
            (
                LifecycleIntentV1::Stop {
                    sandbox,
                    fence: runtime.runtime(),
                },
                vec![runtime.expectation().clone()],
            )
        }
        Request::Suspend(request) => {
            let sandbox = exact_sandbox(&request.sandbox_id)?;
            let runtime = runtime_fence(journal, project, sandbox, node)?;
            (
                LifecycleIntentV1::SuspendMemory {
                    sandbox,
                    fence: runtime.runtime(),
                },
                vec![runtime.expectation().clone()],
            )
        }
        Request::Resume(request) => {
            let sandbox = exact_sandbox(&request.sandbox_id)?;
            let runtime = runtime_fence(journal, project, sandbox, node)?;
            (
                LifecycleIntentV1::Resume {
                    sandbox,
                    source: LifecycleResumeSourceV1::Memory {
                        fence: runtime.runtime(),
                    },
                },
                vec![runtime.expectation().clone()],
            )
        }
        Request::Delete(request) => {
            let sandbox = exact_sandbox(&request.sandbox_id)?;
            let (expectation, fence) = predecessor_fence(
                operation_projection(journal, operation, project, PublicProjectionKindV1::Sandbox)?,
                LifecycleResourceV1::Sandbox(sandbox),
                mutation(request.mutation.as_option())?,
            )?;
            (
                LifecycleIntentV1::DeleteSandbox { sandbox, fence },
                vec![expectation],
            )
        }
        Request::Exec(request) => {
            let sandbox = exact_sandbox(&request.sandbox_id)?;
            let execution = generated_execution(journal, operation, project)?;
            let runtime = runtime_fence(journal, project, sandbox, node)?;
            let target = absent_target(LifecycleResourceV1::Execution(execution))?;
            (
                LifecycleIntentV1::CreateExecution {
                    sandbox,
                    execution,
                    fence: runtime.runtime(),
                    target_fence: target.1,
                },
                vec![runtime.expectation().clone(), target.0],
            )
        }
        Request::CancelExec(request) => {
            let execution = exact_execution(&request.execution_id)?;
            let execution_projection = current_projection(
                journal,
                project,
                PublicProjectionKindV1::Execution,
                *execution.as_bytes(),
            )?;
            let sandbox = execution_sandbox(&execution_projection)?;
            let runtime = runtime_fence(journal, project, sandbox, node)?;
            let target = current_target_fence(
                &execution_projection,
                LifecycleResourceV1::Execution(execution),
                mutation(request.mutation.as_option())?,
            )?;
            (
                LifecycleIntentV1::CancelExecution {
                    execution,
                    fence: runtime.runtime(),
                    target_fence: target.1,
                },
                vec![runtime.expectation().clone(), target.0],
            )
        }
        Request::ViewCreate(_) => {
            let view = generated_view(journal, operation, project)?;
            let resource = LifecycleResourceV1::View(view);
            (
                LifecycleIntentV1::CreateView { view },
                vec![ResourceExpectationV1::absent(resource)?],
            )
        }
        Request::ViewAttach(request) => {
            let sandbox = exact_sandbox(&request.sandbox_id)?;
            let view = exact_view(&request.view_id)?;
            let attachment = generated_attachment(journal, operation, project)?;
            let runtime = runtime_fence(journal, project, sandbox, node)?;
            let view_expectation = current_expectation(current_projection(
                journal,
                project,
                PublicProjectionKindV1::FilesystemView,
                *view.as_bytes(),
            )?)?;
            let target = absent_target(LifecycleResourceV1::Attachment(ResourceId::from_bytes(
                attachment,
            )))?;
            (
                LifecycleIntentV1::AttachView {
                    sandbox,
                    view,
                    attachment: ResourceId::from_bytes(attachment),
                    fence: runtime.runtime(),
                    target_fence: target.1,
                },
                vec![runtime.expectation().clone(), view_expectation, target.0],
            )
        }
        Request::ViewReplace(request) => {
            let attachment = exact_resource(&request.attachment_id)?;
            let view = exact_view(&request.new_view_id)?;
            let projection = operation_projection(
                journal,
                operation,
                project,
                PublicProjectionKindV1::Attachment,
            )?;
            let sandbox = attachment_sandbox(&projection)?;
            let runtime = runtime_fence(journal, project, sandbox, node)?;
            let target = predecessor_target_fence(
                &projection,
                LifecycleResourceV1::Attachment(attachment),
                mutation(request.mutation.as_option())?,
            )?;
            let view_expectation = current_expectation(current_projection(
                journal,
                project,
                PublicProjectionKindV1::FilesystemView,
                *view.as_bytes(),
            )?)?;
            (
                LifecycleIntentV1::ReplaceAttachment {
                    attachment,
                    view,
                    fence: runtime.runtime(),
                    target_fence: target.1,
                },
                vec![runtime.expectation().clone(), view_expectation, target.0],
            )
        }
        Request::ViewDetach(request) => {
            let attachment = exact_resource(&request.attachment_id)?;
            let projection = operation_projection(
                journal,
                operation,
                project,
                PublicProjectionKindV1::Attachment,
            )?;
            let sandbox = attachment_sandbox(&projection)?;
            let runtime = runtime_fence(journal, project, sandbox, node)?;
            let target = predecessor_target_fence(
                &projection,
                LifecycleResourceV1::Attachment(attachment),
                mutation(request.mutation.as_option())?,
            )?;
            (
                LifecycleIntentV1::DetachView {
                    attachment,
                    fence: runtime.runtime(),
                    target_fence: target.1,
                },
                vec![runtime.expectation().clone(), target.0],
            )
        }
        Request::ViewRelease(request) => {
            let view = exact_view(&request.view_id)?;
            let (expectation, fence) = predecessor_fence(
                operation_projection(
                    journal,
                    operation,
                    project,
                    PublicProjectionKindV1::FilesystemView,
                )?,
                LifecycleResourceV1::View(view),
                mutation(request.mutation.as_option())?,
            )?;
            (
                LifecycleIntentV1::ReleaseView { view, fence },
                vec![expectation],
            )
        }
        Request::Snapshot(request) => {
            let sandbox = exact_sandbox(&request.sandbox_id)?;
            let snapshot = generated_snapshot(journal, operation, project)?;
            let runtime = runtime_fence(journal, project, sandbox, node)?;
            let target = absent_target(LifecycleResourceV1::Snapshot(snapshot))?;
            (
                LifecycleIntentV1::Snapshot {
                    sandbox,
                    snapshot,
                    fence: runtime.runtime(),
                    target_fence: target.1,
                },
                vec![runtime.expectation().clone(), target.0],
            )
        }
        Request::Fork(request) => {
            let source = exact_snapshot(&request.snapshot_id)?;
            let target = generated_sandbox(journal, operation, project)?;
            let source_expectation = current_expectation(current_projection(
                journal,
                project,
                PublicProjectionKindV1::Snapshot,
                *source.as_bytes(),
            )?)?;
            let target_expectation =
                ResourceExpectationV1::absent(LifecycleResourceV1::Sandbox(target))?;
            (
                LifecycleIntentV1::Fork { source, target },
                vec![source_expectation, target_expectation],
            )
        }
        Request::DeleteSnapshot(request) => {
            let snapshot = exact_snapshot(&request.snapshot_id)?;
            let (expectation, fence) = predecessor_fence(
                operation_projection(
                    journal,
                    operation,
                    project,
                    PublicProjectionKindV1::Snapshot,
                )?,
                LifecycleResourceV1::Snapshot(snapshot),
                mutation(request.mutation.as_option())?,
            )?;
            (
                LifecycleIntentV1::DeleteSnapshot { snapshot, fence },
                vec![expectation],
            )
        }
        _ => return Err(LifecyclePublicMutationAdmissionErrorV1::UnsupportedMethod),
    };

    expectations.sort_unstable_by_key(ResourceExpectationV1::resource);
    if expectations
        .windows(2)
        .any(|pair| pair[0].resource() == pair[1].resource())
    {
        return Err(LifecyclePublicMutationAdmissionErrorV1::InvalidIdentity);
    }

    Ok(LifecyclePublicMutationAdmissionV1 {
        intent,
        expectations,
    })
}

fn runtime_fence(
    journal: &mut Journal,
    project: ProjectId,
    sandbox: SandboxId,
    node: NodeId,
) -> Result<LifecycleRuntimeAdmissionFenceV1, LifecyclePublicMutationAdmissionErrorV1> {
    lifecycle_runtime_admission_fence_from_journal_v1(journal, project, sandbox, node)
        .map_err(Into::into)
}

fn absent_target(
    resource: LifecycleResourceV1,
) -> Result<(ResourceExpectationV1, LifecycleTargetFenceV1), LifecyclePublicMutationAdmissionErrorV1>
{
    Ok((
        ResourceExpectationV1::absent(resource)?,
        LifecycleTargetFenceV1::new(
            resource,
            DesiredGeneration::new(0),
            ResourceExpectedStateV1::Absent,
        )?,
    ))
}

fn predecessor_fence(
    projection: PublicProjectionRecordV1,
    resource: LifecycleResourceV1,
    mutation: &MutationContext,
) -> Result<(ResourceExpectationV1, DesiredStateFenceV1), LifecyclePublicMutationAdmissionErrorV1> {
    let successor = projection_generation(&projection)?;
    let predecessor = successor
        .checked_sub(1)
        .filter(|generation| *generation != 0)
        .ok_or(LifecyclePublicMutationAdmissionErrorV1::InvalidPredecessor)?;
    if projection.resource().resource_id() != resource.as_bytes()
        || mutation.expected_resource_version.is_empty()
    {
        return Err(LifecyclePublicMutationAdmissionErrorV1::InvalidPredecessor);
    }
    let revision = Revision::new(predecessor);
    let state = LifecycleResourceStateDigestV1::commit(&mutation.expected_resource_version);
    Ok((
        ResourceExpectationV1::present(resource, revision, state)?,
        DesiredStateFenceV1::new(
            resource,
            DesiredGeneration::new(predecessor),
            revision,
            state,
        )?,
    ))
}

fn predecessor_target_fence(
    projection: &PublicProjectionRecordV1,
    resource: LifecycleResourceV1,
    mutation: &MutationContext,
) -> Result<(ResourceExpectationV1, LifecycleTargetFenceV1), LifecyclePublicMutationAdmissionErrorV1>
{
    let successor = projection_generation(projection)?;
    let predecessor = successor
        .checked_sub(1)
        .filter(|generation| *generation != 0)
        .ok_or(LifecyclePublicMutationAdmissionErrorV1::InvalidPredecessor)?;
    if projection.resource().resource_id() != resource.as_bytes()
        || mutation.expected_resource_version.is_empty()
    {
        return Err(LifecyclePublicMutationAdmissionErrorV1::InvalidPredecessor);
    }
    let revision = Revision::new(predecessor);
    let state = LifecycleResourceStateDigestV1::commit(&mutation.expected_resource_version);
    let expected = ResourceExpectedStateV1::Present {
        revision,
        state_digest: state,
    };
    Ok((
        ResourceExpectationV1::present(resource, revision, state)?,
        LifecycleTargetFenceV1::new(resource, DesiredGeneration::new(predecessor), expected)?,
    ))
}

fn current_target_fence(
    projection: &PublicProjectionRecordV1,
    resource: LifecycleResourceV1,
    mutation: &MutationContext,
) -> Result<(ResourceExpectationV1, LifecycleTargetFenceV1), LifecyclePublicMutationAdmissionErrorV1>
{
    let generation = projection_generation(projection)?;
    if projection.resource().resource_id() != resource.as_bytes()
        || mutation.expected_resource_version.is_empty()
    {
        return Err(LifecyclePublicMutationAdmissionErrorV1::InvalidPredecessor);
    }
    let revision = Revision::new(generation);
    let state = LifecycleResourceStateDigestV1::commit(&mutation.expected_resource_version);
    let expected = ResourceExpectedStateV1::Present {
        revision,
        state_digest: state,
    };
    Ok((
        ResourceExpectationV1::present(resource, revision, state)?,
        LifecycleTargetFenceV1::new(resource, DesiredGeneration::new(generation), expected)?,
    ))
}

fn current_expectation(
    projection: PublicProjectionRecordV1,
) -> Result<ResourceExpectationV1, LifecyclePublicMutationAdmissionErrorV1> {
    let resource = projection_resource(projection.resource())?;
    let generation = projection_generation(&projection)?;
    let state = LifecycleResourceStateDigestV1::from_stored(projection.revision())?;
    Ok(ResourceExpectationV1::present(
        resource,
        Revision::new(generation),
        state,
    )?)
}

fn operation_projection(
    journal: &Journal,
    operation: OperationId,
    project: ProjectId,
    kind: PublicProjectionKindV1,
) -> Result<PublicProjectionRecordV1, LifecyclePublicMutationAdmissionErrorV1> {
    let mut matching = PublicProjectionStoreV1::new(journal)
        .list_operation(operation)?
        .into_iter()
        .filter(|projection| projection.resource().kind() == kind);
    let projection = matching
        .next()
        .filter(|projection| projection.project() == project)
        .ok_or(LifecyclePublicMutationAdmissionErrorV1::MissingOperationProjection)?;
    if matching.next().is_some() {
        return Err(LifecyclePublicMutationAdmissionErrorV1::MissingOperationProjection);
    }
    Ok(projection)
}

fn current_projection(
    journal: &Journal,
    project: ProjectId,
    kind: PublicProjectionKindV1,
    identity: [u8; 16],
) -> Result<PublicProjectionRecordV1, LifecyclePublicMutationAdmissionErrorV1> {
    PublicProjectionStoreV1::new(journal)
        .get(kind, identity)?
        .filter(|projection| projection.project() == project)
        .ok_or(LifecyclePublicMutationAdmissionErrorV1::MissingCurrentProjection)
}

fn generated_sandbox(
    journal: &Journal,
    operation: OperationId,
    project: ProjectId,
) -> Result<SandboxId, LifecyclePublicMutationAdmissionErrorV1> {
    let projection =
        operation_projection(journal, operation, project, PublicProjectionKindV1::Sandbox)?;
    exact_sandbox(projection.resource().resource_id())
}

fn generated_execution(
    journal: &Journal,
    operation: OperationId,
    project: ProjectId,
) -> Result<ExecutionId, LifecyclePublicMutationAdmissionErrorV1> {
    let projection = operation_projection(
        journal,
        operation,
        project,
        PublicProjectionKindV1::Execution,
    )?;
    exact_execution(projection.resource().resource_id())
}

fn generated_view(
    journal: &Journal,
    operation: OperationId,
    project: ProjectId,
) -> Result<ViewId, LifecyclePublicMutationAdmissionErrorV1> {
    let projection = operation_projection(
        journal,
        operation,
        project,
        PublicProjectionKindV1::FilesystemView,
    )?;
    exact_view(projection.resource().resource_id())
}

fn generated_attachment(
    journal: &Journal,
    operation: OperationId,
    project: ProjectId,
) -> Result<[u8; 16], LifecyclePublicMutationAdmissionErrorV1> {
    let projection = operation_projection(
        journal,
        operation,
        project,
        PublicProjectionKindV1::Attachment,
    )?;
    exact_identity(projection.resource().resource_id())
}

fn generated_snapshot(
    journal: &Journal,
    operation: OperationId,
    project: ProjectId,
) -> Result<SnapshotId, LifecyclePublicMutationAdmissionErrorV1> {
    let projection = operation_projection(
        journal,
        operation,
        project,
        PublicProjectionKindV1::Snapshot,
    )?;
    exact_snapshot(projection.resource().resource_id())
}

fn projection_resource(
    resource: &PublicProjectionResourceV1,
) -> Result<LifecycleResourceV1, LifecyclePublicMutationAdmissionErrorV1> {
    Ok(match resource {
        PublicProjectionResourceV1::Sandbox(value) => {
            LifecycleResourceV1::Sandbox(exact_sandbox(&value.sandbox_id)?)
        }
        PublicProjectionResourceV1::Execution(value) => {
            LifecycleResourceV1::Execution(exact_execution(&value.execution_id)?)
        }
        PublicProjectionResourceV1::FilesystemView(value) => {
            LifecycleResourceV1::View(exact_view(&value.view_id)?)
        }
        PublicProjectionResourceV1::Attachment(value) => {
            LifecycleResourceV1::Attachment(exact_resource(&value.attachment_id)?)
        }
        PublicProjectionResourceV1::Snapshot(value) => {
            LifecycleResourceV1::Snapshot(exact_snapshot(&value.snapshot_id)?)
        }
        PublicProjectionResourceV1::Capability(value) => {
            LifecycleResourceV1::Capability(exact_resource(&value.capability_id)?)
        }
        PublicProjectionResourceV1::ProjectCacheStatus { project_id, .. } => {
            LifecycleResourceV1::Project(ProjectId::from_bytes(*project_id))
        }
        PublicProjectionResourceV1::SandboxCacheStatus { sandbox_id, .. } => {
            LifecycleResourceV1::Sandbox(SandboxId::from_bytes(*sandbox_id))
        }
    })
}

fn projection_generation(
    projection: &PublicProjectionRecordV1,
) -> Result<u64, LifecyclePublicMutationAdmissionErrorV1> {
    let generation = match projection.resource() {
        PublicProjectionResourceV1::Sandbox(value) => {
            value.desired.as_option().map(|desired| desired.generation)
        }
        PublicProjectionResourceV1::Execution(value) => Some(value.desired_generation),
        PublicProjectionResourceV1::FilesystemView(value) => Some(value.desired_generation),
        PublicProjectionResourceV1::Attachment(value) => Some(value.desired_generation),
        PublicProjectionResourceV1::Snapshot(value) => Some(value.desired_generation),
        PublicProjectionResourceV1::Capability(_)
        | PublicProjectionResourceV1::ProjectCacheStatus { .. }
        | PublicProjectionResourceV1::SandboxCacheStatus { .. } => None,
    }
    .filter(|generation| *generation != 0 && *generation != u64::MAX)
    .ok_or(LifecyclePublicMutationAdmissionErrorV1::InvalidPredecessor)?;
    Ok(generation)
}

fn execution_sandbox(
    projection: &PublicProjectionRecordV1,
) -> Result<SandboxId, LifecyclePublicMutationAdmissionErrorV1> {
    let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
        return Err(LifecyclePublicMutationAdmissionErrorV1::MissingCurrentProjection);
    };
    exact_sandbox(&execution.sandbox_id)
}

fn attachment_sandbox(
    projection: &PublicProjectionRecordV1,
) -> Result<SandboxId, LifecyclePublicMutationAdmissionErrorV1> {
    let PublicProjectionResourceV1::Attachment(attachment) = projection.resource() else {
        return Err(LifecyclePublicMutationAdmissionErrorV1::MissingCurrentProjection);
    };
    exact_sandbox(&attachment.sandbox_id)
}

fn mutation(
    mutation: Option<&MutationContext>,
) -> Result<&MutationContext, LifecyclePublicMutationAdmissionErrorV1> {
    mutation.ok_or(LifecyclePublicMutationAdmissionErrorV1::InvalidPredecessor)
}

fn exact_sandbox(bytes: &[u8]) -> Result<SandboxId, LifecyclePublicMutationAdmissionErrorV1> {
    exact_identity(bytes).map(SandboxId::from_bytes)
}

fn exact_execution(bytes: &[u8]) -> Result<ExecutionId, LifecyclePublicMutationAdmissionErrorV1> {
    exact_identity(bytes).map(ExecutionId::from_bytes)
}

fn exact_snapshot(bytes: &[u8]) -> Result<SnapshotId, LifecyclePublicMutationAdmissionErrorV1> {
    exact_identity(bytes).map(SnapshotId::from_bytes)
}

fn exact_view(bytes: &[u8]) -> Result<ViewId, LifecyclePublicMutationAdmissionErrorV1> {
    exact_identity(bytes).map(ViewId::from_bytes)
}

fn exact_resource(bytes: &[u8]) -> Result<ResourceId, LifecyclePublicMutationAdmissionErrorV1> {
    exact_identity(bytes).map(ResourceId::from_bytes)
}

fn exact_identity(bytes: &[u8]) -> Result<[u8; 16], LifecyclePublicMutationAdmissionErrorV1> {
    let identity = bytes
        .try_into()
        .map_err(|_| LifecyclePublicMutationAdmissionErrorV1::InvalidIdentity)?;
    if identity == [0; 16] {
        return Err(LifecyclePublicMutationAdmissionErrorV1::InvalidIdentity);
    }
    Ok(identity)
}
