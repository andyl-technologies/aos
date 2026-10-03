//! Protected lifecycle-operation construction from authenticated public mutations.
//!
//! Public admission has already selected the immutable intent and canonical
//! resource expectations. This module adds authenticated request identity,
//! idempotency, admission time, and a non-executable plan skeleton so the
//! operation can enter protected custody before late coordination records and
//! complete lower-domain plans exist.

use aos_proto::aos::sandbox::v1::MutationContext;
use aos_sandbox_core::{OperationId, PrincipalId, ProjectId, Revision};

use crate::cli_model::DormantSandboxRequestKindV1;

use super::{
    LifecycleIdempotencyDigestV1, LifecycleModelError, LifecycleOperationV1, LifecyclePhaseV1,
    LifecyclePublicMutationAdmissionV1, LifecycleStepClassV1, LifecycleStepDomainV1,
    LifecycleStepRequestDigestV1, LifecycleStepV1, LifecycleTimeV1,
};

/// Reports why an authenticated public mutation cannot become a lifecycle operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LifecyclePublicOperationErrorV1 {
    /// The request is not a lifecycle mutation supported by this compiler.
    #[error("public mutation does not map to a lifecycle operation")]
    UnsupportedMethod,
    /// The request is missing its validated idempotency binding.
    #[error("public lifecycle mutation has no idempotency binding")]
    MissingIdempotency,
    /// The authenticated admission clock cannot be represented canonically.
    #[error("public lifecycle admission time is invalid")]
    InvalidAdmissionTime,
    /// The compiled record violates a closed lifecycle invariant.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleModelError),
}

/// Constructs the first protected record for an authenticated public mutation.
///
/// The single unbound Controller step is a plan anchor, not effect authority.
/// A later same-phase protected successor replaces it atomically with the
/// complete bound action sequence. No attempt can be reserved from the anchor.
///
/// # Errors
///
/// Returns [`LifecyclePublicOperationErrorV1`] when the request has no
/// lifecycle idempotency key, the admission time overflows nanoseconds, or the
/// resulting first revision violates the lifecycle model.
pub fn lifecycle_operation_from_public_mutation_v1(
    operation: OperationId,
    caller: PrincipalId,
    project: ProjectId,
    accepted_wall_seconds: i64,
    canonical_request: &[u8],
    request: &DormantSandboxRequestKindV1,
    admission: LifecyclePublicMutationAdmissionV1,
) -> Result<LifecycleOperationV1, LifecyclePublicOperationErrorV1> {
    let accepted_seconds = u64::try_from(accepted_wall_seconds)
        .map_err(|_| LifecyclePublicOperationErrorV1::InvalidAdmissionTime)?;
    let accepted_nanoseconds = accepted_seconds
        .checked_mul(1_000_000_000)
        .ok_or(LifecyclePublicOperationErrorV1::InvalidAdmissionTime)?;
    let accepted_at = LifecycleTimeV1::new(accepted_nanoseconds)
        .map_err(|_| LifecyclePublicOperationErrorV1::InvalidAdmissionTime)?;
    let idempotency = request_idempotency(request)?;
    let plan_anchor = LifecycleStepV1::unbound(
        0,
        LifecycleStepClassV1::PostCommitForward,
        LifecycleStepDomainV1::Controller,
        LifecycleStepRequestDigestV1::commit(canonical_request),
        None,
    )?;

    LifecycleOperationV1::new(
        operation,
        caller,
        project,
        LifecycleIdempotencyDigestV1::commit(idempotency),
        admission.intent().clone(),
        accepted_at,
        Revision::new(1),
        admission.expectations().to_vec(),
        vec![plan_anchor],
        LifecyclePhaseV1::Accepted,
        0,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .map_err(Into::into)
}

fn request_idempotency(
    request: &DormantSandboxRequestKindV1,
) -> Result<&[u8], LifecyclePublicOperationErrorV1> {
    use DormantSandboxRequestKindV1 as Request;

    let idempotency = match request {
        Request::Create(request) => request.idempotency_key.as_slice(),
        Request::ViewCreate(request) => request.idempotency_key.as_slice(),
        Request::Fork(request) => request.idempotency_key.as_slice(),
        Request::UpdatePolicy(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::Start(request)
        | Request::Stop(request)
        | Request::Suspend(request)
        | Request::Resume(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::Delete(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::Exec(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::CancelExec(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::ViewAttach(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::ViewReplace(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::ViewDetach(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::ViewRelease(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::Snapshot(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::Restore(request) => mutation_idempotency(request.mutation.as_option())?,
        Request::DeleteSnapshot(request) => mutation_idempotency(request.mutation.as_option())?,
        _ => return Err(LifecyclePublicOperationErrorV1::UnsupportedMethod),
    };
    if idempotency.is_empty() {
        return Err(LifecyclePublicOperationErrorV1::MissingIdempotency);
    }
    Ok(idempotency)
}

fn mutation_idempotency(
    mutation: Option<&MutationContext>,
) -> Result<&[u8], LifecyclePublicOperationErrorV1> {
    mutation
        .map(|mutation| mutation.idempotency_key.as_slice())
        .filter(|idempotency| !idempotency.is_empty())
        .ok_or(LifecyclePublicOperationErrorV1::MissingIdempotency)
}
