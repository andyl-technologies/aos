//! Production admission for explicitly requested operator recovery.
//!
//! The public body names only a resource identity. Protected controller state
//! resolves whether that identity denotes a sandbox or an operation before the
//! capability check is built. The checked recovery current head is then
//! committed atomically with the public operation and its orchestration effect.

use aos_sandbox_core::{CapabilityId, OperationId, ProjectId, ResourceId, ResourceKind, Selector};

use crate::cli_model::{
    DormantSandboxRequestKindV1, OperatorRecoveryRequestV1, PublicApiAuditMethodV1,
    PublicMutationRequestV1,
};
use crate::controller_query::{
    CheckedOperationResourceV1, CheckedSandboxResourceV1, PublicOperationMethodV1,
};
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use crate::{
    EffectPlan, IdempotencyKey, IdempotencyOutcome, Journal, OperationCompilationError,
    OperationPlan, PublicOperationAdmissionV1, PublicOperationAuthorizationV1,
};

pub(super) fn compile_public_operator_recovery(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    capability_id: CapabilityId,
    canonical_request: &[u8],
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    let envelope = PublicMutationRequestV1::decode(canonical_request)
        .map_err(|_| OperationCompilationError::Malformed)?;
    if envelope.method() != PublicApiAuditMethodV1::OperatorRecover {
        return Err(OperationCompilationError::Malformed);
    }
    let DormantSandboxRequestKindV1::OperatorRecover(request) = envelope
        .decode_validated_kind()
        .map_err(|_| OperationCompilationError::Malformed)?
    else {
        return Err(OperationCompilationError::Malformed);
    };
    let request = OperatorRecoveryRequestV1::try_from(request)
        .map_err(|_| OperationCompilationError::Malformed)?;
    let idempotency_key = IdempotencyKey::new(request.idempotency_key().to_vec())
        .map_err(|_| OperationCompilationError::Malformed)?;

    match journal.check_idempotency(&idempotency_key, request_digest) {
        IdempotencyOutcome::Replay(operation_id) => {
            return replay_operator_recovery(
                journal,
                operation_id,
                idempotency_key,
                canonical_request,
                request_digest,
            );
        }
        IdempotencyOutcome::Conflict => return Err(OperationCompilationError::Rejected),
        IdempotencyOutcome::Vacant => {}
    }

    let target = resolve_recovery_target(journal, peer.project(), request.resource_id())?;
    if !target.current.validates_request(&request) {
        return Err(OperationCompilationError::Rejected);
    }
    let selector = Selector::Resource {
        resource: ResourceId::from_bytes(request.resource_id()),
    };
    let authorization = crate::controller::authorize_public_operator_recovery_v1(
        journal,
        peer,
        capability_id,
        target.resource_kind,
        selector.clone(),
        envelope.protobuf_body(),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;

    let operation_id = OperationId::new();
    let desired = super::public_mutation::mutation_intent(
        operation_id,
        PublicOperationMethodV1::OperatorRecover,
        canonical_request,
    );
    let effect = EffectPlan::public_mutation(
        PublicOperationMethodV1::OperatorRecover,
        canonical_request.to_vec(),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let plan = OperationPlan::new(
        operation_id,
        idempotency_key,
        request_digest,
        desired.0,
        desired.1,
        vec![effect],
    )
    .map_err(|_| OperationCompilationError::Rejected)?
    .with_operator_recovery_records(vec![target.current.into_record()])
    .map_err(|_| OperationCompilationError::Rejected)?;
    let scope = PublicOperationAuthorizationV1::new(peer.project(), target.resource_kind, selector)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let public = PublicOperationAdmissionV1::new(
        PublicOperationMethodV1::OperatorRecover,
        1,
        operation_id.into_bytes(),
        authorization.accepted_wall_seconds(),
        scope,
    )
    .map_err(|_| OperationCompilationError::Rejected)?;

    plan.with_public_operation(public)
        .map_err(|_| OperationCompilationError::Rejected)
}

struct ResolvedRecoveryTargetV1 {
    resource_kind: ResourceKind,
    current: crate::controller::PreparedOperatorRecoveryCurrentV1,
}

fn resolve_recovery_target(
    journal: &Journal,
    project: ProjectId,
    resource_id: [u8; 16],
) -> Result<ResolvedRecoveryTargetV1, OperationCompilationError> {
    let sandbox = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Sandbox, resource_id)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let operation_id = OperationId::from_bytes(resource_id);
    let operation =
        crate::reconciler::recovered_public_operation_resource_v1(journal, operation_id)
            .map_err(|_| OperationCompilationError::Rejected)?;

    match (sandbox, operation) {
        (Some(sandbox), None) => {
            if sandbox.project() != project {
                return Err(OperationCompilationError::Rejected);
            }
            let PublicProjectionResourceV1::Sandbox(resource) = sandbox.resource() else {
                return Err(OperationCompilationError::Rejected);
            };
            let resource = CheckedSandboxResourceV1::try_from(resource.clone())
                .map_err(|_| OperationCompilationError::Rejected)?;
            let current =
                crate::controller::prepare_operator_recovery_sandbox_current_v1(journal, &resource)
                    .map_err(|_| OperationCompilationError::Rejected)?;
            Ok(ResolvedRecoveryTargetV1 {
                resource_kind: ResourceKind::Sandbox,
                current,
            })
        }
        (None, Some(resource)) => {
            let scope = crate::reconciler::recovered_public_operation_authorization_v1(
                journal,
                operation_id,
            )
            .map_err(|_| OperationCompilationError::Rejected)?
            .ok_or(OperationCompilationError::Rejected)?;
            if scope.project() != project {
                return Err(OperationCompilationError::Rejected);
            }
            let resource = CheckedOperationResourceV1::try_from(resource)
                .map_err(|_| OperationCompilationError::Rejected)?;
            let current = crate::controller::prepare_operator_recovery_operation_current_v1(
                journal, &resource,
            )
            .map_err(|_| OperationCompilationError::Rejected)?;
            Ok(ResolvedRecoveryTargetV1 {
                resource_kind: ResourceKind::Operation,
                current,
            })
        }
        (Some(_), Some(_)) | (None, None) => Err(OperationCompilationError::Rejected),
    }
}

fn replay_operator_recovery(
    journal: &Journal,
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    canonical_request: &[u8],
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    let desired = super::public_mutation::mutation_intent(
        operation_id,
        PublicOperationMethodV1::OperatorRecover,
        canonical_request,
    );
    let effect = EffectPlan::public_mutation(
        PublicOperationMethodV1::OperatorRecover,
        canonical_request.to_vec(),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let public = crate::reconciler::recovered_public_operation_admission_v1(journal, operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;

    OperationPlan::new(
        operation_id,
        idempotency_key,
        request_digest,
        desired.0,
        desired.1,
        vec![effect],
    )
    .map_err(|_| OperationCompilationError::Rejected)?
    .with_public_operation(public)
    .map_err(|_| OperationCompilationError::Rejected)
}
