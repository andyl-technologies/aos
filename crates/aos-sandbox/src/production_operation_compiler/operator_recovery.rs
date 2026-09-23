//! Production admission for explicitly requested operator recovery.
//!
//! The public body names only a resource identity. Protected controller state
//! resolves whether that identity denotes a sandbox or an operation before the
//! capability check is built. Retry commits its checked current head with an
//! orchestration effect; bounded abandonment commits only an acknowledgment
//! of a protected, already terminal operation.

use aos_proto::aos::sandbox::v1::OperatorRecoveryAction;
use aos_sandbox_core::{CapabilityId, OperationId, ProjectId, ResourceId, ResourceKind, Selector};

use crate::cli_model::{
    DormantSandboxRequestKindV1, OperatorRecoveryRequestV1, PublicApiAuditMethodV1,
    PublicMutationRequestV1,
};
use crate::controller_query::{
    CheckedOperationPhaseV1, CheckedOperationResourceV1, CheckedSandboxResourceV1,
    PublicOperationMethodV1,
};
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use crate::{
    EffectPlan, IdempotencyKey, IdempotencyOutcome, Journal, OperationCompilationError,
    OperationPlan, PublicMutationEffectV1, PublicOperationAdmissionV1,
    PublicOperationAuthorizationV1,
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
                peer,
                capability_id,
                envelope.protobuf_body(),
                &request,
            );
        }
        IdempotencyOutcome::Conflict => return Err(OperationCompilationError::Rejected),
        IdempotencyOutcome::Vacant => {}
    }

    let target = resolve_recovery_target(journal, peer.project(), request.resource_id())?;
    if !target.current.validates_request(&request) {
        return Err(OperationCompilationError::Rejected);
    }
    if request.action() == OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_ABANDON as i32 {
        return compile_blocked_abandon(
            journal,
            peer,
            capability_id,
            &envelope,
            &request,
            idempotency_key,
            canonical_request,
            request_digest,
            target,
        );
    }
    // Only ownership retry has a completing production effect. Reject other
    // recovery targets before creating an operation that cannot terminate.
    if request.action() != OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY as i32
        || target.resource_kind != ResourceKind::Operation
        || crate::reconciler::validated_ownership_gate_from_journal_v1(
            journal,
            OperationId::from_bytes(request.resource_id()),
        )
        .map_err(|_| OperationCompilationError::Rejected)?
        .is_none()
    {
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
    let effect = EffectPlan::authorized_public_mutation(
        PublicOperationMethodV1::OperatorRecover,
        PublicMutationEffectV1::new(
            peer.principal(),
            peer.project(),
            authorization.accepted_wall_seconds(),
            canonical_request.to_vec(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?,
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

#[allow(clippy::too_many_arguments)]
fn compile_blocked_abandon(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    capability_id: CapabilityId,
    envelope: &PublicMutationRequestV1,
    request: &OperatorRecoveryRequestV1,
    idempotency_key: IdempotencyKey,
    canonical_request: &[u8],
    request_digest: [u8; 32],
    target: ResolvedRecoveryTargetV1,
) -> Result<OperationPlan, OperationCompilationError> {
    // Abandonment acknowledges only a terminal blocked operation. In
    // particular, residual cleanup is not silently declared complete.
    if target.resource_kind != ResourceKind::Operation
        || target.operation_phase != Some(CheckedOperationPhaseV1::PermanentlyBlocked)
    {
        return Err(OperationCompilationError::Rejected);
    }
    let target_id = OperationId::from_bytes(request.resource_id());
    let acknowledgment_key = crate::operator_abandon_ack::key_v1(target_id);
    if journal
        .get(
            crate::RecordNamespace::OperatorRecovery,
            &acknowledgment_key,
        )
        .is_some()
    {
        return Err(OperationCompilationError::Rejected);
    }
    let selector = Selector::Resource {
        resource: ResourceId::from_bytes(request.resource_id()),
    };
    let authorization = crate::controller::authorize_public_operator_recovery_v1(
        journal,
        peer,
        capability_id,
        ResourceKind::Operation,
        selector.clone(),
        envelope.protobuf_body(),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;

    let operation_id = OperationId::new();
    let acknowledgment = crate::operator_abandon_ack::record_v1(
        operation_id,
        target_id,
        peer.principal(),
        peer.project(),
        request.idempotency_key(),
        request_digest,
        request.authority_binding(),
        request.expected_resource_version(),
    )
    .ok_or(OperationCompilationError::Rejected)?;
    let desired = super::public_mutation::mutation_intent(
        operation_id,
        PublicOperationMethodV1::OperatorRecover,
        canonical_request,
    );
    let plan = OperationPlan::completed_operator_abandon(
        operation_id,
        target_id,
        idempotency_key,
        request_digest,
        desired.0,
        desired.1,
        acknowledgment,
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let scope =
        PublicOperationAuthorizationV1::new(peer.project(), ResourceKind::Operation, selector)
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
    operation_phase: Option<CheckedOperationPhaseV1>,
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
                operation_phase: None,
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
                operation_phase: Some(resource.phase()),
            })
        }
        (Some(_), Some(_)) | (None, None) => Err(OperationCompilationError::Rejected),
    }
}

fn replay_operator_recovery(
    journal: &mut Journal,
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    canonical_request: &[u8],
    request_digest: [u8; 32],
    peer: &crate::public_api_session::PublicApiPeer,
    capability_id: CapabilityId,
    protobuf_body: &[u8],
    request: &OperatorRecoveryRequestV1,
) -> Result<OperationPlan, OperationCompilationError> {
    let desired = super::public_mutation::mutation_intent(
        operation_id,
        PublicOperationMethodV1::OperatorRecover,
        canonical_request,
    );
    let public = crate::reconciler::recovered_public_operation_admission_v1(journal, operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    if public.project() != peer.project() {
        return Err(OperationCompilationError::Rejected);
    }
    if request.action() == OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_ABANDON as i32 {
        let target = OperationId::from_bytes(request.resource_id());
        let selector = Selector::Resource {
            resource: ResourceId::from_bytes(request.resource_id()),
        };
        crate::controller::authorize_public_operator_recovery_v1(
            journal,
            peer,
            capability_id,
            ResourceKind::Operation,
            selector,
            protobuf_body,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let acknowledgment = crate::operator_abandon_ack::record_v1(
            operation_id,
            target,
            peer.principal(),
            peer.project(),
            request.idempotency_key(),
            request_digest,
            request.authority_binding(),
            request.expected_resource_version(),
        )
        .ok_or(OperationCompilationError::Rejected)?;
        if journal.get(acknowledgment.namespace(), acknowledgment.key()) != acknowledgment.value() {
            return Err(OperationCompilationError::Rejected);
        }
        return OperationPlan::completed_operator_abandon(
            operation_id,
            target,
            idempotency_key,
            request_digest,
            desired.0,
            desired.1,
            acknowledgment,
        )
        .map_err(|_| OperationCompilationError::Rejected)?
        .with_public_operation(public)
        .map_err(|_| OperationCompilationError::Rejected);
    }
    let effect = EffectPlan::authorized_public_mutation(
        PublicOperationMethodV1::OperatorRecover,
        PublicMutationEffectV1::new(
            peer.principal(),
            public.project(),
            public.accepted_wall_seconds(),
            canonical_request.to_vec(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?,
    )
    .map_err(|_| OperationCompilationError::Rejected)?;

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
