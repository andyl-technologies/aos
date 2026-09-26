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

mod successor;

pub(crate) use successor::repair_sandbox_successor_projection_v1;

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

    match checked_recovery_idempotency(journal, &request, &idempotency_key, request_digest)? {
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
    if !supported_public_recovery_action(request.action()) {
        return Err(OperationCompilationError::Rejected);
    }
    let desired = super::public_mutation::mutation_intent(
        operation_id,
        PublicOperationMethodV1::OperatorRecover,
        canonical_request,
    );
    let public = crate::reconciler::recovered_public_operation_admission_v1(journal, operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    let selector = Selector::Resource {
        resource: ResourceId::from_bytes(request.resource_id()),
    };
    require_replayed_recovery_authorization(
        request.action(),
        &public,
        peer.project(),
        request.resource_id(),
        || {
            crate::controller::authorize_public_operator_recovery_v1(
                journal,
                peer,
                capability_id,
                ResourceKind::Operation,
                selector,
                protobuf_body,
            )
            .map(|_| ())
            .map_err(|_| OperationCompilationError::Rejected)
        },
    )?;
    if request.action() == OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_ABANDON as i32 {
        let target = OperationId::from_bytes(request.resource_id());
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

fn supported_public_recovery_action(action: i32) -> bool {
    action == OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY as i32
        || action == OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_ABANDON as i32
}

fn checked_recovery_idempotency(
    journal: &Journal,
    request: &OperatorRecoveryRequestV1,
    idempotency_key: &IdempotencyKey,
    request_digest: [u8; 32],
) -> Result<IdempotencyOutcome, OperationCompilationError> {
    // Replaying an operation is a new public admission decision. Physical
    // actions remain closed even if an older journal contains their identity.
    if !supported_public_recovery_action(request.action()) {
        return Err(OperationCompilationError::Rejected);
    }
    Ok(journal.check_idempotency(idempotency_key, request_digest))
}

fn validate_replayed_recovery_scope(
    public: &PublicOperationAdmissionV1,
    project: ProjectId,
    resource_id: [u8; 16],
) -> Result<(), OperationCompilationError> {
    let selector = Selector::Resource {
        resource: ResourceId::from_bytes(resource_id),
    };
    if public.method() != PublicOperationMethodV1::OperatorRecover
        || public.project() != project
        || public.authorization().resource_kind() != ResourceKind::Operation
        || public.authorization().selector() != &selector
    {
        return Err(OperationCompilationError::Rejected);
    }
    Ok(())
}

fn require_replayed_recovery_authorization(
    action: i32,
    public: &PublicOperationAdmissionV1,
    project: ProjectId,
    resource_id: [u8; 16],
    authorize: impl FnOnce() -> Result<(), OperationCompilationError>,
) -> Result<(), OperationCompilationError> {
    if !supported_public_recovery_action(action) {
        return Err(OperationCompilationError::Rejected);
    }
    validate_replayed_recovery_scope(public, project, resource_id)?;
    authorize()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::{JournalLimits, JournalRecord, JournalTransaction};
    use aos_proto::aos::sandbox::v1::{ObjectDescriptor, OperatorRecoveryRequest};

    #[test]
    fn physical_actions_stay_closed_for_new_and_replayed_admission() {
        assert!(supported_public_recovery_action(
            OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY as i32
        ));
        assert!(supported_public_recovery_action(
            OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_ABANDON as i32
        ));
        assert!(!supported_public_recovery_action(
            OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RECONCILE as i32
        ));
        assert!(!supported_public_recovery_action(
            OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as i32
        ));
        assert!(!supported_public_recovery_action(0));
    }

    #[test]
    fn retained_physical_action_identity_cannot_enter_public_replay() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "recovery-replay.journal",
            JournalLimits::default(),
            rustix::process::getuid().as_raw(),
        )
        .unwrap();
        let request_digest = [7; 32];
        let operation_id = OperationId::from_bytes([8; 16]);

        for (index, action) in [
            OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RECONCILE,
            OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR,
        ]
        .into_iter()
        .enumerate()
        {
            let key = IdempotencyKey::new(vec![index as u8 + 1]).unwrap();
            let transaction = JournalTransaction::new(
                [index as u8 + 1; 16],
                vec![JournalRecord::idempotency(
                    &key,
                    request_digest,
                    operation_id,
                )],
            )
            .unwrap();
            let request = OperatorRecoveryRequestV1::try_from(OperatorRecoveryRequest {
                resource_id: vec![9; 16],
                expected_resource_version: vec![10; 32],
                action: action.into(),
                idempotency_key: key.as_bytes().to_vec(),
                evidence: Some(ObjectDescriptor {
                    media_type: "application/vnd.aos.sandbox.operator-recovery-evidence.v1"
                        .to_owned(),
                    sha256: vec![11; 32],
                    encoded_size: 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(
                journal.check_idempotency(&key, request_digest),
                IdempotencyOutcome::Vacant
            );
            assert!(
                checked_recovery_idempotency(&journal, &request, &key, request_digest).is_err()
            );

            journal.commit(&transaction).unwrap();
            assert_eq!(
                journal.check_idempotency(&key, request_digest),
                IdempotencyOutcome::Replay(operation_id)
            );
            assert!(
                checked_recovery_idempotency(&journal, &request, &key, request_digest).is_err()
            );
        }
    }

    #[test]
    fn replay_requires_the_exact_operation_scope() {
        let project = ProjectId::from_bytes([1; 16]);
        let target = [2; 16];
        let admission = |method, project, kind, resource| {
            PublicOperationAdmissionV1::new(
                method,
                1,
                [3; 16],
                1,
                PublicOperationAuthorizationV1::new(
                    project,
                    kind,
                    Selector::Resource {
                        resource: ResourceId::from_bytes(resource),
                    },
                )
                .unwrap(),
            )
            .unwrap()
        };

        assert!(
            validate_replayed_recovery_scope(
                &admission(
                    PublicOperationMethodV1::OperatorRecover,
                    project,
                    ResourceKind::Operation,
                    target
                ),
                project,
                target,
            )
            .is_ok()
        );
        for invalid in [
            admission(
                PublicOperationMethodV1::DeleteSandbox,
                project,
                ResourceKind::Operation,
                target,
            ),
            admission(
                PublicOperationMethodV1::OperatorRecover,
                ProjectId::from_bytes([4; 16]),
                ResourceKind::Operation,
                target,
            ),
            admission(
                PublicOperationMethodV1::OperatorRecover,
                project,
                ResourceKind::Sandbox,
                target,
            ),
            admission(
                PublicOperationMethodV1::OperatorRecover,
                project,
                ResourceKind::Operation,
                [5; 16],
            ),
        ] {
            assert!(validate_replayed_recovery_scope(&invalid, project, target).is_err());
        }

        let valid = admission(
            PublicOperationMethodV1::OperatorRecover,
            project,
            ResourceKind::Operation,
            target,
        );
        let reauthorized = Cell::new(false);
        assert!(
            require_replayed_recovery_authorization(
                OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY as i32,
                &valid,
                project,
                target,
                || {
                    reauthorized.set(true);
                    Err(OperationCompilationError::Rejected)
                },
            )
            .is_err(),
            "Retry replay must propagate a current authorization denial"
        );
        assert!(reauthorized.get());
    }
}
