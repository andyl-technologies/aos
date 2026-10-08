//! Coordinates only original public Repair admission and atomic completion.
//!
//! A fixed private qualification gate keeps public activation closed. The
//! concrete implementation below retains actual public peer, ordinary signer,
//! authenticated Storage session and Controller journal custody; it does not
//! return an ordinary receipt to generic Apply/Observe completion.

use aos_proto::aos::sandbox::local::v1::{
    BrokerAuthorizationArtifactsV1, BrokerMethod, BrokerRequestEnvelope,
};
use aos_sandbox::controller::{
    OperatorStorageRepairBridgeV1, StorageRepairAdmissionPreparationV1,
    StorageRepairAdmissionV1,
};
use aos_sandbox::public_api_session::PublicApiPeer;
use buffa::Message as _;

use super::*;

// This is a non-authorizing source qualification hold, not caller policy or a
// configurable bypass. Enabling it requires a separate qualification grant.
pub(super) const QUALIFIED: bool = false;

pub(super) fn is_repair(canonical: &[u8]) -> Result<bool, ControllerServiceError> {
    let envelope = PublicMutationRequestV1::decode(canonical)
        .map_err(|_| OperationCompilationError::Malformed)?;
    let DormantSandboxRequestKindV1::OperatorRecover(request) = envelope
        .decode_validated_kind()
        .map_err(|_| OperationCompilationError::Malformed)?
    else {
        return Err(OperationCompilationError::Malformed.into());
    };
    Ok(request.action.as_known()
        == Some(OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR))
}

pub(super) fn admit(
    controller: &mut ProductionController,
    peer: &PublicApiPeer,
    capability: CapabilityId,
    canonical: &[u8],
    signer: Option<&ControllerBrokerPlanSignerV1>,
    node: NodeId,
    sessions: &SharedControllerBrokerSessions,
) -> Result<AcceptOutcome, ControllerServiceError> {
    // Replay is reauthorized against the actual caller before any ordinary
    // query. In particular an unresolved hold cannot cause a cross-socket wait.
    if let Some(replay) = controller
        .replay_operator_storage_repair_admission_v1(peer, capability, canonical)?
    {
        return Ok(replay);
    }

    let signer = signer.ok_or(ControllerServiceError::PublicAuthorizationUnavailable)?;
    let anchor = ControllerBrokerPlanSignerV1::trust_anchor_from_process_credentials()
        .map_err(|_| ControllerServiceError::PublicAuthorizationUnavailable)?;
    let mut sessions = sessions
        .lock()
        .map_err(|_| ControllerServiceError::PublicAuthorizationUnavailable)?;
    let storage = sessions
        .storage
        .as_mut()
        .ok_or(ControllerServiceError::PublicAuthorizationUnavailable)?;
    storage
        .operator_repair_service_identity()
        .map_err(|_| ControllerServiceError::PublicAuthorizationUnavailable)?;
    let inventory = storage
        .current_inventory_observation()
        .map_err(|_| ControllerServiceError::PublicAuthorizationUnavailable)?;
    storage
        .operator_repair_inventory_history(
            inventory.request().request_id(),
            Some(inventory.canonical_packet()),
        )
        .map_err(|_| ControllerServiceError::PublicAuthorizationUnavailable)?;

    let now = sample_ownership_clock()
        .map_err(|_| ControllerServiceError::PublicAuthorizationUnavailable)?;
    let prepared = controller.prepare_operator_storage_repair_admission_v1(
        peer,
        capability,
        canonical,
        &inventory,
        node,
        anchor.revocation_scope(),
        now.wall_seconds(),
        now.boottime_nanoseconds(),
    )?;
    let draft = match prepared {
        StorageRepairAdmissionPreparationV1::Replay(operation) => {
            return Ok(AcceptOutcome::Replay(operation));
        }
        StorageRepairAdmissionPreparationV1::Draft(draft) => draft,
    };
    let (plan, body, ownership_lease, ownership_lease_signature) = draft.into_parts();
    let signed = signer
        .sign_plan(plan, now.wall_seconds())
        .map_err(|_| ControllerServiceError::PublicAuthorizationUnavailable)?;
    let envelope = BrokerRequestEnvelope {
        method: BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN.into(),
        body,
        authorization: Some(BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.canonical_plan().to_vec(),
            broker_plan_signature: signed.canonical_signature().to_vec(),
            ownership_lease,
            ownership_lease_signature,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
    .encode_to_vec();
    let candidate = StorageRepairAdmissionV1::from_authenticated_inventory(
        &inventory,
        envelope,
        &anchor,
        node,
        inventory.request().peer(),
        inventory.request().peer_policy(),
        now.wall_seconds(),
        now.boottime_nanoseconds(),
    )?;
    peer.recheck().map_err(|_| OperationCompilationError::Rejected)?;
    controller.admit_operator_storage_repair_v1(peer, capability, canonical, candidate)
}

pub(super) fn reconcile(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    step: u32,
    plan: &EffectPlan,
    journal: &mut Journal,
    completion_wall_seconds: i64,
) -> Result<aos_sandbox::OperatorStorageRepairReconcileV1, EffectFailure> {
    if !QUALIFIED || step != 0 {
        return Err(EffectFailure::Retryable(
            "public Repair awaits production qualification".to_owned(),
        ));
    }
    let context = plan
        .public_mutation_context()
        .map_err(|error| EffectFailure::Retryable(error.to_string()))?
        .ok_or_else(|| {
            EffectFailure::Retryable("Repair lacks its original public admission".to_owned())
        })?;
    if !is_repair(context.canonical_request())
        .map_err(|error| EffectFailure::Retryable(error.to_string()))?
    {
        return Err(EffectFailure::Retryable(
            "Repair hook names another public method".to_owned(),
        ));
    }

    let mut sessions = executor
        .sessions
        .lock()
        .map_err(|_| EffectFailure::Retryable("broker session lock is poisoned".to_owned()))?;
    let storage = sessions
        .storage
        .as_mut()
        .ok_or_else(|| EffectFailure::Retryable("actual Storage session is unavailable".to_owned()))?;
    let mut bridge = OperatorStorageRepairBridgeV1::claim(journal)
        .map_err(|error| EffectFailure::Retryable(error.to_string()))?;
    match storage.reconcile_operator_storage_repair(
        &mut bridge,
        operation,
        completion_wall_seconds,
    )? {
        aos_sandbox::controller::OperatorStorageRepairTerminalV1::Committed
        | aos_sandbox::controller::OperatorStorageRepairTerminalV1::Replay
        | aos_sandbox::controller::OperatorStorageRepairTerminalV1::OriginalPreconditionReplaced => {
            Ok(aos_sandbox::OperatorStorageRepairReconcileV1::Terminal)
        }
        aos_sandbox::controller::OperatorStorageRepairTerminalV1::NotCommitted => {
            Ok(aos_sandbox::OperatorStorageRepairReconcileV1::Pending)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_repair_activation_remains_closed_and_malformed_input_is_not_repair() {
        assert!(!QUALIFIED);
        assert!(is_repair(&[]).is_err());
        assert!(is_repair(b"not a canonical public operation").is_err());
    }
}
