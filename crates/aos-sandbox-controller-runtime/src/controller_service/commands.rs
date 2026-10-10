//! Closed Controller commands and their sole-worker dispatch.
//!
//! The vocabulary carries the original request and reply owners across the
//! bounded worker channel. Dispatch borrows the actual Controller and broker
//! sessions; admission, retained guest-root refusal, and explicit ownership
//! retry keep their existing ordering. Worker-local Git custody and selected
//! bootstrap bookends remain in the parent reconciliation loop.

use std::time::Instant;

use aos_proto::aos::sandbox::v1::{
    OpenSshAccessEndpoint, Operation, OperatorRecoveryAction, PolicyPlan,
};
use aos_sandbox::cli_model::{
    AuditAuthorizationV1, PublicApiAuditMethodV1, PublicMutationRequestV1,
};
use aos_sandbox_protocol::public_api::projection::{
    PublicProjectionKindV1,
    PublicProjectionRecordV1,
};
use aos_sandbox::controller_service::public_projection::{
    AuthorizedPublicProjectionReadV1,
    PublicProjectionQueryV1,
};
use aos_sandbox::public_policy_planner::PublicPolicyPlanningErrorV1;
use aos_sandbox::{
    AcceptOutcome, ControllerServiceError, OperationCompilationError, OwnershipGateStatusV1,
    OwnershipResumeOutcomeV1,
};
use aos_sandbox_core::{
    CapabilityId, NodeId, Operation as CapabilityOperation, OperationId, ResourceKind, Selector,
};
use aos_sandbox_ownership_protocol::protocol::session_client::OwnershipSessionTransportError;
use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;

use super::{
    ControllerAttachCredentialsV1, ControllerBrokerPlanSignerV1,
    ControllerOwnershipConfigurationV1, ProductionController, SharedControllerBrokerSessions,
    operator_repair, public_attach, sample_ownership_clock,
};

pub(in crate::controller_service) enum ControllerCommand {
    InspectGitRead {
        original: Box<Option<aos_sandbox::git::delegated_read::GitReadRequestOwnerV1>>,
        index: usize,
        reply: tokio::sync::oneshot::Sender<()>,
    },
    BootstrapPublicCapability {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        idempotency_key: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<(CapabilityId, [u8; 32])>>,
    },
    GetOperation {
        operation_id: OperationId,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<Option<Operation>>>,
    },
    GetAuthorizedOperation {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        capability_handle: [u8; 32],
        operation_id: OperationId,
        protobuf_body: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<Option<Operation>>>,
    },
    AuthorizePublicRead {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        capability_handle: [u8; 32],
        method: PublicApiAuditMethodV1,
        resource_kind: ResourceKind,
        operation: CapabilityOperation,
        selector: Selector,
        protobuf_body: Vec<u8>,
        expires_at: Instant,
        reply:
            tokio::sync::oneshot::Sender<ControllerCommandResponse<Option<AuditAuthorizationV1>>>,
    },
    ReadPublicProjection {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        capability_handle: [u8; 32],
        method: PublicApiAuditMethodV1,
        resource_kind: ResourceKind,
        operation: CapabilityOperation,
        selector: Selector,
        protobuf_body: Vec<u8>,
        query: PublicProjectionQueryV1,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<
            ControllerCommandResponse<Option<AuthorizedPublicProjectionReadV1>>,
        >,
    },
    PlanPublicPolicy {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        capability_handle: [u8; 32],
        method: PublicApiAuditMethodV1,
        protobuf_body: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<PolicyPlan>>,
    },
    AdmitPublicOperatorRecovery {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        capability_handle: [u8; 32],
        canonical_request: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<Operation>>,
    },
    AdmitPublicMutation {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        capability_handle: [u8; 32],
        canonical_request: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<AdmittedPublicMutationV1>>,
    },
    AdmitPublicAttach {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        capability_handle: [u8; 32],
        canonical_request: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<AdmittedPublicAttachV1>>,
    },
    ResolvePublicCapabilityTarget {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        handle: [u8; 32],
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<CapabilityId>>,
    },
}

pub(in crate::controller_service) struct AdmittedPublicMutationV1 {
    pub(in crate::controller_service) operation: Operation,
    pub(in crate::controller_service) projections: Vec<PublicProjectionRecordV1>,
    pub(in crate::controller_service) holder_handle: Option<[u8; 32]>,
}

pub(in crate::controller_service) struct AdmittedPublicAttachV1 {
    pub(in crate::controller_service) operation: Operation,
    pub(in crate::controller_service) access: OpenSshAccessEndpoint,
}

pub(in crate::controller_service) type ControllerCommandResponse<T> =
    Result<T, ControllerCommandFailure>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::controller_service) enum ControllerCommandFailure {
    DeadlineExceeded,
    ControllerUnavailable,
    InvalidRequest,
    Rejected,
}

fn reply_read_only_controller_result<T>(
    reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<T>>,
    result: Result<T, ControllerServiceError>,
) -> Result<(), String> {
    match result {
        Ok(value) => {
            let _ = reply.send(Ok(value));
            Ok(())
        }
        Err(error) => {
            let message = error.to_string();
            let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
            Err(message)
        }
    }
}

pub(in crate::controller_service) fn handle_controller_command(
    controller: &mut ProductionController,
    ownership: Option<&ControllerOwnershipConfigurationV1>,
    attach_credentials: Option<&ControllerAttachCredentialsV1>,
    attach_plan_signer: Option<&ControllerBrokerPlanSignerV1>,
    node: NodeId,
    sessions: &SharedControllerBrokerSessions,
    command: ControllerCommand,
) -> Result<(), String> {
    macro_rules! require_holder_handle {
        ($peer:expr, $id:expr, $handle:expr, $reply:expr) => {
            if controller
                .resolve_public_capability_handle(&$peer, $id, &$handle)
                .is_err()
            {
                let _ = $reply.send(Err(ControllerCommandFailure::Rejected));
                return Ok(());
            }
        };
    }

    let effect_command = matches!(
        &command,
        ControllerCommand::AdmitPublicMutation { .. }
            | ControllerCommand::AdmitPublicAttach { .. }
            | ControllerCommand::AdmitPublicOperatorRecovery { .. }
    );
    if effect_command
        && sessions
            .lock()
            .map_err(|_| "broker session lock is poisoned".to_owned())?
            .storage_root
            .has_pending()
    {
        // A retained method-31 packet owns the sole Storage session until the
        // next cycle recovers it and completes a fresh physical readback.
        match command {
            ControllerCommand::AdmitPublicMutation { reply, .. } => {
                let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
            }
            ControllerCommand::AdmitPublicAttach { reply, .. } => {
                let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
            }
            ControllerCommand::AdmitPublicOperatorRecovery { reply, .. } => {
                let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
            }
            _ => return Err("guest-root command guard lost its method".to_owned()),
        }
        return Ok(());
    }
    match command {
        ControllerCommand::InspectGitRead { .. } => std::process::abort(),
        ControllerCommand::BootstrapPublicCapability {
            peer,
            idempotency_key,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            let result = controller.bootstrap_initial_public_capability(&peer, &idempotency_key);
            match result {
                Ok(issued) => {
                    let _ = reply.send(Ok((issued.id(), *issued.holder_handle())));
                }
                Err(aos_sandbox::public_capability_issuance::InitialPublicCapabilityErrorV1::Rejected) => {
                    let _ = reply.send(Err(ControllerCommandFailure::Rejected));
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
            }
            Ok(())
        }
        ControllerCommand::GetOperation {
            operation_id,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            reply_read_only_controller_result(reply, controller.public_operation(operation_id))
        }
        ControllerCommand::GetAuthorizedOperation {
            peer,
            capability_id,
            capability_handle,
            operation_id,
            protobuf_body,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            require_holder_handle!(peer, capability_id, capability_handle, reply);
            reply_read_only_controller_result(
                reply,
                controller.authorized_public_operation(
                    &peer,
                    capability_id,
                    operation_id,
                    &protobuf_body,
                ),
            )
        }
        ControllerCommand::AuthorizePublicRead {
            peer,
            capability_id,
            capability_handle,
            method,
            resource_kind,
            operation,
            selector,
            protobuf_body,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            require_holder_handle!(peer, capability_id, capability_handle, reply);
            reply_read_only_controller_result(
                reply,
                controller.authorize_public_read(
                    &peer,
                    capability_id,
                    method,
                    resource_kind,
                    operation,
                    selector,
                    &protobuf_body,
                ),
            )
        }
        ControllerCommand::ReadPublicProjection {
            peer,
            capability_id,
            capability_handle,
            method,
            resource_kind,
            operation,
            selector,
            protobuf_body,
            query,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            require_holder_handle!(peer, capability_id, capability_handle, reply);
            reply_read_only_controller_result(
                reply,
                controller.authorized_public_projection_read(
                    &peer,
                    capability_id,
                    method,
                    resource_kind,
                    operation,
                    selector,
                    &protobuf_body,
                    query,
                ),
            )
        }
        ControllerCommand::PlanPublicPolicy {
            peer,
            capability_id,
            capability_handle,
            method,
            protobuf_body,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            require_holder_handle!(peer, capability_id, capability_handle, reply);
            match controller.plan_public_policy(&peer, capability_id, method, &protobuf_body) {
                Ok(plan) => {
                    let _ = reply.send(Ok(plan));
                    Ok(())
                }
                Err(PublicPolicyPlanningErrorV1::Malformed) => {
                    let _ = reply.send(Err(ControllerCommandFailure::InvalidRequest));
                    Ok(())
                }
                Err(PublicPolicyPlanningErrorV1::Rejected) => {
                    let _ = reply.send(Err(ControllerCommandFailure::Rejected));
                    Ok(())
                }
                Err(PublicPolicyPlanningErrorV1::Unavailable) => {
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Ok(())
                }
                Err(PublicPolicyPlanningErrorV1::InvalidPlan) => {
                    let message = "public policy planner returned an invalid plan".to_owned();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Err(message)
                }
            }
        }
        ControllerCommand::AdmitPublicOperatorRecovery {
            peer,
            capability_id,
            capability_handle,
            canonical_request,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            require_holder_handle!(peer, capability_id, capability_handle, reply);
            let repair = operator_repair::is_repair(&canonical_request);
            if matches!(repair, Ok(true)) && !operator_repair::QUALIFIED {
                let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                return Ok(());
            }
            let admitted = match repair {
                Ok(true) => operator_repair::admit(
                    controller,
                    &peer,
                    capability_id,
                    &canonical_request,
                    attach_plan_signer,
                    node,
                    sessions,
                ),
                Ok(false) => controller.admit_public_operator_recovery(
                    &peer,
                    capability_id,
                    &canonical_request,
                ),
                Err(error) => Err(error),
            };
            let operation_id = match admitted {
                Ok(AcceptOutcome::Accepted(operation) | AcceptOutcome::Replay(operation)) => {
                    operation
                }
                Err(
                    ControllerServiceError::EmptyRequest
                    | ControllerServiceError::RequestTooLarge
                    | ControllerServiceError::Compilation(OperationCompilationError::Malformed),
                ) => {
                    let _ = reply.send(Err(ControllerCommandFailure::InvalidRequest));
                    return Ok(());
                }
                Err(ControllerServiceError::Compilation(OperationCompilationError::Rejected)) => {
                    let _ = reply.send(Err(ControllerCommandFailure::Rejected));
                    return Ok(());
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
            };
            match controller.public_operation(operation_id) {
                Ok(Some(operation)) => {
                    let _ = reply.send(Ok(operation));
                    resume_operator_ownership(controller, ownership, &canonical_request)
                }
                Ok(None) => {
                    let message = "accepted operator recovery has no public operation".to_owned();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Err(message)
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Err(message)
                }
            }
        }
        ControllerCommand::AdmitPublicMutation {
            peer,
            capability_id,
            capability_handle,
            canonical_request,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            let admission = if controller
                .resolve_public_capability_handle(&peer, capability_id, &capability_handle)
                .is_ok()
            {
                controller.admit_public(&peer, capability_id, &canonical_request)
            } else {
                // Renewal atomically retires its invoking handle. Only the
                // controller's exact committed-renewal proof may replay it.
                controller.replay_committed_public_capability_renewal(
                    &peer,
                    capability_id,
                    &capability_handle,
                    &canonical_request,
                )
            };
            let operation_id = match admission {
                Ok(AcceptOutcome::Accepted(operation) | AcceptOutcome::Replay(operation)) => {
                    operation
                }
                Err(
                    ControllerServiceError::EmptyRequest
                    | ControllerServiceError::RequestTooLarge
                    | ControllerServiceError::Compilation(OperationCompilationError::Malformed),
                ) => {
                    let _ = reply.send(Err(ControllerCommandFailure::InvalidRequest));
                    return Ok(());
                }
                Err(ControllerServiceError::Compilation(OperationCompilationError::Rejected)) => {
                    let _ = reply.send(Err(ControllerCommandFailure::Rejected));
                    return Ok(());
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
            };
            let operation = match controller.public_operation(operation_id) {
                Ok(Some(operation)) => operation,
                Ok(None) => {
                    let message = "accepted public mutation has no public operation".to_owned();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
            };
            let projections = match controller.public_operation_projections(operation_id) {
                Ok(projections) => projections,
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
            };
            let returns_capability_handle = matches!(
                PublicMutationRequestV1::decode(&canonical_request).map(|request| request.method()),
                Ok(PublicApiAuditMethodV1::AttenuateCapability
                    | PublicApiAuditMethodV1::RenewCapability)
            );
            let holder_handle = if returns_capability_handle {
                let Some(record) = projections.first() else {
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err("capability mutation has no public projection".to_owned());
                };
                let resource = record.resource();
                let id: [u8; 16] = match resource.resource_id().try_into() {
                    Ok(id)
                        if projections.len() == 1
                            && resource.kind() == PublicProjectionKindV1::Capability =>
                    {
                        id
                    }
                    _ => {
                        let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                        return Err("capability mutation has invalid public projection".to_owned());
                    }
                };
                match controller.public_holder_handle(&peer, CapabilityId::from_bytes(id)) {
                    Ok(handle) => Some(handle),
                    Err(error) => {
                        let message = error.to_string();
                        let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                        return Err(message);
                    }
                }
            } else {
                None
            };
            let _ = reply.send(Ok(AdmittedPublicMutationV1 {
                operation,
                projections,
                holder_handle,
            }));
            Ok(())
        }
        ControllerCommand::AdmitPublicAttach {
            peer,
            capability_id,
            capability_handle,
            canonical_request,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            require_holder_handle!(peer, capability_id, capability_handle, reply);
            let result = sessions
                .lock()
                .map_err(|_| ControllerCommandFailure::ControllerUnavailable)
                .and_then(|mut sessions| {
                    let host = sessions
                        .host
                        .as_mut()
                        .ok_or(ControllerCommandFailure::ControllerUnavailable)?;
                    public_attach::admit_public_attach(
                        controller,
                        attach_credentials,
                        attach_plan_signer,
                        node,
                        host,
                        &peer,
                        capability_id,
                        &canonical_request,
                    )
                });
            let _ = reply.send(result);
            Ok(())
        }
        ControllerCommand::ResolvePublicCapabilityTarget {
            peer,
            handle,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            match controller.resolve_public_capability_target(&peer, &handle) {
                Ok(id) => {
                    let _ = reply.send(Ok(id));
                }
                Err(_) => {
                    let _ = reply.send(Err(ControllerCommandFailure::Rejected));
                }
            }
            Ok(())
        }
    }
}

fn resume_operator_ownership(
    controller: &mut ProductionController,
    ownership: Option<&ControllerOwnershipConfigurationV1>,
    canonical_request: &[u8],
) -> Result<(), String> {
    let envelope = PublicMutationRequestV1::decode(canonical_request)
        .map_err(|error| format!("admitted ownership recovery envelope is invalid: {error}"))?;
    let DormantSandboxRequestKindV1::OperatorRecover(request) = envelope
        .decode_validated_kind()
        .map_err(|error| format!("admitted ownership recovery request is invalid: {error}"))?
    else {
        return Err("admitted ownership recovery has the wrong method".to_owned());
    };
    if request.action.as_known() != Some(OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY) {
        return Ok(());
    }
    let target_bytes: [u8; 16] = request
        .resource_id
        .as_slice()
        .try_into()
        .map_err(|_| "admitted ownership recovery target is invalid".to_owned())?;
    let target = OperationId::from_bytes(target_bytes);
    if controller
        .public_operation(target)
        .map_err(|error| error.to_string())?
        .is_none()
    {
        return Ok(());
    }
    let Some(gate) = controller
        .ownership_gate(target)
        .map_err(|error| error.to_string())?
    else {
        return Ok(());
    };
    let OwnershipGateStatusV1::Pending(plan) = gate else {
        return Ok(());
    };
    let Some(ownership) = ownership else {
        eprintln!("aos-sandboxd: explicit ownership retry is pending protected configuration");
        return Ok(());
    };
    if plan.expected_authority() != ownership.verifier().authority() {
        return Err("ownership retry authority differs from the admitted gate".to_owned());
    }
    let mut client = match ownership.connect() {
        Ok(client) => client,
        Err(OwnershipSessionTransportError::Unavailable) => {
            eprintln!("aos-sandboxd: explicit ownership retry could not reach the authority");
            return Ok(());
        }
        Err(error) => return Err(error.to_string()),
    };
    let outcome = controller
        .resume_ownership(
            target,
            &mut client,
            ownership.verifier(),
            &mut sample_ownership_clock,
        )
        .map_err(|error| error.to_string())?;
    if !matches!(
        outcome,
        OwnershipResumeOutcomeV1::Activated | OwnershipResumeOutcomeV1::Replay
    ) {
        eprintln!("aos-sandboxd: explicit ownership retry remains pending: {outcome:?}");
    }
    Ok(())
}
