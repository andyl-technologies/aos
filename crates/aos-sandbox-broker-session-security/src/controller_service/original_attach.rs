//! Sole-worker polling and held consumption of an already-issued original ticket.
//!
//! The existing forward Host session carries both steps. Polling is advisory;
//! the same Controller writer, current registration/policy/revocation/trust cut
//! and original expiry remain borrowed through the fixed consume exchange.
//! This path never replays ControlExecution, creates a peer or signs a ticket.

use aos_proto::aos::sandbox::local::v1::{BrokerAuthorizationArtifactsV1, BrokerMethod};
use aos_sandbox::{ControllerServiceError, CurrentOriginalAttachHostConsumeDraftV3};
use aos_sandbox_agent::openssh_consume::{
    OriginalAttachPhaseV3, decode_original_attach_response_v3,
};
use aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2;
use aos_sandbox_core::{NodeId, ObjectDigest};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};

use crate::controller_ownership::sample_ownership_clock;
use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::entropy::{KernelEntropy, nonzero_random};

use super::{ProductionController, SharedControllerBrokerSessions};

pub(super) fn poll_one(
    controller: &mut ProductionController,
    node: NodeId,
    sessions: &SharedControllerBrokerSessions,
    signer: Option<&ControllerBrokerPlanSignerV1>,
    cursor: &mut usize,
) {
    let Some(signer) = signer else {
        return;
    };
    let Ok(candidates) = controller.current_original_attach_candidates_v3(node, 32) else {
        return;
    };
    if candidates.is_empty() {
        *cursor = 0;
        return;
    }
    let operation = candidates[*cursor % candidates.len()];
    *cursor = cursor.wrapping_add(1);
    let Ok(mut sessions) = sessions.lock() else {
        return;
    };
    let Some(host) = sessions.host.as_mut() else {
        return;
    };
    // Missing/revoked/expired current authority denies this ticket. Selection,
    // a historical signed reply and the round-robin cursor confer no rights.
    let _ = controller.with_current_original_attach_consume_v3(operation, node, |cut| {
        let ticket =
            PublicAttachTicketBindingV2::decode(cut.original_ticket()).map_err(|_| denied())?;
        let poll = cut.prepare_host_poll_plan_v3()?;
        let authorization = sign_borrowed_plan(&poll, signer)?;
        poll.recheck()?;
        let outcome = host
            .query_attach_gate_route(ticket.operation_id, ticket.execution_id, &authorization)
            .map_err(|_| denied())?;
        let route = accepted_route_evidence(&outcome, &ticket, cut.original_ticket())?;
        if !route.original_session_observation_v5.is_empty() {
            let (control, physical) = aos_sandbox_agent::openssh_control_channel::decode_original_control_response_shape_v5(
                &route.original_session_observation_v5,
            ).map_err(|_| denied())?;
            if physical != route.signed_ticket_readback_v2 { return Err(denied()); }
            if control.phase == aos_sandbox_agent::openssh_control_channel::OriginalControlPhaseV5::Queued {
                let challenge = nonzero_random::<32, _>(&mut KernelEntropy).map_err(|_| denied())?;
                let draft = cut.prepare_host_control_plan_v5(ObjectDigest::from_bytes(control.binding), challenge, &control.request)?;
                let authorization = sign_borrowed_plan(&draft, signer)?;
                draft.recheck()?;
                let outcome = host.apply_original_monitor_control_v5(draft.original_grant(), draft.original_ticket(),
                    control.binding, challenge, &control.request, &authorization).map_err(|_| denied())?;
                require_control_completion(&outcome)?;
                draft.recheck()?;
            } else if control.phase != aos_sandbox_agent::openssh_control_channel::OriginalControlPhaseV5::Idle {
                return Err(denied());
            }
            // An already attempted transfer is never redispatched. Initial
            // PTY ACK precedes relay registration, so a later poll sees V3 ready.
            return Ok(());
        }
        let Some(binding) = ready_binding(&outcome, &ticket, cut.original_ticket())? else {
            return Ok(());
        };

        let challenge = nonzero_random::<32, _>(&mut KernelEntropy).map_err(|_| denied())?;
        let consume =
            cut.prepare_host_consume_plan_v3(ObjectDigest::from_bytes(binding), challenge)?;
        let authorization = sign_borrowed_plan(&consume, signer)?;
        consume.recheck()?;
        let outcome = host
            .consume_original_attach_ticket_v3(
                consume.original_grant(),
                consume.original_ticket(),
                binding,
                challenge,
                &authorization,
            )
            .map_err(|_| denied())?;
        require_consume_completion(&outcome)?;
        consume.recheck()?;
        Ok(())
    });
}

fn sign_borrowed_plan(
    draft: &CurrentOriginalAttachHostConsumeDraftV3<'_, '_>,
    signer: &ControllerBrokerPlanSignerV1,
) -> Result<BrokerAuthorizationArtifactsV1, ControllerServiceError> {
    draft.recheck()?;
    let now = sample_ownership_clock().map_err(|_| denied())?;
    let signed = signer
        .sign_plan(draft.plan().clone(), now.wall_seconds())
        .map_err(|_| denied())?;
    Ok(BrokerAuthorizationArtifactsV1 {
        broker_plan: signed.canonical_plan().to_vec(),
        broker_plan_signature: signed.canonical_signature().to_vec(),
        ownership_lease: draft.ownership_lease().to_vec(),
        ownership_lease_signature: draft.ownership_lease_signature().to_vec(),
        ..Default::default()
    })
}

fn ready_binding(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ticket: &PublicAttachTicketBindingV2,
    original_bytes: &[u8],
) -> Result<Option<[u8; 32]>, ControllerServiceError> {
    let evidence = accepted_route_evidence(outcome, ticket, original_bytes)?;
    let (observation, physical) =
        decode_original_attach_response_v3(&evidence.original_attach_observation_v3)
            .map_err(|_| denied())?;
    if physical != evidence.signed_ticket_readback_v2 {
        return Err(denied());
    }
    match observation.phase {
        OriginalAttachPhaseV3::Pending => Ok(None),
        OriginalAttachPhaseV3::Ready => Ok(Some(observation.binding)),
        OriginalAttachPhaseV3::Transferred => Err(denied()),
    }
}

fn accepted_route_evidence(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ticket: &PublicAttachTicketBindingV2,
    original_bytes: &[u8],
) -> Result<aos_proto::aos::sandbox::local::v1::HostAttachGateEvidenceV1, ControllerServiceError> {
    require_received_method(
        outcome,
        BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE,
    )?;
    let now = sample_ownership_clock().map_err(|_| denied())?;
    let request = aos_sandbox_protocol::decode_host_attach_route_query_v1(
        outcome.request().exact_body(),
        outcome.request().peer(),
        outcome.request().peer_policy(),
        now.boottime_nanoseconds(),
    )
    .map_err(|_| denied())?;
    if request.operation_id() != ticket.operation_id
        || request.execution_id() != ticket.execution_id
    {
        return Err(denied());
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(denied());
    };
    let evidence = aos_sandbox_protocol::decode_host_attach_route_evidence_v1(exact_body, &request)
        .map_err(|_| denied())?;
    if evidence.original_ticket_digest_v2.as_slice()
        != aos_sandbox_agent::openssh_ticket::ticket_digest_v2(original_bytes)
        || evidence.route_digest.as_slice() != ticket.base_route_digest
        || evidence.incarnation_id.as_slice() != ticket.incarnation_id
        || evidence.assignment_epoch != ticket.assignment_epoch
        || evidence.principal_id.as_slice() != ticket.principal_id
        || evidence.audit_id.as_slice() != ticket.audit_id
    {
        return Err(denied());
    }
    Ok(evidence)
}

fn require_control_completion(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<(), ControllerServiceError> {
    require_received_method(
        outcome,
        BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE,
    )?;
    let now = sample_ownership_clock().map_err(|_| denied())?;
    let request = aos_sandbox_protocol::decode_host_attach_gate_request_v1(
        outcome.request().exact_body(),
        outcome.request().peer(),
        outcome.request().peer_policy(),
        now.boottime_nanoseconds(),
    )
    .map_err(|_| denied())?;
    if request.original_session_control_v5().is_none() {
        return Err(denied());
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(denied());
    };
    aos_sandbox_protocol::decode_host_attach_gate_evidence_v1(exact_body, &request)
        .map_err(|_| denied())?;
    Ok(())
}

fn require_consume_completion(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<(), ControllerServiceError> {
    require_received_method(
        outcome,
        BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE,
    )?;
    let now = sample_ownership_clock().map_err(|_| denied())?;
    let request = aos_sandbox_protocol::decode_host_attach_gate_request_v1(
        outcome.request().exact_body(),
        outcome.request().peer(),
        outcome.request().peer_policy(),
        now.boottime_nanoseconds(),
    )
    .map_err(|_| denied())?;
    if request.original_ticket_consume_v3().is_none() {
        return Err(denied());
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(denied());
    };
    aos_sandbox_protocol::decode_host_attach_gate_evidence_v1(exact_body, &request)
        .map_err(|_| denied())?;
    Ok(())
}

fn require_received_method(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    method: BrokerMethod,
) -> Result<(), ControllerServiceError> {
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != method
    {
        return Err(denied());
    }
    Ok(())
}

fn denied() -> ControllerServiceError {
    ControllerServiceError::PublicAuthorizationUnavailable
}
