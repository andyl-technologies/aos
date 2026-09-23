//! Sole-worker public ATTACH sequencing behind authenticated Host evidence.
//!
//! A signed live-readiness query precedes a new durable reservation. Existing
//! pending identity resumes its exact Host install request, while accepted
//! replay requires a fresh read-only physical gate observation.

use aos_proto::aos::sandbox::local::v1::{
    BrokerAuthorizationArtifactsV1, BrokerMethod, HostAttachGateEvidenceV1,
};
use aos_sandbox::attach_route_issuer::AuthenticatedOpenSshRouteV1;
use aos_sandbox::public_api_session::PublicApiPeer;
use aos_sandbox::public_attach_pending::PublicAttachHostQueryDraftV1;
use aos_sandbox::public_attach_pending::PublicAttachPendingV1;
use aos_sandbox::{AcceptOutcome, ControllerServiceError, OperationCompilationError};
use aos_sandbox_core::{CapabilityId, NodeId};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};
use aos_sandbox_protocol::{
    decode_host_attach_gate_evidence_v1, decode_host_attach_gate_request_v1,
    decode_host_attach_readiness_request_v1, decode_host_attach_readiness_v1,
    decode_host_attach_route_evidence_v1, decode_host_attach_route_query_v1,
};

use crate::controller_attach_credentials::ControllerAttachCredentialsV1;
use crate::controller_ownership::sample_ownership_clock;
use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::controller_publication::ControllerHostPublication;

use super::{AdmittedPublicAttachV1, ControllerCommandFailure, ProductionController};

/// Adapts only a retained authenticated Host broker session to signed outcomes.
pub(super) trait AuthenticatedHostAttachRouteExchangeV1 {
    /// Completes any older exact request before its reservation is renewed.
    fn drain_pending(&mut self) -> Result<(), ControllerCommandFailure>;

    /// Queries live Host readiness before the public reservation CAS.
    fn query_readiness(
        &mut self,
        authorization: &BrokerAuthorizationArtifactsV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, ControllerCommandFailure>;

    /// Installs and observes the exact signed pending grant.
    fn install(
        &mut self,
        grant: &[u8],
        authorization: &BrokerAuthorizationArtifactsV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, ControllerCommandFailure>;

    /// Reads an accepted route with fresh signed physical gate evidence.
    fn query_route(
        &mut self,
        operation_id: [u8; 16],
        execution_id: [u8; 16],
        authorization: &BrokerAuthorizationArtifactsV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, ControllerCommandFailure>;
}

impl AuthenticatedHostAttachRouteExchangeV1 for ControllerHostPublication {
    fn drain_pending(&mut self) -> Result<(), ControllerCommandFailure> {
        self.drain_attach_gate()
            .map(|_| ())
            .map_err(|_| ControllerCommandFailure::ControllerUnavailable)
    }

    fn query_readiness(
        &mut self,
        authorization: &BrokerAuthorizationArtifactsV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, ControllerCommandFailure> {
        self.query_attach_gate_readiness(authorization)
            .map_err(|_| ControllerCommandFailure::ControllerUnavailable)
    }

    fn install(
        &mut self,
        grant: &[u8],
        authorization: &BrokerAuthorizationArtifactsV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, ControllerCommandFailure> {
        self.install_attach_gate(grant, authorization)
            .map_err(|_| ControllerCommandFailure::ControllerUnavailable)
    }

    fn query_route(
        &mut self,
        operation_id: [u8; 16],
        execution_id: [u8; 16],
        authorization: &BrokerAuthorizationArtifactsV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, ControllerCommandFailure> {
        self.query_attach_gate_route(operation_id, execution_id, authorization)
            .map_err(|_| ControllerCommandFailure::ControllerUnavailable)
    }
}

/// Accepts only a signed-session Host success for the exact protected grant.
///
/// The shared protocol decoder checks the canonical request/response shape and
/// the signed guest packet commitment. The Host must have verified the guest
/// signature against its protected peer before signing this broker outcome.
///
/// # Errors
///
/// Rejects any failed, late, rebound, noncanonical, or unpinned response.
pub(super) fn route_from_authenticated_outcome(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    grant: &[u8],
    pending: &PublicAttachPendingV1,
    credentials: &ControllerAttachCredentialsV1,
) -> Result<AuthenticatedOpenSshRouteV1, ControllerCommandFailure> {
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE
    {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    }
    let now =
        sample_ownership_clock().map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    let request = decode_host_attach_gate_request_v1(
        outcome.request().exact_body(),
        outcome.request().peer(),
        outcome.request().peer_policy(),
        now.boottime_nanoseconds(),
    )
    .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    if request.pending_grant().as_slice() != grant
        || request.operation_id() != *pending.operation_id().as_bytes()
        || request.execution_id() != pending.execution_id()
    {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    };
    let evidence = decode_host_attach_gate_evidence_v1(exact_body, &request)
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    route_from_host_evidence(evidence, pending, credentials, now.wall_seconds())
}

fn route_from_query_outcome(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    pending: &PublicAttachPendingV1,
    credentials: &ControllerAttachCredentialsV1,
) -> Result<AuthenticatedOpenSshRouteV1, ControllerCommandFailure> {
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE
    {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    }
    let now =
        sample_ownership_clock().map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    let request = decode_host_attach_route_query_v1(
        outcome.request().exact_body(),
        outcome.request().peer(),
        outcome.request().peer_policy(),
        now.boottime_nanoseconds(),
    )
    .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    if request.operation_id() != *pending.operation_id().as_bytes()
        || request.execution_id() != pending.execution_id()
    {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    };
    let evidence = decode_host_attach_route_evidence_v1(exact_body, &request)
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    route_from_host_evidence(evidence, pending, credentials, now.wall_seconds())
}

fn route_from_host_evidence(
    evidence: HostAttachGateEvidenceV1,
    pending: &PublicAttachPendingV1,
    credentials: &ControllerAttachCredentialsV1,
    now_seconds: i64,
) -> Result<AuthenticatedOpenSshRouteV1, ControllerCommandFailure> {
    let port = u16::try_from(evidence.port)
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    if evidence.incarnation_id != pending.sandbox_incarnation_id()
        || evidence.assignment_epoch != pending.assignment_epoch()
        || evidence.principal_id != pending.principal_id()
        || evidence.audit_id != pending.audit_id()
        || evidence.expires_at != pending.expires_at()
        || evidence.expires_at <= now_seconds
        || !credentials.matches_route_pins(
            &evidence.host,
            port,
            &evidence.user,
            &evidence.host_public_key,
            &evidence.trusted_user_ca_public_key,
        )
    {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    }

    let route_digest = evidence
        .route_digest
        .as_slice()
        .try_into()
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    let gate_observation_commitment = evidence
        .gate_observation_commitment
        .as_slice()
        .try_into()
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    Ok(AuthenticatedOpenSshRouteV1 {
        execution_id: pending.execution_id(),
        attach_operation_id: *pending.operation_id().as_bytes(),
        sandbox_incarnation_id: pending.sandbox_incarnation_id(),
        assignment_epoch: pending.assignment_epoch(),
        principal_id: pending.principal_id(),
        audit_id: pending.audit_id(),
        host: evidence.host,
        port,
        user: evidence.user,
        host_public_key: evidence.host_public_key,
        trusted_user_ca_public_key: evidence.trusted_user_ca_public_key,
        forced_command_gate_active: true,
        route_digest,
        gate_observation_commitment,
        expires_at: evidence.expires_at,
    })
}

fn authorization_from_query_draft(
    draft: PublicAttachHostQueryDraftV1,
    signer: &ControllerBrokerPlanSignerV1,
    now_seconds: i64,
) -> Result<BrokerAuthorizationArtifactsV1, ControllerCommandFailure> {
    let (plan, ownership_lease, ownership_lease_signature) = draft.into_parts();
    let signed_plan = signer
        .sign_plan(plan, now_seconds)
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    Ok(BrokerAuthorizationArtifactsV1 {
        broker_plan: signed_plan.canonical_plan().to_vec(),
        broker_plan_signature: signed_plan.canonical_signature().to_vec(),
        ownership_lease,
        ownership_lease_signature,
        ..Default::default()
    })
}

fn verify_readiness_outcome(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    currentness: ([u8; 16], u64, [u8; 32], u64, [u8; 32]),
    trust_digest: [u8; 32],
) -> Result<(), ControllerCommandFailure> {
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS
    {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    }
    let now =
        sample_ownership_clock().map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    decode_host_attach_readiness_request_v1(
        outcome.request().exact_body(),
        outcome.request().peer(),
        outcome.request().peer_policy(),
        now.boottime_nanoseconds(),
    )
    .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    };
    let readiness = decode_host_attach_readiness_v1(exact_body)
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    if readiness.incarnation_id != currentness.0
        || readiness.assignment_epoch != currentness.1
        || readiness.assignment_digest != currentness.2
        || readiness.lease_generation != currentness.3
        || readiness.lease_digest != currentness.4
        || readiness.trust_digest != trust_digest
    {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    }
    Ok(())
}

pub(super) fn admit_public_attach(
    controller: &mut ProductionController,
    credentials: Option<&ControllerAttachCredentialsV1>,
    plan_signer: Option<&ControllerBrokerPlanSignerV1>,
    node: NodeId,
    host: &mut impl AuthenticatedHostAttachRouteExchangeV1,
    peer: &PublicApiPeer,
    capability_id: CapabilityId,
    canonical_request: &[u8],
) -> Result<AdmittedPublicAttachV1, ControllerCommandFailure> {
    let credentials = credentials.ok_or(ControllerCommandFailure::ControllerUnavailable)?;
    let plan_signer = plan_signer.ok_or(ControllerCommandFailure::ControllerUnavailable)?;
    let existing = controller
        .lookup_public_attach_existing(peer, capability_id, canonical_request)
        .map_err(classify_controller_error)?;
    if let Some((pending, true)) = &existing {
        return replay_attach(
            controller,
            credentials,
            plan_signer,
            node,
            host,
            peer,
            capability_id,
            canonical_request,
            pending,
        );
    }
    if let Some((pending, false)) = &existing {
        let now_seconds = sample_ownership_clock()
            .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?
            .wall_seconds();
        if pending.expires_at() <= now_seconds {
            host.drain_pending()?;
        }
    }
    if existing.is_none() {
        let preflight_time = sample_ownership_clock()
            .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?
            .wall_seconds();
        let readiness_draft = controller
            .prepare_public_attach_readiness(
                peer,
                capability_id,
                canonical_request,
                node,
                preflight_time,
            )
            .map_err(classify_controller_error)?;
        let expected_currentness = readiness_draft.currentness();
        let readiness_authorization =
            authorization_from_query_draft(readiness_draft, plan_signer, preflight_time)?;
        let readiness = host.query_readiness(&readiness_authorization)?;
        verify_readiness_outcome(&readiness, expected_currentness, credentials.trust_digest())?;
    }

    let pending = controller
        .reserve_public_attach(peer, capability_id, canonical_request)
        .map_err(classify_controller_error)?;
    if controller
        .public_operation(pending.operation_id())
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?
        .is_some()
    {
        return replay_attach(
            controller,
            credentials,
            plan_signer,
            node,
            host,
            peer,
            capability_id,
            canonical_request,
            &pending,
        );
    }
    let now_seconds = sample_ownership_clock()
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?
        .wall_seconds();
    let gate_config_digest = credentials
        .gate_config_digest(&pending)
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    let draft = controller
        .prepare_public_attach_host_install(
            peer,
            capability_id,
            canonical_request,
            &pending,
            node,
            &credentials.signing_key(),
            credentials.trust_digest(),
            gate_config_digest,
            now_seconds,
        )
        .map_err(classify_controller_error)?;
    let (grant, plan, ownership_lease, ownership_lease_signature) = draft.into_parts();
    let signed_plan = plan_signer
        .sign_plan(plan, now_seconds)
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    let authorization = BrokerAuthorizationArtifactsV1 {
        broker_plan: signed_plan.canonical_plan().to_vec(),
        broker_plan_signature: signed_plan.canonical_signature().to_vec(),
        ownership_lease,
        ownership_lease_signature,
        ..Default::default()
    };
    let outcome = host.install(&grant, &authorization)?;
    let route = route_from_authenticated_outcome(&outcome, &grant, &pending, credentials)?;
    finalize_attach(
        controller,
        credentials,
        peer,
        capability_id,
        canonical_request,
        &pending,
        &route,
    )
}

fn replay_attach(
    controller: &mut ProductionController,
    credentials: &ControllerAttachCredentialsV1,
    plan_signer: &ControllerBrokerPlanSignerV1,
    node: NodeId,
    host: &mut impl AuthenticatedHostAttachRouteExchangeV1,
    peer: &PublicApiPeer,
    capability_id: CapabilityId,
    canonical_request: &[u8],
    pending: &PublicAttachPendingV1,
) -> Result<AdmittedPublicAttachV1, ControllerCommandFailure> {
    // Accepted replay cannot invoke the Vacant-only grant signer or mutate
    // Host route state. It needs a fresh read-only physical readback.
    let now_seconds = sample_ownership_clock()
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?
        .wall_seconds();
    let query_draft = controller
        .prepare_public_attach_route_query(
            peer,
            capability_id,
            canonical_request,
            pending,
            node,
            now_seconds,
        )
        .map_err(classify_controller_error)?;
    let authorization = authorization_from_query_draft(query_draft, plan_signer, now_seconds)?;
    let outcome = host.query_route(
        *pending.operation_id().as_bytes(),
        pending.execution_id(),
        &authorization,
    )?;
    let route = route_from_query_outcome(&outcome, pending, credentials)?;
    finalize_attach(
        controller,
        credentials,
        peer,
        capability_id,
        canonical_request,
        pending,
        &route,
    )
}

fn finalize_attach(
    controller: &mut ProductionController,
    credentials: &ControllerAttachCredentialsV1,
    peer: &PublicApiPeer,
    capability_id: CapabilityId,
    canonical_request: &[u8],
    pending: &PublicAttachPendingV1,
    route: &AuthenticatedOpenSshRouteV1,
) -> Result<AdmittedPublicAttachV1, ControllerCommandFailure> {
    let (outcome, access) = controller
        .admit_public_attach_route(
            peer,
            capability_id,
            canonical_request,
            pending,
            route,
            credentials.issuer(),
        )
        .map_err(classify_controller_error)?;
    let operation_id = match outcome {
        AcceptOutcome::Accepted(operation) | AcceptOutcome::Replay(operation) => operation,
    };
    let operation = controller
        .public_operation(operation_id)
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?
        .ok_or(ControllerCommandFailure::ControllerUnavailable)?;

    Ok(AdmittedPublicAttachV1 { operation, access })
}

fn classify_controller_error(error: ControllerServiceError) -> ControllerCommandFailure {
    match error {
        ControllerServiceError::EmptyRequest
        | ControllerServiceError::RequestTooLarge
        | ControllerServiceError::Compilation(OperationCompilationError::Malformed) => {
            ControllerCommandFailure::InvalidRequest
        }
        ControllerServiceError::Compilation(OperationCompilationError::Rejected) => {
            ControllerCommandFailure::Rejected
        }
        _ => ControllerCommandFailure::ControllerUnavailable,
    }
}
