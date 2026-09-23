//! Sole-worker public ATTACH sequencing behind authenticated Host evidence.
//!
//! The Host exchange is deliberately unavailable until the retained broker
//! session implements the signed pending-grant install and physical readback
//! method. Its availability check precedes the durable reservation, so an
//! unsupported deployment does not strand a public idempotency key.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::attach_route_issuer::AuthenticatedOpenSshRouteV1;
use aos_sandbox::public_api_session::PublicApiPeer;
use aos_sandbox::public_attach_pending::PublicAttachPendingV1;
use aos_sandbox::{AcceptOutcome, ControllerServiceError, OperationCompilationError};
use aos_sandbox_core::CapabilityId;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};
use aos_sandbox_protocol::{
    decode_host_attach_gate_evidence_v1, decode_host_attach_gate_request_v1,
};

use crate::controller_attach_credentials::ControllerAttachCredentialsV1;
use crate::controller_ownership::sample_ownership_clock;

use super::{AdmittedPublicAttachV1, ControllerCommandFailure, ProductionController};

/// Adapts only a retained authenticated Host broker session to route evidence.
///
/// An implementation must submit the exact signed grant, verify the Host
/// method's authenticated response and signed physical gate commitment, and
/// construct the route solely from that response. It must not accept any route
/// fields from the public request or a caller-supplied address.
pub(super) trait AuthenticatedHostAttachRouteExchangeV1 {
    /// Reports whether the Host method and retained authenticated session exist.
    fn is_available(&self) -> bool;

    /// Installs and reads back the exact pending operation's Host gate.
    ///
    /// # Errors
    ///
    /// Returns an error if the signed grant, current Host admission, gate
    /// installation, or signed physical readback cannot be verified.
    fn install_and_observe(
        &mut self,
        grant: &[u8],
    ) -> Result<AuthenticatedOpenSshRouteV1, ControllerCommandFailure>;
}

/// Fail-closed adapter until the Host broker route method is wired.
pub(super) struct UnavailableHostAttachRouteV1;

impl AuthenticatedHostAttachRouteExchangeV1 for UnavailableHostAttachRouteV1 {
    fn is_available(&self) -> bool {
        false
    }

    fn install_and_observe(
        &mut self,
        _grant: &[u8],
    ) -> Result<AuthenticatedOpenSshRouteV1, ControllerCommandFailure> {
        Err(ControllerCommandFailure::ControllerUnavailable)
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
    let port = u16::try_from(evidence.port)
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    if evidence.incarnation_id != pending.sandbox_incarnation_id()
        || evidence.assignment_epoch != pending.assignment_epoch()
        || evidence.principal_id != pending.principal_id()
        || evidence.audit_id != pending.audit_id()
        || evidence.expires_at != pending.expires_at()
        || evidence.expires_at <= now.wall_seconds()
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

pub(super) fn admit_public_attach(
    controller: &mut ProductionController,
    credentials: Option<&ControllerAttachCredentialsV1>,
    host: &mut impl AuthenticatedHostAttachRouteExchangeV1,
    peer: &PublicApiPeer,
    capability_id: CapabilityId,
    canonical_request: &[u8],
) -> Result<AdmittedPublicAttachV1, ControllerCommandFailure> {
    let credentials = credentials.ok_or(ControllerCommandFailure::ControllerUnavailable)?;
    if !host.is_available() {
        return Err(ControllerCommandFailure::ControllerUnavailable);
    }

    let pending = controller
        .reserve_public_attach(peer, capability_id, canonical_request)
        .map_err(classify_controller_error)?;
    let now_seconds = sample_ownership_clock()
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?
        .wall_seconds();
    let gate_config_digest = credentials
        .gate_config_digest(&pending)
        .map_err(|_| ControllerCommandFailure::ControllerUnavailable)?;
    let grant = controller
        .sign_public_attach_pending_grant(
            peer,
            capability_id,
            canonical_request,
            &pending,
            &credentials.signing_key(),
            credentials.trust_digest(),
            gate_config_digest,
            now_seconds,
        )
        .map_err(classify_controller_error)?;
    let route = host.install_and_observe(&grant)?;
    let (outcome, access) = controller
        .admit_public_attach_route(
            peer,
            capability_id,
            canonical_request,
            &pending,
            &route,
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
