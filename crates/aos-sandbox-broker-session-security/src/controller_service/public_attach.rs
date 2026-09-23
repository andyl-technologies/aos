//! Sole-worker public ATTACH sequencing behind authenticated Host evidence.
//!
//! The Host exchange is deliberately unavailable until the retained broker
//! session implements the signed pending-grant install and physical readback
//! method. Its availability check precedes the durable reservation, so an
//! unsupported deployment does not strand a public idempotency key.

use aos_sandbox::attach_route_issuer::AuthenticatedOpenSshRouteV1;
use aos_sandbox::public_api_session::PublicApiPeer;
use aos_sandbox::{AcceptOutcome, ControllerServiceError, OperationCompilationError};
use aos_sandbox_core::CapabilityId;

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
