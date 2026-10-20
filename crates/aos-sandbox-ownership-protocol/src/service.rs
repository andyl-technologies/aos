//! Portable ordinary Ownership dispatch contract without an issuer or payer.
//!
//! The trait carries semantic envelopes only. It does not authenticate a native
//! peer, supply a protected key, construct a financial original or authorize a
//! role-specific IO entrance. The paid fixed local owner never implements this
//! naked handler interface; it keeps its private original operation loop.

use aos_sandbox_core::model::KeyReference;
use crate::protocol::{NegotiatedOwnershipSessionV1, OwnershipRequestEnvelopeV1,
    OwnershipResponseEnvelopeV1, OwnershipProtocolValidationError};

/// Reports invalid service composition or request-session substitution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipProtocolServiceError {
    /// The session does not exactly select this authority and V1 service shape.
    #[error("ownership protocol service session is invalid")]
    InvalidSession,
    /// A request or response violates the negotiated semantic protocol.
    #[error("ownership protocol service envelope is invalid: {0}")]
    Protocol(#[from] OwnershipProtocolValidationError),
}

/// Dispatches one authenticated request to a fixed ownership-authority owner.
///
/// The carrier validates its socket, MAC, sequence, and canonical request
/// before calling this interface. Implementations must retain the durable
/// authority and issuer in one protected process and reject a substituted
/// negotiated session before producing a response.
pub trait OwnershipProtocolRequestHandler {
    /// Returns the authority generation fixed by protected configuration.
    fn authority(&self) -> &KeyReference;

    /// Handles one validated request under the exact negotiated session.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipProtocolServiceError`] if the session or request
    /// differs from the handler's protected authority contract.
    fn handle(
        &mut self,
        session: &NegotiatedOwnershipSessionV1,
        request: &OwnershipRequestEnvelopeV1,
    ) -> Result<OwnershipResponseEnvelopeV1, OwnershipProtocolServiceError>;
}
