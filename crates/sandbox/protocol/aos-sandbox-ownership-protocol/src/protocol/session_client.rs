//! Transport-neutral clients and untrusted response fields for ownership sessions.
//!
//! Carriers retain authentication and pre-allocation framing responsibilities.
//! Decoded response fields remain untrusted until the negotiated session checks
//! their exact request, method, transaction and outcome binding.

use super::{
    NegotiatedOwnershipSessionV1, OwnershipMethodV1, OwnershipProtocolValidationError,
    OwnershipRequestEnvelopeV1, OwnershipResponseEnvelopeV1, OwnershipResponseOutcomeV1,
    OwnershipTransactionReferenceV1,
};

/// Carries independently decoded, untrusted ownership-response fields.
///
/// A carrier constructs this value without normalizing echoed metadata. The
/// controller submits every field to
/// [`NegotiatedOwnershipSessionV1::validate_response_parts`] before observing
/// the outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedOwnershipResponsePartsV1 {
    binding: [u8; 32],
    method: OwnershipMethodV1,
    transaction: OwnershipTransactionReferenceV1,
    outcome: OwnershipResponseOutcomeV1,
}

impl UntrustedOwnershipResponsePartsV1 {
    /// Retains independently decoded fields for controller-side validation.
    #[must_use]
    pub const fn new(
        binding: [u8; 32],
        method: OwnershipMethodV1,
        transaction: OwnershipTransactionReferenceV1,
        outcome: OwnershipResponseOutcomeV1,
    ) -> Self {
        Self {
            binding,
            method,
            transaction,
            outcome,
        }
    }

    /// Validates all retained fields against the exact session and request.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipProtocolValidationError`] when any echoed binding,
    /// method, transaction or outcome violates the negotiated protocol.
    pub fn validate(
        self,
        session: &NegotiatedOwnershipSessionV1,
        request: &OwnershipRequestEnvelopeV1,
    ) -> Result<OwnershipResponseEnvelopeV1, OwnershipProtocolValidationError> {
        session.validate_response_parts(
            request,
            self.binding,
            self.method,
            self.transaction,
            self.outcome,
        )
    }
}

/// Exchanges ownership messages over one already-authenticated carrier.
///
/// Implementations own transport authentication, byte framing, deadlines, and
/// allocation ceilings. Before allocating or decoding a response, an adapter
/// must reject its carrier frame length above
/// [`NegotiatedOwnershipSessionV1::maximum_response_bytes`]. The negotiated
/// semantic session must describe those exact carrier limits. Response fields
/// are returned without semantic trust; the controller validates them
/// independently. An observed post-allocation wire size is deliberately not a
/// substitute for enforcement at the carrier framing boundary.
pub trait OwnershipAuthoritySessionClient {
    /// Returns the immutable negotiated semantic contract for this connection.
    fn session(&self) -> &NegotiatedOwnershipSessionV1;

    /// Sends one validated request and returns independently decoded fields.
    ///
    /// The implementation must authenticate the peer and enforce the session's
    /// complete response ceiling at its framing layer before allocating the
    /// decoded outcome or any artifact buffers.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipSessionTransportError`] when no authenticated,
    /// bounded response can be delivered.
    fn exchange(
        &mut self,
        request: &OwnershipRequestEnvelopeV1,
    ) -> Result<UntrustedOwnershipResponsePartsV1, OwnershipSessionTransportError>;
}

/// Classifies carrier failure by its safe controller recovery action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipSessionTransportError {
    /// Delivery or response status is indeterminate, so exact query is required.
    #[error("ownership authority transport is unavailable")]
    Unavailable,
    /// Authentication, framing, canonical decoding, or integrity failed.
    #[error("ownership authority transport integrity failed")]
    IntegrityFailure,
}
