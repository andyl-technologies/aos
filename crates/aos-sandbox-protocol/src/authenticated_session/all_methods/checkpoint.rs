//! Durable record drafts derived only from live method-complete evidence.
//!
//! Draft construction re-decodes both exact signed packets and rebuilds their
//! fixed companions before handing a canonical value to a journal owner. It
//! performs no write and the returned record remains nonauthorizing.

use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionDurableError, BrokerSessionDurableRecordV1,
    BrokerSessionOutcomeCompanionV1, BrokerSessionPeerBindingV1, BrokerSessionProtectedBindingsV1,
    BrokerSessionRequestCompanionV1, complete_signed_request_digest_v1,
    decode_canonical_request_v1, decode_canonical_response_v1,
};

use super::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerOutcomeDirectionV1, AuthenticatedBrokerRequestDirectionV1,
};

/// Reports an inconsistent live-to-durable projection.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthenticatedBrokerMethodCheckpointErrorV1 {
    /// A signed packet, companion, or durable record failed validation.
    #[error("invalid authenticated broker durable projection")]
    Durable(#[from] BrokerSessionDurableError),
    /// Canonical packet decoding or a live evidence cross-link failed.
    #[error("authenticated broker live evidence is inconsistent")]
    InconsistentEvidence,
}

/// Derives a canonical pending request record from live semantic evidence.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodCheckpointErrorV1`] if any signed
/// artifact, method, session, request, sequence, ceiling, or peer cross-link
/// differs from the admitted evidence.
pub fn derive_pending_request_record_v1(
    request: &AuthenticatedBrokerMethodRequestV1,
    revision: u64,
    predecessor: [u8; 32],
    peer_binding: BrokerSessionPeerBindingV1,
    protected_bindings: BrokerSessionProtectedBindingsV1,
) -> Result<BrokerSessionDurableRecordV1, AuthenticatedBrokerMethodCheckpointErrorV1> {
    let endpoint = match request.direction() {
        AuthenticatedBrokerRequestDirectionV1::ClientSend => BrokerSessionDurableEndpointV1::Client,
        AuthenticatedBrokerRequestDirectionV1::ServerReceive => {
            BrokerSessionDurableEndpointV1::Broker
        }
    };
    let canonical = decode_canonical_request_v1(request.canonical_packet())
        .map_err(|_| AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence)?;
    let signed = canonical.signed_artifact().clone();
    if signed.method() != request.method()
        || signed.subject().session_binding() != request.session_binding()
        || signed.subject().request_id() != request.request_id()
        || signed.subject().sequence() != request.client_sequence()
        || complete_signed_request_digest_v1(&signed) != request.signed_request_digest()
    {
        return Err(AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence);
    }
    let profile = aos_sandbox_broker_session_protocol::authenticated_broker_method_profile_v1(
        request.method(),
    )
    .ok_or(AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence)?;
    let companion = BrokerSessionRequestCompanionV1::try_from_parts(
        profile.protocol(),
        request.method(),
        request.deadline_boottime_nanoseconds(),
        request.maximum_response_bytes(),
        signed,
    )
    .map_err(BrokerSessionDurableError::from)?;
    BrokerSessionDurableRecordV1::new_request(
        revision,
        predecessor,
        endpoint,
        request.session_binding(),
        peer_binding,
        protected_bindings,
        request.semantic_commitment(),
        request.request_id(),
        companion,
        request.canonical_packet().to_vec(),
    )
    .map_err(Into::into)
}

/// Advances a terminal record to its exact next admitted request.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodCheckpointErrorV1`] unless the record
/// is terminal and the request preserves its protocol, session, peer binding,
/// predecessor commitment, revision, and next client sequence.
pub fn derive_successor_request_record_v1(
    terminal: &BrokerSessionDurableRecordV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    peer_binding: BrokerSessionPeerBindingV1,
    protected_bindings: BrokerSessionProtectedBindingsV1,
) -> Result<BrokerSessionDurableRecordV1, AuthenticatedBrokerMethodCheckpointErrorV1> {
    let expected_direction = match terminal.endpoint() {
        BrokerSessionDurableEndpointV1::Client => AuthenticatedBrokerRequestDirectionV1::ClientSend,
        BrokerSessionDurableEndpointV1::Broker => {
            AuthenticatedBrokerRequestDirectionV1::ServerReceive
        }
    };
    if request.session_binding() != terminal.session_binding()
        || peer_binding != terminal.peer_binding()
        || request.direction() != expected_direction
        || request.client_sequence()
            != terminal
                .client_sequence()
                .checked_add(1)
                .ok_or(AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence)?
    {
        return Err(AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence);
    }
    let canonical = decode_canonical_request_v1(request.canonical_packet())
        .map_err(|_| AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence)?;
    let signed = canonical.signed_artifact().clone();
    if signed.method() != request.method()
        || signed.subject().request_id() != request.request_id()
        || complete_signed_request_digest_v1(&signed) != request.signed_request_digest()
    {
        return Err(AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence);
    }
    let profile = aos_sandbox_broker_session_protocol::authenticated_broker_method_profile_v1(
        request.method(),
    )
    .ok_or(AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence)?;
    if profile.protocol() != terminal.protocol() {
        return Err(AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence);
    }
    let companion = BrokerSessionRequestCompanionV1::try_from_parts(
        terminal.protocol(),
        request.method(),
        request.deadline_boottime_nanoseconds(),
        request.maximum_response_bytes(),
        signed,
    )
    .map_err(BrokerSessionDurableError::from)?;
    terminal
        .with_next_request(
            protected_bindings,
            request.semantic_commitment(),
            request.request_id(),
            companion,
            request.canonical_packet().to_vec(),
        )
        .map_err(Into::into)
}

/// Adds a canonical terminal outcome to its exact pending durable record.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodCheckpointErrorV1`] unless the live
/// outcome, pending record, and both signed artifacts form one exact exchange.
pub fn derive_terminal_record_v1(
    pending: &BrokerSessionDurableRecordV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    revision: u64,
    predecessor: [u8; 32],
    protected_bindings: BrokerSessionProtectedBindingsV1,
) -> Result<BrokerSessionDurableRecordV1, AuthenticatedBrokerMethodCheckpointErrorV1> {
    let expected_direction = match pending.endpoint() {
        BrokerSessionDurableEndpointV1::Client => {
            AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        }
        BrokerSessionDurableEndpointV1::Broker => AuthenticatedBrokerOutcomeDirectionV1::ServerSend,
    };
    if outcome.request().canonical_packet() != pending.request_packet()
        || outcome.request().request_id() != pending.request_id()
        || outcome.request().session_binding() != pending.session_binding()
        || outcome.request().method() != pending.method()
        || outcome.direction() != expected_direction
    {
        return Err(AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence);
    }
    let canonical = decode_canonical_response_v1(outcome.canonical_packet())
        .map_err(|_| AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence)?;
    let signed = canonical.signed_artifact().clone();
    if signed.method() != outcome.method()
        || signed.subject().session_binding() != pending.session_binding()
        || signed.subject().request_id() != pending.request_id()
        || signed.subject().sequence() != outcome.broker_sequence()
        || signed.subject().signed_request_digest() != outcome.request().signed_request_digest()
    {
        return Err(AuthenticatedBrokerMethodCheckpointErrorV1::InconsistentEvidence);
    }
    let companion = BrokerSessionOutcomeCompanionV1::try_from_parts(
        pending.protocol(),
        pending.method(),
        pending.request_id(),
        pending.client_sequence(),
        outcome.request().maximum_response_bytes(),
        outcome.request().signed_request_digest(),
        signed,
    )
    .map_err(BrokerSessionDurableError::from)?;
    pending
        .with_terminal_outcome(
            revision,
            predecessor,
            protected_bindings,
            outcome.semantic_commitment(),
            companion,
            outcome.canonical_packet().to_vec(),
        )
        .map_err(Into::into)
}
