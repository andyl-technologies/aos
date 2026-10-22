//! Connection sequence and outstanding-response correlation after negotiation.
//!
//! A guard binds one admitted session/incarnation and fences malformed traffic.
//! It tracks transport correlations only; accepted messages still need schema,
//! capability, graph and authentic native-custody checks before model effects.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_format::Id;

use crate::ProviderError;
use crate::envelope::{Envelope, MessageKind, Method};

/// Limits outstanding request IDs independently in each connection direction.
pub const MAX_OUTSTANDING_REQUESTS: usize = 256;

/// Verifies one negotiated connection without inferring operation completion.
pub struct CorrelationGuard {
    session: Id,
    incarnation: Id,
    next_received: u64,
    next_sent: u64,
    maximum_requests: usize,
    pending: BTreeMap<Id, Envelope>,
    received_requests: BTreeMap<Id, Envelope>,
    writing_responses: BTreeMap<Id, Envelope>,
    extensions: BTreeSet<String>,
    failed: bool,
    continuation_installed: bool,
}

impl CorrelationGuard {
    pub(crate) fn observe_owned_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            session,
            incarnation,
            next_received,
            next_sent,
            maximum_requests,
            pending,
            received_requests,
            writing_responses,
            extensions,
            failed,
            continuation_installed,
        } = self;
        observer.observe(session)?;
        observer.observe(incarnation)?;
        observer.observe(next_received)?;
        observer.observe(next_sent)?;
        observer.observe(maximum_requests)?;
        observer.observe(pending)?;
        observer.observe(received_requests)?;
        observer.observe(writing_responses)?;
        observer.observe(extensions)?;
        observer.observe(failed)?;
        observer.observe(continuation_installed)
    }

    pub(crate) fn protocol_cut(
        &self,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
    ) -> Result<(), ProviderError> {
        if self.failed || !self.pending.is_empty() || !self.writing_responses.is_empty() {
            return Err(ProviderError::Correlation(
                "protocol capture unresolved outgoing correlation",
            ));
        }
        match cut {
            crate::protocol_snapshot::ProtocolCaptureCut::HostSettled
                if self.received_requests.is_empty() =>
            {
                Ok(())
            }
            crate::protocol_snapshot::ProtocolCaptureCut::NativeIncomingCapture
                if self.received_requests.len() == 1
                    && self.received_requests.values().all(|r| {
                        r.method == Method::Begin
                            && r.body.get("kind").and_then(serde_json::Value::as_str)
                                == Some("capture")
                    }) =>
            {
                Ok(())
            }
            _ => Err(ProviderError::Correlation(
                "protocol capture cut does not match original incoming requests",
            )),
        }
    }

    pub(crate) fn authenticate_prepared_capture_suffix(
        &self,
        originals: &[Envelope],
    ) -> Result<(), ProviderError> {
        let mut requests = originals
            .iter()
            .filter(|frame| frame.message == MessageKind::Request);
        if self.failed
            || !self.writing_responses.is_empty()
            || self.received_requests.len() != 1
            || self.received_requests.values().any(|frame| {
                frame.method != Method::Begin
                    || frame.body.get("kind").and_then(serde_json::Value::as_str) != Some("capture")
            })
            || self.pending.len() != requests.clone().count()
            || requests.any(|frame| {
                frame
                    .request_id
                    .0
                    .as_ref()
                    .is_none_or(|id| self.pending.get(id) != Some(frame))
            })
        {
            return Err(ProviderError::Correlation(
                "after preflight has unrelated prepared correlation",
            ));
        }
        Ok(())
    }

    pub(crate) fn preflight_restore_input_sequences(
        &self,
        outgoing: usize,
        incoming: usize,
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        if !self.pending.is_empty()
            || !self.writing_responses.is_empty()
            || self.received_requests.len() != 1
            || self.received_requests.values().any(|frame| {
                frame.method != Method::Begin
                    || frame.body.get("kind").and_then(serde_json::Value::as_str)
                        != Some("prepare_restore")
            })
        {
            return Err(ProviderError::Correlation(
                "restore input quote original phase",
            ));
        }
        self.preflight_confirmation_sequences(outgoing, incoming)
    }

    pub(crate) fn preflight_confirmation_sequences(
        &self,
        outgoing: usize,
        incoming: usize,
    ) -> Result<(), ProviderError> {
        let outgoing = u64::try_from(outgoing).map_err(|_| {
            ProviderError::ResourceExhausted("confirmation outgoing sequence count")
        })?;
        let incoming = u64::try_from(incoming).map_err(|_| {
            ProviderError::ResourceExhausted("confirmation incoming sequence count")
        })?;
        self.next_sent
            .checked_add(outgoing)
            .ok_or(ProviderError::ResourceExhausted(
                "confirmation outgoing sequence exhausted",
            ))?;
        self.next_received
            .checked_add(incoming)
            .ok_or(ProviderError::ResourceExhausted(
                "confirmation incoming sequence exhausted",
            ))?;
        Ok(())
    }

    pub(crate) fn authenticate_incoming_canonical_ack_admit(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(original)?;
        if original.message != MessageKind::Request
            || original.method != Method::Admit
            || original.sequence.get().checked_add(1) != Some(self.next_received)
            || self.received_requests.len() != 1
            || self.received_requests.values().next() != Some(original)
            || !self.pending.is_empty()
            || !self.writing_responses.is_empty()
        {
            return Err(ProviderError::Correlation(
                "native ACK has unrelated original Admit correlation",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticate_prepared_confirmation(
        &self,
        poll: &Envelope,
        originals: &[Envelope],
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(poll)?;
        let requests = originals
            .iter()
            .filter(|frame| frame.message == MessageKind::Request);
        let responses = originals
            .iter()
            .filter(|frame| frame.message == MessageKind::Response);
        if poll.message != MessageKind::Request
            || poll.method != Method::Poll
            || self.received_requests.len() != 1
            || self.received_requests.values().next() != Some(poll)
            || self.pending.len() != requests.clone().count()
            || self.writing_responses.len() != responses.clone().count()
            || requests.clone().any(|frame| {
                frame
                    .request_id
                    .0
                    .as_ref()
                    .is_none_or(|id| self.pending.get(id) != Some(frame))
            })
            || responses.clone().any(|frame| {
                frame
                    .request_id
                    .0
                    .as_ref()
                    .is_none_or(|id| self.writing_responses.get(id) != Some(frame))
            })
            || originals.iter().any(|frame| {
                frame.session_id != poll.session_id
                    || frame.incarnation_id != poll.incarnation_id
                    || frame.node_id != poll.node_id
                    || frame.capture_owner_id != poll.capture_owner_id
                    || frame.operation_id != poll.operation_id
                    || frame.execution_owner_id != poll.execution_owner_id
                    || (frame.message == MessageKind::Request
                        && (!frame.extensions.is_empty()
                            || !matches!(
                                frame.method,
                                Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
                            )))
                    || (frame.message == MessageKind::Response && frame.method != Method::Poll)
                    || frame.message == MessageKind::Event
            })
        {
            return Err(ProviderError::Correlation(
                "canonical ACK prepared Poll/proof originals differ",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticate_incoming_confirmation(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(original)?;
        if original.message != MessageKind::Request
            || original.method != Method::Poll
            || self.received_requests.len() != 1
            || self.received_requests.values().next() != Some(original)
            || !self.pending.is_empty()
            || !self.writing_responses.is_empty()
        {
            return Err(ProviderError::Correlation(
                "confirmation publication has unrelated original correlation",
            ));
        }
        Ok(())
    }

    pub(crate) fn protocol_view(&self) -> impl serde::Serialize + '_ {
        (
            "source-private.correlations/6",
            &self.session,
            &self.incarnation,
            crucible_node_format::U64::new(self.next_received),
            crucible_node_format::U64::new(self.next_sent),
            self.maximum_requests,
            &self.pending,
            &self.received_requests,
            &self.writing_responses,
            &self.extensions,
            self.failed,
            self.continuation_installed,
        )
    }

    /// Checks initial sequencing, including frames whose transport credit retired.
    pub(crate) fn unused(&self) -> bool {
        !self.failed
            && !self.continuation_installed
            && self.next_received == 2
            && self.next_sent == 2
            && self.pending.is_empty()
            && self.received_requests.is_empty()
            && self.writing_responses.is_empty()
    }

    /// Binds the negotiated identities and positive request credit.
    ///
    /// # Errors
    /// Rejects credit outside the CNP/1 hard ceiling. The caller must verify
    /// hello authentication and fence any previous connection before binding.
    pub fn new(
        session: Id,
        incarnation: Id,
        maximum_requests: usize,
        extensions: BTreeSet<String>,
    ) -> Result<Self, ProviderError> {
        if maximum_requests == 0 || maximum_requests > MAX_OUTSTANDING_REQUESTS {
            return Err(ProviderError::ResourceExhausted(
                "invalid outstanding request credit",
            ));
        }

        Ok(Self {
            session,
            incarnation,
            // The initial (or resumed) hello already consumed sequence one.
            next_received: 2,
            next_sent: 2,
            maximum_requests,
            pending: BTreeMap::new(),
            received_requests: BTreeMap::new(),
            writing_responses: BTreeMap::new(),
            extensions,
            failed: false,
            continuation_installed: false,
        })
    }

    /// Reserves response correlation before publishing an outgoing request.
    ///
    /// # Errors
    /// Rejects foreign scope, unsupported extensions, exhausted credit,
    /// duplicate outstanding IDs or use after connection failure. A failed
    /// write must retain this record until reconciliation or containment.
    pub fn register_request(&mut self, request: Envelope) -> Result<(), ProviderError> {
        if request.message != MessageKind::Request {
            return Err(ProviderError::Correlation("expected outgoing request"));
        }
        self.register_outgoing(request)
    }

    /// Reserves an outgoing frame's sequence and correlation before writing.
    ///
    /// Both requests and replies consume this direction's single sequence.
    /// A response discharges only transport request credit; native operation,
    /// journal, output and content custody require independent settlement.
    ///
    /// # Errors
    /// Rejects stale scope, wrong sequence, duplicate requests, exhausted
    /// credit, or replies that do not match an original incoming request.
    /// Refusal changes no state. An uncertain write requires [`Self::fence`].
    pub fn register_outgoing(&mut self, envelope: Envelope) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(&envelope)?;
        if envelope.sequence.get() != self.next_sent {
            return Err(ProviderError::Correlation(
                "outgoing frame sequence gap or duplicate",
            ));
        }
        let next = self
            .next_sent
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted("connection sequence"))?;

        match envelope.message {
            MessageKind::Request => {
                let id = envelope
                    .request_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation("missing outgoing request ID"))?;
                if self.pending.contains_key(id) {
                    return Err(ProviderError::Conflict("request is already outstanding"));
                }
                if self.pending.len() >= self.maximum_requests {
                    return Err(ProviderError::ResourceExhausted(
                        "outstanding request credit",
                    ));
                }
                self.pending.insert(id.clone(), envelope);
            }
            MessageKind::Response => {
                let id = envelope
                    .request_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation("missing outgoing response ID"))?;
                let original = self
                    .received_requests
                    .get(id)
                    .ok_or(ProviderError::Correlation(
                        "response has no incoming request",
                    ))?;
                original.matches_response(&envelope)?;
                if self.writing_responses.contains_key(id) {
                    return Err(ProviderError::Conflict("response write remains unresolved"));
                }
                self.writing_responses.insert(id.clone(), envelope);
            }
            MessageKind::Event => {}
        }

        self.next_sent = next;
        Ok(())
    }

    /// Releases incoming transport credit after the exact response write succeeds.
    ///
    /// # Errors
    /// Rejects an unknown or changed response. Failed/partial writes must fence
    /// the connection instead, retaining the original incoming request.
    pub fn confirm_response_sent(&mut self, response: &Envelope) -> Result<(), ProviderError> {
        self.check_live()?;
        let id = response
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("response lacks request ID"))?;
        if self.writing_responses.get(id) != Some(response) {
            return Err(ProviderError::Correlation(
                "response write confirmation mismatch",
            ));
        }
        self.writing_responses.remove(id);
        self.received_requests.remove(id);
        Ok(())
    }

    /// Checks an incoming frame and consumes exactly its connection sequence.
    ///
    /// # Errors
    /// Rejects stale scope, sequence gaps/duplicates, foreign response IDs,
    /// changed response correlation or unnegotiated extensions. Any failure
    /// fences the connection while preserving unresolved request records.
    pub fn receive(&mut self, envelope: &Envelope) -> Result<(), ProviderError> {
        self.check_live()?;
        let result = self.check_received(envelope);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Returns unresolved transport requests retained after a failure.
    pub fn pending_requests(&self) -> impl Iterator<Item = &Envelope> {
        self.pending.values()
    }

    /// Returns accepted incoming requests whose transport response is pending.
    pub fn incoming_requests(&self) -> impl Iterator<Item = &Envelope> {
        self.received_requests.values()
    }

    /// Fences a failed stream without treating unanswered requests as stopped.
    pub fn fence(&mut self) {
        self.failed = true;
    }

    fn check_received(&mut self, envelope: &Envelope) -> Result<(), ProviderError> {
        self.check_scope(envelope)?;
        if envelope.sequence.get() != self.next_received {
            return Err(ProviderError::Correlation(
                "frame sequence gap or duplicate",
            ));
        }
        let next = self
            .next_received
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted("connection sequence"))?;

        if envelope.message == MessageKind::Response {
            let id = envelope
                .request_id
                .0
                .as_ref()
                .ok_or(ProviderError::Correlation("missing response request ID"))?;
            let original = self.pending.get(id).ok_or(ProviderError::Correlation(
                "response has no original request",
            ))?;
            original.matches_response(envelope)?;
            self.pending.remove(id);
        } else if envelope.message == MessageKind::Request {
            let id = envelope
                .request_id
                .0
                .as_ref()
                .ok_or(ProviderError::Correlation("missing incoming request ID"))?;
            if self.received_requests.contains_key(id) {
                return Err(ProviderError::Conflict(
                    "incoming request is already outstanding",
                ));
            }
            if self.received_requests.len() >= self.maximum_requests {
                return Err(ProviderError::ResourceExhausted("incoming request credit"));
            }
            self.received_requests.insert(id.clone(), envelope.clone());
        }
        self.next_received = next;
        Ok(())
    }

    fn check_scope(&self, envelope: &Envelope) -> Result<(), ProviderError> {
        envelope.validate()?;
        if envelope.method == Method::Hello {
            return Err(ProviderError::Correlation("hello after negotiation"));
        }
        if envelope.session_id.0.as_ref() != Some(&self.session)
            || envelope.incarnation_id.0.as_ref() != Some(&self.incarnation)
        {
            return Err(ProviderError::Correlation("stale session or incarnation"));
        }
        if envelope
            .extensions
            .keys()
            .any(|key| !self.extensions.contains(key))
        {
            return Err(ProviderError::Correlation(
                "unnegotiated envelope extension",
            ));
        }
        Ok(())
    }

    fn check_live(&self) -> Result<(), ProviderError> {
        if self.failed {
            return Err(ProviderError::Correlation("connection is fenced"));
        }
        Ok(())
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These session tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use crucible_node_format::U64;

    use crate::envelope::{Nullable, tests::request};

    use super::*;

    fn guard() -> CorrelationGuard {
        CorrelationGuard::new(
            Id::new("session-1").unwrap(),
            Id::new("provider-1").unwrap(),
            2,
            BTreeSet::new(),
        )
        .unwrap()
    }

    fn first_request() -> Envelope {
        let mut envelope = request();
        envelope.sequence = U64::new(2);
        envelope
    }

    #[test]
    fn responses_can_arrive_in_an_order_different_from_requests() {
        let first = first_request();
        let mut second = first.clone();
        second.request_id = Nullable(Some(Id::new("request-2").unwrap()));
        second.sequence = U64::new(3);
        let mut guard = guard();
        guard.register_request(first.clone()).unwrap();
        guard.register_request(second.clone()).unwrap();

        let mut second_response = second;
        second_response.message = MessageKind::Response;
        second_response.sequence = U64::new(2);
        guard.receive(&second_response).unwrap();
        let mut first_response = first;
        first_response.message = MessageKind::Response;
        first_response.sequence = U64::new(3);
        guard.receive(&first_response).unwrap();

        assert_eq!(guard.pending_requests().count(), 0);
    }

    #[test]
    fn malformed_response_fences_connection_without_releasing_request_custody() {
        let original = first_request();
        let mut guard = guard();
        guard.register_request(original.clone()).unwrap();
        let mut response = original;
        response.message = MessageKind::Response;
        response.sequence = U64::new(2);
        response.execution_owner_id = Nullable(Some(Id::new("foreign-owner").unwrap()));

        assert!(guard.receive(&response).is_err());
        assert_eq!(guard.pending_requests().count(), 1);
        response.execution_owner_id = Nullable(Some(Id::new("owner-1").unwrap()));
        assert!(guard.receive(&response).is_err());
        assert_eq!(guard.pending_requests().count(), 1);
    }

    #[test]
    fn a_sequence_gap_cannot_be_healed_by_retrying_on_the_same_stream() {
        let mut guard = guard();
        let mut frame = request();
        frame.sequence = U64::new(3);

        assert!(guard.receive(&frame).is_err());
        frame.sequence = U64::new(2);
        assert!(guard.receive(&frame).is_err());
    }

    #[test]
    fn both_directions_have_bounded_credit_and_independent_sequences() {
        let mut guard = guard();
        let first = first_request();
        guard.receive(&first).unwrap();

        let mut second = first.clone();
        second.request_id = Nullable(Some(Id::new("incoming-2").unwrap()));
        second.sequence = U64::new(3);
        guard.receive(&second).unwrap();
        assert_eq!(guard.incoming_requests().count(), 2);

        let mut response = first;
        response.message = MessageKind::Response;
        // Sending is an independent direction; it still starts at two.
        guard.register_outgoing(response.clone()).unwrap();
        assert_eq!(guard.incoming_requests().count(), 2);
        guard.confirm_response_sent(&response).unwrap();
        assert_eq!(guard.incoming_requests().count(), 1);

        let mut outgoing = first_request();
        outgoing.request_id = Nullable(Some(Id::new("outgoing-1").unwrap()));
        outgoing.sequence = U64::new(3);
        guard.register_request(outgoing).unwrap();
        assert_eq!(guard.pending_requests().count(), 1);
    }

    #[test]
    fn incoming_credit_exhaustion_fences_without_losing_originals() {
        let mut guard = guard();
        let mut frame = first_request();
        guard.receive(&frame).unwrap();
        frame.request_id = Nullable(Some(Id::new("incoming-2").unwrap()));
        frame.sequence = U64::new(3);
        guard.receive(&frame).unwrap();

        frame.request_id = Nullable(Some(Id::new("incoming-3").unwrap()));
        frame.sequence = U64::new(4);
        assert!(matches!(
            guard.receive(&frame),
            Err(ProviderError::ResourceExhausted(_))
        ));
        assert_eq!(guard.incoming_requests().count(), 2);
        assert!(guard.receive(&frame).is_err());
    }

    #[test]
    fn invalid_outgoing_proposal_does_not_consume_sequence_or_credit() {
        let mut guard = guard();
        let mut frame = first_request();
        frame.sequence = U64::new(3);

        assert!(guard.register_request(frame.clone()).is_err());
        assert_eq!(guard.pending_requests().count(), 0);
        frame.sequence = U64::new(2);
        guard.register_request(frame).unwrap();

        guard.fence();
        assert_eq!(guard.pending_requests().count(), 1);
        assert!(guard.register_request(first_request()).is_err());
    }
}

mod continuation_data;
pub use continuation_data::DecodedSettledCorrelationData;

impl CorrelationGuard {
    pub(crate) fn authenticate_incoming_complete_restore(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(original)?;
        if original.message != MessageKind::Request
            || original.method != Method::Begin
            || original
                .body
                .get("kind")
                .and_then(serde_json::Value::as_str)
                != Some("prepare_restore")
            || original.sequence.get().checked_add(1) != Some(self.next_received)
            || self.received_requests.len() != 1
            || self.received_requests.values().next() != Some(original)
            || !self.pending.is_empty()
            || !self.writing_responses.is_empty()
        {
            return Err(ProviderError::Correlation(
                "complete restore unrelated original correlation",
            ));
        }
        Ok(())
    }
}

impl CorrelationGuard {
    pub(crate) fn original_restore_response_sequence(
        &self,
        request: &Envelope,
    ) -> Result<crucible_node_format::U64, ProviderError> {
        self.authenticate_incoming_complete_restore(request)?;
        self.next_sent
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted(
                "assigned native restore response sequence",
            ))?;
        Ok(crucible_node_format::U64::new(self.next_sent))
    }
}

impl CorrelationGuard {
    /// Checks the exact completed proof suffix while retaining its sole Commit.
    pub(crate) fn original_restore_response_after_proof_sequence(
        &self,
        request: &Envelope,
        proof: &crate::connection::CompletedHeldProof,
    ) -> Result<crucible_node_format::U64, ProviderError> {
        self.check_live()?;
        self.check_scope(request)?;
        let (received, sent) = proof.counter_boundary(request)?;
        if request.message != MessageKind::Request
            || request.method != Method::Begin
            || request.body.get("kind").and_then(serde_json::Value::as_str)
                != Some("prepare_restore")
            || self.next_received != received
            || self.next_sent != sent
            || self.received_requests.len() != 1
            || self.received_requests.values().next() != Some(request)
            || !self.pending.is_empty()
            || !self.writing_responses.is_empty()
        {
            return Err(ProviderError::Correlation(
                "held proof has unrelated original Commit correlation",
            ));
        }
        self.next_sent
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted(
                "held proof restore response sequence",
            ))?;
        Ok(crucible_node_format::U64::new(self.next_sent))
    }
}

/// Owns already allocated outgoing correlation nodes for one exact proof plan.
pub(crate) struct OriginalRestoreProofRegistration {
    pending: BTreeMap<Id, Envelope>,
    next_received: u64,
    first_sent: u64,
    next_sent: u64,
    activated: bool,
}

impl CorrelationGuard {
    pub(crate) fn prebuild_original_restore_proof_registration(
        &self,
        commit: &Envelope,
        originals: &[Envelope],
    ) -> Result<OriginalRestoreProofRegistration, ProviderError> {
        self.authenticate_incoming_complete_restore(commit)?;
        if originals.len() < 3 || originals.len() > self.maximum_requests {
            return Err(ProviderError::ResourceExhausted(
                "held proof correlation roster",
            ));
        }
        let mut next = self.next_sent;
        let mut pending = BTreeMap::new();
        for original in originals {
            self.check_scope(original)?;
            if original.message != MessageKind::Request
                || !matches!(
                    original.method,
                    Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
                )
                || !original.extensions.is_empty()
                || original.sequence.get() != next
            {
                return Err(ProviderError::Correlation(
                    "held proof prebuilt original scope",
                ));
            }
            next = next.checked_add(1).ok_or(ProviderError::ResourceExhausted(
                "held proof correlation sequence",
            ))?;
            let id = original
                .request_id
                .0
                .as_ref()
                .ok_or(ProviderError::Correlation("held proof request ID absent"))?;
            if pending.contains_key(id) {
                return Err(ProviderError::Conflict("held proof repeated request ID"));
            }
            pending.insert(id.clone(), original.clone());
        }
        Ok(OriginalRestoreProofRegistration {
            pending,
            next_received: self.next_received,
            first_sent: self.next_sent,
            next_sent: next,
            activated: false,
        })
    }
}

impl OriginalRestoreProofRegistration {
    pub(crate) fn activate(
        &mut self,
        guard: &mut CorrelationGuard,
        commit: &Envelope,
    ) -> Result<(), ProviderError> {
        guard.authenticate_incoming_complete_restore(commit)?;
        if self.activated
            || guard.next_received != self.next_received
            || guard.next_sent != self.first_sent
            || !guard.pending.is_empty()
        {
            return Err(ProviderError::Correlation(
                "held proof activation changed correlation",
            ));
        }
        // All nodes and deep Envelope copies were allocated before native effect.
        // Swapping into the proven empty map does not allocate or reencode.
        std::mem::swap(&mut guard.pending, &mut self.pending);
        guard.next_sent = self.next_sent;
        self.activated = true;
        Ok(())
    }

    pub(crate) fn observe_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            pending,
            next_received,
            first_sent,
            next_sent,
            activated,
        } = self;
        observer.observe(pending)?;
        observer.observe(next_received)?;
        observer.observe(first_sent)?;
        observer.observe(next_sent)?;
        observer.observe(activated)
    }
}

#[path = "session/prepared_blob_proof.rs"]
mod prepared_blob_proof;

impl CorrelationGuard {
    /// Checks the sole current request lent by the private native17 action cut.
    ///
    /// This does not widen the older capture-cut grammar or accept a caller's
    /// arbitrary Envelope as a current native request.
    pub(crate) fn authenticate_native17_current_action_cut_data(
        &self,
        current: &crate::reference_packet::service::native_startup::NativeRestoredSettledActionCurrent17<'_>,
    ) -> Result<(), ProviderError> {
        let original = current.current_capture_cut_original17_data()?;
        self.check_live()?;
        self.check_scope(original)?;
        let id = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native17 current action has no request identity",
            ))?;
        if original.message != MessageKind::Request
            || original.sequence.get().checked_add(1) != Some(self.next_received)
            || self.received_requests.len() != 1
            || self.received_requests.get(id) != Some(original)
            || !self.pending.is_empty()
            || !self.writing_responses.is_empty()
        {
            return Err(ProviderError::Correlation(
                "native17 current action correlation mismatch",
            ));
        }
        Ok(())
    }
}

#[path = "session/observation17_cut.rs"]
mod observation17_cut;

#[path = "session/capture17_cut.rs"]
mod capture17_cut;
pub(crate) use capture17_cut::is_native_capture17_original_data;

impl CorrelationGuard {
    /// Returns the actual outgoing sequence for the first retained bootstrap reply.
    ///
    /// This reads transport DATA only. The enclosing original SDK/Source/Birth
    /// guards and separately admitted reply construction remain mandatory.
    ///
    /// # Errors
    /// Refuses a fenced guard, foreign or absent original, another method/cut,
    /// or any outgoing request or response write already in progress.
    pub(crate) fn original_bootstrap_response_sequence_data(
        &self,
        original: &Envelope,
    ) -> Result<crucible_node_format::U64, ProviderError> {
        self.check_live()?;
        self.check_scope(original)?;
        let mut incoming = self.received_requests.values();
        if original.method != Method::NativeImport18Bootstrap
            || original.sequence.get() != 2
            || self.next_received != 3
            || self.next_sent != 2
            || !self.pending.is_empty()
            || !self.writing_responses.is_empty()
            || incoming.next() != Some(original)
            || incoming.next().is_some()
        {
            return Err(ProviderError::Correlation(
                "original bootstrap reply sequence DATA",
            ));
        }
        Ok(crucible_node_format::U64::new(self.next_sent))
    }

    /// Names actual original-reply sequence-query controls before its loan.
    pub(crate) fn original_bootstrap_response_sequence_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&Envelope>()
            + size_of::<std::collections::btree_map::Values<'static, Id, Envelope>>()
            + size_of::<Option<&Envelope>>() * 2
            + size_of::<crucible_node_format::U64>()
            + size_of::<Result<crucible_node_format::U64, ProviderError>>()
            + size_of::<Result<(), ProviderError>>() * 2
    }
}

#[path = "session/bootstrap_publication.rs"]
mod bootstrap_publication;
