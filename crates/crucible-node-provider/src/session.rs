//! Connection sequence and outstanding-response correlation after negotiation.
//!
//! A guard binds one admitted session/incarnation and fences malformed traffic.
//! It tracks transport correlations only; accepted messages still need schema,
//! capability, graph and authentic native-custody checks before model effects.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::Id;

use crate::ProviderError;
use crate::envelope::{Envelope, MessageKind, Method};

/// Limits outstanding request IDs independently in each connection direction.
pub const MAX_OUTSTANDING_REQUESTS: usize = 256;

/// Verifies one negotiated connection without inferring operation completion.
pub struct CorrelationGuard {
    session: Id,
    incarnation: Id,
    next_received: u64,
    maximum_requests: usize,
    pending: BTreeMap<Id, Envelope>,
    extensions: BTreeSet<String>,
    failed: bool,
}

impl CorrelationGuard {
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
            maximum_requests,
            pending: BTreeMap::new(),
            extensions,
            failed: false,
        })
    }

    /// Reserves response correlation before publishing an outgoing request.
    ///
    /// # Errors
    /// Rejects foreign scope, unsupported extensions, exhausted credit,
    /// duplicate outstanding IDs or use after connection failure. A failed
    /// write must retain this record until reconciliation or containment.
    pub fn register_request(&mut self, request: Envelope) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(&request)?;
        if request.message != MessageKind::Request {
            return Err(ProviderError::Correlation("expected outgoing request"));
        }
        let id = request
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

        self.pending.insert(id.clone(), request);
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
#[allow(clippy::unwrap_used)]
mod tests {
    use crucible_node_contract::U64;

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

    #[test]
    fn responses_can_arrive_in_an_order_different_from_requests() {
        let first = request();
        let mut second = first.clone();
        second.request_id = Nullable(Some(Id::new("request-2").unwrap()));
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
        let original = request();
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
}
