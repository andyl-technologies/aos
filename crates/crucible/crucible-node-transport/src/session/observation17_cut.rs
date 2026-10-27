//! Rejoins one actual incoming signed Observe17 transport correlation.
//!
//! This cut preserves the normal settled/capture guards. It creates no native
//! authority, model currentness, Source proof, row grant or replay permission.

use super::*;
use crate::reference_packet::service::restored_input_reactive17::RESTORED_INPUT_REACTIVE17_FEATURE;

impl CorrelationGuard {
    /// Compares the exact current incoming request before its new17 action.
    ///
    /// # Errors
    /// Refuses a failed guard, outgoing correlations, another complete request,
    /// missing selected extension, another method or a different live sequence.
    pub(crate) fn authenticate_incoming_observation17_cut_data(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        if self.failed
            || !self.pending.is_empty()
            || !self.writing_responses.is_empty()
            || self.received_requests.len() != 1
            || self.received_requests.get(id) != Some(original)
            || original.message != MessageKind::Request
            || original.method != Method::Observe
            || original.extensions.len() != 1
            || !original
                .extensions
                .contains_key(RESTORED_INPUT_REACTIVE17_FEATURE)
            || original.sequence.get().checked_add(1) != Some(self.next_received)
        {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("signed Observe17 incoming correlation cut differs")
}

// crucible-lint: allow panic-shortcut -- These transport DATA controls never create a native action.
#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::U64;

    fn fixture() -> (CorrelationGuard, Envelope) {
        let mut original = crate::envelope::tests::request();
        original.method = Method::Observe;
        original.sequence = U64::new(2);
        original.extensions.clear();
        original.extensions.insert(
            RESTORED_INPUT_REACTIVE17_FEATURE.into(),
            serde_json::Value::Null,
        );
        let guard = CorrelationGuard::new(
            original.session_id.0.clone().unwrap(),
            original.incarnation_id.0.clone().unwrap(),
            4,
            [RESTORED_INPUT_REACTIVE17_FEATURE.to_owned()]
                .into_iter()
                .collect(),
        )
        .unwrap();
        (guard, original)
    }

    #[test]
    fn actual_incoming_cut_is_distinct_from_settled_and_preserves_custody() {
        let (mut guard, original) = fixture();
        assert!(
            guard
                .authenticate_incoming_observation17_cut_data(&original)
                .is_err()
        );
        guard.receive(&original).unwrap();
        let retained = guard.incoming_requests().next().unwrap() as *const Envelope;
        guard
            .authenticate_incoming_observation17_cut_data(&original)
            .unwrap();
        assert!(
            guard
                .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)
                .is_err()
        );
        assert_eq!(guard.incoming_requests().count(), 1);
        assert_eq!(
            guard.incoming_requests().next().unwrap() as *const Envelope,
            retained
        );
        assert_eq!(guard.incoming_requests().next(), Some(&original));
    }

    #[test]
    fn changed_body_extra_request_outgoing_or_failure_cannot_qualify_the_cut() {
        for changed in 0..5 {
            let (mut guard, original) = fixture();
            guard.receive(&original).unwrap();
            let mut candidate = original.clone();
            match changed {
                0 => {
                    candidate
                        .body
                        .insert("changed".into(), serde_json::Value::Bool(true));
                }
                1 => {
                    candidate.sequence = U64::new(3);
                }
                2 => {
                    let mut next = original.clone();
                    next.request_id.0 = Some(Id::new("other-incoming").unwrap());
                    next.sequence = U64::new(3);
                    guard.receive(&next).unwrap();
                }
                3 => {
                    let mut outgoing = original.clone();
                    outgoing.request_id.0 = Some(Id::new("actual-outgoing").unwrap());
                    guard.register_request(outgoing).unwrap();
                }
                _ => guard.fence(),
            }
            assert!(
                guard
                    .authenticate_incoming_observation17_cut_data(&candidate)
                    .is_err()
            );
            assert!(
                guard
                    .received_requests
                    .values()
                    .any(|actual| actual == &original)
            );
        }
    }
}
