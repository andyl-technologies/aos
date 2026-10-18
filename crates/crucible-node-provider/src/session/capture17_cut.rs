//! Rejoins the exact sole incoming selected17 Capture-family correlation.
//!
//! These transport predicates do not authenticate a Source, current model,
//! native reserve or administrative Capture ticket. Normal cuts stay unchanged.

use super::*;
use crate::reference_packet::service::{
    restored_settled_capture::{
        RESTORED_SETTLED_CAPTURE_FEATURE, upload::RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE,
    },
    restored_settled_confirmation::PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
};

/// Recognizes only the selected family’s finite method/extension correspondence.
pub(crate) fn is_native_capture17_original_data(original: &Envelope) -> bool {
    let feature = match original.method {
        Method::Begin => RESTORED_SETTLED_CAPTURE_FEATURE,
        Method::BlobBegin | Method::BlobChunk | Method::BlobFinish => {
            RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE
        }
        Method::Poll => PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
        _ => return false,
    };
    original.message == MessageKind::Request
        && original.extensions.len() == 1
        && original.extensions.contains_key(feature)
}

impl CorrelationGuard {
    /// Compares this complete actual incoming request before its native phase.
    ///
    /// # Errors
    /// Refuses failed correlation, another live request, pending outgoing work,
    /// wrong selected method/feature or changed current sequence/original.
    pub(crate) fn authenticate_incoming_capture17_cut_data(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        if self.failed
            || !self.pending.is_empty()
            || !self.writing_responses.is_empty()
            || self.received_requests.len() != 1
            || self.received_requests.get(id) != Some(original)
            || !is_native_capture17_original_data(original)
            || original.sequence.get().checked_add(1) != Some(self.next_received)
        {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("Capture17 sole incoming correlation differs")
}

// crucible-lint: allow panic-shortcut -- These real correlation controls issue no native or Source authority.
#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::U64;
    use serde_json::Value;

    const PHASES: [(Method, &str); 5] = [
        (Method::Begin, RESTORED_SETTLED_CAPTURE_FEATURE),
        (Method::BlobBegin, RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE),
        (Method::BlobChunk, RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE),
        (Method::BlobFinish, RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE),
        (
            Method::Poll,
            PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
        ),
    ];

    fn fixture(method: Method, feature: &str) -> (CorrelationGuard, Envelope) {
        // The null artifact is deliberate: this fixture proves transport DATA
        // only. It cannot validate a Source signature, body or native action.
        let mut original = crate::envelope::tests::request();
        original.method = method;
        original.sequence = U64::new(2);
        original.extensions.clear();
        original.extensions.insert(feature.into(), Value::Null);
        let features = [
            RESTORED_SETTLED_CAPTURE_FEATURE.to_owned(),
            RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.to_owned(),
            PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE.to_owned(),
        ]
        .into_iter()
        .collect();
        let guard = CorrelationGuard::new(
            original.session_id.0.clone().unwrap(),
            original.incarnation_id.0.clone().unwrap(),
            4,
            features,
        )
        .unwrap();
        (guard, original)
    }

    #[test]
    fn each_actual_received_phase_lends_the_same_custody_without_settling_it() {
        for (method, feature) in PHASES {
            let (mut guard, original) = fixture(method, feature);
            assert!(
                guard
                    .authenticate_incoming_capture17_cut_data(&original)
                    .is_err()
            );
            guard.receive(&original).unwrap();
            let retained = guard.incoming_requests().next().unwrap() as *const Envelope;
            let next = guard.next_received;
            let capacity = guard.received_requests.len();

            for _ in 0..32 {
                guard
                    .authenticate_incoming_capture17_cut_data(&original)
                    .unwrap();
            }

            assert_eq!(guard.next_received, next);
            assert_eq!(guard.received_requests.len(), capacity);
            assert_eq!(
                guard.incoming_requests().next().unwrap() as *const Envelope,
                retained
            );
            assert_eq!(guard.incoming_requests().next(), Some(&original));
            assert!(guard.pending_requests().next().is_none());
            assert!(
                guard
                    .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)
                    .is_err()
            );
        }
    }

    #[test]
    fn wrong_method_feature_pair_or_extra_extension_cannot_qualify_a_received_request() {
        for (method, expected) in PHASES {
            for wrong in [
                RESTORED_SETTLED_CAPTURE_FEATURE,
                RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE,
                PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
            ] {
                if wrong == expected {
                    continue;
                }
                let (mut guard, original) = fixture(method, wrong);
                guard.receive(&original).unwrap();

                assert!(!is_native_capture17_original_data(&original));
                assert!(
                    guard
                        .authenticate_incoming_capture17_cut_data(&original)
                        .is_err()
                );
                assert_eq!(guard.incoming_requests().next(), Some(&original));
                assert!(!guard.failed);
            }
        }
        for method in [Method::Observe, Method::Input, Method::Retire] {
            let (mut guard, original) = fixture(method, RESTORED_SETTLED_CAPTURE_FEATURE);
            guard.receive(&original).unwrap();
            assert!(!is_native_capture17_original_data(&original));
            assert!(
                guard
                    .authenticate_incoming_capture17_cut_data(&original)
                    .is_err()
            );
            assert_eq!(guard.incoming_requests().next(), Some(&original));
        }
        let (mut guard, mut original) = fixture(Method::Begin, RESTORED_SETTLED_CAPTURE_FEATURE);
        original
            .extensions
            .insert(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.into(), Value::Null);
        guard.receive(&original).unwrap();
        assert!(!is_native_capture17_original_data(&original));
        assert!(
            guard
                .authenticate_incoming_capture17_cut_data(&original)
                .is_err()
        );
        assert_eq!(guard.incoming_requests().next(), Some(&original));
    }

    #[test]
    fn changed_candidate_or_another_received_request_does_not_replace_the_actual_owner() {
        for changed in 0..6 {
            let (mut guard, original) =
                fixture(Method::BlobBegin, RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE);
            guard.receive(&original).unwrap();
            let mut candidate = original.clone();
            match changed {
                0 => {
                    candidate.body.insert("changed".into(), Value::Bool(true));
                }
                1 => {
                    candidate.sequence = U64::new(u64::MAX);
                }
                2 => {
                    candidate.method = Method::BlobFinish;
                }
                3 => {
                    candidate.node_id.0 = Some(Id::new("another-capture-node").unwrap());
                }
                4 => {
                    candidate.request_id.0 = Some(Id::new("another-capture-request").unwrap());
                }
                _ => {
                    let mut next = original.clone();
                    next.sequence = U64::new(3);
                    next.request_id.0 = Some(Id::new("second-actual-incoming").unwrap());
                    guard.receive(&next).unwrap();
                }
            }

            assert!(
                guard
                    .authenticate_incoming_capture17_cut_data(&candidate)
                    .is_err()
            );
            assert!(guard.incoming_requests().any(|value| value == &original));
            assert!(!guard.failed);
        }
    }

    #[test]
    fn actual_pending_or_partial_response_and_failed_receive_keep_the_original_unqualified() {
        let (mut guard, original) =
            fixture(Method::BlobBegin, RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE);
        guard.receive(&original).unwrap();
        let mut outgoing = original.clone();
        outgoing.request_id.0 = Some(Id::new("actual-provider-outgoing").unwrap());
        guard.register_request(outgoing.clone()).unwrap();
        assert!(
            guard
                .authenticate_incoming_capture17_cut_data(&original)
                .is_err()
        );
        assert_eq!(guard.pending_requests().next(), Some(&outgoing));
        assert_eq!(guard.incoming_requests().next(), Some(&original));

        let (mut guard, original) =
            fixture(Method::BlobBegin, RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE);
        guard.receive(&original).unwrap();
        let mut terminal = original.clone();
        terminal.message = MessageKind::Response;
        guard.register_outgoing(terminal.clone()).unwrap();
        assert!(
            guard
                .authenticate_incoming_capture17_cut_data(&original)
                .is_err()
        );
        assert_eq!(guard.writing_responses.len(), 1);
        assert_eq!(guard.incoming_requests().next(), Some(&original));
        guard.confirm_response_sent(&terminal).unwrap();
        assert!(
            guard
                .authenticate_incoming_capture17_cut_data(&original)
                .is_err()
        );
        assert!(guard.incoming_requests().next().is_none());
        guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)
            .unwrap();

        let (mut guard, original) =
            fixture(Method::BlobBegin, RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE);
        guard.receive(&original).unwrap();
        // The real duplicate receive fences the guard and preserves custody.
        assert!(guard.receive(&original).is_err());
        assert!(guard.failed);
        assert!(
            guard
                .authenticate_incoming_capture17_cut_data(&original)
                .is_err()
        );
        assert_eq!(guard.incoming_requests().next(), Some(&original));
    }

    #[test]
    fn selected_auxiliary_cut_does_not_widen_the_existing_capture_cut() {
        let (mut guard, original) =
            fixture(Method::BlobChunk, RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE);
        guard.receive(&original).unwrap();

        guard
            .authenticate_incoming_capture17_cut_data(&original)
            .unwrap();
        assert!(
            guard
                .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::NativeIncomingCapture)
                .is_err()
        );
        assert!(
            guard
                .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)
                .is_err()
        );
        assert_eq!(guard.incoming_requests().next(), Some(&original));
    }
}
