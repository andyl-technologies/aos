//! Exercises actual SDK custody moves independently of Source signing authority.

use super::*;
use crate::envelope::Nullable;
use crucible_node_format::U64;
use serde_json::json;

fn original() -> Envelope {
    let mut original = crate::envelope::tests::request();
    original.method = Method::NativeImport18Bootstrap;
    original.sequence = U64::new(2);
    original.node_id = Nullable(None);
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(None);
    original.operation_id = Nullable(None);
    // Correlation alone deliberately does not interpret this DATA as a signed
    // profile request. The defining exchange must validate the closed DTO first.
    original.body =
        serde_json::from_value(json!({"retained": "actual pending allocation"})).unwrap();
    original.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        json!({"unverified": true}),
    );
    original
}

fn pending(original: &Envelope) -> CorrelationGuard {
    let mut guard = CorrelationGuard::new(
        original.session_id.0.clone().unwrap(),
        original.incarnation_id.0.clone().unwrap(),
        2,
        BTreeSet::from([
            NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
            NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(),
        ]),
    )
    .unwrap();
    guard.register_request(original.clone()).unwrap();
    guard
}

fn response(original: &Envelope) -> Envelope {
    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.extensions.clear();
    response.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(),
        json!({"unverified": true}),
    );
    response.body = serde_json::from_value(json!({"unverified": true})).unwrap();
    response
}

fn retained_text_pointer(envelope: &Envelope) -> *const u8 {
    envelope.body["retained"].as_str().unwrap().as_ptr()
}

#[test]
fn source_bootstrap_settlement_moves_the_actual_pending_allocation_once() {
    let original = original();
    let response = response(&original);
    let mut guard = pending(&original);
    let pending_pointer = retained_text_pointer(guard.pending_requests().next().unwrap());
    assert_ne!(pending_pointer, retained_text_pointer(&original));
    guard.original_bootstrap_pending_data(&original).unwrap();

    let mut retained = None;
    guard
        .original_bootstrap_receive_into_data(&original, &response, &mut retained)
        .unwrap();

    let retained = retained.as_ref().unwrap();
    assert_eq!(retained, &original);
    assert_eq!(retained_text_pointer(retained), pending_pointer);
    assert_eq!((guard.next_received, guard.next_sent), (3, 3));
    assert_eq!(guard.pending_requests().count(), 0);
    guard
        .original_bootstrap_received_data(retained, &response)
        .unwrap();
    assert!(guard.original_bootstrap_pending_data(&original).is_err());

    let mut duplicate = None;
    assert!(
        guard
            .original_bootstrap_receive_into_data(&original, &response, &mut duplicate)
            .is_err()
    );
    assert!(guard.failed && duplicate.is_none());
    assert_eq!(retained_text_pointer(retained), pending_pointer);
    assert!(
        guard
            .original_bootstrap_received_data(retained, &response)
            .is_err()
    );
}

#[test]
fn refused_source_bootstrap_headers_keep_the_original_and_fence_retry() {
    let original = original();
    for fault in 0..12 {
        let mut guard = pending(&original);
        let pending_pointer = retained_text_pointer(guard.pending_requests().next().unwrap());
        let mut response = response(&original);
        match fault {
            0 => response.protocol = "CNP/2".into(),
            1 => response.session_id = Nullable(Some(Id::new("foreign-session").unwrap())),
            2 => response.incarnation_id = Nullable(Some(Id::new("foreign-incarnation").unwrap())),
            3 => response.request_id = Nullable(Some(Id::new("foreign-request").unwrap())),
            4 => response.sequence = U64::new(3),
            5 => response.method = Method::Admit,
            6 => response.message = MessageKind::Request,
            7 => response.node_id = Nullable(Some(Id::new("foreign-node").unwrap())),
            8 => {
                response.execution_owner_id = Nullable(Some(Id::new("foreign-execution").unwrap()))
            }
            9 => response.capture_owner_id = Nullable(Some(Id::new("foreign-capture").unwrap())),
            10 => response.operation_id = Nullable(Some(Id::new("foreign-operation").unwrap())),
            11 => {
                response
                    .extensions
                    .insert("foreign-extension".into(), json!({}));
            }
            _ => unreachable!(),
        }
        let mut retained = None;

        assert!(
            guard
                .original_bootstrap_receive_into_data(&original, &response, &mut retained)
                .is_err(),
            "fault {fault}"
        );

        assert!(guard.failed && retained.is_none(), "fault {fault}");
        assert_eq!((guard.next_received, guard.next_sent), (2, 3));
        assert_eq!(guard.pending_requests().count(), 1);
        assert_eq!(
            retained_text_pointer(guard.pending_requests().next().unwrap()),
            pending_pointer
        );
        let corrected = self::response(&original);
        assert!(
            guard
                .original_bootstrap_receive_into_data(&original, &corrected, &mut retained)
                .is_err()
        );
    }
}

#[test]
fn occupied_source_destination_preserves_both_owners_without_receiving() {
    let original = original();
    let response = response(&original);
    let mut guard = pending(&original);
    let pending_pointer = retained_text_pointer(guard.pending_requests().next().unwrap());
    let mut retained = Some(original.clone());
    let retained_pointer = retained_text_pointer(retained.as_ref().unwrap());

    assert!(
        guard
            .original_bootstrap_receive_into_data(&original, &response, &mut retained)
            .is_err()
    );

    assert!(!guard.failed);
    assert_eq!((guard.next_received, guard.next_sent), (2, 3));
    assert_eq!(
        retained_text_pointer(retained.as_ref().unwrap()),
        retained_pointer
    );
    assert_eq!(
        retained_text_pointer(guard.pending_requests().next().unwrap()),
        pending_pointer
    );
    guard.original_bootstrap_pending_data(&original).unwrap();
}

#[test]
fn source_settlement_refuses_changed_original_and_unrelated_sdk_traffic() {
    let original = original();
    let response = response(&original);
    for fault in 0..6 {
        let mut guard = pending(&original);
        let mut offered = original.clone();
        match fault {
            0 => {
                offered.body.insert("changed".into(), json!(true));
            }
            1 => {
                guard.continuation_installed = true;
            }
            2 => {
                let mut second = original.clone();
                second.request_id = Nullable(Some(Id::new("second-original").unwrap()));
                second.sequence = U64::new(3);
                guard.register_request(second).unwrap();
            }
            3 => {
                guard
                    .received_requests
                    .insert(Id::new("other-incoming").unwrap(), original.clone());
            }
            4 => {
                guard
                    .writing_responses
                    .insert(Id::new("other-writing").unwrap(), response.clone());
            }
            5 => {
                guard.pending.clear();
            }
            _ => unreachable!(),
        }
        let expected_pending = guard.pending.len();
        let mut retained = None;

        assert!(
            guard
                .original_bootstrap_receive_into_data(&offered, &response, &mut retained)
                .is_err(),
            "fault {fault}"
        );

        assert!(guard.failed && retained.is_none());
        assert_eq!(guard.pending.len(), expected_pending);
        assert_eq!(guard.next_received, 2);
    }
}

#[test]
fn matching_node_or_owner_routes_cannot_turn_bootstrap_into_a_native_phase() {
    for fault in 0..5 {
        let mut original = original();
        let routed = Nullable(Some(Id::new("matching-concrete-route").unwrap()));
        match fault {
            0 => original.node_id = routed,
            1 => original.execution_owner_id = routed,
            2 => original.capture_owner_id = routed,
            3 => original.operation_id = routed,
            4 => original.method = Method::Admit,
            _ => unreachable!(),
        }
        let response = response(&original);
        let mut guard = pending(&original);
        let mut retained = None;
        assert!(
            guard
                .original_bootstrap_receive_into_data(&original, &response, &mut retained)
                .is_err(),
            "fault {fault}"
        );
        assert!(guard.failed && retained.is_none());
        assert_eq!(guard.pending_requests().next(), Some(&original));
    }
}

#[test]
fn bootstrap_transport_requires_its_distinct_negotiated_extension_positions() {
    for fault in 0..6 {
        let mut original = original();
        let mut response = response(&original);
        match fault {
            0 => original.extensions.clear(),
            1 => {
                original.extensions.clear();
                original
                    .extensions
                    .insert(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(), json!({}));
            }
            2 => response.extensions.clear(),
            3 => {
                response.extensions.clear();
                response
                    .extensions
                    .insert(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(), json!({}));
            }
            4 => {
                original
                    .extensions
                    .insert(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(), json!({}));
            }
            5 => {
                response
                    .extensions
                    .insert(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(), json!({}));
            }
            _ => unreachable!(),
        }
        let mut guard = pending(&original);
        let mut retained = None;

        assert!(
            guard
                .original_bootstrap_receive_into_data(&original, &response, &mut retained)
                .is_err(),
            "fault {fault}"
        );

        assert!(guard.failed && retained.is_none());
        assert_eq!(guard.pending_requests().next(), Some(&original));
        assert_eq!((guard.next_received, guard.next_sent), (2, 3));
    }
}
