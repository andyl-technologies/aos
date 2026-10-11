//! Component-only failure custody and privacy checks for finite observations.
//!
//! Synthetic archive rows exercise bookkeeping; they are not wire evidence or
//! connection authority. Actual send/read coverage lives in client_reference.

// crucible-lint: allow panic-shortcut -- Invalid observation bookkeeping deliberately fails component assertions.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::Extensions;
use serde_json::{Map, json};

use super::*;
use crate::envelope::{MessageKind, Nullable};

fn envelope() -> Envelope {
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Response,
        session_id: Nullable(Some(Id::new("component-session").unwrap())),
        incarnation_id: Nullable(Some(Id::new("component-incarnation").unwrap())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(Id::new("component-original").unwrap())),
        operation_id: Nullable(None),
        sequence: U64::new(9),
        method: crate::envelope::Method::Discover,
        body: Map::new(),
        extensions: Extensions::new(),
    }
}

fn attempt(response_credit: usize) -> (TransmissionAttempt, TransmissionObservationHandle) {
    let mut request = envelope();
    request.message = MessageKind::Request;
    request.sequence = U64::new(7);
    let bytes = encode(&request).unwrap();
    let length = bytes.len();
    let archive = Arc::new(Mutex::new(Archive {
        scope: Scope {
            session: Id::new("component-session").unwrap(),
            incarnation: Id::new("component-incarnation").unwrap(),
            connection: Id::new("component-connection").unwrap(),
        },
        rows: vec![Row {
            transmission: U64::new(1),
            origin: RequestOrigin::Controller,
            request_id: request.request_id.0.clone().unwrap(),
            identity: request.request_hash(RequestOrigin::Controller).unwrap(),
            sent_sequence: request.sequence,
            write_completed: false,
            semantic_response_verified: false,
            request_start: 0,
            request_length: length,
            received: None,
        }],
        bytes,
        maximum_transmissions: 1,
        maximum_bytes: 4096,
        reserved_bytes: length + response_credit,
        incomplete: false,
    }));
    (
        TransmissionAttempt {
            private_token: Bytes::new(vec![7; 32]),
            archive: archive.clone(),
            index: 0,
            response_credit,
            completed: false,
        },
        TransmissionObservationHandle { archive },
    )
}

#[test]
fn response_without_completed_write_cannot_be_a_successful_transmission() {
    let (mut attempt, handle) = attempt(2048);
    attempt.received(&envelope()).unwrap();
    assert!(attempt.completed().is_err());
    drop(attempt);
    let snapshot = handle.snapshot(4096).unwrap();
    assert!(snapshot.incomplete);
    assert!(!snapshot.rows[0].write_completed);
    assert!(!snapshot.rows[0].semantic_response_verified);
}

#[test]
fn privacy_failure_retains_attempt_without_exporting_actual_private_response() {
    for body in [
        json!({"nested":{"admission_token":"excluded"}}),
        json!({"opaque":Bytes::new(vec![7;32])}),
    ] {
        let (mut attempt, handle) = attempt(2048);
        let mut response = envelope();
        response.body = body.as_object().unwrap().clone();
        attempt.sent().unwrap();
        assert!(attempt.received(&response).is_err());
        drop(attempt);
        let snapshot = handle.snapshot(4096).unwrap();
        assert!(snapshot.incomplete);
        assert!(snapshot.rows[0].write_completed);
        assert!(snapshot.rows[0].received.is_none());
        assert_eq!(
            snapshot.bytes.as_slice().len(),
            snapshot.rows[0].request_length
        );
    }
}

#[test]
fn over_credit_response_never_replaces_retained_original_bytes() {
    let (mut attempt, handle) = attempt(1);
    let before = handle.snapshot(4096).unwrap().bytes;
    attempt.sent().unwrap();
    assert!(matches!(
        attempt.received(&envelope()),
        Err(ProviderError::ResourceExhausted(_))
    ));
    drop(attempt);
    let after = handle.snapshot(4096).unwrap();
    assert!(after.incomplete);
    assert_eq!(after.bytes, before);
    assert!(after.rows[0].received.is_none());
}

#[test]
fn unwind_keeps_the_exact_attempt_and_sticky_incompleteness() {
    let (mut attempt, handle) = attempt(2048);
    let before = handle.snapshot(4096).unwrap().bytes;
    let failed = std::panic::catch_unwind(move || {
        attempt.sent().unwrap();
        panic!("modeled post-write unwind");
    });
    assert!(failed.is_err());
    let after = handle.snapshot(4096).unwrap();
    assert!(after.incomplete);
    assert_eq!(after.bytes, before);
    assert!(after.rows[0].write_completed);
    assert!(!after.rows[0].semantic_response_verified);
    assert!(
        handle
            .snapshot(before.as_slice().len().saturating_sub(1))
            .is_err()
    );
}
