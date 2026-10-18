//! Checks actual assigned-envelope joins without native owners or phase tokens.

use super::shared::*;
use super::*;
use crate::envelope::{MessageKind, Method, Nullable};
use crucible_node_contract::{HashRef, Id, canonical};
use serde_json::{Map, json};

fn original(id: &str, sequence: u64) -> Envelope {
    Envelope {
        protocol: "CNP/1".to_owned(),
        message: MessageKind::Request,
        session_id: Nullable(Some(Id::new("session").unwrap())),
        incarnation_id: Nullable(Some(Id::new("incarnation").unwrap())),
        node_id: Nullable(Some(Id::new("node").unwrap())),
        execution_owner_id: Nullable(Some(Id::new("owner").unwrap())),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(Id::new(id).unwrap())),
        operation_id: Nullable(None),
        sequence: U64::new(sequence),
        method: Method::Observe,
        body: serde_json::from_value(json!({
            "binding_hash":canonical::hash("cnp.owner-binding.v1", b"owner").unwrap(),
            "owner_generation":"1","after_observation_sequence":"0","maximum_items":"1","extensions":{},
        })).unwrap(),
        extensions: Default::default(),
    }
}

fn terminal(original: &Envelope, sequence: u64) -> Envelope {
    let mut terminal = original.clone();
    terminal.message = MessageKind::Response;
    terminal.sequence = U64::new(sequence);
    terminal.body = serde_json::from_value(json!({
        "status":"completed","operation_state":"completed","extensions":{},
        "result":{"observations":[],"next_sequence":"0","complete":true,
            "inventory_hash":canonical::hash("source-owned.packet-inventory.v1", b"inventory").unwrap()},
    })).unwrap();
    terminal
}

#[test]
fn chronology_compares_each_real_direction_and_rejects_duplicate_originals() {
    let first = original("first", 40);
    let first_terminal = terminal(&first, 7);
    let second = original("second", 41);
    let second_terminal = terminal(&second, 8);
    let a = HistoricalCompletedPair17 {
        original: &first,
        terminal: &first_terminal,
    };
    let b = HistoricalCompletedPair17 {
        original: &second,
        terminal: &second_terminal,
    };

    completed_pair(a, Method::Observe, 65536).unwrap();
    completed_pair(b, Method::Observe, 65536).unwrap();
    follows(a, b).unwrap();
    assert!(follows(b, a).is_err());
    let mut reused = second.clone();
    reused.request_id = first.request_id.clone();
    assert!(
        follows(
            a,
            HistoricalCompletedPair17 {
                original: &reused,
                terminal: &second_terminal
            }
        )
        .is_err()
    );
    let mut reordered = second_terminal.clone();
    reordered.sequence = first_terminal.sequence;
    assert!(
        follows(
            a,
            HistoricalCompletedPair17 {
                original: &second,
                terminal: &reordered
            }
        )
        .is_err()
    );
}

#[test]
fn a_completed_label_cannot_replace_real_correlation_or_typed_body() {
    let request = original("observe", 1);
    let response = terminal(&request, 1);
    let mut altered = response.clone();
    altered.request_id = Nullable(Some(Id::new("another-request").unwrap()));
    assert!(
        completed_pair(
            HistoricalCompletedPair17 {
                original: &request,
                terminal: &altered
            },
            Method::Observe,
            65536
        )
        .is_err()
    );

    let mut altered = response.clone();
    altered.body.insert(
        "operation_state".to_owned(),
        Value::String("running".to_owned()),
    );
    assert!(
        completed_pair(
            HistoricalCompletedPair17 {
                original: &request,
                terminal: &altered
            },
            Method::Observe,
            65536
        )
        .is_err()
    );
    let mut altered = response;
    altered
        .body
        .get_mut("result")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), Value::Bool(true));
    assert!(
        completed_pair(
            HistoricalCompletedPair17 {
                original: &request,
                terminal: &altered
            },
            Method::Observe,
            65536
        )
        .is_err()
    );
}

#[test]
fn literal_hello_binding_includes_length_header_and_every_payload_byte() {
    let mut literal = Vec::new();
    literal.extend_from_slice(&3u32.to_be_bytes());
    literal.extend_from_slice(b"abc");
    let first = hello_digest(&literal, 3).unwrap();
    literal[6] = b'd';
    assert_ne!(first, hello_digest(&literal, 3).unwrap());
    assert!(hello_digest(&literal, 2).is_err());
    literal[3] = 4;
    assert!(hello_digest(&literal, 4).is_err());
}

#[test]
fn full_typed_extension_join_refuses_unknown_members_and_canonical_reference_changes() {
    let value: HashRef = canonical::hash("cnp.owner-binding.v1", b"actual").unwrap();
    let mut request = original("extension", 1);
    request.extensions.insert(
        "actual-extension".to_owned(),
        serde_json::to_value(&value).unwrap(),
    );
    extension(&request, "actual-extension", &value, 65536).unwrap();
    request
        .extensions
        .get_mut("actual-extension")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), Value::Bool(true));
    assert!(extension(&request, "actual-extension", &value, 65536).is_err());

    let bytes = canonical_bytes(&value, 65536).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    verify_reference(&reference, &value, 65536).unwrap();
    let changed = Map::from_iter([("different".to_owned(), Value::Bool(true))]);
    assert!(verify_reference(&reference, &changed, 65536).is_err());
}
