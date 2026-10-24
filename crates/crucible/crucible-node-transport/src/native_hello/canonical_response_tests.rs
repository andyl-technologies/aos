//! Checks the borrowed envelope codec against the complete original JCS codec.

use super::*;
use crate::envelope::{MessageKind, Method};
use serde_json::{Map, Value, json};

fn response() -> Envelope {
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Response,
        session_id: Nullable(None),
        incarnation_id: Nullable(Some(Id::new("original-incarnation").unwrap())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(Id::new("original-request").unwrap())),
        operation_id: Nullable(None),
        sequence: U64::new(1),
        method: Method::Hello,
        body: Map::new(),
        extensions: crucible_node_format::Extensions::new(),
    }
}

#[test]
fn borrowed_response_matches_the_complete_envelope_without_a_second_dom() {
    let mut response = response();
    response.body.insert(
        "\u{10000}".into(),
        json!({"array": [1e30, null, "\n\u{0}"]}),
    );
    response
        .body
        .insert("\u{e000}".into(), json!({"flag": true}));
    response.extensions.insert(
        "cnp.extension_negotiation.v1".into(),
        json!({"format": "1", "selected": []}),
    );
    let expected = canonical::canonical_json(&serde_json::to_value(&response).unwrap()).unwrap();
    let mut actual = Vec::new();

    write_response_data(&response, &mut actual).unwrap();

    assert_eq!(actual, expected);
}

#[test]
fn every_header_and_nesting_boundary_preserves_the_original_envelope_codec() {
    let mut response = response();
    let present = Nullable(Some(Id::new("same-header").unwrap()));
    response.session_id = present.clone();
    response.node_id = present.clone();
    response.execution_owner_id = present.clone();
    response.capture_owner_id = present.clone();
    response.operation_id = present;
    response.sequence = U64::new(u64::MAX);
    let expected = canonical::canonical_json(&serde_json::to_value(&response).unwrap()).unwrap();
    let mut actual = Vec::new();
    write_response_data(&response, &mut actual).unwrap();
    assert_eq!(actual, expected);

    for containers in [0, 61, 62, 63, 64] {
        let mut value = Value::Null;
        for _ in 0..containers {
            value = json!({"child": value});
        }
        response.body.insert("nested".into(), value);
        let expected = canonical::canonical_json(&serde_json::to_value(&response).unwrap());
        let mut actual = Vec::new();
        let outcome = write_response_data(&response, &mut actual);
        assert_eq!(outcome.is_ok(), expected.is_ok());
        if let Ok(expected) = expected {
            assert_eq!(actual, expected);
        }
    }
}
