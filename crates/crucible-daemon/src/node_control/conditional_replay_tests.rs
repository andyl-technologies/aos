//! Tests the explicit conditional wire mode without issuing replay authority.

// crucible-lint: allow panic-shortcut -- Portable codec and mode-isolation regressions deliberately fail on their first unmet assertion; these records issue no replay authority.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use super::*;

fn request() -> NodeConditionalReplayRequest {
    let reference = canonical::content_ref(b"unqualified test data", "application/json").unwrap();
    NodeConditionalReplayRequest::new(
        "conditional-original".into(), "29292929292929292929292929292929".into(),
        BTreeMap::from([(Id::new("producer").unwrap(), reference.clone()),
            (Id::new("consumer").unwrap(), reference)]),
        br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"150","maximum_rounds":"32"}"#.to_vec(),
    ).unwrap()
}

#[test]
fn conditional_requires_exact_explicit_control_edition_and_preserves_ordinary_bytes() {
    let original =
        NodeControlRequest::conditional_replay("operator/conditional", request()).unwrap();
    assert_eq!(original.version, 5);
    original.validate().unwrap();
    let bytes = canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
    let decoded: NodeControlRequest =
        serde_json::from_value(canonical::parse_json(&bytes, MAX_NODE_CONTROL_BYTES).unwrap())
            .unwrap();
    decoded.validate().unwrap();
    for edition in [1, 2, 3, 4, 6] {
        let mut altered = decoded.clone();
        altered.version = edition;
        assert!(altered.validate().is_err());
    }
    assert!(NodeControlRequest::new("operator/conditional", original.command).is_err());
    let ordinary = NodeControlRequest::new(
        "operator/status",
        NodeControlCommand::Status {
            execution: "29292929292929292929292929292929".into(),
        },
    )
    .unwrap();
    assert_eq!(ordinary.version, 1);
    assert_eq!(canonical::canonical_json(&serde_json::to_value(&ordinary).unwrap()).unwrap(),
        br#"{"command":{"execution":"29292929292929292929292929292929","operation":"status"},"format":"crucible.node-control","request_id":"operator/status","version":1}"#);
}

#[test]
fn conditional_source_roster_and_input_codec_refuse_missing_foreign_fields() {
    let original = request();
    let mut missing = original.clone();
    missing.sources.remove(&Id::new("consumer").unwrap());
    assert!(missing.validate().is_err());
    let mut wrong = original.clone();
    wrong.configuration = Bytes::new(br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"150","maximum_rounds":"32","qualification":true}"#.to_vec());
    assert!(wrong.validate().is_err());
    let mut object = serde_json::to_value(&original).unwrap();
    object["source_signer_key"] = serde_json::json!("caller-authentication");
    assert!(serde_json::from_value::<NodeConditionalReplayRequest>(object).is_err());
    assert!(decode_conditional_replay_sources(br#"{"producer":{},"producer":{}}"#).is_err());
}
