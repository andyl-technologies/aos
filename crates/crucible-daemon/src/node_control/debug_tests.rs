//! Preserves literal earlier control statuses and refuses packet-driven upgrade.

// crucible-lint: allow panic-shortcut -- Literal wire and edition guards deliberately panic on mismatch.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_node_contract::canonical;

#[test]
fn earlier_status_bytes_remain_exact_and_debug_requires_explicit_eight() {
    let execution = "29292929292929292929292929292929";
    for (version, command, operation) in [
        (
            1,
            NodeControlCommand::Status {
                execution: execution.into(),
            },
            "status",
        ),
        (
            5,
            NodeControlCommand::ConditionalReplayStatus {
                execution: execution.into(),
            },
            "conditional_replay_status",
        ),
        (
            7,
            NodeControlCommand::CapabilityPreparationStatus {
                execution: execution.into(),
            },
            "capability_preparation_status",
        ),
    ] {
        let request = NodeControlRequest {
            format: "crucible.node-control".into(),
            version,
            request_id: Id::new("legacy/status").unwrap(),
            command,
        };
        request.validate().unwrap();
        let bytes = canonical::canonical_json(&serde_json::to_value(request).unwrap()).unwrap();
        let literal = format!(
            "{{\"command\":{{\"execution\":\"{execution}\",\"operation\":\"{operation}\"}},\"format\":\"crucible.node-control\",\"request_id\":\"legacy/status\",\"version\":{version}}}"
        );
        assert_eq!(bytes, literal.as_bytes());
    }

    let mut debug = NodeControlRequest::debug_status("debug/status", execution.into()).unwrap();
    for legacy in 1..=7 {
        debug.version = legacy;
        assert!(debug.validate().is_err());
    }
    debug.version = 8;
    assert!(debug.validate().is_ok());
    let bytes = canonical::canonical_json(&serde_json::to_value(debug).unwrap()).unwrap();
    assert_eq!(bytes, br#"{"command":{"execution":"29292929292929292929292929292929","operation":"debug_status"},"format":"crucible.node-control","request_id":"debug/status","version":8}"#);
}
