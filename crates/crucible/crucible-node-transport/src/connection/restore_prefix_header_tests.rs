//! Exercises the selected pretyped filter on actual portable Envelope values.

use super::*;
use crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase as Phase;
use serde_json::Value;

fn original() -> Envelope {
    serde_json::from_value(serde_json::json!({
        "protocol":"CNP/1","message":"request","session_id":"session",
        "incarnation_id":"incarnation","node_id":"node","execution_owner_id":"owner",
        "capture_owner_id":null,"request_id":"commit-id","operation_id":null,
        "sequence":"8","method":"begin","body":{},"extensions":{}
    }))
    .unwrap()
}

#[test]
fn restricted_receive_refuses_unbounded_or_unrelated_body_before_typed_decode() {
    let original = original();
    let mut request = original.clone();
    request.node_id.0 = None;
    request.execution_owner_id.0 = None;
    request.method = Method::BlobChunk;
    request.body=serde_json::json!({"transfer_id":"packet-restore-held-transfer-20","offset":"0","bytes":"YWJj","extensions":{}}).as_object().unwrap().clone();
    authenticate_restore_prefix_header_data(&original, Phase::Commit, 3, &request).unwrap();
    assert!(
        authenticate_restore_prefix_header_data(&original, Phase::Prepare, 3, &request).is_err()
    );
    request
        .body
        .insert("bytes".into(), Value::String("Y".repeat(5)));
    assert!(
        authenticate_restore_prefix_header_data(&original, Phase::Commit, 3, &request).is_err()
    );
    request
        .body
        .insert("bytes".into(), Value::String("YWJj".into()));
    request.body.insert(
        "unknown".into(),
        serde_json::json!([[[["still raw data"]]]]),
    );
    assert!(
        authenticate_restore_prefix_header_data(&original, Phase::Commit, 3, &request).is_err()
    );
    request.body.remove("unknown");
    request.method = Method::Realize;
    assert!(
        authenticate_restore_prefix_header_data(&original, Phase::Commit, 3, &request).is_err()
    );
    request.message = MessageKind::Event;
    assert!(
        authenticate_restore_prefix_header_data(&original, Phase::Commit, 3, &request).is_err()
    );
}
