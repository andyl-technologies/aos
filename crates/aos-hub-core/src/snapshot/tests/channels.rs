//! Closed historical/current channel evidence, without signing or activation.

use super::*;
use serde_json::json;

fn envelope(payload: serde_json::Value) -> String {
    json!({"schema_version":aos_release::receipt::SIGNED_RECEIPT,
        "key_id":"retained-fixture","signature_base64":"retained-signature-shape",
        "payload":payload})
    .to_string()
}

fn historical() -> serde_json::Value {
    json!({"schema_version":"aos.release.channel-receipt/v1","channel":"stable",
        "first_partition":0,"last_partition":255,"prior_generation":0,"new_generation":1,
        "manifest_digest":format!("sha256:{}","a".repeat(64)),
        "production_receipt_digest":format!("sha256:{}","b".repeat(64)),
        "committed_at":"2026-09-30T00:00:00Z"})
}

fn current() -> serde_json::Value {
    let mut payload = historical();
    payload
        .as_object_mut()
        .unwrap()
        .remove("production_receipt_digest");
    payload["channel"] = json!("stable-2026.9");
    payload["destination"] = json!("production/stable-2026.9");
    payload["ring"] = json!(1);
    payload["publication_receipt_digest"] = json!(format!("sha256:{}", "b".repeat(64)));
    payload["surface_kind"] = json!("hub");
    payload["surface_identity"] = json!("fixture-hub");
    payload
}

#[test]
fn copied_old_and_current_channel_receipts_keep_distinct_closed_shapes() {
    let old = envelope(historical());
    let new = envelope(current());

    json::validate_current_release_receipt("release_channel_advances", &old).unwrap();
    json::validate_current_release_receipt("release_channel_advances", &new).unwrap();
    json::validate_private("release_channel_operations", "receipt_json", &old, None).unwrap();
    assert!(
        json::validate_private("release_channel_operations", "receipt_json", &new, None).is_err()
    );

    let mut mixed = current();
    mixed["production_receipt_digest"] = historical()["production_receipt_digest"].clone();
    assert!(
        json::validate_current_release_receipt("release_channel_advances", &envelope(mixed))
            .is_err()
    );
    let mut incomplete = current();
    incomplete
        .as_object_mut()
        .unwrap()
        .remove("publication_receipt_digest");
    assert!(json::validate_current_release_receipt(
        "release_channel_advances",
        &envelope(incomplete)
    )
    .is_err());
}
