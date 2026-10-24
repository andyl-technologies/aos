//! Exercises strict original delivery joins without source or live authority.

// crucible-lint: allow panic-shortcut -- These parser tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use serde_json::{Value, json};

fn hex(body: &[u8]) -> String {
    Sha256::digest(body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn packet() -> Value {
    json!({
        "kind":"writer_final_debits", "schema":"crucible.dmtcp.capture-writer-final.v3",
        "capture":"capture-1", "checkpoint_status":"1", "native_finalized":true,
        "native_account_bytes":"4096", "request_projection_sha256":hex(br#"{"capture":"capture-1","kind":"capture"}"#),
        "earlier_history_sha256":hex(b"old"),
        "history_media_type":"application/vnd.crucible.dmtcp-writer-history.v1",
        "history_length":"3", "history_sha256":hex(b"new"), "history_base64":"bmV3",
        "terminal_park_media_type":"application/vnd.crucible.dmtcp-terminal-control-park.v1",
        "terminal_park_length":"64", "terminal_park_sha256":hex(&[0;64]),
        "terminal_park_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        "native_exchange_sha256":hex(b"exchange"), "control_history_sha256":hex(b"control"),
        "original_role_frames":"2"
    })
}

fn check(body: &[u8]) -> Result<OriginalWriterDelivery<'_>, &'static str> {
    OriginalWriterDelivery::parse(
        body,
        "capture-1",
        b"old",
        b"new",
        b"exchange",
        b"control",
        &[0; 64],
    )
}

#[test]
fn complete_original_delivery_is_borrowed() {
    let body = serde_json::to_vec(&packet()).unwrap();
    let parsed = check(&body).unwrap();

    assert_eq!(parsed.body().as_ptr(), body.as_ptr());
    assert_eq!(parsed.native_account_bytes(), 4096);
}

#[test]
fn foreign_capture_status_finalization_and_sizes_refuse() {
    for (field, value) in [
        ("capture", json!("foreign")),
        ("checkpoint_status", json!("2")),
        ("native_finalized", json!(false)),
        ("native_account_bytes", json!("0")),
        ("native_account_bytes", json!("08388608")),
        ("native_account_bytes", json!("8388609")),
        ("history_length", json!("2")),
        ("original_role_frames", json!("3")),
    ] {
        let mut original = packet();
        original[field] = value;
        let body = serde_json::to_vec(&original).unwrap();

        assert!(check(&body).is_err(), "{field}");
    }
}

#[test]
fn full_body_associations_cannot_be_replaced_by_labels() {
    for field in [
        "history_sha256",
        "earlier_history_sha256",
        "native_exchange_sha256",
        "control_history_sha256",
        "terminal_park_sha256",
        "request_projection_sha256",
    ] {
        let mut original = packet();
        original[field] = json!(hex(b"foreign"));
        let body = serde_json::to_vec(&original).unwrap();

        assert!(check(&body).is_err(), "{field}");
    }
}

#[test]
fn duplicate_unknown_and_truncated_json_refuse() {
    let body = serde_json::to_vec(&packet()).unwrap();
    let mut duplicate = body.clone();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"capture\":\"capture-1\"}");
    let mut unknown = packet();
    unknown["adopted"] = json!(true);

    assert!(check(&duplicate).is_err());
    assert!(check(&serde_json::to_vec(&unknown).unwrap()).is_err());
    assert!(check(&body[..body.len() - 1]).is_err());
}

#[test]
fn streaming_base64_requires_canonical_padding_and_bytes() {
    for (raw, encoded) in [
        (b"".as_slice(), ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
    ] {
        assert!(base64_matches(raw, encoded));
    }
    for (raw, encoded) in [
        (b"f".as_slice(), "Zh=="),
        (b"fo", "Zm9="),
        (b"foo", "Zm9v="),
        (b"new", "b2xk"),
    ] {
        assert!(!base64_matches(raw, encoded));
    }
}
