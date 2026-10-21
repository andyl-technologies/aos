//! Cross-checks generated Distribution codecs against fixed wire and JSON values.
//!
//! These checks establish encoding compatibility, not content or ref authority.

#![allow(clippy::unwrap_used, reason = "Fixture failures intentionally panic.")]

#[path = "wire_contract/refs.rs"]
mod refs;
#[path = "wire_contract/status.rs"]
mod status;

use buffa::Message;
use serde_json::json;
use terrane_sdk::wire::{DESCRIPTOR_SET, v1::*};

#[test]
fn stable_field_numbers_preserve_complete_ref_records() {
    let record = RefValue {
        commit: Hash {
            value: vec![7; 32],
            ..Default::default()
        }
        .into(),
        sequence: 150,
        writer_epoch: 9,
        profile: "p".into(),
        canonical_ref_record: vec![0xa1, 0x01, 0x02],
        ..Default::default()
    };
    let mut expected = vec![0x0a, 34, 0x0a, 32];
    expected.extend([7; 32]);
    expected.extend([
        0x10, 0x96, 0x01, 0x18, 9, 0x22, 1, b'p', 0x2a, 3, 0xa1, 1, 2,
    ]);
    assert_eq!(record.encode_to_vec(), expected);
    let decoded = RefValue::decode_from_slice(&expected).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.canonical_ref_record, [0xa1, 1, 2]);
}

#[test]
fn protojson_preserves_uint64_bytes_aliases_and_defaults() {
    let record = RefValue {
        sequence: u64::MAX,
        writer_epoch: 100,
        canonical_ref_record: vec![0xff, 0],
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(&record).unwrap(),
        json!({
            "sequence": "18446744073709551615", "writerEpoch": "100",
            "canonicalRefRecord": "/wA="
        })
    );
    let decoded: RefValue = serde_json::from_value(json!({
        "sequence": "18446744073709551615", "writer_epoch": "1e2",
        "canonical_ref_record": "_wA"
    }))
    .unwrap();
    assert_eq!(decoded, record);
    assert_eq!(
        serde_json::to_value(RefValue::default()).unwrap(),
        json!({})
    );
    for number in ["18446744073709551616", "-1", "1.5"] {
        assert!(serde_json::from_value::<RefValue>(json!({"sequence":number})).is_err());
    }
}

#[test]
fn unknown_wire_fields_and_open_enum_numbers_survive_roundtrip() {
    let encoded = [0x10, 0x7b, 0x98, 0x06, 0x01];
    let request = GetRefRequest::decode_from_slice(&encoded).unwrap();
    assert_eq!(request.freshness.to_i32(), 123);
    assert_eq!(request.encode_to_vec(), encoded);
    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json, json!({"freshness":123}));
    let decoded: GetRefRequest = serde_json::from_value(json).unwrap();
    assert_eq!(decoded.freshness.to_i32(), 123);
}

#[test]
fn unknown_json_fields_are_ignored_and_null_is_unset() {
    let value: GetRefRequest = serde_json::from_value(json!({
        "name": "refs/heads/main", "boundMs": null, "freshness": null,
        "futureExtension": {"nested": [1, 2, 3]}
    }))
    .unwrap();
    assert_eq!(value.name, "refs/heads/main");
    assert_eq!(value.bound_ms, 0);
    assert_eq!(value.freshness.to_i32(), 0);
    assert!(serde_json::from_str::<GetRefRequest>(r#"{"boundMs":1,"bound_ms":2}"#).is_err());
}

#[test]
fn oneof_frames_reject_ambiguous_json_and_keep_binary_tags() {
    let body: PutPackFrame = serde_json::from_value(json!({"body":"YWJj"})).unwrap();
    assert_eq!(body.encode_to_vec(), [0x12, 3, b'a', b'b', b'c']);
    assert!(serde_json::from_value::<PutPackFrame>(json!({"header":{},"body":"YWJj"})).is_err());
    let absent: CompareAndSwapRefRequest = serde_json::from_value(json!({"absent":true})).unwrap();
    assert_eq!(absent.encode_to_vec(), [0x18, 1]);
    assert!(
        serde_json::from_value::<CompareAndSwapRefRequest>(json!({"absent":true,"expected":{}}))
            .is_err()
    );
}

#[test]
fn well_known_time_types_use_canonical_protojson() {
    let span: Span =
        serde_json::from_value(json!({"expires":"1970-01-01T00:00:01.000000001Z"})).unwrap();
    assert_eq!(span.expires.seconds, 1);
    assert_eq!(span.expires.nanos, 1);
    assert_eq!(
        serde_json::to_value(span).unwrap(),
        json!({"expires":"1970-01-01T00:00:01.000000001Z"})
    );
    let error: ErrorInfo =
        serde_json::from_value(json!({"retryAfter":"1.250s","retryable":true})).unwrap();
    assert_eq!(error.retry_after.seconds, 1);
    assert_eq!(error.retry_after.nanos, 250_000_000);
    assert_eq!(
        serde_json::to_value(error).unwrap(),
        json!({"retryAfter":"1.250s","retryable":true})
    );
    assert!(serde_json::from_value::<Span>(json!({"expires":"not-a-timestamp"})).is_err());
}

#[test]
fn independent_descriptor_decoder_retains_service_shapes_and_record_fields() {
    let descriptor =
        <prost_types::FileDescriptorSet as prost::Message>::decode(DESCRIPTOR_SET).unwrap();
    let package: Vec<_> = descriptor
        .file
        .iter()
        .filter(|file| file.package.as_deref() == Some("terrane.v1"))
        .collect();
    assert_eq!(package.len(), 1);
    let file = package[0];
    assert_eq!(file.syntax.as_deref(), Some("proto3"));
    let methods: Vec<_> = file
        .service
        .iter()
        .flat_map(|service| {
            service.method.iter().map(move |method| {
                (
                    service.name.as_deref().unwrap(),
                    method.name.as_deref().unwrap(),
                    method.client_streaming.unwrap_or(false),
                    method.server_streaming.unwrap_or(false),
                )
            })
        })
        .collect();
    assert_eq!(
        methods,
        [
            ("ContentService", "Negotiate", false, false),
            ("ContentService", "Has", false, false),
            ("ContentService", "PutPack", true, false),
            ("ContentService", "GetRange", false, true),
            ("ContentService", "PresignRead", false, false),
            ("ContentService", "GetBundle", false, true),
            ("ContentService", "GetFilter", false, true),
            ("ContentService", "GetIndex", false, true),
            ("RefService", "GetRef", false, false),
            ("RefService", "CompareAndSwapRef", false, false),
            ("RefService", "GetRefLog", false, true),
            ("RefService", "WatchRefs", false, true),
            ("RefService", "ListRefs", false, true),
            ("TierService", "Capabilities", false, false),
            ("TierService", "Residency", false, false),
            ("TierService", "Where", false, false),
            ("TierService", "Warm", false, false),
            ("TierService", "Costs", false, false),
        ]
    );
    for (message, field, tag) in [
        ("RefValue", "canonical_ref_record", 5),
        ("RefLogEntry", "canonical_ref_log_record", 6),
    ] {
        let definition = file
            .message_type
            .iter()
            .find(|value| value.name.as_deref() == Some(message))
            .unwrap();
        assert!(
            definition
                .field
                .iter()
                .any(|value| value.name.as_deref() == Some(field) && value.number == Some(tag))
        );
    }
}
