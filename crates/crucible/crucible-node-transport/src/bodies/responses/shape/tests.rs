//! Compares the live branch decoder with the preceding tagged-enum path.

use super::*;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn compare(body: &Map<String, Value>) -> TestResult {
    let before = serde_json::to_vec(body)?;
    match (decode_response_shape(body), object::<ResponseShape>(body)) {
        (Ok(actual), Ok(expected)) => {
            assert_eq!(actual, expected);
            assert_eq!(serde_json::to_vec(&actual)?, serde_json::to_vec(&expected)?);
        }
        (Err(actual), Err(expected)) => assert_eq!(actual.to_string(), expected.to_string()),
        _ => panic!("live response decoding changed the preceding closed schema"),
    }
    assert_eq!(serde_json::to_vec(body)?, before);
    Ok(())
}

fn map(value: Value) -> Map<String, Value> {
    let Value::Object(body) = value else {
        panic!("response body fixture")
    };
    body
}

fn details() -> Value {
    json!({
        "nested": [null, false, true, -0.0, 1e-7, 1e20, u64::MAX],
        "\u{10000}": "雪\n\"\\",
        "\u{e000}": {"$serde_json::private::Number":"123"}
    })
}

#[test]
fn all_live_statuses_preserve_owned_fields_and_feature_sensitive_values() -> TestResult {
    for payload in [
        details(),
        json!({"$serde_json::private::RawValue":"ordinary DATA"}),
        json!({"$serde_json::private::RawValue":"{\"nested\":true}"}),
        json!({"$serde_json::private::Number":"123"}),
        json!({"dense":vec![0;4096]}),
    ] {
        for (status, state) in [("accepted", "running"), ("completed", "completed")] {
            compare(&map(json!({
                "status":status, "operation_state":state,
                "result":payload, "extensions":{}
            })))?;
        }
        compare(&map(json!({
            "status":"error", "operation_state":"not_started",
            "error":{
                "code":"RESOURCE_EXHAUSTED", "message":"bounded refusal",
                "effect":"not_started", "retryable":true, "details":payload
            }, "extensions":{}
        })))?;
    }

    let mut body = map(json!({
        "status":"completed", "operation_state":"completed",
        "result":details(), "extensions":{}
    }));
    let decoded = decode_response_shape(&body)?;
    let expected = serde_json::to_vec(&decoded)?;
    body.insert("result".into(), Value::Null);
    drop(body);

    assert_eq!(serde_json::to_vec(&decoded)?, expected);
    assert!(response_shape_decode_counter_scratch_data() > 0);
    Ok(())
}

#[test]
fn malformed_status_missing_fields_and_cross_variant_fields_keep_original_refusals() -> TestResult {
    let accepted = map(json!({
        "status":"accepted", "operation_state":"running", "result":{}, "extensions":{}
    }));
    let completed = map(json!({
        "status":"completed", "operation_state":"completed", "result":{}, "extensions":{}
    }));
    let error = map(json!({
        "status":"error", "operation_state":"not_started",
        "error":{
            "code":"RESOURCE_EXHAUSTED", "message":"bounded refusal",
            "effect":"not_started", "retryable":false, "details":{}
        }, "extensions":{}
    }));
    for original in [accepted, completed, error] {
        for key in original.keys() {
            let mut body = original.clone();
            body.remove(key);
            compare(&body)?;
        }
        for status in [
            Value::Null,
            json!(false),
            json!(7),
            json!([]),
            json!({}),
            json!({"accepted":null}),
            json!({"completed":null}),
            json!({"error":null}),
            json!("unknown"),
        ] {
            let mut body = original.clone();
            body.insert("status".into(), status);
            compare(&body)?;
        }
        for (key, value) in [
            ("unknown", Value::Null),
            ("operation_state", json!("unknown")),
            ("operation_state", json!("running")),
            ("operation_state", Value::Null),
            ("extensions", Value::Null),
            ("result", Value::Null),
            ("error", Value::Null),
        ] {
            let mut body = original.clone();
            body.insert(key.into(), value);
            compare(&body)?;
        }
    }
    Ok(())
}

#[test]
fn live_shape_keeps_the_original_canonical_depth_and_body_byte_limits() -> TestResult {
    let mut nested = Value::Null;
    for _ in 0..63 {
        nested = Value::Array(vec![nested]);
    }
    for payload in [
        json!({"nested":nested}),
        json!({"text":"x".repeat(16_777_216)}),
    ] {
        compare(&map(json!({
            "status":"completed", "operation_state":"completed",
            "result":payload, "extensions":{}
        })))?;
    }
    Ok(())
}
