//! Checks actual typed body validation against its preceding allocating oracle.

use super::*;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

mod borrowed_typed;

fn preceding<T: DeserializeOwned + Validate>(
    value: &Map<String, Value>,
) -> Result<T, ContractError> {
    let bytes = canonical::canonical_json(&Value::Object(value.clone()))?;
    if bytes.len() > MAXIMUM_BODY_BYTES {
        return Err(invalid("body", "body exceeds hard frame ceiling"));
    }
    let decoded: T = serde_json::from_value(Value::Object(value.clone()))?;
    decoded.validate()?;
    Ok(decoded)
}

fn body(extension: Value) -> Map<String, Value> {
    let Value::Object(value) = json!({
        "after_observation_sequence": "0", "extensions": {"payload": extension}
    }) else {
        panic!("body fixture must be an object")
    };
    value
}

#[test]
fn typed_decoding_preserves_independent_results_and_original_spare_capacity() -> TestResult {
    let mut value = body(json!({
        "\u{10000}": [null, false, true, -0.0, 1e20, u64::MAX],
        "\u{e000}": "雪\n\"\\",
        "text": "$serde_json::private::RawValue"
    }));
    let mut sequence = value
        .get("after_observation_sequence")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    sequence.reserve(65_536);
    let capacity = sequence.capacity();
    value.insert("after_observation_sequence".into(), Value::String(sequence));
    let original = serde_json::to_vec(&value)?;

    let decoded: PollRequest = object(&value)?;
    let expected: PollRequest = preceding(&value)?;

    assert_eq!(decoded, expected);
    assert_eq!(
        serde_json::to_vec(&decoded)?,
        serde_json::to_vec(&expected)?
    );
    assert_eq!(serde_json::to_vec(&value)?, original);
    let Value::String(sequence) = &value["after_observation_sequence"] else {
        panic!("original scalar changed")
    };
    assert_eq!(sequence.capacity(), capacity);
    assert!(matches!(
        decode_request(Method::Poll, &value)?,
        RequestBody::Poll(_)
    ));
    Ok(())
}

#[test]
fn private_marker_fields_keep_the_preceding_feature_dependent_typed_behavior() -> TestResult {
    for extension in [
        json!({"$serde_json::private::RawValue": "ordinary DATA"}),
        json!({"$serde_json::private::RawValue": "{\"nested\":true}"}),
        json!({"$serde_json::private::Number": "123"}),
    ] {
        // Construct the map directly: from_value in fixture setup would apply
        // the same feature-sensitive Value visitor that this test exercises.
        let value = body(extension);
        let original = serde_json::to_vec(&value)?;
        let decoded = object::<PollRequest>(&value);
        let expected = preceding::<PollRequest>(&value);

        match (decoded, expected) {
            (Ok(decoded), Ok(expected)) => {
                assert_eq!(
                    serde_json::to_vec(&decoded)?,
                    serde_json::to_vec(&expected)?
                );
            }
            (Err(decoded), Err(expected)) => assert_eq!(decoded.to_string(), expected.to_string()),
            _ => panic!("borrowed validation changed the preceding typed decoder"),
        }
        assert_eq!(serde_json::to_vec(&value)?, original);
    }
    Ok(())
}

#[test]
fn typed_missing_unknown_null_and_noncanonical_fields_still_refuse() -> TestResult {
    for value in [
        json!({"extensions": {}}),
        json!({"after_observation_sequence": "0", "extensions": {}, "unknown": true}),
        json!({"after_observation_sequence": null, "extensions": {}}),
        json!({"after_observation_sequence": 0, "extensions": {}}),
        json!({"after_observation_sequence": "00", "extensions": {}}),
        json!({"after_observation_sequence": "0"}),
    ] {
        let values = value.as_object().unwrap();
        assert!(preceding::<PollRequest>(values).is_err());
        assert!(object::<PollRequest>(values).is_err());
        assert!(decode_request(Method::Poll, values).is_err());
    }
    Ok(())
}

#[test]
fn canonical_grammar_is_enforced_even_inside_arbitrary_extension_values() -> TestResult {
    let mut nested = Value::Null;
    for _ in 0..62 {
        nested = json!([nested]);
    }
    let value = body(nested.clone());
    let _: PollRequest = object(&value)?;
    let _: PollRequest = preceding(&value)?;

    let value = body(json!([nested]));
    assert!(object::<PollRequest>(&value).is_err());
    assert!(preceding::<PollRequest>(&value).is_err());

    let value = body(Value::Array(vec![Value::Null; 65_537]));
    assert!(object::<PollRequest>(&value).is_err());
    assert!(preceding::<PollRequest>(&value).is_err());
    Ok(())
}

#[test]
fn exact_hard_canonical_byte_limit_matches_the_preceding_decoder() -> TestResult {
    let mut value = body(Value::String(String::new()));
    let overhead = canonical::canonical_json(&Value::Object(value.clone()))?.len();
    let Value::Object(extensions) = value.get_mut("extensions").unwrap() else {
        panic!("missing extensions")
    };
    extensions.insert(
        "payload".into(),
        Value::String("x".repeat(MAXIMUM_BODY_BYTES - overhead)),
    );

    let decoded: PollRequest = object(&value)?;
    let expected: PollRequest = preceding(&value)?;
    assert_eq!(decoded, expected);
    drop(decoded);
    drop(expected);

    let Value::Object(extensions) = value.get_mut("extensions").unwrap() else {
        panic!("missing extensions")
    };
    let Value::String(payload) = extensions.get_mut("payload").unwrap() else {
        panic!("missing payload")
    };
    payload.push('x');

    for result in [
        object::<PollRequest>(&value),
        preceding::<PollRequest>(&value),
    ] {
        assert!(
            matches!(result, Err(ContractError::Invalid { field: "body", reason }) if reason == "body exceeds hard frame ceiling")
        );
    }
    Ok(())
}
