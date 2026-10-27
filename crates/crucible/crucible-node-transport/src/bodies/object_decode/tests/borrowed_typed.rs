//! Compares borrowed typed owners and details validation with their old decoders.

use super::*;

fn equivalent<T: DeserializeOwned + Validate + Serialize>(value: Value) -> TestResult {
    let values = value.as_object().unwrap();
    let before = serde_json::to_vec(values)?;
    match (object::<T>(values), preceding::<T>(values)) {
        (Ok(actual), Ok(expected)) => {
            assert_eq!(serde_json::to_vec(&actual)?, serde_json::to_vec(&expected)?);
        }
        (Err(actual), Err(expected)) => assert_eq!(actual.to_string(), expected.to_string()),
        _ => panic!("borrowed typed decoding differs from the preceding decoder"),
    }
    assert_eq!(serde_json::to_vec(values)?, before);
    Ok(())
}

fn details() -> Value {
    json!({
        "nested": [null, false, -0.0, 1e-7, 1e20, u64::MAX],
        "\u{10000}": "雪\n\"\\",
        "\u{e000}": {"$serde_json::private::Number": "123"}
    })
}

#[test]
fn tagged_response_owners_and_failures_match_the_preceding_decoder() -> TestResult {
    for value in [
        json!({"status":"accepted", "operation_state":"running", "result":details(), "extensions":{}}),
        json!({"status":"completed", "operation_state":"completed", "result":details(), "extensions":{}}),
        json!({"status":"error", "operation_state":"not_started", "error":{
            "code":"RESOURCE_EXHAUSTED", "message":"bounded refusal", "effect":"not_started",
            "retryable":true, "details":details()
        }, "extensions":{}}),
        json!({"status":"accepted", "operation_state":"completed", "result":{}, "extensions":{}}),
        json!({"status":"completed", "operation_state":"completed", "result":null, "extensions":{}}),
        json!({"status":"completed", "operation_state":"completed", "result":{}, "extensions":{}, "unknown":true}),
    ] {
        equivalent::<ResponseShape>(value)?;
    }
    Ok(())
}

#[test]
fn notification_and_blob_owners_match_and_survive_input_mutation() -> TestResult {
    equivalent::<NotificationBody>(json!({
        "operation_state":"running", "last_observation_sequence":"18446744073709551615",
        "details":details(), "extensions":{}
    }))?;
    for bytes in [
        json!("AAH_"),
        json!("AA=="),
        json!([0, 1, 255]),
        Value::Null,
    ] {
        equivalent::<BlobChunkRequest>(json!({
            "transfer_id":"transfer", "offset":"0", "bytes":bytes, "extensions":{}
        }))?;
    }

    let mut values = json!({
        "operation_state":"running", "last_observation_sequence":"0",
        "details":details(), "extensions":{}
    });
    let decoded: NotificationBody = object(values.as_object().unwrap())?;
    let expected = serde_json::to_vec(&decoded)?;
    values["details"] = json!({"replacement":true});
    drop(values);

    assert_eq!(serde_json::to_vec(&decoded)?, expected);
    assert!(decoded.details.contains_key("nested"));
    Ok(())
}

fn validate_details(
    values: &Map<String, Value>,
) -> (Result<(), ContractError>, Result<(), ContractError>) {
    let error = ErrorRecord {
        code: "RESOURCE_EXHAUSTED".into(),
        message: "bounded refusal".into(),
        effect: EffectCertainty::NotStarted,
        retryable: false,
        details: values.clone(),
    };
    let notification = NotificationBody {
        operation_state: OperationState::Running,
        last_observation_sequence: U64::new(0),
        details: values.clone(),
        extensions: Extensions::new(),
    };
    (error.validate(), notification.validate())
}

#[test]
fn borrowed_details_validation_keeps_the_defining_grammar_and_marker_data() -> TestResult {
    let mut nested = Value::Null;
    for _ in 0..63 {
        nested = Value::Array(vec![nested]);
    }
    for value in [
        details(),
        json!({"$serde_json::private::RawValue":"ordinary DATA"}),
        json!({"payload":nested.clone()}),
        json!({"payload":[nested]}),
        json!({"payload":vec![Value::Null;65_536]}),
        json!({"payload":vec![Value::Null;65_537]}),
    ] {
        let values = value.as_object().unwrap();
        let before = serde_json::to_vec(values)?;
        let expected = canonical::canonical_json(&value).map(|_| ());
        let (error, notification) = validate_details(values);
        for actual in [error, notification] {
            assert_eq!(actual.is_ok(), expected.is_ok());
            if let (Err(actual), Err(expected)) = (&actual, &expected) {
                assert_eq!(actual.to_string(), expected.to_string());
            }
        }
        assert_eq!(serde_json::to_vec(values)?, before);
    }
    Ok(())
}

#[test]
fn standalone_details_validation_does_not_acquire_a_new_whole_body_byte_limit() -> TestResult {
    let values = json!({"payload":"x".repeat(MAXIMUM_BODY_BYTES + 1)});
    let map = values.as_object().unwrap();
    assert!(canonical::canonical_json(&values)?.len() > MAXIMUM_BODY_BYTES);

    let (error, notification) = validate_details(map);

    error?;
    notification?;
    let mut whole_body = json!({
        "operation_state":"running", "last_observation_sequence":"0",
        "details":{}, "extensions":{}
    });
    whole_body["details"] = values;
    assert!(object::<NotificationBody>(whole_body.as_object().unwrap()).is_err());
    Ok(())
}
