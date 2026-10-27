//! Keeps arbitrary CNP JSON data independent of Serde's private field names.

use super::*;

#[test]
fn extension_json_never_reparses_private_marker_strings() -> TestResult {
    for payload in [
        json!({"$serde_json::private::RawValue": "ordinary DATA"}),
        json!({"$serde_json::private::RawValue": "{\"nested\":true}"}),
        json!({"$serde_json::private::RawValue": "[0,1,2]"}),
        json!({"nested": [{"$serde_json::private::RawValue": "null"}]}),
    ] {
        let input = body(payload.clone());

        let decoded: PollRequest = object(&input)?;

        assert_eq!(decoded.extensions.get("payload"), Some(&payload));
        assert_eq!(serde_json::to_vec(&input)?, serde_json::to_vec(&decoded)?);
    }
    Ok(())
}

#[test]
fn envelope_body_and_typed_request_keep_literal_extension_data() -> TestResult {
    let payload = json!({"$serde_json::private::RawValue": "ordinary DATA"});
    let input = json!({
        "protocol": "CNP/1", "message": "request", "session_id": "session/0",
        "incarnation_id": "provider/0", "node_id": null,
        "execution_owner_id": null, "capture_owner_id": null,
        "request_id": "request/0", "operation_id": "operation/0",
        "sequence": "1", "method": "poll", "body": body(payload.clone()),
        "extensions": {}
    });

    let decoded = crate::envelope::Envelope::decode(&serde_json::to_vec(&input)?, 65_536)?;
    let request: PollRequest = object(&decoded.body)?;

    assert_eq!(request.extensions.get("payload"), Some(&payload));
    assert_eq!(serde_json::to_value(decoded)?, input);
    Ok(())
}

#[test]
fn response_error_notification_and_nullable_outcome_keep_literal_data() -> TestResult {
    let details = json!({"$serde_json::private::RawValue": "ordinary DATA"});
    let response = json!({
        "status": "error", "operation_state": "not_started",
        "error": {
            "code": "INVALID_ARGUMENT", "message": "refused", "effect": "not_started",
            "retryable": false, "details": details
        }, "extensions": {}
    });
    let fields = response.as_object().ok_or("response object absent")?;

    let decoded = responses::decode_response_shape(fields)?;
    let owned: ResponseShape = serde_json::from_value(response.clone())?;

    decoded.validate()?;
    assert_eq!(decoded, owned);
    assert_eq!(serde_json::to_value(decoded)?, response);

    let notification = json!({
        "operation_state": "not_started", "last_observation_sequence": "0",
        "details": details, "extensions": {}
    });
    let decoded = decode_notification(
        Method::OperationUpdate,
        notification.as_object().ok_or("notification absent")?,
    )?;
    assert_eq!(serde_json::to_value(decoded)?, notification);

    let input = json!({
        "operation_id": "operation/0", "operation_state": "not_started", "outcome": response,
        "observations": [], "next_observation_sequence": "0"
    });
    let decoded: PollResult = object(input.as_object().ok_or("poll result absent")?)?;
    assert_eq!(serde_json::to_value(decoded)?, input);

    let mut missing = input.as_object().ok_or("poll result absent")?.clone();
    missing.remove("outcome");
    assert!(object::<PollResult>(&missing).is_err());
    Ok(())
}
