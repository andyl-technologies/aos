//! Checks the selected receipt's required nullable input key with inert data.

// These decoder controls confer no native or current world authority.
#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Fixture serialization and exact refusal assertions deliberately panic.
#![allow(clippy::unwrap_used)]

use super::*;

fn receipt_value() -> serde_json::Value {
    let native = canonical::content_ref(b"native", "application/octet-stream").unwrap();
    let causes = canonical::content_ref(b"causes", "application/json").unwrap();
    serde_json::json!({
        "schema_version": 1,
        "profile": HOST_EXACT_PROFILE,
        "node": Id::new("clock/required-input").unwrap(),
        "owners": [],
        "boundary": Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        "native": native,
        "native_sequence": U64::new(0),
        "input": null,
        "pending_causes": causes,
    })
}

#[test]
fn explicit_null_and_populated_input_retain_original_receipt_bytes() {
    let mut value = receipt_value();
    let null_bytes = serde_json::to_vec(&value).unwrap();
    let null: Receipt = serde_json::from_slice(&null_bytes).unwrap();
    assert!(null.input.is_none());
    assert_eq!(serde_json::to_vec(&value).unwrap(), null_bytes);

    let batch = Id::new("input/original-batch").unwrap();
    let reference = canonical::content_ref(b"original input", "application/octet-stream").unwrap();
    value["input"] = serde_json::json!([batch, reference, U64::new(7)]);
    let populated_bytes = serde_json::to_vec(&value).unwrap();
    let populated: Receipt = serde_json::from_slice(&populated_bytes).unwrap();
    assert_eq!(populated.input, Some((batch, reference, U64::new(7))));
    assert_eq!(serde_json::to_vec(&value).unwrap(), populated_bytes);
}

#[test]
fn omitted_input_refuses_before_a_typed_receipt_exists() {
    let mut value = receipt_value();
    value.as_object_mut().unwrap().remove("input");

    let error = serde_json::from_value::<Receipt>(value.clone())
        .err()
        .unwrap();
    assert!(error.to_string().contains("missing field `input`"));

    let body = serde_json::to_vec(&value).unwrap();
    let original = OriginalReceipt {
        objects: [
            InputPayload {
                reference: canonical::content_ref(&body, "application/octet-stream").unwrap(),
                bytes: body,
            },
            InputPayload {
                reference: canonical::content_ref(b"native", "application/octet-stream").unwrap(),
                bytes: b"native".to_vec(),
            },
            InputPayload {
                reference: canonical::content_ref(b"causes", "application/json").unwrap(),
                bytes: b"causes".to_vec(),
            },
        ],
    };
    let refusal = original
        .checked(&Id::new("clock/required-input").unwrap())
        .err()
        .unwrap();
    assert!(refusal.reason.contains("missing field `input`"));
}

#[test]
fn duplicate_and_wrong_input_shapes_preserve_closed_grammar() {
    let value = receipt_value();
    let original = serde_json::to_vec(&value).unwrap();
    let text = serde_json::to_string(&value).unwrap();
    let duplicate = format!("{},\"input\":null}}", &text[..text.len() - 1]);
    assert!(serde_json::from_str::<Receipt>(&duplicate).is_err());

    for input in [
        serde_json::json!({}),
        serde_json::json!([]),
        serde_json::json!(false),
    ] {
        let mut malformed = value.clone();
        malformed["input"] = input;
        assert!(serde_json::from_value::<Receipt>(malformed).is_err());
    }
    assert!(serde_json::from_slice::<Receipt>(&original).is_ok());
    assert_eq!(serde_json::to_vec(&value).unwrap(), original);
}
