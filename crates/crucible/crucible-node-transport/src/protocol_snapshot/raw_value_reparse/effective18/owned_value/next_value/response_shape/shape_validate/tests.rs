//! Exercises actual completed cursors, common validators and retained refusals.

use super::*;
use crate::bodies::ResponseShape;
use crate::envelope::Envelope;
use crate::protocol_snapshot::raw_value_reparse::historical_serde::{
    decode_envelope, decode_response_shape,
};
use crate::transport::FrameReader;
use crucible_node_format::{Validate, canonical as locked_canonical};
use serde_json::json;
use std::io::Cursor;

fn envelope(body: Value) -> Value {
    json!({"protocol":"CNP/1","message":"response","session_id":"session-1","incarnation_id":"provider-1","node_id":null,"execution_owner_id":"owner-1","capture_owner_id":null,"request_id":"request-1","operation_id":"operation-1","sequence":"1","method":"poll","body":body,"extensions":{}})
}

fn envelope_fields(value: &Value) -> NativeImport18OwningEnvelopeAttemptData {
    let bytes = serde_json::to_vec(value).unwrap();
    let mut wire = Vec::new();
    wire.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(&bytes);
    let mut received = FrameReader::new(Cursor::new(wire), bytes.len())
        .unwrap()
        .read_retained()
        .unwrap();
    let mut raw = None;
    NativeImport18ImmutableRawCustodyData::take_into_data(&mut received, &mut raw).unwrap();
    let raw = raw.as_mut().unwrap();
    raw.quote_into_data(usize::MAX).unwrap();
    raw.freeze_data().unwrap();
    let row = raw
        .completed_bank_data()
        .unwrap()
        .root_selection_row_data(usize::MAX)
        .unwrap();
    let mut selected = None;
    NativeImport18RawSelectionData::read_into_data(&row, &mut selected).unwrap();
    let mut fields = None;
    NativeImport18OwningEnvelopeAttemptData::take_into_data(&mut selected, &mut fields).unwrap();
    let mut fields = fields.unwrap();
    fields.quote_into_data(usize::MAX).unwrap();
    fields.run_data().unwrap();
    fields
}

fn source(value: &Value, finish: bool) -> NativeImport18OwningResponseAttemptData {
    let mut fields = envelope_fields(value);
    fields.quote_body_canonical_into_data(usize::MAX).unwrap();
    fields.check_body_canonical_data().unwrap();
    let mut fields = Some(fields);
    let mut output = None;
    NativeImport18OwningResponseAttemptData::take_into_data(&mut fields, &mut output).unwrap();
    let mut output = output.unwrap();
    if finish {
        for _ in 0..200 {
            if output.state_data().1 {
                return output;
            }
            output.quote_into_data(usize::MAX).unwrap();
            output.run_data().unwrap();
        }
        panic!("finite tiny cursor fixture did not finish");
    }
    output
}

fn take(source: NativeImport18OwningResponseAttemptData) -> NativeImport18ShapeValidateAttemptData {
    let mut input = Some(source);
    let mut output = None;
    NativeImport18ShapeValidateAttemptData::take_into_data(&mut input, &mut output).unwrap();
    assert!(input.is_none());
    output.unwrap()
}

fn quoted(value: &Value) -> NativeImport18ShapeValidateAttemptData {
    let mut owner = take(source(value, true));
    owner.quote_into_data(usize::MAX).unwrap();
    owner
}

fn census(owner: &NativeImport18ShapeValidateAttemptData, result: &Result<(), ProviderError>) {
    let bytes = add(
        owner.retained_requested_storage_data(usize::MAX).unwrap(),
        super::super::super::super::envelope_fields::error_retained_requested_data(result).unwrap(),
    )
    .unwrap();
    assert_eq!(
        owner.census_data(),
        NativeImport18ShapeValidateCensusData::Observed {
            requested_bytes: bytes,
            within_row: owner.row.as_ref().map(|row| bytes <= row.retained)
        }
    );
}

fn error_body(code: &str, message: &str, details: Value, sequence: bool) -> Value {
    let error = if sequence {
        json!([code, message, "not_started", false, details])
    } else {
        json!({"code":code,"message":message,"effect":"not_started","retryable":false,"details":details})
    };
    envelope(
        json!({"status":"error","operation_state":"not_started","error":error,"extensions":{}}),
    )
}

fn wrapped_detail(text: &str) -> Value {
    let protected = format!(
        r#"{{"{RAW_VALUE_KEY}":{}}}"#,
        serde_json::to_string(text).unwrap()
    );
    json!({RAW_VALUE_KEY:protected})
}

fn shallow_error_source(code: &str, message: &str) -> NativeImport18OwningResponseAttemptData {
    source(
        &error_body(code, message, json!({"detail":[true,null,42]}), false),
        true,
    )
}

#[test]
fn actual_common_validation_matches_locked_shallow_shape_for_all_statuses_and_error_forms() {
    for value in [
        envelope(
            json!({"status":"accepted","operation_state":"running","result":{},"extensions":{}}),
        ),
        envelope(
            json!({"status":"accepted","operation_state":"completed","result":{},"extensions":{}}),
        ),
        envelope(
            json!({"status":"completed","operation_state":"completed","result":{},"extensions":{}}),
        ),
        envelope(
            json!({"status":"completed","operation_state":"running","result":{},"extensions":{}}),
        ),
        error_body(
            "INVALID_ARGUMENT",
            "bad",
            json!({"detail":[true,null,1.25]}),
            false,
        ),
        error_body("INVALID_ARGUMENT", "bad", json!({"detail":42}), true),
        envelope(
            json!({"status":"accepted","operation_state":{"running":null},"result":{},"extensions":{}}),
        ),
        envelope(
            json!({"status":"error","operation_state":{"unknown":null},"error":{"code":"INVALID_ARGUMENT","message":"bad","effect":{"not_started":null},"retryable":true,"details":{}},"extensions":{}}),
        ),
        error_body("bad id", "bad", json!({}), false),
        error_body("INVALID_ARGUMENT", &"x".repeat(4097), json!({}), true),
    ] {
        let source = source(&value, true);
        let raw = source.retained_frame_data().unwrap();
        let locked: Envelope = decode_envelope(raw.value.clone()).unwrap();
        let shape: ResponseShape = decode_response_shape(Value::Object(locked.body)).unwrap();
        let expected = shape.validate();
        let expected_extent = match &shape {
            ResponseShape::Error { error, .. } if expected.is_ok() => Some(
                locked_canonical::canonical_json(&Value::Object(error.details.clone()))
                    .unwrap()
                    .len(),
            ),
            _ => None,
        };
        let mut owner = take(source);
        owner.quote_into_data(usize::MAX).unwrap();
        let result = owner.run_data();
        assert_eq!(result.is_ok(), expected.is_ok());
        census(&owner, &result);
        assert_eq!(owner.error_details_canonical_bytes_data(), expected_extent);
        if result.is_ok() {
            assert_eq!(owner.state_data(), (false, true));
        } else {
            assert_eq!(owner.state_data(), (true, false));
        }
        assert_eq!(owner.fields.operation, Some(shape.operation_state()));
        if let Some(error) = &owner.fields.error {
            let ResponseShape::Error {
                error: expected, ..
            } = &shape
            else {
                panic!("actual error fields require locked Error shape")
            };
            assert_eq!(error.code.as_deref(), Some(expected.code.as_str()));
            assert_eq!(error.message.as_deref(), Some(expected.message.as_str()));
            assert_eq!(error.effect, Some(expected.effect));
            assert_eq!(error.retryable, Some(expected.retryable));
            assert!(
                error.code.is_some()
                    && error.message.is_some()
                    && error.effect.is_some()
                    && error.retryable.is_some()
            );
        }
    }
}

#[test]
fn actual_invalid_code_backing_and_original_reason_precede_message_and_details_validation() {
    let source = shallow_error_source("bad id", &"x".repeat(4097));
    let bytes = source.retained_frame_data().unwrap().bytes.clone();
    let mut owner = take(source);
    owner.quote_into_data(usize::MAX).unwrap();
    let result = owner.run_data();
    assert!(matches!(
        &result,
        Err(ProviderError::Contract(
            crucible_node_format::ContractError::Invalid { field: "id", .. }
        ))
    ));
    census(&owner, &result);
    let error = owner.fields.error.as_ref().unwrap();
    assert_eq!(error.code.as_deref(), Some("bad id"));
    let Some(CodeCheck::Invalid(code)) = &error.code_check else {
        panic!("invalid clone must remain rooted")
    };
    assert_eq!(code, "bad id");
    assert!(code.capacity() >= code.len());
    assert!(error.message.as_ref().unwrap().len() > 4096);
    assert!(owner.error_details_canonical_bytes_data().is_none());
    assert_eq!(owner.retained_frame_data().unwrap().bytes, bytes);
    assert!(owner.source.as_ref().unwrap().state_data().1);
    let saved = owner.census_data();
    assert!(owner.run_data().is_err());
    assert_eq!(owner.census_data(), saved);
}

#[test]
fn actual_message_refusal_follows_valid_id_and_precedes_details_validation() {
    let source = shallow_error_source("INVALID_ARGUMENT", &"x".repeat(4097));
    let mut owner = take(source);
    owner.quote_into_data(usize::MAX).unwrap();
    let result = owner.run_data();
    assert!(matches!(
        &result,
        Err(ProviderError::Contract(
            crucible_node_format::ContractError::Invalid {
                field: "message",
                ..
            }
        ))
    ));
    census(&owner, &result);
    assert!(matches!(
        &owner.fields.error.as_ref().unwrap().code_check,
        Some(CodeCheck::Valid(_))
    ));
    assert!(owner.error_details_canonical_bytes_data().is_none());
}

#[test]
fn original_nested_raw_deep_fixtures_stop_at_body_canonical_before_shape_validation() {
    let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let detail = wrapped_detail(&deep);
    let cases = [
        error_body(
            "bad id",
            &"x".repeat(4097),
            json!({"detail":detail.clone()}),
            false,
        ),
        error_body(
            "INVALID_ARGUMENT",
            &"x".repeat(4097),
            json!({"detail":detail.clone()}),
            false,
        ),
        error_body(
            "INVALID_ARGUMENT",
            "bad",
            json!({"detail":detail.clone()}),
            false,
        ),
        envelope(
            json!({"status":"completed","operation_state":"completed","result":{"deep":detail.clone()},"extensions":{"deep":detail}}),
        ),
    ];
    for value in cases {
        let original_bytes = serde_json::to_vec(&value).unwrap();
        let mut owner = envelope_fields(&value);
        assert_eq!(owner.retained_frame_data().unwrap().bytes, original_bytes);
        assert_eq!(owner.retained_frame_data().unwrap().value, value);
        let body = owner.body_data().unwrap();
        let member = body
            .keys()
            .position(|key| key == "error" || key == "result")
            .unwrap();
        let first = owner
            .cut_first_data(EnvelopeField18Data::Body, member)
            .unwrap();
        let reparsing = matches!(first.state_data().mode, Some(RawMode::Reparse));
        if reparsing {
            // Both nested wrappers expand within the same FIRST invocation.
            assert!(first.maximum_intermediate_depth_data() >= 80);
        }

        owner.quote_body_canonical_into_data(usize::MAX).unwrap();
        let result = owner.check_body_canonical_data();
        assert_eq!(result.is_err(), reparsing);
        if reparsing {
            assert!(matches!(&result, Err(ProviderError::Frame(_))));
            assert!(owner.completed_canonical_bytes_data().is_err());
        } else {
            assert!(owner.completed_canonical_bytes_data().is_ok());
        }
        let actual = add(
            owner.retained_requested_storage_data(usize::MAX).unwrap(),
            super::super::super::super::envelope_fields::error_retained_requested_data(&result)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            owner.census_data(),
            NativeImport18OwningEnvelopeCensusData::Observed {
                requested_bytes: actual,
                within_row: Some(true),
            }
        );
        assert_eq!(owner.retained_frame_data().unwrap().bytes, original_bytes);
        assert_eq!(owner.retained_frame_data().unwrap().value, value);
        // No Response cursor, second pass or Shape owner is fabricated after
        // this genuine earlier refusal. Deep results remain in flat custody.
    }
}

#[test]
fn shallow_nested_raw_oracle_expands_within_one_first_call_and_matches_the_actual_cursor() {
    let detail = wrapped_detail("[0]");
    let bytes = serde_json::to_vec(&detail).unwrap();
    let strict = locked_canonical::parse_json(&bytes, bytes.len()).unwrap();
    assert_eq!(strict, detail);
    let text: Value = serde_json::from_slice(&bytes).unwrap();
    let first: Value = serde_json::from_value(strict).unwrap();
    assert_eq!(first, text);
    let next: Value = serde_json::from_value(first.clone()).unwrap();
    assert_eq!(next, first);
    // These separate ordinary oracle owners are shallow in both feature modes.
    // They prove the wrapper schedule without constructing an ordinary deep tree.
    let value = error_body("INVALID_ARGUMENT", "bad", json!({"detail":detail}), false);
    let source = source(&value, true);
    let cut = source.completed_cut_data(0).unwrap().unwrap().2;
    if text.is_array() {
        let NativeImport18NextValuePassKindData::Array(mut values) = cut.kind_data().unwrap()
        else {
            panic!("the same FIRST-expanded array must reach the actual second output");
        };
        let element = values.next().unwrap();
        let NativeImport18NextValuePassKindData::Number(number) = element.kind_data().unwrap()
        else {
            panic!("the actual nested Raw text contains one scalar zero");
        };
        assert_eq!(number.as_u64(), Some(0));
        assert!(values.next().is_none());
        assert_eq!(text, json!([0]));
    } else {
        assert!(text.is_object());
        assert!(matches!(
            cut.kind_data().unwrap(),
            NativeImport18NextValuePassKindData::Object(_)
        ));
    }
    let locked: Envelope =
        decode_envelope(source.retained_frame_data().unwrap().value.clone()).unwrap();
    let shape: ResponseShape = decode_response_shape(Value::Object(locked.body)).unwrap();
    shape.validate().unwrap();
    let ResponseShape::Error { error, .. } = shape else {
        panic!("error fixture")
    };
    let expected = locked_canonical::canonical_json(&Value::Object(error.details))
        .unwrap()
        .len();
    let mut owner = take(source);
    owner.quote_into_data(usize::MAX).unwrap();
    let result = owner.run_data();
    census(&owner, &result);
    result.unwrap();
    assert_eq!(owner.error_details_canonical_bytes_data(), Some(expected));
}

#[test]
fn actual_next_numeric_unicode_and_empty_details_match_locked_jcs_extent_without_another_pass() {
    for details in [
        json!({}),
        json!({"z":-0.0,"😀":"\n\u{0000}","\u{e000}":[1.25,true,null]}),
        json!({"value":{RAW_VALUE_KEY:"null"}}),
    ] {
        let value = error_body("INVALID_ARGUMENT", "bad", details, false);
        let source = source(&value, true);
        let locked: Envelope =
            decode_envelope(source.retained_frame_data().unwrap().value.clone()).unwrap();
        let shape: ResponseShape = decode_response_shape(Value::Object(locked.body)).unwrap();
        let ResponseShape::Error { error, .. } = shape else {
            panic!("error fixture")
        };
        let expected = locked_canonical::canonical_json(&Value::Object(error.details)).unwrap();
        let mut owner = take(source);
        owner.quote_into_data(usize::MAX).unwrap();
        let result = owner.run_data();
        census(&owner, &result);
        result.unwrap();
        assert_eq!(
            owner.error_details_canonical_bytes_data(),
            Some(expected.len())
        );
    }
}

#[test]
fn actual_exact_row_runs_and_each_one_short_axis_refuses_before_scalar_or_validator_effects() {
    let value = error_body("INVALID_ARGUMENT", "bad", json!({"detail":42}), false);
    let mut exact = quoted(&value);
    let (r, t, s) = exact.requested_storage_data().unwrap();
    exact.row.as_mut().unwrap().maximum = add(add(r, t).unwrap(), s).unwrap();
    exact.run_data().unwrap();
    census(&exact, &Ok(()));
    for axis in 0..3 {
        let mut owner = quoted(&value);
        let row = owner.row.as_mut().unwrap();
        match axis {
            0 => row.retained -= 1,
            1 => row.transient -= 1,
            _ => row.scratch -= 1,
        }
        let result = owner.run_data();
        assert!(result.is_err());
        census(&owner, &result);
        assert!(
            owner.fields.status.is_none()
                && owner.fields.operation.is_none()
                && owner.fields.error.is_none()
        );
        assert!(owner.error_details_canonical_bytes_data().is_none());
        assert!(owner.source.as_ref().unwrap().state_data().1);
    }
}

#[test]
fn actual_unfinished_take_and_refused_quote_keep_original_cursor_and_reused_input() {
    let value = envelope(
        json!({"status":"completed","operation_state":"completed","result":{},"extensions":{}}),
    );
    let mut input = Some(source(&value, false));
    let mut output = None;
    let result = NativeImport18ShapeValidateAttemptData::take_into_data(&mut input, &mut output);
    assert!(result.is_err() && input.is_none());
    census(output.as_ref().unwrap(), &result);
    assert!(output.as_ref().unwrap().retained_frame_data().is_ok());
    assert!(output.as_ref().unwrap().fields.status.is_none());
    let mut owner = take(source(&value, true));
    let result = owner.quote_into_data(0);
    assert!(result.is_err());
    census(&owner, &result);
    let mut original = Some(source(&value, true));
    let bytes = original
        .as_ref()
        .unwrap()
        .retained_frame_data()
        .unwrap()
        .bytes
        .clone();
    let mut spent = Some(owner);
    assert!(
        NativeImport18ShapeValidateAttemptData::take_into_data(&mut original, &mut spent).is_err()
    );
    assert_eq!(
        original
            .as_ref()
            .unwrap()
            .retained_frame_data()
            .unwrap()
            .bytes,
        bytes
    );
    assert!(spent.as_ref().unwrap().fields.status.is_none());
}

#[test]
fn successful_common_validation_leaves_result_schema_and_extension_consumers_unselected() {
    let value = envelope(
        json!({"status":"completed","operation_state":"completed","result":{"arbitrary_result_key":[true,null,42]},"extensions":{"arbitrary_extension_key":{"value":"unselected"}}}),
    );
    let source = source(&value, true);
    let mut owner = take(source);
    owner.quote_into_data(usize::MAX).unwrap();
    let result = owner.run_data();
    census(&owner, &result);
    result.unwrap();
    assert_eq!(owner.state_data(), (false, true));
    assert!(owner.fields.error.is_none());
    assert!(owner.error_details_canonical_bytes_data().is_none());
    // The selecting request/result producer owns its typed DTO and result
    // canonical obligations. This reachable fixture asserts only common Shape
    // validation; the original 80-deep case is checked at its earlier boundary.
}

#[test]
fn actual_string_copy_paths_cover_empty_utf8_and_full_invalid_code_without_a_new_cap() {
    for (code, message) in [
        (String::new(), String::new()),
        ("A".to_owned(), String::new()),
        ("x".repeat(129), "😀\n\u{0000}".repeat(64)),
        ("bad id".repeat(256), "é".repeat(1024)),
    ] {
        let value = error_body(&code, &message, json!({}), false);
        let source = source(&value, true);
        let locked: Envelope =
            decode_envelope(source.retained_frame_data().unwrap().value.clone()).unwrap();
        let shape: ResponseShape = decode_response_shape(Value::Object(locked.body)).unwrap();
        let expected = shape.validate();
        let mut owner = take(source);
        owner.quote_into_data(usize::MAX).unwrap();
        let result = owner.run_data();

        assert_eq!(result.is_ok(), expected.is_ok());
        census(&owner, &result);
        let fields = owner.fields.error.as_ref().unwrap();
        assert_eq!(fields.code.as_deref(), Some(code.as_str()));
        assert_eq!(fields.message.as_deref(), Some(message.as_str()));
        if expected.is_err() {
            let Some(CodeCheck::Invalid(retained)) = &fields.code_check else {
                panic!("the complete invalid validation copy must remain rooted");
            };
            assert_eq!(retained, &code);
            assert!(retained.capacity() >= code.len());
            assert!(owner.error_details_canonical_bytes_data().is_none());
        } else {
            assert!(matches!(&fields.code_check, Some(CodeCheck::Valid(_))));
            assert_eq!(owner.error_details_canonical_bytes_data(), Some(2));
        }
    }
}

#[test]
fn typed_identifier_refusal_is_funded_before_scalar_transfer_at_exact_boundary() {
    for short in [false, true] {
        let source = shallow_error_source("bad id", &"x".repeat(4097));
        let mut owner = take(source);
        let row = storage::quote_data(owner.source.as_ref().unwrap(), usize::MAX).unwrap();
        let exact = add(add(row.retained, row.transient).unwrap(), row.scratch).unwrap();
        let raw = owner.retained_frame_data().unwrap().bytes.as_ptr();
        if short {
            assert!(owner.quote_into_data(exact - 1).is_err());
            assert!(owner.fields.error.is_none());
            assert_eq!(owner.retained_frame_data().unwrap().bytes.as_ptr(), raw);
            assert!(owner.run_data().is_err());
            assert!(owner.fields.error.is_none());
        } else {
            owner.quote_into_data(exact).unwrap();
            let result = owner.run_data();
            assert!(matches!(
                &result,
                Err(ProviderError::Contract(
                    crucible_node_format::ContractError::Invalid { field: "id", .. }
                ))
            ));
            census(&owner, &result);
            assert_eq!(owner.retained_frame_data().unwrap().bytes.as_ptr(), raw);
            let fields = owner.fields.error.as_ref().unwrap();
            assert!(
                matches!(&fields.code_check, Some(CodeCheck::Invalid(text)) if text == "bad id")
            );
            assert!(owner.error_details_canonical_bytes_data().is_none());
        }
    }
}
