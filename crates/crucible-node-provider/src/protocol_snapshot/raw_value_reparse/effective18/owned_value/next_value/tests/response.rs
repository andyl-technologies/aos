//! Exercises the actual Envelope-body/ResponseShape second-pass seam.

use super::*;
use crate::bodies::ResponseShape;
use crate::envelope::Envelope;
use crucible_node_contract::canonical;

fn envelope(body: Value) -> Value {
    json!({
        "protocol": "CNP/1", "message": "response", "session_id": "session-1",
        "incarnation_id": "provider-1", "node_id": null,
        "execution_owner_id": "owner-1", "capture_owner_id": null,
        "request_id": "request-1", "operation_id": "operation-1", "sequence": "1",
        "method": "poll", "body": body, "extensions": {}
    })
}

fn first_envelope(raw: &RetainedFrame) -> NativeImport18EnvelopeFieldsAttemptData<'_> {
    let row = NativeImport18EnvelopeFieldsConstructionData::quote_data(raw, usize::MAX).unwrap();
    let mut output = None;
    NativeImport18EnvelopeFieldsAttemptData::read_into_data(raw, &row, &mut output).unwrap();
    output.unwrap()
}

#[test]
fn actual_response_cut_order_and_jcs_extent_match_the_locked_shallow_boundary() {
    let raw = frame(envelope(json!({
        "status": "completed", "operation_state": "completed",
        "result": {"value": ["\n\u{0000}", 1.25, "😀", "\u{e000}"]},
        "extensions": {"named": true}
    })));
    let locked: Envelope = serde_json::from_value(raw.value.clone()).unwrap();
    let expected_bytes = canonical::canonical_json(&Value::Object(locked.body.clone())).unwrap();
    let expected: ResponseShape = serde_json::from_value(Value::Object(locked.body)).unwrap();
    let first = first_envelope(&raw);
    let row =
        NativeImport18ResponseShapeCutsPreludeData::quote_data(&raw, &first, usize::MAX).unwrap();
    let mut output = None;
    NativeImport18ResponseShapeCutsData::read_into_data(&raw, &first, &row, &mut output).unwrap();
    let cursor = output.as_mut().unwrap();
    assert_eq!(cursor.canonical_bytes_data(), Some(expected_bytes.len()));

    let mut retained = Vec::new();
    let mut locations = Vec::new();
    while let Some(cut) = cursor.next_cut_data().unwrap() {
        let prewalk = cut.prewalk_data(usize::MAX).unwrap();
        let row = cut.quote_data(&prewalk, usize::MAX).unwrap();
        let mut next = None;
        cut.read_into_data(&row, &mut next).unwrap();
        let owner = next.as_ref().unwrap();
        let value = shallow(cut.completed_data(owner).unwrap(), 8);
        let ResponseShape::Completed {
            result, extensions, ..
        } = &expected
        else {
            panic!("completed");
        };
        match cut.location_data() {
            NativeImport18ResponseValueCutLocationData::Result(0) => {
                assert_eq!(value, result["value"])
            }
            NativeImport18ResponseValueCutLocationData::Extension(0) => {
                assert_eq!(value, extensions["named"])
            }
            _ => panic!("unexpected actual structural cut"),
        }
        cursor.complete_cut_data(owner).unwrap();
        locations.push(cut.location_data());
        retained.push(next);
    }
    assert_eq!(
        locations,
        [
            NativeImport18ResponseValueCutLocationData::Extension(0),
            NativeImport18ResponseValueCutLocationData::Result(0)
        ]
    );
    assert_eq!(retained.len(), 2);
}

#[test]
fn error_record_sequence_keeps_its_detail_cut_before_a_late_extra_position_refuses() {
    for extra in [false, true] {
        let mut error = json!(["INVALID_ARGUMENT", "bad", "not_started", false, {"detail": 42}]);
        if extra {
            error.as_array_mut().unwrap().push(Value::Null);
        }
        let raw = frame(envelope(
            json!({"status": "error", "operation_state": "not_started", "error": error, "extensions": {}}),
        ));
        let locked: Envelope = serde_json::from_value(raw.value.clone()).unwrap();
        let expected = serde_json::from_value::<ResponseShape>(Value::Object(locked.body));
        assert_eq!(expected.is_err(), extra);
        let first = first_envelope(&raw);
        let row = NativeImport18ResponseShapeCutsPreludeData::quote_data(&raw, &first, usize::MAX)
            .unwrap();
        let mut cursor = None;
        NativeImport18ResponseShapeCutsData::read_into_data(&raw, &first, &row, &mut cursor)
            .unwrap();
        let cursor = cursor.as_mut().unwrap();

        let cut = cursor.next_cut_data().unwrap().unwrap();
        assert_eq!(
            cut.location_data(),
            NativeImport18ResponseValueCutLocationData::ErrorDetail(0)
        );
        let prewalk = cut.prewalk_data(usize::MAX).unwrap();
        let row = cut.quote_data(&prewalk, usize::MAX).unwrap();
        let mut child = None;
        cut.read_into_data(&row, &mut child).unwrap();
        let child = child.as_ref().unwrap();
        assert_eq!(shallow(cut.completed_data(child).unwrap(), 4), json!(42));
        cursor.complete_cut_data(child).unwrap();
        assert_eq!(cursor.next_cut_data().is_err(), extra);
        assert_censused(child);
    }
}

#[test]
fn canonical_body_refusal_precedes_any_second_pass_on_a_real_deep_first_result() {
    let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let raw = frame(envelope(
        json!({"status": "completed", "operation_state": "completed", "result": {"value": {RAW_VALUE_KEY: deep}}, "extensions": {}}),
    ));
    let first = first_envelope(&raw);
    let row =
        NativeImport18ResponseShapeCutsPreludeData::quote_data(&raw, &first, usize::MAX).unwrap();
    let mut cursor = None;
    let result =
        NativeImport18ResponseShapeCutsData::read_into_data(&raw, &first, &row, &mut cursor);
    let body = first.body_data(&raw).unwrap();
    let (member, (_, input)) = body
        .iter()
        .enumerate()
        .find(|(_, (key, _))| *key == "result")
        .unwrap();
    let value = first
        .completed_cut_data(&raw, EnvelopeField18Data::Body, member, input)
        .unwrap();
    if matches!(value.boundary_data().mode, Some(RawMode::Reparse)) {
        assert!(result.is_err());
        let cursor = cursor.as_ref().unwrap();
        assert_eq!(cursor.state_data(), (true, false, false));
        assert!(cursor.canonical_bytes_data().is_none());
    } else {
        assert!(result.is_ok());
    }
    // The actual deep first result stays in flat custody; this control never
    // builds an ordinary deep Envelope or a deep ordinary comparison value.
}

#[test]
fn internally_tagged_sequence_is_real_but_the_actual_envelope_body_cut_is_a_map() {
    let shape = json!(["completed", "completed", {"value": 1}, {}]);
    assert!(serde_json::from_value::<ResponseShape>(shape.clone()).is_ok());
    let raw = frame(envelope(shape));
    assert!(serde_json::from_value::<Envelope>(raw.value.clone()).is_err());
    let row = NativeImport18EnvelopeFieldsConstructionData::quote_data(&raw, usize::MAX).unwrap();
    let mut output = None;
    assert!(
        NativeImport18EnvelopeFieldsAttemptData::read_into_data(&raw, &row, &mut output).is_err()
    );
    assert!(output.is_some());
}
