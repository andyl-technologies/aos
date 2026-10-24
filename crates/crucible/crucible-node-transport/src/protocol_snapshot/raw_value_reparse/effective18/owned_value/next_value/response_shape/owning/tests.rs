//! Exercises real retained receipts, actual scheduled constructors and refusals.

use super::*;
use crate::bodies::ResponseShape;
use crate::envelope::Envelope;
use crate::transport::FrameReader;
use serde_json::json;
use std::io::Cursor;

fn envelope(body: Value) -> Value {
    json!({"protocol":"CNP/1","message":"response","session_id":"session-1","incarnation_id":"provider-1","node_id":null,"execution_owner_id":"owner-1","capture_owner_id":null,"request_id":"request-1","operation_id":"operation-1","sequence":"1","method":"poll","body":body,"extensions":{}})
}

fn fields(value: &Value) -> NativeImport18OwningEnvelopeAttemptData {
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
    let mut output = None;
    NativeImport18OwningEnvelopeAttemptData::take_into_data(&mut selected, &mut output).unwrap();
    let mut owner = output.unwrap();
    owner.quote_into_data(usize::MAX).unwrap();
    owner.run_data().unwrap();
    owner
}

fn canonical(
    mut owner: NativeImport18OwningEnvelopeAttemptData,
) -> NativeImport18OwningEnvelopeAttemptData {
    owner.quote_body_canonical_into_data(usize::MAX).unwrap();
    owner.check_body_canonical_data().unwrap();
    owner
}

fn take(owner: NativeImport18OwningEnvelopeAttemptData) -> NativeImport18OwningResponseAttemptData {
    let mut input = Some(owner);
    let mut output = None;
    NativeImport18OwningResponseAttemptData::take_into_data(&mut input, &mut output).unwrap();
    assert!(input.is_none());
    output.unwrap()
}

fn census(owner: &NativeImport18OwningResponseAttemptData, result: &Result<(), ProviderError>) {
    let bytes = add(
        owner.retained_requested_storage_data(usize::MAX).unwrap(),
        super::super::super::super::envelope_fields::error_retained_requested_data(result).unwrap(),
    )
    .unwrap();
    assert_eq!(
        owner.census_data(),
        NativeImport18OwningResponseCensusData::Observed {
            requested_bytes: bytes,
            within_row: owner.row.as_ref().map(|row| bytes <= row.retained)
        }
    );
}

fn step(owner: &mut NativeImport18OwningResponseAttemptData) -> Result<(), ProviderError> {
    let result = owner.quote_into_data(usize::MAX);
    census(owner, &result);
    result?;
    let result = owner.run_data();
    census(owner, &result);
    result
}

fn finish(owner: &mut NativeImport18OwningResponseAttemptData) -> Result<(), ProviderError> {
    // This bound is a test liveness assertion for these finite tiny examples;
    // the production schedule has no caller-selected pass/depth/step cap.
    for _ in 0..200 {
        if owner.finished {
            return Ok(());
        }
        step(owner)?;
    }
    panic!("tiny actual schedule did not finish");
}

fn shallow(value: NativeImport18NextValuePassViewData<'_>, remaining: usize) -> Value {
    assert!(
        remaining > 0,
        "comparison never reconstructs deep user values"
    );
    match value.kind_data().unwrap() {
        NativeImport18NextValuePassKindData::Null => Value::Null,
        NativeImport18NextValuePassKindData::Bool(v) => Value::Bool(v),
        NativeImport18NextValuePassKindData::Number(v) => Value::Number(v.clone()),
        NativeImport18NextValuePassKindData::String(v) => Value::String(v.into()),
        NativeImport18NextValuePassKindData::Array(v) => {
            Value::Array(v.map(|v| shallow(v, remaining - 1)).collect())
        }
        NativeImport18NextValuePassKindData::Object(v) => Value::Object(
            v.map(|(k, v)| (k.into(), shallow(v, remaining - 1)))
                .collect(),
        ),
    }
}

#[test]
fn actual_owning_cursor_matches_locked_shallow_response_and_keeps_all_real_outputs() {
    for body in [
        json!({"status":"completed","operation_state":"completed","extensions":{"one":[true,null]},"result":{"value":42}}),
        json!({"status":"accepted","operation_state":{"running":null},"extensions":{},"result":{"value":{"x":"same"}}}),
        json!({"status":"completed","operation_state":"completed","extensions":{},"result":{RAW_VALUE_KEY:"{\"a\":1,\"a\":2}"}}),
        json!({"status":"error","operation_state":"not_started","extensions":{"one":false},"error":{"code":"INVALID_ARGUMENT","message":"bad","effect":{"not_started":null},"retryable":false,"details":{"detail":[1,2]}}}),
        json!({"status":"error","operation_state":"not_started","extensions":{},"error":["INVALID_ARGUMENT","bad","not_started",false,{"detail":42}]}),
    ] {
        let first = fields(&envelope(body));
        let actual = first.retained_frame_data().unwrap();
        let locked: Envelope = serde_json::from_value(actual.value.clone()).unwrap();
        let expected: ResponseShape = serde_json::from_value(Value::Object(locked.body)).unwrap();
        let mut owner = take(canonical(first));
        finish(&mut owner).unwrap();
        assert_eq!(owner.state_data(), (false, true, false));
        let mut expected_values = Vec::new();
        match expected {
            ResponseShape::Accepted {
                extensions, result, ..
            }
            | ResponseShape::Completed {
                extensions, result, ..
            } => {
                expected_values.extend(extensions.into_iter().enumerate().map(
                    |(i, (key, value))| {
                        (
                            NativeImport18ResponseValueCutLocationData::Extension(i),
                            key,
                            value,
                        )
                    },
                ));
                expected_values.extend(result.into_iter().enumerate().map(|(i, (key, value))| {
                    (
                        NativeImport18ResponseValueCutLocationData::Result(i),
                        key,
                        value,
                    )
                }));
            }
            ResponseShape::Error {
                extensions, error, ..
            } => {
                expected_values.extend(error.details.into_iter().enumerate().map(
                    |(i, (key, value))| {
                        (
                            NativeImport18ResponseValueCutLocationData::ErrorDetail(i),
                            key,
                            value,
                        )
                    },
                ));
                expected_values.extend(extensions.into_iter().enumerate().map(
                    |(i, (key, value))| {
                        (
                            NativeImport18ResponseValueCutLocationData::Extension(i),
                            key,
                            value,
                        )
                    },
                ));
            }
        }
        assert_eq!(owner.history.len(), expected_values.len());
        for (index, (location, key, value)) in expected_values.into_iter().enumerate() {
            let (actual_location, actual_key, actual_value) =
                owner.completed_cut_data(index).unwrap().unwrap();
            assert_eq!(actual_location, location);
            assert_eq!(actual_key, key);
            assert_eq!(shallow(actual_value, 8), value);
        }
        assert!(
            owner
                .completed_cut_data(owner.history.len())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            owner.retained_frame_data().unwrap().bytes,
            owner
                .envelope
                .as_ref()
                .unwrap()
                .retained_frame_data()
                .unwrap()
                .bytes
        );
    }
}

#[test]
fn actual_error_sequence_late_position_keeps_completed_detail_and_original_failure() {
    for extra in [false, true] {
        let mut error = json!(["INVALID_ARGUMENT","bad","not_started",false,{"detail":42}]);
        if extra {
            error.as_array_mut().unwrap().push(Value::Null);
        }
        let first = fields(&envelope(
            json!({"status":"error","operation_state":"not_started","extensions":{},"error":error}),
        ));
        let locked: Envelope =
            serde_json::from_value(first.retained_frame_data().unwrap().value.clone()).unwrap();
        assert_eq!(
            serde_json::from_value::<ResponseShape>(Value::Object(locked.body)).is_err(),
            extra
        );
        let mut owner = take(canonical(first));
        let result = finish(&mut owner);
        assert_eq!(result.is_err(), extra);
        census(&owner, &result);
        assert_eq!(owner.history.len(), 1);
        assert_eq!(
            owner.history[0].cut.location,
            NativeImport18ResponseValueCutLocationData::ErrorDetail(0)
        );
        assert_eq!(
            shallow(
                owner.history[0]
                    .next
                    .as_ref()
                    .unwrap()
                    .completed_data()
                    .unwrap(),
                4
            ),
            json!(42)
        );
        if extra {
            assert!(owner.failed);
            let saved = owner.census_data();
            assert!(owner.run_data().is_err());
            assert_eq!(owner.census_data(), saved);
        }
    }
}

#[test]
fn canonical_failure_precedes_status_selection_transfer_or_any_second_pass() {
    let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let mut first = fields(&envelope(
        json!({"status":"bogus","operation_state":"completed","extensions":{},"result":{"value":{RAW_VALUE_KEY:deep}}}),
    ));
    let mode = first
        .cut_first_data(
            EnvelopeField18Data::Body,
            first
                .body_data()
                .unwrap()
                .keys()
                .position(|name| name == "result")
                .unwrap(),
        )
        .unwrap()
        .state_data()
        .mode;
    first.quote_body_canonical_into_data(usize::MAX).unwrap();
    let result = first.check_body_canonical_data();
    if matches!(mode, Some(RawMode::Reparse)) {
        assert!(result.is_err());
    }
    let mut input = Some(first);
    let mut output = None;
    let result = NativeImport18OwningResponseAttemptData::take_into_data(&mut input, &mut output);
    let owner = output.as_ref().unwrap();
    if matches!(mode, Some(RawMode::Reparse)) {
        assert!(result.is_err());
        assert!(owner.banks.is_empty());
        assert!(owner.history.is_empty());
        assert!(owner.pending.is_none());
    }
    assert!(input.is_none());
    census(owner, &result);
}

#[test]
fn actual_next_failure_retains_flat_deep_child_and_does_not_acknowledge_pending_cut() {
    let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let text = format!(
        r#"{{"z":0,"{RAW_VALUE_KEY}":{}}}"#,
        serde_json::to_string(&deep).unwrap()
    );
    let first = fields(&envelope(
        json!({"status":"completed","operation_state":"completed","extensions":{"earlier":true},"result":{"value":{RAW_VALUE_KEY:text}}}),
    ));
    let result_member = first
        .body_data()
        .unwrap()
        .keys()
        .position(|key| key == "result")
        .unwrap();
    let mode = first
        .cut_first_data(EnvelopeField18Data::Body, result_member)
        .unwrap()
        .state_data()
        .mode;
    let mut owner = take(canonical(first));
    let result = finish(&mut owner);
    census(&owner, &result);
    if matches!(mode, Some(RawMode::Reparse)) {
        assert!(result.is_err());
        assert_eq!(owner.history.len(), 1);
        assert_eq!(
            owner.pending_location_data(),
            Some(NativeImport18ResponseValueCutLocationData::Result(0))
        );
        let next = owner.pending.as_ref().unwrap().next.as_ref().unwrap();
        assert!(next.completed_data().is_err());
        assert!(next.maximum_intermediate_depth_data() >= 80);
        assert!(
            owner.banks[result_member]
                .custody
                .as_ref()
                .unwrap()
                .completed_bank_data()
                .is_ok()
        );
        assert_eq!(owner.schedule.state_data(), (true, false, true));
    } else {
        result.unwrap();
    }
}

fn at_action(action: Action) -> NativeImport18OwningResponseAttemptData {
    let mut owner = take(canonical(fields(&envelope(
        json!({"status":"completed","operation_state":"completed","extensions":{"one":true},"result":{"value":42}}),
    ))));
    for _ in 0..40 {
        if owner.action == Some(action) {
            return owner;
        }
        step(&mut owner).unwrap();
    }
    panic!("actual action was not reached");
}

fn effects(owner: &NativeImport18OwningResponseAttemptData) -> (usize, usize, usize, bool, bool) {
    (
        owner.banks.capacity(),
        owner.history.len(),
        owner
            .banks
            .iter()
            .filter(|slot| slot.custody.is_some())
            .count(),
        owner
            .pending
            .as_ref()
            .is_some_and(|p| p.selection.is_some()),
        owner.pending.as_ref().is_some_and(|p| p.next.is_some()),
    )
}

#[test]
fn every_real_action_exact_row_executes_and_each_one_short_axis_stops_before_effects() {
    for action in [
        Action::Start,
        Action::Advance,
        Action::TakeFirst,
        Action::QuoteFirst,
        Action::FreezeFirst,
        Action::Select,
        Action::TakeNext,
        Action::PrewalkNext,
        Action::QuoteNext,
        Action::RunNext,
        Action::Commit,
    ] {
        let mut exact = at_action(action);
        exact.quote_into_data(usize::MAX).unwrap();
        let (_, axes) = exact.requested_storage_data().unwrap();
        exact.row.as_mut().unwrap().maximum = sum(&[axes.0, axes.1, axes.2]).unwrap();
        exact.run_data().unwrap();
        census(&exact, &Ok(()));
        for axis in 0..3 {
            let mut owner = at_action(action);
            owner.quote_into_data(usize::MAX).unwrap();
            let before = effects(&owner);
            let row = owner.row.as_mut().unwrap();
            match axis {
                0 => row.retained -= 1,
                1 => row.transient -= 1,
                _ => row.scratch -= 1,
            }
            let result = owner.run_data();
            assert!(result.is_err());
            assert_eq!(effects(&owner), before);
            census(&owner, &result);
            assert!(owner.failed);
        }
    }
}

#[test]
fn actual_foreign_bank_selection_and_reused_output_cannot_replace_original_inputs() {
    let value = envelope(
        json!({"status":"completed","operation_state":"completed","extensions":{},"result":{"value":42}}),
    );
    let mut a = at_action(Action::Select);
    let b = at_action(Action::Select);
    let route = a.pending.as_ref().unwrap().cut.route;
    let bank_a = a.banks[route.body]
        .custody
        .as_ref()
        .unwrap()
        .completed_bank_data()
        .unwrap();
    let bank_b = b.banks[route.body]
        .custody
        .as_ref()
        .unwrap()
        .completed_bank_data()
        .unwrap();
    assert!(
        bank_a
            .response_row_data(bank_b.root_input_data().unwrap().selected, usize::MAX)
            .is_err()
    );
    step(&mut a).unwrap();
    assert!(a.pending.as_ref().unwrap().selection.is_some());
    let mut input = Some(canonical(fields(&value)));
    let input_bytes = input
        .as_ref()
        .unwrap()
        .retained_frame_data()
        .unwrap()
        .bytes
        .clone();
    let mut output = Some(a);
    assert!(
        NativeImport18OwningResponseAttemptData::take_into_data(&mut input, &mut output).is_err()
    );
    assert_eq!(
        input.as_ref().unwrap().retained_frame_data().unwrap().bytes,
        input_bytes
    );
    assert!(
        output
            .as_ref()
            .unwrap()
            .pending
            .as_ref()
            .unwrap()
            .selection
            .is_some()
    );
}

#[test]
fn structural_raw_keys_and_one_completed_text_result_do_not_acquire_an_extra_pass() {
    let protected = format!(r#"{{"z":0,"{RAW_VALUE_KEY}":"null"}}"#);
    let first = fields(&envelope(
        json!({"status":"completed","operation_state":"completed","extensions":{},"result":{"":0,RAW_VALUE_KEY:"null","value":{RAW_VALUE_KEY:protected}}}),
    ));
    let locked: Envelope =
        serde_json::from_value(first.retained_frame_data().unwrap().value.clone()).unwrap();
    let expected = serde_json::from_value::<ResponseShape>(Value::Object(locked.body));
    let mut owner = take(canonical(first));
    let result = finish(&mut owner);
    assert_eq!(result.is_ok(), expected.is_ok());
    census(&owner, &result);
    // The key is structural; the member is a String, not a root Raw object.
    assert_eq!(
        shallow(
            owner.history[1]
                .next
                .as_ref()
                .unwrap()
                .completed_data()
                .unwrap(),
            4
        ),
        json!("null")
    );
}

fn borrowed_prefix(raw: &RetainedFrame) -> (bool, Vec<NativeImport18ResponseValueCutLocationData>) {
    let row = NativeImport18EnvelopeFieldsConstructionData::quote_data(raw, usize::MAX).unwrap();
    let mut fields = None;
    NativeImport18EnvelopeFieldsAttemptData::read_into_data(raw, &row, &mut fields).unwrap();
    let fields = fields.as_ref().unwrap();
    let row =
        NativeImport18ResponseShapeCutsPreludeData::quote_data(raw, fields, usize::MAX).unwrap();
    let mut cursor = None;
    let result =
        NativeImport18ResponseShapeCutsData::read_into_data(raw, fields, &row, &mut cursor);
    if result.is_err() {
        return (false, Vec::new());
    }
    let cursor = cursor.as_mut().unwrap();
    let mut history = Vec::new();
    let mut locations = Vec::new();
    loop {
        let cut = match cursor.next_cut_data() {
            Ok(Some(cut)) => cut,
            Ok(None) => return (true, locations),
            Err(_) => return (false, locations),
        };
        let prewalk = cut.prewalk_data(usize::MAX).unwrap();
        let row = cut.quote_data(&prewalk, usize::MAX).unwrap();
        let mut next = None;
        if cut.read_into_data(&row, &mut next).is_err() {
            return (false, locations);
        }
        cursor.complete_cut_data(next.as_ref().unwrap()).unwrap();
        locations.push(cut.location_data());
        history.push(next);
    }
}

#[test]
fn both_real_adapters_preserve_locked_shallow_schema_refusals_and_completed_prefix_order() {
    let base = json!({"status":"completed","operation_state":"completed","extensions":{"one":true},"result":{"value":42}});
    let mut cases = vec![base.clone()];
    for key in ["a_unknown", "zz_unknown"] {
        let mut body = base.clone();
        body[key] = json!(0);
        cases.push(body);
    }
    for (key, value) in [
        ("operation_state", json!(false)),
        ("extensions", json!([])),
        ("result", json!(null)),
        ("status", json!("unknown")),
    ] {
        let mut body = base.clone();
        body[key] = value;
        cases.push(body);
    }
    let mut missing = base;
    missing.as_object_mut().unwrap().remove("operation_state");
    cases.push(missing);
    cases.push(json!({"status":"error","operation_state":"not_started","extensions":{},"error":{"code":"INVALID_ARGUMENT","details":{"detail":42},"effect":"not_started","message":"bad","retryable":false,"zz_unknown":null}}));
    for body in cases {
        let first = fields(&envelope(body));
        let raw = first.retained_frame_data().unwrap();
        let locked: Envelope = serde_json::from_value(raw.value.clone()).unwrap();
        let expected = serde_json::from_value::<ResponseShape>(Value::Object(locked.body));
        let borrowed = borrowed_prefix(raw);
        let mut owner = take(canonical(first));
        let result = finish(&mut owner);
        census(&owner, &result);
        assert_eq!(result.is_ok(), expected.is_ok());
        assert_eq!(result.is_ok(), borrowed.0);
        assert_eq!(
            owner
                .history
                .iter()
                .map(|pending| pending.cut.location)
                .collect::<Vec<_>>(),
            borrowed.1
        );
    }
}

#[test]
fn refused_actual_bank_allocation_quote_keeps_inline_first_and_original_frame() {
    let mut owner = at_action(Action::QuoteFirst);
    let route = owner.pending.as_ref().unwrap().cut.route;
    let original = owner
        .envelope
        .as_ref()
        .unwrap()
        .retained_frame_data()
        .unwrap()
        .bytes
        .clone();
    let result = owner.quote_into_data(0);
    assert!(result.is_err());
    census(&owner, &result);
    let custody = owner.banks[route.body].custody.as_ref().unwrap();
    assert!(custody.completed_bank_data().is_err());
    assert!(
        custody
            .retained_first_data()
            .unwrap()
            .completed_data()
            .is_ok()
    );
    assert_eq!(
        owner
            .envelope
            .as_ref()
            .unwrap()
            .retained_frame_data()
            .unwrap()
            .bytes,
        original
    );
    assert!(owner.pending.as_ref().unwrap().selection.is_none());
    assert!(owner.pending.as_ref().unwrap().next.is_none());
}

#[test]
fn top_level_extensions_keep_arbitrary_deep_flat_custody_without_a_global_ban() {
    let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let mut value = envelope(
        json!({"status":"completed","operation_state":"completed","extensions":{},"result":{"value":42}}),
    );
    value["extensions"] = json!({"deep":{RAW_VALUE_KEY:deep}});
    let first = fields(&value);
    let mut owner = take(canonical(first));
    finish(&mut owner).unwrap();
    census(&owner, &Ok(()));
    assert_eq!(owner.history.len(), 1);
    assert_eq!(owner.state_data(), (false, true, false));
    // Only the body is canonical-checked. The unrelated Envelope Extensions
    // FIRST and all of its actual flat histories remain owned in Envelope.
}
