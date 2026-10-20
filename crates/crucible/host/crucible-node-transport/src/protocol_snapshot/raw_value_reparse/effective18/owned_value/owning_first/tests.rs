//! Exercises actual owning inputs and the shared first engine without deep Values.

use super::*;
use crate::transport::FrameReader;
use serde::Deserialize;
use serde_json::json;
use std::io::Cursor;

fn input(body: &[u8]) -> NativeImport18RawSelectionData {
    let mut wire = Vec::new();
    wire.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(body);
    let mut received = FrameReader::new(Cursor::new(wire), body.len())
        .unwrap()
        .read_retained()
        .unwrap();
    let mut custody = None;
    NativeImport18ImmutableRawCustodyData::take_into_data(&mut received, &mut custody).unwrap();
    let custody = custody.as_mut().unwrap();
    custody.quote_into_data(usize::MAX).unwrap();
    custody.freeze_data().unwrap();
    let row = custody
        .completed_bank_data()
        .unwrap()
        .root_selection_row_data(usize::MAX)
        .unwrap();
    let mut selected = None;
    NativeImport18RawSelectionData::read_into_data(&row, &mut selected).unwrap();
    selected.unwrap()
}

fn take(selection: NativeImport18RawSelectionData) -> NativeImport18OwningFirstAttemptData {
    let mut selection = Some(selection);
    let mut output = None;
    NativeImport18OwningFirstAttemptData::take_into_data(&mut selection, &mut output).unwrap();
    assert!(selection.is_none());
    output.unwrap()
}

fn shallow(value: NativeImport18FirstFlatViewData<'_>, remaining: usize) -> Value {
    assert!(
        remaining > 0,
        "comparison must never materialize a deep user Value"
    );
    match value.kind_data().unwrap() {
        NativeImport18FirstFlatKindData::Null => Value::Null,
        NativeImport18FirstFlatKindData::Bool(value) => Value::Bool(value),
        NativeImport18FirstFlatKindData::Number(value) => Value::Number(value.clone()),
        NativeImport18FirstFlatKindData::String(value) => Value::String(value.into()),
        NativeImport18FirstFlatKindData::Array(values) => {
            Value::Array(values.map(|value| shallow(value, remaining - 1)).collect())
        }
        NativeImport18FirstFlatKindData::Object(values) => Value::Object(
            values
                .map(|(key, value)| (key.into(), shallow(value, remaining - 1)))
                .collect(),
        ),
    }
}

fn assert_censused(owner: &NativeImport18OwningFirstAttemptData) {
    let bytes = owner.retained_requested_storage_data(usize::MAX).unwrap();
    assert_eq!(
        owner.census_data(),
        NativeImport18OwningFirstCensusData::Observed {
            requested_bytes: bytes,
            within_row: owner.row.as_ref().map(|row| bytes <= row.retained),
        }
    );
}

#[test]
fn owning_and_borrowed_adapters_match_one_locked_first_pass_on_real_shallow_receipts() {
    for value in [
        json!(null),
        json!([1, true]),
        json!({"a":1}),
        json!({RAW_VALUE_KEY:"null"}),
        json!({RAW_VALUE_KEY:1}),
        json!({RAW_VALUE_KEY:"{\"z\":0,\"a\":1,\"z\":2}"}),
    ] {
        let bytes = serde_json::to_vec(&value).unwrap();
        let selection = input(&bytes);
        let expected = Value::deserialize(selection.value_data().unwrap().clone());
        {
            let raw = selection.retained_frame_data().unwrap();
            let value = selection.value_data().unwrap();
            let row =
                NativeImport18OwnedValuePassConstructionData::quote_data(raw, value, usize::MAX)
                    .unwrap();
            let mut borrowed = None;
            let result = NativeImport18OwnedValuePassAttemptData::read_into_data(
                raw,
                value,
                &row,
                &mut borrowed,
            );
            assert_eq!(result.is_ok(), expected.is_ok());
            if result.is_ok() {
                // Both adapters reach the very same shared flat projection.
                let owner = borrowed.as_ref().unwrap();
                assert_eq!(
                    shallow(state_view::raw_data(&owner.state, value), 8),
                    expected.as_ref().unwrap().clone()
                );
                assert!(owner.completed_data(raw, value).is_ok());
            }
        }
        let mut owner = take(selection);
        owner.quote_into_data(usize::MAX).unwrap();
        let result = owner.run_data();
        assert_eq!(result.is_ok(), expected.is_ok());
        assert_censused(&owner);
        if let Ok(expected) = expected {
            assert_eq!(shallow(owner.completed_data().unwrap(), 8), expected);
        }
    }
}

#[test]
fn late_extra_raw_key_keeps_a_real_deep_flat_child_without_success_allocation_or_retry() {
    let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let body = format!(
        r#"{{"{RAW_VALUE_KEY}":{},"z":0}}"#,
        serde_json::to_string(&deep).unwrap()
    );
    let mut owner = take(input(body.as_bytes()));
    owner.quote_into_data(usize::MAX).unwrap();
    let result = owner.run_data();
    assert_censused(&owner);
    if matches!(owner.state.mode, Some(RawMode::Reparse)) {
        assert!(result.is_err());
        assert_eq!(owner.state.reparses.len(), 1);
        let child = owner.state.reparses[0].attempt.as_ref().unwrap();
        assert!(child.complete && !child.failed);
        assert!(child.maximum_intermediate_depth_data() >= 80);
        assert!(owner.maximum_intermediate_depth_data() >= 80);
        assert!(owner.completed_data().is_err());
    } else {
        assert!(result.is_ok());
    }
    let bytes = owner.retained_requested_storage_data(usize::MAX).unwrap();
    assert!(owner.run_data().is_err());
    assert_eq!(
        owner.retained_requested_storage_data(usize::MAX).unwrap(),
        bytes
    );
    assert_eq!(
        owner
            .retained_selection_data()
            .unwrap()
            .retained_frame_data()
            .unwrap()
            .bytes,
        body.as_bytes()
    );
}

#[test]
fn completed_owning_input_and_state_move_by_value_without_foreign_rebinding() {
    let mut a = take(input(b"null"));
    let mut b = take(input(b"true"));
    a.quote_into_data(usize::MAX).unwrap();
    b.quote_into_data(usize::MAX).unwrap();
    a.run_data().unwrap();
    b.run_data().unwrap();
    let mut owners = vec![a, b];

    assert_eq!(shallow(owners[0].completed_data().unwrap(), 1), Value::Null);
    assert_eq!(
        shallow(owners[1].completed_data().unwrap(), 1),
        Value::Bool(true)
    );
    assert!(owners[0].run_data().is_err());
    assert!(owners[0].quote_into_data(usize::MAX).is_err());
    assert_eq!(shallow(owners[0].completed_data().unwrap(), 1), Value::Null);
    assert_eq!(
        owners[0]
            .retained_selection_data()
            .unwrap()
            .retained_frame_data()
            .unwrap()
            .bytes,
        b"null"
    );
    for owner in &owners {
        assert_censused(owner);
    }
}

#[test]
fn real_no_cut_exact_row_runs_and_every_one_short_axis_stops_before_the_probe() {
    let mut exact = take(input(b"null"));
    exact.quote_into_data(usize::MAX).unwrap();
    let exact_r = exact.requested_storage_data().unwrap().0;
    exact.run_data().unwrap();
    assert_eq!(
        exact.retained_requested_storage_data(usize::MAX).unwrap(),
        exact_r
    );
    for axis in 0..3 {
        let mut owner = take(input(b"null"));
        owner.quote_into_data(usize::MAX).unwrap();
        owner.row.as_mut().unwrap().shorten_axis_data(axis);
        assert!(owner.run_data().is_err());
        assert!(owner.state.mode.is_none());
        assert_eq!(owner.state.reparses.capacity(), 0);
        assert!(owner.completed_data().is_err());
        assert!(
            owner
                .retained_selection_data()
                .unwrap()
                .value_data()
                .unwrap()
                .is_null()
        );
        assert_censused(&owner);
    }
}

#[test]
fn a_used_owning_take_keeps_the_new_selection_and_original_failed_prefix_separate() {
    let mut original = Some(input(b"null"));
    let mut output = None;
    NativeImport18OwningFirstAttemptData::take_into_data(&mut original, &mut output).unwrap();
    assert!(output.as_mut().unwrap().quote_into_data(0).is_err());
    let mut foreign = Some(input(b"true"));
    assert!(
        NativeImport18OwningFirstAttemptData::take_into_data(&mut foreign, &mut output).is_err()
    );
    assert_eq!(
        foreign.as_ref().unwrap().value_data().unwrap(),
        &Value::Bool(true)
    );
    let failed = output.as_ref().unwrap();
    assert!(
        failed
            .retained_selection_data()
            .unwrap()
            .value_data()
            .unwrap()
            .is_null()
    );
    assert!(failed.completed_data().is_err());
    assert_censused(failed);
}

#[test]
fn fresh_flat_text_is_projected_without_an_accidental_second_owned_value_pass() {
    let text = format!(r#"{{"z":0,"{RAW_VALUE_KEY}":"null"}}"#);
    let body = format!(
        r#"{{"{RAW_VALUE_KEY}":{}}}"#,
        serde_json::to_string(&text).unwrap()
    );
    let mut owner = take(input(body.as_bytes()));
    owner.quote_into_data(usize::MAX).unwrap();
    owner.run_data().unwrap();
    if matches!(owner.state.mode, Some(RawMode::Reparse)) {
        let once = shallow(owner.completed_data().unwrap(), 8);
        assert_eq!(once[RAW_VALUE_KEY], Value::String("null".into()));
        assert!(Value::deserialize(once).is_err());
        assert_eq!(owner.state.reparses.len(), 1);
    }
    assert_censused(&owner);
}

#[test]
fn actual_quote_exact_total_runs_and_one_short_keeps_its_unstarted_input() {
    // The fixed prelude is a prerequisite to calling the actual quotation;
    // the complete row below is a separate admission before execution.
    let (_, _, prequote_s) = NativeImport18OwningFirstAttemptData::take_requested_storage_data();
    assert!(prequote_s >= NativeImport18OwnedValuePassConstructionData::counter_scratch_data());
    let mut measured = take(input(b"null"));
    measured.quote_into_data(usize::MAX).unwrap();
    let (r, t, s) = measured.requested_storage_data().unwrap();
    let total = r.checked_add(t).unwrap().checked_add(s).unwrap();

    let mut exact = take(input(b"null"));
    exact.quote_into_data(total).unwrap();
    assert_eq!(exact.requested_storage_data().unwrap(), (r, t, s));
    exact.run_data().unwrap();
    assert_eq!(shallow(exact.completed_data().unwrap(), 1), Value::Null);
    assert_censused(&exact);

    let mut short = take(input(b"null"));
    assert!(short.quote_into_data(total - 1).is_err());
    assert!(short.row.is_none());
    assert!(short.state.mode.is_none());
    assert_eq!(short.state.reparses.capacity(), 0);
    assert!(short.requested_storage_data().is_err());
    assert!(short.run_data().is_err());
    assert_eq!(
        short
            .retained_selection_data()
            .unwrap()
            .retained_frame_data()
            .unwrap()
            .bytes,
        b"null"
    );
    assert_censused(&short);
}
