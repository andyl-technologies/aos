//! Tests real owned FIRST-to-second boundaries; deep comparison stays flat.

use super::*;
use serde::Deserialize;
use serde_json::json;

fn selection(body: &[u8]) -> NativeImport18FirstSelectionData {
    let frozen = first_bank::tests::frozen(body);
    let row = frozen
        .completed_bank_data()
        .unwrap()
        .root_selection_row_data(usize::MAX)
        .unwrap();
    let mut output = None;
    NativeImport18FirstSelectionData::read_into_data(&row, &mut output).unwrap();
    output.unwrap()
}

fn take(body: &[u8]) -> NativeImport18OwningNextAttemptData {
    let mut selection = Some(selection(body));
    let mut owner = None;
    NativeImport18OwningNextAttemptData::take_into_data(&mut selection, &mut owner).unwrap();
    assert!(selection.is_none());
    owner.unwrap()
}

fn quoted(body: &[u8]) -> NativeImport18OwningNextAttemptData {
    let mut owner = take(body);
    owner.prewalk_into_data(usize::MAX).unwrap();
    owner.quote_into_data().unwrap();
    owner
}

fn shallow(value: NativeImport18NextValuePassViewData<'_>, remaining: usize) -> Value {
    assert!(remaining > 0, "comparison never owns deep user Values");
    match value.kind_data().unwrap() {
        NativeImport18NextValuePassKindData::Null => Value::Null,
        NativeImport18NextValuePassKindData::Bool(value) => Value::Bool(value),
        NativeImport18NextValuePassKindData::Number(value) => Value::Number(value.clone()),
        NativeImport18NextValuePassKindData::String(value) => Value::String(value.into()),
        NativeImport18NextValuePassKindData::Array(values) => {
            Value::Array(values.map(|value| shallow(value, remaining - 1)).collect())
        }
        NativeImport18NextValuePassKindData::Object(values) => Value::Object(
            values
                .map(|(key, value)| (key.into(), shallow(value, remaining - 1)))
                .collect(),
        ),
    }
}

fn assert_censused(owner: &NativeImport18OwningNextAttemptData) {
    let bytes = owner.retained_requested_storage_data(usize::MAX).unwrap();
    assert_eq!(
        owner.census_data(),
        NativeImport18OwningNextCensusData::Observed {
            requested_bytes: bytes,
            within_row: owner.row.as_ref().map(|row| bytes <= row.retained)
        }
    );
}

#[test]
fn actual_owning_second_matches_one_locked_pass_over_the_actual_first_result() {
    let protected = format!(r#"{{"z":0,"{RAW_VALUE_KEY}":"null"}}"#);
    let wrong_type = format!(r#"{{"z":0,"{RAW_VALUE_KEY}":1}}"#);
    let duplicate = r#"{"z":0,"a":1,"z":2}"#;
    for value in [
        json!(null),
        json!([0,{"a":true}]),
        json!({RAW_VALUE_KEY:protected}),
        json!({RAW_VALUE_KEY:wrong_type}),
        json!({RAW_VALUE_KEY:duplicate}),
    ] {
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut owner = quoted(&bytes);
        // Clone only this actual shallow FrameReader receipt; expected passes
        // start at the same decoded boundary as the owning first engine.
        let actual_raw = &owner
            .retained_selection_data()
            .unwrap()
            .input_data()
            .unwrap()
            .selected
            .loans
            .raw
            .value;
        let expected = Value::deserialize(Value::deserialize(actual_raw.clone()).unwrap());
        let result = owner.run_data();
        assert_eq!(result.is_ok(), expected.is_ok());
        assert_censused(&owner);
        if let Ok(expected) = expected {
            assert_eq!(shallow(owner.completed_data().unwrap(), 8), expected);
        }
    }
}

#[test]
fn owning_second_keeps_deep_child_before_late_extra_key_failure_without_an_extra_pass() {
    let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let text = format!(
        r#"{{"z":0,"{RAW_VALUE_KEY}":{}}}"#,
        serde_json::to_string(&deep).unwrap()
    );
    let bytes = serde_json::to_vec(&json!({RAW_VALUE_KEY:text})).unwrap();
    let mut owner = quoted(&bytes);
    let result = owner.run_data();
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
    assert_censused(&owner);
    let census = owner.census_data();
    assert!(owner.run_data().is_err());
    assert_eq!(owner.census_data(), census);
}

#[test]
fn actual_no_cut_exact_next_row_runs_and_every_one_short_axis_refuses_before_reserve() {
    let mut exact = quoted(b"null");
    let r = exact.requested_storage_data().unwrap().0;
    exact.run_data().unwrap();
    assert_eq!(
        exact.retained_requested_storage_data(usize::MAX).unwrap(),
        r
    );
    for axis in 0..3 {
        let mut short = quoted(b"null");
        let row = short.row.as_mut().unwrap();
        match axis {
            0 => row.retained -= 1,
            1 => row.transient -= 1,
            _ => row.scratch -= 1,
        }
        assert!(short.run_data().is_err());
        assert!(short.state.mode.is_none());
        assert_eq!(short.state.reparses.capacity(), 0);
        assert!(short.completed_data().is_err());
        assert_censused(&short);
    }
}

#[test]
fn independently_admitted_prewalk_is_required_before_real_logical_quote() {
    let mut owner = take(b"null");
    assert!(owner.quote_into_data().is_err());
    owner.prewalk_into_data(usize::MAX).unwrap();
    let (_, t, s) = owner.prewalk_requested_storage_data().unwrap();
    assert!(t > 0 && s > 0);
    owner.prewalk.as_mut().unwrap().transient -= 1;
    assert!(owner.quote_into_data().is_err());
    assert!(owner.row.is_none());
    assert!(owner.state.mode.is_none());
    assert_eq!(owner.state.reparses.capacity(), 0);
    assert_censused(&owner);
}

#[test]
fn moved_completed_owning_seconds_cannot_rebind_and_used_transfer_keeps_foreign_input() {
    let mut a = quoted(b"null");
    let mut b = quoted(b"true");
    a.run_data().unwrap();
    b.run_data().unwrap();
    let mut owners = vec![a, b];
    assert_eq!(shallow(owners[0].completed_data().unwrap(), 1), Value::Null);
    assert_eq!(
        shallow(owners[1].completed_data().unwrap(), 1),
        Value::Bool(true)
    );
    let mut foreign = Some(selection(b"true"));
    let mut used = Some(owners.remove(0));
    assert!(NativeImport18OwningNextAttemptData::take_into_data(&mut foreign, &mut used).is_err());
    assert!(foreign.is_some());
    let owner = used.as_mut().unwrap();
    assert!(owner.run_data().is_err());
    assert_eq!(shallow(owner.completed_data().unwrap(), 1), Value::Null);
    assert_censused(owner);
}

#[test]
fn actual_second_text_child_remains_once_normalized_before_its_parent_failure() {
    let child_text = format!(r#"{{"z":0,"{RAW_VALUE_KEY}":"null"}}"#);
    let text = format!(
        r#"{{"a":0,"{RAW_VALUE_KEY}":{}}}"#,
        serde_json::to_string(&child_text).unwrap()
    );
    let bytes = serde_json::to_vec(&json!({RAW_VALUE_KEY:text})).unwrap();
    let mut owner = quoted(&bytes);
    let result = owner.run_data();
    if matches!(owner.state.mode, Some(RawMode::Reparse)) {
        assert!(result.is_err());
        let child = owner.state.reparses[0].attempt.as_ref().unwrap();
        assert!(child.complete && !child.failed);
        let NativeImport18EffectiveValueKindData::Object(mut fields) =
            child.completed_data().unwrap().kind_data().unwrap()
        else {
            panic!("actual text child must remain an object");
        };
        let (key, value) = fields.next().unwrap();
        assert_eq!(key, RAW_VALUE_KEY);
        assert!(matches!(
            value.kind_data().unwrap(),
            NativeImport18EffectiveValueKindData::String("null")
        ));
        assert_eq!(fields.count(), 1);
        let once: Value = serde_json::from_str(&child_text).unwrap();
        assert!(Value::deserialize(once).is_err());
    } else {
        assert!(result.is_ok());
    }
    assert_censused(&owner);
}

#[test]
fn actual_owned_next_quote_exact_total_runs_and_one_short_retains_unstarted_custody() {
    let measured = quoted(b"null");
    let (r, t, s) = measured.requested_storage_data().unwrap();
    let total = r.checked_add(t).unwrap().checked_add(s).unwrap();
    let mut exact = take(b"null");
    exact.prewalk_into_data(total).unwrap();
    exact.quote_into_data().unwrap();
    assert_eq!(exact.requested_storage_data().unwrap(), (r, t, s));
    exact.run_data().unwrap();
    assert_eq!(shallow(exact.completed_data().unwrap(), 1), Value::Null);
    assert_censused(&exact);
    let mut short = take(b"null");
    short.prewalk_into_data(total - 1).unwrap();
    assert!(short.quote_into_data().is_err());
    assert!(short.row.is_none());
    assert!(short.state.mode.is_none());
    assert_eq!(short.state.reparses.capacity(), 0);
    assert!(matches!(
        short
            .retained_selection_data()
            .unwrap()
            .input_data()
            .unwrap()
            .selected
            .kind_data()
            .unwrap(),
        SourceKind::Null
    ));
    assert_censused(&short);
}
