//! Differential shallow boundaries and opaque deep failed ownership controls.

use super::*;
use serde::Deserialize;
use serde_json::json;

mod response;

fn frame(value: Value) -> RetainedFrame {
    RetainedFrame {
        bytes: serde_json::to_vec(&value).unwrap(),
        value,
    }
}

fn first(raw: &RetainedFrame) -> NativeImport18OwnedValuePassAttemptData<'_> {
    let row = NativeImport18OwnedValuePassConstructionData::quote_data(raw, &raw.value, usize::MAX)
        .unwrap();
    let mut output = None;
    NativeImport18OwnedValuePassAttemptData::read_into_data(raw, &raw.value, &row, &mut output)
        .unwrap();
    output.unwrap()
}

fn input<'a>(
    raw: &'a RetainedFrame,
    owner: &'a NativeImport18OwnedValuePassAttemptData<'_>,
) -> NativeImport18NextValueInputData<'a> {
    let value = owner.completed_data(raw, &raw.value).unwrap();
    NativeImport18NextValueInputData::selected_data(raw, owner, value).unwrap()
}

fn quote<'a>(
    input: NativeImport18NextValueInputData<'a>,
) -> NativeImport18NextValuePassConstructionData<'a> {
    let prewalk = NativeImport18NextValuePrewalkData::quote_data(input, usize::MAX).unwrap();
    NativeImport18NextValuePassConstructionData::quote_data(input, &prewalk, usize::MAX).unwrap()
}

fn shallow(value: NativeImport18NextValuePassViewData<'_>, remaining: usize) -> Value {
    assert!(
        remaining > 0,
        "this comparison helper must never construct a deep expected Value"
    );
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

fn assert_censused(owner: &NativeImport18NextValuePassAttemptData<'_>) {
    let requested_bytes = owner.retained_requested_storage_data(usize::MAX).unwrap();
    assert_eq!(
        owner.census_data(),
        NativeImport18NextValueCensusData::Observed {
            requested_bytes,
            within_row: requested_bytes <= owner.row.retained
        }
    );
}

#[test]
fn one_subsequent_pass_matches_locked_value_deserialize_at_the_actual_boundary() {
    let protected = format!(r#"{{"z":0,"{RAW_VALUE_KEY}":"null"}}"#);
    let wrong_type = format!(r#"{{"z":0,"{RAW_VALUE_KEY}":1}}"#);
    let nonfirst = format!(r#"{{"":0,"{RAW_VALUE_KEY}":"null"}}"#);
    let duplicate = r#"{"z":0,"a":1,"z":2}"#;
    for value in [
        json!(null),
        json!([0, {"a": true}]),
        json!({RAW_VALUE_KEY: protected}),
        json!({RAW_VALUE_KEY: wrong_type}),
        json!({RAW_VALUE_KEY: nonfirst}),
        json!({RAW_VALUE_KEY: duplicate}),
    ] {
        let raw = frame(value);
        // Every ordinary comparison owner in this control is shallow. This is
        // the exact first result, then ONE actual owned-Value Deserialize pass.
        let preceding = Value::deserialize(raw.value.clone()).unwrap();
        let expected = Value::deserialize(preceding);
        let prior = first(&raw);
        let input = input(&raw, &prior);
        let row = quote(input);
        let mut output = None;

        let actual =
            NativeImport18NextValuePassAttemptData::read_into_data(input, &row, &mut output);
        assert_eq!(actual.is_ok(), expected.is_ok());
        let owner = output.as_ref().unwrap();
        assert_censused(owner);
        if let Ok(expected) = expected {
            assert_eq!(shallow(owner.completed_data(input).unwrap(), 8), expected);
        }
    }
}

#[test]
fn deep_child_is_rooted_flat_before_a_late_extra_key_error_and_retry_cannot_clear_it() {
    let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let text = format!(
        r#"{{"z":0,"{RAW_VALUE_KEY}":{}}}"#,
        serde_json::to_string(&deep).unwrap()
    );
    let raw = frame(json!({RAW_VALUE_KEY: text}));
    let prior = first(&raw);
    let input = input(&raw, &prior);
    let row = quote(input);
    let mut output = None;

    let result = NativeImport18NextValuePassAttemptData::read_into_data(input, &row, &mut output);
    let owner = output.as_ref().unwrap();
    assert_censused(owner);
    if matches!(prior.state.mode, Some(RawMode::Reparse)) {
        assert!(result.is_err());
        assert!(owner.failed && !owner.complete);
        assert_eq!(owner.reparses.len(), 1);
        let child = owner.reparses[0].attempt.as_ref().unwrap();
        assert!(child.complete && !child.failed);
        assert!(child.maximum_intermediate_depth_data() >= 80);
    } else {
        assert!(result.is_ok());
    }
    let census = owner.census_data();

    assert!(
        NativeImport18NextValuePassAttemptData::read_into_data(input, &row, &mut output).is_err()
    );
    assert_eq!(output.as_ref().unwrap().census_data(), census);
    // No ordinary deep expected Value, clone, equality or destructor is used.
}

#[test]
fn actual_completed_text_child_is_not_fed_back_through_an_extra_owned_pass() {
    let child_text = format!(r#"{{"z":0,"{RAW_VALUE_KEY}":"null"}}"#);
    let text = format!(
        r#"{{"a":0,"{RAW_VALUE_KEY}":{}}}"#,
        serde_json::to_string(&child_text).unwrap()
    );
    let raw = frame(json!({RAW_VALUE_KEY: text}));
    let prior = first(&raw);
    let input = input(&raw, &prior);
    let row = quote(input);
    let mut output = None;
    let result = NativeImport18NextValuePassAttemptData::read_into_data(input, &row, &mut output);
    if !matches!(prior.state.mode, Some(RawMode::Reparse)) {
        assert!(result.is_ok());
        return;
    }

    assert!(result.is_err());
    let owner = output.as_ref().unwrap();
    let child = owner.reparses[0].attempt.as_ref().unwrap();
    assert!(child.complete && !child.failed);
    let NativeImport18EffectiveValueKindData::Object(mut fields) =
        child.completed_data().unwrap().kind_data().unwrap()
    else {
        panic!("text output must remain its actual object");
    };
    let (key, value) = fields.next().unwrap();
    assert_eq!(key, RAW_VALUE_KEY);
    assert!(matches!(
        value.kind_data().unwrap(),
        NativeImport18EffectiveValueKindData::String("null")
    ));
    assert_eq!(fields.count(), 1);
    let once: Value = serde_json::from_str(&child_text).unwrap();
    assert!(
        Value::deserialize(once).is_err(),
        "an accidental extra owned pass would refuse this completed child"
    );
    assert_censused(owner);
}

#[test]
fn equal_foreign_owner_or_selected_sibling_cannot_spend_the_actual_row() {
    let raw_a = frame(json!(["same", "same"]));
    let raw_b = frame(json!(["same", "same"]));
    let prior_a = first(&raw_a);
    let prior_b = first(&raw_b);
    let foreign = prior_b.completed_data(&raw_b, &raw_b.value).unwrap();
    assert!(NativeImport18NextValueInputData::selected_data(&raw_a, &prior_a, foreign).is_err());
    let NativeImport18OwnedValuePassKindData::Array(mut values) = prior_a
        .completed_data(&raw_a, &raw_a.value)
        .unwrap()
        .kind_data()
        .unwrap()
    else {
        panic!("array");
    };
    let first =
        NativeImport18NextValueInputData::selected_data(&raw_a, &prior_a, values.next().unwrap())
            .unwrap();
    let second =
        NativeImport18NextValueInputData::selected_data(&raw_a, &prior_a, values.next().unwrap())
            .unwrap();
    let row = quote(first);
    let NativeImport18OwnedValuePassKindData::Array(mut foreign_values) =
        foreign.kind_data().unwrap()
    else {
        panic!("array");
    };
    let foreign_input = NativeImport18NextValueInputData::selected_data(
        &raw_b,
        &prior_b,
        foreign_values.next().unwrap(),
    )
    .unwrap();
    let mut foreign_output = None;
    assert!(
        NativeImport18NextValuePassAttemptData::read_into_data(
            foreign_input,
            &row,
            &mut foreign_output
        )
        .is_err()
    );
    let foreign_owner = foreign_output.as_ref().unwrap();
    assert!(foreign_owner.failed && !foreign_owner.complete);
    assert_eq!(foreign_owner.reparses.capacity(), 0);
    assert_censused(foreign_owner);
    let mut output = None;
    assert!(
        NativeImport18NextValuePassAttemptData::read_into_data(second, &row, &mut output).is_err()
    );
    let owner = output.as_ref().unwrap();
    assert!(owner.failed && !owner.complete);
    assert_eq!(owner.reparses.capacity(), 0);
    assert_censused(owner);
}

#[test]
fn one_short_actual_spine_population_refuses_before_constructor_allocation() {
    let raw = frame(json!([0]));
    let prior = first(&raw);
    let input = input(&raw, &prior);
    let mut row = quote(input);
    row.prewalk.population -= 1;
    let mut output = None;
    assert!(matches!(
        NativeImport18NextValuePassAttemptData::read_into_data(input, &row, &mut output),
        Err(ProviderError::ResourceExhausted(_))
    ));
    let owner = output.as_ref().unwrap();
    assert!(owner.failed && !owner.complete);
    assert_eq!(owner.reparses.capacity(), 0);
    assert_censused(owner);
}

#[test]
fn no_cut_exact_row_constructs_and_one_short_refuses_with_the_actual_root_censused() {
    let raw = frame(Value::Null);
    let prior = first(&raw);
    let input = input(&raw, &prior);
    let row = quote(input);
    assert_eq!(row.reparses, 0);
    let mut exact = None;
    NativeImport18NextValuePassAttemptData::read_into_data(input, &row, &mut exact).unwrap();
    let exact = exact.as_ref().unwrap();
    assert_censused(exact);
    assert_eq!(
        exact.retained_requested_storage_data(usize::MAX).unwrap(),
        row.retained
    );
    assert_eq!(
        shallow(exact.completed_data(input).unwrap(), 1),
        Value::Null
    );

    let mut short = row;
    short.retained -= 1;
    let mut refused = None;
    assert!(
        NativeImport18NextValuePassAttemptData::read_into_data(input, &short, &mut refused)
            .is_err()
    );
    let refused = refused.as_ref().unwrap();
    assert_censused(refused);
    assert!(refused.failed && !refused.complete);
    assert_eq!(refused.reparses.capacity(), 0);
    assert_eq!(
        refused.census_data(),
        NativeImport18NextValueCensusData::Observed {
            requested_bytes: row.retained,
            within_row: false,
        }
    );
}

#[test]
fn same_raw_slot_can_change_only_after_all_prior_rows_and_outputs_are_retired() {
    let mut raw = Box::new(frame(Value::Null));
    let slot = &raw.value as *const Value;
    {
        let prior = first(&raw);
        let selected = input(&raw, &prior);
        let row = quote(selected);
        let mut output = None;
        NativeImport18NextValuePassAttemptData::read_into_data(selected, &row, &mut output)
            .unwrap();
        assert_eq!(
            shallow(
                output.as_ref().unwrap().completed_data(selected).unwrap(),
                1
            ),
            Value::Null
        );
        assert_censused(output.as_ref().unwrap());
    }

    raw.value = Value::Bool(true);
    raw.bytes = b"true".to_vec();
    assert!(std::ptr::eq(slot, &raw.value));
    let prior = first(&raw);
    let selected = input(&raw, &prior);
    let row = quote(selected);
    let mut output = None;
    NativeImport18NextValuePassAttemptData::read_into_data(selected, &row, &mut output).unwrap();
    assert_eq!(
        shallow(
            output.as_ref().unwrap().completed_data(selected).unwrap(),
            1
        ),
        Value::Bool(true)
    );
    assert_censused(output.as_ref().unwrap());
}

#[test]
fn immutable_first_row_still_rejects_an_equal_foreign_raw_bank() {
    let raw = frame(Value::Null);
    let equal = frame(Value::Null);
    let row =
        NativeImport18OwnedValuePassConstructionData::quote_data(&raw, &raw.value, usize::MAX)
            .unwrap();
    let mut output = None;
    assert!(
        NativeImport18OwnedValuePassAttemptData::read_into_data(
            &equal,
            &equal.value,
            &row,
            &mut output
        )
        .is_err()
    );
    let failed = output.as_ref().unwrap();
    assert!(failed.state.failed && !failed.state.complete);
    assert!(failed.completed_data(&equal, &equal.value).is_err());
    assert_eq!(failed.state.reparses.capacity(), 0);
    assert!(failed.retained_requested_storage_data(usize::MAX).unwrap() > 0);
}

#[test]
fn a_failed_second_attempt_keeps_its_real_first_bank_and_actual_census() {
    let raw = frame(Value::Null);
    let prior = first(&raw);
    let selected = input(&raw, &prior);
    let row = quote(selected);
    let mut short = row;
    short.retained -= 1;
    let mut output = None;
    assert!(
        NativeImport18NextValuePassAttemptData::read_into_data(selected, &short, &mut output)
            .is_err()
    );
    let failed = output.as_ref().unwrap();
    assert!(std::ptr::eq(failed.row.prewalk.raw, &raw));
    assert!(std::ptr::eq(failed.row.prewalk.first, &prior));
    assert!(matches!(
        prior
            .completed_data(&raw, &raw.value)
            .unwrap()
            .kind_data()
            .unwrap(),
        NativeImport18OwnedValuePassKindData::Null
    ));
    assert_censused(failed);
}
