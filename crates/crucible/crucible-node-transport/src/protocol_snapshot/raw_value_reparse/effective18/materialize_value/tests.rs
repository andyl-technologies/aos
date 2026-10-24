//! Exercises real text owners, constructor rows and retained failed prefixes.

use super::*;

fn source(input: &str) -> NativeImport18EffectiveTextAttemptData {
    let row = NativeImport18EffectiveTextConstructionData::quote_data(input, usize::MAX).unwrap();
    let mut output = None;
    NativeImport18EffectiveTextAttemptData::read_into_data(input, &row, &mut output).unwrap();
    output.unwrap()
}

fn take(input: &str) -> NativeImport18GuardedValueAttemptData {
    let mut source = Some(source(input));
    let pointer = source.as_ref().unwrap().nodes.as_ptr();
    let mut output = None;
    NativeImport18GuardedValueAttemptData::take_requested_storage_data().unwrap();
    NativeImport18GuardedValueAttemptData::take_into_data(&mut source, &mut output).unwrap();
    assert!(source.is_none());
    let owner = output.unwrap();
    assert_eq!(owner.source.as_ref().unwrap().nodes.as_ptr(), pointer);
    owner
}

fn total(row: [usize; 3]) -> usize {
    row.into_iter()
        .try_fold(0usize, usize::checked_add)
        .unwrap()
}

fn assert_matches_flat(owner: &NativeImport18GuardedValueAttemptData) {
    let source = owner.source.as_ref().unwrap().completed_data().unwrap();
    let mut work = vec![(source, owner.completed_data().unwrap())];
    while let Some((source, actual)) = work.pop() {
        match (source.kind_data().unwrap(), actual) {
            (NativeImport18EffectiveValueKindData::Null, Value::Null) => {}
            (NativeImport18EffectiveValueKindData::Bool(a), Value::Bool(b)) => assert_eq!(a, *b),
            (NativeImport18EffectiveValueKindData::Number(a), Value::Number(b)) => assert_eq!(a, b),
            (NativeImport18EffectiveValueKindData::String(a), Value::String(b)) => assert_eq!(a, b),
            (NativeImport18EffectiveValueKindData::Array(source), Value::Array(actual)) => {
                let mut source = source;
                for actual in actual {
                    work.push((source.next().unwrap(), actual));
                }
                assert!(source.next().is_none());
            }
            (NativeImport18EffectiveValueKindData::Object(source), Value::Object(actual)) => {
                let mut source = source;
                for (key, actual) in actual {
                    let (expected_key, child) = source.next().unwrap();
                    assert_eq!(key, expected_key);
                    work.push((child, actual));
                }
                assert!(source.next().is_none());
            }
            _ => panic!("materialized kind differs from its actual flat operand"),
        }
    }
}

#[test]
fn shallow_actual_operands_match_locked_serde_and_duplicate_semantics() {
    for input in [
        "null",
        "[]",
        "{}",
        "18446744073709551615",
        r#"[false, -0.0, 1e-20, "\ud83d\ude80"]"#,
        r#"{"b":[{},[],"value"],"a":1,"a":3}"#,
        r#"{"\u0061":1,"a":2}"#,
        r#"{"$serde_json::private::RawValue":"[1,\"x\"]"}"#,
        r#"{"z":0,"$serde_json::private::RawValue":"null"}"#,
    ] {
        let mut owner = take(input);
        let row = owner.quote_into_data(usize::MAX).unwrap();
        owner.run_data().unwrap();
        assert_eq!(
            owner.completed_data().unwrap(),
            &serde_json::from_str::<Value>(input).unwrap()
        );
        assert_matches_flat(&owner);
        assert!(owner.retained_requested_storage_data(usize::MAX).unwrap() <= row[0]);
        assert!(owner.run_data().is_err());
        assert!(owner.quote_into_data(usize::MAX).is_err());
    }
}

#[test]
fn exact_quote_and_one_short_use_the_same_actual_operand() {
    let input = r#"{"long-key":[{"leaf":"payload"},[],null],"other":{"a":1}}"#;
    let mut probe = take(input);
    let row = probe.quote_into_data(usize::MAX).unwrap();
    let exact = total(row);

    let mut owner = take(input);
    assert_eq!(owner.quote_into_data(exact).unwrap(), row);
    owner.run_data().unwrap();
    assert_matches_flat(&owner);

    let mut short = take(input);
    let pointer = short.source.as_ref().unwrap().nodes.as_ptr();
    assert!(short.quote_into_data(exact - 1).is_err());
    assert!(short.stage == Stage::Failed);
    assert!(short.run_data().is_err());
    assert!(short.quote_into_data(exact).is_err());
    assert_eq!(short.source.as_ref().unwrap().nodes.as_ptr(), pointer);
    assert_eq!(short.work.capacity(), 0);
    assert_eq!(short.frames.capacity(), 0);
    assert_eq!(short.retirement.capacity(), 0);
}

#[test]
fn actual_reverse_key_insertion_and_map_retirement_cross_multiple_tree_nodes() {
    let members = (0..256)
        .map(|index| format!(r#""key-{index:04}":[{index},{{"empty":{{}}}}]"#))
        .collect::<Vec<_>>()
        .join(",");
    let input = format!("{{{members}}}");
    let mut owner = take(&input);
    let row = owner.quote_into_data(usize::MAX).unwrap();
    owner.run_data().unwrap();
    assert_matches_flat(&owner);
    assert_eq!(
        owner.completed_data().unwrap().as_object().unwrap().len(),
        256
    );
    assert!(owner.retained_requested_storage_data(usize::MAX).unwrap() <= row[0]);

    let capacity = owner.retirement.capacity();
    owner.retire_all_data();
    assert_eq!(owner.retirement.capacity(), capacity);
    assert_eq!(owner.tree_members, 0);
    assert_eq!(owner.tree_containers, 0);
    assert!(owner.retirement.is_empty());
}

#[test]
fn actual_failed_text_is_retained_without_materialization_or_retry() {
    let input = r#"{"first":[1,2],"second":"unterminated}"#;
    let row = NativeImport18EffectiveTextConstructionData::quote_data(input, usize::MAX).unwrap();
    let mut source = None;
    assert!(
        NativeImport18EffectiveTextAttemptData::read_into_data(input, &row, &mut source).is_err()
    );
    let pointer = source.as_ref().unwrap().nodes.as_ptr();
    let mut output = None;
    assert!(
        NativeImport18GuardedValueAttemptData::take_into_data(&mut source, &mut output).is_err()
    );
    assert!(source.is_none());
    let failed = output.as_mut().unwrap();
    assert_eq!(failed.source.as_ref().unwrap().nodes.as_ptr(), pointer);
    assert!(failed.quote_into_data(usize::MAX).is_err());
    assert!(failed.run_data().is_err());
    assert!(failed.retained_requested_storage_data(usize::MAX).unwrap() > 0);
}

#[test]
fn missing_input_spends_output_and_cannot_take_a_later_source() {
    let mut missing = None;
    let mut output = None;
    assert!(
        NativeImport18GuardedValueAttemptData::take_into_data(&mut missing, &mut output).is_err()
    );
    assert!(output.as_ref().unwrap().stage == Stage::Failed);

    let mut later = Some(source(r#"{"actual":"later"}"#));
    let pointer = later.as_ref().unwrap().nodes.as_ptr();
    assert!(
        NativeImport18GuardedValueAttemptData::take_into_data(&mut later, &mut output).is_err()
    );
    assert_eq!(later.as_ref().unwrap().nodes.as_ptr(), pointer);
    assert!(output.as_ref().unwrap().source.is_none());
    assert!(
        output
            .as_mut()
            .unwrap()
            .quote_into_data(usize::MAX)
            .is_err()
    );
    assert!(output.as_mut().unwrap().run_data().is_err());
}

#[test]
fn every_interrupted_constructor_prefix_remains_owned_and_retires_in_place() {
    let input = r#"{"a":[{"deep":[1,2,3]},"key"],"b":[[null],{}]}"#;
    let mut probe = take(input);
    probe.quote_into_data(usize::MAX).unwrap();
    probe.run_data().unwrap();
    let steps = probe.steps;

    for step in 1..=steps {
        let mut owner = take(input);
        let row = owner.quote_into_data(usize::MAX).unwrap();
        let pointer = owner.source.as_ref().unwrap().nodes.as_ptr();
        owner.fail_after = Some(step);
        assert!(owner.run_data().is_err());
        assert!(owner.stage == Stage::Failed);
        assert_eq!(owner.source.as_ref().unwrap().nodes.as_ptr(), pointer);
        assert!(owner.retained_requested_storage_data(usize::MAX).unwrap() <= row[0]);
        assert!(owner.run_data().is_err());

        let capacity = owner.retirement.capacity();
        owner.retire_all_data();
        assert_eq!(owner.retirement.capacity(), capacity);
        assert!(owner.frames.is_empty());
        assert!(owner.work.is_empty());
        assert!(owner.retirement.is_empty());
        assert!(owner.root.is_none());
        assert!(owner.pending.is_none());
        assert!(owner.pending_old.is_none());
    }
}

#[test]
fn unwind_keeps_the_same_partial_owner_and_refuses_reentry() {
    let input = r#"{"a":[[[[1]]]],"b":[2,3]}"#;
    let mut probe = take(input);
    probe.quote_into_data(usize::MAX).unwrap();
    probe.run_data().unwrap();

    let mut owner = take(input);
    let row = owner.quote_into_data(usize::MAX).unwrap();
    let pointer = owner.source.as_ref().unwrap().nodes.as_ptr();
    // Interrupt immediately before the root Finish: the same open root frame
    // already owns the completed nested child instead of only scalar work.
    owner.panic_after = Some(probe.steps);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.run_data())).is_err());
    assert!(owner.stage == Stage::Running);
    assert_eq!(owner.source.as_ref().unwrap().nodes.as_ptr(), pointer);
    assert!(owner.retained_requested_storage_data(usize::MAX).unwrap() <= row[0]);
    assert!(owner.run_data().is_err());
    assert!(owner.quote_into_data(usize::MAX).is_err());
    owner.retire_all_data();
    assert!(owner.retirement.is_empty());
}

#[test]
fn actual_raw_resets_materialize_without_a_new_depth_cap_or_recursive_comparison() {
    let mut input = "null".to_owned();
    for _ in 0..3 {
        let inner = format!("{}{}{}", "[".repeat(45), input, "]".repeat(45));
        input = format!(
            r#"{{"$serde_json::private::RawValue":{}}}"#,
            serde_json::to_string(&inner).unwrap()
        );
    }
    let mut owner = take(&input);
    let row = owner.quote_into_data(usize::MAX).unwrap();
    owner.run_data().unwrap();
    assert_matches_flat(&owner);
    assert!(owner.retained_requested_storage_data(usize::MAX).unwrap() <= row[0]);

    // This tests the actual build's existing semantics, without choosing a
    // feature mode or passing the expanded tree to ordinary recursive serde.
    if matches!(owner.source.as_ref().unwrap().mode, Some(RawMode::Reparse)) {
        let mut value = owner.completed_data().unwrap();
        let mut depth = 0usize;
        while let Value::Array(values) = value {
            assert_eq!(values.len(), 1);
            value = &values[0];
            depth += 1;
        }
        assert_eq!(depth, 135);
        assert!(matches!(value, Value::Null));
    }

    let capacity = owner.retirement.capacity();
    owner.retire_all_data();
    assert_eq!(owner.retirement.capacity(), capacity);
    assert!(owner.root.is_none());
    assert!(owner.retirement.is_empty());
}
