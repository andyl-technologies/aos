//! Exercises lossless number custody, generic JSON and independent storage bounds.

use super::*;
use crucible_node_format::canonical;
use serde_json::{Number, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn check_round_trip(value: &Value) -> TestResult {
    let canonical = canonical::canonical_json(value)?;
    let maximum = CompactJson::maximum_storage_bytes(canonical.len(), usize::MAX)?;
    let exact = CompactJson::storage_bytes(value, maximum)?;
    let original = CompactJson::from_value(value, exact)?;

    assert_eq!(original.retained_bytes(), exact);
    assert!(original.retained_bytes() <= maximum);
    assert_eq!(original.to_value()?, *value);
    assert_eq!(
        serde_json::to_vec(&original.as_serializable())?,
        serde_json::to_vec(value)?
    );
    Ok(())
}

#[test]
fn numbers_preserve_variants_and_exact_bits_instead_of_jcs_normalization() -> TestResult {
    let mut numbers = vec![
        Number::from(0),
        Number::from(u64::MAX),
        Number::from(i64::MIN),
        Number::from(9_007_199_254_740_993_u64),
    ];
    for value in [
        -0.0,
        0.0,
        1.0,
        -1.0,
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        f64::MAX,
        1.0000000000000002,
        2.2250738585072014e-308,
    ] {
        numbers.push(Number::from_f64(value).unwrap());
    }

    for number in numbers {
        let original = Value::Number(number.clone());
        check_round_trip(&original)?;
        let stored = CompactJson::from_value(&original, 9)?;
        let restored = stored.to_value()?;
        let restored = restored.as_number().unwrap();

        assert_eq!(restored.is_f64(), number.is_f64());
        assert_eq!(restored.as_i64(), number.as_i64());
        assert_eq!(restored.as_u64(), number.as_u64());
        assert_eq!(
            restored.as_f64().unwrap().to_bits(),
            number.as_f64().unwrap().to_bits()
        );
    }
    Ok(())
}

#[test]
fn arbitrary_error_details_poll_outcomes_and_unicode_keys_are_retained() -> TestResult {
    let value = json!({
        "error": {"details": {
            "nested": [{"": []}, {"\u{0}\n\"\\": {"𐀀": "雪", "\u{e000}": null}}],
            "truth": [true, false],
        }},
        "poll": {"outcome": {"result": {"unexpected": [{"deep": [0, -1, 2.5]}]}}},
    });

    check_round_trip(&value)?;
    let stored = CompactJson::from_value(&value, usize::MAX)?;
    let mut output = [0; 4096];
    let mut writer = std::io::Cursor::new(output.as_mut_slice());
    serde_json::to_writer(&mut writer, &stored.as_serializable())?;
    let length = usize::try_from(writer.position())?;

    assert_eq!(&output[..length], serde_json::to_vec(&value)?.as_slice());
    Ok(())
}

#[test]
fn independent_grammar_families_obey_the_shared_canonical_bound() -> TestResult {
    for value in [
        Value::Null,
        json!(true),
        json!(false),
        json!(""),
        json!([]),
        json!({}),
    ] {
        check_round_trip(&value)?;
    }

    for count in [1, 5, 11, 12, 63, 257, 4096] {
        let numbers = Value::Array(vec![json!(0); count]);
        let empty_objects = Value::Array(vec![json!({}); count]);
        let one_entry_objects = Value::Array(vec![json!({"": 0}); count]);
        let map = Value::Object(
            (0..count)
                .map(|index| (index.to_string(), json!(0)))
                .collect(),
        );

        for value in [&numbers, &empty_objects, &one_entry_objects, &map] {
            check_round_trip(value)?;
        }
    }
    Ok(())
}

#[test]
fn caller_spare_capacity_is_neither_copied_nor_counted_as_bank_storage() -> TestResult {
    let mut text = String::with_capacity(1_048_576);
    text.push('x');
    let mut array = Vec::with_capacity(16_384);
    array.push(Value::String(text));
    let value = Value::Array(array);

    let requested = CompactJson::storage_bytes(&value, 27)?;
    let stored = CompactJson::from_value(&value, requested)?;
    assert_eq!(stored.retained_bytes(), 27);
    assert_eq!(stored.to_value()?, value);
    assert_eq!(value.as_array().unwrap().capacity(), 16_384);
    assert_eq!(value[0].as_str(), Some("x"));
    Ok(())
}

#[test]
fn maximum_portable_array_and_depth_fit_but_excess_refuses() -> TestResult {
    let array = Value::Array(vec![Value::Null; crucible_node_format::MAX_ARRAY_ELEMENTS]);
    check_round_trip(&array)?;
    let excessive = Value::Array(vec![
        Value::Null;
        crucible_node_format::MAX_ARRAY_ELEMENTS + 1
    ]);
    assert!(CompactJson::storage_bytes(&excessive, usize::MAX).is_err());
    assert!(CompactJson::from_value(&excessive, usize::MAX).is_err());

    let mut nested = Value::Null;
    for _ in 0..64 {
        nested = Value::Array(vec![nested]);
    }
    check_round_trip(&nested)?;
    let excessive = Value::Array(vec![nested]);
    assert!(CompactJson::storage_bytes(&excessive, usize::MAX).is_err());
    assert!(CompactJson::from_value(&excessive, usize::MAX).is_err());
    Ok(())
}

#[test]
fn insufficient_or_overflowing_restrictions_refuse_without_changing_input() -> TestResult {
    let value = json!({"original": [1, 2, 3]});
    let before = value.clone();
    let requested = CompactJson::storage_bytes(&value, usize::MAX)?;

    assert!(CompactJson::storage_bytes(&value, requested - 1).is_err());
    assert!(CompactJson::from_value(&value, requested - 1).is_err());
    assert!(CompactJson::from_value(&Value::Null, 0).is_err());
    assert!(CompactJson::maximum_storage_bytes(usize::MAX, usize::MAX).is_err());
    assert!(CompactJson::maximum_storage_bytes(2, 17).is_err());
    assert_eq!(CompactJson::maximum_storage_bytes(2, 18)?, 18);
    assert_eq!(value, before);
    Ok(())
}
