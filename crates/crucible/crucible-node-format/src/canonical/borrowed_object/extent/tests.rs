//! Compares bounded borrowed validation with the defining canonical byte oracle.

use super::*;
use crate::canonical::canonical_json;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn compare(values: &Map<String, Value>) -> TestResult {
    let expected = canonical_json(&Value::Object(values.clone()))?.len();

    assert_eq!(
        canonical_json_object_length_with_limit(values, expected)?,
        Some(expected)
    );
    assert_eq!(
        canonical_json_object_length_with_limit(values, usize::MAX)?,
        Some(expected)
    );
    assert_eq!(
        canonical_json_object_length_with_limit(values, expected - 1)?,
        None
    );
    assert_eq!(canonical_json_object_length_with_limit(values, 0)?, None);
    Ok(())
}

#[test]
fn borrowed_extent_matches_complete_escaping_unicode_and_marker_key_data() -> TestResult {
    let controls: String = (0u8..=127).map(char::from).collect();
    let values = serde_json::from_value(json!({
        "\u{e000}": {"\u{10000}": [null, false, true, {}, [], controls]},
        "\u{10000}": {"\u{e000}": "雪🙂\u{2028}\u{2029}"},
        "$serde_json::private::RawValue": "ordinary DATA",
        "$serde_json::private::Number": {"nested": "1e+42"}
    }))?;
    compare(&values)?;
    compare(&Map::new())?;
    Ok(())
}

#[test]
fn numeric_extent_uses_defining_jcs_and_preserves_original_number_bits() -> TestResult {
    let mut numbers = vec![
        json!(i64::MIN),
        json!(u64::MAX),
        json!(9_007_199_254_740_993_u64),
    ];
    for number in [
        -0.0,
        0.0,
        1.0,
        -1.0,
        1e-7,
        1e-6,
        1e20,
        1e21,
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        f64::MAX,
    ] {
        numbers.push(json!(number));
    }
    let values = serde_json::from_value(json!({"numbers": numbers}))?;
    let original = serde_json::to_vec(&values)?;

    compare(&values)?;

    assert_eq!(serde_json::to_vec(&values)?, original);
    Ok(())
}

#[test]
fn canonical_depth_and_array_restrictions_remain_independent_of_bytes() -> TestResult {
    let mut nested = Value::Null;
    for _ in 0..63 {
        nested = json!([nested]);
    }
    let mut values = Map::new();
    values.insert("nested".into(), nested.clone());
    compare(&values)?;

    values.insert("nested".into(), json!([nested]));
    assert!(canonical_json_object_length_with_limit(&values, usize::MAX).is_err());
    assert!(canonical_json(&Value::Object(values.clone())).is_err());

    values.insert("nested".into(), Value::Array(vec![Value::Null; 65_536]));
    compare(&values)?;
    values
        .get_mut("nested")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(Value::Null);
    assert!(canonical_json_object_length_with_limit(&values, usize::MAX).is_err());
    Ok(())
}

#[test]
fn first_exhausted_byte_restriction_stops_before_later_invalid_fields() -> TestResult {
    let mut nested = Value::Null;
    for _ in 0..64 {
        nested = json!([nested]);
    }
    let values = serde_json::from_value(json!({"a": "prefix", "z": nested}))?;

    assert_eq!(canonical_json_object_length_with_limit(&values, 0)?, None);
    assert!(canonical_json_object_length_with_limit(&values, usize::MAX).is_err());
    Ok(())
}

#[test]
fn extent_sink_preserves_a_refused_prefix_without_integer_wrap() -> TestResult {
    let mut output = Extent {
        used: 0,
        maximum: 3,
        exceeded: false,
    };
    output.write_all(b"ab")?;
    assert!(output.write_all(b"cd").is_err());
    assert_eq!(output.used, 2);
    assert!(output.exceeded);

    let mut output = Extent {
        used: usize::MAX - 1,
        maximum: usize::MAX,
        exceeded: false,
    };
    assert!(output.write_all(b"ab").is_err());
    assert_eq!(output.used, usize::MAX - 1);
    assert!(output.exceeded);
    Ok(())
}
