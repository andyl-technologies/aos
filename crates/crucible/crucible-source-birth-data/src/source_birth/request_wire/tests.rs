//! Exercises literal fidelity and guarded failed typed-field prefixes.

use super::*;
use serde_json::{Map, Number, Value};

fn round_trip<T: Wire>(value: &T) -> Owned<T> {
    let mut bytes = Vec::new();
    let mut out = Encoder::new(
        &mut bytes,
        1024 * 1024,
        100_000,
        None,
        super::super::literal_value::LiteralWriteWorkspace::new(8192).unwrap(),
    );
    value.encode(&mut out).unwrap();
    let expected = out.work;
    drop(out);

    let limits = OperationalLimits {
        maximum_input_bytes: 1024 * 1024,
        maximum_elements: 100_000,
        maximum_output_bytes: 1,
        maximum_diagnostic_bytes: 1,
    };
    let length = bytes.len();
    let mut input = Decoder::new(bytes.as_slice(), length, limits, &[]);
    let value = T::decode(&mut input).unwrap();

    assert_eq!(input.remaining, 0);
    assert_eq!(input.work, expected);
    value
}

#[test]
fn literal_marker_keys_numbers_and_empty_containers_keep_actual_content() {
    let mut object = Map::new();
    object.insert(
        "$serde_json::private::RawValue".into(),
        Value::String("null".into()),
    );
    let cases = [
        Value::Object(object),
        Value::Number(Number::from(u64::MAX)),
        Value::Number(Number::from(i64::MIN)),
        Value::Number(Number::from_f64(-0.0).unwrap()),
        Value::Array(Vec::new()),
        Value::Object(Map::new()),
    ];

    for value in cases {
        let value = Owned::new(value);
        let result = round_trip(value.get());

        assert_eq!(result.get(), value.get());
        if let Value::Number(number) = value.get() {
            if let Some(float) = number.as_f64() {
                assert_eq!(result.get().as_f64().unwrap().to_bits(), float.to_bits());
            }
        }
    }
}

#[test]
fn deep_literal_clone_and_failed_following_field_retire_iteratively() {
    let mut value = Owned::new(Value::Null);
    for _ in 0..4096 {
        value = Owned::new(Value::Array(vec![value.into_inner()]));
    }

    let mut bytes = Vec::new();
    let mut out = Encoder::new(
        &mut bytes,
        1024 * 1024,
        100_000,
        None,
        super::super::literal_value::LiteralWriteWorkspace::new(8192).unwrap(),
    );
    value.get().encode(&mut out).unwrap();
    drop(out);

    let limits = OperationalLimits {
        maximum_input_bytes: 1024 * 1024,
        maximum_elements: 100_000,
        maximum_output_bytes: 1,
        maximum_diagnostic_bytes: 1,
    };
    let length = bytes.len();
    let mut input = Decoder::new(bytes.as_slice(), length, limits, &[]);
    let completed = Value::decode(&mut input).unwrap();
    assert!(String::decode(&mut input).is_err());
    drop(completed);

    // Each truncation retains the real literal reader failure; no bare partial
    // Value is returned to recursive ordinary destruction.
    for end in [0, 1, 31, 32, bytes.len() - 1] {
        let mut input = Decoder::new(&bytes[..end], end, limits, &[]);
        assert!(Value::decode(&mut input).is_err());
    }
}

#[test]
fn oversized_collection_length_refuses_before_reserving_declared_slots() {
    let bytes = u64::MAX.to_be_bytes();
    let limits = OperationalLimits {
        maximum_input_bytes: 8,
        maximum_elements: usize::MAX,
        maximum_output_bytes: 1,
        maximum_diagnostic_bytes: 1,
    };
    let mut input = Decoder::new(bytes.as_slice(), bytes.len(), limits, &[]);

    assert!(Vec::<String>::decode(&mut input).is_err());
}

#[test]
fn admitted_literal_workspace_reuses_actual_bank_and_refuses_without_growth() {
    use super::super::literal_value::{self, LiteralWriteWorkspace, StreamLimits};

    let value = Owned::new(Value::Array(vec![Value::Array(vec![Value::Bool(true)])]));
    let limits = StreamLimits {
        maximum_wire_bytes: 1024,
        maximum_values: 16,
    };

    let mut too_small = LiteralWriteWorkspace::new(1).unwrap();
    let retained = too_small.retained_bytes();
    let mut untouched = Vec::new();

    assert!(
        literal_value::write_value_in(value.get(), &mut untouched, limits, &mut too_small).is_err()
    );
    assert!(untouched.is_empty());
    assert_eq!(too_small.retained_bytes(), retained);

    let mut workspace = LiteralWriteWorkspace::new(2).unwrap();
    let retained = workspace.retained_bytes();
    let mut original = Vec::new();
    literal_value::write_value(value.get(), &mut original, limits).unwrap();

    for _ in 0..2 {
        let mut actual = Vec::new();
        literal_value::write_value_in(value.get(), &mut actual, limits, &mut workspace).unwrap();

        assert_eq!(actual, original);
        assert_eq!(workspace.retained_bytes(), retained);
    }
}
