//! Exercises the actual retained DOM owner on normal and unwinding teardown.

use super::*;
use serde_json::Map;

fn deep_value() -> Value {
    let mut literal = Map::new();
    literal.insert(
        "$serde_json::private::RawValue".into(),
        Value::String("[1,2]".into()),
    );
    let mut value = Value::Object(literal);
    for depth in 0..100_000 {
        value = if depth % 2 == 0 {
            Value::Array(vec![value])
        } else {
            let mut object = Map::new();
            object.insert("child".into(), value);
            Value::Object(object)
        };
    }
    value
}

#[test]
fn retained_dom_retires_deep_mixed_values_without_recursive_value_drop() {
    let owner = RetainedValue::new(deep_value());
    assert!(owner.value().is_object());
    drop(owner);
}

#[test]
fn retained_dom_keeps_literal_marker_and_retires_during_actual_unwind() {
    let result = std::panic::catch_unwind(|| {
        let owner = RetainedValue::new(deep_value());
        assert!(owner.value().is_object());
        panic!("actual contained DOM unwind control");
    });
    assert!(result.is_err());

    let mut marker = Map::new();
    marker.insert(
        "$serde_json::private::RawValue".into(),
        Value::String("[1,2]".into()),
    );
    let owner = RetainedValue::new(Value::Object(marker));
    assert_eq!(owner.value()["$serde_json::private::RawValue"], "[1,2]");
}
