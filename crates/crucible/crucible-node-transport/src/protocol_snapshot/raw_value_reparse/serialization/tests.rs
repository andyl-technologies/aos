//! Compares prospective serializer populations with independent actual Value walks.

use super::*;
use serde::ser::SerializeMap;
use serde_json::json;

#[derive(Serialize)]
struct Borrowed<'a> {
    label: &'a str,
    entries: &'a Value,
    empty: Option<&'a Value>,
}

#[test]
fn borrowed_actual_serialization_matches_the_independent_value_reset_walk() {
    for entries in [
        json!({"ordinary": [1, "text", null]}),
        json!({RAW_VALUE_KEY: "{\"nested\":[1,2]}"}),
        json!({"outer": [{RAW_VALUE_KEY: "0"}, {RAW_VALUE_KEY: ""}]}),
        json!({RAW_VALUE_KEY: [true, {RAW_VALUE_KEY: "[0]"}]}),
        json!({"𝄞": {RAW_VALUE_KEY: 17}}),
    ] {
        let original = Borrowed {
            label: "unchanged",
            entries: &entries,
            empty: None,
        };
        let before = entries.clone();
        let prospective = quote_serialized_data(&original, usize::MAX / 4).unwrap();
        let value = serde_json::to_value(&original).unwrap();
        let actual = quote_value_data(&value, usize::MAX / 4).unwrap();
        assert_eq!(prospective, actual);
        assert_eq!(entries, before);
    }
}

struct SplitDisplay;

impl fmt::Display for SplitDisplay {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("$serde_json::")?;
        out.write_str("private::RawValue")
    }
}

struct DisplayString;

impl Serialize for DisplayString {
    fn serialize<S: ser::Serializer>(&self, out: S) -> Result<S::Ok, S::Error> {
        out.collect_str(&SplitDisplay)
    }
}

struct DisplayMap;

impl Serialize for DisplayMap {
    fn serialize<S: ser::Serializer>(&self, out: S) -> Result<S::Ok, S::Error> {
        let mut map = out.serialize_map(Some(1))?;
        map.serialize_entry(&DisplayString, &'0')?;
        map.end()
    }
}

#[test]
fn streamed_display_keys_and_character_values_keep_actual_json_string_semantics() {
    let prospective = quote_serialized_data(&DisplayMap, usize::MAX / 4).unwrap();
    let actual =
        quote_value_data(&serde_json::to_value(DisplayMap).unwrap(), usize::MAX / 4).unwrap();
    assert_eq!(prospective, actual);
    assert_eq!(prospective.detected_strings_data(), 1);
}

#[test]
fn exact_reset_work_is_accepted_and_one_short_refuses_before_any_body_allocation() {
    let value = json!({RAW_VALUE_KEY: "[0]"});
    let quote = quote_serialized_data(&value, usize::MAX / 4).unwrap();
    let (r, t, s) = quote.requested_storage_data();
    let maximum = r + t + s;
    assert_eq!(quote_serialized_data(&value, maximum).unwrap(), quote);
    assert!(quote_serialized_data(&value, maximum - 1).is_err());
}

#[test]
fn the_canonical_container_profile_is_checked_without_encoding_a_body() {
    let mut value = Value::Null;
    for _ in 0..RAW_OUTER_DEPTH {
        value = Value::Array(vec![value]);
    }
    quote_serialized_data(&value, usize::MAX / 4).unwrap();
    value = Value::Array(vec![value]);
    assert!(quote_serialized_data(&value, usize::MAX / 4).is_err());
}

#[test]
fn prospective_raw_tokens_cover_quotes_escapes_and_the_native_outer_depth() {
    for text in ["", "0", "[0]", "{\"a\":[0]}", "\n\r\t\\\"", "𝄞"] {
        let value = json!({RAW_VALUE_KEY: text});
        let prospective = quote_serialized_raw_bound_data(&value, 0, usize::MAX / 4).unwrap();
        let bank = crucible_node_format::canonical::canonical_json(&value).unwrap();
        let native = quote_raw_json_data(&bank, usize::MAX / 4).unwrap();
        let p = prospective.requested_storage_data();
        let n = native.requested_storage_data();
        assert!(p.0 >= n.0 && p.1 >= n.1 && p.2 >= n.2);
        assert!(prospective.maximum_parser_layers_data() >= native.maximum_parser_layers_data());
    }

    let mut value = Value::Null;
    for _ in 0..RAW_OUTER_DEPTH - 1 {
        value = Value::Array(vec![value]);
    }
    quote_serialized_raw_bound_data(&value, 1, usize::MAX / 4).unwrap();
    assert!(quote_serialized_raw_bound_data(&value, 2, usize::MAX / 4).is_err());
}

#[test]
fn independent_forests_add_without_alias_discount_and_failed_addition_keeps_data() {
    let first = json!({RAW_VALUE_KEY: "0"});
    let second = json!({RAW_VALUE_KEY: "[0]"});
    let mut separate = quote_value_data(&first, usize::MAX / 4).unwrap();
    let next = quote_value_data(&second, usize::MAX / 4).unwrap();
    let original = separate;
    assert!(separate.include_data(next, 1).is_err());
    assert_eq!(separate, original);
    separate.include_data(next, usize::MAX / 4).unwrap();
    let together = quote_value_data(&json!([first, second]), usize::MAX / 4).unwrap();
    assert_eq!(separate, together);
}
