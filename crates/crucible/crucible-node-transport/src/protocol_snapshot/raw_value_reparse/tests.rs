//! Exercises real generic JSON DATA and accounting without native authority.

use super::*;
use crate::retained_metadata::{
    MetadataObserver, requested_storage::requested_metadata_backing_storage_data,
};
use crucible_node_format::canonical;
use serde_json::json;

fn marker(text: &str) -> Value {
    Value::Object(
        [(RAW_VALUE_KEY.into(), Value::String(text.into()))]
            .into_iter()
            .collect(),
    )
}

fn total(value: JsonValueReparseConstructionData) -> usize {
    let (r, t, s) = value.requested_storage_data();
    r.checked_add(t).unwrap().checked_add(s).unwrap()
}

#[test]
fn plain_body_has_no_extra_reparse_axes_and_keeps_scanner_separate() {
    let body = json!({"a":[0,{"text":"$serde_json::private::RawValue"}],
        "b":"{\"$serde_json::private::RawValue\":\"[0]\"}"});
    let row = quote_value_data(&body, 0).unwrap();
    assert_eq!(row.requested_storage_data(), (0, 0, 0));
    assert_eq!(row.detected_strings_data(), 0);
    assert!(value_scanner_counter_scratch_data() > 0);
    assert!(raw_scanner_counter_scratch_data() > 0);
    let bytes = canonical::canonical_json(&body).unwrap();
    assert_eq!(
        quote_raw_json_data(&bytes, 0)
            .unwrap()
            .requested_storage_data(),
        (0, 0, 0)
    );
}

#[test]
fn actual_map_counts_each_string_marker_without_a_first_key_assumption() {
    let body = json!({"first":[marker("[0,1]"),marker("{\"a\":0}")],
        "second":{"$0":"earlier","$serde_json::private::RawValue":"true"},
        "third":{"$serde_json::private::RawValue":false}});
    let row = quote_map_data(body.as_object().unwrap(), usize::MAX).unwrap();
    assert_eq!(row.detected_strings_data(), 3);
    let (retained, transient, scratch) = row.requested_storage_data();
    assert!(retained > 0 && transient > 0 && scratch > 0);
    let (nodes, members, strings) = row.expanded_json_extents_data();
    assert!(nodes > 0 && members > 0 && strings > 0);
}

#[test]
fn raw_and_borrowed_maps_agree_on_markers_and_raw_literal_is_an_upper_bound() {
    let body = json!({"extension":marker("{\"quoted\":\"a\\b\"}")});
    let typed = quote_map_data(body.as_object().unwrap(), usize::MAX).unwrap();
    let bytes = canonical::canonical_json(&body).unwrap();
    let raw = quote_raw_json_data(&bytes, usize::MAX).unwrap();
    assert_eq!(raw.detected_strings_data(), typed.detected_strings_data());
    let (r, t, s) = raw.requested_storage_data();
    let (tr, tt, ts) = typed.requested_storage_data();
    assert!(r >= tr && t >= tt && s >= ts);
    // Escaped key spellings are compared through the real Unicode decoder.
    let escaped = br#"{"\u0024serde_json::private::RawValue":"[0]"}"#;
    assert_eq!(
        quote_raw_json_data(escaped, usize::MAX)
            .unwrap()
            .detected_strings_data(),
        1
    );
}

#[test]
fn exactly_quoted_total_admits_and_one_short_refuses() {
    let body = marker("[0,1,2]");
    let quoted = quote_value_data(&body, usize::MAX).unwrap();
    let maximum = total(quoted);
    assert_eq!(quote_value_data(&body, maximum).unwrap(), quoted);
    assert!(quote_value_data(&body, maximum - 1).is_err());
    assert_eq!(body, marker("[0,1,2]"));
}

#[test]
fn real_from_value_result_fits_without_assuming_raw_value_feature_state() {
    let inner = json!({"many":[0,1,2,3,4,5],"escaped":"a\"b\\c🦀"});
    let text = serde_json::to_string(&inner).unwrap();
    let body = marker(&text);
    let row = quote_value_data(&body, usize::MAX).unwrap();
    let actual: Value = serde_json::from_value(body.clone()).unwrap();
    // Feature-unified raw_value may normalize the object; without it the
    // object is ordinary DATA. Both are covered without changing semantics.
    assert!(actual == inner || actual == body);
    let mut observer = MetadataObserver::new();
    observer.observe(&actual).unwrap();
    let actual_backing = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
    assert!(actual_backing <= row.requested_storage_data().0);
}

#[test]
fn geometric_quote_bound_covers_actual_nested_reserved_string_encodings() {
    let mut text = "[0,1,2]".to_owned();
    for actual_layers in 1..=12usize {
        assert!(geometry::maximum_layers_data(text.len()).unwrap() >= actual_layers);
        assert!(text.len() >= 1usize << (actual_layers - 1));
        let body = marker(&text);
        let row = quote_value_data(&body, usize::MAX).unwrap();
        assert!(row.maximum_parser_layers_data() >= actual_layers);
        text = serde_json::to_string(&body).unwrap();
    }
}

#[test]
fn unescaped_bulk_payload_does_not_justify_a_twofold_string_bank_shortcut() {
    let mut text = format!("[{}]", vec!["0"; 8192].join(","));
    let mut sum = 0usize;
    for _ in 0..8 {
        sum += text.len();
        text = serde_json::to_string(&marker(&text)).unwrap();
    }
    assert!(sum > 2 * text.len());
    let row = quote_value_data(&marker(&text), usize::MAX).unwrap();
    assert!(row.expanded_json_extents_data().2 >= sum);
}

#[test]
fn malformed_or_unsupported_framing_and_depth_refuse_without_mutation() {
    for raw in [
        b"".as_slice(),
        b"{ }",
        br#"{"\uXX00":"x"}"#,
        br#"{"x":"unterminated}"#,
    ] {
        assert!(quote_raw_json_data(raw, usize::MAX).is_err());
    }
    let mut value = Value::Null;
    for _ in 0..129 {
        value = Value::Array(vec![value]);
    }
    assert!(quote_value_data(&value, usize::MAX).is_err());
    assert!(original_json_value_storage_extent_data(usize::MAX).is_err());
    assert!(geometry::parser_storage_data(usize::MAX).is_err());
}

#[test]
fn wrong_type_reserved_keys_pay_errors_without_claiming_parser_layers() {
    for rejected in [
        Value::Null,
        Value::Bool(false),
        json!(u64::MAX),
        json!(-1),
        json!(1.5),
        json!([]),
        json!({}),
    ] {
        let body = Value::Object([(RAW_VALUE_KEY.into(), rejected)].into_iter().collect());
        let row = quote_value_data(&body, usize::MAX).unwrap();
        assert_eq!(row.detected_strings_data(), 0);
        assert_eq!(row.maximum_parser_layers_data(), 0);
        assert_eq!(row.expanded_json_extents_data(), (0, 0, 0));
        let (r, t, s) = row.requested_storage_data();
        assert!(r > 0 && t > 0 && s > 0);
        assert!(quote_value_data(&body, total(row) - 1).is_err());

        let raw = canonical::canonical_json(&body).unwrap();
        assert_eq!(quote_raw_json_data(&raw, usize::MAX).unwrap(), row);
        match serde_json::from_value::<Value>(body.clone()) {
            Ok(value) => assert_eq!(value, body), // raw_value disabled
            Err(error) => {
                assert!(error.to_string().len() <= geometry::error_text_length_data(0).unwrap())
            }
        }
    }
}

#[test]
fn real_error_custom_wrapping_keeps_one_location_suffix() {
    for text in ["[", "{\"a\":", "\"\\uXY00\"", "[0,]", "[\n0,\n]"] {
        let mut error = serde_json::from_str::<Value>(text).unwrap_err();
        let first = error.to_string();
        let bound = geometry::error_text_length_data(text.len()).unwrap();
        assert!(first.len() <= bound);
        for _ in 0..64 {
            error = <serde_json::Error as serde::de::Error>::custom(error);
            // The actual make_error parse_line_col strips and restores the
            // same suffix on every wrap, rather than growing a suffix chain.
            assert_eq!(error.to_string(), first);
            assert!(error.to_string().len() <= bound);
        }
    }
}

#[test]
fn fragmented_reparse_forests_fit_the_whole_source_extent() {
    let forest = Value::Array((0..64).map(|_| marker("[0,0,0,0]")).collect());
    let text = serde_json::to_string(&forest).unwrap();
    let body = marker(&text);
    let quote = quote_value_data(&body, usize::MAX).unwrap();
    let actual: Value = serde_json::from_value(body).unwrap();
    let mut observer = MetadataObserver::new();
    observer.observe(&actual).unwrap();
    let actual_backing = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
    assert!(actual_backing <= quote.requested_storage_data().0);
}

#[test]
fn iterative_scanners_preserve_their_named_supported_profile_boundaries() {
    let mut value = Value::Null;
    for depth in 1..=128 {
        value = Value::Array(vec![value]);
        let row = quote_value_data(&value, 0).unwrap();
        assert_eq!(row.requested_storage_data(), (0, 0, 0));
        if depth <= 64 {
            let raw = serde_json::to_vec(&value).unwrap();
            assert_eq!(
                quote_raw_json_data(&raw, 0)
                    .unwrap()
                    .requested_storage_data(),
                (0, 0, 0)
            );
        }
    }
    value = Value::Array(vec![value]);
    assert!(quote_value_data(&value, usize::MAX).is_err());

    let raw = format!("{}0{}", "[".repeat(65), "]".repeat(65));
    assert!(quote_raw_json_data(raw.as_bytes(), usize::MAX).is_err());
}

#[test]
fn actual_nested_raw_string_failures_keep_quotes_and_original_input() {
    let nested = serde_json::to_string(&marker("{\"a\":}")).unwrap();
    for text in ["[0,]", "{\"a\":}", nested.as_str()] {
        let body = marker(text);
        let before = serde_json::to_vec(&body).unwrap();
        let quote = quote_value_data(&body, usize::MAX).unwrap();
        let (retained, transient, scratch) = quote.requested_storage_data();
        assert!(retained > 0 && transient > 0 && scratch > 0);
        assert!(quote.detected_strings_data() > 0);

        match serde_json::from_value::<Value>(body.clone()) {
            // Without raw_value, the same reserved-key object is ordinary DATA.
            Ok(actual) => assert_eq!(actual, body),
            Err(error) => {
                let independent_bound = geometry::error_text_length_data(text.len()).unwrap();
                assert!(error.to_string().len() <= independent_bound);
            }
        }
        assert_eq!(serde_json::to_vec(&body).unwrap(), before);
    }
}
