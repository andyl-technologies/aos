//! Exercises the ordinary public parser through its shared transition seam.

use super::*;
use crate::canonical::{parse_json, parse_json_with_depth};

fn invalid(bytes: &[u8], maximum: usize, depth: usize) -> (&'static str, String) {
    match parse_json_with_depth(bytes, maximum, depth) {
        Err(ContractError::Invalid { field, reason }) => (field, reason),
        result => panic!("expected original Invalid error, got {result:?}"),
    }
}

#[test]
fn invalid_depth_precedes_byte_limit_and_grammar() {
    for depth in [0, 65, usize::MAX] {
        assert_eq!(
            invalid(b"not JSON and oversized", 0, depth),
            (
                "json_depth",
                "require a nesting limit between 1 and 64".to_owned()
            )
        );
    }

    assert_eq!(
        invalid(b"not JSON and oversized", 0, 64),
        ("json", "frame exceeds admitted byte limit".to_owned())
    );
}

#[test]
fn duplicate_decoded_key_precedes_colon_and_child_errors() {
    for bytes in [
        br#"{"a":0,"\u0061" !}"#.as_slice(),
        br#"{"a":0,"\u0061": not-json}"#.as_slice(),
    ] {
        assert_eq!(
            invalid(bytes, bytes.len(), 64),
            ("json", "duplicate object key at byte 15".to_owned())
        );
    }

    let bytes = br#"{"a" !}"#;
    assert_eq!(
        invalid(bytes, bytes.len(), 64),
        ("json", "expected object colon at byte 5".to_owned())
    );
}

#[test]
fn full_array_refuses_before_the_next_child_whitespace_or_token() {
    let prefix = format!("[{}", "0,".repeat(MAX_ARRAY_ELEMENTS));
    for suffix in ["not-json]", "  not-json]", "]"] {
        let bytes = format!("{prefix}{suffix}");
        assert_eq!(
            invalid(bytes.as_bytes(), bytes.len(), 64),
            (
                "json",
                format!("array exceeds 65536 elements at byte {}", prefix.len())
            )
        );
    }

    let bytes = format!("[{}0]", "0,".repeat(MAX_ARRAY_ELEMENTS - 1));
    let value = parse_json(bytes.as_bytes(), bytes.len()).unwrap();
    assert_eq!(value.as_array().unwrap().len(), MAX_ARRAY_ELEMENTS);
}

#[test]
fn scalar_below_the_sixty_fourth_container_remains_accepted() {
    for depth in [1, 4, 64] {
        let bytes = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
        assert!(parse_json_with_depth(bytes.as_bytes(), bytes.len(), depth).is_ok());
    }

    let bytes = format!("{}null{}", "[".repeat(65), "]".repeat(65));
    assert_eq!(
        invalid(bytes.as_bytes(), bytes.len(), 64),
        ("json", "JSON nesting limit exceeded at byte 64".to_owned())
    );
}

#[test]
fn trailing_invalid_utf8_remains_a_trailing_content_error() {
    assert_eq!(
        invalid(b"null\xff", 5, 64),
        ("json", "trailing JSON content at byte 4".to_owned())
    );
}

#[test]
fn quoted_token_keeps_the_same_serde_error_and_coordinate() {
    for token in [br#""\ud800""#.as_slice(), br#""\q""#.as_slice()] {
        let expected = serde_json::from_slice::<String>(token).unwrap_err();
        let actual = parse_json(token, token.len()).unwrap_err();

        match actual {
            ContractError::Json(error) => {
                assert_eq!(error.classify(), expected.classify());
                assert_eq!(error.line(), expected.line());
                assert_eq!(error.column(), expected.column());
                assert_eq!(error.to_string(), expected.to_string());
            }
            error => panic!("expected original serde error, got {error:?}"),
        }
    }
}

#[test]
fn cnp_numeric_normalization_and_raw_literal_maps_remain_distinct() {
    for token in [b"1".as_slice(), b"1.0".as_slice(), b"1e0".as_slice()] {
        assert_eq!(parse_json(token, token.len()).unwrap(), Value::from(1));
    }
    for token in [b"-0".as_slice(), b"0".as_slice()] {
        assert_eq!(parse_json(token, token.len()).unwrap(), Value::from(0));
    }
    assert_eq!(
        parse_json(b"18446744073709551615", 20).unwrap().as_u64(),
        Some(u64::MAX)
    );
    assert_eq!(
        invalid(b"1e999", 5, 64),
        ("json", "nonfinite number at byte 5".to_owned())
    );

    let bytes = br#"{"$serde_json::private::RawValue":"[null]"}"#;
    let value = parse_json(bytes, bytes.len()).unwrap();
    assert_eq!(
        value.as_object().unwrap()["$serde_json::private::RawValue"],
        Value::String("[null]".to_owned())
    );
}

#[test]
fn shared_transitions_do_not_open_or_visit_children_early() {
    let mut parser = Parser {
        bytes: br#" [0, true]"#,
        cursor: 0,
        maximum_depth: 64,
    };

    assert!(matches!(parser.value_start().unwrap(), ValueStart::Array));
    assert_eq!(parser.cursor, 1);
    parser.begin_container(0).unwrap();
    assert_eq!(parser.cursor, 2);
    parser.array_before_child(0).unwrap();
    assert!(matches!(
        parser.value_start().unwrap(),
        ValueStart::Scalar(Value::Number(_))
    ));
    assert!(!parser.container_after_child(ContainerKind::Array).unwrap());
    assert_eq!(parser.cursor, 4);
    parser.array_before_child(1).unwrap();
    assert!(matches!(
        parser.value_start().unwrap(),
        ValueStart::Scalar(Value::Bool(true))
    ));
    assert!(parser.container_after_child(ContainerKind::Array).unwrap());
    assert_eq!(parser.cursor, parser.bytes.len());
}
