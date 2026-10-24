//! Exercises the real typed refusal, retained backing and original cause.

use super::*;
use std::error::Error;

#[test]
fn invalid_owned_input_and_cause_keep_their_original_backing() {
    let mut text = String::with_capacity(97);
    text.push_str("private rejected id");
    let pointer = text.as_ptr();
    let capacity = text.capacity();
    let refusal = Id::try_from_owned(text).unwrap_err();
    let cause = refusal
        .source()
        .unwrap()
        .downcast_ref::<ContractError>()
        .unwrap();
    let ContractError::Invalid { field, reason } = cause else {
        panic!("invalid owned input must retain its original typed cause");
    };
    assert_eq!(*field, "id");
    let reason_pointer = reason.as_ptr();
    assert_eq!(refusal.to_string(), cause.to_string());
    assert!(!refusal.to_string().contains("private rejected id"));
    assert!(!format!("{refusal:?}").contains("private rejected id"));

    let (returned, cause) = refusal.into_parts();
    assert_eq!(returned, "private rejected id");
    assert_eq!(returned.as_ptr(), pointer);
    assert_eq!(returned.capacity(), capacity);
    let ContractError::Invalid { field, reason } = cause else {
        panic!("consuming the refusal must not replace its cause");
    };
    assert_eq!(field, "id");
    assert_eq!(reason.as_ptr(), reason_pointer);
    assert_eq!(reason, "expected 1–128 bounded ASCII identifier bytes");
}

#[test]
fn typed_refusal_preserves_the_existing_identifier_grammar() {
    for input in [
        "".to_owned(),
        "bad id".to_owned(),
        "λ".to_owned(),
        "a".repeat(129),
    ] {
        let pointer = input.as_ptr();
        let capacity = input.capacity();
        let refusal = Id::try_from_owned(input).unwrap_err();
        let (input, cause) = refusal.into_parts();
        assert_eq!(input.as_ptr(), pointer);
        assert_eq!(input.capacity(), capacity);
        assert!(matches!(cause, ContractError::Invalid { field: "id", .. }));
    }
    for input in [
        "a".to_owned(),
        "owner/part:0-._".to_owned(),
        "a".repeat(128),
    ] {
        let pointer = input.as_ptr();
        let capacity = input.capacity();
        let id = Id::try_from_owned(input).unwrap();
        assert_eq!(id.as_str().as_ptr(), pointer);
        assert_eq!(id.allocated_capacity(), capacity);
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            format!("\"{}\"", id.as_str())
        );
    }
}

#[test]
fn ordinary_identifier_constructor_returns_the_same_original_error() {
    let owned = Id::try_from_owned("bad id".to_owned()).unwrap_err();
    let ordinary = Id::new("bad id").unwrap_err();
    assert_eq!(owned.to_string(), ordinary.to_string());
    assert!(matches!(
        ordinary,
        ContractError::Invalid { field: "id", .. }
    ));
}
