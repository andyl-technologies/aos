//! Exercises the actual writer's error order and component admission boundary.
//!
//! No test creates a Source, Initial/Recipe, protocol grant or native witness.

use super::*;
use crate::reference_packet::service::PacketNative5SerializedCreditFailureStorage;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use serde::Serialize;
use std::io;
use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

#[test]
fn actual_failure_component_requires_its_exact_independent_axes() {
    const FIXED_COUNTER: usize =
        crate::reference_packet::service::original_import18_serialized_credit_failure_counter_scratch_data(
        );
    let row =
        PacketNative5SourceLaunch::original_import18_serialized_credit_failure_construction_data(
            usize::MAX,
        )
        .unwrap();
    let exact = row.0.checked_add(row.1).unwrap();
    assert!(row.0 > SERIALIZED_CREDIT_FAILURE_MESSAGE.len());
    assert!(row.1 > FIXED_COUNTER);
    assert_eq!(
        PacketNative5SourceLaunch::original_import18_serialized_credit_failure_construction_data(
            exact
        )
        .unwrap(),
        row
    );
    assert!(
        PacketNative5SourceLaunch::original_import18_serialized_credit_failure_construction_data(
            exact - 1
        )
        .is_err()
    );
}

#[test]
fn short_component_refuses_before_the_actual_writer_error_constructor() {
    fn run(maximum: usize, entered: &std::cell::Cell<bool>) -> Result<(), ProviderError> {
        PacketNative5SourceLaunch::original_import18_serialized_credit_failure_construction_data(
            maximum,
        )?;
        entered.set(true);
        let mut counter = SerializedCreditCounter::projection_data(1);
        let error = serde_json::to_writer(&mut counter, "actual-fragment").unwrap_err();
        assert!(error.is_io());
        assert_eq!(counter.used_data(), 1);
        drop(error);
        Ok(())
    }
    let row =
        PacketNative5SourceLaunch::original_import18_serialized_credit_failure_construction_data(
            usize::MAX,
        )
        .unwrap();
    let exact = row.0 + row.1;
    let entered = std::cell::Cell::new(false);
    assert!(run(exact - 1, &entered).is_err());
    assert!(!entered.get());
    run(exact, &entered).unwrap();
    assert!(entered.get());
}

#[test]
fn actual_writer_keeps_last_accepted_chunk_on_credit_refusal() {
    let mut counter = SerializedCreditCounter::projection_data(1);
    let error = serde_json::to_writer(&mut counter, "ordinary-content").unwrap_err();
    // Original CompactFormatter first writes the opening quote, then the
    // ordinary UTF8 fragment. The failed fragment cannot advance used.
    assert_eq!(counter.used_data(), 1);
    assert!(error.is_io());
    assert_eq!(error.io_error_kind(), Some(io::ErrorKind::Other));
    assert_eq!(error.to_string(), SERIALIZED_CREDIT_FAILURE_MESSAGE);
    drop(error); // retains the legacy pure temporary lifetime
    assert_eq!(counter.used_data(), 1);
    assert!(matches!(
        serialized_credit(&"ordinary-content", 1),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));
}

#[test]
fn actual_escape_chunks_keep_exact_and_one_short_credit_behavior() {
    for value in ["", "plain", "\"\\\n\t\u{0000}", "λ𝄞", "\u{2028}/"] {
        let bytes = serde_json::to_vec(value).unwrap();
        let mut exact = SerializedCreditCounter::projection_data(bytes.len());
        serde_json::to_writer(&mut exact, value).unwrap();
        assert_eq!(exact.used_data(), bytes.len());
        let mut short = SerializedCreditCounter::projection_data(bytes.len() - 1);
        let error = serde_json::to_writer(&mut short, value).unwrap_err();
        assert!(error.is_io());
        assert!(short.used_data() <= bytes.len() - 1);
        assert_eq!(error.to_string(), SERIALIZED_CREDIT_FAILURE_MESSAGE);
    }
}

#[test]
fn original_credit_refusal_precedes_later_malformed_path_serializer() {
    #[derive(Serialize)]
    struct OriginalFields<'a> {
        first: &'a str,
        effects: PathBuf,
    }
    let original = OriginalFields {
        first: "must-fail-before-visiting-effects",
        effects: PathBuf::from(OsString::from_vec(vec![0xff])),
    };
    let mut early = SerializedCreditCounter::projection_data(1);
    let error = serde_json::to_writer(&mut early, &original).unwrap_err();
    assert_eq!(early.used_data(), 1); // opening object accepted; first key quote refuses
    assert!(error.is_io());
    assert_eq!(error.to_string(), SERIALIZED_CREDIT_FAILURE_MESSAGE);
    drop(error);

    let mut later = SerializedCreditCounter::projection_data(usize::MAX);
    let error = serde_json::to_writer(&mut later, &original).unwrap_err();
    assert!(error.is_data());
    assert_eq!(error.to_string(), "path contains invalid UTF-8 characters");
    assert!(later.used_data() > early.used_data());
    drop(error);
    assert!(matches!(
        serialized_credit(&original, 1),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));
    assert!(matches!(
        serialized_credit(&original, usize::MAX),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));
}

#[test]
fn actual_bytes_formatter_and_reserved_literal_remain_ordinary_serde() {
    #[derive(Serialize)]
    struct OriginalFields<'a> {
        literal: &'a serde_json::Value,
        bytes: &'a crucible_node_format::Bytes,
        number: &'a serde_json::Value,
    }
    let literal = serde_json::json!({"$serde_json::private::RawValue":"[1,2]"});
    let bytes = crucible_node_format::Bytes::new(vec![0, 1, 2, 253, 254, 255]);
    let number = serde_json::json!([u64::MAX, -0.0, 1.0e-300]);
    let original = OriginalFields {
        literal: &literal,
        bytes: &bytes,
        number: &number,
    };
    let encoded = serde_json::to_vec(&original).unwrap();
    assert_eq!(
        serialized_credit(&original, encoded.len()).unwrap(),
        encoded.len()
    );
    assert!(serialized_credit(&original, encoded.len() - 1).is_err());
    assert!(literal.get("$serde_json::private::RawValue").is_some());
}
