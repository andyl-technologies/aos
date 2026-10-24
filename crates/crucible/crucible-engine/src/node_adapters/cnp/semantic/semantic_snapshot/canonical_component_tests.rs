//! Exercises permitted extension numbers/order with the actual canonical bank.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn backend_value() -> serde_json::Value {
    serde_json::json!({
        "schema":"source-owned.packet-complete-archive-backend-before/15",
        "implementation":{"extensions":{"number":1.0,"\u{10000}":"astral","\u{e000}":"bmp"}}
    })
}

#[test]
fn canonical_backend_bank_preserves_permitted_number_and_utf16_key_spelling() -> TestResult {
    let value = backend_value();
    let expected = canonical::canonical_json(&value)?;
    assert_ne!(expected, serde_json::to_vec(&value)?);
    let mut bank = Some(
        CnpSemanticSnapshotReservation::reserve(expected.len(), expected.len())
            .map_err(|failure| failure.reason)?,
    );
    record_canonical_component(&mut bank, &value).map_err(|failure| failure.reason)?;
    let original =
        take_component(&mut bank, "application/json").map_err(|failure| failure.reason)?;

    assert!(bank.is_none());
    assert_eq!(original.bytes, expected);
    original.reference.verify(&expected)?;
    authenticate_canonical_component(&original, &value).map_err(|failure| failure.reason)?;
    assert!(authenticate_component(&original, &value).is_err());
    Ok(())
}

#[test]
fn short_canonical_backend_bank_retains_the_original_attempt_without_writing() -> TestResult {
    let value = backend_value();
    let extent = canonical::canonical_json(&value)?.len();
    let mut bank = Some(
        CnpSemanticSnapshotReservation::reserve(extent - 1, extent - 1)
            .map_err(|failure| failure.reason)?,
    );

    assert!(record_canonical_component(&mut bank, &value).is_err());
    let Some(original) = &bank else {
        return Err("canonical bank was discarded".into());
    };
    assert!(original.started);
    assert!(original.bytes.is_empty());
    assert_eq!(original.allocated_bytes(), extent - 1);
    assert!(record_canonical_component(&mut bank, &value).is_err());
    assert!(take_component(&mut bank, "application/json").is_err());
    assert!(bank.is_some());
    Ok(())
}
