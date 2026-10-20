//! Checks prospective retained geometry with independently decoded real field types.

use super::*;
use crate::retained_metadata::{
    MetadataObserver, requested_storage::requested_metadata_backing_storage_data,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn independent_envelope_maps_typed_vectors_and_canonical_bank_fit() -> TestResult {
    // These are ordinary DTO fields, never a fabricated validated SDK owner.
    let mut original = crate::handshake::tests::original_hello_envelope();
    original.body.insert(
        "retained-field-shapes".to_owned(),
        serde_json::json!({
            "escaped": "\u{0000}\n\"\\𝄞",
            "empty": [{}, [], ""],
            "dense": (0..65).collect::<Vec<u64>>(),
        }),
    );
    let participants = (0..65)
        .map(|index| Id::new(format!("participant-{index:03}")))
        .collect::<Result<Vec<_>, _>>()?;
    let references = vec![canonical::content_ref(b"retained field", "application/json")?; 65];
    let canonical_original = canonical::canonical_json(&serde_json::to_value(&original)?)?;
    let value = serde_json::json!({
        "originals": [&original, &original, &original, &original],
        "participants": participants,
        "references": references,
        "canonical": canonical_original,
    });
    let encoded = serde_json::to_vec(&value)?;
    let admitted =
        historical_restored_settled_capture17_retained_construction_bytes_data(encoded.len())?;

    let originals: Vec<Envelope> = read(&value["originals"])?;
    let participants: Vec<Id> = read(&value["participants"])?;
    let references: Vec<ContentRef> = read(&value["references"])?;
    let canonical_original: Vec<u8> = read(&value["canonical"])?;
    let mut observer = MetadataObserver::new();
    for original in &originals {
        observer.observe(original)?;
    }
    observer.observe(&participants)?;
    observer.observe(&references)?;
    observer.observe(&canonical_original)?;
    let actual = requested_metadata_backing_storage_data(&observer.finish())?
        .checked_add(size_of::<ValidatedHistoricalRestoredSettledCapture17>())
        .ok_or_else(invalid)?;

    assert!(actual <= admitted);
    assert_eq!(originals.len(), 4);
    assert_eq!(participants.len(), 65);
    assert_eq!(references.len(), 65);
    assert!(!canonical_original.is_empty());
    assert_eq!(serde_json::to_vec(&value)?, encoded);
    Ok(())
}

#[test]
fn zero_and_overflow_refuse_before_any_sdk_construction() {
    assert!(historical_restored_settled_capture17_retained_construction_bytes_data(0).is_err());
    assert!(
        historical_restored_settled_capture17_retained_construction_bytes_data(usize::MAX).is_err()
    );
    assert!(
        historical_restored_settled_capture17_retained_construction_bytes_data(usize::MAX / 32)
            .is_err()
    );
}
