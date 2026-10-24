//! Adversarial DATA controls for the borrowed semantic boundary.

use super::{BorrowedAuthority17Lineage, bytes::*, custody::*};
use crate::ProviderError;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use crucible_node_format::{ContentRef, canonical};
use serde_json::{Value, json};

#[test]
fn streamed_correspondence_matches_real_jcs_for_unicode_keys_and_numbers()
-> Result<(), ProviderError> {
    let value =
        json!({"\u{e000}": [1.0, -0.0, u64::MAX], "\u{10000}": {"quoted\"key": "line\n\\end"}});
    let source = serde_json::to_vec(&value)
        .map_err(|_| crate::protocol_snapshot::owned11::typed::invalid())?;
    let expected = canonical::canonical_json(&value)?;
    let encoded = serde_json::to_vec(&BorrowedCompactBytes::new(&expected))
        .map_err(|_| crate::protocol_snapshot::owned11::typed::invalid())?;
    Bytes17::compact(&encoded)?.canonical(&source)?;
    let changed =
        json!({"\u{e000}": [2.0, -0.0, u64::MAX], "\u{10000}": {"quoted\"key": "line\n\\end"}});
    let changed = serde_json::to_vec(&changed)
        .map_err(|_| crate::protocol_snapshot::owned11::typed::invalid())?;
    assert!(Bytes17::compact(&encoded)?.canonical(&changed).is_err());
    Ok(())
}

fn reference(bytes: &[u8]) -> Result<ContentRef, ProviderError> {
    Ok(canonical::content_ref(bytes, "application/octet-stream")?)
}

fn authority<'a>(input: &'a [u8]) -> Result<BorrowedAuthority17Lineage<'a>, ProviderError> {
    BorrowedAuthority17Lineage::read(input)
}

fn authority_bytes() -> Result<Vec<u8>, ProviderError> {
    Ok(br#"{"schema":"source-private.connection-authority/17","gate_role":"registrar-gate","epoch_role":"registrar-epoch","saved_epoch":1,"observed_epoch":1,"gate_poisoned":false,"connection":"connection","session":"session","incarnation":"incarnation","limits":{"frame_bytes":"65536","nesting":"64","requests":"8","journal_entries":"16","blob_chunk_bytes":"64"},"features":[],"envelope_extensions":[],"extensions":null}"#.to_vec())
}

fn receiver(record: Value, reserved: usize, pins: usize) -> Result<Vec<u8>, ProviderError> {
    serde_json::to_vec(&json!([
        "source-private.native-blob-receiver/11",
        "session",
        "incarnation",
        [1024, 1024, 64, 4, 4, 32, 8],
        [
            "source-private.native-blob-ledger/11",
            reserved,
            (pins + 1).to_string(),
            pins,
            [record]
        ],
        "source-private.native-supervisor-owner/11"
    ]))
    .map_err(|_| crate::protocol_snapshot::owned11::typed::invalid())
}

#[test]
fn settled_pin_requires_exact_receipt_owner_and_nonrefunded_credit() -> Result<(), ProviderError> {
    let bytes = b"actual historical bytes";
    let content = reference(bytes)?;
    let schema = reference(b"schema")?;
    let receipt = reference(b"settled receipt")?;
    let compact = serde_json::to_value(BorrowedCompactBytes::new(bytes))
        .map_err(|_| crate::protocol_snapshot::owned11::typed::invalid())?;
    let key = json!(["controller", "session", "incarnation", "transfer"]);
    let record = json!([
        key,
        content,
        bytes.len(),
        [bytes.len(), compact],
        [[0, bytes.len()]],
        true,
        false,
        true,
        ["none", null, null],
        [["1", "owner", schema, "settled", receipt]],
        true
    ]);
    let receiver = receiver(record.clone(), bytes.len(), 1)?;
    let wrappers = serde_json::to_vec(
        &json!([{"key":key,"pin":"1","owner":"owner","schema":schema,"settled":true}]),
    )
    .map_err(|_| crate::protocol_snapshot::owned11::typed::invalid())?;
    let authority_bytes = authority_bytes()?;
    let source_pointer = receiver.as_ptr();
    let source_capacity = receiver.capacity();
    let data = authenticate_borrowed_settled_capture17_custody_data(
        &receiver,
        &wrappers,
        authority(&authority_bytes)?,
    )?;
    assert_eq!(data.reserved, bytes.len());
    assert_eq!(data.pins_created, 1);
    assert_eq!(data.next_pin, 2);
    let changed = serde_json::to_vec(
        &json!([{"key":key,"pin":"1","owner":"another-owner","schema":schema,"settled":true}]),
    )
    .map_err(|_| crate::protocol_snapshot::owned11::typed::invalid())?;
    assert!(
        authenticate_borrowed_settled_capture17_custody_data(
            &receiver,
            &changed,
            authority(&authority_bytes)?
        )
        .is_err()
    );
    assert_eq!(receiver.as_ptr(), source_pointer);
    assert_eq!(receiver.capacity(), source_capacity);
    assert_eq!(data.reserved, bytes.len());
    Ok(())
}

#[test]
fn discharged_failed_tombstone_keeps_original_quarantine_and_spent_ids() -> Result<(), ProviderError>
{
    let content = reference(b"original declaration")?;
    let empty = serde_json::to_value(BorrowedCompactBytes::new(&[]))
        .map_err(|_| crate::protocol_snapshot::owned11::typed::invalid())?;
    let record = json!([
        ["controller", "session", "incarnation", "failed-transfer"],
        content,
        20,
        [128, empty],
        [],
        false,
        true,
        false,
        ["abandon-inert", null, null],
        [],
        false
    ]);
    let receiver = receiver(record, 0, 0)?;
    let authority_bytes = authority_bytes()?;
    let data = authenticate_borrowed_settled_capture17_custody_data(
        &receiver,
        b"[]",
        authority(&authority_bytes)?,
    )?;
    assert_eq!(data.reserved, 0);
    assert_eq!(data.next_pin, 1);
    assert!(boolean(item(item(data.records, 0)?, 6)?)?);
    Ok(())
}
