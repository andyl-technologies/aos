//! Checks actual Source bank reservations and incomplete slot DATA independently.

use super::super::super::tests::{coordinator, installation, producer, storage_selection};
use super::*;

fn source() -> PacketCompleteSemanticSource {
    let coordinator = coordinator();
    PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&coordinator, 0),
        producer(),
        coordinator,
        storage_selection(),
    )
    .unwrap()
}

fn limits() -> PacketCompleteCaptureBankLimits {
    PacketCompleteCaptureBankLimits {
        host_protocol_bytes: 4096,
        semantic_bytes: 1024,
        ancestry_bytes: 2048,
        journal_bytes: 512,
    }
}

#[test]
fn capture_capacity_keeps_actual_source_reservations_and_independent_byte_oracle() {
    let mut source = source();
    assert_eq!(
        source
            .original_complete_capture_banks_capacity_data(None)
            .unwrap()
            .capacity_records,
        0
    );
    source
        .reserve_complete_capture_banks(limits(), 4 * 1024 * 1024)
        .unwrap();
    let bytes = source
        .capture_banks
        .borrow()
        .as_ref()
        .unwrap()
        .facts()
        .unwrap()
        .total_bytes;

    let facts = source
        .original_complete_capture_banks_capacity_data(None)
        .unwrap();

    assert_eq!(facts.vector_banks, 9);
    assert_eq!(facts.capacity_records, 9);
    assert_eq!(facts.vector_capacity_bytes, bytes);
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<RuntimeError>(
            &facts, bytes
        ),
        Ok(bytes)
    );
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<RuntimeError>(
            &facts,
            bytes - 1
        ),
        Err(RuntimeError::ResourceLimit)
    );
    assert!(source.ack_peer_birth.borrow().is_none());
}

#[test]
fn capture_capacity_keeps_incomplete_coexisting_slots_without_granting_transfer() {
    let mut source = source();
    source
        .reserve_complete_capture_banks(limits(), 4 * 1024 * 1024)
        .unwrap();
    let before = source
        .original_complete_capture_banks_capacity_data(None)
        .unwrap();
    let mut bytes = Vec::with_capacity(173);
    bytes.extend_from_slice(b"incomplete DATA");
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    let expected = bytes.capacity() + NodeRuntime::capture_reference_storage(&reference).unwrap();
    source
        .capture_banks
        .borrow_mut()
        .as_mut()
        .unwrap()
        .ancestry_record = Some(InputPayload { reference, bytes });

    let facts = source
        .original_complete_capture_banks_capacity_data(None)
        .unwrap();

    assert_eq!(facts.capacity_records, before.capacity_records + 5);
    assert_eq!(facts.vector_banks, before.vector_banks + 1);
    assert_eq!(
        facts.vector_capacity_bytes + facts.string_capacity_bytes,
        before.vector_capacity_bytes + expected
    );
    let banks = source.capture_banks.borrow();
    let banks = banks.as_ref().unwrap();
    assert!(banks.facts().is_err());
    assert!(!banks.transferred);
    assert!(banks.ancestry.is_some());
}

#[test]
fn capture_capacity_busy_foreign_and_short_rows_preserve_original_source() {
    let mut source = source();
    source
        .reserve_complete_capture_banks(limits(), 4 * 1024 * 1024)
        .unwrap();
    let lock = source.capture_banks.borrow_mut();
    assert_eq!(
        source.original_complete_capture_banks_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );
    drop(lock);
    let banks = source.capture_banks.borrow();
    let original = String::with_capacity(173);
    let mut census = OriginalOwnerCapacityMetadataData::new(3, None);
    census.observe(&original).unwrap();

    assert_eq!(
        banks.as_ref().unwrap().record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 3);
    assert_eq!(facts.string_capacity_bytes, original.capacity());
    assert_eq!(facts.vector_banks, 2);
    drop(banks);
    source.process = source.process.wrapping_add(1);
    assert_eq!(
        source.original_complete_capture_banks_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );
    assert!(source.ack_peer_birth.borrow().is_none());
}
