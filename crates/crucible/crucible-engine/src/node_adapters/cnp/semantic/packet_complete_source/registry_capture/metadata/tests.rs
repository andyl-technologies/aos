//! Checks independent registry bank accounting and refusal without registry grants.

use super::super::super::tests::{coordinator, installation, producer, storage_selection};
use super::*;

fn capture() -> OriginalCompleteRegistryCapture {
    let mut capture = None;
    OriginalCompleteRegistryCapture::reserve_into(&mut capture, 1024, 7, 65536).unwrap();
    capture.unwrap()
}

// Keep the original separate byte formula as an independent census oracle.
fn original_bytes(capture: &OriginalCompleteRegistryCapture) -> usize {
    capture.encoded.capacity()
        + capture
            .records
            .as_ref()
            .map_or(0, MetadataRecordBank::allocated_bytes)
        + capture
            .aliases
            .as_ref()
            .map_or(0, MetadataAliasBank::allocated_bytes)
        + capture.payload.as_ref().map_or(0, |payload| {
            payload.bytes.capacity()
                + NodeRuntime::capture_reference_storage(&payload.reference).unwrap()
        })
}

#[test]
fn registry_census_matches_independent_spare_backing_and_exact_credit() {
    let capture = capture();
    let bytes = original_bytes(&capture);
    let pointer = capture.encoded.as_ptr();

    let facts = capture.capacity_facts_data(None).unwrap();

    assert_eq!(facts.capacity_records, 4);
    assert_eq!(facts.vector_banks, 4);
    assert_eq!(facts.vector_capacity_bytes, bytes);
    assert_eq!(facts.string_banks, 0);
    assert_eq!(facts.observed_nodes, 1); // The actual empty encoding Vec.
    assert_eq!(
        capture.retained_storage_with_error::<RuntimeError>(bytes),
        Ok(bytes)
    );
    assert_eq!(
        capture.retained_storage_with_error::<RuntimeError>(bytes - 1),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(capture.encoded.as_ptr(), pointer);
    assert!(!capture.attempted);
    assert!(capture.completed_payload().is_err());
}

#[test]
fn registry_payload_move_and_refused_completion_keep_actual_backing() {
    let mut capture = capture();
    let before = original_bytes(&capture);
    let original_pointer = capture.encoded.as_ptr();
    capture.payload = Some(InputPayload {
        reference: canonical::content_ref(b"retained registry DATA", "application/json").unwrap(),
        bytes: std::mem::take(&mut capture.encoded),
    });
    capture.failed = true;
    let bytes = original_bytes(&capture);

    let facts = capture.capacity_facts_data(None).unwrap();

    assert_eq!(facts.vector_banks, 5);
    assert_eq!(facts.string_banks, 4);
    assert_eq!(facts.capacity_records, 9);
    assert_eq!(facts.vector_capacity_bytes, before);
    assert_eq!(
        facts.vector_capacity_bytes + facts.string_capacity_bytes,
        bytes
    );
    assert_eq!(
        capture.retained_storage_with_error::<RuntimeError>(bytes),
        Ok(bytes)
    );
    assert_eq!(
        capture.payload.as_ref().unwrap().bytes.as_ptr(),
        original_pointer
    );
    assert!(capture.encoded.is_empty());
    assert_eq!(capture.encoded.capacity(), 0);
    assert!(capture.completed_payload().is_err());
    assert!(capture.failed);
}

#[test]
fn registry_short_rows_preserve_the_prior_component_and_refused_prefix() {
    let capture = capture();
    let original = String::with_capacity(173);
    let mut census = OriginalOwnerCapacityMetadataData::new(4, None);
    census.observe(&original).unwrap();

    let result = capture.record_retained_capacity_data(&mut census);
    let facts = census.finish();

    assert_eq!(result, Err(RuntimeError::ResourceLimit));
    assert_eq!(facts.capacity_records, 4);
    assert_eq!(facts.string_banks, 1);
    assert_eq!(facts.string_capacity_bytes, original.capacity());
    assert_eq!(facts.vector_banks, 3);
    assert_eq!(
        facts.vector_capacity_bytes,
        capture.encoded.capacity()
            + capture.records.as_ref().unwrap().allocated_bytes()
            + capture
                .aliases
                .as_ref()
                .unwrap()
                .allocation_facts()
                .row_bytes
    );
    assert!(!capture.attempted);
    assert!(!capture.failed);
}

#[test]
fn source_registry_census_refuses_busy_or_foreign_custody_without_reservation() {
    let coordinator = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&coordinator, 0),
        producer(),
        coordinator,
        storage_selection(),
    )
    .unwrap();
    assert_eq!(
        source
            .original_complete_registry_capacity_data(None)
            .unwrap(),
        RetainedProtocolMetadataFacts::default()
    );
    let loan = source.registry_capture.borrow_mut();

    assert_eq!(
        source.original_complete_registry_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );
    drop(loan);
    source.process = source.process.wrapping_add(1);

    assert_eq!(
        source.original_complete_registry_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );
    assert!(source.registry_capture.borrow().is_none());
    assert!(!source.registry_retention_attempted.get());
    assert!(!source.registry_retention_failed.get());
}
