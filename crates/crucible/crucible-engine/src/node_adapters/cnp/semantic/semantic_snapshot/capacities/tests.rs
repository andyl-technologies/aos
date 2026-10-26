//! Checks actual reserved and refused semantic backing without capture authority.

use super::*;

#[test]
fn semantic_capacity_preserves_spare_and_failed_original_bank() {
    let mut reservation = Some(CnpSemanticSnapshotReservation::reserve(1024, 1024).unwrap());
    let reference = canonical::content_ref(b"original", "application/json").unwrap();
    assert!(record_original_bytes(&mut reservation, &reference, b"different").is_err());
    let bank = reservation.as_ref().unwrap();
    let pointer = bank.bytes.as_ptr();
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    bank.record_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.vector_banks, 1);
    assert_eq!(facts.vector_capacity_bytes, bank.allocated_bytes());
    assert_eq!(facts.observed_nodes, 0);
    assert_eq!(bank.bytes.as_ptr(), pointer);
    assert!(bank.started);
    assert!(bank.bytes.is_empty());
    assert!(record_original_bytes(&mut reservation, &reference, b"original").is_err());
}

#[test]
fn semantic_capacity_refusal_keeps_prior_component_and_original_backing() {
    let bank = CnpSemanticSnapshotReservation::reserve(1024, 1024).unwrap();
    let prior = String::with_capacity(173);
    let mut census = OriginalOwnerCapacityMetadataData::new(1, None);
    census.observe(&prior).unwrap();

    assert_eq!(
        bank.record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.string_capacity_bytes, prior.capacity());
    assert_eq!(facts.vector_banks, 0);
    assert_eq!(bank.allocated_bytes(), 1024);
    assert!(!bank.started);
}
