//! Checks independent partial materialization backing without native eligibility.

use super::*;
use crate::node_scheduling::InputPayload;
use crucible_node_format::canonical;

fn reference(spare: usize) -> ContentRef {
    let mut reference =
        canonical::content_ref(b"failed materialization DATA", "application/json").unwrap();
    reference.hash.digest.reserve(spare);
    reference
}

fn reference_strings(reference: &ContentRef) -> usize {
    reference.hash.algorithm.capacity()
        + reference.hash.domain.capacity()
        + reference.hash.digest.capacity()
        + reference.media_type.capacity()
}

#[test]
fn source_capture_capacity_materialization_keeps_failed_copies_and_evidence() {
    let mut owner = CaptureMaterializationOwner::empty();
    owner.started = true;
    owner.failed = true;
    owner.participants.reserve_exact(3);
    owner.evidence.reserve_exact(5);
    owner.evidence.push(InputPayload {
        reference: reference(193),
        bytes: Vec::with_capacity(197),
    });
    let mut expected_vectors = owner.participants.capacity() * size_of::<Id>()
        + owner.evidence.capacity() * size_of::<InputPayload>()
        + owner.evidence[0].bytes.capacity();
    let mut expected_strings = reference_strings(&owner.evidence[0].reference);
    for (index, slot) in owner.slots.iter_mut().enumerate() {
        slot.started = true;
        slot.reference = Some(reference(199 + index));
        slot.bytes.reserve_exact(211 + index);
        expected_vectors += slot.bytes.capacity();
        expected_strings += reference_strings(slot.reference.as_ref().unwrap());
    }
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    owner.record_capacity_data(&mut census).unwrap();

    let facts = census.finish();
    assert_eq!(facts.vector_capacity_bytes, expected_vectors);
    assert_eq!(facts.string_capacity_bytes, expected_strings);
    assert_eq!(
        owner.retained_storage_data(usize::MAX).unwrap(),
        expected_vectors + expected_strings
    );
    assert!(owner.failed);
    assert!(!owner.transferred);
    assert!(
        owner
            .slots
            .iter()
            .all(|slot| slot.started && !slot.completed)
    );
    assert!(
        owner
            .slots
            .iter_mut()
            .all(|slot| slot.take_data().is_none())
    );
}

#[test]
fn source_capture_capacity_short_materialization_keeps_first_actual_bank() {
    let mut owner = CaptureMaterializationOwner::empty();
    owner.failed = true;
    owner.participants.reserve_exact(3);
    let prefix = String::with_capacity(223);
    let mut census = OriginalOwnerCapacityMetadataData::new(2, None);
    census.observe(&prefix).unwrap();

    assert_eq!(
        owner.record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 2);
    assert_eq!(facts.string_capacity_bytes, prefix.capacity());
    assert_eq!(
        facts.vector_capacity_bytes,
        owner.participants.capacity() * size_of::<Id>()
    );
    assert!(owner.failed);
    assert!(!owner.transferred);
}
