//! Checks Source Capture DTO backing through the closed SDK dispatch.
//!
//! These invalid journal roles remain ordinary DATA; their observation grants
//! neither journal eligibility nor a native completion witness.

use super::*;
use crate::protocol_snapshot::restored_journal17::{
    PacketRestoredSettledAncestry17, PacketRestoredSettledHistoryCut17,
    PacketRestoredSettledJournal17Objects,
};
use records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind};

fn reference(spare: usize) -> ContentRef {
    let mut reference =
        canonical::content_ref(b"independent journal DATA", "application/json").unwrap();
    reference.hash.digest.reserve(spare);
    reference.media_type.reserve(spare + 1);
    reference
}

fn strings(reference: &ContentRef) -> usize {
    reference.hash.algorithm.capacity()
        + reference.hash.domain.capacity()
        + reference.hash.digest.capacity()
        + reference.media_type.capacity()
}

fn ancestry() -> PacketRestoredSettledAncestry17 {
    PacketRestoredSettledAncestry17 {
        parent_archive_index: reference(101),
        parent_manifest: reference(103),
        first_semantic: reference(107),
        first_journal: reference(109),
        first_observation: reference(113),
        restoration_commit: reference(127),
        restoration_hold: reference(131),
    }
}

fn objects() -> PacketRestoredSettledJournal17Objects {
    PacketRestoredSettledJournal17Objects {
        snapshot: reference(137),
        before: reference(139),
        control: reference(149),
        anchor: reference(151),
        after: reference(157),
        host_protocol: reference(163),
        semantic: reference(167),
        runtime_object: reference(173),
        coordinator_checkpoint: reference(179),
    }
}

#[test]
fn source_capture_capacity_sdk_keeps_all_three_journal_families() {
    let ancestry = ancestry();
    let objects = objects();
    let cut = PacketRestoredSettledHistoryCut17 {
        prefix: reference(181),
        next_sequence: U64::new(0),
    };
    let ancestry_fields = [
        &ancestry.parent_archive_index,
        &ancestry.parent_manifest,
        &ancestry.first_semantic,
        &ancestry.first_journal,
        &ancestry.first_observation,
        &ancestry.restoration_commit,
        &ancestry.restoration_hold,
    ];
    let object_fields = [
        &objects.snapshot,
        &objects.before,
        &objects.control,
        &objects.anchor,
        &objects.after,
        &objects.host_protocol,
        &objects.semantic,
        &objects.runtime_object,
        &objects.coordinator_checkpoint,
    ];
    for (owner, fields, count) in [
        (
            RetainedCaptureProtocolData::RestoredCaptureAncestry(&ancestry),
            ancestry_fields.as_slice(),
            7,
        ),
        (
            RetainedCaptureProtocolData::RestoredCaptureObjects(&objects),
            object_fields.as_slice(),
            9,
        ),
        (
            RetainedCaptureProtocolData::RestoredCaptureHistoryCut(&cut),
            [&cut.prefix].as_slice(),
            1,
        ),
    ] {
        let facts = owner.observe_retained_metadata().unwrap();

        assert_eq!(facts.capacity_records, count * 4);
        assert_eq!(facts.string_banks, count * 4);
        assert_eq!(
            facts.string_capacity_bytes,
            fields.iter().map(|field| strings(field)).sum::<usize>()
        );
        assert_eq!(facts.vector_capacity_bytes, 0);
    }
    assert!(ancestry.validate_data().is_err());
    assert!(objects.validate_data().is_err());
}

#[test]
fn source_capture_capacity_sdk_repeated_views_keep_each_physical_row() {
    let ancestry = ancestry();
    let owner = RetainedCaptureProtocolData::RestoredCaptureAncestry(&ancestry);
    let expected = owner.observe_retained_metadata().unwrap();
    let mut bank = MetadataRecordBank::reserve(56).unwrap();
    let mut observer = MetadataObserver::appending(&mut bank);

    owner.observe_into(&mut observer).unwrap();
    owner.observe_into(&mut observer).unwrap();

    let facts = observer.finish();
    assert_eq!(
        facts.string_capacity_bytes,
        2 * expected.string_capacity_bytes
    );
    assert_eq!(facts.capacity_records, 56);
    assert_eq!(bank.rows().len(), 56);
    assert_eq!(bank.rows()[..28], bank.rows()[28..]);
    assert!(ancestry.validate_data().is_err());
}

#[test]
fn source_capture_capacity_sdk_short_bank_preserves_prior_row_and_first_reference() {
    let ancestry = ancestry();
    let prefix = MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: 191,
        element_bytes: 1,
        alignment: 1,
    };
    let mut bank = MetadataRecordBank::reserve(5).unwrap();
    bank.append(prefix).unwrap();
    let backing = bank.allocated_bytes();
    let mut observer = MetadataObserver::appending(&mut bank);

    assert!(
        RetainedCaptureProtocolData::RestoredCaptureAncestry(&ancestry)
            .observe_into(&mut observer)
            .is_err()
    );
    let _partial = observer.finish();

    assert_eq!(bank.rows().len(), 5);
    assert_eq!(bank.rows()[0], prefix);
    assert_eq!(
        bank.rows()[1..].iter().map(|row| row.extent).sum::<usize>(),
        strings(&ancestry.parent_archive_index)
    );
    assert_eq!(bank.allocated_bytes(), backing);
    assert!(ancestry.validate_data().is_err());
}
