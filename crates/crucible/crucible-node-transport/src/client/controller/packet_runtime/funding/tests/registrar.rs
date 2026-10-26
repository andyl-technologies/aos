//! Checks append-only registrar rows against actual negotiated SDK custody.
//!
//! The actual controller supplies bank population DATA; no Source action is issued.

use super::*;
use crate::retained_metadata::records::{
    MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank,
};

fn prefix() -> MetadataCapacityRecord {
    MetadataCapacityRecord {
        kind: MetadataRecordKind::Vector,
        extent: 173,
        element_bytes: 1,
        alignment: 1,
    }
}

fn bank(fixture: &Fixture, available: usize) -> PacketRuntimeMetadataRecordBank {
    let mut bank = PacketRuntimeMetadataRecordBank::unallocated(&quote(fixture).unwrap()).unwrap();
    bank.reserve_retained_data().unwrap();
    for _ in 0..bank.maximum_rows() - available {
        bank.append_capacity_record_data(prefix()).unwrap();
    }
    bank
}

#[test]
fn registrar_capacity_appends_original_views_without_alias_discount_or_epoch_renewal() {
    let mut fixture = fixture(8, 262_144, 8);
    let controller = fixture.original.as_ref().unwrap();
    let read = controller
        .original_registrar_read(&fixture.handshake)
        .unwrap();
    let expected = read.retained_metadata_facts_data().unwrap();
    assert_eq!(expected.shared_backing_views, 2);
    assert_eq!(expected.capacity_records, 2);
    let mut bank = bank(&fixture, 4);
    let start = bank.rows().len();
    let allocated = bank.allocated_bytes();
    let saved =
        serde_json::to_value(read.borrowed_settled_history_data()).unwrap()["saved_epoch"].clone();

    controller
        .authority()
        .with_live(|| {
            assert!(read.ensure_current().is_err());
            assert_eq!(read.record_retained_capacity_data(&mut bank)?, expected);
            Ok(())
        })
        .unwrap();
    fixture.handshake.contain();
    assert!(read.ensure_current().is_err());
    assert_eq!(
        read.record_retained_capacity_data(&mut bank).unwrap(),
        expected
    );

    assert!(bank.rows()[..start].iter().all(|row| *row == prefix()));
    assert_eq!(
        &bank.rows()[start..start + 2],
        &bank.rows()[start + 2..start + 4]
    );
    assert_eq!(bank.allocated_bytes(), allocated);
    assert_eq!(
        serde_json::to_value(read.borrowed_settled_history_data()).unwrap()["saved_epoch"],
        saved
    );
    assert!(read.ensure_current().is_err());
    assert!(read.record_retained_capacity_data(&mut bank).is_err());
    assert_eq!(bank.rows().len(), start + 4);
}

#[test]
fn registrar_capacity_short_and_unallocated_banks_preserve_original_prefix() {
    let fixture = fixture(8, 262_144, 8);
    let read = fixture
        .original
        .as_ref()
        .unwrap()
        .original_registrar_read(&fixture.handshake)
        .unwrap();
    let mut unallocated =
        PacketRuntimeMetadataRecordBank::unallocated(&quote(&fixture).unwrap()).unwrap();
    assert!(
        read.record_retained_capacity_data(&mut unallocated)
            .is_err()
    );
    assert!(unallocated.rows().is_empty());
    assert_eq!(unallocated.allocated_bytes(), 0);
    let mut short = bank(&fixture, 1);
    let start = short.rows().len();
    let allocated = short.allocated_bytes();

    assert!(read.record_retained_capacity_data(&mut short).is_err());

    assert!(short.rows()[..start].iter().all(|row| *row == prefix()));
    assert_eq!(short.rows().len(), start + 1);
    assert_eq!(short.rows()[start].kind, MetadataRecordKind::Shared);
    assert!(read.record_retained_capacity_data(&mut short).is_err());
    assert_eq!(short.rows().len(), start + 1);
    assert_eq!(short.allocated_bytes(), allocated);
    read.ensure_current().unwrap();
}
