//! Checks capacity DATA on an emitter issued by the actual immutable SDK codec.
//!
//! The existing fixture models Hello verification and peer behavior. These
//! controls establish retained backing, never native or Source18 permission.

use super::*;
use crate::retained_metadata::{
    MetadataObserver, RetainedCaptureProtocolData,
    records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind},
};

fn prefix() -> MetadataCapacityRecord {
    MetadataCapacityRecord {
        kind: MetadataRecordKind::Vector,
        extent: 173,
        element_bytes: 1,
        alignment: 1,
    }
}

#[test]
fn ack_capacity_data_keeps_actual_issued_emitter_after_registrar_revocation() {
    let (mut handshake, controller, mut peer, _) = fixture();
    let emitter = controller
        .retain_original_canonical_blob_ack_emitter()
        .unwrap();
    let expected = emitter.original_retained_metadata_facts().unwrap();
    assert!(expected.shared_backing_views >= 5);
    let before = RetainedCaptureProtocolData::AckEmitter(&emitter)
        .observe_retained_metadata()
        .unwrap();
    assert_eq!(before, expected);
    emitter.authenticate_original(&controller).unwrap();

    controller
        .authority()
        .with_live(|| {
            assert!(emitter.authenticate_original(&controller).is_err());
            assert_eq!(
                RetainedCaptureProtocolData::AckEmitter(&emitter).observe_retained_metadata()?,
                before
            );
            Ok(())
        })
        .unwrap();
    handshake.contain();

    assert!(emitter.original_retained_metadata_facts().is_err());
    assert!(emitter.authenticate_original(&controller).is_err());
    assert_eq!(
        RetainedCaptureProtocolData::AckEmitter(&emitter)
            .observe_retained_metadata()
            .unwrap(),
        before
    );
    assert_eq!(
        RetainedCaptureProtocolData::AckEmitter(&emitter)
            .observe_retained_metadata()
            .unwrap(),
        before
    );
    assert_no_wire(&mut peer);
}

#[test]
fn ack_capacity_data_preserves_prior_rows_short_prefixes_and_repeated_views() {
    let (_handshake, controller, mut peer, _) = fixture();
    let emitter = controller
        .retain_original_canonical_blob_ack_emitter()
        .unwrap();
    let expected = emitter.original_retained_metadata_facts().unwrap();
    let mut records = MetadataRecordBank::reserve(1 + 2 * expected.capacity_records).unwrap();
    records.append(prefix()).unwrap();
    let backing = records.allocated_bytes();
    for _ in 0..2 {
        let mut observer = MetadataObserver::appending(&mut records);
        emitter.observe_capacity_data(&mut observer).unwrap();
        assert_eq!(observer.finish(), expected);
    }
    assert_eq!(records.rows()[0], prefix());
    assert_eq!(
        &records.rows()[1..1 + expected.capacity_records],
        &records.rows()[1 + expected.capacity_records..]
    );
    assert_eq!(records.allocated_bytes(), backing);

    let mut short = MetadataRecordBank::reserve(2).unwrap();
    short.append(prefix()).unwrap();
    let mut observer = MetadataObserver::appending(&mut short);
    assert!(emitter.observe_capacity_data(&mut observer).is_err());
    let _partial = observer.finish();
    assert_eq!(short.rows()[0], prefix());
    assert_eq!(short.rows().len(), 2);
    assert_eq!(short.rows()[1].kind, MetadataRecordKind::Shared);
    emitter.authenticate_original(&controller).unwrap();
    assert_no_wire(&mut peer);
}
