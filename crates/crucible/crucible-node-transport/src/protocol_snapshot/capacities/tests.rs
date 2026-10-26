//! Checks genuine SDK reservations and issuer moves as capacity DATA only.
//!
//! Test handshakes supply the existing protocol models; these controls qualify
//! no real native child, completed Initial or enclosing Source handoff.

use super::*;
use crate::retained_metadata::RetainedCaptureProtocolData;

#[test]
fn snapshot_capacity_roster_preserves_every_independent_spare_bank() {
    for reservation in [
        ProtocolSnapshotReservation::reserve(1024).unwrap(),
        ProtocolSnapshotReservation::reserve_complete(1024, 2048, 3).unwrap(),
        ProtocolSnapshotReservation::reserve_complete_compact(1024, 2048, 3).unwrap(),
        ProtocolSnapshotReservation::reserve_complete_owned11(1024, 2048, 3, 11).unwrap(),
    ] {
        let expected = reservation.original_allocation_facts().unwrap();
        let pointer = reservation.bytes.as_ptr();

        let facts = RetainedCaptureProtocolData::SnapshotReservation(&reservation)
            .observe_retained_metadata()
            .unwrap();

        assert_eq!(facts.vector_capacity_bytes, expected.allocated_bytes);
        assert_eq!(
            facts.vector_banks,
            if reservation.owned11_records.is_some() {
                6
            } else if reservation.literal.is_some() {
                3
            } else {
                1
            }
        );
        assert_eq!(facts.capacity_records, facts.vector_banks);
        assert_eq!(facts.shared_backing_views, 0);
        assert_eq!(reservation.bytes.as_ptr(), pointer);
        assert!(reservation.bytes.is_empty());
        assert!(reservation.issuer.is_none());
    }
}

#[test]
fn snapshot_capacity_move_keeps_associations_and_charges_encoded_bytes_only_at_current_owner() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let owner = Rc::new(ProtocolCaptureOwner::new());
    let deadline =
        crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
            .unwrap();
    let mut reservation = ProtocolSnapshotReservation::reserve_complete(4096, 2048, 3).unwrap();
    reservation
        .bind(
            &authority,
            &owner,
            ProtocolCaptureCut::HostSettled,
            deadline,
        )
        .unwrap();
    reservation
        .encode(&serde_json::json!({"retained":"original"}))
        .unwrap();
    let before = RetainedCaptureProtocolData::SnapshotReservation(&reservation)
        .observe_retained_metadata()
        .unwrap();
    let snapshot = reservation
        .finish(&authority, &owner, ProtocolCaptureCut::HostSettled)
        .unwrap();
    let pointer = snapshot.bytes().as_ptr();
    let issued = snapshot.original_allocation_facts().unwrap();

    let snapshot_facts = RetainedCaptureProtocolData::Snapshot(&snapshot)
        .observe_retained_metadata()
        .unwrap();
    let (payload, bytes) = snapshot.into_original_payload();
    let payload_facts = RetainedCaptureProtocolData::PayloadOwner(&payload)
        .observe_retained_metadata()
        .unwrap();

    assert_eq!(before, snapshot_facts);
    assert_eq!(payload_facts.vector_banks + 1, snapshot_facts.vector_banks);
    assert_eq!(
        payload_facts.capacity_records + 1,
        snapshot_facts.capacity_records
    );
    assert_eq!(
        payload_facts.vector_capacity_bytes + bytes.capacity(),
        snapshot_facts.vector_capacity_bytes
    );
    assert_eq!(
        payload_facts.shared_backing_views,
        snapshot_facts.shared_backing_views
    );
    assert_eq!(
        payload_facts.string_capacity_bytes,
        snapshot_facts.string_capacity_bytes
    );
    assert_eq!(bytes.as_ptr(), pointer);
    assert_eq!(payload.original_allocation_facts().unwrap(), issued);
}

#[test]
fn snapshot_capacity_borrow_and_foreign_creator_refuse_without_changing_banks() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let owner = Rc::new(ProtocolCaptureOwner::new());
    let deadline =
        crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
            .unwrap();
    let mut reservation = ProtocolSnapshotReservation::reserve_complete(4096, 2048, 3).unwrap();
    reservation
        .bind(
            &authority,
            &owner,
            ProtocolCaptureCut::HostSettled,
            deadline,
        )
        .unwrap();
    let hello = Rc::new(RefCell::new(
        OriginalFrameReservation::reserve(512, 2).unwrap(),
    ));
    reservation.retain_owned_hello(hello.clone());
    let pointer = reservation.bytes.as_ptr();
    let lock = hello.borrow_mut();

    assert!(
        RetainedCaptureProtocolData::SnapshotReservation(&reservation)
            .observe_retained_metadata()
            .is_err()
    );
    drop(lock);
    assert!(
        RetainedCaptureProtocolData::SnapshotReservation(&reservation)
            .observe_retained_metadata()
            .is_ok()
    );
    reservation.issuer.as_mut().unwrap().1 = Rc::new(ProtocolCaptureOwner {
        pid: std::process::id().wrapping_add(1),
        thread: std::thread::current().id(),
    });
    assert!(
        RetainedCaptureProtocolData::SnapshotReservation(&reservation)
            .observe_retained_metadata()
            .is_err()
    );
    assert_eq!(reservation.bytes.as_ptr(), pointer);
    assert!(reservation.bytes.is_empty());
}

#[test]
fn snapshot_capacity_short_physical_rows_preserve_prior_component_and_initialized_prefix() {
    let reservation =
        ProtocolSnapshotReservation::reserve_complete_owned11(1024, 2048, 3, 11).unwrap();
    let mut records = MetadataRecordBank::reserve(3).unwrap();
    let prefix = MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: 173,
        element_bytes: 1,
        alignment: 1,
    };
    records.append(prefix).unwrap();
    let mut observer = MetadataObserver::appending(&mut records);

    assert!(reservation.observe_capacity_data(&mut observer).is_err());

    assert_eq!(records.rows().len(), 3);
    assert_eq!(records.rows()[0], prefix);
    assert_eq!(records.rows()[1].extent, reservation.bytes.capacity());
    assert_eq!(
        records.rows()[2],
        reservation
            .owned11_records
            .as_ref()
            .unwrap()
            .retained_capacity_data()
    );
    assert!(reservation.bytes.is_empty());
    assert!(reservation.issuer.is_none());
}
