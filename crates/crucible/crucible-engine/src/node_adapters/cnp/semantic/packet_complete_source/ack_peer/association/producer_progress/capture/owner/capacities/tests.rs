//! Checks original Capture loans and inert failed-phase capacity DATA.
//!
//! Failed private slots exercise retained geometry only. They neither fabricate
//! a Window construction row nor establish native Capture completion.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;

fn source(member: usize) -> PacketCompleteSemanticSource {
    let coordinator = fixture::coordinator();
    let installation = fixture::installation(&coordinator, member);
    if member == 0 {
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installation,
            fixture::producer(),
            coordinator,
            fixture::storage_selection(),
        )
        .unwrap()
    } else {
        let definition = fixture::reactive(&coordinator, member);
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation,
            definition,
            coordinator,
            fixture::storage_selection(),
        )
        .unwrap()
    }
}

#[test]
fn source_capture_capacity_empty_owners_preserve_all_three_declarations() {
    for member in 0..3 {
        let mut source = source(member);
        assert_eq!(
            source
                .original_restored_capture_capacity_data(None)
                .unwrap()
                .capacity_records,
            0
        );
        OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut())
            .unwrap();

        let facts = source
            .original_restored_capture_capacity_data(None)
            .unwrap();

        assert!(facts.capacity_records > 0);
        assert_eq!(facts.vector_capacity_bytes, 0);
        assert_eq!(facts.string_capacity_bytes, 0);
        assert_eq!(
            source
                .original_restored_capture_capacity_data(None)
                .unwrap(),
            facts
        );
        assert!(source.authenticate_current_native().is_err());
        assert!(
            PacketCompleteSemanticSource::original_restored_capture_capacity_counter_scratch_data()
                > 0
        );
    }
}

#[test]
fn source_capture_capacity_all_three_loans_refuse_busy_custody() {
    let mut source = source(0);
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    let before = source
        .original_restored_capture_capacity_data(None)
        .unwrap();
    {
        let _association = source.ack_peer_association.borrow_mut();
        assert_eq!(
            source.original_restored_capture_capacity_data(None),
            Err(RuntimeError::OwnerBusy)
        );
    }
    let association = source.ack_peer_association.borrow();
    let original = association.as_ref().unwrap();
    {
        let _capture = original.restored_capture.borrow_mut();
        assert_eq!(
            source.original_restored_capture_capacity_data(None),
            Err(RuntimeError::OwnerBusy)
        );
    }
    {
        let capture = original.restored_capture.borrow();
        let _materialization = capture.materialization.borrow_mut();
        assert_eq!(
            source.original_restored_capture_capacity_data(None),
            Err(RuntimeError::OwnerBusy)
        );
    }

    assert_eq!(
        source
            .original_restored_capture_capacity_data(None)
            .unwrap(),
        before
    );
}

#[test]
fn source_capture_capacity_foreign_creator_precedes_busy_association() {
    for process in [true, false] {
        let mut source = source(0);
        if process {
            source.process = source.process.wrapping_add(1);
        } else {
            source.thread = std::thread::spawn(|| std::thread::current().id())
                .join()
                .unwrap();
        }
        let _association = source.ack_peer_association.borrow_mut();

        assert_eq!(
            source.original_restored_capture_capacity_data(None),
            Err(RuntimeError::ForeignAuthority)
        );
    }
}

#[test]
fn source_capture_capacity_failed_construction_keeps_independent_spare_banks() {
    let mut source = source(0);
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    let baseline = source
        .original_restored_capture_capacity_data(None)
        .unwrap();
    let association = source.ack_peer_association.borrow();
    let original = association.as_ref().unwrap();
    let expected;
    {
        let mut capture = original.restored_capture.borrow_mut();
        capture.stage = Stage::Preparing;
        let construction = &mut capture.construction;
        construction.started = true;
        construction.final_started = true;
        construction.final_bytes.reserve_exact(151);
        construction.node_bytes.reserve_exact(157);
        let mut text = String::with_capacity(163);
        text.push_str("failed final envelope DATA");
        expected = (
            construction.final_bytes.capacity() + construction.node_bytes.capacity(),
            text.capacity(),
        );
        construction.final_value = Some(serde_json::Value::String(text));
    }

    let facts = source
        .original_restored_capture_capacity_data(None)
        .unwrap();

    assert_eq!(
        facts.vector_capacity_bytes - baseline.vector_capacity_bytes,
        expected.0
    );
    assert_eq!(
        facts.string_capacity_bytes - baseline.string_capacity_bytes,
        expected.1
    );
    let capture = original.restored_capture.borrow();
    assert!(capture.stage == Stage::Preparing);
    assert!(capture.construction.final_started);
    assert!(capture.construction.final_reference.is_none());
    assert!(capture.completed_prefix_payload17_data().is_err());
    assert!(source.authenticate_current_native().is_err());
}

#[test]
fn source_capture_capacity_short_census_preserves_prior_component() {
    let source = source(0);
    let capture = CaptureOnceOwner::new_data();
    let read = capture.capacity_read_data(&source).unwrap();
    let prefix = String::with_capacity(173);
    let mut census = OriginalOwnerCapacityMetadataData::new(1, None);
    census.observe(&prefix).unwrap();

    assert_eq!(
        read.record_capacity_data(&source, &mut census),
        Err(RuntimeError::ResourceLimit)
    );

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.string_capacity_bytes, prefix.capacity());
    assert!(capture.stage == Stage::Unused);
}
