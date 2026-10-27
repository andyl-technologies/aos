//! Checks actual Source reservations without manufacturing restoration authority.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests::{
    coordinator, installation, producer, reactive, storage_selection,
};

fn source(member: usize) -> PacketCompleteSemanticSource {
    let coordinator = coordinator();
    let installation = installation(&coordinator, member);
    if member == 0 {
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installation,
            producer(),
            coordinator,
            storage_selection(),
        )
        .unwrap()
    } else {
        let definition = reactive(&coordinator, member);
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation,
            definition,
            coordinator,
            storage_selection(),
        )
        .unwrap()
    }
}

fn reserve(source: &mut PacketCompleteSemanticSource) {
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    let association = source.ack_peer_association.get_mut().as_mut().unwrap();
    association.reserve_complete_restore_banks(8192).unwrap();
    association
        .reserve_restore_transfer_phase_banks(8192)
        .unwrap();
}

#[test]
fn restoration_capacity_source_keeps_distinct_transfer_reservations_for_all_three_members() {
    for member in 0..3 {
        let mut source = source(member);
        assert_eq!(
            source
                .original_restoration_phase_capacity_data(None)
                .unwrap()
                .capacity_records,
            0
        );
        reserve(&mut source);
        let association = source.ack_peer_association.borrow();
        let transfer = association
            .as_ref()
            .unwrap()
            .restore_transfer_banks
            .as_ref()
            .unwrap();
        let independent = transfer.allocated_bytes().unwrap();
        drop(association);

        let facts = source
            .original_restoration_phase_capacity_data(None)
            .unwrap();

        assert_eq!(facts.capacity_records, 10);
        assert_eq!(facts.vector_banks, 10);
        assert_eq!(facts.vector_capacity_bytes, independent);
        assert!(source.authenticate_current_native().is_err());
    }
}

#[test]
fn restoration_capacity_source_busy_and_foreign_origin_leave_reservations_unchanged() {
    let mut source = source(0);
    reserve(&mut source);
    let before = source
        .original_restoration_phase_capacity_data(None)
        .unwrap();
    let held = source.ack_peer_association.borrow_mut();
    assert_eq!(
        source.original_restoration_phase_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );
    drop(held);
    source.process = source.process.wrapping_add(1);
    let held = source.ack_peer_association.borrow_mut();
    assert_eq!(
        source.original_restoration_phase_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );
    drop(held);
    source.process = std::process::id();
    assert_eq!(
        source
            .original_restoration_phase_capacity_data(None)
            .unwrap(),
        before
    );
    assert!(
        PacketCompleteSemanticSource::original_restoration_phase_capacity_counter_scratch_data()
            > 0
    );
}
