//! Checks real Source history loans without an installed observation claim.

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

#[test]
fn observation_capacity_source_keeps_empty_current_slot_for_all_three_members() {
    for member in 0..3 {
        let mut source = source(member);
        assert_eq!(
            source
                .original_first_and_current_observation_capacity_data(None)
                .unwrap()
                .capacity_records,
            0
        );
        OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut())
            .unwrap();

        let facts = source
            .original_first_and_current_observation_capacity_data(None)
            .unwrap();

        assert_eq!(facts.capacity_records, 1);
        assert_eq!(facts.vector_banks, 1);
        assert_eq!(facts.vector_capacity_bytes, 0);
        assert!(source.authenticate_current_native().is_err());
        assert!(
            PacketCompleteSemanticSource::original_first_and_current_observation_capacity_counter_scratch_data() > 0
        );
    }
}

#[test]
fn observation_capacity_source_busy_history_is_refused_without_changing_source() {
    let mut source = source(0);
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    let before = source
        .original_first_and_current_observation_capacity_data(None)
        .unwrap();
    let association = source.ack_peer_association.borrow();
    let held = association
        .as_ref()
        .unwrap()
        .current_observations
        .borrow_mut();

    assert_eq!(
        source.original_first_and_current_observation_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );

    drop(held);
    drop(association);
    assert_eq!(
        source
            .original_first_and_current_observation_capacity_data(None)
            .unwrap(),
        before
    );
}

#[test]
fn observation_capacity_source_foreign_origin_precedes_busy_association() {
    let mut source = source(0);
    source.process = source.process.wrapping_add(1);
    let held = source.ack_peer_association.borrow_mut();

    assert_eq!(
        source.original_first_and_current_observation_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );

    drop(held);
    source.process = std::process::id();
    assert_eq!(
        source
            .original_first_and_current_observation_capacity_data(None)
            .unwrap()
            .capacity_records,
        0
    );
}
