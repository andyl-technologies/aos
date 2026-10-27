//! Checks the actual Source installation component without issuing native rights.

use super::super::super::tests::{
    coordinator, installation, producer, reactive, storage_selection,
};
use super::*;
use crucible_node_transport::reference_packet::PacketEvent;

fn source(member: usize, spare: bool) -> PacketCompleteSemanticSource {
    let coordinator = coordinator();
    let mut installation = installation(&coordinator, member);
    if spare {
        installation.facets.reserve_exact(37);
    }
    if member == 0 {
        let mut program = producer();
        if spare {
            program.events.reserve_exact(23);
        }
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installation,
            program,
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
fn actual_producer_spare_capacities_change_bytes_without_inventing_rows_or_trees() {
    let original = source(0, false);
    let current = source(0, true);
    let before = original
        .original_complete_installation_capacity_data(None)
        .unwrap();
    let after = current
        .original_complete_installation_capacity_data(None)
        .unwrap();
    let before_events = match &original.original {
        CompletePacketOriginal::Producer(source) => {
            source.original_program_data().events.capacity()
        }
        _ => unreachable!(),
    };
    let after_events = match &current.original {
        CompletePacketOriginal::Producer(source) => {
            source.original_program_data().events.capacity()
        }
        _ => unreachable!(),
    };
    let extra = (after_events - before_events) * size_of::<PacketEvent>()
        + (current.installation().facets.capacity() - original.installation().facets.capacity())
            * size_of::<FacetKind>();

    assert!(extra > 0);
    assert_eq!(
        after.vector_capacity_bytes - before.vector_capacity_bytes,
        extra
    );
    assert_eq!(after.vector_banks, before.vector_banks);
    assert_eq!(after.string_capacity_bytes, before.string_capacity_bytes);
    assert_eq!(after.capacity_records, before.capacity_records);
    assert_eq!(after.tree_containers, before.tree_containers);
    assert_eq!(after.tree_entries, before.tree_entries);
    assert_eq!(
        after.maximum_tree_key_value_bytes,
        before.maximum_tree_key_value_bytes
    );
    assert_eq!(after.boxed_value_bytes, before.boxed_value_bytes);
    assert_eq!(
        current
            .original_complete_installation_storage_data(usize::MAX)
            .unwrap()
            - original
                .original_complete_installation_storage_data(usize::MAX)
                .unwrap(),
        extra
    );
}

#[test]
fn all_actual_source_roles_retain_geometry_at_exact_cost_and_one_byte_short() {
    for member in 0..3 {
        let source = source(member, true);
        let before = source
            .original_complete_installation_capacity_data(None)
            .unwrap();
        let actual = source
            .original_complete_installation_storage_data_with_error::<RuntimeError>(usize::MAX)
            .unwrap();

        assert!(before.capacity_records > 0);
        assert!(before.tree_containers > 0);
        assert!(before.vector_banks >= 2);
        assert!(before.boxed_value_bytes >= size_of::<PacketNative5CoordinatorInstallation>());
        assert_eq!(
            source.original_complete_installation_storage_data_with_error::<RuntimeError>(actual),
            Ok(actual)
        );
        assert_eq!(
            source
                .original_complete_installation_storage_data_with_error::<RuntimeError>(actual - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert_eq!(
            source
                .original_complete_installation_capacity_data(None)
                .unwrap(),
            before
        );
        assert!(source.ack_peer_birth.borrow().is_none());
        assert!(source.capture_banks.borrow().is_none());
    }
}

#[test]
fn foreign_source_refuses_before_the_actual_field_graph_is_observed() {
    let mut source = source(0, true);
    let before = source
        .original_complete_installation_capacity_data(None)
        .unwrap();
    let process = source.process;
    source.process = process.wrapping_add(1);
    assert_eq!(
        source.original_complete_installation_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );
    source.process = process;
    assert_eq!(
        source
            .original_complete_installation_capacity_data(None)
            .unwrap(),
        before
    );
}

#[test]
fn capacity_census_matches_the_independent_original_component_accounting() {
    for member in 0..3 {
        for spare in [false, true] {
            let source = source(member, spare);
            let (view, facets, activation) = source
                .borrowed_installation_capacity_parts::<RuntimeError>()
                .unwrap();
            let protocol = view.observe_retained_metadata().unwrap();
            let baseline =
                PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                    &protocol,
                    usize::MAX,
                )
                .unwrap()
                    + facets.capacity() * size_of::<FacetKind>()
                    + size_of::<PacketNative5CoordinatorInstallation>()
                    + super::super::activation_storage_with_error::<RuntimeError>(
                        activation,
                        usize::MAX,
                    )
                    .unwrap();
            let actual = source
                .original_complete_installation_storage_data_with_error::<RuntimeError>(usize::MAX)
                .unwrap();

            assert_eq!(actual, baseline);
        }
    }
}
