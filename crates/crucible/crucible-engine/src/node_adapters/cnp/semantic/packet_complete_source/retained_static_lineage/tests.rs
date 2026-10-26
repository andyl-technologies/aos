//! Checks genuine declaration holders without native or installed static custody.

use super::super::tests::{coordinator, installation, producer, reactive, storage_selection};
use super::*;

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
fn all_three_static_lineage_views_keep_actual_empty_banks_without_installing_rows() {
    for member in 0..3 {
        let source = source(member);

        let facts = source
            .original_complete_static_lineage_capacity_data(None)
            .unwrap();

        assert_eq!(facts.capacity_records, usize::from(member != 0));
        assert_eq!(facts.vector_banks, usize::from(member != 0));
        assert_eq!(facts.string_banks, 0);
        assert_eq!(facts.shared_backing_views, 0);
        assert_eq!(facts.observed_nodes, 0);
        assert!(source.ack_peer_birth.borrow().is_none());
        if member != 0 {
            assert!(
                source
                    .original_complete_static_lineage_storage_data(usize::MAX)
                    .is_err()
            );
        }
    }
}

#[test]
fn foreign_static_lineage_source_refuses_before_observing_any_child() {
    for member in 0..3 {
        let mut source = source(member);
        source.process = source.process.wrapping_add(1);

        assert_eq!(
            source.original_complete_static_lineage_capacity_data(None),
            Err(RuntimeError::ForeignAuthority)
        );
        assert!(source.ack_peer_birth.borrow().is_none());
    }
}
