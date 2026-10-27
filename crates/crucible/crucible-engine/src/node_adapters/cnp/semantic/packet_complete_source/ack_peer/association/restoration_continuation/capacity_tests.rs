//! Checks fixed failed seed DATA without issuing a seed or a signing claim.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;
use crucible_node_format::{Phase, Tick, U64};

fn source() -> PacketCompleteSemanticSource {
    let coordinator = fixture::coordinator();
    let installation = fixture::installation(&coordinator, 0);
    PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation,
        fixture::producer(),
        coordinator,
        fixture::storage_selection(),
    )
    .unwrap()
}

fn failed_seed(source: &PacketCompleteSemanticSource) -> OriginalRestoredSuffixSeed {
    OriginalRestoredSuffixSeed {
        process: std::process::id(),
        thread: std::thread::current().id(),
        source,
        controller: std::ptr::null(),
        checkpoint: Some(OriginalRestoredSuffixCheckpointData {
            restoration_proof: [1; 32],
            native_binding: [2; 32],
            observation_binding: [3; 32],
            reached: Position::new(Tick::new(4), U64::new(2), Phase::Reaction),
        }),
        signature: Some([5; 32]),
        stage: Stage::Failed,
    }
}

#[test]
fn input_suffix_capacity_fixed_failed_seed_adds_no_backing_or_permission() {
    let source = source();
    let seed = failed_seed(&source);
    let prefix = String::with_capacity(229);
    let mut census = OriginalOwnerCapacityMetadataData::new(1, None);
    census.observe(&prefix).unwrap();

    seed.record_capacity_data(&source, &mut census).unwrap();

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.string_capacity_bytes, prefix.capacity());
    assert_eq!(seed.retained_heap_bytes_data(), 0);
    assert_eq!(seed.stage, Stage::Failed);
    assert_eq!(seed.signature, Some([5; 32]));
    assert!(seed.controller.is_null());
    assert!(OriginalRestoredSuffixSeed::capacity_counter_scratch_data() > 0);
    assert!(source.authenticate_current_native().is_err());
}

#[test]
fn input_suffix_capacity_fixed_seed_foreign_identity_refuses_before_rows() {
    let source = source();
    let other = self::source();
    for process in [true, false] {
        let mut seed = failed_seed(&source);
        if process {
            seed.process = seed.process.wrapping_add(1);
        } else {
            seed.source = &other;
        }
        let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

        assert_eq!(
            seed.record_capacity_data(&source, &mut census),
            Err(RuntimeError::ForeignAuthority)
        );

        assert_eq!(census.finish().capacity_records, 0);
        assert_eq!(seed.stage, Stage::Failed);
    }
}

#[test]
fn input_suffix_capacity_source_retains_failed_seed_without_completing_it() {
    let mut source = source();
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    {
        let association = source.ack_peer_association.borrow();
        *association.as_ref().unwrap().restored_suffix.borrow_mut() = Some(failed_seed(&source));
    }

    let facts = source
        .original_restored_input_and_suffix_capacity_data(None)
        .unwrap();

    let association = source.ack_peer_association.borrow();
    let seed = association.as_ref().unwrap().restored_suffix.borrow();
    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.vector_capacity_bytes, 0);
    assert_eq!(seed.as_ref().unwrap().stage, Stage::Failed);
    assert!(source.authenticate_current_native().is_err());
}
