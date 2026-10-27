//! Checks capacity DATA without constructing a quoted Input17 claim.
//!
//! Populated failed slots below are deliberately inert private test states. They
//! establish field geometry, not production issuance or native lifecycle coverage.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;
use crate::node_contract::OwnerIdentity;
use crate::node_scheduling::NativeInputAcknowledgement;
use crucible_node_format::{Id, Phase, Position, Tick, Validate, canonical};

fn id(label: &str, capacity: usize) -> Id {
    let mut text = String::with_capacity(capacity);
    text.push_str(label);
    Id::new(text).unwrap()
}

fn reference(label: &[u8], spare: usize) -> ContentRef {
    let mut reference = canonical::content_ref(label, "application/json").unwrap();
    reference.hash.digest.reserve(spare);
    reference
}

fn reference_strings(reference: &ContentRef) -> usize {
    reference.hash.algorithm.capacity()
        + reference.hash.domain.capacity()
        + reference.hash.digest.capacity()
        + reference.media_type.capacity()
}

fn failed_data_history() -> InputReactive17History {
    let mut owners = Vec::with_capacity(5);
    owners.push(OwnerIdentity {
        owner: id("input-data/owner", 127),
        incarnation: id("input-data/incarnation", 129),
        generation: U64::new(3),
    });
    let acknowledgement = NativeInputAcknowledgement {
        stage_operation: id("input-data/stage", 101),
        batch: id("input-data/batch", 103),
        node: id("input-data/node", 107),
        owners,
        cutoff: Position::new(Tick::new(4), U64::new(2), Phase::Reaction),
        inventory: reference(b"independent inventory DATA", 131),
        proof_ref: reference(b"independent acknowledgement DATA", 137),
    };
    let mut accepted_event_ids = Vec::with_capacity(7);
    accepted_event_ids.push(id("input-data/duplicate", 109));
    accepted_event_ids.push(id("input-data/duplicate", 113));
    let input_result = InputResult {
        accepted_event_ids,
        input_watermark: U64::new(9),
        custody_receipt: reference(b"independent custody DATA", 139),
        inventory_hash: reference(b"independent terminal inventory DATA", 149).hash,
    };
    let mut normalized = String::with_capacity(223);
    normalized.push_str("retained failed normalization");
    let attempt = InputReactive17Attempt {
        row: None,
        acknowledgement: Some(acknowledgement),
        sdk: None,
        artifact: None,
        context: None,
        post: None,
        record_value: Some(serde_json::Value::String(normalized)),
        record: None,
        underlying: None,
        input_result: Some(input_result),
        previous: [3; 32],
        signature: Some([7; 32]),
        stage: Cell::new(Stage::Failed),
    };
    let mut history = InputReactive17History::new_data();
    history.failed = true;
    history.attempts = Vec::with_capacity(3);
    history.attempts.push(attempt);
    history
}

#[test]
fn input_suffix_capacity_history_keeps_actual_failed_spare_slots() {
    let mut history = InputReactive17History::new_data();
    history.failed = true;
    history.attempts = Vec::with_capacity(3);
    let backing = history.attempts.as_ptr();
    let expected = history.attempts.capacity() * size_of::<InputReactive17Attempt>();
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    history.record_capacity_data(&mut census).unwrap();

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.vector_capacity_bytes, expected);
    assert_eq!(history.attempts.as_ptr(), backing);
    assert!(history.attempts.is_empty());
    assert!(history.failed);
    assert!(matches!(
        history.completed_data(),
        Err(RuntimeError::OutstandingObligations)
    ));
}

#[test]
fn input_suffix_capacity_failed_data_keeps_independent_acknowledgement_and_terminal() {
    let history = failed_data_history();
    let attempt = &history.attempts[0];
    let acknowledgement = attempt.acknowledgement.as_ref().unwrap();
    let result = attempt.input_result.as_ref().unwrap();
    let serde_json::Value::String(normalized) = attempt.record_value.as_ref().unwrap() else {
        panic!("expected retained String DATA")
    };
    let expected_vectors = history.attempts.capacity() * size_of::<InputReactive17Attempt>()
        + acknowledgement.owners.capacity() * size_of::<OwnerIdentity>()
        + result.accepted_event_ids.capacity() * size_of::<Id>();
    let expected_strings = acknowledgement.stage_operation.allocated_capacity()
        + acknowledgement.batch.allocated_capacity()
        + acknowledgement.node.allocated_capacity()
        + acknowledgement
            .owners
            .iter()
            .map(|owner| owner.owner.allocated_capacity() + owner.incarnation.allocated_capacity())
            .sum::<usize>()
        + reference_strings(&acknowledgement.inventory)
        + reference_strings(&acknowledgement.proof_ref)
        + result
            .accepted_event_ids
            .iter()
            .map(Id::allocated_capacity)
            .sum::<usize>()
        + reference_strings(&result.custody_receipt)
        + result.inventory_hash.algorithm.capacity()
        + result.inventory_hash.domain.capacity()
        + result.inventory_hash.digest.capacity()
        + normalized.capacity();
    let backing = history.attempts.as_ptr();
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    history.record_capacity_data(&mut census).unwrap();

    let facts = census.finish();
    assert_eq!(facts.vector_capacity_bytes, expected_vectors);
    assert_eq!(facts.string_capacity_bytes, expected_strings);
    assert_eq!(facts.vector_banks, 3);
    assert_eq!(facts.string_banks, 23);
    assert_eq!(facts.capacity_records, 26);
    assert_eq!(history.attempts.as_ptr(), backing);
    assert_eq!(attempt.stage.get(), Stage::Failed);
    assert!(attempt.row.is_none());
    assert!(result.validate().is_err());
    assert!(matches!(
        history.completed_data(),
        Err(RuntimeError::OutstandingObligations)
    ));
    assert!(InputReactive17History::capacity_counter_scratch_data() > 0);
}

#[test]
fn input_suffix_capacity_short_history_keeps_prior_component_and_vector() {
    let history = failed_data_history();
    let prefix = String::with_capacity(227);
    let mut census = OriginalOwnerCapacityMetadataData::new(2, None);
    census.observe(&prefix).unwrap();

    assert_eq!(
        history.record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 2);
    assert_eq!(facts.string_capacity_bytes, prefix.capacity());
    assert_eq!(
        facts.vector_capacity_bytes,
        history.attempts.capacity() * size_of::<InputReactive17Attempt>()
    );
    assert_eq!(history.attempts[0].stage.get(), Stage::Failed);
    assert!(history.attempts[0].row.is_none());
}

#[test]
fn input_suffix_capacity_foreign_history_precedes_rows() {
    for process in [true, false] {
        let mut history = InputReactive17History::new_data();
        let expected = if process {
            history.process = history.process.wrapping_add(1);
            RuntimeError::ForeignAuthority
        } else {
            history.thread = std::thread::spawn(|| std::thread::current().id())
                .join()
                .unwrap();
            RuntimeError::ThreadAffinity
        };
        let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

        assert_eq!(history.record_capacity_data(&mut census), Err(expected));

        assert_eq!(census.finish().capacity_records, 0);
    }
}

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
fn input_suffix_capacity_source_preserves_all_three_real_empty_histories() {
    for member in 0..3 {
        let mut source = source(member);
        assert_eq!(
            source
                .original_restored_input_and_suffix_capacity_data(None)
                .unwrap()
                .capacity_records,
            0
        );
        OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut())
            .unwrap();
        {
            let association = source.ack_peer_association.borrow();
            let mut inputs = association.as_ref().unwrap().restored_inputs.borrow_mut();
            inputs.failed = true;
            inputs.attempts.reserve_exact(2);
        }

        let facts = source
            .original_restored_input_and_suffix_capacity_data(None)
            .unwrap();

        let association = source.ack_peer_association.borrow();
        let original = association.as_ref().unwrap();
        let inputs = original.restored_inputs.borrow();
        assert_eq!(facts.capacity_records, 1);
        assert_eq!(
            facts.vector_capacity_bytes,
            inputs.attempts.capacity() * size_of::<InputReactive17Attempt>()
        );
        assert!(inputs.failed);
        assert!(original.restored_suffix.borrow().is_none());
        assert!(source.authenticate_current_native().is_err());
        assert!(PacketCompleteSemanticSource::original_restored_input_and_suffix_capacity_counter_scratch_data() > 0);
    }
}

#[test]
fn input_suffix_capacity_source_checks_both_loans_and_outer_origin() {
    let mut source = source(0);
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    let before = source
        .original_restored_input_and_suffix_capacity_data(None)
        .unwrap();
    let association = source.ack_peer_association.borrow();
    let original = association.as_ref().unwrap();
    {
        let _held = original.restored_inputs.borrow_mut();
        assert_eq!(
            source.original_restored_input_and_suffix_capacity_data(None),
            Err(RuntimeError::OwnerBusy)
        );
    }
    {
        let _held = original.restored_suffix.borrow_mut();
        assert_eq!(
            source.original_restored_input_and_suffix_capacity_data(None),
            Err(RuntimeError::OwnerBusy)
        );
    }
    drop(association);
    assert_eq!(
        source
            .original_restored_input_and_suffix_capacity_data(None)
            .unwrap(),
        before
    );
    source.process = source.process.wrapping_add(1);
    let _held = source.ack_peer_association.borrow_mut();

    assert_eq!(
        source.original_restored_input_and_suffix_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );
}
