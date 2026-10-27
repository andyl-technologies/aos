//! Checks actual pending construction, retained failure, spare slots and loans.
//!
//! Moving a failed partial between private slots below supplies no completed
//! native history. No quoted claim, SDK assignment or Root Window is fabricated.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests::{
    coordinator, installation, producer, reactive, storage_selection,
};

fn failed_owner() -> Observation17Owner {
    let owner = Observation17Owner::new_data();
    owner.begin_pending_data(1, [19; 32]).unwrap();
    {
        let mut pending = owner.pending.borrow_mut();
        let attempt = pending.as_mut().unwrap();
        attempt.record_bytes = Some(Vec::with_capacity(257));
        attempt.model_bytes = Some(Vec::with_capacity(263));
        let mut text = String::with_capacity(193);
        text.push_str("failed normalized Observe17 DATA");
        let mut children = Vec::with_capacity(3);
        children.push(serde_json::Value::String(text));
        attempt.model_value = Some(serde_json::Value::Array(children));
    }
    drop(PendingGuard(&owner));
    owner
}

fn facts(owner: &Observation17Owner) -> RetainedProtocolMetadataFacts {
    let view = owner.capacity_view_data().unwrap();
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    view.record_capacity_data(&mut census).unwrap();
    census.finish()
}

#[test]
fn observation17_capacity_failed_pending_keeps_banks_normalization_and_history_spares() {
    let owner = failed_owner();
    owner.completed.borrow_mut().reserve_exact(2);
    let before = owner
        .retained_heap_bytes_with_error::<RuntimeError>(usize::MAX)
        .unwrap();
    let pending = owner.pending.borrow();
    let attempt = pending.as_ref().unwrap();
    let serde_json::Value::Array(children) = attempt.model_value.as_ref().unwrap() else {
        panic!("array DATA");
    };
    let expected_vectors = owner.completed.borrow().capacity() * size_of::<Observation17Attempt>()
        + attempt.record_bytes.as_ref().unwrap().capacity()
        + attempt.model_bytes.as_ref().unwrap().capacity()
        + children.capacity() * size_of::<serde_json::Value>();

    let actual = facts(&owner);

    assert_eq!(actual.vector_capacity_bytes, expected_vectors);
    assert_eq!(actual.string_capacity_bytes, 193);
    assert_eq!(actual.vector_banks, 4);
    assert_eq!(actual.capacity_records, 5);
    assert_eq!(attempt.stage, Stage::Failed);
    assert_eq!(attempt.previous, [19; 32]);
    drop(pending);
    assert!(owner.begin_pending_data(1, [0; 32]).is_err());
    assert_eq!(
        owner
            .retained_heap_bytes_with_error::<RuntimeError>(usize::MAX)
            .unwrap(),
        before
    );
}

#[test]
fn observation17_capacity_independent_history_slot_keeps_failed_partial_without_completion() {
    let owner = failed_owner();
    let mut other = failed_owner();
    let failed = other.pending.get_mut().take().unwrap();
    owner.completed.borrow_mut().push(failed);
    let pending_only = facts(&other);
    assert_eq!(pending_only.vector_capacity_bytes, 0);

    let actual = facts(&owner);
    let slots = owner.completed.borrow().capacity() * size_of::<Observation17Attempt>();
    let pending = owner.pending.borrow();
    let attempt = pending.as_ref().unwrap();
    let serde_json::Value::Array(children) = attempt.model_value.as_ref().unwrap() else {
        panic!("array DATA");
    };
    let partial_vectors = attempt.record_bytes.as_ref().unwrap().capacity()
        + attempt.model_bytes.as_ref().unwrap().capacity()
        + children.capacity() * size_of::<serde_json::Value>();

    assert_eq!(actual.vector_capacity_bytes, slots + 2 * partial_vectors);
    assert_eq!(actual.string_capacity_bytes, 386);
    assert_eq!(actual.capacity_records, 9);
    assert_eq!(owner.completed.borrow()[0].stage, Stage::Failed);
    assert!(owner.require_idle_data().is_err());
}

#[test]
fn observation17_capacity_short_rows_keep_prior_component_and_actual_history_prefix() {
    let owner = failed_owner();
    let prefix = String::with_capacity(223);
    let view = owner.capacity_view_data().unwrap();
    let mut census = OriginalOwnerCapacityMetadataData::new(2, None);
    census.observe(&prefix).unwrap();

    assert_eq!(
        view.record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );

    let partial = census.finish();
    assert_eq!(partial.capacity_records, 2);
    assert_eq!(partial.string_capacity_bytes, prefix.capacity());
    assert_eq!(partial.vector_banks, 1);
    assert_eq!(partial.vector_capacity_bytes, 0);
    assert_eq!(
        owner.pending.borrow().as_ref().unwrap().stage,
        Stage::Failed
    );
}

#[test]
fn observation17_capacity_creator_and_both_loans_precede_census() {
    for pending_busy in [true, false] {
        let owner = failed_owner();
        if pending_busy {
            let held = owner.pending.borrow_mut();
            assert!(matches!(
                owner.capacity_view_data(),
                Err(RuntimeError::OwnerBusy)
            ));
            drop(held);
        } else {
            let held = owner.completed.borrow_mut();
            assert!(matches!(
                owner.capacity_view_data(),
                Err(RuntimeError::OwnerBusy)
            ));
            drop(held);
        }
        assert_eq!(facts(&owner).capacity_records, 5);
    }
    for process in [true, false] {
        let mut owner = failed_owner();
        if process {
            owner.process = owner.process.wrapping_add(1);
        } else {
            owner.thread = std::thread::spawn(|| std::thread::current().id())
                .join()
                .unwrap();
        }
        let held = owner.pending.borrow_mut();
        let result = owner.capacity_view_data();
        let expected = if process {
            RuntimeError::ForeignAuthority
        } else {
            RuntimeError::ThreadAffinity
        };
        assert!(matches!(result, Err(error) if error == expected));
        drop(held);
    }
}

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
fn observation17_capacity_source_observes_all_three_actual_declarations() {
    for member in 0..3 {
        let mut source = source(member);
        assert_eq!(
            source
                .original_restored_observation17_capacity_data(None)
                .unwrap()
                .capacity_records,
            0
        );
        OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut())
            .unwrap();
        {
            let association = source.ack_peer_association.borrow();
            let owner = &association.as_ref().unwrap().restored_observations17;
            owner.begin_pending_data(1, [23; 32]).unwrap();
            owner.pending.borrow_mut().as_mut().unwrap().record_bytes =
                Some(Vec::with_capacity(271));
            drop(PendingGuard(owner));
        }

        let actual = source
            .original_restored_observation17_capacity_data(None)
            .unwrap();

        assert_eq!(actual.capacity_records, 2);
        assert_eq!(actual.vector_capacity_bytes, 271);
        assert!(source.authenticate_current_native().is_err());
        assert!(
            source
                .authenticate_unused_signed_observation17_owner_data()
                .is_err()
        );
        assert!(PacketCompleteSemanticSource::original_restored_observation17_capacity_counter_scratch_data() > 0);
    }
}

#[test]
fn observation17_capacity_source_refuses_busy_pending_or_completed_without_mutation() {
    let mut source = source(0);
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    let before = source
        .original_restored_observation17_capacity_data(None)
        .unwrap();
    let association = source.ack_peer_association.borrow();
    let owner = &association.as_ref().unwrap().restored_observations17;
    let pending = owner.pending.borrow_mut();
    assert_eq!(
        source.original_restored_observation17_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );
    drop(pending);
    let completed = owner.completed.borrow_mut();
    assert_eq!(
        source.original_restored_observation17_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );
    drop(completed);
    drop(association);
    assert_eq!(
        source
            .original_restored_observation17_capacity_data(None)
            .unwrap(),
        before
    );
}

#[test]
fn observation17_capacity_source_foreign_origin_precedes_busy_association() {
    let mut source = source(0);
    source.process = source.process.wrapping_add(1);
    let held = source.ack_peer_association.borrow_mut();

    assert_eq!(
        source.original_restored_observation17_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );

    drop(held);
    source.process = std::process::id();
    assert_eq!(
        source
            .original_restored_observation17_capacity_data(None)
            .unwrap()
            .capacity_records,
        0
    );
}
