//! Checks real history spare slots and root loans without creating a quoted claim.
//!
//! Populated Producer attempts require genuine independently issued construction
//! rows. These controls never fabricate one or claim native execution coverage.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests::{
    coordinator, installation, producer, reactive, storage_selection,
};

#[test]
fn producer_capacity_history_keeps_failed_spare_attempt_geometry() {
    let mut history = ProducerProgressHistory::new();
    history.attempts = Vec::with_capacity(3);
    history.failed = true;
    let backing = history.attempts.as_ptr();
    let bytes = history.attempts.capacity() * size_of::<ProducerProgressAttempt>();
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    history.record_capacity_data(&mut census).unwrap();

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.vector_banks, 1);
    assert_eq!(facts.vector_capacity_bytes, bytes);
    assert_eq!(history.attempts.as_ptr(), backing);
    assert!(history.attempts.is_empty());
    assert!(history.failed);
    assert_eq!(
        history.require_verified_prefix_data(),
        Err(RuntimeError::OutstandingObligations)
    );
    assert!(ProducerProgressHistory::capacity_counter_scratch_data() > 0);
}

#[test]
fn producer_capacity_history_short_rows_keep_prior_component() {
    let mut history = ProducerProgressHistory::new();
    history.attempts = Vec::with_capacity(3);
    let prefix = String::with_capacity(223);
    let mut census = OriginalOwnerCapacityMetadataData::new(1, None);
    census.observe(&prefix).unwrap();

    assert_eq!(
        history.record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.vector_banks, 0);
    assert_eq!(facts.string_capacity_bytes, prefix.capacity());
    assert!(!history.failed);
    assert!(history.attempts.is_empty());
}

#[test]
fn producer_capacity_history_foreign_creator_precedes_rows() {
    for process in [true, false] {
        let mut history = ProducerProgressHistory::new();
        if process {
            history.process = history.process.wrapping_add(1);
        } else {
            history.thread = std::thread::spawn(|| std::thread::current().id())
                .join()
                .unwrap();
        }
        let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

        assert_eq!(
            history.record_capacity_data(&mut census),
            Err(RuntimeError::ForeignAuthority)
        );

        assert_eq!(census.finish().capacity_records, 0);
    }
}

#[test]
fn producer_capacity_durable_root_loan_retains_actual_reference_and_blocks_mutation() {
    let mut reference = canonical::content_ref(b"durable root DATA", "application/json").unwrap();
    reference.hash.digest.reserve(193);
    let digest_capacity = reference.hash.digest.capacity();
    let root = RefCell::new(Some(reference));
    let busy = root.borrow_mut();
    assert!(matches!(
        durable_root_loan_data(&root),
        Err(RuntimeError::OwnerBusy)
    ));
    drop(busy);
    let original = root.borrow().as_ref().unwrap().clone();
    let loan = durable_root_loan_data(&root).unwrap();
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    census.observe(&*loan).unwrap();

    let facts = census.finish();
    assert!(facts.string_capacity_bytes >= digest_capacity);
    assert!(root.try_borrow_mut().is_err());
    assert_eq!(loan.as_ref().unwrap(), &original);
    drop(loan);
    assert!(root.try_borrow_mut().is_ok());
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
fn producer_capacity_source_keeps_empty_history_geometry_for_all_three_declarations() {
    for member in 0..3 {
        let mut source = source(member);
        assert_eq!(
            source
                .original_restored_producer_progress_capacity_data(None)
                .unwrap()
                .capacity_records,
            0
        );
        OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut())
            .unwrap();
        {
            let association = source.ack_peer_association.borrow();
            let mut history = association.as_ref().unwrap().producer_progress.borrow_mut();
            history.failed = true;
            history.attempts.reserve_exact(2);
        }

        let actual = source
            .original_restored_producer_progress_capacity_data(None)
            .unwrap();

        let association = source.ack_peer_association.borrow();
        let history = association.as_ref().unwrap().producer_progress.borrow();
        assert_eq!(actual.capacity_records, 1);
        assert_eq!(
            actual.vector_capacity_bytes,
            history.attempts.capacity() * size_of::<ProducerProgressAttempt>()
        );
        assert!(history.failed);
        assert!(history.require_verified_prefix_data().is_err());
        assert!(source.authenticate_current_native().is_err());
        assert!(PacketCompleteSemanticSource::original_restored_producer_progress_capacity_counter_scratch_data() > 0);
    }
}

#[test]
fn producer_capacity_source_busy_history_refuses_without_changing_source() {
    let mut source = source(0);
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    let before = source
        .original_restored_producer_progress_capacity_data(None)
        .unwrap();
    let association = source.ack_peer_association.borrow();
    let held = association.as_ref().unwrap().producer_progress.borrow_mut();

    assert_eq!(
        source.original_restored_producer_progress_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );

    drop(held);
    drop(association);
    assert_eq!(
        source
            .original_restored_producer_progress_capacity_data(None)
            .unwrap(),
        before
    );
}

#[test]
fn producer_capacity_source_foreign_origin_precedes_busy_association() {
    let mut source = source(0);
    source.process = source.process.wrapping_add(1);
    let held = source.ack_peer_association.borrow_mut();

    assert_eq!(
        source.original_restored_producer_progress_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );

    drop(held);
    source.process = std::process::id();
    assert_eq!(
        source
            .original_restored_producer_progress_capacity_data(None)
            .unwrap()
            .capacity_records,
        0
    );
}
