//! Checks actual reservation allocations as DATA, without native completion.
//!
//! Ordinary constructors create the three real unassociated Source declarations.
//! The deliberately inert failed row supplies no live Source binding, declaration,
//! completed Initial, native claim or publication witness. Its real Box and
//! defining reserve_into calls retain storage only; no Source constructor or
//! admission method accepts the inert row as permission.

use super::super::tests::inert_row;
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

fn failed_owner() -> Box<Import18CaptureBankReservation> {
    Box::new(Import18CaptureBankReservation::retaining(
        inert_row().unwrap(),
    ))
}

fn bytes(facts: &RetainedProtocolMetadataFacts, maximum: usize) -> Result<usize, RuntimeError> {
    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<RuntimeError>(
        facts, maximum,
    )
}

#[test]
fn reservation_capacity_keeps_missing_empty_and_spent_source_holders_distinct() {
    for member in 0..3 {
        let mut source = source(member);
        source.native_import18_bank_attempted.set(true);
        assert_eq!(
            source
                .original_complete_capture_banks_capacity_data(None)
                .unwrap(),
            RetainedProtocolMetadataFacts::default()
        );
        *source.native_import18_bank_reservation.get_mut() = Some(failed_owner());
        let missing = source
            .original_complete_capture_banks_capacity_data(None)
            .unwrap();
        let header = size_of::<Import18CaptureBankReservation>();

        assert_eq!(missing.capacity_records, 1);
        assert_eq!(missing.boxed_value_bytes, header);
        assert_eq!(bytes(&missing, header), Ok(header));
        assert_eq!(
            bytes(&missing, header - 1),
            Err(RuntimeError::ResourceLimit)
        );

        let mut slot = source.native_import18_bank_reservation.borrow_mut();
        let owner = slot.as_mut().unwrap();
        assert!(owner.history_data().partial_capacities.is_none());
        owner.banks = Some(PacketCompleteCaptureBanks::empty_import18_data());
        drop(slot);

        let empty = source
            .original_complete_capture_banks_capacity_data(None)
            .unwrap();

        // Present empty banks also visit protocol_detached and transferred.
        let mut expected = missing;
        expected.observed_nodes += 2;
        assert_eq!(empty, expected);
        let slot = source.native_import18_bank_reservation.borrow();
        let history = slot.as_ref().unwrap().history_data();
        assert_eq!(history.partial_capacities, Some([0; 7]));
        assert!(source.native_import18_bank_attempted.get());
        assert!(history.started && history.failed);
        assert!(!history.complete && !history.published);
        assert!(
            !source
                .is_original_native_import18_declaration_data()
                .unwrap()
        );
        assert!(source.authenticate_current_native().is_err());
        assert!(source.ack_peer_birth.borrow().is_none());
    }
}

#[test]
fn reservation_capacity_keeps_real_failed_reservations_and_all_sdk_banks() {
    let mut source = source(0);
    let mut owner = failed_owner();
    owner.banks = Some(PacketCompleteCaptureBanks::empty_import18_data());
    let banks = owner.banks.as_mut().unwrap();
    CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
        64,
        64,
        &mut banks.semantic,
    )
    .unwrap();
    CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
        32,
        32,
        &mut banks.ancestry,
    )
    .unwrap();
    ProtocolSnapshotReservation::reserve_complete_owned11_into(128, 256, 2, 7, &mut banks.protocol)
        .unwrap();
    let protocol_bytes = banks.protocol.as_ref().unwrap().allocated_bytes();

    assert!(
        CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
            0,
            0,
            &mut banks.journal
        )
        .is_err()
    );
    let expected = owner
        .retained_backing_data::<RuntimeError>(usize::MAX)
        .unwrap();
    let pointer = std::ptr::from_ref(owner.as_ref());
    source.native_import18_bank_attempted.set(true);
    *source.native_import18_bank_reservation.get_mut() = Some(owner);

    let facts = source
        .original_complete_capture_banks_capacity_data(None)
        .unwrap();

    assert!(facts.vector_banks > 3);
    assert_eq!(
        facts.boxed_value_bytes,
        size_of::<Import18CaptureBankReservation>()
    );
    assert_eq!(facts.vector_capacity_bytes, 64 + 32 + protocol_bytes);
    assert_eq!(bytes(&facts, expected), Ok(expected));
    assert_eq!(
        bytes(&facts, expected - 1),
        Err(RuntimeError::ResourceLimit)
    );
    let slot = source.native_import18_bank_reservation.borrow();
    let owner = slot.as_ref().unwrap();
    assert_eq!(std::ptr::from_ref(owner.as_ref()), pointer);
    let history = owner.history_data();
    assert_eq!(
        history.partial_capacities,
        Some([64, 32, 0, 0, 0, 0, protocol_bytes])
    );
    assert!(history.failed && !history.complete && !history.published);
    assert!(source.capture_banks.borrow().is_none());
    assert!(source.authenticate_current_native().is_err());
}

#[test]
fn reservation_capacity_keeps_coexisting_source_banks_and_unsupported_partial_slots() {
    let mut source = source(0);
    source
        .reserve_complete_capture_banks(
            PacketCompleteCaptureBankLimits {
                host_protocol_bytes: 4096,
                semantic_bytes: 1024,
                ancestry_bytes: 2048,
                journal_bytes: 512,
            },
            4 * 1024 * 1024,
        )
        .unwrap();
    let before = source
        .original_complete_capture_banks_capacity_data(None)
        .unwrap();
    let mut owner = failed_owner();
    owner.banks = Some(PacketCompleteCaptureBanks::empty_import18_data());
    let banks = owner.banks.as_mut().unwrap();
    CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
        8,
        8,
        &mut banks.native_after_bank,
    )
    .unwrap();
    assert!(
        owner
            .retained_backing_data::<RuntimeError>(usize::MAX)
            .is_err()
    );
    *source.native_import18_bank_reservation.get_mut() = Some(owner);

    let facts = source
        .original_complete_capture_banks_capacity_data(None)
        .unwrap();

    assert_eq!(facts.capacity_records, before.capacity_records + 2);
    assert_eq!(
        facts.boxed_value_bytes,
        size_of::<Import18CaptureBankReservation>()
    );
    assert_eq!(
        facts.vector_capacity_bytes,
        before.vector_capacity_bytes + 8
    );
    assert_eq!(facts.vector_banks, before.vector_banks + 1);
    let slot = source.native_import18_bank_reservation.borrow();
    let owner = slot.as_ref().unwrap();
    assert!(owner.failed && !owner.complete && !owner.published);
    assert!(
        owner
            .retained_backing_data::<RuntimeError>(usize::MAX)
            .is_err()
    );
    assert_eq!(
        source
            .capture_banks
            .borrow()
            .as_ref()
            .unwrap()
            .facts()
            .unwrap()
            .total_bytes,
        before.vector_capacity_bytes
    );
    assert!(source.authenticate_current_native().is_err());
}

#[test]
fn reservation_capacity_short_rows_preserve_prior_component_box_and_bank_prefix() {
    let mut owner = failed_owner();
    owner.banks = Some(PacketCompleteCaptureBanks::empty_import18_data());
    let banks = owner.banks.as_mut().unwrap();
    CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
        64,
        64,
        &mut banks.semantic,
    )
    .unwrap();
    CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
        32,
        32,
        &mut banks.ancestry,
    )
    .unwrap();
    let prior = String::with_capacity(173);
    let mut census = OriginalOwnerCapacityMetadataData::new(3, None);
    census.observe(&prior).unwrap();

    assert_eq!(
        owner.record_boxed_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 3);
    assert_eq!(facts.string_capacity_bytes, prior.capacity());
    assert_eq!(
        facts.boxed_value_bytes,
        size_of::<Import18CaptureBankReservation>()
    );
    assert_eq!(facts.vector_banks, 1);
    assert_eq!(facts.vector_capacity_bytes, 64);
    assert_eq!(
        owner.history_data().partial_capacities,
        Some([64, 32, 0, 0, 0, 0, 0])
    );
    assert!(owner.failed && !owner.complete && !owner.published);
}

#[test]
fn reservation_capacity_checks_both_source_loans_and_origin_before_observation() {
    for member in 0..3 {
        let mut source = source(member);
        *source.native_import18_bank_reservation.get_mut() = Some(failed_owner());
        let reservation_lock = source.native_import18_bank_reservation.borrow_mut();
        assert_eq!(
            source.original_complete_capture_banks_capacity_data(None),
            Err(RuntimeError::OwnerBusy)
        );
        drop(reservation_lock);

        let published_lock = source.capture_banks.borrow_mut();
        assert_eq!(
            source.original_complete_capture_banks_capacity_data(None),
            Err(RuntimeError::OwnerBusy)
        );
        drop(published_lock);
        source.process = source.process.wrapping_add(1);
        let reservation_lock = source.native_import18_bank_reservation.borrow_mut();
        let published_lock = source.capture_banks.borrow_mut();

        assert_eq!(
            source.original_complete_capture_banks_capacity_data(None),
            Err(RuntimeError::ForeignAuthority)
        );
        assert!(reservation_lock.as_ref().unwrap().failed);
        assert!(published_lock.is_none());
    }
}

#[test]
fn reservation_capacity_repeated_box_views_receive_no_sharing_discount() {
    let mut owner = failed_owner();
    owner.banks = Some(PacketCompleteCaptureBanks::empty_import18_data());
    CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
        64,
        64,
        &mut owner.banks.as_mut().unwrap().semantic,
    )
    .unwrap();
    let pointer = std::ptr::from_ref(owner.as_ref());
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    owner.record_boxed_capacity_data(&mut census).unwrap();
    owner.record_boxed_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 4);
    assert_eq!(
        facts.boxed_value_bytes,
        2 * size_of::<Import18CaptureBankReservation>()
    );
    assert_eq!(facts.vector_capacity_bytes, 128);
    assert_eq!(facts.shared_backing_views, 0);
    assert_eq!(std::ptr::from_ref(owner.as_ref()), pointer);
    assert!(owner.failed && !owner.complete && !owner.published);
}
