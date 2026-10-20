//! Pure local-account/backing vectors, authored and UNRUN.

use super::*;

#[test]
fn closed_charge_covers_one_entry_two_original_fds_and_existing_payload_widths() {
    let amount = closed_charge();

    assert_eq!(amount.get(ResourceDimension::ConcurrentOperations), 1);
    assert_eq!(amount.get(ResourceDimension::OpenFiles), 2);
    assert_eq!(
        amount.get(ResourceDimension::MemoryBytes),
        (MAXIMUM_BODY_BYTES + FRAME_BYTES) as u64,
    );
    assert_eq!(amount.get(ResourceDimension::StorageBytes), 0);
    assert_eq!(amount.get(ResourceDimension::OutputBytes), 0);
    assert_eq!(charge_for_capacity(MAXIMUM_BODY_BYTES).unwrap(), amount);
}

#[test]
fn occupied_funding_cannot_reserve_a_second_entry() {
    let mut funding = GatewayFundingV1::new();
    let amount = closed_charge();
    funding.budget = funding.budget.reserve(ReservationClass::Hard, amount).unwrap();
    funding.charge = Some(ChargeV1::Reserved(amount));

    assert!(matches!(funding.prepare(), Err(GatewayFundingErrorV1::State)));
    assert_eq!(funding.budget.account(ReservationClass::Hard).reserved(), amount);
}

#[test]
fn backing_transfer_keeps_actual_allocation_and_commit_until_disposal() {
    let mut funding = GatewayFundingV1::new();
    funding.prepare().unwrap();
    funding.commit().unwrap();
    let backing = funding.take_backing().unwrap();
    let original_pointer = backing.bytes.as_ptr();

    assert_eq!(backing.bytes.capacity(), MAXIMUM_BODY_BYTES);
    assert!(!funding.is_vacant());
    assert_eq!(funding.budget.account(ReservationClass::Hard).committed(), closed_charge());

    funding.restore_backing(backing);
    assert_eq!(funding.backing.as_ref().unwrap().bytes.as_ptr(), original_pointer);
    funding.release_destroyed().unwrap();

    assert!(funding.is_vacant());
    assert_eq!(funding.budget.account(ReservationClass::Hard).committed(), ResourceVector::ZERO);
}

#[test]
fn allocation_is_destroyed_before_unaccepted_reservation_is_released() {
    let mut funding = GatewayFundingV1::new();
    funding.prepare().unwrap();

    funding.release_destroyed().unwrap();

    assert!(funding.backing.is_none());
    assert!(funding.is_vacant());
    assert_eq!(funding.budget.account(ReservationClass::Hard).reserved(), ResourceVector::ZERO);
}

#[test]
fn inconsistent_release_latches_failure_and_cannot_reset_into_new_acceptance() {
    let mut funding = GatewayFundingV1::new();
    // Corrupt pure accounting only, never a peer, original IO or authority token.
    funding.charge = Some(ChargeV1::Committed(closed_charge()));

    assert!(matches!(funding.release_destroyed(), Err(GatewayFundingErrorV1::Accounting(_))));
    assert!(funding.failed);
    assert!(matches!(funding.prepare(), Err(GatewayFundingErrorV1::State)));
    assert!(matches!(funding.release_destroyed(), Err(GatewayFundingErrorV1::State)));
}

#[cfg(target_pointer_width = "64")]
#[test]
fn capacity_charge_checks_addition_before_it_can_wrap() {
    assert!(matches!(charge_for_capacity(usize::MAX), Err(GatewayFundingErrorV1::Capacity)));
}
