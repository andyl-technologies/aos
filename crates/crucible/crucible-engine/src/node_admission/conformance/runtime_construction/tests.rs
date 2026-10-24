//! Checks persistent construction reservations at admission and reobservation.

use super::*;

fn policy(maximum_requested_bytes: usize) -> OriginalRuntimeConstructionPolicy {
    OriginalRuntimeConstructionPolicy {
        maximum_requested_bytes,
        maximum_owned_descriptors: 1,
        declared_observer_scratch_bytes: 7,
    }
}

fn storage() -> OriginalRuntimeConstructionStorage {
    OriginalRuntimeConstructionStorage {
        retained_holder_bytes: 11,
        maximum_simultaneous_transient_bytes: 13,
        construction_retained_requested_bytes: 17,
        construction_retained_observation_growth_bytes: 19,
        construction_retained_reservation_bytes: 23,
        construction_transient_requested_bytes: 29,
        construction_counter_scratch_bytes: 31,
        retained_descriptors: 0,
        maximum_simultaneous_transient_descriptors: 0,
    }
}

#[test]
fn reservation_is_admitted_beside_every_constructor_and_observer_charge() {
    let row = storage();
    let peak = 11 + 13 + 17 + 19 + 23 + 29 + 31 + 7;

    assert_eq!(
        construction_requested_peak(policy(peak), row, false),
        Ok(peak)
    );
    assert!(matches!(
        construction_requested_peak(policy(peak - 1), row, false),
        Err(RuntimeError::ResourceLimit)
    ));

    let mut without_reservation = row;
    without_reservation.construction_retained_reservation_bytes = 0;
    assert_eq!(
        construction_requested_peak(policy(peak), without_reservation, false),
        Ok(peak - row.construction_retained_reservation_bytes)
    );
}

#[test]
fn post_construction_keeps_the_reservation_in_the_retained_holder_row() {
    let before = storage();
    // The holder census adds the spent member's unchanged reservation beside
    // actual owners. Construction-only DATA must then be empty.
    let after = OriginalRuntimeConstructionStorage {
        retained_holder_bytes: before.retained_holder_bytes
            + before.construction_retained_requested_bytes
            + before.construction_retained_reservation_bytes,
        construction_retained_requested_bytes: 0,
        construction_retained_observation_growth_bytes: 0,
        construction_retained_reservation_bytes: 0,
        construction_transient_requested_bytes: 0,
        construction_counter_scratch_bytes: 0,
        ..before
    };
    let retained_peak = after.retained_holder_bytes
        + after.maximum_simultaneous_transient_bytes
        + policy(usize::MAX).declared_observer_scratch_bytes;

    assert_eq!(
        construction_requested_peak(policy(retained_peak), after, true),
        Ok(retained_peak)
    );
    assert!(matches!(
        construction_requested_peak(policy(retained_peak - 1), after, true),
        Err(RuntimeError::ResourceLimit)
    ));

    let duplicate_reservation = OriginalRuntimeConstructionStorage {
        construction_retained_reservation_bytes: before.construction_retained_reservation_bytes,
        ..after
    };
    assert!(matches!(
        construction_requested_peak(policy(usize::MAX), duplicate_reservation, true),
        Err(RuntimeError::ForeignAuthority)
    ));
}

#[test]
fn reservation_overflow_refuses_before_a_member_can_be_issued() {
    let row = OriginalRuntimeConstructionStorage {
        construction_retained_reservation_bytes: usize::MAX,
        ..storage()
    };

    assert!(matches!(
        construction_requested_peak(policy(usize::MAX), row, false),
        Err(RuntimeError::ResourceLimit)
    ));
}
