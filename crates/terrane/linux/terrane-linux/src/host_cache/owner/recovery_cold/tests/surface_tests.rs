//! Preserves unrelated cold policy when disposable surface holds retire.

#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn retired_surface_holds_preserve_all_other_cold_candidates_and_refuse_dependencies() {
    let cold = candidates();
    let original = cold.state.as_ref().clone();
    let mut state = original.clone();
    let id = format!("surface-index:{}", "ab".repeat(16));
    state.reservations.push(ReservationRecord {
        id: id.clone(),
        owner: "original-owner".into(),
        bytes: 8192,
    });
    let cold = ColdPolicy {
        state: Arc::new(state.clone()),
    };
    let retired = cold.without_surface_reservations().unwrap().unwrap();
    assert!(require_same(retired.state.as_ref(), &original).is_ok());
    assert!(require_same(cold.state.as_ref(), &state).is_ok());
    assert!(retired.without_surface_reservations().unwrap().is_none());

    state.leases.push(LeaseRecord {
        owner: id,
        expires: 100,
    });
    assert!(
        ColdPolicy {
            state: Arc::new(state)
        }
        .without_surface_reservations()
        .is_err()
    );
    let mut malformed = original;
    malformed.reservations.push(ReservationRecord {
        id: "surface-index:bad".into(),
        owner: "original-owner".into(),
        bytes: 8192,
    });
    assert!(
        ColdPolicy {
            state: Arc::new(malformed)
        }
        .without_surface_reservations()
        .is_err()
    );
}
