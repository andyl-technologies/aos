//! Canonical action observations, dependency cuts and physical-return negatives.

// crucible-lint: allow panic-shortcut -- causal test fixtures panic to localize clock, custody and wire regressions.
#![allow(clippy::unwrap_used)]

use super::*;

fn binding() -> ActionBinding {
    ActionBinding {
        cap: [1; 32],
        reservation: [2; 32],
        account_generation: 3,
        process_generation: 4,
        loan_sequence: 2,
        token: 0,
        capture: Some(1),
        park_request: None,
        frontier: 9,
    }
}

fn parent(class: u32, role: u32) -> ActionParent {
    ActionParent {
        cap: [7; 32],
        operation: u64::from(class) + 1,
        class,
        role,
        origin_ns: 100,
        started_ns: 110,
        progress_ns: 110,
        total_end_ns: 200,
        poll_ns: 1,
        required: 1,
        ..ActionParent::default()
    }
}

fn park_action() -> ActionObservation {
    let mut request = binding();
    request.capture = None;
    request.park_request = Some(9);
    let mut parents = [ActionParent::default(); 4];
    parents[0] = parent(6, 0);
    parents[1] = parent(6, 0);
    parents[1].operation += 1;
    ActionObservation {
        binding: request,
        primary_count: 2,
        row_count: 2,
        borrowed_mask: 3,
        projected_mask: 3,
        cohort_current: true,
        parents,
    }
}

#[test]
fn park_has_a_distinct_request_lifetime_without_a_control_token() {
    let action = park_action();
    let bytes = action.encode().unwrap();

    assert_eq!(&bytes[..8], b"CRUCPRK1");
    assert_eq!(get64(&bytes, 96), 9);
    assert_eq!(ActionObservation::decode(&bytes).unwrap(), action);
    assert_eq!(action.binding.token, 0);
    assert_eq!(action.binding.capture, None);

    let mut invalid = action;
    invalid.binding.token = 2;
    assert!(invalid.encode().is_err());
    invalid = action;
    invalid.binding.park_request = Some(0);
    assert!(invalid.encode().is_err());
    invalid = action;
    invalid.parents[1] = invalid.parents[0];
    assert!(invalid.encode().is_err());
    invalid = action;
    invalid.parents[1].class = 7;
    assert!(invalid.encode().is_err());
}

#[test]
fn park_physical_return_cannot_settle_a_control_binding() {
    let action = park_action();
    let returned = ActionReturn {
        binding: action.binding,
        first: -5,
        post: -110,
        physical_state: 1,
        returned_mask: 3,
        borrowed_mask: 3,
        row_count: 2,
        progress_kind: 0,
        progress_row: 0,
        progress_ns: 0,
        progress_witness: 0,
    };
    assert!(returned.encode().is_err());
    let mut old_wire = [0; ACTION_RETURN_BYTES];
    header(&mut old_wire, *b"CRUCPRR1", action.binding);
    assert!(ActionReturn::decode(&old_wire).is_err());
}

#[test]
fn borrowed_quiescence_keeps_class_and_explicit_preparation() {
    let mut parents = [ActionParent::default(); 4];
    parents[0] = parent(6, 0);
    parents[0].preparation = 2;
    parents[1] = parent(12, 1);
    let action = ActionObservation {
        binding: binding(),
        primary_count: 1,
        row_count: 2,
        borrowed_mask: 3,
        projected_mask: 3,
        cohort_current: true,
        parents,
    };

    let bytes = action.encode().unwrap();
    assert_eq!(ActionObservation::decode(&bytes).unwrap(), action);
    assert_eq!(
        ActionObservation::decode(&bytes).unwrap().parents[0].class,
        6
    );
    assert!(ActionObservation::decode(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn partial_birth_cannot_claim_a_current_pair_or_unborn_physical_return() {
    let mut parents = [ActionParent::default(); 4];
    parents[0] = parent(6, 0);
    let mut action = ActionObservation {
        binding: binding(),
        primary_count: 2,
        row_count: 2,
        borrowed_mask: 1,
        projected_mask: 1,
        cohort_current: false,
        parents,
    };

    assert_eq!(
        ActionObservation::decode(&action.encode().unwrap()).unwrap(),
        action
    );
    action.cohort_current = true;
    assert!(action.encode().is_err());

    let mut returned = ActionReturn {
        binding: binding(),
        first: -5,
        post: 0,
        physical_state: 1,
        borrowed_mask: 1,
        returned_mask: 1,
        row_count: 2,
        progress_kind: 0,
        progress_row: 0,
        progress_ns: 0,
        progress_witness: 0,
    };
    assert_eq!(
        ActionReturn::decode(&returned.encode().unwrap()).unwrap(),
        returned
    );
    returned.returned_mask = 3;
    assert!(returned.encode().is_err());
}

#[test]
fn padding_changed_class_and_incomplete_return_are_refused() {
    let mut parents = [ActionParent::default(); 4];
    parents[0] = parent(5, 0);
    let action = ActionObservation {
        binding: binding(),
        primary_count: 1,
        row_count: 1,
        borrowed_mask: 1,
        projected_mask: 1,
        cohort_current: true,
        parents,
    };
    let mut bytes = action.encode().unwrap();
    bytes[128 + 168] = 1;
    assert!(ActionObservation::decode(&bytes).is_err());
    let mut invalid = action;
    invalid.parents[0].class = 14;
    assert!(invalid.encode().is_err());
    let returned = ActionReturn {
        binding: binding(),
        first: 0,
        post: 0,
        physical_state: 1,
        borrowed_mask: 1,
        returned_mask: 0,
        row_count: 1,
        progress_kind: 0,
        progress_row: 0,
        progress_ns: 0,
        progress_witness: 0,
    };
    assert!(returned.encode().is_err());
}

#[test]
fn deliberate_quantum_absence_is_not_replaced_with_a_new_limit() {
    let mut parents = [ActionParent::default(); 4];
    parents[0] = parent(1, 0);
    parents[0].total_end_ns = 0;
    let mut action = ActionObservation {
        binding: binding(),
        primary_count: 1,
        row_count: 1,
        borrowed_mask: 1,
        projected_mask: 1,
        cohort_current: true,
        parents,
    };

    assert_eq!(
        ActionObservation::decode(&action.encode().unwrap()).unwrap(),
        action
    );
    action.parents[0].class = 5;
    assert!(action.encode().is_err());
}

#[test]
fn unknown_flags_and_progress_for_an_unborn_lender_are_refused() {
    let mut parents = [ActionParent::default(); 4];
    parents[0] = parent(6, 0);
    let action = ActionObservation {
        binding: binding(),
        primary_count: 2,
        row_count: 2,
        borrowed_mask: 1,
        projected_mask: 1,
        cohort_current: false,
        parents,
    };
    let mut bytes = action.encode().unwrap();
    bytes[120] |= 0x40;
    assert!(ActionObservation::decode(&bytes).is_err());

    let returned = ActionReturn {
        binding: binding(),
        first: 0,
        post: 0,
        physical_state: 1,
        returned_mask: 1,
        borrowed_mask: 1,
        row_count: 2,
        progress_kind: 1,
        progress_row: 2,
        progress_ns: 111,
        progress_witness: 1,
    };
    assert!(returned.encode().is_err());
}

#[test]
fn born_output_survives_projection_refusal_without_read_authority() {
    let mut action = ActionObservation {
        binding: binding(),
        primary_count: 1,
        row_count: 1,
        borrowed_mask: 1,
        projected_mask: 0,
        cohort_current: false,
        parents: [ActionParent::default(); 4],
    };

    let bytes = action.encode().unwrap();
    assert_eq!(ActionObservation::decode(&bytes).unwrap(), action);
    assert_eq!(&bytes[..8], b"CRUCACT2");
    let mut predecessor = bytes;
    predecessor[..8].copy_from_slice(b"CRUCACT1");
    predecessor[8..12].copy_from_slice(&1_u32.to_be_bytes());
    assert!(ActionObservation::decode(&predecessor).is_err());
    action.cohort_current = true;
    assert!(action.encode().is_err());
    action.cohort_current = false;
    action.parents[0] = parent(5, 0);
    assert!(action.encode().is_err());
}
