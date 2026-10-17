//! Checks the actual publisher-state decision after a collected cohort.
//!
//! These factual state controls create no Source, map, subscriber or Native
//! grant. The full authenticated publisher driver remains a separate gate.

use super::*;

fn current() -> PendingAction {
    PendingAction {
        observation: ActionObservation {
            binding: ActionBinding {
                cap: [1; 32],
                reservation: [2; 32],
                account_generation: 1,
                process_generation: 1,
                loan_sequence: 2,
                token: 0,
                capture: Some(1),
                park_request: None,
                frontier: 7,
            },
            primary_count: 2,
            row_count: 2,
            borrowed_mask: 3,
            projected_mask: 3,
            cohort_current: true,
            parents: [ActionParent::default(); 4],
        },
        returning: false,
        clearing: false,
        refused: false,
        verified_return: None,
        verified_park_return: None,
        park_members_returned_mask: 0,
    }
}

#[test]
fn equal_fresh_cohort_skips_only_already_current_rows() {
    let mut state = current();
    let binding = state.observation.binding;
    let fresh = state.observation.parents;

    assert!(state.matches_current_cohort(binding, &fresh, 2));
    state.observation.cohort_current = false;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
    state.observation.cohort_current = true;
    state.returning = true;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
}

#[test]
fn one_owner_change_never_reuses_a_previous_cohort() {
    let state = current();
    let binding = state.observation.binding;
    let mut fresh = state.observation.parents;

    fresh[1].policy_revision = 1;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
    fresh = state.observation.parents;
    fresh[0].state = 3;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
    fresh = state.observation.parents;
    fresh[0].total_end_ns = 1;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));

    let mut another = binding;
    another.loan_sequence = 4;
    assert!(!state.matches_current_cohort(another, &fresh, 2));
}

#[test]
fn dirty_or_refused_no_capture_keeps_the_existing_membership() {
    let mut state = current();
    state.observation.binding.capture = None;
    let binding = state.observation.binding;
    let fresh = state.observation.parents;
    let retained_mask = state.observation.borrowed_mask;
    let projected_mask = state.observation.projected_mask;

    state.observation.cohort_current = false;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
    assert_eq!(state.observation.borrowed_mask, retained_mask);
    assert_eq!(state.observation.projected_mask, projected_mask);
    assert_eq!(state.observation.binding, binding);

    state.observation.cohort_current = true;
    state.refused = true;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
    assert_eq!(state.observation.borrowed_mask, retained_mask);
    assert_eq!(state.observation.binding.capture, None);
}
