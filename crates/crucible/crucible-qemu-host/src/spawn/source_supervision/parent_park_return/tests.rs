//! Checks retained factual state, not a constructed Source or QMP issuer.
//!
//! These controls cannot create a transport closure proof or a paid subscriber.

// crucible-lint: allow panic-shortcut -- state fixtures localize exact identity regressions.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_qemu_protocol::boundary_action::{ActionObservation, ActionParent};
use crucible_qemu_protocol::parent_park_return::PARENT_PARK_PHYSICAL_RESOLUTION_ALL;

fn pending() -> action::PendingAction {
    let mut pending = action::PendingAction::from_observation_for_test(ActionObservation {
        binding: ActionBinding {
            cap: [1; 32],
            reservation: [2; 32],
            account_generation: 3,
            process_generation: 4,
            loan_sequence: 6,
            token: 0,
            capture: None,
            park_request: Some(7),
            frontier: 8,
        },
        primary_count: 2,
        row_count: 2,
        borrowed_mask: 3,
        projected_mask: 3,
        cohort_current: false,
        parents: [ActionParent::default(); 4],
    });
    pending.refused = true;
    pending
}

fn evidence() -> VerifiedParkReturn {
    VerifiedParkReturn {
        journal: ParentParkReturn {
            binding: pending().observation.binding,
            first: -5,
            post: -110,
            physical_resolution_mask: PARENT_PARK_PHYSICAL_RESOLUTION_ALL,
            publication_count: 2,
            pair_view_return_mask: 3,
            original_statuses: [-125, -110],
            operation_status: -5,
            return_status: 0,
            stopped_generation: 11,
            native_generation: 13,
        },
        completed_requests: 1,
    }
}

#[test]
fn retry_keeps_same_evidence_and_actual_host_unlink_state() {
    let mut action = pending();
    let verified = evidence();
    action.retain_park_return(verified, 0).unwrap();
    action.park_members_returned_mask = 1;

    action.retain_park_return(verified, 1).unwrap();

    assert!(action.returning);
    assert_eq!(action.park_members_returned_mask, 1);
    assert_eq!(action.observation.borrowed_mask, 3);
    assert_eq!(action.verified_park_return, Some(verified));
    assert_eq!(verified.journal.first, -5);
    assert_eq!(verified.journal.original_statuses, [-125, -110]);
}

#[test]
fn new_closure_requires_advancement_but_retry_cannot_change_it() {
    let mut action = pending();
    let mut verified = evidence();
    assert!(action.retain_park_return(verified, 1).is_err());
    assert!(action.verified_park_return.is_none());
    action.retain_park_return(verified, 0).unwrap();
    verified.completed_requests = 2;
    assert!(action.retain_park_return(verified, 0).is_err());
    verified = evidence();
    verified.journal.post = -4;
    assert!(action.retain_park_return(verified, 0).is_err());
    assert_eq!(action.verified_park_return, Some(evidence()));
}

#[test]
fn zero_received_views_do_not_erase_the_actual_born_host_cohort() {
    let mut action = pending();
    let mut verified = evidence();
    verified.journal.publication_count = 0;
    verified.journal.pair_view_return_mask = 0;
    verified.journal.native_generation = 0;

    action.retain_park_return(verified, 0).unwrap();

    assert_eq!(action.observation.row_count, 2);
    assert_eq!(action.observation.borrowed_mask, 3);
    assert_eq!(action.park_members_returned_mask, 0);
}

#[test]
fn wrong_binding_or_received_geometry_cannot_replace_pending_owner() {
    for mutation in 0..4 {
        let mut action = pending();
        let mut verified = evidence();
        match mutation {
            0 => verified.journal.binding.loan_sequence = 8,
            1 => verified.journal.binding.park_request = Some(9),
            2 => verified.journal.publication_count = 3,
            3 => action.observation.projected_mask = 1,
            _ => unreachable!(),
        }
        assert!(action.retain_park_return(verified, 0).is_err());
        assert!(!action.returning);
        assert!(action.verified_park_return.is_none());
        assert_eq!(action.observation.borrowed_mask, 3);
    }
}
