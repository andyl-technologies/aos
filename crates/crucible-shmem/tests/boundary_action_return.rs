//! Checks factual return framing independently of control/sample ACKs.
//!
//! The test writer exercises public atomic bytes. It is not a Native Source,
//! operation, mapping-writer grant or physical completion fixture.

// crucible-lint: allow panic-shortcut -- causal test fixtures panic to localize clock, custody and wire regressions.
#![allow(clippy::unwrap_used)]

use crucible_protocol::boundary_action::{ActionBinding, ActionReturn};
use crucible_shmem::{ABI_VERSION, NODE_SLOT_SIZE, NodeSlot};

fn returned(sequence: u64) -> ActionReturn {
    ActionReturn {
        binding: ActionBinding {
            cap: [1; 32],
            reservation: [2; 32],
            account_generation: 1,
            process_generation: 1,
            loan_sequence: sequence,
            token: 0,
            capture: Some(1),
            frontier: 7,
        },
        first: -5,
        post: 0,
        physical_state: 1,
        returned_mask: 1,
        borrowed_mask: 1,
        row_count: 2,
        progress_kind: 0,
        progress_row: 0,
        progress_ns: 0,
        progress_witness: 0,
    }
}

#[test]
fn acknowledgements_do_not_release_the_retained_frontier_or_create_return() {
    let slot = NodeSlot::new(0);
    assert_eq!(ABI_VERSION, 32);
    assert_eq!(NODE_SLOT_SIZE, 512);
    assert!(slot.reserved_bytes_are_zero());
    slot.retain_action_frontier(2).unwrap();
    slot.acknowledge_control_boundary();

    assert!(slot.action_frontier_is_retained());
    assert_eq!(slot.observe_action_return().unwrap(), None);
    assert!(slot.release_action_frontier(4).is_err());
    assert!(slot.action_frontier_is_retained());
}

#[test]
fn return_epoch_and_sequence_remain_distinct_from_semantic_status() {
    let slot = NodeSlot::new(0);
    slot.retain_action_frontier(2).unwrap();
    assert!(slot.publish_action_return(0, returned(4)).is_err());
    assert_eq!(slot.observe_action_return().unwrap(), None);

    assert_eq!(slot.publish_action_return(0, returned(2)).unwrap(), 2);
    assert_eq!(slot.observe_action_return().unwrap(), Some(returned(2)));
    assert!(slot.publish_action_return(0, returned(2)).is_err());
    assert!(slot.action_frontier_is_retained());

    slot.release_action_frontier(2).unwrap();
    assert!(!slot.action_frontier_is_retained());
    assert!(slot.release_action_frontier(2).is_err());
    slot.retain_action_frontier(4).unwrap();
    assert!(slot.publish_action_return(2, returned(2)).is_err());
    assert!(slot.action_frontier_is_retained());
}

#[test]
fn observation_clone_cannot_copy_a_physical_owner_or_return_proof() {
    let slot = NodeSlot::new(0);
    slot.retain_action_frontier(2).unwrap();
    slot.publish_action_return(0, returned(2)).unwrap();

    let copied = slot.clone();
    assert!(!copied.action_frontier_is_retained());
    assert_eq!(copied.observe_action_return().unwrap(), None);
    assert!(copied.publish_action_return(0, returned(2)).is_err());

    assert!(slot.action_frontier_is_retained());
    assert_eq!(slot.observe_action_return().unwrap(), Some(returned(2)));
}

#[test]
fn no_capture_ack_keeps_the_exact_queued_frontier_owned() {
    let slot = NodeSlot::new(0);
    let frontier = 17;
    let token = slot.preview_action_token(frontier, None).unwrap();
    slot.retain_action_frontier(2).unwrap();

    assert_eq!(
        slot.request_control_boundary(frontier, None).unwrap(),
        token
    );
    slot.acknowledge_control_boundary();
    assert!(slot.action_frontier_is_retained());
    assert_eq!(slot.observe_action_return().unwrap(), None);
    assert!(slot.release_action_frontier(4).is_err());
    assert!(slot.action_frontier_is_retained());
}
