//! Checks factual return framing independently of control/sample ACKs.
//!
//! The test writer exercises public atomic bytes. It is not a Native Source,
//! operation, mapping-writer grant or physical completion fixture.

// crucible-lint: allow panic-shortcut -- causal test fixtures panic to localize clock, custody and wire regressions.
#![allow(clippy::unwrap_used)]

use crucible_qemu_protocol::boundary_action::{ActionBinding, ActionReturn};
use crucible_qemu_protocol::parent_park_return::{
    PARENT_PARK_PHYSICAL_RESOLUTION_ALL, ParentParkReturn,
};
use crucible_qemu_shmem::{
    ABI_VERSION, NODE_SLOT_ACTION_RETURN_OFFSET, NODE_SLOT_PARK_RETURN_OFFSET, NODE_SLOT_SIZE,
    NodeSlot,
};

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
            park_request: None,
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

fn park_returned(sequence: u64, correlation: u64) -> ParentParkReturn {
    let mut binding = returned(sequence).binding;
    binding.capture = None;
    binding.park_request = Some(correlation);
    ParentParkReturn {
        binding,
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
    }
}

#[test]
fn acknowledgements_do_not_release_the_retained_frontier_or_create_return() {
    let slot = NodeSlot::new(0);
    assert_eq!(ABI_VERSION, 33);
    assert_eq!(NODE_SLOT_SIZE, 768);
    assert_eq!(NODE_SLOT_ACTION_RETURN_OFFSET, 264);
    assert_eq!(NODE_SLOT_PARK_RETURN_OFFSET, 512);
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

#[test]
fn park_journal_has_a_distinct_writer_and_return_sequence() {
    let slot = NodeSlot::new(0);
    slot.retain_action_frontier(2).unwrap();
    let park = park_returned(2, 19);
    let mut wrong_control = returned(2);
    wrong_control.binding = park.binding;
    let mut wrong_park = park;
    wrong_park.binding = returned(2).binding;

    assert!(slot.publish_action_return(0, wrong_control).is_err());
    assert!(slot.publish_parent_park_return(0, wrong_park).is_err());
    assert_eq!(slot.observe_parent_park_return().unwrap(), None);
    assert_eq!(slot.observe_action_return().unwrap(), None);

    assert_eq!(slot.publish_parent_park_return(0, park).unwrap(), 2);
    assert_eq!(slot.observe_parent_park_return().unwrap(), Some(park));
    assert_eq!(slot.observe_action_return().unwrap(), None);
    assert!(slot.action_frontier_is_retained());
}

#[test]
fn park_clone_and_ack_do_not_copy_or_return_module_custody() {
    let slot = NodeSlot::new(0);
    slot.retain_action_frontier(2).unwrap();
    let park = park_returned(2, 23);
    slot.publish_parent_park_return(0, park).unwrap();

    let copied = slot.clone();
    slot.acknowledge_control_boundary();

    assert_eq!(copied.observe_parent_park_return().unwrap(), None);
    assert!(copied.publish_parent_park_return(0, park).is_err());
    assert_eq!(slot.observe_parent_park_return().unwrap(), Some(park));
    assert!(slot.action_frontier_is_retained());
    assert!(copied.reserved_bytes_are_zero());
}

#[test]
fn park_writer_checks_frontier_and_complete_resource_resolution() {
    let slot = NodeSlot::new(0);
    slot.retain_action_frontier(2).unwrap();
    assert!(
        slot.publish_parent_park_return(0, park_returned(4, 19))
            .is_err()
    );
    let mut incomplete = park_returned(2, 19);
    incomplete.physical_resolution_mask &= !(1 << 6);
    assert!(slot.publish_parent_park_return(0, incomplete).is_err());
    assert_eq!(slot.observe_parent_park_return().unwrap(), None);

    let mut absent_views = park_returned(2, 19);
    absent_views.pair_view_return_mask = 0;
    assert_eq!(slot.publish_parent_park_return(0, absent_views).unwrap(), 2);
    assert!(slot.publish_parent_park_return(0, absent_views).is_err());
    assert_eq!(
        slot.observe_parent_park_return().unwrap(),
        Some(absent_views)
    );
    assert!(slot.action_frontier_is_retained());
}
