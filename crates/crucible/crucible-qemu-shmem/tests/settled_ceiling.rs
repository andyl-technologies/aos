//! Checks settlement records for bounded advance ceilings (RFC-0010 SCHED-12).
//!
//! A published ceiling is an upper bound. A node stops at its last retirement
//! at or below it and attests, per advance publication, that nothing else
//! happens before the ceiling. These tests pin how that attestation is written
//! and matched.

#![forbid(unsafe_code)]

use crucible_qemu_shmem::{
    ADVANCE_STOP_CONDITION_EXACT_EVENT, AdvanceCeiling, AdvanceStopCondition, IDLE_WAKE_NONE,
    KIND_VM, NODE_SLOT_PAD4_OFFSET, NODE_SLOT_SETTLED_CEILING_TICK_OFFSET,
    NODE_SLOT_SETTLED_PUBLICATION_SEQUENCE_OFFSET, NodeSlot, NodeSlotError, STATUS_IDLE,
    STATUS_RUNNING, authorize_advance_ceiling,
};

fn ceiling(current_icount: u64, max_advance_icount: u64) -> AdvanceCeiling {
    match authorize_advance_ceiling(current_icount, max_advance_icount, None) {
        Ok(ceiling) => ceiling,
        Err(error) => panic!("advance ceiling should be valid: {error}"),
    }
}

fn running_slot_with_ceiling(max_advance_icount: u64, stop: AdvanceStopCondition) -> NodeSlot {
    let slot = NodeSlot::new(KIND_VM);
    slot.mark_running();
    if let Err(error) = slot.publish_scheduler_advance(ceiling(0, max_advance_icount), stop) {
        panic!("publish scheduler advance: {error}");
    }
    slot
}

#[test]
fn settlement_fields_occupy_former_reserved_bytes() {
    assert_eq!(NODE_SLOT_SETTLED_CEILING_TICK_OFFSET, 216);
    assert_eq!(NODE_SLOT_SETTLED_PUBLICATION_SEQUENCE_OFFSET, 224);
    assert_eq!(NODE_SLOT_PAD4_OFFSET, 240);
    assert!(NodeSlot::new(KIND_VM).reserved_bytes_are_zero());
}

#[test]
fn exact_event_stop_condition_round_trips_and_authorizes_its_ceiling() {
    assert_eq!(AdvanceStopCondition::ExactEvent.encode(), 2);
    assert_eq!(
        AdvanceStopCondition::decode(ADVANCE_STOP_CONDITION_EXACT_EVENT),
        Ok(AdvanceStopCondition::ExactEvent)
    );
    assert_eq!(
        AdvanceStopCondition::decode(3),
        Err(NodeSlotError::InvalidAdvanceStopCondition { encoded: 3 })
    );
    assert!(AdvanceStopCondition::Ceiling.authorizes_ceiling());
    assert!(AdvanceStopCondition::ExactEvent.authorizes_ceiling());
    assert!(!AdvanceStopCondition::NextAuthenticatedIdle.authorizes_ceiling());

    let slot = running_slot_with_ceiling(1_000, AdvanceStopCondition::ExactEvent);
    assert_eq!(
        slot.load_scheduler_advance(),
        Ok((1_000, AdvanceStopCondition::ExactEvent))
    );
}

#[test]
fn settlement_below_the_ceiling_names_its_advance_publication() {
    let slot = running_slot_with_ceiling(1_000, AdvanceStopCondition::Ceiling);
    let sequence = slot.snapshot().advance_publication_sequence;

    // The last retirement fits at 951; the next one would end at 1001.
    assert_eq!(slot.publish_settled_icount(951, 1_000), Ok(true));

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 951);
    assert_eq!(snapshot.status, STATUS_RUNNING);
    assert_eq!(snapshot.settled_ceiling_tick, 1_000);
    assert_eq!(snapshot.settled_publication_sequence, sequence);
    assert!(snapshot.settles(1_000, sequence));
    assert!(snapshot.settles_current_advance());
    assert!(!snapshot.settles(999, sequence));
    assert!(slot.reserved_bytes_are_zero());
}

#[test]
fn a_new_advance_invalidates_the_previous_settlement() {
    let slot = running_slot_with_ceiling(1_000, AdvanceStopCondition::Ceiling);
    let first = slot.snapshot().advance_publication_sequence;
    assert_eq!(slot.publish_settled_icount(951, 1_000), Ok(true));

    // Reissuing the same ceiling publishes a new advance that is not settled.
    if let Err(error) =
        slot.publish_scheduler_advance(ceiling(951, 1_000), AdvanceStopCondition::Ceiling)
    {
        panic!("republish scheduler advance: {error}");
    }
    let snapshot = slot.snapshot();
    assert_ne!(snapshot.advance_publication_sequence, first);
    assert!(snapshot.settles(1_000, first));
    assert!(!snapshot.settles_current_advance());
}

#[test]
fn a_stale_ceiling_publishes_the_clock_without_settlement() {
    let slot = running_slot_with_ceiling(2_000, AdvanceStopCondition::Ceiling);

    // QEMU sampled an older ceiling; the host has since published 2000.
    assert_eq!(slot.publish_settled_icount(951, 1_000), Ok(false));

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 951);
    assert!(!snapshot.settles_current_advance());
}

#[test]
fn settlement_never_crosses_the_ceiling_or_settles_a_next_idle_probe() {
    let slot = running_slot_with_ceiling(1_000, AdvanceStopCondition::Ceiling);
    assert_eq!(
        slot.publish_settled_icount(1_001, 1_000),
        Err(NodeSlotError::NodeAdvancePastCeiling {
            next_icount: 1_001,
            max_advance_icount: 1_000,
        })
    );

    let probe = running_slot_with_ceiling(1_000, AdvanceStopCondition::NextAuthenticatedIdle);
    assert_eq!(probe.publish_settled_icount(951, 1_000), Ok(false));
    assert!(!probe.snapshot().settles_current_advance());
}

#[test]
fn a_control_boundary_after_settlement_publishes_an_idle_boundary() {
    let slot = running_slot_with_ceiling(1_000, AdvanceStopCondition::Ceiling);
    assert_eq!(slot.publish_settled_icount(951, 1_000), Ok(true));

    assert_eq!(slot.publish_control_boundary(951, 19), Ok(()));

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.status, STATUS_IDLE);
    assert_eq!(snapshot.current_icount, 951);
    assert_eq!(snapshot.idle_wake_icount, 951);
}

#[test]
fn a_control_boundary_below_an_unsettled_ceiling_keeps_running() {
    let slot = running_slot_with_ceiling(1_000, AdvanceStopCondition::Ceiling);
    assert_eq!(slot.publish_reached_icount(951), Ok(()));

    assert_eq!(slot.publish_control_boundary(951, 19), Ok(()));

    assert_eq!(slot.snapshot().status, STATUS_RUNNING);
}

/// Leaves the zero-length idle that a settled clamp at 951 publishes.
fn slot_with_a_settled_ceiling_marker() -> (NodeSlot, u64) {
    let slot = running_slot_with_ceiling(1_000, AdvanceStopCondition::Ceiling);
    assert_eq!(slot.publish_settled_icount(951, 1_000), Ok(true));
    let marker = slot.publish_control_boundary_answering(951, 19, None);
    let snapshot = slot.snapshot();
    assert_eq!(marker, Ok(Some(snapshot.advance_publication_sequence)));
    assert_eq!(snapshot.status, STATUS_IDLE);
    assert_eq!(snapshot.idle_wake_icount, 951);
    (slot, snapshot.advance_publication_sequence)
}

fn publish_next_advance(slot: &NodeSlot) -> u64 {
    if let Err(error) =
        slot.publish_scheduler_advance(ceiling(951, 2_000), AdvanceStopCondition::Ceiling)
    {
        panic!("publish next scheduler advance: {error}");
    }
    slot.snapshot().advance_publication_sequence
}

#[test]
fn a_control_boundary_below_a_new_ceiling_drops_an_earlier_advances_zero_length_idle() {
    let (slot, marker_advance) = slot_with_a_settled_ceiling_marker();
    publish_next_advance(&slot);

    // The marker answered the clamp. Below the next ceiling it would claim
    // the node stopped at 951 for an advance it has not run.
    assert_eq!(
        slot.publish_control_boundary_answering(951, 19, Some(marker_advance)),
        Ok(None)
    );

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.status, STATUS_RUNNING);
    assert_eq!(snapshot.current_icount, 951);
    assert!(!snapshot.settles_current_advance());
}

#[test]
fn a_control_boundary_below_the_ceiling_keeps_a_zero_length_idle_for_this_advance() {
    let (slot, _marker_advance) = slot_with_a_settled_ceiling_marker();
    let advance = publish_next_advance(&slot);
    // A stop taken for this advance at the same coordinate, as the plugin's
    // output, console, selectable, marker and pause writers publish it.
    if let Err(error) = slot.publish_pause_quiesced(951, 19) {
        panic!("publish current stop: {error}");
    }

    assert_eq!(
        slot.publish_control_boundary_answering(951, 19, Some(advance)),
        Ok(Some(advance))
    );

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.status, STATUS_IDLE);
    assert_eq!(snapshot.idle_wake_icount, 951);
}

#[test]
fn a_control_boundary_without_a_record_keeps_the_original_classification() {
    let (slot, _marker_advance) = slot_with_a_settled_ceiling_marker();
    publish_next_advance(&slot);

    assert_eq!(slot.publish_control_boundary(951, 19), Ok(()));

    assert_eq!(slot.snapshot().status, STATUS_IDLE);
}

#[test]
fn a_control_boundary_below_a_new_ceiling_keeps_a_future_idle_wake() {
    let slot = running_slot_with_ceiling(1_000, AdvanceStopCondition::Ceiling);
    if let Err(error) = slot.publish_idle(951, 990) {
        panic!("publish future idle: {error}");
    }

    assert_eq!(
        slot.publish_control_boundary_answering(951, 19, None),
        Ok(None)
    );

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.status, STATUS_IDLE);
    assert_eq!(snapshot.idle_wake_icount, 990);
}

#[test]
fn a_halted_node_without_a_wake_parks_at_its_physical_point() {
    let slot = running_slot_with_ceiling(1_000, AdvanceStopCondition::Ceiling);

    if let Err(error) = slot.publish_idle(400, IDLE_WAKE_NONE) {
        panic!("publish idle without a wake: {error}");
    }

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.status, STATUS_IDLE);
    assert_eq!(snapshot.current_icount, 400);
    assert_eq!(snapshot.idle_wake_icount, IDLE_WAKE_NONE);
}
