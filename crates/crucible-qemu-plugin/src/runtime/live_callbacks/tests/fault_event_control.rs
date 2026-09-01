//! Control-boundary occurrence-event ownership regressions.

use super::*;

use crucible_shmem::{
    FaultCommandKind, FaultCommandSlotV1, FaultEventHeaderV1, FaultEventOutcomeV1,
    FaultEventSlotV1, FaultPayloadArenaHeader, FaultResultSlotV1, RingHeader, dequeue_fault_event,
    enqueue_fault_event,
};

#[test]
fn control_boundary_retries_occurrence_event_after_host_drain_before_ack() {
    const COMMAND_ARENA_OFFSET: u64 = 4_096;
    const RESULT_ARENA_OFFSET: u64 = 8_192;
    const EVENT_ARENA_OFFSET: u64 = 12_288;

    let target_node_hash = *blake3::hash(b"control-boundary-node").as_bytes();
    let command_ring = RingHeader::new();
    let command_arena_header = FaultPayloadArenaHeader::new();
    let mut command_slots = vec![FaultCommandSlotV1::new(); 1];
    let mut command_arena = vec![0_u8; 512];
    let result_ring = RingHeader::new();
    let result_arena_header = FaultPayloadArenaHeader::new();
    let mut result_slots = vec![FaultResultSlotV1::new(); 1];
    let mut result_arena = vec![0_u8; 512];
    let event_ring = RingHeader::new();
    let event_arena_header = FaultPayloadArenaHeader::new();
    let mut event_slots = vec![FaultEventSlotV1::new(); 1];
    let mut event_arena = vec![0_u8; 512];
    let bridge = crate::fault_command::test_support::initialized_bridge(
        target_node_hash,
        &command_ring,
        &mut command_slots,
        &command_arena_header,
        &mut command_arena,
        COMMAND_ARENA_OFFSET,
        &result_ring,
        &mut result_slots,
        &result_arena_header,
        &mut result_arena,
        RESULT_ARENA_OFFSET,
        &event_ring,
        &mut event_slots,
        &event_arena_header,
        &mut event_arena,
        EVENT_ARENA_OFFSET,
    );

    enqueue_fault_event(
        &event_ring,
        &mut event_slots,
        &event_arena_header,
        &mut event_arena,
        EVENT_ARENA_OFFSET,
        FaultEventHeaderV1 {
            command_kind: FaultCommandKind::MemoryAccessTransform,
            outcome: FaultEventOutcomeV1::Applied,
            event_sequence: 1,
            rule_command_sequence: 1,
            observed_icount: 1,
            model_phase: 18,
            target_kind: 4,
            generation: 1,
            binding_hash: [1; 32],
            opportunity_hash: [2; 32],
            action_hash: [3; 32],
            target_hash: [4; 32],
            before_hash: [5; 32],
            after_hash: [6; 32],
            evidence_hash: [0; 32],
            payload_hash: [0; 32],
            payload_offset: 0,
            payload_length: 0,
        },
        &[7],
    )
    .unwrap_or_else(|error| panic!("fill occurrence-event ring: {error}"));
    let (pending_event_sequence, pending_evidence) =
        crate::fault_command::test_support::stage_node_event(target_node_hash);

    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 7, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(80, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    *state
        .fault_commands
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(bridge);
    let request = slot
        .request_control_boundary()
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));

    state.on_control_boundary(7).unwrap_or_else(|error| {
        panic!("backpressured control callback should remain live: {error}")
    });
    assert_eq!(slot.snapshot().control_boundary_ack, request);
    assert!(crate::fault_command::test_support::node_event_is_pending());

    let released = dequeue_fault_event(
        &event_ring,
        &mut event_slots,
        &event_arena_header,
        &event_arena,
        EVENT_ARENA_OFFSET,
    )
    .unwrap_or_else(|error| panic!("host should drain one occurrence event: {error}"));
    assert!(released.is_some());

    state
        .on_control_boundary(7)
        .unwrap_or_else(|error| panic!("host wake should retry the pending event: {error}"));
    assert_eq!(
        slot.snapshot().control_boundary_ack,
        request.wrapping_add(1)
    );
    assert!(!crate::fault_command::test_support::node_event_is_pending());

    let retried = dequeue_fault_event(
        &event_ring,
        &mut event_slots,
        &event_arena_header,
        &event_arena,
        EVENT_ARENA_OFFSET,
    )
    .unwrap_or_else(|error| panic!("host should drain the retried event: {error}"))
    .unwrap_or_else(|| panic!("retried event should be published before acknowledgement"));
    assert_eq!(retried.header.event_sequence, pending_event_sequence);
    assert_eq!(retried.header.rule_command_sequence, 77);
    assert_eq!(retried.header.observed_icount, 300);
    assert_eq!(retried.header.binding_hash, [2; 32]);
    assert_eq!(retried.payload, pending_evidence);
    assert!(
        dequeue_fault_event(
            &event_ring,
            &mut event_slots,
            &event_arena_header,
            &event_arena,
            EVENT_ARENA_OFFSET,
        )
        .unwrap_or_else(|error| panic!("final event-ring drain should succeed: {error}"))
        .is_none(),
        "the retried event must be published exactly once"
    );
}
