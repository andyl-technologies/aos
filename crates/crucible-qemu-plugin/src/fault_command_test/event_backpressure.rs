//! Lossless QEMU occurrence-event backpressure regressions.

use super::*;
use crucible_shmem::{
    FaultEventHeaderV1, FaultEventOutcomeV1, NodeFaultFieldV1, dequeue_fault_event,
    enqueue_fault_event,
};

#[test]
fn bridge_accepts_every_canonical_qemu_result_status() {
    for value in 1_u16..=14 {
        let status = result_status(value)
            .unwrap_or_else(|error| panic!("canonical status {value} was rejected: {error}"));
        assert_eq!(status as u16, value);
    }
    assert!(matches!(
        result_status(15),
        Err(FaultCommandBridgeError::QemuStatus { value: 15 })
    ));
}

pub(super) fn assert_pump(bridge: &mut FaultCommandBridge, expected: bool, operation: &str) {
    let drained = bridge
        .pump(40, 12)
        .unwrap_or_else(|error| panic!("{operation}: {error}"));
    assert_eq!(drained, expected, "{operation}");
}

pub(super) fn assert_event_ring_backpressure(
    bridge: &mut FaultCommandBridge,
    event_ring: &RingHeader,
    event_slots: &mut [FaultEventSlotV1],
    event_arena_header: &FaultPayloadArenaHeader,
    event_arena: &mut [u8],
    event_arena_offset: u64,
) {
    for event_sequence in 1..=event_slots.len() as u64 {
        enqueue_fault_event(
            event_ring,
            event_slots,
            event_arena_header,
            event_arena,
            event_arena_offset,
            FaultEventHeaderV1 {
                command_kind: FaultCommandKind::MemoryAccessTransform,
                outcome: FaultEventOutcomeV1::Applied,
                event_sequence,
                rule_command_sequence: 2,
                observed_icount: 300,
                model_phase: 18,
                target_kind: 4,
                generation: 7,
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
        .unwrap_or_else(|error| panic!("fill event ring: {error}"));
    }
    let request = NodeFaultPayloadV1 {
        command_kind: FaultCommandKind::CpuService,
        operation: NodeFaultOperationV1::Upsert,
        target_kind: NodeFaultTargetKindV1::Node,
        model_phase: 10,
        generation: 7,
        action_hash: [3; 32],
        target_hash: [4; 32],
        schema_hash: [5; 32],
        fields: vec![
            NodeFaultFieldV1::bytes(node_fault_field::P1, b"CRUCJSN1[0]".to_vec()),
            NodeFaultFieldV1::ratio(node_fault_field::P2, 1, 2),
            NodeFaultFieldV1::u64(node_fault_field::P3, 100),
            NodeFaultFieldV1::u32(node_fault_field::P4, 1),
        ],
    }
    .encode()
    .unwrap_or_else(|error| panic!("encode pending event request: {error}"));
    let evidence = vec![9];
    let pending_event = QemuFaultEvent {
        command_kind: FaultCommandKind::CpuService as u16,
        outcome: FaultEventOutcomeV1::Applied as u16,
        model_phase: 10,
        target_kind: NodeFaultTargetKindV1::Node as u16,
        evidence_length: evidence.len() as u32,
        event_sequence: 99,
        rule_command_sequence: 77,
        observed_icount: 300,
        generation: 7,
        binding_hash: [2; 32],
        opportunity_hash: [8; 32],
        action_hash: [3; 32],
        target_hash: [4; 32],
        before_hash: [5; 32],
        after_hash: [6; 32],
    };
    let envelope = encode_test_node_event_envelope(
        &request,
        &evidence,
        &pending_event,
        bridge.target_node_hash,
    );
    TEST_EVENT_PENDING.with(|pending| {
        *pending.borrow_mut() = Some((pending_event, envelope));
    });
    assert_pump(bridge, false, "event backpressure must be nonterminal");
    TEST_EVENT_PENDING.with(|pending| assert!(pending.borrow().is_some()));

    let released = dequeue_fault_event(
        event_ring,
        event_slots,
        event_arena_header,
        event_arena,
        event_arena_offset,
    )
    .unwrap_or_else(|error| panic!("release event capacity: {error}"));
    assert!(released.is_some());
    assert_pump(bridge, true, "event retry after backpressure");
    TEST_EVENT_PENDING.with(|pending| assert!(pending.borrow().is_none()));

    let mut retried = None;
    while let Some(event) = dequeue_fault_event(
        event_ring,
        event_slots,
        event_arena_header,
        event_arena,
        event_arena_offset,
    )
    .unwrap_or_else(|error| panic!("drain event ring: {error}"))
    {
        if event.header.event_sequence == pending_event.event_sequence {
            assert!(
                retried.replace(event).is_none(),
                "event published more than once"
            );
        }
    }
    let retried = retried.unwrap_or_else(|| panic!("retried event was not published"));
    assert_eq!(retried.header.command_kind, FaultCommandKind::CpuService);
    assert_eq!(retried.header.rule_command_sequence, 77);
    assert_eq!(retried.header.observed_icount, 340);
    assert_eq!(retried.header.binding_hash, [2; 32]);
    assert_eq!(retried.header.action_hash, [3; 32]);
    assert_eq!(retried.header.target_hash, [4; 32]);
    assert_eq!(retried.payload, evidence);
}
