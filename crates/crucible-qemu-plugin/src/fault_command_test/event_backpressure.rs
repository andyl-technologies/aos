//! Lossless QEMU occurrence-event backpressure regressions.

use super::*;
use crucible_shmem::{FaultEventHeaderV1, FaultEventOutcomeV1, enqueue_fault_event};

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
    TEST_EVENT_PENDING.with(|pending| {
        pending.set(Some((
            QemuFaultEvent {
                command_kind: FaultCommandKind::MemoryAccessTransform as u16,
                evidence_length: 1,
                ..QemuFaultEvent::default()
            },
            193,
        )));
    });
    assert_pump(bridge, false, "event backpressure must be nonterminal");
    TEST_EVENT_PENDING.with(|pending| pending.set(None));
}
