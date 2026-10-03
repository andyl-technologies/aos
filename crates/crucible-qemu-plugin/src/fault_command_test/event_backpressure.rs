//! Lossless QEMU occurrence-event backpressure regressions.

use super::*;
use crucible_shmem::{
    FaultEventHeaderV1, FaultEventOutcomeV1, NodeFaultFieldV1, dequeue_fault_event,
    enqueue_fault_event,
};
use sha2::Sha256;

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
    let evidence = crate::fault_command::test_support::cpu_service_event_evidence(300, 15_000);
    let pending_event = QemuFaultEvent {
        command_kind: FaultCommandKind::CpuService as u16,
        outcome: FaultEventOutcomeV1::Applied as u16,
        model_phase: 10,
        target_kind: NodeFaultTargetKindV1::Node as u16,
        evidence_length: evidence.len() as u32,
        event_sequence: 99,
        rule_command_sequence: 77,
        observed_icount: 300,
        observed_tick: 15_000,
        generation: 7,
        binding_hash: [2; 32],
        opportunity_hash: [8; 32],
        action_hash: [3; 32],
        target_hash: [4; 32],
        before_hash: Sha256::digest(&evidence[..64]).into(),
        after_hash: Sha256::digest(&evidence[..160]).into(),
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
    assert_eq!(retried.header.observed_icount, 15_000);
    assert_eq!(retried.header.binding_hash, [2; 32]);
    assert_eq!(retried.header.action_hash, [3; 32]);
    assert_eq!(retried.header.target_hash, [4; 32]);
    assert_eq!(retried.payload, evidence);

    // Even a freshly authenticated envelope cannot substitute either original
    // QEMU clock receipt before the event enters the public transport.
    for (offset, forged) in [
        (112, 301_u64),
        (96, 15_001_u64),
        (0, u64::from_le_bytes(*b"CRUCVCS1")),
    ] {
        let mut forged_evidence = evidence.clone();
        forged_evidence[offset..offset + 8].copy_from_slice(&forged.to_le_bytes());
        let mut forged_event = pending_event;
        forged_event.before_hash = Sha256::digest(&forged_evidence[..64]).into();
        forged_event.after_hash = Sha256::digest(&forged_evidence[..160]).into();
        let envelope = encode_test_node_event_envelope(
            &request,
            &forged_evidence,
            &forged_event,
            bridge.target_node_hash,
        );
        TEST_EVENT_PENDING.with(|pending| {
            *pending.borrow_mut() = Some((forged_event, envelope));
        });

        assert!(matches!(
            bridge.pump(40, 12),
            Err(FaultCommandBridgeError::EventEnvelope)
        ));
        assert!(
            dequeue_fault_event(
                event_ring,
                event_slots,
                event_arena_header,
                event_arena,
                event_arena_offset,
            )
            .unwrap_or_else(|error| panic!("forged clock event publication: {error}"))
            .is_none()
        );
    }

    let mut request = NodeFaultPayloadV1::decode(&request)
        .unwrap_or_else(|error| panic!("decode state fixture request: {error}"));
    request.command_kind = FaultCommandKind::CpuVcpuState;
    request.target_kind = NodeFaultTargetKindV1::Vcpu;
    request.fields = vec![
        NodeFaultFieldV1::u32(node_fault_field::P1, 2),
        NodeFaultFieldV1::boolean(node_fault_field::P2, false),
        NodeFaultFieldV1::hash(node_fault_field::P3, [0; 32]),
        NodeFaultFieldV1::u32(node_fault_field::T1, 0),
    ];
    let request = request
        .encode()
        .unwrap_or_else(|error| panic!("encode state fixture request: {error}"));
    let mut evidence = vec![0; 192];
    evidence[..8].copy_from_slice(b"CRUCVST1");
    evidence[8..10].copy_from_slice(&1_u16.to_le_bytes());
    evidence[16..20].copy_from_slice(&1_u32.to_le_bytes());
    evidence[20..24].copy_from_slice(&2_u32.to_le_bytes());
    evidence[24..32].copy_from_slice(&pending_event.observed_icount.to_le_bytes());
    evidence[160..192].copy_from_slice(&pending_event.binding_hash);

    for forged_raw in [None, Some(pending_event.observed_icount + 1)] {
        let mut evidence = evidence.clone();
        if let Some(raw) = forged_raw {
            evidence[24..32].copy_from_slice(&raw.to_le_bytes());
        }
        let mut event = pending_event;
        event.command_kind = FaultCommandKind::CpuVcpuState as u16;
        event.target_kind = NodeFaultTargetKindV1::Vcpu as u16;
        let mut before = evidence.clone();
        before[..8].copy_from_slice(b"CRUCVSB1");
        before[20..24].copy_from_slice(&evidence[16..20]);
        event.before_hash = Sha256::digest(before).into();
        let mut after = evidence.clone();
        after[..8].copy_from_slice(b"CRUCVSA1");
        after[16..20].copy_from_slice(&evidence[20..24]);
        event.after_hash = Sha256::digest(after).into();
        let envelope =
            encode_test_node_event_envelope(&request, &evidence, &event, bridge.target_node_hash);
        TEST_EVENT_PENDING.with(|pending| {
            *pending.borrow_mut() = Some((event, envelope));
        });

        if forged_raw.is_some() {
            assert!(matches!(
                bridge.pump(40, 12),
                Err(FaultCommandBridgeError::EventEnvelope)
            ));
        } else {
            assert_pump(
                bridge,
                true,
                "state event with distinct raw and logical clocks",
            );
        }
        let published = dequeue_fault_event(
            event_ring,
            event_slots,
            event_arena_header,
            event_arena,
            event_arena_offset,
        )
        .unwrap_or_else(|error| panic!("state event publication: {error}"));
        if forged_raw.is_some() {
            assert!(published.is_none());
        } else {
            let published = published.unwrap_or_else(|| panic!("state event was not published"));
            assert_eq!(
                published.header.observed_icount,
                pending_event.observed_tick
            );
            assert_eq!(published.payload, evidence);
        }
    }
}
