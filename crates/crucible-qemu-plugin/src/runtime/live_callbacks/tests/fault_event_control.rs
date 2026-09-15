//! Control-boundary occurrence-event ownership regressions.

use super::*;

use crucible_shmem::{
    DequeuedFaultResult, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR, FAULT_COMMAND_FLAG_NONE,
    FAULT_COMMAND_SEMANTIC_VERSION, FaultBoundaryPhase, FaultCommandHeaderV1, FaultCommandKind,
    FaultCommandSlotV1, FaultEventHeaderV1, FaultEventOutcomeV1, FaultEventSlotV1,
    FaultPayloadArenaHeader, FaultResultSlotV1, FingerprintSampleSlot, RingHeader,
    dequeue_fault_event, dequeue_fault_result, enqueue_fault_command, enqueue_fault_event,
};

const COMMAND_ARENA_OFFSET: u64 = 4_096;
const RESULT_ARENA_OFFSET: u64 = 8_192;
const EVENT_ARENA_OFFSET: u64 = 12_288;

struct ControlFaultTransports {
    command_ring: Box<RingHeader>,
    command_slots: Vec<FaultCommandSlotV1>,
    command_arena_header: Box<FaultPayloadArenaHeader>,
    command_arena: Vec<u8>,
    result_ring: Box<RingHeader>,
    result_slots: Vec<FaultResultSlotV1>,
    result_arena_header: Box<FaultPayloadArenaHeader>,
    result_arena: Vec<u8>,
    event_ring: Box<RingHeader>,
    event_slots: Vec<FaultEventSlotV1>,
    event_arena_header: Box<FaultPayloadArenaHeader>,
    event_arena: Vec<u8>,
}

fn control_fault_bridge(
    target_node_hash: [u8; 32],
) -> (
    crate::fault_command::FaultCommandBridge,
    ControlFaultTransports,
) {
    let mut transports = ControlFaultTransports {
        command_ring: Box::new(RingHeader::new()),
        command_slots: vec![FaultCommandSlotV1::new(); 2],
        command_arena_header: Box::new(FaultPayloadArenaHeader::new()),
        command_arena: vec![0; 512],
        result_ring: Box::new(RingHeader::new()),
        result_slots: vec![FaultResultSlotV1::new(); 1],
        result_arena_header: Box::new(FaultPayloadArenaHeader::new()),
        result_arena: vec![0; 512],
        event_ring: Box::new(RingHeader::new()),
        event_slots: vec![FaultEventSlotV1::new(); 1],
        event_arena_header: Box::new(FaultPayloadArenaHeader::new()),
        event_arena: vec![0; 512],
    };
    let bridge = crate::fault_command::test_support::initialized_bridge(
        target_node_hash,
        &transports.command_ring,
        &mut transports.command_slots,
        &transports.command_arena_header,
        &mut transports.command_arena,
        COMMAND_ARENA_OFFSET,
        &transports.result_ring,
        &mut transports.result_slots,
        &transports.result_arena_header,
        &mut transports.result_arena,
        RESULT_ARENA_OFFSET,
        &transports.event_ring,
        &mut transports.event_slots,
        &transports.event_arena_header,
        &mut transports.event_arena,
        EVENT_ARENA_OFFSET,
    );
    (bridge, transports)
}

fn boundary_probe(target_node_hash: [u8; 32], sequence: u64) -> FaultCommandHeaderV1 {
    FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::BoundaryProbe,
        command_flags: FAULT_COMMAND_FLAG_NONE,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: sequence,
        target_node_hash,
        target_icount: 7,
        authorization_ceiling_icount: 7,
        binding_hash: [1; 32],
        opportunity_hash: [2; 32],
        expected_precondition_hash: [0; 32],
        payload_hash: [0; 32],
        payload_offset: 0,
        payload_length: 0,
    }
}

fn fingerprint_state(
    slot: &NodeSlot,
    fingerprint_slot: &FingerprintSampleSlot,
    bridge: crate::fault_command::FaultCommandBridge,
) -> LiveVcpuTimeCallbackState {
    let introspector = crate::PluginVcpuIntrospector::require(
        Some(test_fingerprint_read_vcpu_regs),
        Some(test_fingerprint_read_rr_cursor),
    )
    .unwrap_or_else(|error| panic!("test introspector should bind: {error}"));
    let sampling = crate::fingerprint_sampler::PluginFingerprintSampling::from_test_exports(
        introspector,
        test_fingerprint_capture,
    );
    test_live_state_with_fault_commands(90, 1, 0, 0, slot, Box::new(bridge))
        .and_then(|state| {
            state.attach_fingerprint(
                sampling,
                fingerprint_slot,
                LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL),
            )
        })
        .unwrap_or_else(|error| panic!("live fingerprint state should build: {error}"))
}

#[test]
fn bound_frontier_rejects_a_late_producer_without_capture_pause_or_ack() {
    let target_node_hash = [0x31; 32];
    let (bridge, mut transports) = control_fault_bridge(target_node_hash);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 7, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let fingerprint_slot = FingerprintSampleSlot::new();
    let state = fingerprint_state(&slot, &fingerprint_slot, bridge);

    let first = boundary_probe(target_node_hash, 1);
    enqueue_fault_command(
        &transports.command_ring,
        &mut transports.command_slots,
        &transports.command_arena_header,
        &mut transports.command_arena,
        COMMAND_ARENA_OFFSET,
        first,
        &[],
    )
    .unwrap_or_else(|error| panic!("enqueue bound command: {error}"));
    let bound_frontier = transports.command_ring.write_index();
    let capture_request = fingerprint_slot.request_capture_v1();
    let control_request = slot
        .request_control_boundary(bound_frontier, Some(capture_request))
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));

    let late = boundary_probe(target_node_hash, 2);
    enqueue_fault_command(
        &transports.command_ring,
        &mut transports.command_slots,
        &transports.command_arena_header,
        &mut transports.command_arena,
        COMMAND_ARENA_OFFSET,
        late,
        &[],
    )
    .unwrap_or_else(|error| panic!("enqueue late command: {error}"));
    TEST_REQUEST_VMSTOP_CALLS.set(0);

    state
        .on_control_boundary(7)
        .unwrap_or_else(|error| panic!("late frontier must fail closed: {error}"));

    assert_eq!(transports.command_ring.read_index(), 0);
    assert_eq!(slot.snapshot().control_boundary_ack, control_request);
    assert_eq!(fingerprint_slot.snapshot(), None);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
}

#[test]
fn synchronous_node_dispatch_precedes_same_icount_capture_and_ack() {
    let target_node_hash = [0x32; 32];
    let (bridge, mut transports) = control_fault_bridge(target_node_hash);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 7, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let fingerprint_slot = FingerprintSampleSlot::new();
    let state = fingerprint_state(&slot, &fingerprint_slot, bridge);

    TEST_FINGERPRINT_CAPTURE_SEED.set(0x10);
    let baseline_capture = fingerprint_slot.request_capture_v1();
    slot.request_control_boundary(0, Some(baseline_capture))
        .unwrap_or_else(|error| panic!("baseline request should publish: {error}"));
    state
        .on_control_boundary(7)
        .unwrap_or_else(|error| panic!("baseline capture should complete: {error}"));
    let baseline = wait_for_fingerprint_sample(&fingerprint_slot, baseline_capture);

    let command = boundary_probe(target_node_hash, 1);
    enqueue_fault_command(
        &transports.command_ring,
        &mut transports.command_slots,
        &transports.command_arena_header,
        &mut transports.command_arena,
        COMMAND_ARENA_OFFSET,
        command.clone(),
        &[],
    )
    .unwrap_or_else(|error| panic!("enqueue due command: {error}"));
    crate::fault_command::test_support::stage_dispatch_results(
        std::slice::from_ref(&command),
        0x55,
    );
    let event_sequence = crate::fault_command::test_support::stage_dispatch_event(target_node_hash);
    let capture_request = fingerprint_slot.request_capture_v1();
    let control_request = slot
        .request_control_boundary(transports.command_ring.write_index(), Some(capture_request))
        .unwrap_or_else(|error| panic!("mutation request should publish: {error}"));

    state
        .on_control_boundary(7)
        .unwrap_or_else(|error| panic!("mutation boundary should complete: {error}"));

    let post_commit = wait_for_fingerprint_sample(&fingerprint_slot, capture_request);
    assert_eq!(post_commit.sample_icount, baseline.sample_icount);
    assert_ne!(post_commit.ram_digest, baseline.ram_digest);
    assert_eq!(
        slot.snapshot().control_boundary_ack,
        control_request.wrapping_add(1)
    );
    let result = dequeue_fault_result(
        &transports.result_ring,
        &transports.result_slots,
        &transports.result_arena_header,
        &transports.result_arena,
        RESULT_ARENA_OFFSET,
    )
    .unwrap_or_else(|error| panic!("dequeue dispatch result: {error}"));
    assert!(matches!(
        result,
        Some(DequeuedFaultResult::Valid { header, .. })
            if header.command_sequence == command.command_sequence
    ));
    let event = dequeue_fault_event(
        &transports.event_ring,
        &mut transports.event_slots,
        &transports.event_arena_header,
        &transports.event_arena,
        EVENT_ARENA_OFFSET,
    )
    .unwrap_or_else(|error| panic!("dequeue dispatch event: {error}"))
    .unwrap_or_else(|| panic!("dispatch event must publish before acknowledgement"));
    assert_eq!(event.header.event_sequence, event_sequence);
}

#[test]
fn post_dispatch_result_backpressure_retries_publication_without_redispatch() {
    let target_node_hash = [0x33; 32];
    let (bridge, mut transports) = control_fault_bridge(target_node_hash);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 7, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let fingerprint_slot = FingerprintSampleSlot::new();
    let state = fingerprint_state(&slot, &fingerprint_slot, bridge);

    let first = boundary_probe(target_node_hash, 1);
    let second = boundary_probe(target_node_hash, 2);
    for command in [first.clone(), second.clone()] {
        enqueue_fault_command(
            &transports.command_ring,
            &mut transports.command_slots,
            &transports.command_arena_header,
            &mut transports.command_arena,
            COMMAND_ARENA_OFFSET,
            command,
            &[],
        )
        .unwrap_or_else(|error| panic!("enqueue due command: {error}"));
    }
    crate::fault_command::test_support::stage_dispatch_results(&[first, second], 0x66);
    let capture_request = fingerprint_slot.request_capture_v1();
    let control_request = slot
        .request_control_boundary(transports.command_ring.write_index(), Some(capture_request))
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));
    TEST_REQUEST_VMSTOP_CALLS.set(0);

    state
        .on_control_boundary(7)
        .unwrap_or_else(|error| panic!("backpressured dispatch should remain live: {error}"));
    assert_eq!(slot.snapshot().control_boundary_ack, control_request);
    assert_eq!(fingerprint_slot.snapshot(), None);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
    assert!(crate::fault_command::test_support::dispatch_result_is_pending());

    let first_result = dequeue_fault_result(
        &transports.result_ring,
        &transports.result_slots,
        &transports.result_arena_header,
        &transports.result_arena,
        RESULT_ARENA_OFFSET,
    )
    .unwrap_or_else(|error| panic!("drain first result: {error}"));
    assert!(first_result.is_some());
    state
        .on_control_boundary(7)
        .unwrap_or_else(|error| panic!("result publication retry should complete: {error}"));

    let _sample = wait_for_fingerprint_sample(&fingerprint_slot, capture_request);
    assert!(!crate::fault_command::test_support::dispatch_result_is_pending());
    assert_eq!(
        slot.snapshot().control_boundary_ack,
        control_request.wrapping_add(1)
    );
    let second_result = dequeue_fault_result(
        &transports.result_ring,
        &transports.result_slots,
        &transports.result_arena_header,
        &transports.result_arena,
        RESULT_ARENA_OFFSET,
    )
    .unwrap_or_else(|error| panic!("drain retried result: {error}"));
    assert!(matches!(
        second_result,
        Some(DequeuedFaultResult::Valid { header, .. }) if header.command_sequence == 2
    ));
}

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
    let state = test_live_state_with_fault_commands(80, 1, 0, 0, &slot, Box::new(bridge))
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    let request = slot
        .request_control_boundary(0, None)
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
