//! Test-only QEMU-side fixtures for the fault-command transport.

use std::os::raw::c_int;

use std::collections::{BTreeMap, BTreeSet};
use std::ptr::NonNull;

use crucible_shmem::{
    FaultCommandKind, FaultCommandSlotV1, FaultEventOutcomeV1, FaultEventSlotV1,
    FaultPayloadArenaHeader, FaultResultSlotV1, NodeFaultFieldV1, NodeFaultOperationV1,
    NodeFaultPayloadV1, NodeFaultTargetKindV1, RingHeader, node_fault_field,
};

use super::{
    FaultCommandBridge, FaultResultStatus, QemuFaultCommand, QemuFaultCommandApis, QemuFaultEvent,
    QemuFaultResult, StableFaultCommandTransport, StableFaultEventTransport,
    StableFaultResultTransport, encode_test_node_event_envelope,
};

thread_local! {
    pub(super) static TEST_EVENT_PENDING: std::cell::RefCell<Option<(QemuFaultEvent, Vec<u8>)>> =
        const { std::cell::RefCell::new(None) };
}

pub(super) extern "C" fn test_event_peek(
    event: *mut QemuFaultEvent,
    payload_length: *mut usize,
) -> c_int {
    if event.is_null() || payload_length.is_null() {
        return -libc::EINVAL;
    }
    TEST_EVENT_PENDING.with(|pending| {
        let pending = pending.borrow();
        let Some((pending_event, pending_payload)) = pending.as_ref() else {
            return 0;
        };
        // SAFETY: the bridge supplies complete writable output objects for
        // this synchronous, non-consuming ABI call.
        unsafe {
            *event = *pending_event;
            *payload_length = pending_payload.len();
        }
        1
    })
}

pub(super) extern "C" fn test_event_poll(
    event: *mut QemuFaultEvent,
    payload: *mut u8,
    payload_capacity: usize,
    payload_length: *mut usize,
) -> c_int {
    if event.is_null() || payload_length.is_null() {
        return -libc::EINVAL;
    }
    TEST_EVENT_PENDING.with(|pending| {
        let mut pending = pending.borrow_mut();
        let Some((pending_event, pending_payload)) = pending.as_ref() else {
            return 0;
        };
        if pending_payload.len() > payload_capacity
            || (!pending_payload.is_empty() && payload.is_null())
        {
            return -libc::ENOSPC;
        }
        // SAFETY: the bridge supplies a complete writable event and an output
        // buffer of at least `payload_capacity` bytes for this synchronous ABI
        // call. The capacity check above proves the copy is in bounds.
        unsafe {
            *event = *pending_event;
            std::ptr::copy_nonoverlapping(pending_payload.as_ptr(), payload, pending_payload.len());
            *payload_length = pending_payload.len();
        }
        let _consumed = pending.take();
        1
    })
}

pub(super) fn test_result_for_command(command: QemuFaultCommand) -> QemuFaultResult {
    QemuFaultResult {
        command_kind: command.command_kind,
        status: FaultResultStatus::Applied as u16,
        phase: command.phase,
        reserved: 0,
        semantic_version: command.semantic_version,
        capability_version: 1,
        command_sequence: command.command_sequence,
        observed_icount: command.target_icount,
        applied_icount: command.target_icount,
        before_hash: [0; 32],
        after_hash: [0; 32],
        evidence_hash: [0; 32],
    }
}

/// Builds an initialized bridge over caller-owned test transports.
// crucible-lint: allow rust-allow -- the fixture binds all three public fault transports explicitly.
#[allow(clippy::too_many_arguments)]
pub(crate) fn initialized_bridge(
    target_node_hash: [u8; 32],
    command_ring: &RingHeader,
    command_slots: &mut [FaultCommandSlotV1],
    command_arena_header: &FaultPayloadArenaHeader,
    command_arena: &mut [u8],
    command_arena_offset: u64,
    result_ring: &RingHeader,
    result_slots: &mut [FaultResultSlotV1],
    result_arena_header: &FaultPayloadArenaHeader,
    result_arena: &mut [u8],
    result_arena_offset: u64,
    event_ring: &RingHeader,
    event_slots: &mut [FaultEventSlotV1],
    event_arena_header: &FaultPayloadArenaHeader,
    event_arena: &mut [u8],
    event_arena_offset: u64,
) -> FaultCommandBridge {
    FaultCommandBridge {
        apis: QemuFaultCommandApis::test_stub(),
        target_node_hash,
        commands: StableFaultCommandTransport {
            ring: NonNull::from(command_ring),
            slots: NonNull::new(command_slots.as_mut_ptr())
                .unwrap_or_else(|| panic!("test command slots must be non-empty")),
            slot_count: command_slots.len(),
            arena_header: NonNull::from(command_arena_header),
            arena: NonNull::new(command_arena.as_mut_ptr())
                .unwrap_or_else(|| panic!("test command arena must be non-empty")),
            arena_len: command_arena.len(),
            arena_region_offset: command_arena_offset,
        },
        results: StableFaultResultTransport {
            ring: NonNull::from(result_ring),
            slots: NonNull::new(result_slots.as_mut_ptr())
                .unwrap_or_else(|| panic!("test result slots must be non-empty")),
            slot_count: result_slots.len(),
            arena_header: NonNull::from(result_arena_header),
            arena: NonNull::new(result_arena.as_mut_ptr())
                .unwrap_or_else(|| panic!("test result arena must be non-empty")),
            arena_len: result_arena.len(),
            arena_region_offset: result_arena_offset,
        },
        events: StableFaultEventTransport {
            ring: NonNull::from(event_ring),
            slots: NonNull::new(event_slots.as_mut_ptr())
                .unwrap_or_else(|| panic!("test event slots must be non-empty")),
            slot_count: event_slots.len(),
            arena_header: NonNull::from(event_arena_header),
            arena: NonNull::new(event_arena.as_mut_ptr())
                .unwrap_or_else(|| panic!("test event arena must be non-empty")),
            arena_len: event_arena.len(),
            arena_region_offset: event_arena_offset,
        },
        last_sequence: 0,
        capability_payload: Vec::new(),
        capability_queries: BTreeSet::new(),
        register_manifest_payload: None,
        interrupt_manifest_payload: None,
        hardware_error_manifest_payload: None,
        clock_manifest_payload: None,
        accelerator_manifest_payload: None,
        system_manifest_payload: Vec::new(),
        register_evidence_identity: None,
        instruction_evidence_identity: None,
        register_commands: BTreeMap::new(),
        active_register_bindings: BTreeMap::new(),
        instruction_commands: BTreeMap::new(),
        active_instruction_bindings: BTreeMap::new(),
        exception_commands: BTreeMap::new(),
        memory_ecc_commands: BTreeMap::new(),
        clock_commands: BTreeMap::new(),
        active_clock_bindings: BTreeMap::new(),
        accelerator_commands: BTreeMap::new(),
        active_accelerator_bindings: BTreeMap::new(),
        prepared_commands: BTreeSet::new(),
        prepare_only_commands: BTreeSet::new(),
        pending_command: None,
        initialized: true,
    }
}

/// Stages one authenticated QEMU occurrence event for the test ABI.
pub(crate) fn stage_node_event(target_node_hash: [u8; 32]) -> (u64, Vec<u8>) {
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
    let event = QemuFaultEvent {
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
    let envelope = encode_test_node_event_envelope(&request, &evidence, &event, target_node_hash);
    TEST_EVENT_PENDING.with(|pending| {
        *pending.borrow_mut() = Some((event, envelope));
    });
    (event.event_sequence, evidence)
}

/// Reports whether the test QEMU ABI still owns its staged event.
pub(crate) fn node_event_is_pending() -> bool {
    TEST_EVENT_PENDING.with(|pending| pending.borrow().is_some())
}
