//! Exercises destructive negative returns without claiming native authority.

use super::*;
// SPDX-License-Identifier: GPL-2.0-only
use std::cell::Cell;

thread_local! {
    static SUBMITS: Cell<u32> = const { Cell::new(0) };
    static DISPATCHES: Cell<u32> = const { Cell::new(0) };
    static POLLS: Cell<u32> = const { Cell::new(0) };
    static RESULT_STATUS: Cell<i32> = const { Cell::new(-libc::ECANCELED) };
    static RESULT_KIND: Cell<u16> = const { Cell::new(FaultCommandKind::QueryCapabilities as u16) };
}

fn must<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("component fixture: {error}"))
}

fn with_bridge(test: impl FnOnce(&mut FaultCommandBridge, &RingHeader, &RingHeader)) {
    test_support::with_initialized_bridge(|bridge, commands, results| {
        bridge.apis.peek = empty_result;
        bridge.apis.event_peek = empty_event;
        SUBMITS.with(|count| count.set(0));
        DISPATCHES.with(|count| count.set(0));
        POLLS.with(|count| count.set(0));
        test(bridge, commands, results);
    });
}

extern "C" fn empty_result(_: *mut QemuFaultResult, _: *mut usize) -> i32 {
    0
}

extern "C" fn empty_event(_: *mut QemuFaultEvent, _: *mut usize) -> i32 {
    0
}

extern "C" fn submit_after_effect(_: *const QemuFaultCommand, _: *const u8, _: usize) -> i32 {
    SUBMITS.with(|count| count.set(count.get() + 1));
    -libc::ETIMEDOUT
}

extern "C" fn dispatch_after_effect(_: u64) -> i32 {
    DISPATCHES.with(|count| count.set(count.get() + 1));
    -libc::ECANCELED
}

extern "C" fn dispatch_success(_: u64) -> i32 {
    DISPATCHES.with(|count| count.set(count.get() + 1));
    0
}

fn result_record() -> QemuFaultResult {
    QemuFaultResult {
        command_kind: RESULT_KIND.with(Cell::get),
        status: FaultResultStatus::Applied as u16,
        command_sequence: 9,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        capability_version: 1,
        phase: FaultBoundaryPhase::NodeBoundary as u16,
        ..QemuFaultResult::default()
    }
}

extern "C" fn result_peek(out: *mut QemuFaultResult, length: *mut usize) -> i32 {
    // SAFETY: the actual bridge passes unique complete output objects.
    unsafe {
        out.write(result_record());
        length.write(4);
    }
    1
}

extern "C" fn result_poll(
    out: *mut QemuFaultResult,
    bytes: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    assert!(capacity >= 4);
    POLLS.with(|count| count.set(count.get() + 1));
    // SAFETY: the checked bridge capacity contains all four output bytes.
    unsafe {
        out.write(result_record());
        std::ptr::copy_nonoverlapping([41, 42, 43, 44].as_ptr(), bytes, 4);
        length.write(4);
    }
    RESULT_STATUS.with(Cell::get)
}

fn event_record() -> QemuFaultEvent {
    QemuFaultEvent {
        command_kind: FaultCommandKind::CpuService as u16,
        event_sequence: 55,
        evidence_length: 1,
        ..QemuFaultEvent::default()
    }
}

extern "C" fn event_peek(out: *mut QemuFaultEvent, length: *mut usize) -> i32 {
    // SAFETY: the actual bridge passes unique complete output objects.
    unsafe {
        out.write(event_record());
        length.write(3);
    }
    1
}

extern "C" fn event_poll(
    out: *mut QemuFaultEvent,
    bytes: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    assert!(capacity >= 3);
    POLLS.with(|count| count.set(count.get() + 1));
    // SAFETY: the checked bridge capacity contains these actual consumed bytes.
    unsafe {
        out.write(event_record());
        std::ptr::copy_nonoverlapping([9, 8, 7].as_ptr(), bytes, 3);
        length.write(3);
    }
    1
}

#[test]
fn submit_negative_keeps_consumed_payload_correlations_and_prohibits_replay() {
    with_bridge(|bridge, commands, _| {
        bridge.apis.submit = submit_after_effect;
        let header = FaultCommandHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::QueryCapabilities,
            command_flags: FAULT_COMMAND_FLAG_NONE,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: 1,
            target_node_hash: [7; 32],
            target_icount: 0,
            authorization_ceiling_icount: 0,
            phase: FaultBoundaryPhase::NodeBoundary,
            binding_hash: [0; 32],
            opportunity_hash: [0; 32],
            expected_precondition_hash: [0; 32],
            payload_hash: [0; 32],
            payload_offset: 0,
            payload_length: 0,
        };
        let payload = [17, 19];
        // SAFETY: this fixture retains unique live command transport backing.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                bridge.commands.ring.as_ref(),
                std::slice::from_raw_parts_mut(
                    bridge.commands.slots.as_ptr(),
                    bridge.commands.slot_count,
                ),
                bridge.commands.arena_header.as_ref(),
                std::slice::from_raw_parts_mut(
                    bridge.commands.arena.as_ptr(),
                    bridge.commands.arena_len,
                ),
            )
        };
        must(enqueue_fault_command(
            ring,
            slots,
            arena_header,
            arena,
            bridge.commands.arena_region_offset,
            header,
            &payload,
        ));

        assert!(
            matches!(bridge.pump(0, 0), Err(FaultCommandBridgeError::QemuSubmit { status }) if status == -libc::ETIMEDOUT)
        );
        assert_eq!(commands.read_index(), 1);
        let Some(DequeuedFaultCommand::Valid {
            payload: retained, ..
        }) = &bridge.pending_command
        else {
            panic!("consumed payload lost")
        };
        assert_eq!(retained, &payload);
        assert!(bridge.capability_queries.contains(&1));
        assert_eq!(
            bridge
                .custody
                .submit
                .as_ref()
                .and_then(|receipt| receipt.attempt.returned_status),
            Some(-libc::ETIMEDOUT)
        );
        assert_eq!(
            bridge
                .custody
                .submit
                .as_ref()
                .map(|receipt| receipt.command.command_sequence),
            Some(1)
        );
        assert!(!bridge.local_custody_is_empty());
        assert!(matches!(
            bridge.pump(0, 0),
            Err(FaultCommandBridgeError::EffectUnresolved { .. })
        ));
        assert_eq!(SUBMITS.with(Cell::get), 1);
    });
}

#[test]
fn dispatch_negative_is_not_repeated_and_wrapped_zero_is_a_real_key() {
    with_bridge(|bridge, _, _| {
        bridge.apis.dispatch_node_boundary = dispatch_success;
        must(bridge.dispatch_node_boundary(0, 0, 0));
        must(bridge.dispatch_node_boundary(0, 0, 0));
        assert_eq!(DISPATCHES.with(Cell::get), 1);

        bridge.apis.dispatch_node_boundary = dispatch_after_effect;
        assert!(
            matches!(bridge.dispatch_node_boundary(0, 2, 0), Err(FaultCommandBridgeError::NodeBoundaryDispatch { status }) if status == -libc::ECANCELED)
        );
        assert_eq!(
            bridge
                .custody
                .dispatch
                .as_ref()
                .and_then(|receipt| receipt.attempt.returned_status),
            Some(-libc::ECANCELED)
        );
        assert!(bridge.dispatch_node_boundary(0, 2, 0).is_err());
        assert!(bridge.dispatch_node_boundary(1, 4, 1).is_err());
        assert!(bridge.command_frontier_is_settled(0).is_err());
        assert_eq!(DISPATCHES.with(Cell::get), 2);
    });
}

#[test]
fn destructive_result_negative_retains_raw_outputs_without_second_poll() {
    with_bridge(|bridge, _, _| {
        RESULT_STATUS.with(|value| value.set(-libc::ECANCELED));
        RESULT_KIND.with(|value| value.set(FaultCommandKind::QueryCapabilities as u16));
        bridge.apis.peek = result_peek;
        bridge.apis.poll = result_poll;

        assert!(
            matches!(bridge.drain_publications(0), Err(FaultCommandBridgeError::QemuPoll { status }) if status == -libc::ECANCELED)
        );
        let receipt = bridge
            .custody
            .result
            .as_ref()
            .unwrap_or_else(|| panic!("consumed result lost"));
        assert_eq!(receipt.raw.command_sequence, 9);
        assert_eq!(receipt.payload, [41, 42, 43, 44]);
        assert_eq!(receipt.payload_len, 4);
        assert!(receipt.attempt.serial > 0);
        assert!(!receipt.publication_attempted);
        assert!(bridge.drain_publications(0).is_err());
        assert_eq!(POLLS.with(Cell::get), 1);
    });
}

#[test]
fn consumed_malformed_event_keeps_actual_bytes_and_no_repoll() {
    with_bridge(|bridge, _, _| {
        bridge.apis.event_peek = event_peek;
        bridge.apis.event_poll = event_poll;

        assert!(bridge.drain_publications(0).is_err());
        let receipt = bridge
            .custody
            .event
            .as_ref()
            .unwrap_or_else(|| panic!("consumed event lost"));
        assert_eq!(receipt.raw.event_sequence, 55);
        assert_eq!(receipt.payload, [9, 8, 7]);
        assert_eq!(receipt.attempt.returned_status, Some(1));
        assert!(!receipt.publication_attempted);
        assert!(!bridge.local_custody_is_empty());
        assert!(bridge.drain_publications(0).is_err());
        assert_eq!(POLLS.with(Cell::get), 1);
    });
}

#[test]
fn result_published_before_correlation_failure_retains_receipt_and_never_republishes() {
    with_bridge(|bridge, _, results| {
        RESULT_STATUS.with(|value| value.set(1));
        RESULT_KIND.with(|value| value.set(FaultCommandKind::ClockTransform as u16));
        bridge.apis.peek = result_peek;
        bridge.apis.poll = result_poll;

        assert!(matches!(
            bridge.drain_publications(0),
            Err(FaultCommandBridgeError::ClockEvidence)
        ));
        let receipt = bridge
            .custody
            .result
            .as_ref()
            .unwrap_or_else(|| panic!("published receipt lost"));
        assert!(receipt.publication_attempted);
        assert!(receipt.published);
        assert_eq!(receipt.payload, [41, 42, 43, 44]);
        assert_eq!(results.write_index(), 1);
        assert!(bridge.drain_publications(0).is_err());
        assert_eq!(results.write_index(), 1);
        assert_eq!(POLLS.with(Cell::get), 1);
    });
}
