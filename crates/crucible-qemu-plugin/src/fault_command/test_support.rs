//! Test-only QEMU-side fixtures for the fault-command transport.

use std::os::raw::c_int;

use super::{FaultResultStatus, QemuFaultCommand, QemuFaultEvent, QemuFaultResult};

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
