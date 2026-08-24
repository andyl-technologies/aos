//! Test-only QEMU-side fixtures for the fault-command transport.

use std::os::raw::c_int;

use super::{FaultResultStatus, QemuFaultCommand, QemuFaultEvent, QemuFaultResult};

thread_local! {
    pub(super) static TEST_EVENT_PENDING: std::cell::Cell<Option<(QemuFaultEvent, usize)>> =
        const { std::cell::Cell::new(None) };
}

pub(super) extern "C" fn test_event_peek(
    event: *mut QemuFaultEvent,
    payload_length: *mut usize,
) -> c_int {
    if event.is_null() || payload_length.is_null() {
        return -libc::EINVAL;
    }
    TEST_EVENT_PENDING.with(|pending| {
        let Some((pending_event, pending_payload_length)) = pending.get() else {
            return 0;
        };
        // SAFETY: the bridge supplies complete writable output objects for
        // this synchronous, non-consuming ABI call.
        unsafe {
            *event = pending_event;
            *payload_length = pending_payload_length;
        }
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
