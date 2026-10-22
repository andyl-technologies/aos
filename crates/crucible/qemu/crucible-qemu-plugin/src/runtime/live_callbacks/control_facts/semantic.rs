//! First-binds semantic sample callbacks to the actual retained module child.
//!
//! The module's own baseline and pending sample branch choose the class and
//! complete-operation unit. Source separately validates its nominal publisher
//! subscription and entered Main. Lifetime-only payload loans grant no semantics.
// SPDX-License-Identifier: GPL-2.0-only

use super::{
    FingerprintAction, FingerprintActionEvidence, Payload, PayloadBorrow, SemanticPayloadBorrow,
};
use super::super::LiveVcpuTimeCallbackState;
use std::ffi::c_void;

fn with_state<T>(
    userdata: *mut c_void,
    run: impl FnOnce(&LiveVcpuTimeCallbackState) -> Result<T, i32>,
) -> Result<T, i32> {
    let state = std::ptr::NonNull::new(userdata.cast::<LiveVcpuTimeCallbackState>())
        .ok_or(-libc::EINVAL)?;
    // SAFETY: the actual first-bound member retains its genuine pinned complete
    // child through every semantic call, worker use and final physical return.
    run(unsafe { state.as_ref() })
}

/// Enters only the module's actual independently established sample branch.
pub(in crate::runtime) extern "C" fn fingerprint_action_enter(
    payload_holder: *mut *mut Payload,
    payload_serial: u64,
    borrow_holder: *mut *mut PayloadBorrow,
    borrow_serial: u64,
    action_holder: *mut *mut FingerprintAction,
    action_serial: *mut u64,
    known_absent: *mut u32,
    evidence: *mut FingerprintActionEvidence,
    userdata: *mut c_void,
) -> i32 {
    if action_holder.is_null()
        || action_serial.is_null()
        || known_absent.is_null()
        || evidence.is_null()
    {
        return -libc::EINVAL;
    }
    // SAFETY: genuine Source supplies aligned, disjoint, stable output fields.
    // Occupied outputs may already carry custody and remain unknown on refusal.
    unsafe {
        known_absent.write(0);
        if !action_holder.read().is_null() || action_serial.read() != 0 {
            return -libc::EINVAL;
        }
        known_absent.write(1);
    }
    let result = with_state(userdata, |state| {
        let fingerprint = state.fingerprint.as_ref().ok_or(-libc::EOPNOTSUPP)?;
        let worker = fingerprint.worker.semantic_receipt_snapshot()?;
        if worker.closed {
            return Err(-libc::ESHUTDOWN);
        }
        if !worker.quiet {
            return Err(-libc::EBUSY);
        }
        let class = crate::ram_fingerprint::pending_sample_class().map_err(|_| -libc::EBUSY)?;
        // SAFETY: genuine Source retains the same pinned child and all exact
        // fields; class/worker floor come from this module's actual owners.
        unsafe {
            state.slot.request_reader.enter_fingerprint_action(
                SemanticPayloadBorrow {
                    payload_holder,
                    payload_serial,
                    borrow_holder,
                    borrow_serial,
                },
                action_holder,
                action_serial,
                known_absent,
                (class, worker.sequence),
            )
        }
    });
    match result {
        Ok(observed) => {
            // SAFETY: the independent evidence output remains live and writable.
            unsafe { evidence.write(observed) };
            0
        }
        Err(status) => status,
    }
}

/// Observes this same semantic owner without entering work or renewing clocks.
pub(in crate::runtime) extern "C" fn fingerprint_action_current(
    payload_holder: *mut *mut Payload,
    payload_serial: u64,
    borrow_holder: *mut *mut PayloadBorrow,
    borrow_serial: u64,
    action_holder: *mut *mut FingerprintAction,
    action_serial: u64,
    evidence: *mut FingerprintActionEvidence,
    userdata: *mut c_void,
) -> i32 {
    if evidence.is_null() {
        return -libc::EINVAL;
    }
    let result = with_state(userdata, |state| {
        let fingerprint = state.fingerprint.as_ref().ok_or(-libc::EOPNOTSUPP)?;
        let worker = fingerprint.worker.semantic_receipt_snapshot()?;
        // SAFETY: the actual member retains the exact original fields/child.
        unsafe {
            state.slot.request_reader.current_fingerprint_action(
                SemanticPayloadBorrow {
                    payload_holder,
                    payload_serial,
                    borrow_holder,
                    borrow_serial,
                },
                action_holder,
                action_serial,
                worker,
            )
        }
    });
    match result {
        Ok(observed) => {
            // SAFETY: genuine Source retains this disjoint writable output.
            unsafe { evidence.write(observed) };
            0
        }
        Err(status) => status,
    }
}

/// Reports real callback history separately from asynchronous sample completion.
pub(in crate::runtime) extern "C" fn fingerprint_action_post(
    payload_holder: *mut *mut Payload,
    payload_serial: u64,
    borrow_holder: *mut *mut PayloadBorrow,
    borrow_serial: u64,
    action_holder: *mut *mut FingerprintAction,
    action_serial: u64,
    first_status: *mut i32,
    post_status: *mut i32,
    evidence: *mut FingerprintActionEvidence,
    userdata: *mut c_void,
) -> i32 {
    if first_status.is_null() || post_status.is_null() || evidence.is_null() {
        return -libc::EINVAL;
    }
    let result = with_state(userdata, |state| {
        // SAFETY: Source retains the same genuine child and original fields.
        unsafe {
            state.slot.request_reader.post_fingerprint_action(
                SemanticPayloadBorrow {
                    payload_holder,
                    payload_serial,
                    borrow_holder,
                    borrow_serial,
                },
                action_holder,
                action_serial,
            )
        }
    });
    match result {
        Ok((observed, first, post)) => {
            // SAFETY: Source supplies three disjoint aligned writable outputs.
            unsafe {
                evidence.write(observed);
                first_status.write(first);
                post_status.write(post);
            }
            0
        }
        Err(status) => status,
    }
}

/// Returns the actual branch only after genuine worker/material closure.
pub(in crate::runtime) extern "C" fn fingerprint_action_return(
    payload_holder: *mut *mut Payload,
    payload_serial: u64,
    borrow_holder: *mut *mut PayloadBorrow,
    borrow_serial: u64,
    action_holder: *mut *mut FingerprintAction,
    action_serial: *mut u64,
    evidence: *mut FingerprintActionEvidence,
    locally_returned: *mut u32,
    userdata: *mut c_void,
) -> i32 {
    if locally_returned.is_null() || evidence.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source retains this actual aligned independent output cell.
    unsafe { locally_returned.write(0) };
    let result = with_state(userdata, |state| {
        let fingerprint = state.fingerprint.as_ref().ok_or(-libc::EOPNOTSUPP)?;
        #[cfg(not(test))]
        let first = fingerprint
            .worker
            .drain_semantic_completed()
            .err()
            .map(|_| -libc::EIO);
        #[cfg(test)]
        let first: Option<i32> = None;
        let worker = fingerprint.worker.semantic_receipt_snapshot()?;
        // SAFETY: actual Source keeps the exact original fields and child live
        // across the genuine cleanup entry and independent physical output.
        unsafe {
            state.slot.request_reader.return_fingerprint_action(
                SemanticPayloadBorrow {
                    payload_holder,
                    payload_serial,
                    borrow_holder,
                    borrow_serial,
                },
                action_holder,
                action_serial,
                evidence,
                locally_returned,
                worker,
            )
        }?;
        // Physical consumption has already been saved before reporting a known
        // earlier worker return failure; there is no fallible post after it.
        first.map_or(Ok(()), Err)
    });
    result.map_or_else(|status| status, |()| 0)
}
