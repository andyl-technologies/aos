//! Adapts first-bound Native callbacks to actual module payload ownership.
//!
//! Source retains the genuine complete child and supplies its stable canonical
//! output field. These callbacks transfer only local payload custody; they grant
//! no Host publisher epoch, entered Original, guest access or acknowledgement.
// SPDX-License-Identifier: GPL-2.0-only

use super::{Payload, PayloadBorrow};
use std::ffi::c_void;

/// Claims the actual request retained by the nominal member's complete child.
///
/// Source binds this function at first member construction, retains that child,
/// and supplies aligned disjoint writable empty outputs whose holder address
/// remains stable until return. Copied facts cannot nominate another payload.
pub(in crate::runtime) extern "C" fn protected_payload_claim(
    holder: *mut *mut Payload,
    serial: *mut u64,
    userdata: *mut c_void,
) -> i32 {
    let Some(state) =
        std::ptr::NonNull::new(userdata.cast::<super::super::LiveVcpuTimeCallbackState>())
    else {
        return -libc::EINVAL;
    };
    // SAFETY: the first-bound actual member retains this pinned complete child
    // and the exact canonical Source field across all payload lifetimes.
    let result = unsafe {
        state
            .as_ref()
            .slot
            .request_reader
            .claim_payload(holder, serial)
    };
    match result {
        Ok(()) => 0,
        Err(status) => status,
    }
}

/// Retires the real payload before consuming its exact canonical Source field.
///
/// Source retains the same first-bound child and closes all native payload uses
/// before this callback. The module's actual journal lock excludes a remaining
/// local borrower. Every negative keeps the real payload and holder retained.
pub(in crate::runtime) extern "C" fn protected_payload_return(
    holder: *mut *mut Payload,
    serial: u64,
    userdata: *mut c_void,
) -> i32 {
    let Some(state) =
        std::ptr::NonNull::new(userdata.cast::<super::super::LiveVcpuTimeCallbackState>())
    else {
        return -libc::EINVAL;
    };
    // SAFETY: Source authenticates the exact field and actual retained child;
    // module ownership independently checks that field and local generation.
    let result = unsafe {
        state
            .as_ref()
            .slot
            .request_reader
            .return_payload(holder, serial)
    };
    match result {
        Ok(()) => 0,
        Err(status) => status,
    }
}

/// Pins the actual payload in its original paid local borrower record.
///
/// The first-bound Source member retains the complete child and every supplied
/// field through physical return. Known absence describes this invocation only;
/// Native independently saves physical outputs before checking its own post.
pub(in crate::runtime) extern "C" fn protected_payload_borrow_acquire(
    payload_holder: *mut *mut Payload,
    payload_serial: u64,
    holder: *mut *mut PayloadBorrow,
    serial: *mut u64,
    known_absent: *mut u32,
    userdata: *mut c_void,
) -> i32 {
    let Some(state) =
        std::ptr::NonNull::new(userdata.cast::<super::super::LiveVcpuTimeCallbackState>())
    else {
        return -libc::EINVAL;
    };
    // SAFETY: the actual first-bound member retains this pinned complete child,
    // canonical payload and disjoint stable output fields through all local uses.
    let result = unsafe {
        state.as_ref().slot.request_reader.acquire_payload_borrow(
            payload_holder,
            payload_serial,
            holder,
            serial,
            known_absent,
        )
    };
    match result {
        Ok(()) => 0,
        Err(status) => status,
    }
}

/// Consumes the actual local record before reporting its physical output facts.
///
/// Native closes all users first and supplies the same first-bound child and
/// exact canonical fields. A copied token or serial cannot consume the record.
pub(in crate::runtime) extern "C" fn protected_payload_borrow_release(
    payload_holder: *mut *mut Payload,
    payload_serial: u64,
    holder: *mut *mut PayloadBorrow,
    serial: u64,
    locally_returned: *mut u32,
    userdata: *mut c_void,
) -> i32 {
    let Some(state) =
        std::ptr::NonNull::new(userdata.cast::<super::super::LiveVcpuTimeCallbackState>())
    else {
        return -libc::EINVAL;
    };
    // SAFETY: Source retains the same child and original fields through this
    // callback and authenticates actual Main custody before closing its users.
    let result = unsafe {
        state.as_ref().slot.request_reader.release_payload_borrow(
            payload_holder,
            payload_serial,
            holder,
            serial,
            locally_returned,
        )
    };
    match result {
        Ok(()) => 0,
        Err(status) => status,
    }
}
