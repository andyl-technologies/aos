//! Adapts first-bound Native callbacks to actual module payload ownership.
//!
//! Source retains the genuine complete child and supplies its stable canonical
//! output field. These callbacks transfer only local payload custody; they grant
//! no Host publisher epoch, entered Original, guest access or acknowledgement.
// SPDX-License-Identifier: GPL-2.0-only

use super::Payload;
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
