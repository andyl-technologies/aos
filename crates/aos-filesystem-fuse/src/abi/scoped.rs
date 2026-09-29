//! Private reply-scoped V3 declarations, without a production caller.
//!
//! A future genuine owner keeps its guard on the callback stack while C
//! publishes the reply and Rust settles it. The check context must be an
//! independent shared guard borrow, not the mutably borrowed callback Context.
//! Neither this ABI nor a pointer/table supplies that missing authority.

use super::{Attributes, DirectoryEntry, FallbackOperationsV2, PreparedSession};
use std::ffi::{c_int, c_void};

#[repr(C)]
pub(super) struct ReplyScopeV3 {
    _private: [u8; 0],
}

pub(super) type ScopeCheckV3 = unsafe extern "C" fn(*const c_void) -> c_int;
pub(super) type PublishV3 =
    unsafe extern "C" fn(*mut ReplyScopeV3, u64, *const c_void, ScopeCheckV3, c_int) -> c_int;

#[repr(C)]
pub(super) struct ScopedOperationsV3 {
    pub abi_major: u16,
    pub abi_minor: u16,
    pub struct_size: u32,
    pub profile: u32,
    pub reserved: u32,
    pub legacy: FallbackOperationsV2,
    pub lookup: unsafe extern "C" fn(
        *mut c_void,
        u64,
        *const u8,
        u64,
        *mut Attributes,
        u64,
        *mut ReplyScopeV3,
        PublishV3,
    ) -> c_int,
    pub getattr: unsafe extern "C" fn(
        *mut c_void,
        u64,
        *mut Attributes,
        u64,
        *mut ReplyScopeV3,
        PublishV3,
    ) -> c_int,
    pub readlink: unsafe extern "C" fn(
        *mut c_void,
        u64,
        *mut u8,
        u64,
        *mut u64,
        u64,
        *mut ReplyScopeV3,
        PublishV3,
    ) -> c_int,
    pub readdir: unsafe extern "C" fn(
        *mut c_void,
        u64,
        u64,
        u64,
        u64,
        *mut DirectoryEntry,
        u64,
        *mut u64,
        *mut u8,
        u64,
        *mut u64,
        u64,
        *mut ReplyScopeV3,
        PublishV3,
    ) -> c_int,
    pub read: unsafe extern "C" fn(
        *mut c_void,
        u64,
        u64,
        i64,
        u32,
        u64,
        *mut u8,
        u64,
        *mut u64,
        *mut ReplyScopeV3,
        PublishV3,
    ) -> c_int,
}

unsafe extern "C" {
    // The unsafe caller must own the genuine prepared session and live
    // cross-owner authority; no safe wrapper or production call is provided.
    pub(super) fn aos_fuse_transport_continue_prepared_v3(
        session: *mut PreparedSession,
        operations: *const ScopedOperationsV3,
        context: *mut c_void,
    ) -> c_int;
}

const _: () = {
    assert!(size_of::<ScopedOperationsV3>() == 192);
    assert!(std::mem::offset_of!(ScopedOperationsV3, legacy) == 16);
    assert!(std::mem::offset_of!(ScopedOperationsV3, lookup) == 152);
};
