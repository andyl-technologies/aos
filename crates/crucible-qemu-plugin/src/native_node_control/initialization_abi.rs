//! GPL-local construction callbacks and native cut ABI.
//!
//! Every pointer here remains in the QEMU process. Public channel records use
//! separately encoded scalar bytes; these layouts never cross the process or
//! license boundary. Registration pins the original early launch preparation,
//! and callback completion establishes no whole-owner readiness.

use std::ffi::{CStr, c_int, c_void};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeInitializationCommand {
    pub version: u32,
    pub size: u32,
    pub class_mask: u32,
    pub maximum_callbacks: u32,
    pub sequence: u64,
    pub prepared_scope_hash: [u8; 32],
    pub realize_request_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub original_cut_digest: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeInitializationRow {
    pub class_id: u32,
    pub flags: u32,
    pub callback_id: u64,
    pub arm_generation: u64,
    pub context_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeInitializationCut {
    pub version: u32,
    pub size: u32,
    pub row_count: u32,
    pub flags: u32,
    pub hold_generation: u64,
    pub prepared_scope_hash: [u8; 32],
    pub initialization_commitment: [u8; 32],
    pub original_cut_digest: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeInitializationReceipt {
    pub version: u32,
    pub size: u32,
    pub status: u32,
    pub applied_callbacks: u32,
    pub sequence: u64,
    pub hold_generation: u64,
    pub prepared_scope_hash: [u8; 32],
    pub initialization_commitment: [u8; 32],
    pub original_cut_digest: [u8; 32],
    pub realize_request_digest: [u8; 32],
}

pub(crate) type GetInitializationCommand =
    extern "C" fn(*mut NativeInitializationCommand, *mut c_void) -> bool;
pub(crate) type PublishInitializationReceipt =
    extern "C" fn(*const NativeInitializationReceipt, *mut c_void);

pub(crate) type RegisterInitialization = extern "C" fn(
    u32,
    *const u8,
    *const u8,
    *const u8,
    *const u8,
    u32,
    u32,
    Option<GetInitializationCommand>,
    Option<PublishInitializationReceipt>,
    *mut c_void,
) -> c_int;

pub(crate) type QueryInitializationCut = extern "C" fn(
    *const u8,
    *const u8,
    *mut NativeInitializationCut,
    *mut NativeInitializationRow,
    u32,
) -> c_int;

fn resolve_symbol(name: &'static CStr) -> *mut c_void {
    // SAFETY: Static names select exact source exports. The loader pointer stays
    // inside this GPL process and is checked before conversion or invocation.
    unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) }
}

pub(crate) fn resolve_register_initialization() -> Option<RegisterInitialization> {
    let symbol = resolve_symbol(c"qemu_plugin_register_crucible_node_initialization");
    if symbol.is_null() {
        None
    } else {
        // SAFETY: The selected export has exactly the source-declared edition-one
        // registration signature, including the separately pinned original fields.
        Some(unsafe { std::mem::transmute::<*mut c_void, RegisterInitialization>(symbol) })
    }
}

pub(crate) fn resolve_query_initialization_cut() -> Option<QueryInitializationCut> {
    let symbol = resolve_symbol(c"qemu_plugin_crucible_node_query_initialization_cut");
    if symbol.is_null() {
        None
    } else {
        // SAFETY: The exact export accepts the bounded scalar row layout below.
        Some(unsafe { std::mem::transmute::<*mut c_void, QueryInitializationCut>(symbol) })
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeInitializationCommand>() == 152);
    assert!(std::mem::offset_of!(NativeInitializationCommand, sequence) == 16);
    assert!(std::mem::offset_of!(NativeInitializationCommand, prepared_scope_hash) == 24);
    assert!(std::mem::offset_of!(NativeInitializationCommand, original_cut_digest) == 120);
    assert!(std::mem::size_of::<NativeInitializationRow>() == 32);
    assert!(std::mem::offset_of!(NativeInitializationRow, callback_id) == 8);
    assert!(std::mem::size_of::<NativeInitializationCut>() == 120);
    assert!(std::mem::offset_of!(NativeInitializationCut, prepared_scope_hash) == 24);
    assert!(std::mem::size_of::<NativeInitializationReceipt>() == 160);
    assert!(std::mem::offset_of!(NativeInitializationReceipt, prepared_scope_hash) == 32);
    assert!(std::mem::offset_of!(NativeInitializationReceipt, realize_request_digest) == 128);
};
