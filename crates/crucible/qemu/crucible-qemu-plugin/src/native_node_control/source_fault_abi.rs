//! GPL-local observational ABI for an immutable original native source fault.

use std::ffi::{c_int, c_void};

/// Copies scalar diagnostics without callback pointers or containment authority.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeSourceFault {
    pub version: u32,
    pub size: u32,
    pub code: u32,
    pub flags: u32,
    pub fault_id: u64,
    pub command_sequence: u64,
    pub ingress_id: u64,
    pub cpu_index: u32,
    pub ingress_kind: u32,
    pub prepared_scope_hash: [u8; 32],
    pub original_command_digest: [u8; 32],
}

pub(crate) type QuerySourceFault = extern "C" fn(*const u8, *mut NativeSourceFault) -> c_int;

/// Resolves the independently versioned diagnostic query; it requires no BQL.
pub(crate) fn resolve_query_source_fault() -> Option<QuerySourceFault> {
    // SAFETY: This static name pins the exact source-declared scalar ABI. The
    // pointer remains inside the GPL process and is never serialized.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_node_query_source_fault".as_ptr(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: The source export has exactly the declared function signature.
        Some(unsafe { std::mem::transmute::<*mut c_void, QuerySourceFault>(symbol) })
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeSourceFault>() == 112);
    assert!(std::mem::offset_of!(NativeSourceFault, fault_id) == 16);
    assert!(std::mem::offset_of!(NativeSourceFault, prepared_scope_hash) == 48);
    assert!(std::mem::offset_of!(NativeSourceFault, original_command_digest) == 80);
};
