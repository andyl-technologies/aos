//! Scalar GPL-side callback ABI for the independent native control edition.

use std::ffi::{c_int, c_void};

/// Pins the exact independently negotiated native callback edition.
pub(crate) const NATIVE_NODE_CONTROL_VERSION: u32 = 1;

/// Copies an original native command into QEMU-owned callback storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct NativeNodeCommand {
    pub version: u32,
    pub size: u32,
    pub kind: u32,
    pub policy: u32,
    pub sequence: u64,
    pub start_ps: u64,
    pub start_microstep: u64,
    pub start_phase: u64,
    pub limit_ps: u64,
    pub limit_microstep: u64,
    pub limit_phase: u64,
    pub binding_hash: [u8; 32],
    pub owner_incarnation_hash: [u8; 32],
    pub grant_hash: [u8; 32],
}

/// Retains native stop facts without representing complete queue authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct NativeNodeReceipt {
    pub version: u32,
    pub size: u32,
    pub reason: u32,
    pub pending_classes: u32,
    pub command_sequence: u64,
    pub current_ps: u64,
    pub raw_icount: u64,
    pub reached_microstep: u64,
    pub reached_phase: u64,
    pub next_native_deadline_ps: u64,
    pub next_service_deadline_ps: u64,
    pub pending_service_credit_ps: u64,
    pub grant_hash: [u8; 32],
}

pub(crate) type GetCommand = extern "C" fn(*mut NativeNodeCommand, *mut c_void) -> bool;
pub(crate) type PublishStop = extern "C" fn(*const NativeNodeReceipt, *mut c_void);
pub(crate) type RegisterNodeControl =
    extern "C" fn(u32, Option<GetCommand>, Option<PublishStop>, *mut c_void) -> c_int;

/// Resolves the native extension without silently falling back after opt-in.
#[cfg(unix)]
pub(crate) fn resolve_register_node_control() -> Option<RegisterNodeControl> {
    // SAFETY: The name is a static NUL-terminated string. The independently
    // versioned patched export declares exactly RegisterNodeControl above.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_register_crucible_node_control".as_ptr(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: The registered API name and negotiated version pin this ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, RegisterNodeControl>(symbol) })
    }
}

#[cfg(not(unix))]
pub(crate) fn resolve_register_node_control() -> Option<RegisterNodeControl> {
    None
}

const _: () = {
    assert!(std::mem::size_of::<NativeNodeCommand>() == 168);
    assert!(std::mem::size_of::<NativeNodeReceipt>() == 112);
    assert!(std::mem::offset_of!(NativeNodeCommand, sequence) == 16);
    assert!(std::mem::offset_of!(NativeNodeCommand, binding_hash) == 72);
    assert!(std::mem::offset_of!(NativeNodeReceipt, command_sequence) == 16);
    assert!(std::mem::offset_of!(NativeNodeReceipt, grant_hash) == 80);
};

/// Wakes the registered strict controller without publishing modeled CPU work.
pub(crate) type NotifyNodeControl = extern "C" fn() -> c_int;

#[cfg(unix)]
pub(crate) fn resolve_notify_node_control() -> Option<NotifyNodeControl> {
    // SAFETY: The name is a static NUL-terminated string for the exactly typed
    // independently versioned native notification export.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_node_control_notify".as_ptr(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: The native export declaration pins this scalar function ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, NotifyNodeControl>(symbol) })
    }
}

/// Copies CPU-only physical observations at the registered RR callback seam.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NativeCpuParkReceipt {
    pub version: u32,
    pub size: u32,
    pub coverage: u32,
    pub cpu_count: u32,
    pub current_ps: u64,
    pub raw_icount: u64,
    pub next_service_deadline_ps: u64,
    pub pending_service_credit_ps: u64,
    pub prepared_scope_hash: [u8; 32],
    pub roster_hash: [u8; 32],
}

pub(crate) type QueryCpuPark = extern "C" fn(*const u8, *mut NativeCpuParkReceipt) -> c_int;

#[cfg(unix)]
pub(crate) fn resolve_query_cpu_park() -> Option<QueryCpuPark> {
    // SAFETY: This static symbol names the independently versioned exact C ABI.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_node_query_cpu_park".as_ptr(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: The named export's header pins this scalar query signature.
        Some(unsafe { std::mem::transmute::<*mut c_void, QueryCpuPark>(symbol) })
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeCpuParkReceipt>() == 112);
    assert!(std::mem::offset_of!(NativeCpuParkReceipt, current_ps) == 16);
    assert!(std::mem::offset_of!(NativeCpuParkReceipt, prepared_scope_hash) == 48);
};

/// Receives the coherent native timer summary only at the RR callback seam.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NativeTimerInventory {
    pub version: u32,
    pub size: u32,
    pub list_count: u32,
    pub timer_count: u32,
    pub current_ps: u64,
    pub mutation_generation: u64,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NativeTimerList {
    pub list_id: u64,
    pub timer_count: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NativeTimerArm {
    pub timer_id: u64,
    pub list_id: u64,
    pub arm_generation: u64,
    pub expiry_ps: u64,
    pub fifo_ordinal: u64,
    pub attributes: u32,
    pub scale: u32,
}

pub(crate) type QueryTimers = extern "C" fn(
    *mut NativeTimerInventory,
    *mut NativeTimerList,
    u32,
    *mut NativeTimerArm,
    u32,
) -> c_int;

#[cfg(unix)]
pub(crate) fn resolve_query_timers() -> Option<QueryTimers> {
    // SAFETY: This static export is declared with this exact GPL-side scalar ABI.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_node_query_timer_inventory".as_ptr(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: The versioned native header pins the function signature.
        Some(unsafe { std::mem::transmute::<*mut c_void, QueryTimers>(symbol) })
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeTimerInventory>() == 32);
    assert!(std::mem::size_of::<NativeTimerList>() == 16);
    assert!(std::mem::size_of::<NativeTimerArm>() == 48);
    assert!(std::mem::offset_of!(NativeTimerArm, arm_generation) == 16);
};
