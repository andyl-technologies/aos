//! GPL-local bounded writer-cut ABI, independent of the portable process codec.

use std::ffi::{c_int, c_void};

pub(crate) const WRITER_CUT_VERSION: u32 = 1;
pub(crate) const CPU_MAXIMUM: usize = 1024;
pub(crate) const WORK_MAXIMUM: usize = 4096;
pub(crate) const AIO_MAXIMUM: usize = 64;
pub(crate) const BH_MAXIMUM: usize = 4096;
pub(crate) const HANDLER_MAXIMUM: usize = 4096;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NativeWriterCut {
    pub version: u32,
    pub size: u32,
    pub coverage: u32,
    pub flags: u32,
    pub cpu_count: u32,
    pub work_count: u32,
    pub aio_count: u32,
    pub bh_count: u32,
    pub handler_count: u32,
    pub reserved: u32,
    pub gate_generation: u64,
    pub current_ps: u64,
    pub raw_icount: u64,
    pub aio_generation: u64,
    pub bh_generation: u64,
    pub handler_generation: u64,
    pub admissions_in_flight: u64,
    pub prepared_scope_hash: [u8; 32],
    pub roster_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NativeWriterCpu {
    pub cpu_index: u32,
    pub interrupt_mask: u32,
    pub exception_index: i32,
    pub flags: u32,
    pub work_count: u64,
    pub next_work_sequence: u64,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NativeWriterWork {
    pub cpu_index: u32,
    pub flags: u32,
    pub work_id: u64,
    pub fifo_ordinal: u64,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NativeWriterAio {
    pub context_id: u64,
    pub home_thread_id: i64,
    pub active_polls: u32,
    pub active_dispatches: u32,
    pub pending_bhs: u32,
    pub active_bhs: u32,
    pub queued_coroutines: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NativeWriterBh {
    pub bh_id: u64,
    pub context_id: u64,
    pub active_callbacks: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NativeWriterHandler {
    pub handler_id: u64,
    pub context_id: u64,
    pub fd: i64,
    pub active_callbacks: u32,
    pub flags: u32,
}

pub(crate) type QueryWriters = extern "C" fn(
    *const u8,
    u64,
    *mut NativeWriterCut,
    *mut NativeWriterCpu,
    u32,
    *mut NativeWriterWork,
    u32,
    *mut NativeWriterAio,
    u32,
    *mut NativeWriterBh,
    u32,
    *mut NativeWriterHandler,
    u32,
) -> c_int;

#[cfg(unix)]
pub(crate) fn resolve_query_writers() -> Option<QueryWriters> {
    // SAFETY: The static name identifies the GPL-side versioned writer-cut API.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_node_query_writer_cut".as_ptr(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: The source header pins this exact scalar and caller-buffer ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, QueryWriters>(symbol) })
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeWriterCut>() == 160);
    assert!(std::mem::offset_of!(NativeWriterCut, gate_generation) == 40);
    assert!(std::mem::offset_of!(NativeWriterCut, prepared_scope_hash) == 96);
    assert!(std::mem::size_of::<NativeWriterCpu>() == 32);
    assert!(std::mem::size_of::<NativeWriterWork>() == 24);
    assert!(std::mem::size_of::<NativeWriterAio>() == 40);
    assert!(std::mem::size_of::<NativeWriterBh>() == 24);
    assert!(std::mem::size_of::<NativeWriterHandler>() == 32);
};
