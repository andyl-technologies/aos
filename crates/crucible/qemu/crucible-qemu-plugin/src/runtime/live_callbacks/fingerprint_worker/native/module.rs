//! Exports the matched Source worker constructor, entry and final destructor.
//!
//! Ordinary Arc construction creates the language-owned allocation; Native
//! corroborates its full geometry and keeps its one raw strong owner. Borrowed
//! views never decrement that owner. Only actual joined destruction consumes it.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::fingerprint_native::{WorkerFrame, WorkerLayout};

const CONTROL_OFFSET: usize =
    crate::runtime::prebirth::shared_data_offset::<FingerprintWorkerControl>();
const CONTROL_ALIGNMENT: usize = if align_of::<FingerprintWorkerControl>() > align_of::<usize>() {
    align_of::<FingerprintWorkerControl>()
} else {
    align_of::<usize>()
};
const CONTROL_BYTES: usize =
    (CONTROL_OFFSET + size_of::<FingerprintWorkerControl>() + CONTROL_ALIGNMENT - 1)
        & !(CONTROL_ALIGNMENT - 1);

/// Describes the matched module's actual full Arc geometry and fixed stack.
#[unsafe(no_mangle)]
pub static qemu_plugin_crucible_fingerprint_worker_layout_v1: WorkerLayout = WorkerLayout {
    schema_version: 1,
    struct_size: size_of::<WorkerLayout>() as u32,
    control_bytes: CONTROL_BYTES as u64,
    control_alignment: CONTROL_ALIGNMENT as u64,
    stack_bytes: 2 * 1024 * 1024,
};

/// Allocates the ordinary shared control only inside Source's entered frame.
#[unsafe(no_mangle)]
pub extern "C" fn qemu_plugin_crucible_fingerprint_worker_construct_v1(
    id: u64,
    frame: *mut WorkerFrame,
    input: *mut c_void,
) -> i32 {
    if frame.is_null() || input.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: the matched Source synchronously returns the exact caller input;
    // it retains no pointer to this Rust frame or any borrowed input.
    let input = unsafe { &mut *input.cast::<ConstructorInput>() };
    if id != input.handle.id || input.control_address.is_null() || input.projection.is_null() {
        return -libc::EPERM;
    }
    let api = input.handle.api;
    let status = (api.allocation_begin)(frame);
    if status != 0 {
        input.first_status = status;
        return status;
    }
    let Some(quiescence) = input.quiescence.take() else {
        return -libc::EPROTO;
    };
    // SAFETY: Source saved the actual born projection before invoking construct.
    let worker = unsafe { *input.projection };
    if worker.is_null() {
        return -libc::EPROTO;
    }
    let handle = Handle {
        worker: worker as usize,
        ..input.handle
    };
    let mut body = FingerprintWorkerControl::new();
    body.native = Some(Context {
        handle,
        slot: input.slot,
        quiescence,
        current_material: std::sync::atomic::AtomicUsize::new(0),
    });
    let control = Arc::new(body);
    let owning_alias = Arc::into_raw(control);
    // SAFETY: this output belongs to the already retained Runtime worker slot;
    // save the actual control before any allocation/result/post can refuse.
    unsafe {
        *input.control_address = owning_alias as usize;
    }
    // SAFETY: the pinned toolchain's shared geometry supplies the full base for
    // Source corroboration only. Neither Source nor Rust constructs, mutates or
    // frees a private Arc header; final ownership uses ordinary Arc::from_raw.
    let allocation = unsafe { owning_alias.cast::<u8>().sub(CONTROL_OFFSET) }
        .cast_mut()
        .cast();
    let status = (api.allocation_result)(frame, allocation, owning_alias.cast_mut().cast());
    if status != 0 {
        input.first_status = status;
        return status;
    }
    let status = (api.initialized)(frame);
    if status != 0 {
        input.first_status = status;
    }
    status
}

/// Runs only on the actual native pthread with retained module/control custody.
#[unsafe(no_mangle)]
pub extern "C" fn qemu_plugin_crucible_fingerprint_worker_entry_v1(
    id: u64,
    worker: *mut Worker,
    owner: *mut c_void,
) -> i32 {
    if owner.is_null() || worker.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source retains its one ordinary Arc owner until true pthread join;
    // this callback borrows the body and does not consume that raw strong alias.
    let control = unsafe { &*owner.cast::<FingerprintWorkerControl>() };
    if !control
        .native
        .as_ref()
        .is_some_and(|context| context.handle.id == id && context.handle.pointer() == worker)
    {
        return -libc::EPERM;
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        LiveFingerprintDigestWorker::run_native(control)
    })) {
        Ok(status) => status,
        Err(payload) => {
            let mut state = control.lock();
            if state.failure.is_none() {
                state.failure = Some(FingerprintWorkerCause::Panic);
            }
            state.panic_payload = Some(payload);
            drop(state);
            control.available.notify_all();
            control.capacity.notify_all();
            -libc::EFAULT
        }
    }
}

/// Closes module admission after Native has closed its actual work producer.
#[unsafe(no_mangle)]
pub extern "C" fn qemu_plugin_crucible_fingerprint_worker_module_close_v1(
    id: u64,
    worker: *mut Worker,
    owner: *mut c_void,
) -> i32 {
    if owner.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: native close retains the canonical owning alias and excludes final destruction.
    let control = unsafe { &*owner.cast::<FingerprintWorkerControl>() };
    if !control
        .native
        .as_ref()
        .is_some_and(|context| context.handle.id == id && context.handle.pointer() == worker)
    {
        return -libc::EPERM;
    }
    control.close();
    0
}

/// Consumes the sole ordinary Arc only after physical join and all aliases end.
#[unsafe(no_mangle)]
pub extern "C" fn qemu_plugin_crucible_fingerprint_worker_destroy_v1(
    id: u64,
    frame: *mut WorkerFrame,
    owner: *mut *mut c_void,
) -> i32 {
    if frame.is_null() || owner.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source lends its exact owning field while excluding worker/users.
    let raw = unsafe { *owner }.cast::<FingerprintWorkerControl>();
    if raw.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: this exact pointer was produced by Arc::into_raw and remains its
    // one native owning alias. ManuallyDrop preserves it on every pre-drop refusal.
    let mut control = ManuallyDrop::new(unsafe { Arc::from_raw(raw) });
    let Some(unique) = Arc::get_mut(&mut control) else {
        return -libc::EBUSY;
    };
    let Some(context) = unique.native.as_ref() else {
        return -libc::EPROTO;
    };
    if context.handle.id != id {
        return -libc::EPERM;
    }
    let api = context.handle.api;
    {
        let state = unique.lock();
        if state.pending.is_some()
            || state.terminal_history.as_ref().is_some_and(|job| {
                !job.native_work.is_null()
                    || !job.worker_work.is_null()
                    || !job.captured.native_material().is_null()
            })
            || unique.in_flight().is_some()
        {
            return -libc::EBUSY;
        }
    }
    let capture = match unique.capture_attempt.try_lock() {
        Ok(capture) => capture,
        Err(_) => return -libc::EBUSY,
    };
    if capture.has_material_debt() {
        return -libc::EBUSY;
    }
    drop(capture);
    let begun = (api.destroy_begin)(frame);
    if begun != 0 {
        return begun;
    }
    // SAFETY: physical destruction consumes this exact owning alias once; clear
    // Source's field before drop so an unwinding destructor cannot be replayed.
    unsafe {
        *owner = std::ptr::null_mut();
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(ManuallyDrop::into_inner(control))
    }));
    if let Err(payload) = result {
        std::mem::forget(payload);
        return -libc::EFAULT;
    }
    (api.destroyed)(frame)
}
