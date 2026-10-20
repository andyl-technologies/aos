//! Exports the matched Source worker constructor, entry and final destructor.
//!
//! Ordinary Arc construction creates the language-owned allocation; Native
//! corroborates its full geometry and keeps its one raw strong owner. Borrowed
//! views never decrement that owner. Only actual joined destruction consumes it.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::fingerprint_native::{WorkerFrame, WorkerLayout};
use crate::runtime::native_worker::shared::{self, ControlGeometry};

/// Describes the matched module's actual full Arc geometry and fixed stack.
#[unsafe(no_mangle)]
pub static qemu_plugin_crucible_fingerprint_worker_layout_v1: WorkerLayout = WorkerLayout {
    schema_version: 1,
    struct_size: size_of::<WorkerLayout>() as u32,
    control_bytes: ControlGeometry::<FingerprintWorkerControl>::BYTES as u64,
    control_alignment: ControlGeometry::<FingerprintWorkerControl>::ALIGNMENT as u64,
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
    });
    // SAFETY: allocation_begin admitted this birth, and the output is the
    // actual retained Runtime slot supplied by its synchronous constructor.
    let control = unsafe { shared::publish(body, input.control_address) };
    let status = (api.allocation_result)(frame, control.allocation, control.owner);
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
    // SAFETY: Source lends its exact owning field only after physical join and
    // excludes users. Role-specific debt checks precede the same destroy frame.
    unsafe {
        shared::destroy::<FingerprintWorkerControl, _>(
            owner,
            |unique| {
                let context = unique.native.as_ref().ok_or(-libc::EPROTO)?;
                if context.handle.id != id {
                    return Err(-libc::EPERM);
                }
                let api = context.handle.api;
                if unique.jobs_have_native_debt() {
                    return Err(-libc::EBUSY);
                }
                let capture = unique
                    .capture_attempt
                    .try_lock()
                    .map_err(|_| -libc::EBUSY)?;
                if capture.has_material_debt() {
                    return Err(-libc::EBUSY);
                }
                drop(capture);
                Ok(api)
            },
            |api| (api.destroy_begin)(frame),
            |api| (api.destroyed)(frame),
        )
    }
}
