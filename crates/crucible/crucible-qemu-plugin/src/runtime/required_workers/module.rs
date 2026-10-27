//! Supplies the exact matched role constructors and physical lifetime callbacks.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::runtime::native_worker::{
    scope,
    shared::{self, ControlGeometry},
};
use std::mem::size_of;

pub(super) struct ConstructorInput {
    pub(super) native: Handle,
    pub(super) projection: *const *mut abi::Worker,
    pub(super) body: *mut Option<Body>,
    pub(super) workers: Option<Arc<LiveWorkerQuiescence>>,
    pub(super) router: Option<Arc<LiveRuntimeTeardownRouter>>,
    pub(super) interrupt: RuntimeInterrupt,
    pub(super) control_address: *mut usize,
    pub(super) panic_payload: *mut Option<Box<dyn Any + Send>>,
}

pub(super) struct HandoffInput {
    pub(super) stream: *mut Option<ControlLifecycleStream<SetupControlSocket>>,
    pub(super) moved: bool,
    pub(super) committed_status: Option<i32>,
}

const LAYOUT: abi::LayoutDescriptor = abi::LayoutDescriptor {
    schema_version: 1,
    struct_size: size_of::<abi::LayoutDescriptor>() as u32,
    control_bytes: ControlGeometry::<Control>::BYTES as u64,
    control_alignment: ControlGeometry::<Control>::ALIGNMENT as u64,
    stack_bytes: 2 * 1024 * 1024,
};

/// Describes the complete separately paid RUN control and its real stack.
#[unsafe(no_mangle)]
pub static qemu_plugin_crucible_run_worker_layout_v1: abi::LayoutDescriptor = LAYOUT;

/// Describes the complete separately paid teardown control and its real stack.
#[unsafe(no_mangle)]
pub static qemu_plugin_crucible_teardown_worker_layout_v1: abi::LayoutDescriptor = LAYOUT;

/// Validates only the identity of the body already retained by the actual caller.
///
/// # Safety
/// Source must retain the same initialized Arc owner through the returned borrow;
/// no reference may survive that real callback/entry user or physical lifetime.
unsafe fn checked<'a>(
    kind: Kind,
    id: u64,
    worker: *mut abi::Worker,
    owner: *mut c_void,
) -> Result<&'a Control, i32> {
    if worker.is_null() || owner.is_null() {
        return Err(-libc::EINVAL);
    }
    // SAFETY: Source retains this exact initialized Arc body during its callback.
    let control = unsafe { &*owner.cast::<Control>() };
    if control.owner_process != std::process::id()
        || control.native.id != id
        || control.native.worker != worker as usize
        || control.native.kind != kind
    {
        return Err(-libc::EPERM);
    }
    Ok(control)
}

fn construct(kind: Kind, id: u64, frame: *mut abi::Frame, raw: *mut c_void) -> i32 {
    if frame.is_null() || raw.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source returns only this exact live synchronous installer input.
    let input = unsafe { &mut *raw.cast::<ConstructorInput>() };
    if input.native.id != id
        || input.native.kind != kind
        || input.projection.is_null()
        || (kind == Kind::Teardown && input.body.is_null())
        || input.control_address.is_null()
        || input.panic_payload.is_null()
    {
        return -libc::EPERM;
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let api = input.native.api;
        let status = (api.allocation_begin)(frame);
        if status != 0 {
            return status;
        }
        // SAFETY: these pointers name pinned, paid Runtime fields. Source saved
        // the born native projection before entering this synchronous callback.
        let worker = unsafe { *input.projection };
        if worker.is_null() {
            return -libc::EPROTO;
        }
        let Some(workers) = input.workers.take() else {
            return -libc::EPROTO;
        };
        let Some(router) = input.router.take() else {
            return -libc::EPROTO;
        };
        let body = match kind {
            Kind::Run => Body::Run(RunControl {
                stream: Mutex::new(None),
            }),
            Kind::Teardown => {
                // SAFETY: no other callback can take this same retained input.
                let Some(body) = (unsafe { &mut *input.body }).take() else {
                    return -libc::EPROTO;
                };
                if !matches!(body, Body::Teardown(_)) {
                    return -libc::EPROTO;
                }
                body
            }
        };
        let control = Control {
            native: Handle {
                worker: worker as usize,
                ..input.native
            },
            workers,
            router,
            interrupt: input.interrupt,
            owner_process: std::process::id(),
            closing: AtomicBool::new(false),
            state: Mutex::new(State::default()),
            body,
        };
        // SAFETY: allocation entry is genuine and output is the retained field.
        let control = unsafe { shared::publish(control, input.control_address) };
        let status = (api.allocation_result)(frame, control.allocation, control.owner);
        if status != 0 {
            return status;
        }
        (api.initialized)(frame)
    }));
    match result {
        Ok(status) => status,
        Err(payload) => {
            // SAFETY: the same actual Runtime retains this output before birth.
            unsafe { *input.panic_payload = Some(payload) };
            -libc::EFAULT
        }
    }
}

fn entry(kind: Kind, id: u64, worker: *mut abi::Worker, owner: *mut c_void) -> i32 {
    // SAFETY: the real native entry retains its one owning control alias.
    let control = match unsafe { checked(kind, id, worker, owner) } {
        Ok(value) => value,
        Err(status) => return status,
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| control::run(control))) {
        Ok(status) => status,
        Err(payload) => {
            control.refuse(Cause::Panic);
            control.lock().entry_panic = Some(payload);
            // Mandatory workers previously ran inside fail-loud thread entry.
            // Retention alone cannot permit guest execution after this panic.
            emit_control_worker_diagnostic(
                "required native worker panicked; aborting QEMU process",
            );
            std::process::abort();
        }
    }
}

fn close(kind: Kind, id: u64, worker: *mut abi::Worker, owner: *mut c_void) -> i32 {
    // SAFETY: Source excludes destruction throughout this actual close callback.
    let control = match unsafe { checked(kind, id, worker, owner) } {
        Ok(value) => value,
        Err(status) => return status,
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| control::close(control))) {
        Ok(status) => {
            if status != 0 {
                control.refuse(Cause::Native {
                    cut: NativeCut::Close,
                    status,
                });
            }
            status
        }
        Err(payload) => {
            control.refuse(Cause::Panic);
            control.lock().close_panic = Some(payload);
            -libc::EFAULT
        }
    }
}

fn destroy(kind: Kind, id: u64, frame: *mut abi::Frame, owner: *mut *mut c_void) -> i32 {
    if frame.is_null() || owner.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source lends its exact owner only after join and user exclusion.
    unsafe {
        shared::destroy::<Control, _>(
            owner,
            |control| {
                if control.native.id != id
                    || control.native.kind != kind
                    || control.owner_process != std::process::id()
                {
                    return Err(-libc::EPERM);
                }
                let state = match control.state.try_lock() {
                    Ok(state) => state,
                    Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return Err(-libc::EBUSY),
                };
                if !state.destruction_ready() {
                    return Err(-libc::EBUSY);
                }
                drop(state);
                if let Body::Teardown(body) = &control.body {
                    let selected = body.selected.try_lock().map_err(|_| -libc::EBUSY)?;
                    if selected.is_some() && !body.completed.load(Ordering::Acquire) {
                        return Err(-libc::EBUSY);
                    }
                }
                Ok(control.native.api)
            },
            |api| (api.destroy_begin)(frame),
            |api| (api.destroyed)(frame),
        )
    }
}

macro_rules! exports {
    ($kind:expr, $construct:ident, $entry:ident, $close:ident, $control:ident, $destroy:ident) => {
        /// Constructs only the same actual role inside its entered allocation frame.
        #[unsafe(no_mangle)]
        pub extern "C" fn $construct(id: u64, frame: *mut abi::Frame, input: *mut c_void) -> i32 {
            construct($kind, id, frame, input)
        }

        /// Runs only on this Source-created role's actual native thread.
        #[unsafe(no_mangle)]
        pub extern "C" fn $entry(id: u64, worker: *mut abi::Worker, owner: *mut c_void) -> i32 {
            entry($kind, id, worker, owner)
        }

        /// Closes actual admission without claiming the thread or body returned.
        #[unsafe(no_mangle)]
        pub extern "C" fn $close(id: u64, worker: *mut abi::Worker, owner: *mut c_void) -> i32 {
            close($kind, id, worker, owner)
        }

        /// Dispatches one synchronous action while Source protects this owner.
        ///
        /// # Safety
        /// Source must retain the exact control and supply this module's unchanged
        /// live private synchronous header. Neither pointer may escape the call.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $control(
            id: u64,
            worker: *mut abi::Worker,
            owner: *mut c_void,
            input: *mut c_void,
        ) -> i32 {
            if input.is_null() {
                return -libc::EINVAL;
            }
            // SAFETY: the real Source control user protects this matched owner.
            if let Err(status) = unsafe { checked($kind, id, worker, owner) } {
                return status;
            }
            // SAFETY: the validated user spans the same synchronous thunk.
            unsafe { scope::dispatch(owner, input) }
        }

        /// Destroys the exact unique ordinary Arc after physical worker join.
        #[unsafe(no_mangle)]
        pub extern "C" fn $destroy(
            id: u64,
            frame: *mut abi::Frame,
            owner: *mut *mut c_void,
        ) -> i32 {
            destroy($kind, id, frame, owner)
        }
    };
}

exports!(
    Kind::Run,
    qemu_plugin_crucible_run_worker_construct_v1,
    qemu_plugin_crucible_run_worker_entry_v1,
    qemu_plugin_crucible_run_worker_module_close_v1,
    qemu_plugin_crucible_run_worker_module_control_v1,
    qemu_plugin_crucible_run_worker_destroy_v1
);
exports!(
    Kind::Teardown,
    qemu_plugin_crucible_teardown_worker_construct_v1,
    qemu_plugin_crucible_teardown_worker_entry_v1,
    qemu_plugin_crucible_teardown_worker_module_close_v1,
    qemu_plugin_crucible_teardown_worker_module_control_v1,
    qemu_plugin_crucible_teardown_worker_destroy_v1
);

/// Moves only the installer's same retained stream inside Source's handoff frame.
#[unsafe(no_mangle)]
pub extern "C" fn qemu_plugin_crucible_run_worker_module_handoff_v1(
    id: u64,
    frame: *mut abi::Frame,
    owner: *mut c_void,
    raw: *mut c_void,
) -> i32 {
    if frame.is_null() || owner.is_null() || raw.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source pins the genuine RUN owner and exact synchronous input.
    let control = unsafe { &*owner.cast::<Control>() };
    if control.native.kind != Kind::Run
        || control.native.id != id
        || control.owner_process != std::process::id()
    {
        return -libc::EPERM;
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handoff(control, frame, raw)
    })) {
        Ok(status) => status,
        Err(payload) => {
            control.refuse(Cause::Panic);
            control.lock().handoff_panic = Some(payload);
            -libc::EFAULT
        }
    }
}

fn handoff(control: &Control, frame: *mut abi::Frame, raw: *mut c_void) -> i32 {
    // SAFETY: this caller-owned input remains live until the native API returns.
    let input = unsafe { &mut *raw.cast::<HandoffInput>() };
    if input.stream.is_null() {
        return -libc::EINVAL;
    }
    let Body::Run(body) = &control.body else {
        return -libc::EPERM;
    };
    let mut slot = match body.stream.try_lock() {
        Ok(slot) => slot,
        Err(_) => return -libc::EBUSY,
    };
    let mut state = control.lock();
    if state.handoff_attempted || slot.is_some() {
        return -libc::EALREADY;
    }
    state.handoff_attempted = true;
    // SAFETY: Source returns the address of the pinned Runtime's sole input.
    let Some(stream) = (unsafe { &mut *input.stream }).take() else {
        return -libc::ENOKEY;
    };
    *slot = Some(stream);
    input.moved = true;
    drop(slot);
    drop(state);
    // Acknowledge the actual move before interpreting any signed status or post.
    let status = (control.native.api.handoff_committed)(frame);
    input.committed_status = Some(status);
    control.lock().handoff_committed_status = Some(status);
    if status != 0 {
        control.refuse(Cause::Native {
            cut: NativeCut::HandoffCommitted,
            status,
        });
    }
    status
}
