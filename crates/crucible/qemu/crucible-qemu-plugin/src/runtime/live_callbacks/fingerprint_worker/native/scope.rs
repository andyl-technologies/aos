//! Borrows the real worker control only inside Source's synchronous user scope.
//!
//! Source retains the canonical owner before the matched module callback and
//! returns that actual user after the callback. The closure can return owned
//! results or owning failure handles, never a body reference or mutex guard.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::mem::MaybeUninit;

struct InputHeader {
    /// Invokes the thunk paired with the caller's live synchronous input.
    ///
    /// # Safety
    /// The owner must remain retained by Source, and the payload must point to
    /// the exact live `ScopedInput<F, R>` paired with this monomorphized thunk.
    invoke: unsafe fn(*mut c_void, *mut c_void) -> i32,
    payload: *mut c_void,
}

struct ScopedInput<F, R> {
    action: Option<F>,
    output: MaybeUninit<Result<R, LiveVcpuTimeCallbackError>>,
    completed: bool,
}

impl Handle {
    /// Enters only an actual Source-owned ordinary or terminal lifetime scope.
    ///
    /// # Errors
    /// Refuses missing native custody, closed admission, callback failure or an
    /// incomplete synchronous result. This method grants no operation authority.
    /// Copy success values cannot hide custody when an independent native post
    /// fails; all successful effects remain in the actual paid control journals.
    pub(super) fn with_control<F, R>(
        self,
        terminal: bool,
        action: F,
    ) -> Result<R, LiveVcpuTimeCallbackError>
    where
        F: for<'a> FnOnce(
            &'a Arc<FingerprintWorkerControl>,
        ) -> Result<R, LiveVcpuTimeCallbackError>,
        R: Copy + 'static,
    {
        let mut input = ScopedInput {
            action: Some(action),
            output: MaybeUninit::uninit(),
            completed: false,
        };
        let mut header = InputHeader {
            invoke: invoke::<F, R>,
            payload: std::ptr::from_mut(&mut input).cast(),
        };
        let use_control = if terminal {
            self.api.control_retire
        } else {
            self.api.control_use
        };
        let status = use_control(
            self.id,
            self.pointer(),
            std::ptr::from_mut(&mut header).cast(),
        );
        if !input.completed {
            return Err(status_error(if status != 0 {
                status
            } else {
                -libc::EPROTO
            }));
        }
        // SAFETY: only the matched synchronous thunk sets completed, strictly
        // after writing the complete owned R; no body-derived borrow can escape.
        let output = unsafe { input.output.assume_init() };
        match (output, status) {
            (Ok(output), 0) => Ok(output),
            (Ok(_), status) => Err(status_error(status)),
            (Err(error), 0) => Err(error),
            (Err(LiveVcpuTimeCallbackError::FingerprintWorkerFailed { source }), status) => {
                // This real owning Arc protects the body after the user scope
                // returns, so both histories remain inspectable without a loan.
                source
                    .control
                    .record_native_failure("control scope return", status);
                Err(LiveVcpuTimeCallbackError::FingerprintWorkerControlScope {
                    source,
                    native_status: status,
                })
            }
            (
                Err(error @ LiveVcpuTimeCallbackError::FingerprintWorkerControlScope { .. }),
                status,
            ) => {
                if let LiveVcpuTimeCallbackError::FingerprintWorkerControlScope { source, .. } =
                    &error
                {
                    source
                        .control
                        .lock()
                        .scope_return_failure
                        .get_or_insert(status);
                }
                Err(error)
            }
            (Err(_), _) => Err(status_error(-libc::EPROTO)),
        }
    }
}

/// Runs one caller action while Source retains the canonical control owner.
///
/// # Safety
/// Source must retain its control user through return. `input` must point to the
/// live `ScopedInput<F, R>` paired with this thunk, and `owner` must identify the
/// same initialized control retained by that user.
unsafe fn invoke<F, R>(owner: *mut c_void, input: *mut c_void) -> i32
where
    F: for<'a> FnOnce(&'a Arc<FingerprintWorkerControl>) -> Result<R, LiveVcpuTimeCallbackError>,
    R: Copy + 'static,
{
    // SAFETY: the private header pairs this exact monomorphized thunk with its
    // live caller-owned stack input. Source never retains either pointer.
    let input = unsafe { &mut *input.cast::<ScopedInput<F, R>>() };
    let Some(action) = input.action.take() else {
        return -libc::EALREADY;
    };
    let control =
        // SAFETY: Source's control user spans this callback and prevents the
        // raw Arc owner from being destroyed. ManuallyDrop preserves that owner.
        ManuallyDrop::new(unsafe { Arc::from_raw(owner.cast::<FingerprintWorkerControl>()) });
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(&control))) {
        Ok(output) => {
            let output = output.map_err(|error| retain_module_error(&control, error));
            input.output.write(output);
            input.completed = true;
            0
        }
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

fn retain_module_error(
    control: &Arc<FingerprintWorkerControl>,
    error: LiveVcpuTimeCallbackError,
) -> LiveVcpuTimeCallbackError {
    match error {
        error @ LiveVcpuTimeCallbackError::FingerprintWorkerFailed { .. }
        | error @ LiveVcpuTimeCallbackError::FingerprintWorkerControlScope { .. } => error,
        error => {
            let mut state = control.lock();
            if state.module_action_failure.is_none() {
                state.module_action_failure = Some(error);
            }
            if state.failure.is_none() {
                state.failure = Some(FingerprintWorkerCause::ModuleAction);
            }
            drop(state);
            LiveFingerprintDigestWorker::failed(control)
        }
    }
}

/// Dispatches the matched module action inside the actual native control user.
///
/// # Safety
/// Source must retain the actual canonical owner and its control user through
/// callback return, and pass the same live synchronous input supplied by Rust.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qemu_plugin_crucible_fingerprint_worker_module_control_v1(
    id: u64,
    worker: *mut Worker,
    owner: *mut c_void,
    input: *mut c_void,
) -> i32 {
    if owner.is_null() || input.is_null() || worker.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: the real Source user protects this actual matched control body.
    let control = unsafe { &*owner.cast::<FingerprintWorkerControl>() };
    if !control
        .native
        .as_ref()
        .is_some_and(|context| context.handle.id == id && context.handle.pointer() == worker)
    {
        return -libc::EPERM;
    }
    // SAFETY: only this module constructs the synchronous private header, and
    // Source supplies it unchanged while its caller stack remains live.
    let input = unsafe { &mut *input.cast::<InputHeader>() };
    // SAFETY: this private header retains the matching thunk and live payload;
    // the same Source control user protects owner through the synchronous call.
    unsafe { (input.invoke)(owner, input.payload) }
}
