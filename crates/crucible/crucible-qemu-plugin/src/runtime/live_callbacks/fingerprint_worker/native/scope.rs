//! Borrows the real worker control only inside Source's synchronous user scope.
//!
//! Source retains the canonical owner before the matched module callback and
//! returns that actual user after the callback. The closure can return owned
//! results or owning failure handles, never a body reference or mutex guard.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::runtime::native_worker::scope as native_scope;

impl Handle {
    /// Enters only an actual Source-owned ordinary or terminal lifetime scope.
    ///
    /// # Errors
    /// Refuses missing native custody, closed admission, callback failure or an
    /// incomplete synchronous result. This method grants no operation authority.
    /// Copy success values cannot hide custody when an independent native post
    /// fails; all successful effects remain in the actual paid control journals.
    pub(in crate::runtime::live_callbacks::fingerprint_worker) fn with_control<F, R>(
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
        let use_control = if terminal {
            self.api.control_retire
        } else {
            self.api.control_use
        };
        let outcome =
            native_scope::with_control(action, retain_module_error, retain_module_panic, |input| {
                use_control(self.id, self.pointer(), input)
            });
        let status = outcome.status;
        let Some(output) = outcome.output else {
            return Err(status_error(if status != 0 {
                status
            } else {
                -libc::EPROTO
            }));
        };
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

fn retain_module_panic(
    control: &Arc<FingerprintWorkerControl>,
    payload: Box<dyn std::any::Any + Send>,
) {
    let mut state = control.lock();
    if state.failure.is_none() {
        state.failure = Some(FingerprintWorkerCause::Panic);
    }
    state.panic_payload = Some(payload);
    drop(state);
    control.available.notify_all();
    control.capacity.notify_all();
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
    // SAFETY: Source supplies this module's unchanged live synchronous input;
    // the validated native control user protects owner through thunk return.
    unsafe { native_scope::dispatch(owner, input) }
}
