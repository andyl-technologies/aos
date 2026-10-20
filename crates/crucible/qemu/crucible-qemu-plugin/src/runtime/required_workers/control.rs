//! Runs only the actual entered role and returns its synchronous control users.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::runtime::native_worker::scope;

impl Handle {
    pub(super) fn pointer(self) -> *mut abi::Worker {
        self.worker as *mut abi::Worker
    }

    /// Enters the actual Source-protected synchronous user for this same role.
    ///
    /// # Errors
    /// Preserves owning module failure and the independent Native return; no
    /// body reference or mutex guard can escape this lifetime scope.
    pub(super) fn with_control<R: Copy + 'static>(
        self,
        terminal: bool,
        action: impl for<'a> FnOnce(&'a Arc<Control>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let enter = if terminal {
            self.api.control_retire
        } else {
            self.api.control_use
        };
        let outcome = scope::with_control(action, retain_error, retain_panic, |input| {
            enter(self.id, self.pointer(), input)
        });
        match (outcome.output, outcome.status) {
            (Some(Ok(output)), 0) => Ok(output),
            (Some(Err(error)), 0) => Err(error),
            (Some(Err(Error::Module { source })), status) => {
                source.control.refuse(Cause::Native {
                    cut: NativeCut::ScopeReturn,
                    status,
                });
                Err(Error::Scope { source, status })
            }
            (Some(Err(Error::Scope { source, status })), independent) => {
                source.control.refuse(Cause::Native {
                    cut: NativeCut::ScopeReturn,
                    status: independent,
                });
                Err(Error::Scope { source, status })
            }
            (_, status) => Err(Error::Native {
                operation: "control scope",
                status: if status == 0 { -libc::EPROTO } else { status },
            }),
        }
    }
}

fn retain_error(control: &Arc<Control>, error: Error) -> Error {
    match error {
        error @ (Error::Module { .. } | Error::Scope { .. }) => error,
        Error::ModuleHealth => failed(control),
        Error::Native { status, .. } => {
            control.refuse(Cause::Native {
                cut: NativeCut::ScopeReturn,
                status,
            });
            failed(control)
        }
        Error::Original { source } => {
            control.refuse(Cause::Interruption(source));
            failed(control)
        }
    }
}

pub(super) fn retain_panic(control: &Arc<Control>, payload: Box<dyn Any + Send>) {
    control.refuse(Cause::Panic);
    control.lock().control_panic = Some(payload);
}

/// Puts the same stream back into its retained control even during unwinding.
struct EnteredStream<'a> {
    owner: &'a RunControl,
    stream: Option<ControlLifecycleStream<SetupControlSocket>>,
}

impl Drop for EnteredStream<'_> {
    fn drop(&mut self) {
        let mut slot = match self.owner.stream.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Entry is once-only and handoff cannot run twice. The slot stays empty
        // until this exact entered owner returns; no alternate reader exists.
        *slot = self.stream.take();
    }
}

pub(super) fn run(control: &Control) -> i32 {
    if control.owner_process != std::process::id() {
        return -libc::EPERM;
    }
    if control.closing.load(Ordering::Acquire) {
        return -libc::ECANCELED;
    }
    let _identity = match control.workers.register_current(control.native.kind.mask()) {
        Ok(identity) => identity,
        Err(error) => {
            control.refuse(Cause::Registration(error));
            return -libc::EIO;
        }
    };
    let idle = control.workers.idle(control.native.kind.mask());
    match &control.body {
        Body::Run(body) => {
            {
                let mut state = control.lock();
                if state.read_attempted {
                    return -libc::EALREADY;
                }
                state.read_attempted = true;
            }
            let stream = match body.stream.lock() {
                Ok(mut stream) => stream.take(),
                Err(_) => {
                    control.refuse(Cause::Ownership("RUN stream lock is poisoned"));
                    return -libc::EOWNERDEAD;
                }
            };
            let Some(stream) = stream else {
                control.refuse(Cause::Ownership("entered RUN has no committed stream"));
                return -libc::EPROTO;
            };
            let mut entered = EnteredStream {
                owner: body,
                stream: Some(stream),
            };
            control.workers.run_control_started();
            let trigger = match entered.stream.as_mut() {
                Some(stream) => read_run_control_trigger_retaining(stream, |error| {
                    // Actual typed failure survives formatting or publication.
                    control.refuse(Cause::Read(error));
                    let state = control.lock();
                    match &state.read {
                        Some(error) => error.to_string(),
                        None => String::from("RUN read failed"),
                    }
                }),
                None => return -libc::EPROTO,
            };
            let pending = idle.received();
            let _operation = pending.enter();
            // A refused publication retains the earlier selected cause. The
            // same single-consumer rule forbids a second shutdown operation.
            let _delivered = control.router.publish(trigger).is_ok();
            0
        }
        Body::Teardown(body) => {
            let ready = (control.native.api.ready)(control.native.pointer());
            // This endpoint has no operation post. Its distinct ECANCELED is
            // authenticated Native closing after valid entry checks, even when
            // module_close has not yet published the separate local flag.
            control.lock().native[NativeCut::Ready as usize] = Some(ready);
            if ready == -libc::ECANCELED {
                return ready;
            }
            if ready != 0 {
                control.refuse(Cause::Native {
                    cut: NativeCut::Ready,
                    status: ready,
                });
                return ready;
            }
            if !control.workers.wait_run_control_started(&control.closing) {
                return -libc::ECANCELED;
            }
            let trigger = match body.consumer.receive() {
                Ok(trigger) => trigger,
                Err(()) if control.closing.load(Ordering::Acquire) => return -libc::ECANCELED,
                Err(()) => {
                    control.refuse(Cause::Ownership(
                        "teardown consumer closed without selecting a cause",
                    ));
                    emit_control_worker_diagnostic(
                        "teardown trigger owner closed before selecting a trigger",
                    );
                    std::process::abort();
                }
            };
            let mut selected = match body.selected.lock() {
                Ok(value) => value,
                Err(poisoned) => poisoned.into_inner(),
            };
            *selected = Some(trigger);
            let pending = idle.received();
            let _operation = pending.enter();
            if let Some(trigger) = selected.as_ref() {
                if let Err(error) =
                    perform_live_teardown(trigger, &body.handle, body.request_shutdown)
                {
                    control.refuse(Cause::Teardown(error));
                    emit_control_worker_diagnostic(
                        "control teardown failed; actual typed failure retained",
                    );
                    std::process::abort();
                }
                body.completed.store(true, Ordering::Release);
            }
            0
        }
    }
}

pub(super) fn close(control: &Control) -> i32 {
    if control.owner_process != std::process::id() {
        return -libc::EPERM;
    }
    if control.closing.swap(true, Ordering::AcqRel) {
        return -libc::EALREADY;
    }
    control.workers.wake_startup_close();
    match &control.body {
        Body::Run(_) => {
            // No stream before handoff means Native can cancel its parked entry
            // without touching the installer's still-owned setup endpoint.
            let committed = control.lock().handoff_committed_status.is_some();
            if !committed {
                return 0;
            }
            let receipt = control.interrupt.request();
            let interrupted = receipt.interrupted();
            control.lock().interruption = Some(receipt);
            match interrupted {
                Ok(true) => {
                    let status = receipt.initiating_status();
                    if status != 0 {
                        control.refuse(Cause::Interruption(
                            crate::StartupSourceError::NativeStatus { status },
                        ));
                    }
                    status
                }
                Ok(false) => -libc::EBUSY,
                Err(error) => {
                    control.refuse(Cause::Interruption(error));
                    -libc::EIO
                }
            }
        }
        Body::Teardown(_) => {
            control.router.close();
            0
        }
    }
}
