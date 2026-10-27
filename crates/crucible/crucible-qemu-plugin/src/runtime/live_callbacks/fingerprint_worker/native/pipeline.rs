//! Keeps active, queued and completed native loans in fixed paid owning slots.
//!
//! Main drains only completed receipts. It captures before capacity waiting;
//! the worker returns bytes and immediately takes the next queued job, while
//! completed jobs retain their independent Main-return and failure histories.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use super::super::pipeline_queue::WORK_CELLS;
use super::super::worker_outcome::{self, CancelledWork, JobOutcome, PrimaryFailure, TakeReceipt};

/// Separates a real canceled transaction from failed physical return.
enum ReturnFailure {
    Native(i32),
    CaptureCancelled { capture_request: u32 },
}

impl From<i32> for ReturnFailure {
    fn from(status: i32) -> Self {
        Self::Native(status)
    }
}

impl FingerprintWorkerControl {
    fn refuse_entry(&self, cause: FingerprintWorkerCause, status: i32) {
        let mut state = self.lock();
        if state.native_entry_failure.is_none() {
            state.native_entry_failure = Some(EntryFailure { status, cause });
        }
        if state.failure.is_none() {
            state.failure = Some(FingerprintWorkerCause::WorkerEntry);
        }
        drop(state);
        self.available.notify_all();
        self.capacity.notify_all();
    }

    fn refuse_entry_native(&self, operation: &'static str, status: i32) {
        self.record_native_failure(operation, status);
        self.refuse_entry(FingerprintWorkerCause::Native { operation, status }, status);
    }

    fn entry_failed(&self, native_close_observed: bool) -> bool {
        let state = self.lock();
        let primary = match state.failure.as_ref() {
            None => PrimaryFailure::Absent,
            Some(FingerprintWorkerCause::CaptureCancelled { .. }) => {
                PrimaryFailure::CaptureCancelled
            }
            Some(_) => PrimaryFailure::Other,
        };
        // Cancellation may be the first typed cause while a later genuine
        // worker/Source/cleanup error occupies another paid journal. Check all
        // independent records rather than interpreting the primary alone.
        let independent = state.native_entry_failure.is_some()
            || state.native_failure.is_some()
            || state.cleanup_failure.is_some()
            || state.panic_payload.is_some()
            || state.supervision_failure.is_some()
            || state.native_submit_failure.is_some()
            || state.native_terminal_observation_failure.is_some()
            || state.native_cleanup_failure.is_some()
            || state.module_action_failure.is_some()
            || state.scope_return_failure.is_some()
            || state.sampler_action_failure.is_some();
        worker_outcome::entry_failed(primary, native_close_observed || state.closed, independent)
    }

    fn job(&self, index: usize) -> Result<MutexGuard<'_, Option<LiveFingerprintDigestWork>>, i32> {
        match self.jobs.get(index).ok_or(-libc::EPROTO)?.try_lock() {
            Ok(job) => Ok(job),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Ok(poisoned.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => Err(-libc::EBUSY),
        }
    }

    fn next_native_job(&self) -> Option<usize> {
        let mut state = self.lock();
        loop {
            if state.closed || state.failure.is_some() {
                return None;
            }
            if state.pipeline.pending.is_some() {
                let selected = state.pipeline.take();
                if selected.is_none() && state.failure.is_none() {
                    state.failure = Some(FingerprintWorkerCause::UnsettledWork);
                }
                return selected;
            }
            state = match self.available.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    /// Checks physical debts only after Source has joined and excluded users.
    pub(super) fn jobs_have_native_debt(&self) -> bool {
        let state = self.lock();
        if state.pipeline.pending.is_some()
            || state.pipeline.active.is_some()
            || state.pipeline.submitting.is_some()
            || state.pipeline.taking.is_some()
        {
            return true;
        }
        drop(state);
        self.jobs.iter().any(|slot| {
            let job = match slot.try_lock() {
                Ok(job) => job,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return true,
            };
            job.as_ref().is_some_and(|job| {
                !job.native_work.is_empty()
                    || !job.worker_work.is_empty()
                    || !job.captured.native_material().is_empty()
            })
        })
    }
}

impl LiveFingerprintDigestWorker {
    /// Returns already-completed owners without waiting for the active digest.
    ///
    /// # Errors
    /// Retains actual completed-return or sticky worker failure independently.
    pub(in crate::runtime::live_callbacks) fn drain_native_completed(
        &self,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.native
            .with_control(false, |control| self.drain_control(control, false))
    }

    /// Returns semantic leaves in the actual ordinary or closed cleanup scope.
    ///
    /// # Errors
    /// Retains incomplete actual close, busy material, worker handoffs and each
    /// independent failure. Observed closing selects only a terminal attempt;
    /// Source authenticates completed close before the closure can run.
    pub(in crate::runtime::live_callbacks) fn drain_semantic_completed(
        &self,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let terminal = self.native.observe()?.closing == 1;
        self.native.with_control(terminal, |control| {
            if !terminal {
                return self.drain_control(control, false);
            }
            control.close();
            let material_error = match control.capture_attempt.try_lock() {
                Ok(mut attempt) => attempt
                    .retire_native_material(self.native.id, self.native.api)
                    .err()
                    .map(|source| {
                        control
                            .lock()
                            .native_cleanup_failure
                            .get_or_insert(source.clone());
                        control.refuse(FingerprintWorkerCause::Digest(source));
                        Self::failed(control)
                    }),
                Err(_) => Some(status_error(-libc::EBUSY)),
            };
            // Material refusal does not skip independent completed-work return.
            let drained = self.drain_control(control, true);
            match material_error {
                Some(error) => Err(error),
                None => drained,
            }
        })
    }

    /// Queues one prepared capture while the preceding digest remains active.
    ///
    /// # Errors
    /// Waits only for occupied queue capacity under this prepared Material's
    /// Original; retains every born output before independent Source refusal.
    pub(in crate::runtime::live_callbacks) fn submit_native(
        &self,
        attempt: &mut crate::fingerprint_sampler::CaptureAttempt,
        capture_request: u32,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.native.with_control(false, |control| {
            self.submit_control(control, attempt, capture_request)
        })
    }

    fn submit_control(
        &self,
        control: &Arc<FingerprintWorkerControl>,
        attempt: &mut crate::fingerprint_sampler::CaptureAttempt,
        capture_request: u32,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        loop {
            self.drain_control(control, false)?;
            let mut state = control.lock();
            if state.closed || state.failure.is_some() {
                drop(state);
                return Err(Self::failed(control));
            }
            let queue_available = state.pipeline.pending.is_none()
                && state.pipeline.submitting.is_none()
                && state.pipeline.taking.is_none();
            if queue_available {
                for index in 0..WORK_CELLS {
                    let mut slot = match control.job(index) {
                        Ok(slot) => slot,
                        Err(status) if status == -libc::EBUSY => continue,
                        Err(status) => return Err(status_error(status)),
                    };
                    if slot.is_some() {
                        continue;
                    }
                    let receipt_epoch = state.receipts.reserve().map_err(status_error)?;
                    if !state.pipeline.reserve(index) {
                        drop(slot);
                        drop(state);
                        control.refuse_native("job reservation", -libc::EPROTO);
                        return Err(Self::failed(control));
                    }
                    drop(state);
                    let Some(sample) = attempt.pending().take() else {
                        control.lock().pipeline.publish(index, false);
                        return Err(status_error(-libc::EPROTO));
                    };
                    *slot = Some(LiveFingerprintDigestWork::new(
                        sample,
                        capture_request,
                        receipt_epoch,
                    ));
                    let Some(job) = slot.as_mut() else {
                        return Err(status_error(-libc::EPROTO));
                    };
                    let material = job.captured.native_material();
                    job.native_history.material_serial = material.serial;
                    job.native_history.identity = material;
                    // Native writes directly into this paid owning job before
                    // its independent post. No caller field address is retained.
                    let status = (self.native.api.submit)(
                        self.native.id,
                        self.native.pointer(),
                        &material,
                        &mut job.native_work,
                    );
                    job.native_history.work_serial = job.native_work.serial;
                    job.native_history.submit_status = Some(status);
                    let valid_output = job.native_work.is_live();
                    let born = !job.native_work.is_empty();
                    let transfer = if born {
                        attempt.moved_to_native_job(material, job.native_work, status)
                    } else {
                        Ok(())
                    };
                    if !born {
                        if let Some(job) = slot.take() {
                            *attempt.pending() = Some(job.captured);
                        }
                    }
                    let mut state = control.lock();
                    let published = state.pipeline.publish(index, born);
                    if status != 0 {
                        state.native_submit_failure.get_or_insert(status);
                    }
                    let refusal = if status != 0 {
                        Some(status)
                    } else if !published || !valid_output {
                        Some(-libc::EPROTO)
                    } else {
                        None
                    };
                    if let Some(status) = refusal {
                        if state.failure.is_none() {
                            state.failure = Some(FingerprintWorkerCause::Native {
                                operation: "submit",
                                status,
                            });
                        }
                    }
                    drop(state);
                    drop(slot);
                    control.available.notify_all();
                    if let Err(source) = transfer {
                        control.refuse(FingerprintWorkerCause::Digest(source));
                        return Err(Self::failed(control));
                    }
                    if let Some(status) = refusal {
                        control.refuse_native("submit", status);
                        return Err(Self::failed(control));
                    }
                    return Ok(());
                }
            }
            drop(state);
            let material = attempt
                .pending()
                .as_ref()
                .map(CapturedFingerprintSample::native_material)
                .ok_or_else(|| status_error(-libc::EPROTO))?;
            let slice = self.prequeue_slice(control, &material)?;
            let state = control.lock();
            if state.closed || state.failure.is_some() {
                continue;
            }
            // Recheck after the observation: completion/take may have released
            // capacity while no queue lock was held. The wait releases it too.
            if state.pipeline.pending.is_none()
                && state.pipeline.submitting.is_none()
                && state.pipeline.taking.is_none()
            {
                drop(state);
                continue;
            }
            let waited = control.capacity.wait_timeout(state, slice);
            drop(match waited {
                Ok((state, _)) => state,
                Err(poisoned) => poisoned.into_inner().0,
            });
        }
    }

    fn prequeue_slice(
        &self,
        control: &Arc<FingerprintWorkerControl>,
        material: &MaterialRef,
    ) -> Result<std::time::Duration, LiveVcpuTimeCallbackError> {
        let mut bounded_ns = 0;
        let status = (self.native.api.material_current)(self.native.id, material, &mut bounded_ns);
        if status != 0 || bounded_ns == 0 {
            control.refuse_native(
                "prequeue Original",
                if status != 0 {
                    status
                } else {
                    -libc::ETIMEDOUT
                },
            );
            return Err(Self::failed(control));
        }
        Ok(std::time::Duration::from_nanos(bounded_ns).min(std::time::Duration::from_millis(10)))
    }

    /// Attempts every eligible receipt independently, including terminal cancel.
    pub(super) fn drain_control(
        &self,
        control: &Arc<FingerprintWorkerControl>,
        terminal: bool,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let mut refused = false;
        let entry_returned = if terminal {
            // A completed Source close admitted this terminal scope. Local
            // closure excludes new pending-to-active selections before observing
            // whether this exact native worker has returned its Rust entry.
            let closed = control.lock().closed;
            if !closed {
                control.refuse_native("terminal local closure", -libc::EPROTO);
                return Err(Self::failed(control));
            }
            let mut status = WorkerStatus::default();
            let observed =
                (self.native.api.observe)(self.native.id, self.native.pointer(), &mut status);
            let observation = if observed != 0 {
                observed
            } else if validate_status(&status).is_err() {
                -libc::EPROTO
            } else {
                0
            };
            if observation != 0 {
                control
                    .lock()
                    .native_terminal_observation_failure
                    .get_or_insert(observation);
                control.refuse_native("terminal worker observation", observation);
                refused = true;
                false
            } else {
                status.entry_returned == 1
            }
        } else {
            false
        };
        let completed = {
            let mut state = control.lock();
            if terminal && state.closed && !state.pipeline.cancel_pending() {
                if state.failure.is_none() {
                    state.failure = Some(FingerprintWorkerCause::UnsettledWork);
                }
            }
            state.pipeline.completed()
        };
        let eligible = if terminal {
            [Some(0), Some(1)]
        } else {
            completed
        };
        for index in eligible.into_iter().flatten() {
            match self.return_job(control, index, terminal, entry_returned) {
                Ok(()) => {}
                Err(ReturnFailure::Native(status)) if terminal && status == -libc::EBUSY => {
                    // An active byte borrower or its short receipt handoff is
                    // physical debt. Actual tryjoin remains independently gated.
                }
                Err(ReturnFailure::CaptureCancelled { capture_request }) => {
                    refused = true;
                    control.refuse(FingerprintWorkerCause::CaptureCancelled { capture_request });
                }
                Err(ReturnFailure::Native(status)) => {
                    refused = true;
                    control.refuse_native("completed return", status);
                }
            }
        }
        if refused || control.lock().failure.is_some() {
            Err(Self::failed(control))
        } else {
            Ok(())
        }
    }

    fn return_job(
        &self,
        control: &Arc<FingerprintWorkerControl>,
        index: usize,
        terminal: bool,
        entry_returned: bool,
    ) -> Result<(), ReturnFailure> {
        if terminal {
            let state = control.lock();
            if !state.closed {
                return Err(ReturnFailure::Native(-libc::EPROTO));
            }
            // The worker may be between local selection and locking its job, or
            // between returning native bytes and publishing local completion.
            // Source's actual entry-return witness is needed to override either
            // live handoff; closed or native Work completion alone is insufficient.
            if !entry_returned && state.pipeline.worker_handoff_pending(index) {
                return Err(ReturnFailure::Native(-libc::EBUSY));
            }
        }
        let mut slot = control.job(index)?;
        let Some(job) = slot.as_mut() else {
            return if terminal {
                Ok(())
            } else {
                Err(ReturnFailure::Native(-libc::EPROTO))
            };
        };
        let mut first = 0;
        if !job.work_returned {
            let before = self.observe_job(job)?;
            if before.bytes_held != 0 || before.completed != 1 {
                return Err(ReturnFailure::Native(-libc::EBUSY));
            }
            let mut result = 0;
            let status =
                (self.native.api.work_return)(self.native.id, &mut job.native_work, &mut result);
            job.native_history.work_return_status = Some(status);
            job.native_history.work_return_output = Some(result);
            if status != 0 {
                job.native_history
                    .work_return_first_failure
                    .get_or_insert(status);
            }
            if job.native_work.is_empty() {
                job.work_returned = true;
                job.native_history.work_result = Some(result);
            }
            if status != 0 {
                first = status;
            }
            if !job.work_returned {
                return Err(ReturnFailure::Native(if first != 0 {
                    first
                } else {
                    -libc::EPROTO
                }));
            }
        }
        if !job.captured.native_material().is_empty() {
            if let Err(source) = job
                .captured
                .return_material(self.native.id, self.native.api)
            {
                let status = match &source {
                    FingerprintSamplerError::NativeMaterial { status } => *status,
                    _ => -libc::EPROTO,
                };
                job.native_history.material_return_last_status = Some(status);
                job.native_history
                    .material_return_failure
                    .get_or_insert(source.clone());
                control.lock().native_cleanup_failure.get_or_insert(source);
                if first == 0 {
                    first = status;
                }
            } else {
                job.native_history.material_return_last_status = Some(0);
            }
        }
        if let Err(status) = self.observe_job(job) {
            if first == 0 {
                first = status;
            }
        }
        let physically_returned = job.work_returned
            && job.native_work.is_empty()
            && job.worker_work.is_empty()
            && job.captured.native_material().is_empty();
        if terminal && physically_returned {
            // Source's real return proofs settle local placement even after a
            // worker unwind. The paid slot still retains its failed transcript.
            control.lock().pipeline.retired(index);
        }
        let native_return_healthy = first == 0
            && job.native_history.work_return_first_failure.is_none()
            && job.native_history.material_return_failure.is_none()
            && job.native_history.observation_first_failure.is_none()
            && job.native_history.pipeline.is_some_and(|native| {
                native.material_first_status == 0
                    && native.material_post_status == 0
                    && native.submit_post_status == 0
                    && native.complete_first_status == 0
                    && native.complete_status == 0
                    && native.work_return_first_status == 0
                    && native.work_return_status == 0
                    && native.material_return_first_status == 0
                    && native.material_return_status == 0
                    && native.close_status == 0
                    && native.bytes_held == 0
                    && native.work_returned == 1
                    && native.close_uncertain == 0
                    && native.physical_returned == 1
            });
        let cancelled = native_return_healthy
            && physically_returned
            && job.native_history.work_result == Some(-libc::ECANCELED)
            && !job.native_history.completion_attempted
            && job.native_history.completion_result.is_none()
            && job.native_history.complete_status.is_none()
            && (job.native_history.take_status.is_none() || job.native_history.cooperative_close)
            && job.publication == MaterialPublication::NotStarted
            && job.native_history.pipeline.is_some_and(|native| {
                CancelledWork {
                    expected_material: job.native_history.material_serial,
                    expected_work: job.native_history.work_serial,
                    material: native.material_serial,
                    work: native.work_serial,
                    cancelled: native.cancelled,
                    result: native.work_result,
                    complete_attempted: native.complete_attempted,
                }
                .matches()
            });
        let healthy = native_return_healthy
            && job.native_history.work_result == Some(0)
            && job.native_history.take_status == Some(0)
            && job.native_history.complete_status == Some(0)
            && job.native_history.bytes_returned
            && job.publication == MaterialPublication::Acknowledged
            && job
                .native_history
                .pipeline
                .is_some_and(|native| native.work_result == 0);
        if terminal && physically_returned && job.physical_leaves_returned() {
            let failure = if first < 0 {
                first
            } else if cancelled {
                -libc::ECANCELED
            } else if healthy {
                0
            } else {
                // Acknowledgement alone cannot erase an independent return,
                // material, observation or native pipeline failure. Full typed
                // histories remain in the paid job beside this summary.
                -libc::EIO
            };
            control.lock().receipts.record(
                index,
                CaptureReceipt {
                    epoch: job.receipt_epoch,
                    capture: job.capture_request,
                    sample_completed: job.publication == MaterialPublication::Acknowledged,
                    first: failure,
                },
            )?;
        }
        if cancelled {
            return Err(ReturnFailure::CaptureCancelled {
                capture_request: job.capture_request,
            });
        }
        if !healthy {
            if first == 0 {
                first = -libc::EIO;
            }
            return Err(ReturnFailure::Native(first));
        }
        if !job.captured.native_material().is_empty() || !job.worker_work.is_empty() {
            return Err(ReturnFailure::Native(-libc::EBUSY));
        }
        // Every actual owner returned. Clear the same local completed entry
        // before freeing its transcript slot for another genuine native birth.
        let mut state = control.lock();
        if !terminal && !state.pipeline.returned(index) {
            return Err(ReturnFailure::Native(-libc::EPROTO));
        }
        state.receipts.record(
            index,
            CaptureReceipt {
                epoch: job.receipt_epoch,
                capture: job.capture_request,
                sample_completed: true,
                first: 0,
            },
        )?;
        drop(slot.take());
        drop(state);
        drop(slot);
        control.capacity.notify_all();
        Ok(())
    }

    fn observe_job(&self, job: &mut LiveFingerprintDigestWork) -> Result<PipelineStatus, i32> {
        let mut pipeline = PipelineStatus::default();
        let status = (self.native.api.pipeline_observe)(
            self.native.id,
            &job.native_history.identity,
            &mut pipeline,
        );
        let status = if status == 0
            && (pipeline.schema_version != 1
                || pipeline.struct_size as usize != size_of::<PipelineStatus>()
                || pipeline.material_serial != job.native_history.identity.serial)
        {
            -libc::EPROTO
        } else {
            status
        };
        job.native_history.observation_status = Some(status);
        if status == 0 {
            job.native_history.pipeline = Some(pipeline);
            Ok(pipeline)
        } else {
            job.native_history
                .observation_first_failure
                .get_or_insert(status);
            Err(status)
        }
    }

    pub(super) fn run_native(control: &FingerprintWorkerControl) -> i32 {
        let Some(context) = control.native.as_ref() else {
            return -libc::EPROTO;
        };
        let identity = match context.quiescence.register_current(WORKER_FINGERPRINT) {
            Ok(identity) => identity,
            Err(source) => {
                control.refuse_entry(FingerprintWorkerCause::Registration(source), -libc::ECHILD);
                return -libc::ECHILD;
            }
        };
        control.lock().registered = true;
        control.capacity.notify_all();
        let mut native_close_observed = false;
        loop {
            let idle = context.quiescence.idle(WORKER_FINGERPRINT);
            let Some(index) = control.next_native_job() else {
                break;
            };
            let pending = idle.received();
            let _operation = pending.enter();
            match Self::digest_job(control, context, index) {
                Ok(JobOutcome::Completed) => {}
                Ok(JobOutcome::NativeClosed) => {
                    native_close_observed = true;
                    break;
                }
                Err(_) => break,
            }
        }
        drop(identity);
        if control.entry_failed(native_close_observed) {
            -libc::EIO
        } else {
            0
        }
    }

    fn digest_job(
        control: &FingerprintWorkerControl,
        context: &Context,
        index: usize,
    ) -> Result<JobOutcome, i32> {
        let handle = context.handle;
        let mut slot = match control.job(index) {
            Ok(slot) => slot,
            Err(status) => {
                control.refuse_entry_native("job borrow", status);
                return Err(status);
            }
        };
        let Some(job) = slot.as_mut() else {
            control.refuse_entry_native("job owner", -libc::EPROTO);
            return Err(-libc::EPROTO);
        };
        let mut address = std::ptr::null_mut();
        let mut length = 0;
        let taken = (handle.api.take)(
            handle.pointer(),
            &mut job.worker_work,
            &mut address,
            &mut length,
        );
        let cooperative_close = TakeReceipt {
            status: taken,
            work_empty: job.worker_work.is_empty(),
            workspace_address: address as usize,
            workspace_length: length,
        }
        .is_cooperative_close();
        job.native_history.take_status = Some(taken);
        job.native_history.cooperative_close = cooperative_close;
        job.native_history.take_output = Some(job.worker_work);
        job.native_history.take_workspace = Some((address as usize, length));
        job.workspace_address = address as usize;
        job.workspace_length = length;
        let take_valid = taken == 0
            && job.worker_work == job.native_work
            && job.worker_work.is_live()
            && !address.is_null()
            && length == 65_536;
        job.native_history.byte_loan_issued = !job.worker_work.is_empty();
        if taken != 0 && !cooperative_close {
            control.refuse_entry_native("take", taken);
        } else if !take_valid && !cooperative_close {
            control.refuse_entry_native("take projection", -libc::EPROTO);
        }
        let (taken_locally, local_closed) = {
            let mut state = control.lock();
            (state.pipeline.taken(index), state.closed)
        };
        job.native_history.take_local_closed = Some(local_closed);
        if !taken_locally {
            control.refuse_entry(FingerprintWorkerCause::UnsettledWork, -libc::EPROTO);
        }
        control.capacity.notify_all();
        let mut result = taken;
        if take_valid {
            // SAFETY: this exact successful take exclusively lends the complete
            // Source workspace until complete consumes this serial-bearing loan.
            // No byte slice or body reference leaves the born worker callback.
            let workspace = unsafe { &mut *address.cast::<[u8; 65_536]>() };
            let work = job.worker_work;
            match job
                .captured
                .digest_native(workspace, handle.api, handle.pointer(), &work)
            {
                Ok(sample) => {
                    if let Err(source) =
                        job.publish_native(context.slot.get(), &sample, handle, &work)
                    {
                        result = -libc::EIO;
                        control.refuse_entry(source, result);
                    }
                }
                Err(source) => {
                    result = -libc::EIO;
                    if let FingerprintSamplerError::NativeMaterial { status } = &source {
                        control.record_native_failure("material read", *status);
                    }
                    control.refuse_entry(FingerprintWorkerCause::Digest(source), result);
                }
            }
        } else if result == 0 {
            result = -libc::EPROTO;
            control.refuse_entry_native("take projection", result);
        }
        // Completion is independent of the earlier read/publication failure.
        // Its signed result and consumed-output fact occupy separate paid fields.
        let completion = if job.worker_work.is_empty() {
            None
        } else {
            job.native_history.completion_attempted = true;
            job.native_history.completion_result = Some(result);
            let status = (handle.api.complete)(handle.pointer(), &mut job.worker_work, result);
            job.native_history.complete_status = Some(status);
            Some(status)
        };
        let bytes_returned = job.native_history.byte_loan_issued && job.worker_work.is_empty();
        job.native_history.bytes_returned = bytes_returned;
        if bytes_returned {
            job.workspace_address = 0;
            job.workspace_length = 0;
        }
        if let Some(completion) = completion {
            if completion != 0 {
                control.refuse_entry_native("complete", completion);
            }
        }
        if job.native_history.byte_loan_issued && !bytes_returned {
            control.refuse_entry_native("byte return", -libc::EBUSY);
        }
        drop(slot);
        let completed_locally = control.lock().pipeline.complete(index);
        if !completed_locally {
            control.refuse_entry(FingerprintWorkerCause::UnsettledWork, -libc::EPROTO);
        }
        control.capacity.notify_all();
        // No Main-return handshake here: the next queued job may borrow the
        // workspace while this completed receipt remains in its owning slot.
        if cooperative_close {
            // This actual authenticated empty response proves Native has closed
            // irreversibly, even if module_close has not set local closed yet.
            // Stop entry immediately; no later local job selection is permitted.
            Ok(JobOutcome::NativeClosed)
        } else if taken != 0
            || result != 0
            || completion.is_some_and(|status| status != 0)
            || !bytes_returned
        {
            Err(-libc::EIO)
        } else {
            Ok(JobOutcome::Completed)
        }
    }
}

impl LiveFingerprintDigestWork {
    // The saved Source observation is corroboration of actual consumed fields;
    // neither a status nor a local empty marker can certify these leaves alone.
    pub(in crate::runtime::live_callbacks::fingerprint_worker) fn physical_leaves_returned(
        &self,
    ) -> bool {
        self.work_returned
            && self.native_work.is_empty()
            && self.worker_work.is_empty()
            && self.captured.native_material().is_empty()
            && self.native_history.pipeline.is_some_and(|status| {
                status.physical_returned == 1
                    && status.close_uncertain == 0
                    && status.bytes_held == 0
                    && status.work_returned == 1
            })
    }
}
