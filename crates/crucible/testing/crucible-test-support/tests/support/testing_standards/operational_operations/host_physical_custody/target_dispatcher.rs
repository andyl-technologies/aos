//! Binds exact saved-operation custody and physical return ordering.

use super::{Companion, Contract};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-host",
    target: "src/linux_cgroup/target_dispatcher",
    required: &[
        (
            r#"self.state = Some(Arc::new(DispatcherState {
            slots: Mutex::new(slots),
            running: Mutex::new(running),
            readiness,
            shutdown: AtomicBool::new(false),
            worker_exited: AtomicBool::new(false),
            retained_worker: OnceLock::new(),
            startup: Mutex::new(None),
            outcome: Mutex::new(None),
            wake,
            _namespace: namespace,
            path: root.path.clone(),
        }));
        let state = Arc::clone(
            self.state
                .as_ref()
                .ok_or_else(|| failure(&root.path, "Target dispatcher state is absent"))?,
        );
        let worker = self
            .purpose
            .as_mut()
            .ok_or_else(|| failure(&root.path, "Target dispatcher payer is absent"))?
            .spawn_worker("crucible-target-dispatcher", move || {
                let outcome_state = Arc::clone(&state);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(state, event_capacity);
                }));
                let mut saved = match outcome_state.outcome.lock() {
                    Ok(saved) => saved,
                    Err(poison) => poison.into_inner(),
                };
                *saved = Some(outcome);
            })
            .map_err(|source| failure(&root.path, source))?;
        self.worker = Some(worker);
        self.worker_born = true;"#,
            1,
        ),
        (
            r#"fn wait_for_worker_startup(&self) -> Result<(), DispatcherStartupFailure> {
        loop {
            let slice = self
                .purpose
                .as_ref()
                .ok_or(DispatcherStartupFailure::Custody(
                    "Target dispatcher payer is absent",
                ))?
                .startup_wait_slice()
                .map_err(DispatcherStartupFailure::Original)?;
            let state = self
                .state
                .as_ref()
                .ok_or(DispatcherStartupFailure::Custody(
                    "Target dispatcher state is absent",
                ))?;
            if worker_startup_ready(state)? {
                return Ok(());
            }
            if state.worker_exited.load(Ordering::Acquire) || self.worker.is_none() {
                return Err(DispatcherStartupFailure::Custody(
                    "Target worker exited before startup acknowledgement",
                ));
            }
            thread::sleep(slice.min(WATCHER_WAIT_POLL_INTERVAL));
        }
    }"#,
            1,
        ),
        (
            r#"fn worker_startup_ready(state: &DispatcherState) -> Result<bool, DispatcherStartupFailure> {
    let startup = state.startup.lock().map_err(|_| {
        DispatcherStartupFailure::Custody("Target worker startup custody is poisoned")
    })?;
    match startup.as_ref() {
        Some(Ok(())) => Ok(true),
        Some(Err(source)) => Err(DispatcherStartupFailure::Allocation(source.clone())),
        None => Ok(false),
    }
}"#,
            1,
        ),
        (
            r#"fn report_retirement_history(&mut self) -> Result<(), LinuxQemuCgroupError> {
        let panicked = self.worker_panic().is_some();
        if self
            .join_observations
            .iter()
            .any(|(pre, post)| pre.is_some() || post.is_some())
        {
            return Err(failure(
                &self.path,
                format_args!(
                    "Target worker return history: {:?}; startup {}; panic {panicked}",
                    self.join_observations, self.startup_history,
                ),
            ));
        }
        if self.startup_history.has_failure() {
            return Err(if panicked {
                failure(
                    &self.path,
                    format_args!(
                        "{}; Target dispatcher physically joined after worker panic",
                        self.startup_history,
                    ),
                )
            } else {
                failure(&self.path, &self.startup_history)
            });
        }
        if panicked {
            return Err(failure(
                &self.path,
                "Target dispatcher physically joined after worker panic",
            ));
        }
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn finish(&mut self) -> Result<(), LinuxQemuCgroupError> {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.belongs_to_current_process())
        {
            return Err(failure(
                &self.path,
                "Target worker belongs to another process",
            ));
        }
        if self.phase == WorkerPhase::Complete {
            return self.report_retirement_history();
        }
        let path = self.path.clone();
        self.retry_abandoned_jobs()?;
        if matches!(self.phase, WorkerPhase::Reserved | WorkerPhase::Running)
            && let Some(state) = self.state.as_ref()
        {
            let slots = match state.slots.try_lock() {
                Ok(slots) => slots,
                Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    return Err(failure(&path, "Target retirement custody is pending"));
                }
            };
            if slots.iter().any(|slot| {
                slot.phase != JobPhase::Idle || slot.control.is_some() || slot.original.is_some()
            }) {
                return Err(failure(
                    &path,
                    "Target dispatcher still owns an actual job or returned control",
                ));
            }
            let running = match state.running.try_lock() {
                Ok(running) => running,
                Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    return Err(failure(&path, "Target worker custody is pending"));
                }
            };
            if running.iter().any(Option::is_some) {
                return Err(failure(&path, "Target worker still owns actual controls"));
            }
            // Only the complete absence of every actual slot/worker owner
            // permits retiring poison; individual job recovery never does.
            state.running.clear_poison();
            state.slots.clear_poison();
        }
        if self.cleanup.is_none() {
            self.cleanup = Some(
                self.purpose
                    .as_ref()
                    .ok_or_else(|| failure(&path, "Target dispatcher payer is absent"))?
                    .retained_cleanup()
                    .map_err(|source| failure(&path, source))?,
            );
        }
        let cleanup = self
            .cleanup
            .as_ref()
            .ok_or_else(|| failure(&path, "Target dispatcher Cleanup is absent"))?;
        if matches!(self.phase, WorkerPhase::Reserved | WorkerPhase::Running) {
            if let Some(state) = self.state.as_ref() {
                state.shutdown.store(true, Ordering::Release);
                wake(&state.wake).map_err(|source| failure(&path, source))?;
            }
            loop {
                let before = cleanup.wait_slice();
                if self.join_observations[0].0.is_none() {
                    self.join_observations[0].0 = before.as_ref().err().copied();
                }
                let observed = match self.worker.as_mut() {
                    Some(worker) => self
                        .purpose
                        .as_mut()
                        .ok_or_else(|| failure(&path, "Target dispatcher payer is absent"))?
                        .observe_worker_return(worker, cleanup)
                        .map_err(|source| failure(&path, source)),
                    None if self.phase == WorkerPhase::Reserved => {
                        Ok(NativeJoinObservation::Returned)
                    }
                    None => Err(failure(&path, "Target native join owner is absent")),
                };
                // The actual native zero is recorded before independent post.
                if matches!(observed, Ok(NativeJoinObservation::Returned)) {
                    self.worker = None;
                    self.phase = WorkerPhase::Joined;
                }
                let after = cleanup.wait_slice();
                if self.join_observations[0].1.is_none() {
                    self.join_observations[0].1 = after.as_ref().err().copied();
                }
                match observed? {
                    NativeJoinObservation::Returned => break,
                    NativeJoinObservation::Pending => {
                        before.map_err(|source| failure(&path, source))?;
                        after.map_err(|source| failure(&path, source))?;
                        let wait_before = cleanup.wait_slice();
                        if self.join_observations[1].0.is_none() {
                            self.join_observations[1].0 = wait_before.as_ref().err().copied();
                        }
                        if let Ok(slice) = wait_before {
                            thread::sleep(slice.min(WATCHER_WAIT_POLL_INTERVAL));
                        }
                        let wait_after = cleanup.wait_slice();
                        if self.join_observations[1].1.is_none() {
                            self.join_observations[1].1 = wait_after.as_ref().err().copied();
                        }
                        wait_before.map_err(|source| failure(&path, source))?;
                        wait_after.map_err(|source| failure(&path, source))?;
                    }
                }
            }
        }
        if self.phase == WorkerPhase::Joined {
            if let Some(state) = self.state.as_mut() {
                let state = Arc::get_mut(state).ok_or_else(|| {
                    failure(&path, "Target dispatcher has surviving queue aliases")
                })?;
                let outcome = match state.outcome.get_mut() {
                    Ok(outcome) => outcome,
                    Err(poison) => poison.into_inner(),
                }
                .take();
                let outcome = match outcome {
                    Some(outcome) => outcome,
                    None if !self.worker_born => Ok(()),
                    None => return Err(failure(&path, "Target worker outcome was not delivered")),
                };
                if let Err(payload) = outcome {
                    let history = match self.worker_panic.get_mut() {
                        Ok(history) => history,
                        Err(poison) => poison.into_inner(),
                    };
                    *history = Some(payload);
                }
            }
            drop(self.state.take());
            self.phase = WorkerPhase::QueueClosed;
        }
        self.purpose
            .as_mut()
            .ok_or_else(|| failure(&path, "Target dispatcher payer is absent"))?
            .retire_worker_debits(cleanup)
            .map_err(|source| failure(&path, source))?;
        cleanup
            .wait_slice()
            .map_err(|source| failure(&path, source))?;
        self.purpose
            .as_mut()
            .ok_or_else(|| failure(&path, "Target dispatcher payer is absent"))?
            .complete_cleanup(cleanup)
            .map_err(|source| failure(&path, source))?;
        self.cleanup = None;
        self.phase = WorkerPhase::Complete;
        self.report_retirement_history()
    }"#,
            1,
        ),
        (
            r#"fn retry_quarantined(
    state: &DispatcherState,
    slot: &mut JobSlot,
) -> Result<(), LinuxQemuCgroupError> {
    let phase = |original: &mut Option<TargetWatcherOriginal>| -> Result<(), crate::OriginalActorAccountError> {
        match original.as_mut() {
            Some(original) => original.wait_slice(true).map(|_| ()),
            #[cfg(test)]
            None => Ok(()),
            #[cfg(not(test))]
            None => Err(crate::OriginalActorAccountError::Unavailable),
        }
    };
    if let Err(source) = phase(&mut slot.original) {
        let error = failure(&state.path, &source);
        slot.failure
            .get_or_insert_default()
            .after
            .get_or_insert(source);
        return Err(error);
    }
    let delay = match slot.next_retry.poll(CGROUP_KILL_INTERVAL) {
        Ok(delay) => delay,
        Err(source) => {
            slot.failure
                .get_or_insert_default()
                .cadence
                .get_or_insert(source);
            return Err(failure(&state.path, source));
        }
    };
    if !delay.is_zero() {
        return Err(failure(
            &state.path,
            "Target physical retry cadence is pending",
        ));
    }
    let control = slot
        .control
        .as_mut()
        .ok_or_else(|| failure(&state.path, "Target quarantine lost its actual control"))?;
    let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        control.kill_members()?;
        control.is_populated()
    }));
    let after = phase(&mut slot.original);
    let after_failed = after.is_err();
    if let Err(source) = after {
        slot.failure
            .get_or_insert_default()
            .after
            .get_or_insert(source);
    }
    let physical = match attempted {
        Ok(Ok(false)) => true,
        Ok(Ok(true)) => false,
        Ok(Err(source)) => {
            slot.failure
                .get_or_insert_default()
                .control
                .get_or_insert(source);
            false
        }
        Err(_) => {
            slot.failure.get_or_insert_default().panicked = true;
            false
        }
    };
    if !physical || after_failed {
        return Err(failure(
            &state.path,
            "Target physical retry remains retained",
        ));
    }
    match epoll::delete(&state.readiness, &control.cancellation_event) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(source) => {
            slot.failure
                .get_or_insert_default()
                .poller
                .get_or_insert_with(|| failure(&state.path, source));
            return Err(failure(&state.path, source));
        }
    }
    // Historical first/post failure remains factual even after this physical
    // return. Releasing the exact descriptors still precedes slot reuse.
    slot.phase = JobPhase::Returned;
    Ok(())
}"#,
            1,
        ),
        (
            r#"if slot.facade_live || slot.phase == JobPhase::Idle {
        continue;
    }
    // The private slot and epoch are the retained owner. This new
    // facade neither issues a job nor authorizes physical work.
    slot.facade_live = true;
    slot.epoch
};"#,
            1,
        ),
        (
            r#"let job = TargetWatchJob {
    state: Arc::clone(state),
    epoch,
    index,
    released: false,
};
match job.retire() {
    Ok(returned) => drop(returned),
    Err((job, source)) => {
        // Drop marks this same cell abandoned and requests cancel;
        // controls and first/post causes remain for the next call.
        drop(job);
        first_failure.get_or_insert(source);
    }
}"#,
            1,
        ),
        (
            r#"if slot.epoch == self.epoch && slot.phase == JobPhase::Quarantined {
    // Report the first failed attempt before any explicit retry can
    // return physical controls. Keep that cause in the occupied cell.
    if !slot.failure_reported {
        slot.failure_reported = true;
        let source = match slot.failure.as_ref() {
            Some(cause) => failure(&state.path, cause),
            None => failure(&state.path, "Target control is quarantined"),
        };
        drop(slots);
        return Err((self, source));
    }
    if let Err(source) = retry_quarantined(&state, slot) {
        drop(slots);
        return Err((self, source));
    }
}
if slot.epoch != self.epoch || slot.phase != JobPhase::Returned {
    let source = failure(
        &state.path,
        "Target job has not returned its actual control",
    );
    drop(slots);
    return Err((self, source));
}
let Some(control) = slot.control.take() else {"#,
            1,
        ),
        (
            r#"let original = slot.original.take();
slot.phase = JobPhase::Retiring;
drop(slots);
Ok(TargetReturnedControl {
    control: Some(control),
    original,
    job: Some(self),
})"#,
            1,
        ),
        (
            r#"impl Drop for TargetReturnedControl {
    fn drop(&mut self) {
        drop(self.control.take());
        drop(self.original.take());
        if let Some(mut job) = self.job.take() {
            job.released = true;
            drop(job);
        }
    }
}"#,
            1,
        ),
        (
            r#"if let Some(slot) = slots.get_mut(self.index).filter(|slot| {
    slot.epoch == self.epoch
        && slot.phase == JobPhase::Retiring
        && slot.control.is_none()
        && slot.original.is_none()
}) {
    slot.phase = JobPhase::Idle;
    slot.facade_live = false;
}"#,
            1,
        ),
        (
            r#"let slot = slots
    .get_mut(self.index)
    .filter(|slot| slot.epoch == self.epoch)
    .ok_or_else(|| failure(&self.state.path, "Target poisoned return epoch is stale"))?;"#,
            1,
        ),
        (
            r#"if slot.control.is_some()
    || slot.original.is_some()
    || entry.as_ref().is_none_or(|job| job.epoch != self.epoch)
{
    return Err(failure(
        &self.state.path,
        "Target poisoned ownership does not match",
    ));
}"#,
            1,
        ),
        (
            r#"slot.control = Some(job.control); slot.original = job.original; slot.failure = job.failure; slot.next_retry = job.next_attempt;"#,
            2,
        ),
        (
            r#"let started = self.wait_for_worker_startup();
let purpose = self.purpose.as_mut();
self.startup_history.observe(started, || {
    purpose
        .as_ref()
        .ok_or(DispatcherStartupFailure::Custody(
            "Target dispatcher payer is absent",
        ))?
        .startup_wait_slice()
        .map(|_| ())
        .map_err(DispatcherStartupFailure::Original)
});
if let Some(purpose) = purpose {
    purpose.release_startup_observation();
}
self.report_retirement_history()?;
self.phase = WorkerPhase::Running;"#,
            1,
        ),
        (
            r#"self.first = started.err(); self.post = post().err();"#,
            1,
        ),
        (
            r#"let delay = match job.next_attempt.poll(CGROUP_KILL_INTERVAL) {
                Ok(delay) => delay,
                Err(source) => {
                    job.failure
                        .get_or_insert_default()
                        .cadence
                        .get_or_insert(source);
                    if !return_job(&state, index, entry) {
                        return;
                    }
                    continue;
                }
            };
            if !delay.is_zero() {
                timeout = timeout.min(delay);
                continue;
            }"#,
            1,
        ),
        (r#"let after = job.wait_slice();"#, 1),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"begin_original_cleanup_control("#, 0),
        (r#"HostOperationClass::Preparation"#, 0),
        (r#"HostOperationClass::Cleanup"#, 0),
        (r#"thread::spawn("#, 0),
        (r#"thread::sleep("#, 2),
        (r#"now.checked_add(CGROUP_KILL_INTERVAL)"#, 0),
        (r#"Instant::now()"#, 0),
        (r#"self.cleanup = None;"#, 1),
        (r#".spawn_worker("#, 1),
    ],
    expressions: &[
        (r#"self.retry_abandoned_jobs()?;"#, 1),
        (r#"retry_quarantined(&state, slot)"#, 1),
        (
            r#"thread::sleep(slice.min(WATCHER_WAIT_POLL_INTERVAL));"#,
            2,
        ),
    ],
    identifiers: &[
        (r#"retry_abandoned_jobs"#, 2),
        (r#"retry_quarantined"#, 2),
        (r#"next_retry"#, 6),
    ],
    companions: &[
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_process.rs",
            required: &[(
                r#"self.target_dispatcher = Some(crate::linux_cgroup::TargetDispatcher::reserved(
                purpose, capacity,
            ));
            let started = self
                .target_dispatcher
                .as_mut()
                .ok_or_else(|| invalid_config("Target dispatcher custody is absent"))?
                .start(&self.root);"#,
                1,
            )],
        },
        Companion {
            path: "crates/crucible/host/crucible-host-resources/src/host_services/native_join.rs",
            required: &[
                (
                    r#"fn observe(&mut self, status: i32) -> Result<NativeJoinObservation, NativeJoinError> {
        match *self {
            Self::Returned => return Ok(NativeJoinObservation::Returned),
            Self::Uncertain(status) => return Err(NativeJoinError::Native { status }),
            Self::Active => {}
        }
        match status {
            0 => {
                *self = Self::Returned;
                Ok(NativeJoinObservation::Returned)
            }
            libc::EBUSY => Ok(NativeJoinObservation::Pending),
            status => {
                *self = Self::Uncertain(status);
                Err(NativeJoinError::Native { status })
            }
        }
    }"#,
                    1,
                ),
                (
                    r#"pub fn from_worker(worker: JoinHandle<()>) -> Self {
        let thread = worker.thread().id();
        let creator_process = std::process::id();
        let native = worker.into_pthread_t();
        Self {
            native: Some(native),
            thread,
            creator_process,
            disposition: Disposition::Active,
            last_status: None,
        }
    }"#,
                    1,
                ),
                (
                    r#"pub fn belongs_to_current_process(&self) -> bool {
        self.creator_process == std::process::id()
    }"#,
                    1,
                ),
                (
                    r#"pub fn poll(&mut self) -> Result<NativeJoinObservation, NativeJoinError> {
        if !self.belongs_to_current_process() {
            return Err(NativeJoinError::ForeignProcess);
        }
        match self.disposition {
            Disposition::Returned => return Ok(NativeJoinObservation::Returned),
            Disposition::Uncertain(status) => return Err(NativeJoinError::Native { status }),
            Disposition::Active => {}
        }
        let Some(native) = self.native else {
            return Err(NativeJoinError::MissingOwner);
        };
        let status = unsafe {
            // SAFETY: into_pthread_t transferred this joinable pthread's unique
            // ownership. No handle alias, detach or other join exists. Exclusive
            // mutable access serializes polling, and the creator-process check
            // prevents inherited child access. GNU libc 2.39 tryjoin returns
            // EBUSY without consuming the handle or waiting; zero consumes it.
            // The Rust trampoline returns null; actual Rust results have a
            // separately owned outcome cell, so no result pointer is needed.
            libc::pthread_tryjoin_np(native as libc::pthread_t, std::ptr::null_mut())
        };
        if status == 0 {
            self.native = None;
        }
        self.last_status = Some(status);
        self.disposition.observe(status)
    }"#,
                    1,
                ),
                (r#"libc::pthread_tryjoin_np("#, 1),
                (r#"as_pthread_t"#, 0),
                (r#".join("#, 0),
                (r#".detach("#, 0),
            ],
        },
        Companion {
            path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/target_dispatcher.rs",
            required: &[
                (
                    r#"pub fn startup_wait_slice(&self) -> Result<std::time::Duration, ServiceBirthError> {
        self.check()?;
        self.startup_original
            .as_ref()
            .ok_or_else(|| {
                ServiceBirthError::policy("Target dispatcher startup observation ended")
            })?
            .wait_slice()
            .map_err(ServiceBirthError::from)
    }"#,
                    1,
                ),
                (
                    r#"pub fn release_startup_observation(&mut self) {
        self.startup_original = None;
    }"#,
                    1,
                ),
                (
                    r#"fn enter(
        &self,
        origin: &HostOperationGuard,
    ) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        if self.completed {
            return Err(ServiceBirthError::policy(
                "Target dispatcher Cleanup already completed",
            ));
        }
        let entered = self
            .entered
            .get_or_init(|| origin.begin_original_cleanup_control().map(Arc::new));
        let cleanup = entered
            .as_ref()
            .map_err(|source| ServiceBirthError::from(*source))?;
        cleanup.verify_operation_class(HostOperationClass::Cleanup)?;
        Ok(Arc::clone(cleanup))
    }"#,
                    1,
                ),
                (
                    r#"fn verify_identity(&self, supplied: &Arc<HostOperationGuard>) -> Result<(), ServiceBirthError> {
        let entered = self.entered.get().ok_or_else(|| {
            ServiceBirthError::policy("Target dispatcher Cleanup has not been entered")
        })?;
        let saved = entered
            .as_ref()
            .map_err(|source| ServiceBirthError::from(*source))?;
        if !Arc::ptr_eq(saved, supplied) {
            return Err(ServiceBirthError::policy(
                "Target dispatcher Cleanup operation is foreign",
            ));
        }
        Ok(())
    }"#,
                    1,
                ),
                (
                    r#"fn verify(&self, supplied: &Arc<HostOperationGuard>) -> Result<(), ServiceBirthError> {
        self.verify_identity(supplied)?;
        supplied.verify_operation_class(HostOperationClass::Cleanup)?;
        Ok(())
    }"#,
                    1,
                ),
                (
                    r#"pub fn retained_cleanup(&self) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        self.cleanup.enter(&self.issuer.original)
    }"#,
                    1,
                ),
                (
                    r#"pub fn complete_cleanup(
        &mut self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        if !self.is_physically_retired() {
            return Err(ServiceBirthError::policy(
                "Target dispatcher resources remain held",
            ));
        }
        self.verify_cleanup(cleanup)?;
        self.cleanup.complete(cleanup)
    }"#,
                    1,
                ),
                (
                    r#"pub fn retire_worker_debits(
        &mut self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        self.verify_cleanup(cleanup)?;
        if self.worker.is_some() {
            return Err(ServiceBirthError::policy(
                "Target worker has not physically joined",
            ));
        }
        if self.is_physically_retired() {
            return Ok(());
        }
        self.issuer
            .host_descriptors
            .lock()
            .map_err(|_| ServiceBirthError::policy("Target window closure is uncertain"))?
            .as_mut()
            .ok_or_else(|| ServiceBirthError::policy("Target window owner is absent"))?
            .close_target_window(self.epoch)?;
        self.descriptors = None;
        self.task = None;
        // A joined or failed pthread allocation can remain in Main's cache.
        // Exactly one birth is permitted; this constant charge remains held.
        if let Some(metadata) = self.metadata.take() {
            std::mem::forget(metadata);
        }
        Ok(())
    }"#,
                    1,
                ),
                (
                    r#"self.cleanup.verify(cleanup)?; self.issuer.family.check_retained_custody()?;"#,
                    1,
                ),
                (
                    r#"pub fn observe_worker_return(
        &mut self,
        worker: &mut NativeJoinOwner,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<NativeJoinObservation, ServiceBirthError> {
        self.cleanup.verify_identity(cleanup)?;
        if self.worker != Some(worker.thread_id()) {
            return Err(ServiceBirthError::policy(
                "Target dispatcher worker identity changed",
            ));
        }
        let observed = worker.poll().map_err(ServiceBirthError::NativeJoin)?;
        if observed == NativeJoinObservation::Returned {
            self.worker = None;
        }
        Ok(observed)
    }"#,
                    1,
                ),
                (
                    r#"pub fn spawn_worker<F>(
        &mut self,
        name: &str,
        body: F,
    ) -> Result<NativeJoinOwner, ServiceBirthError>
    where
        F: FnOnce() + Send + 'static,
    {
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = (name, body);
            Err(ServiceBirthError::policy(
                "nonblocking Target worker join is unsupported on this platform",
            ))
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            self.check()?;
            if self.birth_attempted {
                return Err(ServiceBirthError::policy(
                    "Target dispatcher worker was already born",
                ));
            }
            self.birth_attempted = true;
            let worker = std::thread::Builder::new()
                .name(name.to_owned())
                .stack_size(self.stack_request_bytes())
                .spawn(body)
                .map_err(|source| ServiceBirthError::Kernel {
                    operation: "start actual Target dispatcher worker",
                    source,
                })?;
            self.worker = Some(worker.thread().id());
            Ok(NativeJoinOwner::from_worker(worker))
        }
    }"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/target_dispatcher.rs",
            required: &[(
                r#"pub(crate) fn wait_slice(
        &mut self,
        draining: bool,
    ) -> Result<(std::time::Duration, bool), OriginalActorAccountError> {
        if draining {
            return Ok((self.cleanup.guard()?.wait_slice()?, true));
        }
        Ok((self.original.wait_slice()?, true))
    }"#,
                1,
            )],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/fork_target.rs",
            required: super::super::TARGET_CLEANUP_REQUIRED,
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_cgroup.rs",
            required: &[
                (
                    r#"const CGROUP_KILL_INTERVAL: Duration = Duration::from_millis(10);"#,
                    1,
                ),
                (
                    r#"const WATCHER_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);"#,
                    1,
                ),
            ],
        },
    ],
};
