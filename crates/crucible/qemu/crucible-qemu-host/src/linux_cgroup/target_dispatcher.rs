//! Reuses one Main-prepaid watcher through separately retired Target jobs.
//!
//! A job owns its actual cgroup controls and same original operation. Returning
//! those controls closes that job only; the permanent worker and its original
//! task/stack/control debit remain retained across all later campaigns.

use super::*;
use crate::linux_attempt_host::TargetWatcherOriginal;
use crucible_host_resources::host_services::native_join::{NativeJoinObservation, NativeJoinOwner};
use crucible_host_resources::host_services::process_birth::{
    AuthenticatedTargetDispatcherPurpose, ServiceBirthError,
};
use crucible_host_resources::host_supervision::{HostOperationGuard, HostRetryCadence};
use rustix::event::epoll;
use std::sync::atomic::AtomicBool;
use std::sync::{Mutex, TryLockError};

const RUNTIME_CONTROL_OVERLAP: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JobPhase {
    Idle,
    Queued,
    Running,
    Returned,
    Retiring,
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkerPhase {
    Reserved,
    Running,
    QueueClosed,
    Joined,
    Complete,
}

struct JobSlot {
    epoch: u64,
    phase: JobPhase,
    control: Option<LinuxQemuCgroupControl>,
    original: Option<TargetWatcherOriginal>,
    cancel_requested: bool,
    failure: Option<JobFailure>,
    failure_reported: bool,
    facade_live: bool,
    next_retry: HostRetryCadence,
}

struct DispatcherState {
    slots: Mutex<Vec<JobSlot>>,
    running: Mutex<Vec<Option<RunningJob>>>,
    readiness: OwnedFd,
    shutdown: AtomicBool,
    worker_exited: AtomicBool,
    // The actual worker publishes its fallible local buffer allocation before
    // start can accept jobs. The same state retains the initiating failure.
    startup: Mutex<Option<Result<(), std::collections::TryReserveError>>>,
    outcome: Mutex<Option<std::thread::Result<()>>>,
    wake: OwnedFd,
    _namespace: OwnedFd,
    path: PathBuf,
}

/// Holds the physical worker and external Main payer through real join.
pub(crate) struct TargetDispatcher {
    purpose: Option<AuthenticatedTargetDispatcherPurpose>,
    capacity: usize,
    state: Option<Arc<DispatcherState>>,
    worker: Option<NativeJoinOwner>,
    worker_born: bool,
    failed: bool,
    cleanup: Option<Arc<HostOperationGuard>>,
    phase: WorkerPhase,
    worker_panic: Mutex<Option<Box<dyn std::any::Any + Send>>>,
    startup_history: DispatcherStartupHistory,
    join_observations: [(
        Option<crucible_host_resources::host_supervision::HostSupervisionError>,
        Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    ); 2],
    path: PathBuf,
}

/// Keeps actual startup and independent saved-Preparation failures in the payer.
#[derive(Default)]
struct DispatcherStartupHistory {
    first: Option<DispatcherStartupFailure>,
    post: Option<DispatcherStartupFailure>,
}

/// Preserves startup authority and allocation failures before diagnostic rendering.
#[derive(Debug)]
enum DispatcherStartupFailure {
    Original(ServiceBirthError),
    Allocation(std::collections::TryReserveError),
    Custody(&'static str),
}

impl std::fmt::Display for DispatcherStartupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Original(source) => write!(formatter, "{source}"),
            Self::Allocation(source) => write!(formatter, "{source}"),
            Self::Custody(message) => formatter.write_str(message),
        }
    }
}

impl DispatcherStartupHistory {
    fn observe(
        &mut self,
        started: Result<(), DispatcherStartupFailure>,
        post: impl FnOnce() -> Result<(), DispatcherStartupFailure>,
    ) {
        // Keep the actual first outcome before the independent observation.
        self.first = started.err();
        self.post = post().err();
    }

    fn has_failure(&self) -> bool {
        self.first.is_some() || self.post.is_some()
    }
}

impl std::fmt::Display for DispatcherStartupHistory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.first, &self.post) {
            (Some(first), Some(post)) => {
                write!(formatter, "{first}; independent startup post: {post}")
            }
            (Some(first), None) => write!(formatter, "{first}"),
            (None, Some(post)) => write!(formatter, "{post}"),
            (None, None) => Ok(()),
        }
    }
}

/// Borrows one actual control-return slot under an unforgeable local epoch.
pub(super) struct TargetWatchJob {
    state: Arc<DispatcherState>,
    epoch: u64,
    index: usize,
    released: bool,
}

pub(super) enum TargetJobSubmitError {
    Unsubmitted {
        control: LinuxQemuCgroupControl,
        source: LinuxQemuCgroupError,
    },
    Staged {
        job: TargetWatchJob,
        source: LinuxQemuCgroupError,
    },
}

/// Closes the exact returned descriptors before permitting another job.
pub(super) struct TargetReturnedControl {
    control: Option<LinuxQemuCgroupControl>,
    original: Option<TargetWatcherOriginal>,
    job: Option<TargetWatchJob>,
}

impl Drop for TargetReturnedControl {
    fn drop(&mut self) {
        drop(self.control.take());
        drop(self.original.take());
        if let Some(mut job) = self.job.take() {
            job.released = true;
            drop(job);
        }
    }
}

impl std::fmt::Debug for TargetWatchJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetWatchJob")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for TargetDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetDispatcher")
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl TargetDispatcher {
    pub(crate) fn control_peak(capacity: usize) -> Option<u64> {
        if capacity == 0 {
            return None;
        }
        let slots = std::alloc::Layout::array::<JobSlot>(capacity).ok()?;
        let running = std::alloc::Layout::array::<Option<RunningJob>>(capacity).ok()?;
        let events = std::alloc::Layout::array::<epoll::Event>(capacity.checked_add(1)?).ok()?;
        let (state, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<DispatcherState>())
        .ok()?;
        u64::try_from(state.pad_to_align().size())
            .ok()?
            .checked_add(u64::try_from(std::mem::size_of::<Self>()).ok()?)?
            .checked_add(u64::try_from(std::mem::size_of::<thread::Builder>()).ok()?)?
            .checked_add(4 * 4096)?
            .checked_add(u64::try_from(slots.size()).ok()?)?
            .checked_add(u64::try_from(running.size()).ok()?)?
            .checked_add(u64::try_from(events.size()).ok()?)?
            .checked_add(RUNTIME_CONTROL_OVERLAP)
    }

    pub(crate) fn reserved(purpose: AuthenticatedTargetDispatcherPurpose, capacity: usize) -> Self {
        Self {
            purpose: Some(purpose),
            capacity,
            state: None,
            worker: None,
            worker_born: false,
            failed: false,
            cleanup: None,
            phase: WorkerPhase::Reserved,
            worker_panic: Mutex::new(None),
            startup_history: DispatcherStartupHistory::default(),
            join_observations: [(None, None); 2],
            path: PathBuf::from("/"),
        }
    }

    pub(crate) fn purpose(&self) -> Option<&AuthenticatedTargetDispatcherPurpose> {
        self.purpose.as_ref()
    }

    /// Reuses the exact occupied slot when its caller facade has disappeared.
    fn retry_abandoned_jobs(&mut self) -> Result<(), LinuxQemuCgroupError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };
        let mut first_failure = None;
        for index in 0..self.capacity {
            let epoch = {
                let mut slots = match state.slots.try_lock() {
                    Ok(slots) => slots,
                    Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
                    Err(TryLockError::WouldBlock) => {
                        return Err(failure(&state.path, "Target abandoned custody is pending"));
                    }
                };
                let Some(slot) = slots.get_mut(index) else {
                    return Err(failure(&state.path, "Target abandoned slot is absent"));
                };
                if slot.facade_live || slot.phase == JobPhase::Idle {
                    continue;
                }
                // The private slot and epoch are the retained owner. This new
                // facade neither issues a job nor authorizes physical work.
                slot.facade_live = true;
                slot.epoch
            };
            let job = TargetWatchJob {
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
            }
        }
        match first_failure {
            Some(source) => Err(source),
            None => Ok(()),
        }
    }

    /// Starts the single paid worker while retaining every partial owner.
    ///
    /// # Errors
    /// Refuses prior birth, stale payer, or actual descriptor/thread failures.
    pub(crate) fn start(&mut self, root: &LinuxQemuCgroupRoot) -> Result<(), LinuxQemuCgroupError> {
        if self.phase != WorkerPhase::Reserved
            || self.failed
            || self.worker.is_some()
            || self.state.is_some()
        {
            return Err(failure(
                &root.path,
                "Target dispatcher is occupied or failed",
            ));
        }
        self.failed = true;
        self.path = root.path.clone();
        self.purpose
            .as_ref()
            .ok_or_else(|| failure(&root.path, "Target dispatcher payer is absent"))?
            .check()
            .map_err(|source| failure(&root.path, source))?;
        let namespace = duplicate_fd(
            root.directory.as_raw_fd(),
            "retain Target dispatcher namespace lock",
            &root.path,
        )?;
        let wake = rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )
        .map_err(|source| failure(&root.path, source))?;
        let readiness = epoll::create(epoll::CreateFlags::CLOEXEC)
            .map_err(|source| failure(&root.path, source))?;
        epoll::add(
            &readiness,
            &wake,
            epoll::EventData::new_u64(0),
            epoll::EventFlags::IN,
        )
        .map_err(|source| failure(&root.path, source))?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(self.capacity)
            .map_err(|source| failure(&root.path, source))?;
        slots.resize_with(self.capacity, || JobSlot {
            epoch: 0,
            phase: JobPhase::Idle,
            control: None,
            original: None,
            cancel_requested: false,
            failure: None,
            failure_reported: false,
            facade_live: false,
            next_retry: HostRetryCadence::default(),
        });
        let mut running = Vec::new();
        running
            .try_reserve_exact(self.capacity)
            .map_err(|source| failure(&root.path, source))?;
        running.resize_with(self.capacity, || None);
        let event_capacity = self
            .capacity
            .checked_add(1)
            .ok_or_else(|| failure(&root.path, "Target event geometry overflow"))?;
        self.state = Some(Arc::new(DispatcherState {
            slots: Mutex::new(slots),
            running: Mutex::new(running),
            readiness,
            shutdown: AtomicBool::new(false),
            worker_exited: AtomicBool::new(false),
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
        self.worker_born = true;
        // EventData is intentionally thread-local. Only its paid scalar
        // geometry crosses spawn; startup waits for the actual allocation.
        let started = self.wait_for_worker_startup();
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
        self.phase = WorkerPhase::Running;
        self.failed = false;
        Ok(())
    }

    /// Borrows the actual saved Target Preparation until its worker is ready.
    fn wait_for_worker_startup(&self) -> Result<(), DispatcherStartupFailure> {
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
    }

    /// Retires the actual queue, worker and window under one saved Cleanup.
    ///
    /// # Errors
    /// Retains live jobs, aliases, expired Cleanup, failed join or window close.
    pub(crate) fn finish(&mut self) -> Result<(), LinuxQemuCgroupError> {
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
                    drop(self.worker.take());
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
    }

    /// Observes actual resource closure independently of retirement history.
    pub(crate) fn is_physically_retired(&self) -> bool {
        self.state.is_none()
            && self.worker.is_none()
            && self
                .purpose
                .as_ref()
                .is_some_and(|purpose| purpose.is_physically_retired())
    }

    /// Borrows the actual join payload through containing-factory retirement.
    pub(crate) fn worker_panic(&mut self) -> Option<&(dyn std::any::Any + Send)> {
        // Exclusive access needs no wait. Poison cannot discard diagnostic
        // custody or turn history into a physical-return decision.
        let history = match self.worker_panic.get_mut() {
            Ok(history) => history,
            Err(poison) => poison.into_inner(),
        };
        history.as_deref()
    }

    fn report_retirement_history(&mut self) -> Result<(), LinuxQemuCgroupError> {
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
    }

    /// Transfers one authentic Target incarnation into the fixed job slot.
    ///
    /// # Errors
    /// Returns unstaged control or the same staged job on admission/wake failure.
    pub(super) fn submit(
        &mut self,
        control: LinuxQemuCgroupControl,
        original: TargetWatcherOriginal,
    ) -> Result<TargetWatchJob, TargetJobSubmitError> {
        let checked = self
            .purpose
            .as_ref()
            .ok_or_else(|| failure(&control.path, "Target dispatcher payer is absent"))
            .and_then(|purpose| {
                purpose
                    .verify_original(original.operation())
                    .map_err(|source| failure(&control.path, source))
            })
            .and_then(|()| {
                verify_directory_identity(
                    &control.parent_directory,
                    &control.name,
                    &control.directory,
                    &control.path,
                )?;
                original
                    .verify_control(&control.parent_directory, &control.directory)
                    .map_err(|source| failure(&control.path, source))
            });
        if let Err(source) = checked {
            return Err(TargetJobSubmitError::Unsubmitted { control, source });
        }
        let Some(state) = self.state.as_ref() else {
            let source = failure(&control.path, "Target dispatcher has no actual worker");
            return Err(TargetJobSubmitError::Unsubmitted { control, source });
        };
        if self.failed
            || state.shutdown.load(Ordering::Acquire)
            || self.worker.is_none()
            || state.worker_exited.load(Ordering::Acquire)
        {
            let source = failure(&control.path, "Target dispatcher is retired or failed");
            return Err(TargetJobSubmitError::Unsubmitted { control, source });
        }
        let Ok(mut slots) = state.slots.lock() else {
            let source = failure(&control.path, "Target job custody is poisoned");
            return Err(TargetJobSubmitError::Unsubmitted { control, source });
        };
        let Some((index, slot)) = slots.iter_mut().enumerate().find(|(_, slot)| {
            slot.phase == JobPhase::Idle && slot.control.is_none() && slot.original.is_none()
        }) else {
            let source = failure(
                &control.path,
                "All paid Target slots still own actual incarnations",
            );
            return Err(TargetJobSubmitError::Unsubmitted { control, source });
        };
        let Some(epoch) = slot.epoch.checked_add(1) else {
            let source = failure(&control.path, "Target job epoch is exhausted");
            return Err(TargetJobSubmitError::Unsubmitted { control, source });
        };
        slot.epoch = epoch;
        slot.cancel_requested = false;
        slot.failure = None;
        slot.failure_reported = false;
        slot.facade_live = true;
        slot.next_retry = HostRetryCadence::default();
        slot.original = Some(original);
        slot.control = Some(control);
        slot.phase = JobPhase::Queued;
        let job = TargetWatchJob {
            state: Arc::clone(state),
            epoch,
            index,
            released: false,
        };
        drop(slots);
        // The nominal job and real control are retained before a wake can fail.
        if let Err(source) = wake(&state.wake) {
            self.failed = true;
            return Err(TargetJobSubmitError::Staged {
                job,
                source: failure(&state.path, source),
            });
        }
        Ok(job)
    }
}

fn failure(path: &Path, source: impl std::fmt::Display) -> LinuxQemuCgroupError {
    LinuxQemuCgroupError::Io {
        operation: "maintain actual Target dispatcher",
        path: path.to_owned(),
        source: io::Error::other(source.to_string()),
    }
}

fn wake(fd: &OwnedFd) -> Result<(), io::Error> {
    rustix::io::write(fd, &1_u64.to_ne_bytes())
        .map(|_| ())
        .map_err(Into::into)
}

fn drain_wake(fd: &OwnedFd) {
    let mut value = [0_u8; 8];
    let _observed = rustix::io::read(fd, &mut value);
}

/// Retains actual initiating and independent phase/control failures per node.
/// A physical empty observation cannot erase any of these causes.
#[derive(Default)]
struct JobFailure {
    original: Option<crate::OriginalActorAccountError>,
    control: Option<LinuxQemuCgroupError>,
    poller: Option<LinuxQemuCgroupError>,
    cadence: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    after: Option<crate::OriginalActorAccountError>,
    panicked: bool,
}

impl std::fmt::Display for JobFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Target phase {:?}; physical control {:?}; poller {:?}; retry cadence {:?}; independent phase {:?}; panic {}",
            self.original, self.control, self.poller, self.cadence, self.after, self.panicked
        )
    }
}

/// Owns controls outside the queue mutex during polling and physical effects.
struct RunningJob {
    epoch: u64,
    control: LinuxQemuCgroupControl,
    original: Option<TargetWatcherOriginal>,
    draining: bool,
    failure: Option<JobFailure>,
    next_attempt: HostRetryCadence,
}

/// Publishes loss of the sole worker on every normal return and unwind.
struct WorkerExit<'a>(&'a AtomicBool);

impl Drop for WorkerExit<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl RunningJob {
    fn wait_slice(&mut self) -> Result<(Duration, bool), crate::OriginalActorAccountError> {
        match self.original.as_mut() {
            Some(original) => original.wait_slice(self.draining),
            // Only the explicitly unissued component mechanism uses no witness.
            // Production submit requires a genuine TargetWatcherOriginal.
            None => Ok((WATCHER_WAIT_POLL_INTERVAL, true)),
        }
    }
}

fn register_target_event(
    state: &DispatcherState,
    index: usize,
    control: &LinuxQemuCgroupControl,
) -> Result<(), rustix::io::Errno> {
    epoll::add(
        &state.readiness,
        &control.cancellation_event,
        epoll::EventData::new_u64(index as u64 + 1),
        epoll::EventFlags::IN | epoll::EventFlags::ONESHOT,
    )
}

fn return_job(state: &DispatcherState, index: usize, entry: &mut Option<RunningJob>) -> bool {
    let Some(job) = entry.as_mut() else {
        return false;
    };
    // Remove kernel interest before closing or recycling its numeric key.
    if let Err(source) = epoll::delete(&state.readiness, &job.control.cancellation_event) {
        job.failure
            .get_or_insert_default()
            .poller
            .get_or_insert_with(|| failure(&job.control.path, source));
    }
    let Ok(mut slots) = state.slots.lock() else {
        return false;
    };
    let Some(slot) = slots.get_mut(index).filter(|slot| {
        slot.epoch == job.epoch
            && slot.phase == JobPhase::Running
            && slot.control.is_none()
            && slot.original.is_none()
    }) else {
        return false;
    };
    let Some(job) = entry.take() else {
        return false;
    };
    slot.control = Some(job.control);
    slot.original = job.original;
    slot.failure = job.failure;
    slot.next_retry = job.next_attempt;
    slot.phase = if slot.failure.is_some() {
        JobPhase::Quarantined
    } else {
        JobPhase::Returned
    };
    if let Some(control) = slot.control.as_ref() {
        control
            .watcher_state
            .store(WATCHER_TERMINAL, Ordering::Release);
        let _notice = wake(&control.cancellation_event);
    }
    true
}

/// Reads the worker's actual once-published allocation outcome.
fn worker_startup_ready(state: &DispatcherState) -> Result<bool, DispatcherStartupFailure> {
    let startup = state.startup.lock().map_err(|_| {
        DispatcherStartupFailure::Custody("Target worker startup custody is poisoned")
    })?;
    match startup.as_ref() {
        Some(Ok(())) => Ok(true),
        Some(Err(source)) => Err(DispatcherStartupFailure::Allocation(source.clone())),
        None => Ok(false),
    }
}

fn run(state: Arc<DispatcherState>, event_capacity: usize) {
    let _exit = WorkerExit(&state.worker_exited);
    let mut events: Vec<epoll::Event> = Vec::new();
    let allocation = events.try_reserve_exact(event_capacity);
    let allocated = allocation.is_ok();
    {
        let Ok(mut startup) = state.startup.lock() else {
            return;
        };
        *startup = Some(allocation);
    }
    if !allocated {
        return;
    }
    loop {
        // The shared containing array retains actual controls on panic or
        // poison. The Main factory can inspect/reconcile these same cells;
        // worker-local destruction never substitutes for physical return.
        let Ok(mut running) = state.running.lock() else {
            return;
        };
        {
            let Ok(mut slots) = state.slots.lock() else {
                return;
            };
            for (index, slot) in slots.iter_mut().enumerate() {
                if let Some(job) = running[index].as_mut() {
                    job.draining |= slot.cancel_requested;
                }
                if slot.phase != JobPhase::Queued {
                    continue;
                }
                let Some(control) = slot.control.take() else {
                    return;
                };
                if let Err(source) = register_target_event(&state, index, &control) {
                    slot.failure = Some(JobFailure {
                        control: Some(failure(&control.path, source)),
                        ..JobFailure::default()
                    });
                    slot.control = Some(control);
                    slot.phase = JobPhase::Quarantined;
                    continue;
                }
                slot.phase = JobPhase::Running;
                running[index] = Some(RunningJob {
                    epoch: slot.epoch,
                    control,
                    original: slot.original.take(),
                    draining: false,
                    failure: None,
                    next_attempt: HostRetryCadence::default(),
                });
            }
        }
        let shutting_down = state.shutdown.load(Ordering::Acquire);
        let mut timeout = WATCHER_WAIT_POLL_INTERVAL;
        for (index, entry) in running.iter_mut().enumerate() {
            let Some(job) = entry.as_mut() else {
                continue;
            };
            job.draining |= shutting_down;
            if !job.draining {
                match job.wait_slice() {
                    Ok((slice, _)) => timeout = timeout.min(slice),
                    Err(source) => {
                        job.failure.get_or_insert_default().original = Some(source);
                        job.draining = true;
                    }
                }
            }
            if !job.draining {
                continue;
            }
            timeout = timeout.min(CGROUP_KILL_INTERVAL);
            // Enter/check this exact Target's already-retained Cleanup before
            // every nonblocking physical pass. No per-node sleep can block peers.
            match job.wait_slice() {
                Ok((slice, true)) => timeout = timeout.min(slice),
                Ok((slice, false)) => {
                    timeout = timeout.min(slice);
                    continue;
                }
                Err(source) => {
                    job.failure.get_or_insert_default().after = Some(source);
                    if !return_job(&state, index, entry) {
                        return;
                    }
                    continue;
                }
            }
            // Readiness from another node must not accelerate this node's
            // retry cadence. This scheduling timestamp grants no work budget:
            // the same retained Cleanup was checked above and is checked after.
            let delay = match job.next_attempt.poll(CGROUP_KILL_INTERVAL) {
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
            }
            let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                job.control.kill_members()?;
                job.control.is_populated()
            }));
            // The independent postcheck runs even after syscall refusal/panic.
            let after = job.wait_slice();
            let populated = match attempted {
                Ok(Ok(populated)) => Some(populated),
                Ok(Err(source)) => {
                    job.failure.get_or_insert_default().control = Some(source);
                    None
                }
                Err(_) => {
                    job.failure.get_or_insert_default().panicked = true;
                    None
                }
            };
            if let Err(source) = after {
                job.failure.get_or_insert_default().after = Some(source);
            }
            if (populated == Some(false)
                || populated.is_none()
                || job
                    .failure
                    .as_ref()
                    .is_some_and(|failure| failure.after.is_some()))
                && !return_job(&state, index, entry)
            {
                return;
            }
        }
        if shutting_down && running.iter().all(Option::is_none) {
            return;
        }
        let timeout = rustix::time::Timespec {
            tv_sec: timeout.as_secs() as i64,
            tv_nsec: i64::from(timeout.subsec_nanos()),
        };
        drop(running);
        events.clear();
        match epoll::wait(
            &state.readiness,
            rustix::buffer::spare_capacity(&mut events),
            Some(&timeout),
        ) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(source) => {
                {
                    let mut slots = match state.slots.lock() {
                        Ok(slots) => slots,
                        Err(poison) => poison.into_inner(),
                    };
                    for slot in slots
                        .iter_mut()
                        .filter(|slot| slot.phase == JobPhase::Queued)
                    {
                        slot.failure
                            .get_or_insert_default()
                            .poller
                            .get_or_insert_with(|| failure(&state.path, source));
                    }
                }
                let Ok(mut running) = state.running.lock() else {
                    return;
                };
                for (index, entry) in running.iter_mut().enumerate() {
                    if let Some(job) = entry.as_mut() {
                        job.failure.get_or_insert_default().poller =
                            Some(failure(&job.control.path, source));
                        if !return_job(&state, index, entry) {
                            return;
                        }
                    }
                }
                return;
            }
        }
        let Ok(mut running) = state.running.lock() else {
            return;
        };
        for event in &events {
            let key = event.data.u64();
            if key == 0 {
                drain_wake(&state.wake);
                continue;
            }
            let Some(index) = key.checked_sub(1).and_then(|key| usize::try_from(key).ok()) else {
                return;
            };
            // Quarantined interest may survive a failed delete. That slot never
            // recycles its epoch, and cannot donate its event to another node.
            if let Some(job) = running.get_mut(index).and_then(Option::as_mut) {
                job.draining = true;
            }
        }
    }
}

/// Performs one physical retry under the same Target's saved Cleanup.
fn retry_quarantined(
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
}

impl TargetWatchJob {
    pub(super) fn is_finished(&self) -> bool {
        let slots = match self.state.slots.try_lock() {
            Ok(slots) => slots,
            Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(TryLockError::WouldBlock) => return false,
        };
        slots.get(self.index).is_some_and(|slot| {
            slot.epoch == self.epoch
                && ((matches!(slot.phase, JobPhase::Returned | JobPhase::Quarantined)
                    && slot.control.is_some())
                    || (matches!(slot.phase, JobPhase::Running | JobPhase::Queued)
                        && (self.state.worker_exited.load(Ordering::Acquire)
                            || self.state.running.is_poisoned())))
        })
    }

    /// Recovers only this exact retained cell after worker exit or unwind.
    fn recover_abandoned_job(&self) -> Result<(), LinuxQemuCgroupError> {
        let exited = self.state.worker_exited.load(Ordering::Acquire);
        let poisoned = self.state.running.is_poisoned();
        if !exited && !poisoned {
            return Ok(());
        }
        let mut running = match self.state.running.try_lock() {
            Ok(running) => running,
            Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(failure(
                    &self.state.path,
                    "Target worker custody is pending",
                ));
            }
        };
        let mut slots = match self.state.slots.try_lock() {
            Ok(slots) => slots,
            Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(failure(
                    &self.state.path,
                    "Target return custody is pending",
                ));
            }
        };
        let slot = slots
            .get_mut(self.index)
            .filter(|slot| slot.epoch == self.epoch)
            .ok_or_else(|| failure(&self.state.path, "Target poisoned return epoch is stale"))?;
        if slot.phase == JobPhase::Queued && exited {
            if slot.control.is_none() || running.get(self.index).is_none_or(Option::is_some) {
                return Err(failure(
                    &self.state.path,
                    "Target queued ownership does not match",
                ));
            }
            slot.failure
                .get_or_insert_default()
                .poller
                .get_or_insert_with(|| {
                    failure(
                        &self.state.path,
                        "Target worker exited before queued control dispatch",
                    )
                });
            slot.phase = JobPhase::Quarantined;
            slot.failure_reported = false;
            return Ok(());
        }
        if slot.phase != JobPhase::Running {
            return Ok(());
        }
        let entry = running
            .get_mut(self.index)
            .ok_or_else(|| failure(&self.state.path, "Target poisoned running cell is absent"))?;
        if slot.control.is_some()
            || slot.original.is_some()
            || entry.as_ref().is_none_or(|job| job.epoch != self.epoch)
        {
            return Err(failure(
                &self.state.path,
                "Target poisoned ownership does not match",
            ));
        }
        // Worker exit or mutex poison proves the worker released this borrow.
        // Move the actual controls, never a reconstruction, into their same cell.
        if let Some(mut job) = entry.take() {
            if poisoned {
                job.failure.get_or_insert_default().panicked = true;
            } else {
                job.failure
                    .get_or_insert_default()
                    .poller
                    .get_or_insert_with(|| {
                        failure(
                            &self.state.path,
                            "Target worker exited with retained control",
                        )
                    });
            }
            slot.control = Some(job.control);
            slot.original = job.original;
            slot.failure = job.failure;
            slot.next_retry = job.next_attempt;
            slot.phase = JobPhase::Quarantined;
            slot.failure_reported = false;
        }
        Ok(())
    }

    pub(super) fn retire(self) -> Result<TargetReturnedControl, (Self, LinuxQemuCgroupError)> {
        if let Err(source) = self.recover_abandoned_job() {
            return Err((self, source));
        }
        let state = Arc::clone(&self.state);
        let mut slots = match state.slots.try_lock() {
            Ok(slots) => slots,
            Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err((self, failure(&state.path, "Target job return is pending")));
            }
        };
        let Some(slot) = slots.get_mut(self.index) else {
            let source = failure(&state.path, "Target job slot is absent");
            drop(slots);
            return Err((self, source));
        };
        if slot.epoch == self.epoch && slot.phase == JobPhase::Quarantined {
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
        let Some(control) = slot.control.take() else {
            let source = failure(&state.path, "Target returned control is absent");
            drop(slots);
            return Err((self, source));
        };
        // Keep the slot unavailable until its exact control and original leave
        // the dispatcher's body. The caller owns the returned control through
        // its actual descriptor close; this job's final release follows below.
        let original = slot.original.take();
        slot.phase = JobPhase::Retiring;
        drop(slots);
        Ok(TargetReturnedControl {
            control: Some(control),
            original,
            job: Some(self),
        })
    }
}

impl Drop for TargetWatchJob {
    fn drop(&mut self) {
        if self.released {
            let mut slots = match self.state.slots.lock() {
                Ok(slots) => slots,
                Err(poison) => poison.into_inner(),
            };
            if let Some(slot) = slots.get_mut(self.index).filter(|slot| {
                slot.epoch == self.epoch
                    && slot.phase == JobPhase::Retiring
                    && slot.control.is_none()
                    && slot.original.is_none()
            }) {
                slot.phase = JobPhase::Idle;
                slot.facade_live = false;
            }
        } else {
            {
                let mut slots = match self.state.slots.lock() {
                    Ok(slots) => slots,
                    Err(poison) => poison.into_inner(),
                };
                if let Some(slot) = slots
                    .get_mut(self.index)
                    .filter(|slot| slot.epoch == self.epoch)
                {
                    slot.facade_live = false;
                    slot.cancel_requested = true;
                    if let Some(control) = slot.control.as_ref() {
                        let _signal = signal_terminal(
                            &control.watcher_state,
                            control.cancellation_event.as_raw_fd(),
                        );
                    }
                }
            }
            let _wake = wake(&self.state.wake);
            // The containing dispatcher already owns these exact cells. This
            // facade's disappearance cannot free a slot, but retaining an extra
            // inaccessible Arc would obstruct every later exclusive close.
        }
    }
}

impl Drop for TargetDispatcher {
    fn drop(&mut self) {
        if let Some(state) = self.state.as_ref() {
            state.shutdown.store(true, Ordering::Release);
            let _signal = wake(&state.wake);
        }
        // Drop never invents a wait or new deadline. Explicit finish owns real
        // join; otherwise these actual owners remain paid until Main exits.
        std::mem::forget(self.worker.take());
        std::mem::forget(self.state.take());
        std::mem::forget(self.purpose.take());
        std::mem::forget(self.cleanup.take());
    }
}

#[cfg(test)]
mod tests;
