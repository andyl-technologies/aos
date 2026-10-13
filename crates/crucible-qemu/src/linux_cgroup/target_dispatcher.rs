//! Reuses one Main-prepaid watcher through separately retired Target jobs.
//!
//! A job owns its actual cgroup controls and same original operation. Returning
//! those controls closes that job only; the permanent worker and its original
//! task/stack/control debit remain retained across all later campaigns.

use super::*;
use crate::linux_attempt_host::TargetWatcherOriginal;
use crucible_linux_resource::host_services::process_birth::AuthenticatedTargetDispatcherPurpose;
use crucible_linux_resource::host_supervision::HostOperationGuard;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

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
}

struct DispatcherState {
    slot: Mutex<JobSlot>,
    shutdown: AtomicBool,
    wake: OwnedFd,
    _namespace: OwnedFd,
    path: PathBuf,
}

/// Holds the physical worker and external Main payer through real join.
pub(crate) struct TargetDispatcher {
    purpose: Option<AuthenticatedTargetDispatcherPurpose>,
    state: Option<Arc<DispatcherState>>,
    worker: Option<JoinHandle<()>>,
    failed: bool,
    cleanup: Option<HostOperationGuard>,
    phase: WorkerPhase,
    join_panicked: bool,
    path: PathBuf,
}

/// Borrows one actual control-return slot under an unforgeable local epoch.
pub(super) struct TargetWatchJob {
    state: Arc<DispatcherState>,
    epoch: u64,
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
    pub(crate) fn control_peak() -> Option<u64> {
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
            .checked_add(RUNTIME_CONTROL_OVERLAP)
    }

    pub(crate) fn reserved(purpose: AuthenticatedTargetDispatcherPurpose) -> Self {
        Self {
            purpose: Some(purpose),
            state: None,
            worker: None,
            failed: false,
            cleanup: None,
            phase: WorkerPhase::Reserved,
            join_panicked: false,
            path: PathBuf::from("/"),
        }
    }

    pub(crate) fn purpose(&self) -> Option<&AuthenticatedTargetDispatcherPurpose> {
        self.purpose.as_ref()
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
        self.state = Some(Arc::new(DispatcherState {
            slot: Mutex::new(JobSlot {
                epoch: 0,
                phase: JobPhase::Idle,
                control: None,
                original: None,
            }),
            shutdown: AtomicBool::new(false),
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
            .spawn_worker("crucible-target-dispatcher", move || run(state))
            .map_err(|source| failure(&root.path, source))?;
        self.worker = Some(worker);
        self.phase = WorkerPhase::Running;
        self.failed = false;
        Ok(())
    }

    /// Retires the actual queue, worker and window under one saved Cleanup.
    ///
    /// # Errors
    /// Retains live jobs, aliases, expired Cleanup, failed join or window close.
    pub(crate) fn finish(&mut self) -> Result<(), LinuxQemuCgroupError> {
        if self.phase == WorkerPhase::Complete {
            return Ok(());
        }
        let path = self.path.clone();
        if matches!(self.phase, WorkerPhase::Reserved | WorkerPhase::Running) {
            if let Some(state) = self.state.as_ref() {
                let slot = state
                    .slot
                    .lock()
                    .map_err(|_| failure(&path, "Target job retirement is poisoned"))?;
                if slot.phase != JobPhase::Idle || slot.control.is_some() || slot.original.is_some()
                {
                    return Err(failure(
                        &path,
                        "Target dispatcher still owns an actual job or returned control",
                    ));
                }
            }
        }
        if self.cleanup.is_none() {
            self.cleanup = Some(
                self.purpose
                    .as_ref()
                    .ok_or_else(|| failure(&path, "Target dispatcher payer is absent"))?
                    .begin_cleanup()
                    .map_err(|source| failure(&path, source))?,
            );
        }
        let cleanup = self
            .cleanup
            .as_ref()
            .ok_or_else(|| failure(&path, "Target dispatcher Cleanup is absent"))?;
        cleanup
            .wait_slice()
            .map_err(|source| failure(&path, source))?;

        if matches!(self.phase, WorkerPhase::Reserved | WorkerPhase::Running) {
            if let Some(state) = self.state.as_ref() {
                state.shutdown.store(true, Ordering::Release);
                wake(&state.wake).map_err(|source| failure(&path, source))?;
            }
            while self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
            {
                let slice = cleanup
                    .wait_slice()
                    .map_err(|source| failure(&path, source))?;
                thread::sleep(slice.min(WATCHER_WAIT_POLL_INTERVAL));
            }
            cleanup
                .wait_slice()
                .map_err(|source| failure(&path, source))?;
            if let Some(state) = self.state.as_mut() {
                Arc::get_mut(state).ok_or_else(|| {
                    failure(&path, "Target dispatcher has surviving queue aliases")
                })?;
            }
            // This physical close is irreversible. Retry retains the same
            // finished handle and Cleanup, without reconstructing a queue.
            drop(self.state.take());
            self.phase = WorkerPhase::QueueClosed;
        }
        if self.phase == WorkerPhase::QueueClosed {
            if let Some(worker) = self.worker.take() {
                let joined = self
                    .purpose
                    .as_mut()
                    .ok_or_else(|| failure(&path, "Target dispatcher payer is absent"))?
                    .try_join_worker(worker);
                match joined {
                    Ok(joined) => self.join_panicked = joined.is_err(),
                    Err((worker, source)) => {
                        self.worker = Some(worker);
                        return Err(failure(&path, source));
                    }
                }
            }
            self.phase = WorkerPhase::Joined;
        }
        self.purpose
            .as_mut()
            .ok_or_else(|| failure(&path, "Target dispatcher payer is absent"))?
            .retire_worker_debits()
            .map_err(|source| failure(&path, source))?;
        if self.join_panicked {
            self.failed = true;
            return Err(failure(
                &path,
                "Target dispatcher physically joined after worker panic",
            ));
        }
        cleanup
            .wait_slice()
            .map_err(|source| failure(&path, source))?;
        cleanup
            .complete()
            .map_err(|source| failure(&path, source))?;
        self.cleanup = None;
        self.purpose = None;
        self.phase = WorkerPhase::Complete;
        Ok(())
    }

    /// Transfers one authentic Target incarnation into the fixed job slot.
    ///
    /// # Errors
    /// Returns unstaged control or the same staged job on admission/wake failure.
    pub(crate) fn submit(
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
            || self.worker.as_ref().is_none_or(JoinHandle::is_finished)
        {
            let source = failure(&control.path, "Target dispatcher is retired or failed");
            return Err(TargetJobSubmitError::Unsubmitted { control, source });
        }
        let Ok(mut slot) = state.slot.lock() else {
            let source = failure(&control.path, "Target job custody is poisoned");
            return Err(TargetJobSubmitError::Unsubmitted { control, source });
        };
        if slot.phase != JobPhase::Idle || slot.control.is_some() || slot.original.is_some() {
            let source = failure(
                &control.path,
                "Target job slot still owns another incarnation",
            );
            return Err(TargetJobSubmitError::Unsubmitted { control, source });
        }
        let Some(epoch) = slot.epoch.checked_add(1) else {
            let source = failure(&control.path, "Target job epoch is exhausted");
            return Err(TargetJobSubmitError::Unsubmitted { control, source });
        };
        slot.epoch = epoch;
        slot.original = Some(original);
        slot.control = Some(control);
        slot.phase = JobPhase::Queued;
        let job = TargetWatchJob {
            state: Arc::clone(state),
            epoch,
            released: false,
        };
        drop(slot);
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

fn run(state: Arc<DispatcherState>) {
    loop {
        let next = {
            let Ok(mut slot) = state.slot.lock() else {
                return;
            };
            if slot.phase == JobPhase::Queued {
                slot.phase = JobPhase::Running;
                slot.control.take().map(|control| (slot.epoch, control))
            } else {
                None
            }
        };
        if let Some((epoch, mut control)) = next {
            let attempted = run_cgroup_watcher_attempt(|| serve(&state, &mut control));
            let Ok(mut slot) = state.slot.lock() else {
                std::mem::forget(control);
                return;
            };
            if slot.epoch != epoch || slot.phase != JobPhase::Running {
                std::mem::forget(control);
                return;
            }
            slot.control = Some(control);
            match attempted {
                LinuxQemuCgroupWatcherAttempt::Closed => slot.phase = JobPhase::Returned,
                _ => slot.phase = JobPhase::Quarantined,
            }
            let returned = slot.phase == JobPhase::Returned;
            if let Some(control) = slot.control.as_ref() {
                control
                    .watcher_state
                    .store(WATCHER_TERMINAL, Ordering::Release);
                let _notice = wake(&control.cancellation_event);
            }
            drop(slot);
            if !returned {
                loop {
                    thread::park();
                }
            }
        }
        if state.shutdown.load(Ordering::Acquire) {
            return;
        }
        let mut poll = [rustix::event::PollFd::new(
            &state.wake,
            rustix::event::PollFlags::IN,
        )];
        // A bounded poll also observes queued work when an eventfd wake failed.
        // It is worker responsiveness, not a replacement operation deadline.
        let timeout = rustix::time::Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        let _observed = rustix::event::poll(&mut poll, Some(&timeout));
        drain_wake(&state.wake);
    }
}

fn serve(
    state: &DispatcherState,
    control: &mut LinuxQemuCgroupControl,
) -> Result<(), LinuxQemuCgroupError> {
    loop {
        let mut poll = [
            rustix::event::PollFd::new(&state.wake, rustix::event::PollFlags::IN),
            rustix::event::PollFd::new(&control.cancellation_event, rustix::event::PollFlags::IN),
        ];
        rustix::event::poll(&mut poll, None).map_err(|source| failure(&control.path, source))?;
        if state.shutdown.load(Ordering::Acquire) || !poll[1].revents().is_empty() {
            break;
        }
        drain_wake(&state.wake);
    }
    loop {
        match control.kill_members().and_then(|_| control.is_populated()) {
            Ok(false) => return Ok(()),
            Ok(true) | Err(_) => thread::sleep(CGROUP_KILL_INTERVAL),
        }
    }
}

impl TargetWatchJob {
    pub(super) fn is_finished(&self) -> bool {
        self.state.slot.lock().is_ok_and(|slot| {
            slot.epoch == self.epoch && slot.phase == JobPhase::Returned && slot.control.is_some()
        })
    }

    pub(super) fn retire(self) -> Result<TargetReturnedControl, (Self, LinuxQemuCgroupError)> {
        let state = Arc::clone(&self.state);
        let Ok(mut slot) = state.slot.lock() else {
            let source = failure(&state.path, "Target job return is poisoned");
            return Err((self, source));
        };
        if slot.epoch != self.epoch || slot.phase != JobPhase::Returned {
            let source = failure(
                &state.path,
                "Target job has not returned its actual control",
            );
            drop(slot);
            return Err((self, source));
        }
        let Some(control) = slot.control.take() else {
            let source = failure(&state.path, "Target returned control is absent");
            drop(slot);
            return Err((self, source));
        };
        // Keep the slot unavailable until its exact control and original leave
        // the dispatcher's body. The caller owns the returned control through
        // its actual descriptor close; this job's final release follows below.
        let original = slot.original.take();
        slot.phase = JobPhase::Retiring;
        drop(slot);
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
            if let Ok(mut slot) = self.state.slot.lock() {
                if slot.epoch == self.epoch && slot.phase == JobPhase::Retiring {
                    slot.phase = JobPhase::Idle;
                }
            }
        } else {
            let _cancel = self.state.slot.lock().map(|slot| {
                if slot.epoch == self.epoch {
                    if let Some(control) = slot.control.as_ref() {
                        let _signal = signal_terminal(
                            &control.watcher_state,
                            control.cancellation_event.as_raw_fd(),
                        );
                    }
                }
            });
            let _wake = wake(&self.state.wake);
            // An uncertain facade cannot certify job retirement or free credit.
            std::mem::forget(Arc::clone(&self.state));
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
