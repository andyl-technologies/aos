//! Ordered device digests with retained startup, workspace and retirement custody.
//!
//! Source owns the production control allocation, pthread and physical workspace.
//! Actual byte loans cover each digest; Main returns detached material after
//! publication/ACK, and physical join precedes matched final Arc destruction.
//! Explicit fixtures retain their local thread and mapping lifecycle.

use std::any::Any;
#[cfg(test)]
use std::cell::UnsafeCell;
use std::fmt;
use std::sync::{Condvar, MutexGuard};
#[cfg(test)]
use std::thread;
#[cfg(test)]
use std::thread::JoinHandle;

use super::*;

mod pipeline_queue;
mod worker_outcome;

#[cfg(not(test))]
mod native;
#[cfg(not(test))]
pub(in crate::runtime) use native::SourceWorkerOwner;
#[cfg(test)]
use crate::device_digest_workspace::DeviceDigestWorkspace;
use crate::device_digest_workspace::DeviceDigestWorkspaceError;
use crate::fingerprint_sampler::FingerprintSamplerError;
use crate::ram_error::RamError;
use crate::runtime::worker_quiescence::{LiveWorkerQuiescence, WORKER_FINGERPRINT};

/// Keeps sampler errors typed until the already-entered control scope records them.
#[cfg(not(test))]
pub(super) enum FingerprintCaptureActionError {
    Sampler {
        boundary: &'static str,
        source: FingerprintSamplerError,
    },
    Worker(LiveVcpuTimeCallbackError),
}

#[cfg(not(test))]
impl From<LiveVcpuTimeCallbackError> for FingerprintCaptureActionError {
    fn from(source: LiveVcpuTimeCallbackError) -> Self {
        Self::Worker(source)
    }
}

struct LiveFingerprintDigestWork {
    captured: CapturedFingerprintSample,
    capture_request: u32,
    publication: MaterialPublication,
    #[cfg(not(test))]
    native_work: crate::fingerprint_native::WorkRef,
    #[cfg(not(test))]
    worker_work: crate::fingerprint_native::WorkRef,
    #[cfg(not(test))]
    workspace_address: usize,
    #[cfg(not(test))]
    workspace_length: usize,
    #[cfg(not(test))]
    work_returned: bool,
    #[cfg(not(test))]
    native_history: native::JobHistory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaterialPublication {
    NotStarted,
    Attempted,
    Published,
    AcknowledgementAttempted,
    Acknowledged,
}

impl LiveFingerprintDigestWork {
    fn new(captured: CapturedFingerprintSample, capture_request: u32) -> Self {
        Self {
            captured,
            capture_request,
            publication: MaterialPublication::NotStarted,
            #[cfg(not(test))]
            native_work: crate::fingerprint_native::WorkRef::empty(),
            #[cfg(not(test))]
            worker_work: crate::fingerprint_native::WorkRef::empty(),
            #[cfg(not(test))]
            workspace_address: 0,
            #[cfg(not(test))]
            workspace_length: 0,
            #[cfg(not(test))]
            work_returned: false,
            #[cfg(not(test))]
            native_history: native::JobHistory::default(),
        }
    }

    #[cfg(test)]
    fn publish(
        &mut self,
        slot: &FingerprintSampleSlot,
        sample: &crucible_qemu_shmem::FingerprintSample,
    ) -> Result<(), FingerprintWorkerCause> {
        if self.publication != MaterialPublication::NotStarted {
            return Err(FingerprintWorkerCause::UnsettledWork);
        }
        self.publication = MaterialPublication::Attempted;
        slot.publish(sample)
            .map_err(FingerprintWorkerCause::Publication)?;
        self.publication = MaterialPublication::Published;

        self.publication = MaterialPublication::AcknowledgementAttempted;
        if !slot.acknowledge_capture_v1(self.capture_request) {
            return Err(FingerprintWorkerCause::CaptureChanged {
                request: self.capture_request,
            });
        }
        self.publication = MaterialPublication::Acknowledged;
        Ok(())
    }
}

/// A publication failure retained in its original prepaid worker control.
///
/// Cloning this handle retains the same control; it never allocates a diagnostic
/// or extracts an owner. Outstanding handles prevent healthy reclamation.
#[derive(Clone)]
pub struct FingerprintWorkerFailure {
    control: Arc<FingerprintWorkerControl>,
}

impl fmt::Debug for FingerprintWorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.control.lock();
        let mut debug = formatter.debug_struct("FingerprintWorkerFailure");
        debug
            .field("primary", &state.failure)
            .field("cleanup", &state.cleanup_failure)
            .field("original", &state.supervision_failure);
        #[cfg(not(test))]
        debug
            .field("native", &state.native_failure)
            .field("entry_malfunction", &state.native_entry_failure)
            .field("submit", &state.native_submit_failure)
            .field("material_cleanup", &state.native_cleanup_failure)
            .field(
                "terminal_worker_observation",
                &state.native_terminal_observation_failure,
            )
            .field("module_action", &state.module_action_failure)
            .field("scope_return", &state.scope_return_failure)
            .field("sampler_action", &state.sampler_action_failure);
        drop(state);
        #[cfg(not(test))]
        for (index, slot) in self.control.jobs.iter().enumerate() {
            let job = match slot.try_lock() {
                Ok(job) => job,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    debug.field(if index == 0 { "job0" } else { "job1" }, &"borrowed");
                    continue;
                }
            };
            if let Some(job) = job.as_ref() {
                debug.field(
                    if index == 0 {
                        "job0_capture_request"
                    } else {
                        "job1_capture_request"
                    },
                    &job.capture_request,
                );
                debug.field(
                    if index == 0 { "job0" } else { "job1" },
                    &job.native_history,
                );
            }
        }
        #[cfg(not(test))]
        match self.control.capture_attempt.try_lock() {
            Ok(attempt) => {
                debug.field("prequeue_return", attempt.native_return_history());
            }
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                debug.field(
                    "prequeue_return",
                    poisoned.into_inner().native_return_history(),
                );
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                debug.field("prequeue_return", &"borrowed");
            }
        }
        debug.finish_non_exhaustive()
    }
}

impl fmt::Display for FingerprintWorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.control.lock();
        match state.failure.as_ref() {
            #[cfg(not(test))]
            Some(FingerprintWorkerCause::WorkerEntry) => match &state.native_entry_failure {
                Some(failure) => fmt::Display::fmt(&failure.cause, formatter),
                None => formatter.write_str("worker entry failed without a retained cause"),
            },
            Some(failure) => fmt::Display::fmt(failure, formatter),
            None => formatter.write_str("worker ownership remains unsettled"),
        }
    }
}

impl std::error::Error for FingerprintWorkerFailure {}

impl PartialEq for FingerprintWorkerFailure {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.control, &other.control)
    }
}

impl Eq for FingerprintWorkerFailure {}

#[derive(Debug, thiserror::Error)]
enum FingerprintWorkerCause {
    #[cfg(not(test))]
    #[error("worker entry failed")]
    WorkerEntry,
    #[cfg(not(test))]
    #[error("fingerprint capture request {capture_request} was canceled before publication")]
    CaptureCancelled { capture_request: u32 },
    #[cfg(not(test))]
    #[error("the retained worker module action failed")]
    ModuleAction,
    #[error("worker registration failed: {0}")]
    Registration(RamError),
    #[cfg(test)]
    #[error("worker workspace failed: {0}")]
    Workspace(DeviceDigestWorkspaceError),
    #[cfg(test)]
    #[error("worker creation failed: {0}")]
    Spawn(std::io::Error),
    #[cfg(not(test))]
    #[error("Source worker {operation} refused ({status})")]
    Native {
        operation: &'static str,
        status: i32,
    },
    #[error("device digest failed: {0}")]
    Digest(FingerprintSamplerError),
    #[error("fingerprint publication failed: {0}")]
    Publication(crucible_qemu_shmem::FingerprintSampleError),
    #[error("fingerprint capture request {request} changed before acknowledgement")]
    CaptureChanged { request: u32 },
    #[error("worker retains an unfinished captured material transaction")]
    UnsettledWork,
    #[error("worker panicked before joined retirement")]
    Panic,
    #[error("worker cleanup cannot establish unique ownership")]
    AliasedControl,
    #[error("the retained installing Source refused worker readiness")]
    Supervision,
}

struct FingerprintWorkerState {
    #[cfg(test)]
    pending: Option<LiveFingerprintDigestWork>,
    closed: bool,
    registered: bool,
    failure: Option<FingerprintWorkerCause>,
    cleanup_failure: Option<DeviceDigestWorkspaceError>,
    panic_payload: Option<Box<dyn Any + Send>>,
    supervision_failure: Option<crate::StartupSourceError>,
    #[cfg(not(test))]
    pipeline: pipeline_queue::PipelineQueue,
    #[cfg(not(test))]
    native_failure: Option<native::NativeFailure>,
    #[cfg(not(test))]
    native_entry_failure: Option<native::EntryFailure>,
    #[cfg(not(test))]
    native_submit_failure: Option<i32>,
    #[cfg(not(test))]
    native_terminal_observation_failure: Option<i32>,
    #[cfg(not(test))]
    native_cleanup_failure: Option<FingerprintSamplerError>,
    #[cfg(not(test))]
    module_action_failure: Option<LiveVcpuTimeCallbackError>,
    #[cfg(not(test))]
    terminal_failure_issued: bool,
    #[cfg(not(test))]
    scope_return_failure: Option<i32>,
    #[cfg(not(test))]
    sampler_action_failure: Option<(&'static str, FingerprintSamplerError)>,
}

struct FingerprintWorkerControl {
    state: Mutex<FingerprintWorkerState>,
    #[cfg(not(test))]
    native: Option<native::Context>,
    #[cfg(not(test))]
    capture_attempt: Mutex<crate::fingerprint_sampler::CaptureAttempt>,
    #[cfg(test)]
    workspace: Mutex<Option<DeviceDigestWorkspace>>,
    #[cfg(test)]
    in_flight: Mutex<Option<LiveFingerprintDigestWork>>,
    // Each accepted job stays in its paid slot through hashing, publication,
    // byte completion and Main return. Other slots remain independently usable.
    #[cfg(not(test))]
    jobs: [Mutex<Option<LiveFingerprintDigestWork>>; pipeline_queue::WORK_CELLS],
    available: Condvar,
    capacity: Condvar,
    #[cfg(test)]
    waiting_producers: std::sync::atomic::AtomicUsize,
}

impl FingerprintWorkerControl {
    fn lock(&self) -> std::sync::MutexGuard<'_, FingerprintWorkerState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn new(#[cfg(test)] workspace: Option<DeviceDigestWorkspace>) -> Self {
        Self {
            #[cfg(not(test))]
            native: None,
            #[cfg(not(test))]
            capture_attempt: Mutex::new(crate::fingerprint_sampler::CaptureAttempt::new()),
            state: Mutex::new(FingerprintWorkerState {
                #[cfg(test)]
                pending: None,
                closed: false,
                registered: false,
                failure: None,
                cleanup_failure: None,
                panic_payload: None,
                supervision_failure: None,
                #[cfg(not(test))]
                pipeline: pipeline_queue::PipelineQueue::new(),
                #[cfg(not(test))]
                native_failure: None,
                #[cfg(not(test))]
                native_entry_failure: None,
                #[cfg(not(test))]
                native_submit_failure: None,
                #[cfg(not(test))]
                native_terminal_observation_failure: None,
                #[cfg(not(test))]
                native_cleanup_failure: None,
                #[cfg(not(test))]
                module_action_failure: None,
                #[cfg(not(test))]
                terminal_failure_issued: false,
                #[cfg(not(test))]
                scope_return_failure: None,
                #[cfg(not(test))]
                sampler_action_failure: None,
            }),
            #[cfg(test)]
            workspace: Mutex::new(workspace),
            #[cfg(test)]
            in_flight: Mutex::new(None),
            #[cfg(not(test))]
            jobs: std::array::from_fn(|_| Mutex::new(None)),
            available: Condvar::new(),
            capacity: Condvar::new(),
            #[cfg(test)]
            waiting_producers: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    fn workspace(&self) -> MutexGuard<'_, Option<DeviceDigestWorkspace>> {
        match self.workspace.lock() {
            Ok(workspace) => workspace,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[cfg(test)]
    fn in_flight(&self) -> MutexGuard<'_, Option<LiveFingerprintDigestWork>> {
        match self.in_flight.lock() {
            Ok(work) => work,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn refuse(&self, source: FingerprintWorkerCause) {
        let mut state = self.lock();
        if state.failure.is_none() {
            state.failure = Some(source);
        }
        drop(state);
        self.available.notify_all();
        self.capacity.notify_all();
    }

    // There is exactly one queued capture, independent of the in-flight digest.
    // Both predicates and mutations share this mutex, preventing lost wakeups.
    #[cfg(test)]
    fn enqueue(
        &self,
        captured: &mut Option<CapturedFingerprintSample>,
        capture_request: u32,
    ) -> Result<(), ()> {
        if captured.is_none() {
            return Err(());
        }
        let mut state = self.lock();
        while state.pending.is_some() && !state.closed && state.failure.is_none() {
            #[cfg(test)]
            self.waiting_producers.fetch_add(1, Ordering::SeqCst);
            state = match self.capacity.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            #[cfg(test)]
            self.waiting_producers.fetch_sub(1, Ordering::SeqCst);
        }
        if state.failure.is_some() || state.closed {
            return Err(());
        }
        let Some(captured) = captured.take() else {
            return Err(());
        };
        state.pending = Some(LiveFingerprintDigestWork::new(captured, capture_request));
        drop(state);
        self.available.notify_one();
        Ok(())
    }

    #[cfg(test)]
    fn receive(&self) -> Option<MutexGuard<'_, Option<LiveFingerprintDigestWork>>> {
        let mut state = self.lock();
        loop {
            if state.failure.is_some() {
                return None;
            }
            // Closing prevents new sends but drains an already queued capture,
            // matching the old capacity-one channel's receiver contract.
            if state.pending.is_some() {
                let mut in_flight = self.in_flight();
                if in_flight.is_some() {
                    drop(in_flight);
                    drop(state);
                    self.refuse(FingerprintWorkerCause::UnsettledWork);
                    return None;
                }
                *in_flight = state.pending.take();
                drop(state);
                self.capacity.notify_one();
                return Some(in_flight);
            }
            if state.closed {
                return None;
            }
            state = match self.available.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    fn close(&self) {
        self.lock().closed = true;
        self.available.notify_all();
        self.capacity.notify_all();
    }

    fn check_original(
        self: &Arc<Self>,
        wait_slice: &mut impl FnMut() -> Result<std::time::Duration, crate::StartupSourceError>,
    ) -> Result<std::time::Duration, LiveVcpuTimeCallbackError> {
        wait_slice().map_err(|source| {
            let mut state = self.lock();
            if state.failure.is_none() {
                state.failure = Some(FingerprintWorkerCause::Supervision);
            }
            if state.supervision_failure.is_none() {
                state.supervision_failure = Some(source);
            }
            drop(state);
            self.available.notify_all();
            self.capacity.notify_all();
            LiveFingerprintDigestWorker::failed(self)
        })
    }
}

/// Bounded thread and parent-held mapping under one compulsory native purpose.
pub(in crate::runtime) struct LiveFingerprintDigestWorker {
    #[cfg(test)]
    control: Option<Arc<FingerprintWorkerControl>>,
    #[cfg(test)]
    join: Option<JoinHandle<()>>,
    #[cfg(not(test))]
    native: native::Handle,
    #[cfg(not(test))]
    native_retired: bool,
    #[cfg(not(test))]
    native_terminal_status: i32,
    #[cfg(not(test))]
    native_close_failure: Option<i32>,
    #[cfg(not(test))]
    native_retire_scope_failure: Option<i32>,
    owner_process: u32,
    // Only the fully held/parked parent writes this slot. The early child takes
    // it directly, before runtime reconstruction, without a copied Mutex.
    #[cfg(test)]
    fork_workspace: UnsafeCell<Option<DeviceDigestWorkspace>>,
}

// SAFETY: ordinary control state is synchronized by its inline mutexes. Source
// keeps the production raw Arc owner alive through physical join and final drop;
// fixture UnsafeCell access requires the complete existing native fork barrier.
unsafe impl Sync for LiveFingerprintDigestWorker {}

impl LiveFingerprintDigestWorker {
    /// Describes the separately allocated worker control, excluding its creator.
    pub(in crate::runtime) fn configured_control_layout()
    -> Result<std::alloc::Layout, crate::StartupSourceError> {
        super::super::prebirth::shared_layout::<FingerprintWorkerControl>()
    }

    #[cfg(test)]
    pub(super) fn spawn(
        slot: StableFingerprintSlotHandle,
        quiescence: Arc<LiveWorkerQuiescence>,
        workspace: DeviceDigestWorkspace,
        wait_slice: &mut impl FnMut() -> Result<std::time::Duration, crate::StartupSourceError>,
        first_setup_failure: &mut Option<crate::StartupSourceError>,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        // No control, mapping, name or thread birth precedes this cut on the
        // same retained installing Source. The parent already owns its inline error slot.
        check_setup_before_birth(wait_slice, first_setup_failure)?;
        let control = Arc::new(FingerprintWorkerControl::new(Some(workspace)));
        control.check_original(wait_slice)?;
        {
            let mut retained = control.workspace();
            let mapping = match retained.as_mut() {
                Some(workspace) => workspace.map(),
                None => Err(DeviceDigestWorkspaceError::Ownership {
                    reason: "workspace disappeared before mapping",
                }),
            };
            if let Err(source) = mapping {
                drop(retained);
                control.refuse(FingerprintWorkerCause::Workspace(source));
                return Err(Self::failed(&control));
            }
        }
        control.check_original(wait_slice)?;

        let worker_control = Arc::clone(&control);
        let join = thread::Builder::new()
            .name("crucible-fingerprint-digest".to_owned())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let identity = match quiescence.register_current(WORKER_FINGERPRINT) {
                        Ok(identity) => identity,
                        Err(source) => {
                            worker_control.refuse(FingerprintWorkerCause::Registration(source));
                            return;
                        }
                    };
                    worker_control.lock().registered = true;
                    Self::run(slot, &quiescence, &worker_control);
                    drop(identity);
                }));
                if let Err(payload) = result {
                    let mut state = worker_control.lock();
                    if state.failure.is_none() {
                        state.failure = Some(FingerprintWorkerCause::Panic);
                    }
                    state.panic_payload = Some(payload);
                    drop(state);
                    worker_control.available.notify_all();
                    worker_control.capacity.notify_all();
                }
            });
        let join = match join {
            Ok(join) => join,
            Err(source) => {
                control.refuse(FingerprintWorkerCause::Spawn(source));
                return Err(Self::failed(&control));
            }
        };

        Ok(Self {
            control: Some(control),
            join: Some(join),
            owner_process: std::process::id(),
            fork_workspace: UnsafeCell::new(None),
        })
    }

    #[cfg(test)]
    fn run(
        slot: StableFingerprintSlotHandle,
        quiescence: &Arc<LiveWorkerQuiescence>,
        control: &Arc<FingerprintWorkerControl>,
    ) {
        loop {
            let idle = quiescence.idle(WORKER_FINGERPRINT);
            let Some(mut in_flight) = control.receive() else {
                break;
            };
            let pending = idle.received();
            let _operation = pending.enter();
            let Some(work) = in_flight.as_mut() else {
                drop(in_flight);
                control.refuse(FingerprintWorkerCause::UnsettledWork);
                break;
            };
            let sample = {
                let mut retained = control.workspace();
                let digest = match retained.as_mut() {
                    Some(workspace) => match workspace.bytes() {
                        Ok(bytes) => work
                            .captured
                            .digest(bytes)
                            .map_err(FingerprintWorkerCause::Digest),
                        Err(source) => Err(FingerprintWorkerCause::Workspace(source)),
                    },
                    None => Err(FingerprintWorkerCause::Workspace(
                        DeviceDigestWorkspaceError::Ownership {
                            reason: "digest workspace is held by the fork barrier",
                        },
                    )),
                };
                match digest {
                    Ok(sample) => sample,
                    Err(source) => {
                        drop(retained);
                        drop(in_flight);
                        control.refuse(source);
                        break;
                    }
                }
            };

            // The byte borrow ends here, but the file and transcript stay in
            // the control until both publication and the real capture ACK.
            if let Err(source) = work.publish(slot.get(), &sample) {
                drop(in_flight);
                control.refuse(source);
                break;
            }
            if work.publication != MaterialPublication::Acknowledged {
                drop(in_flight);
                control.refuse(FingerprintWorkerCause::UnsettledWork);
                break;
            }
            drop(in_flight.take());
        }
    }

    fn failed(control: &Arc<FingerprintWorkerControl>) -> LiveVcpuTimeCallbackError {
        LiveVcpuTimeCallbackError::FingerprintWorkerFailed {
            source: FingerprintWorkerFailure {
                control: Arc::clone(control),
            },
        }
    }

    /// Waits for actual registration using the caller's retained installing Source.
    #[cfg(test)]
    pub(super) fn wait_registered(
        &self,
        mut wait_slice: impl FnMut() -> Result<std::time::Duration, crate::StartupSourceError>,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let control = self
            .control
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)?;
        loop {
            let slice = control.check_original(&mut wait_slice)?;
            let state = control.lock();
            if state.failure.is_some() {
                drop(state);
                return Err(Self::failed(control));
            }
            let registered = state.registered;
            drop(state);
            #[cfg(not(test))]
            self.native.check_readiness(control)?;
            if registered {
                control.check_original(&mut wait_slice)?;
                return Ok(());
            }
            #[cfg(test)]
            if self.join.as_ref().is_none_or(JoinHandle::is_finished) {
                control.refuse(FingerprintWorkerCause::Panic);
                return Err(Self::failed(control));
            }
            thread::sleep(slice.min(std::time::Duration::from_millis(10)));
        }
    }

    #[cfg(test)]
    pub(super) fn submit(
        &self,
        captured: &mut Option<CapturedFingerprintSample>,
        capture_request: u32,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let control = self
            .control
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)?;
        control.enqueue(captured, capture_request).map_err(|()| {
            if control.lock().failure.is_some() {
                Self::failed(control)
            } else {
                LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable
            }
        })
    }

    /// Rejects a copied child before borrowing any inherited worker/capture mutex.
    pub(super) fn creator_process_is_current(&self) -> bool {
        self.owner_process == std::process::id()
    }

    #[cfg(test)]
    pub(super) fn set_fixture_creator_process(&mut self, process: u32) {
        self.owner_process = process;
    }

    #[cfg(test)]
    pub(super) fn close_fixture_admission(&self) {
        if let Some(control) = &self.control {
            control.close();
        }
    }

    /// Transfers the same mapping without waiting on a worker-owned mutex.
    ///
    /// The caller must retain actual complete callback/ring/worker exclusion.
    ///
    /// # Safety
    ///
    /// The caller must retain complete callback/ring/worker exclusion in this
    /// same parent process. Restoration also requires native producer/execution
    /// exclusion through the final release cut.
    ///
    /// # Errors
    ///
    /// Returns a fixed signed refusal for control/workspace contention, poison,
    /// wrong process, absent owner, pending work, failure or inconsistent custody.
    #[cfg(test)]
    pub(super) unsafe fn hold_workspace_for_parent_park(&self) -> Result<(), i32> {
        if self.owner_process != std::process::id() {
            return Err(-libc::EPERM);
        }
        let control = self.control.as_ref().ok_or(-libc::EPROTO)?;
        let state = control.state.try_lock().map_err(park_lock_status)?;
        let in_flight = control.in_flight.try_lock().map_err(park_lock_status)?;
        let mut workspace = control.workspace.try_lock().map_err(park_lock_status)?;
        if state.failure.is_some() || state.pending.is_some() || in_flight.is_some() || state.closed
        {
            return Err(-libc::EPROTO);
        }
        // SAFETY: the caller retains complete actual admission exclusion; all
        // worker mutexes are borrowed without waiting before the transfer cut.
        let held = unsafe { &mut *self.fork_workspace.get() };
        if held.is_some() {
            return if workspace.is_none() {
                Ok(())
            } else {
                Err(-libc::EPROTO)
            };
        }
        *held = workspace.take();
        if held.is_none() {
            return Err(-libc::EPROTO);
        }
        Ok(())
    }

    /// Restores the same mapping without releasing custody on mutex refusal.
    ///
    /// # Safety
    ///
    /// The caller must retain complete callback/ring/worker exclusion in this
    /// same parent process. Restoration also requires native producer/execution
    /// exclusion through the final release cut.
    ///
    /// # Errors
    ///
    /// Returns a fixed signed refusal for control/workspace contention, poison,
    /// wrong process, absent owner, pending work, failure or inconsistent custody.
    #[cfg(test)]
    pub(super) unsafe fn restore_workspace_for_parent_park(&self) -> Result<(), i32> {
        if self.owner_process != std::process::id() {
            return Err(-libc::EPERM);
        }
        let control = self.control.as_ref().ok_or(-libc::EPROTO)?;
        let state = control.state.try_lock().map_err(park_lock_status)?;
        let in_flight = control.in_flight.try_lock().map_err(park_lock_status)?;
        let mut workspace = control.workspace.try_lock().map_err(park_lock_status)?;
        if state.failure.is_some() || state.pending.is_some() || in_flight.is_some() || state.closed
        {
            return Err(-libc::EPROTO);
        }
        // SAFETY: the caller retains complete actual admission exclusion and
        // native producer exclusion through the final disposition cut.
        let held = unsafe { &mut *self.fork_workspace.get() };
        if workspace.is_some() && held.is_some() {
            return Err(-libc::EPROTO);
        }
        if workspace.is_none() {
            *workspace = held.take();
        }
        if workspace.is_none() {
            return Err(-libc::EPROTO);
        }
        Ok(())
    }

    /// Transfers the mapping to the directly held callback slot before fork.
    ///
    /// The caller must have observed the complete existing worker parked set,
    /// empty pending mask and zero callback/worker operations under its barrier.
    ///
    /// # Safety
    ///
    /// The caller retains the complete worker/callback barrier with no queued or in-flight work until restoration or child disarm.
    #[cfg(test)]
    pub(super) unsafe fn hold_workspace_for_fork(&self) -> Result<(), DeviceDigestWorkspaceError> {
        if self.owner_process != std::process::id() {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "fork hold is not in parent",
            });
        }
        let control = self
            .control
            .as_ref()
            .ok_or(DeviceDigestWorkspaceError::Ownership {
                reason: "worker control is absent",
            })?;
        let state = control.state.try_lock().map_err(fork_lock_error)?;
        let in_flight = control.in_flight.try_lock().map_err(fork_lock_error)?;
        let mut workspace = control.workspace.try_lock().map_err(fork_lock_error)?;
        if state.failure.is_some() || state.pending.is_some() || in_flight.is_some() || state.closed
        {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "worker refused, closed or retains captured material",
            });
        }
        // The worker may own its in-flight borrow while waiting for this park
        // to release. None of these borrows may wait for that worker.
        // SAFETY: the caller holds complete callback/worker exclusion.
        let fork_workspace = unsafe { &mut *self.fork_workspace.get() };
        if fork_workspace.is_some() {
            return if workspace.is_none() {
                Ok(())
            } else {
                Err(DeviceDigestWorkspaceError::Ownership {
                    reason: "held and worker workspace owners overlap",
                })
            };
        }
        *fork_workspace = workspace.take();
        if fork_workspace.is_none() {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "mapping is absent at fork hold",
            });
        }
        Ok(())
    }

    /// Restores the same parent owner before its worker barrier releases.
    ///
    /// # Safety
    ///
    /// The caller retains the same parent barrier from the preceding hold; no worker or callback may access the workspace until this returns.
    #[cfg(test)]
    pub(super) unsafe fn restore_workspace_after_fork(
        &self,
    ) -> Result<(), DeviceDigestWorkspaceError> {
        if self.owner_process != std::process::id() {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "restore is not in parent",
            });
        }
        let control = self
            .control
            .as_ref()
            .ok_or(DeviceDigestWorkspaceError::Ownership {
                reason: "worker control is absent",
            })?;
        let state = control.state.try_lock().map_err(fork_lock_error)?;
        let in_flight = control.in_flight.try_lock().map_err(fork_lock_error)?;
        let mut workspace = control.workspace.try_lock().map_err(fork_lock_error)?;
        if state.failure.is_some() || state.pending.is_some() || in_flight.is_some() || state.closed
        {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "worker refused, closed or retains captured material",
            });
        }
        // SAFETY: the caller still holds complete callback/worker exclusion.
        let fork_workspace = unsafe { &mut *self.fork_workspace.get() };
        if workspace.is_some() && fork_workspace.is_some() {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "parent mapping is duplicated",
            });
        }
        if workspace.is_none() {
            *workspace = fork_workspace.take();
        }
        if workspace.is_none() {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "parent mapping is lost",
            });
        }
        Ok(())
    }

    /// Disarms only the direct inherited owner at authenticated early child entry.
    #[cfg(test)]
    pub(super) fn disarm_child_workspace(&mut self) -> Result<(), DeviceDigestWorkspaceError> {
        if self.owner_process == std::process::id() {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "child disarm is in parent",
            });
        }
        let workspace =
            self.fork_workspace
                .get_mut()
                .take()
                .ok_or(DeviceDigestWorkspaceError::Ownership {
                    reason: "inherited mapping owner is absent",
                })?;
        if let Err(failure) = workspace.disarm_inherited() {
            let source = failure.source;
            *self.fork_workspace.get_mut() = Some(failure.workspace);
            return Err(source);
        }
        Ok(())
    }

    /// Joins before unique control recovery and fallible workspace close.
    #[cfg(test)]
    fn retire(&mut self) -> Result<(), FingerprintWorkerFailure> {
        let Some(control) = self.control.as_ref() else {
            return Ok(());
        };
        if self.owner_process != std::process::id() {
            return Err(FingerprintWorkerFailure {
                control: Arc::clone(control),
            });
        }
        control.close();
        if let Some(join) = self.join.take()
            && let Err(payload) = join.join()
        {
            let mut state = control.lock();
            if state.failure.is_none() {
                state.failure = Some(FingerprintWorkerCause::Panic);
            }
            state.panic_payload = Some(payload);
        }
        if control.lock().panic_payload.is_some() {
            return Err(FingerprintWorkerFailure {
                control: Arc::clone(control),
            });
        }
        if Arc::strong_count(control) != 1 || Arc::weak_count(control) != 0 {
            control.refuse(FingerprintWorkerCause::AliasedControl);
            return Err(FingerprintWorkerFailure {
                control: Arc::clone(control),
            });
        }
        if self.fork_workspace.get_mut().is_some() {
            return Err(FingerprintWorkerFailure {
                control: Arc::clone(control),
            });
        }
        // A failed or unprocessed capture remains the same queued/in-flight
        // owner. Joining and closing admission do not certify its terminal.
        let queued = control.lock().pending.is_some();
        if queued || control.in_flight().is_some() {
            control.refuse(FingerprintWorkerCause::UnsettledWork);
            return Err(FingerprintWorkerFailure {
                control: Arc::clone(control),
            });
        }
        let workspace = control.workspace().take();
        if let Some(workspace) = workspace
            && let Err(failure) = workspace.try_close()
        {
            control.lock().cleanup_failure = Some(failure.source);
            *control.workspace() = Some(failure.workspace);
            return Err(FingerprintWorkerFailure {
                control: Arc::clone(control),
            });
        }
        // All workspace effects are closed before actual control/header free.
        drop(self.control.take());
        Ok(())
    }
}

#[cfg(test)]
impl Drop for LiveFingerprintDigestWorker {
    fn drop(&mut self) {
        if let Err(failure) = self.retire() {
            // This is the fixed unsettled containment path, not a refund or
            // successful cleanup. No replacement allocation is born here.
            // The external native slot remains outstanding until process exit.
            std::mem::forget(failure);
            if let Some(control) = self.control.take() {
                std::mem::forget(control);
            }
            #[cfg(test)]
            if let Some(workspace) = self.fork_workspace.get_mut().take() {
                std::mem::forget(workspace);
            }
            #[cfg(test)]
            if let Some(join) = self.join.take() {
                std::mem::forget(join);
            }
        }
    }
}

#[cfg(not(test))]
impl Drop for LiveFingerprintDigestWorker {
    fn drop(&mut self) {
        // A borrowed view has no owning decrement and cannot retire Source's
        // thread or allocation. Explicit Runtime cleanup owns those effects.
        // Never inspect a body that Source may already have physically returned.
        // Native lifetime and final ownership stay entirely with Runtime's
        // explicit Source worker keeper; this handle owns no body reference.
    }
}

#[cfg(test)]
fn fork_lock_error<T>(error: std::sync::TryLockError<T>) -> DeviceDigestWorkspaceError {
    DeviceDigestWorkspaceError::Ownership {
        reason: match error {
            std::sync::TryLockError::WouldBlock => "worker mutex is contended at fork transfer",
            std::sync::TryLockError::Poisoned(_) => "worker mutex is poisoned at fork transfer",
        },
    }
}

fn park_lock_status<T>(error: std::sync::TryLockError<T>) -> i32 {
    match error {
        std::sync::TryLockError::WouldBlock => -libc::EBUSY,
        std::sync::TryLockError::Poisoned(_) => -libc::EOWNERDEAD,
    }
}

// This cut precedes native claim and each control birth. The inline parent slot
// retains the exact first cause without allocating an error after refusal.
pub(in crate::runtime) fn check_setup_before_birth(
    wait_slice: &mut impl FnMut() -> Result<std::time::Duration, crate::StartupSourceError>,
    first_failure: &mut Option<crate::StartupSourceError>,
) -> Result<(), LiveVcpuTimeCallbackError> {
    if let Some(source) = *first_failure {
        return Err(LiveVcpuTimeCallbackError::DeviceDigestWorkspace {
            source: DeviceDigestWorkspaceError::StartupSource { source },
        });
    }
    if let Err(source) = wait_slice() {
        *first_failure = Some(source);
        return Err(LiveVcpuTimeCallbackError::DeviceDigestWorkspace {
            source: DeviceDigestWorkspaceError::StartupSource { source },
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
