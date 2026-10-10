//! Ordered device digests with retained startup, workspace and retirement custody.
//!
//! One admitted control owns the mapping before the worker starts. The worker
//! borrows it only while hashing; startup reports actual registration, and
//! healthy retirement joins before recovering and closing the unique mapping.

use std::any::Any;
use std::cell::UnsafeCell;
use std::fmt;
use std::sync::{Condvar, MutexGuard};
use std::thread::{self, JoinHandle};

use super::*;
use crate::device_digest_workspace::{DeviceDigestWorkspace, DeviceDigestWorkspaceError};
use crate::fingerprint_sampler::FingerprintSamplerError;
use crate::ram_error::RamError;
use crate::runtime::worker_quiescence::{LiveWorkerQuiescence, WORKER_FINGERPRINT};

struct LiveFingerprintDigestWork {
    captured: CapturedFingerprintSample,
    capture_request: u32,
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
        formatter
            .debug_struct("FingerprintWorkerFailure")
            .field("primary", &state.failure)
            .field("cleanup", &state.cleanup_failure)
            .field("original", &state.supervision_failure)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for FingerprintWorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.control.lock();
        match state.failure.as_ref() {
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
    #[error("worker registration failed: {0}")]
    Registration(RamError),
    #[error("worker workspace failed: {0}")]
    Workspace(DeviceDigestWorkspaceError),
    #[error("worker creation failed: {0}")]
    Spawn(std::io::Error),
    #[error("device digest failed: {0}")]
    Digest(FingerprintSamplerError),
    #[error("fingerprint publication failed: {0}")]
    Publication(crucible_shmem::FingerprintSampleError),
    #[error("fingerprint capture request {request} changed before acknowledgement")]
    CaptureChanged { request: u32 },
    #[error("worker panicked before joined retirement")]
    Panic,
    #[error("worker cleanup cannot establish unique ownership")]
    AliasedControl,
    #[error("the retained installing Source refused worker readiness")]
    Supervision,
}

struct FingerprintWorkerState {
    pending: Option<LiveFingerprintDigestWork>,
    closed: bool,
    registered: bool,
    failure: Option<FingerprintWorkerCause>,
    cleanup_failure: Option<DeviceDigestWorkspaceError>,
    panic_payload: Option<Box<dyn Any + Send>>,
    supervision_failure: Option<crate::StartupSourceError>,
}

struct FingerprintWorkerControl {
    state: Mutex<FingerprintWorkerState>,
    workspace: Mutex<Option<DeviceDigestWorkspace>>,
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

    fn new(workspace: Option<DeviceDigestWorkspace>) -> Self {
        Self {
            state: Mutex::new(FingerprintWorkerState {
                pending: None,
                closed: false,
                registered: false,
                failure: None,
                cleanup_failure: None,
                panic_payload: None,
                supervision_failure: None,
            }),
            workspace: Mutex::new(workspace),
            available: Condvar::new(),
            capacity: Condvar::new(),
            #[cfg(test)]
            waiting_producers: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn workspace(&self) -> MutexGuard<'_, Option<DeviceDigestWorkspace>> {
        match self.workspace.lock() {
            Ok(workspace) => workspace,
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
    fn enqueue(&self, work: LiveFingerprintDigestWork) -> Result<(), ()> {
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
        state.pending = Some(work);
        drop(state);
        self.available.notify_one();
        Ok(())
    }

    fn receive(&self) -> Option<LiveFingerprintDigestWork> {
        let mut state = self.lock();
        loop {
            if state.failure.is_some() {
                return None;
            }
            // Closing prevents new sends but drains an already queued capture,
            // matching the old capacity-one channel's receiver contract.
            if let Some(work) = state.pending.take() {
                drop(state);
                self.capacity.notify_one();
                return Some(work);
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
pub(super) struct LiveFingerprintDigestWorker {
    control: Option<Arc<FingerprintWorkerControl>>,
    join: Option<JoinHandle<()>>,
    owner_process: u32,
    // Only the fully held/parked parent writes this slot. The early child takes
    // it directly, before runtime reconstruction, without a copied Mutex.
    fork_workspace: UnsafeCell<Option<DeviceDigestWorkspace>>,
}

// SAFETY: ordinary state is synchronized by its inline mutexes. The only
// UnsafeCell access occurs under the existing complete native fork barrier;
// child disarm uses exclusive callback userdata before reconstruction begins.
unsafe impl Sync for LiveFingerprintDigestWorker {}

impl LiveFingerprintDigestWorker {
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

    fn run(
        slot: StableFingerprintSlotHandle,
        quiescence: &Arc<LiveWorkerQuiescence>,
        control: &Arc<FingerprintWorkerControl>,
    ) {
        loop {
            let idle = quiescence.idle(WORKER_FINGERPRINT);
            let Some(work) = control.receive() else {
                break;
            };
            let pending = idle.received();
            let _operation = pending.enter();
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
                        control.refuse(source);
                        break;
                    }
                }
            };

            // Release the workspace borrow before publication, ACK and idle.
            // The exact old SHA read requests and publication ordering remain.
            if let Err(source) = slot.get().publish(&sample) {
                control.refuse(FingerprintWorkerCause::Publication(source));
                break;
            }
            if !slot.get().acknowledge_capture_v1(work.capture_request) {
                control.refuse(FingerprintWorkerCause::CaptureChanged {
                    request: work.capture_request,
                });
                break;
            }
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
            if registered {
                control.check_original(&mut wait_slice)?;
                return Ok(());
            }
            if self.join.as_ref().is_none_or(JoinHandle::is_finished) {
                control.refuse(FingerprintWorkerCause::Panic);
                return Err(Self::failed(control));
            }
            thread::sleep(slice.min(std::time::Duration::from_millis(10)));
        }
    }

    pub(super) fn submit(
        &self,
        captured: CapturedFingerprintSample,
        capture_request: u32,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let control = self
            .control
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)?;
        control
            .enqueue(LiveFingerprintDigestWork {
                captured,
                capture_request,
            })
            .map_err(|()| {
                if control.lock().failure.is_some() {
                    Self::failed(control)
                } else {
                    LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable
                }
            })
    }

    /// Transfers the mapping to the directly held callback slot before fork.
    ///
    /// The caller must have observed the complete existing worker parked set,
    /// empty pending mask and zero callback/worker operations under its barrier.
    ///
    /// # Safety
    ///
    /// The caller retains the complete worker/callback barrier with no queued or in-flight work until restoration or child disarm.
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
        // SAFETY: the caller holds complete callback/worker exclusion.
        let fork_workspace = unsafe { &mut *self.fork_workspace.get() };
        if fork_workspace.is_some() {
            return Ok(());
        }
        {
            let state = control.lock();
            if state.failure.is_some() || state.pending.is_some() || state.closed {
                return Err(DeviceDigestWorkspaceError::Ownership {
                    reason: "worker refused, closed or has a queued capture",
                });
            }
        }
        *fork_workspace = control.workspace().take();
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
        // SAFETY: the caller still holds complete callback/worker exclusion.
        let fork_workspace = unsafe { &mut *self.fork_workspace.get() };
        let mut workspace = control.workspace();
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
        // A failure may leave a queued detached File. Drop that real owner
        // after the join and before workspace/control reclamation.
        drop(control.lock().pending.take());
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
            if let Some(workspace) = self.fork_workspace.get_mut().take() {
                std::mem::forget(workspace);
            }
            if let Some(join) = self.join.take() {
                std::mem::forget(join);
            }
        }
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
