//! Reversible parking for the plugin's sealed process-lifetime workers.
//!
//! Each registered worker alternates between an idle safe point and one
//! bounded operation. A hot-fork hold prevents a worker from entering its next
//! operation, while operations admitted before the hold are allowed to drain.
//! The coordinator reports fixed worker-class masks rather than host thread
//! identities so the status remains deterministic and language-neutral.

use std::sync::{Arc, Condvar, Mutex};

use thiserror::Error;

pub(super) const WORKER_RUN_CONTROL: u64 = 1_u64 << 0;
pub(super) const WORKER_TEARDOWN: u64 = 1_u64 << 1;
pub(super) const WORKER_FINGERPRINT: u64 = 1_u64 << 2;
pub(super) const WORKER_REQUIRED: u64 = WORKER_RUN_CONTROL | WORKER_TEARDOWN;
pub(super) const WORKER_ALL: u64 = (1_u64 << 3) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WorkerQuiescenceSnapshot {
    pub(super) held: bool,
    pub(super) worker_mask: u64,
    pub(super) parked_mask: u64,
    pub(super) pending_mask: u64,
    pub(super) operations_in_flight: u64,
}

/// Failure to replace parked template workers with fresh fork-child workers.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(super) enum WorkerForkChildResetError {
    /// The template worker set was not completely parked and empty.
    #[error("template worker set is not quiescent for fork-child replacement")]
    NotQuiescent {
        /// Exact worker state observed before any reset mutation.
        snapshot: WorkerQuiescenceSnapshot,
    },
}

#[derive(Debug)]
struct WorkerQuiescenceState {
    held: bool,
    parked_mask: u64,
    pending_mask: u64,
    active_mask: u64,
}

/// Process-lifetime owner of reversible worker admission and parking state.
#[derive(Debug)]
pub(super) struct LiveWorkerQuiescence {
    worker_mask: u64,
    state: Mutex<WorkerQuiescenceState>,
    released: Condvar,
}

impl LiveWorkerQuiescence {
    pub(super) fn new(worker_mask: u64) -> Arc<Self> {
        debug_assert_eq!(worker_mask & !WORKER_ALL, 0);
        debug_assert_eq!(worker_mask & WORKER_REQUIRED, WORKER_REQUIRED);
        Arc::new(Self {
            worker_mask,
            state: Mutex::new(WorkerQuiescenceState {
                held: false,
                parked_mask: 0,
                pending_mask: 0,
                active_mask: 0,
            }),
            released: Condvar::new(),
        })
    }

    pub(super) const fn worker_mask(&self) -> u64 {
        self.worker_mask
    }

    /// Marks one worker as parked at a blocking receive safe point.
    pub(super) fn idle(self: &Arc<Self>, worker: u64) -> WorkerIdleGuard {
        self.assert_worker(worker);
        let mut state = self.lock_state();
        debug_assert_eq!(state.active_mask & worker, 0);
        state.parked_mask |= worker;
        drop(state);
        WorkerIdleGuard {
            quiescence: Arc::clone(self),
            worker,
            parked: true,
        }
    }

    pub(super) fn hold(&self) -> WorkerQuiescenceSnapshot {
        let mut state = self.lock_state();
        state.held = true;
        self.snapshot_locked(&state)
    }

    pub(super) fn snapshot(&self) -> WorkerQuiescenceSnapshot {
        let state = self.lock_state();
        self.snapshot_locked(&state)
    }

    pub(super) fn release(&self) -> WorkerQuiescenceSnapshot {
        let mut state = self.lock_state();
        state.held = false;
        let snapshot = self.snapshot_locked(&state);
        self.released.notify_all();
        snapshot
    }

    /// Replaces the inherited parked-worker accounting with an empty child set.
    ///
    /// The reversible hold remains active. Fresh child workers must each enter
    /// their idle safe point, after which [`Self::fork_child_workers_ready`]
    /// authorizes the ordinary release transition.
    pub(super) fn reset_fork_child_workers(
        &self,
    ) -> Result<WorkerQuiescenceSnapshot, WorkerForkChildResetError> {
        let mut state = self.lock_state();
        let snapshot = self.snapshot_locked(&state);
        if !snapshot.held
            || snapshot.parked_mask != snapshot.worker_mask
            || snapshot.pending_mask != 0
            || snapshot.operations_in_flight != 0
        {
            return Err(WorkerForkChildResetError::NotQuiescent { snapshot });
        }

        state.parked_mask = 0;
        state.pending_mask = 0;
        state.active_mask = 0;
        Ok(snapshot)
    }

    /// Returns whether every fresh child worker is parked behind the hold.
    pub(super) fn fork_child_workers_ready(&self) -> bool {
        let snapshot = self.snapshot();
        snapshot.held
            && snapshot.parked_mask == snapshot.worker_mask
            && snapshot.pending_mask == 0
            && snapshot.operations_in_flight == 0
    }

    fn assert_worker(&self, worker: u64) {
        debug_assert!(worker.is_power_of_two());
        debug_assert_ne!(self.worker_mask & worker, 0);
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, WorkerQuiescenceState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn snapshot_locked(&self, state: &WorkerQuiescenceState) -> WorkerQuiescenceSnapshot {
        WorkerQuiescenceSnapshot {
            held: state.held,
            worker_mask: self.worker_mask,
            parked_mask: state.parked_mask,
            pending_mask: state.pending_mask,
            operations_in_flight: u64::from(state.active_mask.count_ones()),
        }
    }
}

/// RAII marker for a worker blocked at a process-safe receive boundary.
pub(super) struct WorkerIdleGuard {
    quiescence: Arc<LiveWorkerQuiescence>,
    worker: u64,
    parked: bool,
}

impl WorkerIdleGuard {
    /// Transfers one received item into explicit worker-local ownership.
    pub(super) fn received(mut self) -> WorkerPendingGuard {
        // The receive has completed, but the worker cannot inspect, publish,
        // or otherwise act on the item until this mutex transition makes its
        // local ownership visible to the barrier snapshot.
        let mut state = self.quiescence.lock_state();
        debug_assert_ne!(state.parked_mask & self.worker, 0);
        debug_assert_eq!(state.pending_mask & self.worker, 0);
        debug_assert_eq!(state.active_mask & self.worker, 0);
        state.pending_mask |= self.worker;
        drop(state);

        self.parked = false;
        WorkerPendingGuard {
            quiescence: Arc::clone(&self.quiescence),
            worker: self.worker,
            pending: true,
        }
    }
}

impl Drop for WorkerIdleGuard {
    fn drop(&mut self) {
        if !self.parked {
            return;
        }
        let mut state = self.quiescence.lock_state();
        state.parked_mask &= !self.worker;
    }
}

/// RAII marker for one item dequeued but not yet admitted for processing.
pub(super) struct WorkerPendingGuard {
    quiescence: Arc<LiveWorkerQuiescence>,
    worker: u64,
    pending: bool,
}

impl WorkerPendingGuard {
    /// Waits for a reversible hold to release, then admits the pending item.
    pub(super) fn enter(mut self) -> WorkerOperationGuard {
        let mut state = self.quiescence.lock_state();
        while state.held {
            debug_assert_ne!(state.pending_mask & self.worker, 0);
            debug_assert_eq!(state.active_mask & self.worker, 0);
            state.parked_mask |= self.worker;
            state = self
                .quiescence
                .released
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        state.pending_mask &= !self.worker;
        state.parked_mask &= !self.worker;
        debug_assert_eq!(state.active_mask & self.worker, 0);
        state.active_mask |= self.worker;
        drop(state);

        self.pending = false;
        WorkerOperationGuard {
            quiescence: Arc::clone(&self.quiescence),
            worker: self.worker,
        }
    }
}

impl Drop for WorkerPendingGuard {
    fn drop(&mut self) {
        if !self.pending {
            return;
        }
        let mut state = self.quiescence.lock_state();
        state.pending_mask &= !self.worker;
        state.parked_mask &= !self.worker;
    }
}

/// RAII marker for one admitted worker operation.
pub(super) struct WorkerOperationGuard {
    quiescence: Arc<LiveWorkerQuiescence>,
    worker: u64,
}

impl Drop for WorkerOperationGuard {
    fn drop(&mut self) {
        let mut state = self.quiescence.lock_state();
        state.active_mask &= !self.worker;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::*;

    #[test]
    fn hold_reports_idle_workers_parked() {
        let quiescence = LiveWorkerQuiescence::new(WORKER_REQUIRED);
        let _control = quiescence.idle(WORKER_RUN_CONTROL);
        let _teardown = quiescence.idle(WORKER_TEARDOWN);

        let snapshot = quiescence.hold();
        assert!(snapshot.held);
        assert_eq!(snapshot.worker_mask, WORKER_REQUIRED);
        assert_eq!(snapshot.parked_mask, WORKER_REQUIRED);
        assert_eq!(snapshot.pending_mask, 0);
        assert_eq!(snapshot.operations_in_flight, 0);
    }

    #[test]
    fn admitted_operation_drains_then_parks_until_release() {
        let quiescence = LiveWorkerQuiescence::new(WORKER_REQUIRED);
        let operation = quiescence.idle(WORKER_RUN_CONTROL).received().enter();
        let held = quiescence.hold();
        assert_eq!(held.operations_in_flight, 1);

        let worker_quiescence = Arc::clone(&quiescence);
        let (attempted, attempted_rx) = mpsc::channel();
        let (admitted, admitted_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            drop(operation);
            attempted
                .send(())
                .unwrap_or_else(|error| panic!("attempt marker: {error}"));
            let _next = worker_quiescence
                .idle(WORKER_RUN_CONTROL)
                .received()
                .enter();
            admitted
                .send(())
                .unwrap_or_else(|error| panic!("admit marker: {error}"));
        });

        attempted_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("operation should drain: {error}"));
        assert!(admitted_rx.recv_timeout(Duration::from_millis(20)).is_err());
        let mut parked = None;
        for _attempt in 0..100_000 {
            let snapshot = quiescence.snapshot();
            if snapshot.parked_mask == WORKER_RUN_CONTROL {
                parked = Some(snapshot);
                break;
            }
            thread::yield_now();
        }
        let parked = parked.unwrap_or_else(|| panic!("worker should reach the held safe point"));
        assert_eq!(parked.parked_mask, WORKER_RUN_CONTROL);
        assert_eq!(parked.pending_mask, WORKER_RUN_CONTROL);
        assert_eq!(parked.operations_in_flight, 0);

        let released = quiescence.release();
        assert!(!released.held);
        admitted_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("worker should resume: {error}"));
        worker
            .join()
            .unwrap_or_else(|_panic| panic!("worker should join"));
    }

    #[test]
    fn optional_fingerprint_worker_is_part_of_the_exact_mask() {
        let mask = WORKER_REQUIRED | WORKER_FINGERPRINT;
        let quiescence = LiveWorkerQuiescence::new(mask);
        let _control = quiescence.idle(WORKER_RUN_CONTROL);
        let _teardown = quiescence.idle(WORKER_TEARDOWN);
        let _fingerprint = quiescence.idle(WORKER_FINGERPRINT);

        let snapshot = quiescence.hold();
        assert_eq!(snapshot.worker_mask, mask);
        assert_eq!(snapshot.parked_mask, mask);
        assert_eq!(snapshot.pending_mask, 0);
    }

    #[test]
    fn hold_reports_dequeued_worker_local_state_until_release() {
        let quiescence = LiveWorkerQuiescence::new(WORKER_REQUIRED);
        let pending = quiescence.idle(WORKER_RUN_CONTROL).received();

        let held = quiescence.hold();
        assert_eq!(held.parked_mask, WORKER_RUN_CONTROL);
        assert_eq!(held.pending_mask, WORKER_RUN_CONTROL);
        assert_eq!(held.operations_in_flight, 0);

        drop(pending);
        let drained = quiescence.snapshot();
        assert_eq!(drained.parked_mask, 0);
        assert_eq!(drained.pending_mask, 0);
    }

    #[test]
    fn fork_child_reset_forgets_only_a_complete_parked_template_set() {
        let quiescence = LiveWorkerQuiescence::new(WORKER_REQUIRED);
        let held = quiescence.hold();
        assert_eq!(
            quiescence.reset_fork_child_workers(),
            Err(WorkerForkChildResetError::NotQuiescent { snapshot: held })
        );

        let template_control = quiescence.idle(WORKER_RUN_CONTROL);
        let template_teardown = quiescence.idle(WORKER_TEARDOWN);
        let parked = quiescence.snapshot();
        assert_eq!(parked.parked_mask, WORKER_REQUIRED);
        assert_eq!(quiescence.reset_fork_child_workers(), Ok(parked));
        assert!(!quiescence.fork_child_workers_ready());

        std::mem::forget(template_control);
        std::mem::forget(template_teardown);
        let _child_control = quiescence.idle(WORKER_RUN_CONTROL);
        let _child_teardown = quiescence.idle(WORKER_TEARDOWN);
        assert!(quiescence.fork_child_workers_ready());
        assert!(!quiescence.release().held);
    }
}
