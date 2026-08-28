//! Reversible parking for the plugin's sealed process-lifetime workers.
//!
//! Each registered worker alternates between an idle safe point and one
//! bounded operation. A hot-fork hold prevents a worker from entering its next
//! operation, while operations admitted before the hold are allowed to drain.
//! The coordinator reports fixed worker-class masks rather than host thread
//! identities so the status remains deterministic and language-neutral.

use std::sync::{Arc, Condvar, Mutex};

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
    pub(super) operations_in_flight: u64,
}

#[derive(Debug)]
struct WorkerQuiescenceState {
    held: bool,
    parked_mask: u64,
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
        }
    }

    /// Waits for a reversible hold to release, then admits one worker operation.
    pub(super) fn enter(self: &Arc<Self>, worker: u64) -> WorkerOperationGuard {
        self.assert_worker(worker);
        let mut state = self.lock_state();
        while state.held {
            debug_assert_eq!(state.active_mask & worker, 0);
            state.parked_mask |= worker;
            state = self
                .released
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        state.parked_mask &= !worker;
        debug_assert_eq!(state.active_mask & worker, 0);
        state.active_mask |= worker;
        drop(state);
        WorkerOperationGuard {
            quiescence: Arc::clone(self),
            worker,
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
            operations_in_flight: u64::from(state.active_mask.count_ones()),
        }
    }
}

/// RAII marker for a worker blocked at a process-safe receive boundary.
pub(super) struct WorkerIdleGuard {
    quiescence: Arc<LiveWorkerQuiescence>,
    worker: u64,
}

impl Drop for WorkerIdleGuard {
    fn drop(&mut self) {
        let mut state = self.quiescence.lock_state();
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
        assert_eq!(snapshot.operations_in_flight, 0);
    }

    #[test]
    fn admitted_operation_drains_then_parks_until_release() {
        let quiescence = LiveWorkerQuiescence::new(WORKER_REQUIRED);
        let operation = quiescence.enter(WORKER_RUN_CONTROL);
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
            let _next = worker_quiescence.enter(WORKER_RUN_CONTROL);
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
    }
}
