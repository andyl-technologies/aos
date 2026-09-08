//! Worker completion signals and endpoint retention during pending cleanup.
//!
//! Stopping admission, retaining unresolved state, and completing cleanup are
//! distinct events. A pending service may return while the fixed workers keep
//! the endpoint lock. Only the last model's destruction releases that lock.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Cloneable completion signal for one local executor worker-pool incarnation.
#[derive(Clone)]
pub struct LocalExecutorPoolCompletion {
    pub(super) state: Arc<PoolCompletionState>,
}

impl LocalExecutorPoolCompletion {
    /// Returns whether every fixed worker thread has exited.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_finished()
    }

    /// Blocks until every fixed worker exits or synchronization is poisoned.
    ///
    /// Poison is treated as terminal completion so a containing service fails
    /// closed instead of retaining a listener for a broken executor owner.
    pub fn wait(&self) {
        let Ok(wait) = self.state.wait.lock() else {
            return;
        };
        drop(
            self.state
                .changed
                .wait_while(wait, |_| !self.state.is_finished()),
        );
    }

    pub(crate) fn wait_until_stopping(&self) {
        let wait = self
            .state
            .wait
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        drop(
            self.state
                .changed
                .wait_while(wait, |_| {
                    !self.state.is_finished() && !self.state.stopping.load(Ordering::Acquire)
                })
                .unwrap_or_else(|error| error.into_inner()),
        );
    }

    pub(crate) fn retain_endpoint(
        &self,
        endpoint: Arc<crate::campaign_endpoint::LocalEndpointGuard>,
    ) {
        let mut wait = self
            .state
            .wait
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !self.state.is_finished() {
            wait.endpoint = Some(endpoint);
        }
    }
}

pub(super) struct PoolCompletionState {
    finished_workers: AtomicUsize,
    worker_count: usize,
    stopping: AtomicBool,
    retained: AtomicBool,
    wait: Mutex<PoolCompletionWait>,
    changed: Condvar,
}

#[derive(Default)]
struct PoolCompletionWait {
    // The service also holds an Arc until its listener has joined. The last
    // worker releases this copy only after its execution model is dropped.
    endpoint: Option<Arc<crate::campaign_endpoint::LocalEndpointGuard>>,
}

impl PoolCompletionState {
    pub(super) fn new(worker_count: usize) -> Self {
        Self {
            finished_workers: AtomicUsize::new(0),
            worker_count,
            stopping: AtomicBool::new(false),
            retained: AtomicBool::new(false),
            wait: Mutex::new(PoolCompletionWait::default()),
            changed: Condvar::new(),
        }
    }

    fn is_finished(&self) -> bool {
        self.finished_workers.load(Ordering::Acquire) >= self.worker_count
    }

    fn worker_finished(&self) {
        let mut wait = match self.wait.lock() {
            Ok(wait) => wait,
            Err(poisoned) => poisoned.into_inner(),
        };
        let finished = self
            .finished_workers
            .load(Ordering::Relaxed)
            .saturating_add(1)
            .min(self.worker_count);
        if finished == self.worker_count {
            wait.endpoint = None;
        }
        // Publish only after the endpoint guard's destructor has released its
        // lock, not merely after it has removed the socket pathname.
        self.finished_workers.store(finished, Ordering::Release);
        self.changed.notify_all();
    }

    pub(super) fn signal_stopping(&self) {
        let _wait = self.wait.lock().unwrap_or_else(|error| error.into_inner());
        self.stopping.store(true, Ordering::Release);
        self.changed.notify_all();
    }

    pub(super) fn signal_retained(&self) {
        let _wait = self.wait.lock().unwrap_or_else(|error| error.into_inner());
        self.retained.store(true, Ordering::Release);
        self.changed.notify_all();
    }

    pub(super) fn wait_for_cleanup(&self, timeout: Duration) -> bool {
        let wait = self.wait.lock().unwrap_or_else(|error| error.into_inner());
        let _wait = self
            .changed
            .wait_timeout_while(wait, timeout, |_| {
                !self.is_finished() && !self.retained.load(Ordering::Acquire)
            })
            .unwrap_or_else(|error| error.into_inner());
        self.is_finished()
    }
}

pub(super) struct WorkerCompletion {
    state: Arc<PoolCompletionState>,
}

impl WorkerCompletion {
    pub(super) fn new(state: &Arc<PoolCompletionState>) -> Self {
        Self {
            state: Arc::clone(state),
        }
    }
}

impl Drop for WorkerCompletion {
    fn drop(&mut self) {
        self.state.worker_finished();
    }
}
