//! Checkpoint handoff and execution cancellation control.

use super::*;

#[cfg(test)]
use std::sync::{Condvar, MutexGuard};
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
const MAX_CANCELLATION_WAIT_SLICE: Duration = Duration::from_secs(60 * 60);

/// Stable failure while preparing and durably staging an in-flight checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointHandoffFailure {
    /// A temporary store or ledger failure permits exact retry while capture is retained.
    #[error("checkpoint handoff is temporarily unavailable")]
    Retryable,
    /// Cancellation won before the exact root became staged.
    #[error("checkpoint handoff was canceled")]
    Canceled,
    /// The capture or current operational state cannot accept this root.
    #[error("checkpoint handoff failed its exact execution contract")]
    Terminal,
}

pub(crate) trait AttemptCheckpointHandoff: fmt::Debug + Send + Sync {
    fn prepare_and_stage(
        &self,
        capture: &CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, CheckpointHandoffFailure>;
}

/// Pool-owned capability for staging one exact root before QEMU teardown.
#[derive(Clone)]
pub(crate) struct ExecutionCheckpointHandoff(Arc<dyn AttemptCheckpointHandoff>);

impl ExecutionCheckpointHandoff {
    pub(crate) fn new(handoff: Arc<dyn AttemptCheckpointHandoff>) -> Self {
        Self(handoff)
    }

    pub(crate) fn prepare_and_stage(
        &self,
        capture: &CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, CheckpointHandoffFailure> {
        self.0.prepare_and_stage(capture)
    }

    pub(crate) fn same_incarnation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for ExecutionCheckpointHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionCheckpointHandoff")
            .finish_non_exhaustive()
    }
}

/// One attempt-resource callback installed on an execution cancellation signal.
pub(crate) trait ExecutionCancellationHook: fmt::Debug + Send + Sync {
    /// Makes cancellation sticky at the process/resource boundary.
    fn signal(&self);
}

#[derive(Default)]
pub(super) struct ExecutionCancellationState {
    canceled: AtomicBool,
    hook: Mutex<Option<Arc<dyn ExecutionCancellationHook>>>,
}

impl fmt::Debug for ExecutionCancellationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionCancellationState")
            .field("canceled", &self.canceled.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// Linear registration removing one exact cancellation callback on drop.
#[derive(Debug)]
pub(crate) struct ExecutionCancellationHookRegistration {
    state: Arc<ExecutionCancellationState>,
    hook: Arc<dyn ExecutionCancellationHook>,
}

impl Drop for ExecutionCancellationHookRegistration {
    fn drop(&mut self) {
        let mut installed = match self.state.hook.lock() {
            Ok(installed) => installed,
            Err(poisoned) => poisoned.into_inner(),
        };
        if installed
            .as_ref()
            .is_some_and(|hook| Arc::ptr_eq(hook, &self.hook))
        {
            *installed = None;
        }
    }
}

/// Cloneable process-local cancellation signal for one execution incarnation.
///
/// Concrete resource guards register a sticky callback so cancellation reaches
/// a blocked launch, replay, or shutdown operation without polling.
#[derive(Clone, Debug, Default)]
pub struct ExecutionCancellation {
    state: Arc<ExecutionCancellationState>,
}

impl ExecutionCancellation {
    /// Returns whether cancellation has been requested for this execution.
    #[must_use]
    pub fn is_canceled(&self) -> bool {
        self.state.canceled.load(Ordering::Acquire)
    }

    /// Returns whether two handles name the same execution incarnation.
    #[must_use]
    pub fn same_incarnation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    /// Requests sticky cancellation for this execution incarnation.
    ///
    /// Registered process-resource hooks are signaled before this method
    /// returns. Repeated requests are idempotent.
    pub fn cancel(&self) {
        self.state.canceled.store(true, Ordering::Release);
        let hook = match self.state.hook.lock() {
            Ok(installed) => installed.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        if let Some(hook) = hook {
            hook.signal();
        }
    }

    /// Installs the one resource callback for this execution incarnation.
    ///
    /// A cancellation that won before registration invokes `hook` before this
    /// method returns. The callback must be idempotent because cancellation can
    /// race registration and invoke it from both paths.
    ///
    /// # Errors
    ///
    /// Returns an error when another resource callback is already installed or
    /// synchronization state is poisoned.
    pub(crate) fn register_hook(
        &self,
        hook: Arc<dyn ExecutionCancellationHook>,
    ) -> Result<ExecutionCancellationHookRegistration, &'static str> {
        let canceled = {
            let mut installed = self
                .state
                .hook
                .lock()
                .map_err(|_| "execution cancellation hook state is poisoned")?;
            if installed.is_some() {
                return Err("execution cancellation already has a resource hook");
            }
            *installed = Some(Arc::clone(&hook));
            self.is_canceled()
        };
        if canceled {
            hook.signal();
        }
        Ok(ExecutionCancellationHookRegistration {
            state: Arc::clone(&self.state),
            hook,
        })
    }

    /// Installs a test-owned observer through the production hook contract.
    #[cfg(test)]
    pub(crate) fn observer_for_test(&self) -> Result<ExecutionCancellationObserver, &'static str> {
        ExecutionCancellationObserver::new(self)
    }

    /// Requests cancellation from a crate-internal regression fixture.
    #[cfg(test)]
    pub(crate) fn cancel_for_test(&self) {
        self.cancel();
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct ExecutionCancellationObserverState {
    observed: Mutex<bool>,
    changed: Condvar,
}

#[cfg(test)]
impl ExecutionCancellationHook for ExecutionCancellationObserverState {
    fn signal(&self) {
        let mut observed = match self.observed.lock() {
            Ok(observed) => observed,
            Err(poisoned) => poisoned.into_inner(),
        };
        *observed = true;
        self.changed.notify_all();
    }
}

/// Test-owned cancellation observation that exercises the production hook path.
#[cfg(test)]
pub(crate) struct ExecutionCancellationObserver {
    state: Arc<ExecutionCancellationObserverState>,
    _registration: ExecutionCancellationHookRegistration,
}

#[cfg(test)]
impl ExecutionCancellationObserver {
    fn new(cancellation: &ExecutionCancellation) -> Result<Self, &'static str> {
        let state = Arc::new(ExecutionCancellationObserverState::default());
        let hook: Arc<dyn ExecutionCancellationHook> = state.clone();
        let registration = cancellation.register_hook(hook)?;

        Ok(Self {
            state,
            _registration: registration,
        })
    }

    /// Waits up to `timeout` for the installed hook to observe cancellation.
    #[must_use]
    pub(crate) fn wait_for_cancellation(&self, timeout: Duration) -> bool {
        let mut observed = match self.state.observed.lock() {
            Ok(observed) => observed,
            Err(_) => return true,
        };
        if *observed {
            return true;
        }

        let mut remaining = timeout;
        loop {
            let slice = remaining.min(MAX_CANCELLATION_WAIT_SLICE);
            let result = self
                .state
                .changed
                .wait_timeout_while(observed, slice, |observed| !*observed);
            let (next_observed, elapsed) = match result {
                Ok(result) => result,
                Err(_) => return true,
            };
            observed = next_observed;
            if *observed {
                return true;
            }
            if !elapsed.timed_out() {
                continue;
            }
            let Some(next_remaining) = remaining.checked_sub(slice) else {
                return false;
            };
            if next_remaining.is_zero() {
                return false;
            }
            remaining = next_remaining;
        }
    }

    #[cfg(test)]
    pub(super) fn hold_observation_for_test(&self) -> MutexGuard<'_, bool> {
        match self.state.observed.lock() {
            Ok(observed) => observed,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[cfg(test)]
    pub(super) fn poison_observation_for_test(&self) {
        let _observed = match self.state.observed.lock() {
            Ok(observed) => observed,
            Err(poisoned) => poisoned.into_inner(),
        };
        panic!("poison cancellation observer lock");
    }
}
