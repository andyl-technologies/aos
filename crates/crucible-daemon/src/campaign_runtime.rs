//! Long-lived bounded driving for one local campaign supervisor.
//!
//! The campaign repository owns durable semantic progress, while
//! [`CampaignSupervisor`] owns only restart-rebuildable planner and executor
//! coordination. This module gives that bounded step machine one daemon-owned
//! thread, sticky shutdown, explicit wakeups, and a finite fallback poll for
//! asynchronous executor completion. It does not add another queue of modeled
//! work: every call still delegates to exactly one
//! [`CampaignSupervisor::step`] operation.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crucible_campaign::{
    CampaignExecutorCancelOutcome, CampaignExecutorCheckpointOutcome, CampaignExecutorStepOutcome,
    CampaignPlannerStepOutcome, CampaignSupervisor, CampaignSupervisorStepOutcome,
    ExecutorControlService, ExecutorResumeService, PlannerService,
};

/// Smallest allowed fallback poll interval for one campaign runtime.
pub const MIN_CAMPAIGN_RUNTIME_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Largest allowed fallback poll interval for one campaign runtime.
pub const MAX_CAMPAIGN_RUNTIME_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Default fallback poll interval for asynchronous executor progress.
pub const DEFAULT_CAMPAIGN_RUNTIME_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum immediate component operations before an interruptible fairness pause.
pub const MAX_CAMPAIGN_RUNTIME_IMMEDIATE_BURST: u64 = 256;

/// One bounded runtime step disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignRuntimeStepDisposition {
    /// Another step can make immediate bounded progress.
    Continue,
    /// The driver is quiescent until an explicit wake or fallback poll.
    Wait,
}

/// Bounded step machine owned by one campaign runtime thread.
pub trait CampaignRuntimeDriver {
    /// Stable failure returned by one bounded driver step.
    type Error;

    /// Performs at most one component operation and selects the next cadence.
    ///
    /// # Errors
    ///
    /// Returns a repository, planner, executor, or driver-specific failure.
    /// The runtime stops and makes that failure observable from its join path.
    fn step(&mut self) -> Result<CampaignRuntimeStepDisposition, Self::Error>;
}

impl<P, E> CampaignRuntimeDriver for CampaignSupervisor<P, E>
where
    P: PlannerService,
    E: ExecutorControlService + ExecutorResumeService,
{
    type Error = crucible_campaign::CampaignSupervisorError<P::Error, E::Error>;

    fn step(&mut self) -> Result<CampaignRuntimeStepDisposition, Self::Error> {
        let outcome = CampaignSupervisor::step(self)?;
        Ok(supervisor_step_disposition(&outcome))
    }
}

/// Cloneable signal for repository or executor progress relevant to a runtime.
#[derive(Clone, Debug)]
pub struct CampaignRuntimeWake {
    shared: Arc<CampaignRuntimeShared>,
}

impl CampaignRuntimeWake {
    /// Wakes the attached runtime after externally visible progress.
    pub fn wake(&self) {
        self.shared.generation.fetch_add(1, Ordering::AcqRel);
        self.shared.changed.notify_all();
    }

    /// Returns whether terminal runtime shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.shared.shutdown.load(Ordering::Acquire)
    }
}

/// Fixed configuration for one campaign runtime thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignRuntimeConfig {
    poll_interval: Duration,
}

impl CampaignRuntimeConfig {
    /// Creates a runtime configuration with one finite fallback poll interval.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRuntimeConfigError`] when `poll_interval` is shorter
    /// than 1 ms or longer than 60 seconds.
    pub const fn new(poll_interval: Duration) -> Result<Self, CampaignRuntimeConfigError> {
        if poll_interval.as_nanos() < MIN_CAMPAIGN_RUNTIME_POLL_INTERVAL.as_nanos()
            || poll_interval.as_nanos() > MAX_CAMPAIGN_RUNTIME_POLL_INTERVAL.as_nanos()
        {
            return Err(CampaignRuntimeConfigError::InvalidPollInterval);
        }
        Ok(Self { poll_interval })
    }

    /// Returns the fallback poll interval.
    #[must_use]
    pub const fn poll_interval(self) -> Duration {
        self.poll_interval
    }
}

impl Default for CampaignRuntimeConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_CAMPAIGN_RUNTIME_POLL_INTERVAL,
        }
    }
}

/// Invalid static campaign-runtime configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CampaignRuntimeConfigError {
    /// The fallback interval is outside the fixed 1 ms through 60 s range.
    #[error("campaign runtime poll interval must be in 1 ms..=60 s")]
    InvalidPollInterval,
}

/// Final bounded counters from one campaign runtime incarnation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CampaignRuntimeReport {
    steps: u64,
    immediate_continuations: u64,
    explicit_wakes: u64,
    fallback_polls: u64,
    fairness_pauses: u64,
}

impl CampaignRuntimeReport {
    /// Returns the number of bounded driver steps performed.
    #[must_use]
    pub const fn steps(self) -> u64 {
        self.steps
    }

    /// Returns the number of steps followed immediately by another step.
    #[must_use]
    pub const fn immediate_continuations(self) -> u64 {
        self.immediate_continuations
    }

    /// Returns the number of quiescent waits ended by an explicit wake.
    #[must_use]
    pub const fn explicit_wakes(self) -> u64 {
        self.explicit_wakes
    }

    /// Returns the number of quiescent waits ended by fallback polling.
    #[must_use]
    pub const fn fallback_polls(self) -> u64 {
        self.fallback_polls
    }

    /// Returns the number of 256-step bursts ended by a fairness pause.
    #[must_use]
    pub const fn fairness_pauses(self) -> u64 {
        self.fairness_pauses
    }
}

/// Long-lived owner of one bounded campaign driver thread.
#[must_use = "campaign runtime must be shut down and joined"]
pub struct CampaignRuntime<D>
where
    D: CampaignRuntimeDriver,
{
    wake: CampaignRuntimeWake,
    worker: Option<JoinHandle<Result<CampaignRuntimeReport, D::Error>>>,
}

impl<D> CampaignRuntime<D>
where
    D: CampaignRuntimeDriver + Send + 'static,
    D::Error: Send + 'static,
{
    /// Starts one fixed thread for a bounded campaign driver.
    ///
    /// The thread performs one initial step. Immediate semantic progress may
    /// continue without sleeping; quiescent states wait for [`CampaignRuntimeWake`]
    /// or the finite fallback interval.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRuntimeStartError`] when the operating system refuses
    /// to create the fixed runtime thread.
    pub fn start(
        driver: D,
        config: CampaignRuntimeConfig,
    ) -> Result<Self, CampaignRuntimeStartError> {
        let shared = Arc::new(CampaignRuntimeShared::default());
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name(String::from("crucible-campaign-runtime"))
            .spawn(move || campaign_runtime_loop(driver, worker_shared, config.poll_interval()))
            .map_err(|source| CampaignRuntimeStartError::Spawn { source })?;
        Ok(Self {
            wake: CampaignRuntimeWake { shared },
            worker: Some(worker),
        })
    }

    /// Returns a cloneable explicit progress signal.
    #[must_use]
    pub fn wake_handle(&self) -> CampaignRuntimeWake {
        self.wake.clone()
    }

    /// Requests sticky shutdown and interrupts any quiescent wait.
    pub fn request_shutdown(&self) {
        self.wake.shared.shutdown.store(true, Ordering::Release);
        self.wake.wake();
    }

    /// Requests shutdown, joins the fixed thread, and returns final counters.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRuntimeJoinError::Driver`] when one bounded driver
    /// step failed, or [`CampaignRuntimeJoinError::ThreadPanicked`] if the
    /// runtime escaped through an invariant panic.
    pub fn shutdown_and_join(
        mut self,
    ) -> Result<CampaignRuntimeReport, CampaignRuntimeJoinError<D::Error>> {
        self.request_shutdown();
        let worker = self
            .worker
            .take()
            .ok_or(CampaignRuntimeJoinError::ThreadPanicked)?;
        worker
            .join()
            .map_err(|_| CampaignRuntimeJoinError::ThreadPanicked)?
            .map_err(CampaignRuntimeJoinError::Driver)
    }
}

impl<D> Drop for CampaignRuntime<D>
where
    D: CampaignRuntimeDriver,
{
    fn drop(&mut self) {
        self.wake.shared.shutdown.store(true, Ordering::Release);
        self.wake.wake();
        // Dropping the handle detaches, but the fixed thread observes sticky
        // shutdown before another component call and then releases the driver.
        drop(self.worker.take());
    }
}

/// Failure while starting one campaign runtime thread.
#[derive(Debug, thiserror::Error)]
pub enum CampaignRuntimeStartError {
    /// The operating system refused to create the fixed runtime thread.
    #[error("campaign runtime thread could not be created")]
    Spawn {
        /// Underlying operating-system failure.
        source: io::Error,
    },
}

/// Terminal result while joining one campaign runtime.
#[derive(Debug, thiserror::Error)]
pub enum CampaignRuntimeJoinError<E> {
    /// One bounded driver step failed and stopped the runtime.
    #[error("campaign runtime driver failed")]
    Driver(E),
    /// The fixed runtime thread escaped through an invariant panic.
    #[error("campaign runtime thread panicked")]
    ThreadPanicked,
}

#[derive(Debug, Default)]
struct CampaignRuntimeShared {
    shutdown: AtomicBool,
    generation: AtomicU64,
    wait: Mutex<()>,
    changed: Condvar,
}

fn campaign_runtime_loop<D>(
    mut driver: D,
    shared: Arc<CampaignRuntimeShared>,
    poll_interval: Duration,
) -> Result<CampaignRuntimeReport, D::Error>
where
    D: CampaignRuntimeDriver,
{
    let mut report = CampaignRuntimeReport::default();
    let mut immediate_burst = 0_u64;
    while !shared.shutdown.load(Ordering::Acquire) {
        let generation = shared.generation.load(Ordering::Acquire);
        let disposition = driver.step()?;
        report.steps = report.steps.saturating_add(1);
        if disposition == CampaignRuntimeStepDisposition::Continue {
            report.immediate_continuations = report.immediate_continuations.saturating_add(1);
            immediate_burst = immediate_burst.saturating_add(1);
            if immediate_burst >= MAX_CAMPAIGN_RUNTIME_IMMEDIATE_BURST {
                immediate_burst = 0;
                report.fairness_pauses = report.fairness_pauses.saturating_add(1);
                wait_for_runtime_fairness(&shared);
            }
            thread::yield_now();
            continue;
        }
        immediate_burst = 0;
        if shared.shutdown.load(Ordering::Acquire) {
            break;
        }
        if shared.generation.load(Ordering::Acquire) != generation {
            report.explicit_wakes = report.explicit_wakes.saturating_add(1);
            continue;
        }

        let wait = match shared.wait.lock() {
            Ok(wait) => wait,
            Err(_) => break,
        };
        let result = shared.changed.wait_timeout_while(wait, poll_interval, |_| {
            !shared.shutdown.load(Ordering::Acquire)
                && shared.generation.load(Ordering::Acquire) == generation
        });
        let Ok((_wait, elapsed)) = result else {
            break;
        };
        if shared.shutdown.load(Ordering::Acquire) {
            break;
        }
        if elapsed.timed_out() {
            report.fallback_polls = report.fallback_polls.saturating_add(1);
        } else {
            report.explicit_wakes = report.explicit_wakes.saturating_add(1);
        }
    }
    Ok(report)
}

fn wait_for_runtime_fairness(shared: &CampaignRuntimeShared) {
    if shared.shutdown.load(Ordering::Acquire) {
        return;
    }
    let Ok(wait) = shared.wait.lock() else {
        return;
    };
    let _result =
        shared
            .changed
            .wait_timeout_while(wait, MIN_CAMPAIGN_RUNTIME_POLL_INTERVAL, |_| {
                !shared.shutdown.load(Ordering::Acquire)
            });
}

fn supervisor_step_disposition(
    outcome: &CampaignSupervisorStepOutcome,
) -> CampaignRuntimeStepDisposition {
    match outcome {
        CampaignSupervisorStepOutcome::Inactive { .. }
        | CampaignSupervisorStepOutcome::Planner(
            CampaignPlannerStepOutcome::Inactive { .. }
            | CampaignPlannerStepOutcome::Settled { .. },
        )
        | CampaignSupervisorStepOutcome::Executor {
            outcome:
                CampaignExecutorStepOutcome::Inactive { .. }
                | CampaignExecutorStepOutcome::Running { .. }
                | CampaignExecutorStepOutcome::Checkpointed { .. }
                | CampaignExecutorStepOutcome::RetryScheduled { .. }
                | CampaignExecutorStepOutcome::Blocked { .. },
            ..
        }
        | CampaignSupervisorStepOutcome::Checkpoint(
            CampaignExecutorCheckpointOutcome::Requested { .. }
            | CampaignExecutorCheckpointOutcome::Publishing { .. }
            | CampaignExecutorCheckpointOutcome::Paused { .. },
        ) => CampaignRuntimeStepDisposition::Wait,
        CampaignSupervisorStepOutcome::Planner(CampaignPlannerStepOutcome::Advanced { .. })
        | CampaignSupervisorStepOutcome::Executor { .. }
        | CampaignSupervisorStepOutcome::Cancellation(
            CampaignExecutorCancelOutcome::Idle
            | CampaignExecutorCancelOutcome::Released { .. }
            | CampaignExecutorCancelOutcome::Canceled { .. }
            | CampaignExecutorCancelOutcome::AssignmentRenewed { .. }
            | CampaignExecutorCancelOutcome::Incorporated(_),
        )
        | CampaignSupervisorStepOutcome::Checkpoint(
            CampaignExecutorCheckpointOutcome::Idle
            | CampaignExecutorCheckpointOutcome::Released { .. }
            | CampaignExecutorCheckpointOutcome::Incorporated(_)
            | CampaignExecutorCheckpointOutcome::AssignmentRenewed { .. },
        ) => CampaignRuntimeStepDisposition::Continue,
    }
}

#[cfg(test)]
mod tests;
