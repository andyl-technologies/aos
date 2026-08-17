//! Parallel top-level failure and cancellation precursors.
//!
//! This module owns the safe Phase 3.5 boundary for L1 root failures before
//! the full parallel evaluator exists. It models three RFC-0007 rules:
//!
//! ```text
//! per-root failures are data, not scheduler corruption
//! reported failures are selected by stable root order
//! fail-fast cancellation is cooperative at task boundaries
//! ```
//!
//! The original executor here still uses standard-library deques, mutexes, and
//! scoped threads. The Chase-Lev entry points delegate queue ownership to
//! [`super::parallel_chase_lev`] while keeping root-local error collation and
//! cooperative cancellation in this module. Neither path stores per-thunk error
//! payloads, wakes thunk waiters, interrupts in-flight work, or replaces the
//! final work-stealing scheduler.

use std::{
    collections::VecDeque,
    fmt,
    num::NonZeroUsize,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use thiserror::Error;

use super::parallel_chase_lev::{
    ParallelChaseLevTaskSource, ParallelChaseLevWorkerQueue, parallel_chase_lev_worker_queues,
};

/// Executes independent top-level tasks whose evaluation can fail.
///
/// Task results and task errors are both collected as root-local outcomes.
/// Infrastructure failures, such as poisoned queues or worker panics, are
/// returned as [`ParallelFallibleTopLevelError`]. Successful reports sort
/// outcomes by stable task index so callers can select the canonical error
/// independently of completion order.
///
/// With [`ParallelFailurePolicy::CancelQueuedAfterFirstError`], the first task
/// error requests cancellation with a shared flag. Workers observe that flag only
/// before probing queues for more top-level work, so in-flight work is allowed
/// to finish. This is a cooperative boundary check, not a hard exclusion for a
/// worker that already passed the check while another worker was publishing the
/// cancellation request.
///
/// # Errors
///
/// Returns [`ParallelFallibleTopLevelError`] if a worker queue or result buffer
/// is poisoned, if a worker queue cannot be found for an internal worker id, or
/// if a worker thread panics while evaluating a task.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelFallibleTopLevelError::WorkerPanicked`].
pub fn execute_parallel_top_level_fallible<I, T, R, E, F>(
    tasks: I,
    worker_count: NonZeroUsize,
    policy: ParallelFailurePolicy,
    worker: F,
) -> Result<ParallelFallibleTopLevelReport<R, E>, ParallelFallibleTopLevelError>
where
    I: IntoIterator<Item = T>,
    T: Send,
    R: Send,
    E: Send,
    F: Fn(T) -> Result<R, E> + Sync,
{
    execute_parallel_top_level_fallible_with_worker(tasks, worker_count, policy, |_, payload| {
        worker(payload)
    })
}

/// Executes independent fallible top-level tasks with Chase-Lev worker deques.
///
/// This entry point has the same outcome collation and cooperative cancellation
/// contract as [`execute_parallel_top_level_fallible`], but its worker queues
/// are backed by the Phase 3.5 Chase-Lev deque adapter instead of the
/// standard-library mutex queue precursor.
///
/// # Errors
///
/// Returns [`ParallelFallibleTopLevelError`] if the result buffer is poisoned
/// by a panic, or if a worker thread panics while evaluating a task.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelFallibleTopLevelError::WorkerPanicked`].
pub fn execute_parallel_top_level_fallible_chase_lev<I, T, R, E, F>(
    tasks: I,
    worker_count: NonZeroUsize,
    policy: ParallelFailurePolicy,
    worker: F,
) -> Result<ParallelFallibleTopLevelReport<R, E>, ParallelFallibleTopLevelError>
where
    I: IntoIterator<Item = T>,
    T: Send,
    R: Send,
    E: Send,
    F: Fn(T) -> Result<R, E> + Sync,
{
    execute_parallel_top_level_fallible_chase_lev_with_worker(
        tasks,
        worker_count,
        policy,
        |_, payload| worker(payload),
    )
}

/// Executes independent fallible top-level tasks with worker execution context.
///
/// This is the worker-aware form of [`execute_parallel_top_level_fallible`].
/// The supplied closure receives [`ParallelFallibleTaskContext`] describing the
/// stable task index, initial worker queue, executing worker, and worker count
/// for the task currently being evaluated. Outcomes retain the same stable
/// task-order collation and cooperative cancellation semantics as the
/// context-free entry point.
///
/// # Errors
///
/// Returns [`ParallelFallibleTopLevelError`] if a worker queue or result buffer
/// is poisoned, if a worker queue cannot be found for an internal worker id, or
/// if a worker thread panics while evaluating a task.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelFallibleTopLevelError::WorkerPanicked`].
pub fn execute_parallel_top_level_fallible_with_worker<I, T, R, E, F>(
    tasks: I,
    worker_count: NonZeroUsize,
    policy: ParallelFailurePolicy,
    worker: F,
) -> Result<ParallelFallibleTopLevelReport<R, E>, ParallelFallibleTopLevelError>
where
    I: IntoIterator<Item = T>,
    T: Send,
    R: Send,
    E: Send,
    F: Fn(ParallelFallibleTaskContext, T) -> Result<R, E> + Sync,
{
    let worker_count = worker_count.get();
    let mut seeded_queues = (0..worker_count)
        .map(|_| VecDeque::new())
        .collect::<Vec<_>>();
    let mut task_count = 0;

    for (task_index, payload) in tasks.into_iter().enumerate() {
        let initial_worker = task_index % worker_count;
        seeded_queues[initial_worker].push_back(ParallelFallibleTopLevelTask {
            task_index,
            initial_worker,
            payload,
        });
        task_count = task_index + 1;
    }

    let queues = seeded_queues
        .into_iter()
        .map(Mutex::new)
        .collect::<Vec<_>>();
    let outcomes = Mutex::new(Vec::with_capacity(task_count));
    let cancelled = AtomicBool::new(false);

    let worker_reports = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);

        for worker_id in 0..worker_count {
            let queues = &queues;
            let outcomes = &outcomes;
            let cancelled = &cancelled;
            let worker = &worker;
            handles.push((
                worker_id,
                scope.spawn(move || {
                    fallible_worker_loop(
                        worker_id,
                        queues,
                        outcomes,
                        cancelled,
                        policy,
                        worker,
                        worker_count,
                    )
                }),
            ));
        }

        let mut worker_reports = Vec::with_capacity(worker_count);
        let mut first_error = None;
        for (worker_id, handle) in handles {
            match handle.join() {
                Ok(Ok(report)) => worker_reports.push(report),
                Ok(Err(error)) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                Err(_) => {
                    if first_error.is_none() {
                        first_error =
                            Some(ParallelFallibleTopLevelError::WorkerPanicked { worker_id });
                    }
                }
            }
        }

        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(worker_reports)
        }
    })?;

    let cancelled_before_start_count = remaining_queue_len(&queues)?;
    let mut outcomes = outcomes
        .into_inner()
        .map_err(|_| ParallelFallibleTopLevelError::ResultBufferPoisoned)?;
    outcomes.sort_by_key(ParallelTaskOutcome::task_index);

    Ok(ParallelFallibleTopLevelReport {
        worker_count,
        task_count,
        completed_task_count: outcomes.len(),
        cancelled_before_start_count,
        cancelled: cancelled.load(Ordering::Acquire),
        outcomes,
        worker_reports,
    })
}

/// Executes independent fallible Chase-Lev tasks with worker execution context.
///
/// This is the worker-aware form of
/// [`execute_parallel_top_level_fallible_chase_lev`]. The supplied closure
/// receives [`ParallelFallibleTaskContext`] describing the stable task index,
/// initial worker queue, executing worker, and worker count for the task
/// currently being evaluated.
///
/// # Errors
///
/// Returns [`ParallelFallibleTopLevelError`] if the result buffer is poisoned
/// by a panic, or if a worker thread panics while evaluating a task.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelFallibleTopLevelError::WorkerPanicked`].
pub fn execute_parallel_top_level_fallible_chase_lev_with_worker<I, T, R, E, F>(
    tasks: I,
    worker_count: NonZeroUsize,
    policy: ParallelFailurePolicy,
    worker: F,
) -> Result<ParallelFallibleTopLevelReport<R, E>, ParallelFallibleTopLevelError>
where
    I: IntoIterator<Item = T>,
    T: Send,
    R: Send,
    E: Send,
    F: Fn(ParallelFallibleTaskContext, T) -> Result<R, E> + Sync,
{
    let queues = parallel_chase_lev_worker_queues(tasks, worker_count);
    let worker_count = queues.worker_count();
    let task_count = queues.task_count();
    let worker_queues = queues.into_worker_queues();
    let outcomes = Mutex::new(Vec::with_capacity(task_count));
    let cancelled = AtomicBool::new(false);

    let worker_reports = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);

        for worker_queue in worker_queues {
            let worker_id = worker_queue.worker_id();
            let outcomes = &outcomes;
            let cancelled = &cancelled;
            let worker = &worker;
            handles.push((
                worker_id,
                scope.spawn(move || {
                    chase_lev_fallible_worker_loop(
                        worker_queue,
                        outcomes,
                        cancelled,
                        policy,
                        worker,
                    )
                }),
            ));
        }

        let mut worker_reports = Vec::with_capacity(worker_count);
        let mut first_error = None;
        for (worker_id, handle) in handles {
            match handle.join() {
                Ok(Ok(report)) => worker_reports.push(report),
                Ok(Err(error)) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                Err(_) => {
                    if first_error.is_none() {
                        first_error =
                            Some(ParallelFallibleTopLevelError::WorkerPanicked { worker_id });
                    }
                }
            }
        }

        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(worker_reports)
        }
    })?;

    let mut outcomes = outcomes
        .into_inner()
        .map_err(|_| ParallelFallibleTopLevelError::ResultBufferPoisoned)?;
    outcomes.sort_by_key(ParallelTaskOutcome::task_index);
    let completed_task_count = outcomes.len();
    debug_assert!(
        completed_task_count <= task_count,
        "Chase-Lev fallible executor cannot complete more tasks than were submitted"
    );
    let cancelled_before_start_count = task_count.saturating_sub(completed_task_count);

    Ok(ParallelFallibleTopLevelReport {
        worker_count,
        task_count,
        completed_task_count,
        cancelled_before_start_count,
        cancelled: cancelled.load(Ordering::Acquire),
        outcomes,
        worker_reports,
    })
}

fn fallible_worker_loop<T, R, E, F>(
    worker_id: usize,
    queues: &[Mutex<VecDeque<ParallelFallibleTopLevelTask<T>>>],
    outcomes: &Mutex<Vec<ParallelTaskOutcome<R, E>>>,
    cancelled: &AtomicBool,
    policy: ParallelFailurePolicy,
    worker: &F,
    worker_count: usize,
) -> Result<ParallelFailureWorkerReport, ParallelFallibleTopLevelError>
where
    F: Fn(ParallelFallibleTaskContext, T) -> Result<R, E>,
{
    let mut report = ParallelFailureWorkerReport::new(worker_id);

    while let Some(task) = take_next_fallible_task(
        queues,
        worker_id,
        worker_count,
        cancelled,
        policy,
        &mut report,
    )? {
        let task_index = task.task_index;
        let initial_worker = task.initial_worker;
        let context = ParallelFallibleTaskContext {
            task_index,
            initial_worker,
            worker_id,
            worker_count,
        };
        let outcome = worker(context, task.payload);
        if outcome.is_err() {
            report.task_errors += 1;
            if policy.cancels_queued_after_first_error() {
                cancelled.store(true, Ordering::Release);
            }
        }

        report.tasks_completed += 1;
        lock_outcomes(outcomes)?.push(ParallelTaskOutcome {
            task_index,
            initial_worker,
            worker_id,
            outcome,
        });
    }

    Ok(report)
}

fn chase_lev_fallible_worker_loop<T, R, E, F>(
    queue: ParallelChaseLevWorkerQueue<T>,
    outcomes: &Mutex<Vec<ParallelTaskOutcome<R, E>>>,
    cancelled: &AtomicBool,
    policy: ParallelFailurePolicy,
    worker: &F,
) -> Result<ParallelFailureWorkerReport, ParallelFallibleTopLevelError>
where
    F: Fn(ParallelFallibleTaskContext, T) -> Result<R, E>,
{
    let mut report = ParallelFailureWorkerReport::new(queue.worker_id());

    loop {
        if policy.cancels_queued_after_first_error() && cancelled.load(Ordering::Acquire) {
            report.task_boundary_cancellations += 1;
            return Ok(report);
        }

        let Some(take) = queue.take_next_retrying() else {
            return Ok(report);
        };

        match take.source() {
            ParallelChaseLevTaskSource::Local => report.local_pops += 1,
            ParallelChaseLevTaskSource::Stolen => report.steals += 1,
        }

        let task = take.into_task();
        let task_index = task.task_index();
        let initial_worker = task.initial_worker();
        let worker_id = report.worker_id;
        let context = ParallelFallibleTaskContext {
            task_index,
            initial_worker,
            worker_id,
            worker_count: queue.worker_count(),
        };
        let outcome = worker(context, task.into_payload());
        if outcome.is_err() {
            report.task_errors += 1;
            if policy.cancels_queued_after_first_error() {
                cancelled.store(true, Ordering::Release);
            }
        }

        report.tasks_completed += 1;
        lock_outcomes(outcomes)?.push(ParallelTaskOutcome {
            task_index,
            initial_worker,
            worker_id,
            outcome,
        });
    }
}

fn take_next_fallible_task<T>(
    queues: &[Mutex<VecDeque<ParallelFallibleTopLevelTask<T>>>],
    worker_id: usize,
    worker_count: usize,
    cancelled: &AtomicBool,
    policy: ParallelFailurePolicy,
    report: &mut ParallelFailureWorkerReport,
) -> Result<Option<ParallelFallibleTopLevelTask<T>>, ParallelFallibleTopLevelError> {
    if policy.cancels_queued_after_first_error() && cancelled.load(Ordering::Acquire) {
        report.task_boundary_cancellations += 1;
        return Ok(None);
    }

    {
        let mut own_queue = lock_queue(queues, worker_id)?;
        if let Some(task) = own_queue.pop_back() {
            report.local_pops += 1;
            return Ok(Some(task));
        }
    }

    for offset in 1..worker_count {
        let victim_id = (worker_id + offset) % worker_count;
        let mut victim_queue = lock_queue(queues, victim_id)?;
        if let Some(task) = victim_queue.pop_front() {
            report.steals += 1;
            return Ok(Some(task));
        }
    }

    Ok(None)
}

fn lock_queue<T>(
    queues: &[Mutex<VecDeque<ParallelFallibleTopLevelTask<T>>>],
    worker_id: usize,
) -> Result<MutexGuard<'_, VecDeque<ParallelFallibleTopLevelTask<T>>>, ParallelFallibleTopLevelError>
{
    let queue = queues
        .get(worker_id)
        .ok_or(ParallelFallibleTopLevelError::WorkerQueueMissing { worker_id })?;
    queue
        .lock()
        .map_err(|_| ParallelFallibleTopLevelError::WorkerQueuePoisoned { worker_id })
}

fn lock_outcomes<R, E>(
    outcomes: &Mutex<Vec<ParallelTaskOutcome<R, E>>>,
) -> Result<MutexGuard<'_, Vec<ParallelTaskOutcome<R, E>>>, ParallelFallibleTopLevelError> {
    outcomes
        .lock()
        .map_err(|_| ParallelFallibleTopLevelError::ResultBufferPoisoned)
}

fn remaining_queue_len<T>(
    queues: &[Mutex<VecDeque<ParallelFallibleTopLevelTask<T>>>],
) -> Result<usize, ParallelFallibleTopLevelError> {
    let mut remaining = 0_usize;
    for worker_id in 0..queues.len() {
        remaining += lock_queue(queues, worker_id)?.len();
    }
    Ok(remaining)
}

struct ParallelFallibleTopLevelTask<T> {
    task_index: usize,
    initial_worker: usize,
    payload: T,
}

/// Execution context passed to worker-aware fallible top-level tasks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelFallibleTaskContext {
    task_index: usize,
    initial_worker: usize,
    worker_id: usize,
    worker_count: usize,
}

impl ParallelFallibleTaskContext {
    /// Builds a worker context for unit tests of worker-aware bridge helpers.
    #[cfg(test)]
    pub(crate) const fn for_test(
        task_index: usize,
        initial_worker: usize,
        worker_id: usize,
        worker_count: usize,
    ) -> Self {
        Self {
            task_index,
            initial_worker,
            worker_id,
            worker_count,
        }
    }

    /// Returns the stable top-level task index.
    pub const fn task_index(self) -> usize {
        self.task_index
    }

    /// Returns the worker queue that initially owned this task.
    pub const fn initial_worker(self) -> usize {
        self.initial_worker
    }

    /// Returns the worker that is executing this task.
    pub const fn worker_id(self) -> usize {
        self.worker_id
    }

    /// Returns the total number of scheduler workers.
    pub const fn worker_count(self) -> usize {
        self.worker_count
    }
}

/// The cancellation policy for fallible top-level execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParallelFailurePolicy {
    /// Continue evaluating every queued top-level task after root-local errors.
    CollectAll,
    /// Stop taking new top-level tasks after the first observed root-local error.
    CancelQueuedAfterFirstError,
}

impl ParallelFailurePolicy {
    const fn cancels_queued_after_first_error(self) -> bool {
        matches!(self, Self::CancelQueuedAfterFirstError)
    }
}

/// The root-local outcome produced by one top-level task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelTaskOutcome<R, E> {
    task_index: usize,
    initial_worker: usize,
    worker_id: usize,
    outcome: Result<R, E>,
}

impl<R, E> ParallelTaskOutcome<R, E> {
    /// Builds a task outcome for malformed-report unit tests.
    #[cfg(test)]
    pub(super) fn for_test(
        task_index: usize,
        initial_worker: usize,
        worker_id: usize,
        outcome: Result<R, E>,
    ) -> Self {
        Self {
            task_index,
            initial_worker,
            worker_id,
            outcome,
        }
    }

    /// Returns the stable top-level task index.
    pub const fn task_index(&self) -> usize {
        self.task_index
    }

    /// Returns the worker queue that initially owned this task.
    pub const fn initial_worker(&self) -> usize {
        self.initial_worker
    }

    /// Returns the worker that completed this task.
    pub const fn worker_id(&self) -> usize {
        self.worker_id
    }

    /// Returns the root-local outcome.
    pub const fn outcome(&self) -> &Result<R, E> {
        &self.outcome
    }

    /// Returns whether this task completed successfully.
    pub const fn is_ok(&self) -> bool {
        self.outcome.is_ok()
    }

    /// Returns whether this task completed with a root-local error.
    pub const fn is_err(&self) -> bool {
        self.outcome.is_err()
    }
}

/// Execution counters for one fallible scheduler worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelFailureWorkerReport {
    worker_id: usize,
    local_pops: usize,
    steals: usize,
    tasks_completed: usize,
    task_errors: usize,
    task_boundary_cancellations: usize,
}

impl ParallelFailureWorkerReport {
    const fn new(worker_id: usize) -> Self {
        Self {
            worker_id,
            local_pops: 0,
            steals: 0,
            tasks_completed: 0,
            task_errors: 0,
            task_boundary_cancellations: 0,
        }
    }

    /// Returns the worker index in the execution pool.
    pub const fn worker_id(self) -> usize {
        self.worker_id
    }

    /// Returns the number of tasks popped from this worker's own deque.
    pub const fn local_pops(self) -> usize {
        self.local_pops
    }

    /// Returns the number of tasks stolen from peer deques.
    pub const fn steals(self) -> usize {
        self.steals
    }

    /// Returns the number of completed top-level tasks.
    pub const fn tasks_completed(self) -> usize {
        self.tasks_completed
    }

    /// Returns the number of root-local task errors this worker observed.
    pub const fn task_errors(self) -> usize {
        self.task_errors
    }

    /// Returns how many times this worker stopped at a task boundary because
    /// cooperative cancellation had been requested.
    pub const fn task_boundary_cancellations(self) -> usize {
        self.task_boundary_cancellations
    }
}

/// A complete report from fallible top-level execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelFallibleTopLevelReport<R, E> {
    worker_count: usize,
    task_count: usize,
    completed_task_count: usize,
    cancelled_before_start_count: usize,
    cancelled: bool,
    outcomes: Vec<ParallelTaskOutcome<R, E>>,
    worker_reports: Vec<ParallelFailureWorkerReport>,
}

impl<R, E> ParallelFallibleTopLevelReport<R, E> {
    /// Builds a fallible report for malformed-report unit tests.
    #[cfg(test)]
    pub(super) fn for_test(
        worker_count: usize,
        task_count: usize,
        completed_task_count: usize,
        cancelled_before_start_count: usize,
        cancelled: bool,
        outcomes: Vec<ParallelTaskOutcome<R, E>>,
    ) -> Self {
        Self {
            worker_count,
            task_count,
            completed_task_count,
            cancelled_before_start_count,
            cancelled,
            outcomes,
            worker_reports: (0..worker_count)
                .map(ParallelFailureWorkerReport::new)
                .collect(),
        }
    }

    /// Returns the number of workers used for this execution.
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Returns the number of top-level tasks submitted to the executor.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Returns the number of top-level tasks that completed before shutdown.
    pub const fn completed_task_count(&self) -> usize {
        self.completed_task_count
    }

    /// Returns the number of queued tasks skipped by cooperative cancellation.
    pub const fn cancelled_before_start_count(&self) -> usize {
        self.cancelled_before_start_count
    }

    /// Returns whether any root-local error requested cancellation.
    pub const fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// Returns root-local outcomes sorted by stable task index.
    pub fn outcomes(&self) -> &[ParallelTaskOutcome<R, E>] {
        &self.outcomes
    }

    /// Returns worker execution counters sorted by worker id.
    pub fn worker_reports(&self) -> &[ParallelFailureWorkerReport] {
        &self.worker_reports
    }

    /// Returns the canonical observed error by lowest stable task index.
    pub fn canonical_error(&self) -> Option<&ParallelTaskOutcome<R, E>> {
        self.outcomes.iter().find(|outcome| outcome.is_err())
    }

    /// Consumes the report and returns outcomes sorted by stable task index.
    pub fn into_outcomes(self) -> Vec<ParallelTaskOutcome<R, E>> {
        self.outcomes
    }
}

/// A scheduler infrastructure failure during fallible top-level execution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParallelFallibleTopLevelError {
    /// A worker queue was addressed outside the configured worker set.
    #[error("parallel fallible worker queue {worker_id} is not present")]
    WorkerQueueMissing {
        /// The missing worker queue index.
        worker_id: usize,
    },
    /// A worker queue mutex was poisoned.
    #[error("parallel fallible worker queue {worker_id} is poisoned")]
    WorkerQueuePoisoned {
        /// The poisoned worker queue index.
        worker_id: usize,
    },
    /// The shared result buffer mutex was poisoned.
    #[error("parallel fallible result buffer is poisoned")]
    ResultBufferPoisoned,
    /// A worker panicked while executing a task.
    #[error("parallel fallible worker {worker_id} panicked while executing a task")]
    WorkerPanicked {
        /// The panicking worker index.
        worker_id: usize,
    },
}

impl fmt::Display for ParallelFailurePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CollectAll => formatter.write_str("collect all root-local outcomes"),
            Self::CancelQueuedAfterFirstError => {
                formatter.write_str("cancel queued roots after the first observed error")
            }
        }
    }
}

#[cfg(test)]
mod tests;
