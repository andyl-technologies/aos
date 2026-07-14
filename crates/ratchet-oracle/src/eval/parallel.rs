//! Parallel top-level evaluation scheduling precursors.
//!
//! This module owns the first safe Phase 3.5 scheduling boundary for coarse
//! top-level work. It models the RFC-0007 L1 discipline: seed independent roots
//! across worker-owned queues, let workers pop local work from the hot end, let
//! idle workers steal older peer work from the opposite end, and collate results
//! by stable task index rather than completion order.
//!
//! The original safe executor and ready-work queues here deliberately use
//! standard-library synchronization. The Chase-Lev entry points delegate queue
//! ownership to [`super::parallel_chase_lev`] while keeping result collation,
//! ready-work hook shaping, and error reporting in this module. These are
//! correctness/readiness layers for tests and future evaluator wiring, not the
//! complete parallel graph evaluator and not the L2 CAS thunk protocol.

use std::{
    collections::VecDeque,
    fmt,
    num::NonZeroUsize,
    sync::{Mutex, MutexGuard},
    thread,
};

use thiserror::Error;

use super::parallel_chase_lev::{
    ParallelChaseLevTaskSource, ParallelChaseLevWorkerQueue, parallel_chase_lev_worker_queues,
};
use super::thunk_cas::ParallelThunkWorkerId;
use super::thunk_wait::{
    ParallelThunkContentionReport, ParallelThunkReadyWork, ParallelThunkReadyWorkWaitError,
    ParallelThunkWait, ParallelThunkWaitCell, ParallelThunkWaitError, ParallelThunkWorkWait,
};

/// Builds the deterministic round-robin seed plan for top-level tasks.
///
/// The returned plan is independent of execution timing and is used by the
/// safe scheduler precursor to keep root placement stable across runs.
pub fn parallel_top_level_seed_plan(
    task_count: usize,
    worker_count: NonZeroUsize,
) -> ParallelTopLevelSeedPlan {
    let worker_count = worker_count.get();
    let placements = (0..task_count)
        .map(|task_index| ParallelTaskPlacement {
            task_index,
            initial_worker: task_index % worker_count,
        })
        .collect();

    ParallelTopLevelSeedPlan {
        worker_count,
        task_count,
        placements,
    }
}

/// Executes independent top-level tasks with the safe work-stealing precursor.
///
/// Tasks are seeded round-robin across worker-owned deques. A worker first pops
/// from the back of its own deque, preserving cache-friendly LIFO behavior, then
/// attempts to steal from the front of peer deques. Results are sorted back into
/// task-index order before the report is returned, so caller-visible output is
/// independent of completion order.
///
/// # Examples
///
/// ```no_run
/// use std::num::NonZeroUsize;
///
/// use ratchet_oracle::eval::execute_parallel_top_level;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let workers = NonZeroUsize::new(2).ok_or_else(|| {
///     std::io::Error::new(std::io::ErrorKind::InvalidInput, "worker count cannot be zero")
/// })?;
/// let report = execute_parallel_top_level([1, 2, 3], workers, |value| value * 2)?;
///
/// assert_eq!(report.into_results_in_task_order(), vec![2, 4, 6]);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`ParallelTopLevelError`] if worker queues or the result buffer are
/// poisoned by a panic, or if a worker thread panics while executing a task.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelTopLevelError::WorkerPanicked`].
pub fn execute_parallel_top_level<I, T, R, F>(
    tasks: I,
    worker_count: NonZeroUsize,
    worker: F,
) -> Result<ParallelTopLevelExecutionReport<R>, ParallelTopLevelError>
where
    I: IntoIterator<Item = T>,
    T: Send,
    R: Send,
    F: Fn(T) -> R + Sync,
{
    let worker_count = worker_count.get();
    let mut seeded_queues = (0..worker_count)
        .map(|_| VecDeque::new())
        .collect::<Vec<_>>();
    let mut task_count = 0;

    for (task_index, payload) in tasks.into_iter().enumerate() {
        let initial_worker = task_index % worker_count;
        seeded_queues[initial_worker].push_back(ParallelTopLevelTask {
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
    let results = Mutex::new(Vec::with_capacity(task_count));

    let worker_reports = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);

        for worker_id in 0..worker_count {
            let queues = &queues;
            let results = &results;
            let worker = &worker;
            handles.push((
                worker_id,
                scope.spawn(move || worker_loop(worker_id, queues, results, worker, worker_count)),
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
                        first_error = Some(ParallelTopLevelError::WorkerPanicked { worker_id });
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

    let mut results = results
        .into_inner()
        .map_err(|_| ParallelTopLevelError::ResultBufferPoisoned)?;
    results.sort_by_key(ParallelTaskExecution::task_index);

    Ok(ParallelTopLevelExecutionReport {
        worker_count,
        task_count,
        results,
        worker_reports,
    })
}

/// Executes independent top-level tasks with Chase-Lev worker deques.
///
/// This entry point has the same task metadata and stable result collation
/// contract as [`execute_parallel_top_level`], but its worker queues are backed
/// by the Phase 3.5 Chase-Lev deque adapter instead of the standard-library
/// mutex queue precursor. Workers own their local deque, pop local work in LIFO
/// order, and steal older peer work through cloneable stealers. Result collation
/// remains sorted by stable task index rather than completion order.
///
/// # Errors
///
/// Returns [`ParallelTopLevelError`] if the result buffer is poisoned by a
/// panic, or if a worker thread panics while executing a task.
///
/// # Panics
///
/// Panics if the operating system cannot spawn one of the scoped worker
/// threads. Task panics are caught and returned as
/// [`ParallelTopLevelError::WorkerPanicked`].
pub fn execute_parallel_top_level_chase_lev<I, T, R, F>(
    tasks: I,
    worker_count: NonZeroUsize,
    worker: F,
) -> Result<ParallelTopLevelExecutionReport<R>, ParallelTopLevelError>
where
    I: IntoIterator<Item = T>,
    T: Send,
    R: Send,
    F: Fn(T) -> R + Sync,
{
    let queues = parallel_chase_lev_worker_queues(tasks, worker_count);
    let worker_count = queues.worker_count();
    let task_count = queues.task_count();
    let worker_queues = queues.into_worker_queues();
    let results = Mutex::new(Vec::with_capacity(task_count));

    let worker_reports = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);

        for worker_queue in worker_queues {
            let worker_id = worker_queue.worker_id();
            let results = &results;
            let worker = &worker;
            handles.push((
                worker_id,
                scope.spawn(move || chase_lev_worker_loop(worker_queue, results, worker)),
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
                        first_error = Some(ParallelTopLevelError::WorkerPanicked { worker_id });
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

    let mut results = results
        .into_inner()
        .map_err(|_| ParallelTopLevelError::ResultBufferPoisoned)?;
    results.sort_by_key(ParallelTaskExecution::task_index);

    Ok(ParallelTopLevelExecutionReport {
        worker_count,
        task_count,
        results,
        worker_reports,
    })
}

/// Builds worker-local ready-work queues for thunk wait-or-steal hooks.
///
/// Tasks are seeded with the same round-robin rule as
/// [`execute_parallel_top_level`]. A worker that is blocked on a foreign-owned
/// thunk can call [`ParallelReadyWorkQueues::run_next`] from its ready-work hook
/// to run local work first, then steal older work from peers, and finally report
/// [`ParallelThunkReadyWork::Idle`] when the queues are exhausted.
pub fn parallel_ready_work_queues<I, T>(
    tasks: I,
    worker_count: NonZeroUsize,
) -> ParallelReadyWorkQueues<T>
where
    I: IntoIterator<Item = T>,
{
    let worker_count = worker_count.get();
    let mut seeded_queues = (0..worker_count)
        .map(|_| VecDeque::new())
        .collect::<Vec<_>>();
    let mut task_count = 0;

    for (task_index, payload) in tasks.into_iter().enumerate() {
        let initial_worker = task_index % worker_count;
        seeded_queues[initial_worker].push_back(ParallelReadyWorkTask {
            task_index,
            initial_worker,
            payload,
        });
        task_count = task_index + 1;
    }

    ParallelReadyWorkQueues {
        worker_count,
        task_count,
        queues: seeded_queues.into_iter().map(Mutex::new).collect(),
    }
}

/// Builds owner-local Chase-Lev ready-work queues for thunk wait-or-steal hooks.
///
/// Tasks are seeded with the same round-robin rule as
/// [`parallel_chase_lev_worker_queues`]. The returned pool must be consumed into
/// owner-local worker handles and moved to the corresponding scheduler workers.
/// Each handle can run one local or stolen ready task for a contended thunk wait
/// path, then report an idle preflight observation when no work is available.
pub fn parallel_chase_lev_ready_work_queues<I, T>(
    tasks: I,
    worker_count: NonZeroUsize,
) -> ParallelChaseLevReadyWorkQueues<T>
where
    I: IntoIterator<Item = T>,
{
    ParallelChaseLevReadyWorkQueues {
        queues: parallel_chase_lev_worker_queues(tasks, worker_count),
    }
}

/// Claims a thunk or polls scheduler-backed ready work before waiting.
///
/// This bridge keeps [`ParallelThunkWaitCell`] scheduler-agnostic while letting
/// callers preserve the idle park-preflight evidence from
/// [`ParallelReadyWorkPoll`]. Local or stolen polls feed the wait-cell
/// wait-or-steal loop one task at a time. An idle poll must validate its
/// [`ParallelReadyWorkParkPreflight`] for `ready_worker_id` before the bridge
/// reports [`ParallelThunkReadyWork::Idle`] to the wait cell, so any actual
/// waiter registration can be associated with a checked
/// [`ParallelReadyWorkParkReadiness`] value.
///
/// The readiness is returned only when the wait-cell path really registered a
/// waiter. If the owner publishes a terminal state between the idle preflight
/// and the waiter-registration attempt, the terminal result is returned without
/// park readiness because no parking handoff occurred.
///
/// # Errors
///
/// Returns [`ParallelReadyWorkWaitError::Wait`] if the wait cell rejects a
/// state transition, [`ParallelReadyWorkWaitError::ReadyWork`] if
/// `poll_ready_work` fails, or
/// [`ParallelReadyWorkWaitError::ParkReadiness`] if an idle poll carries a
/// non-idle or wrong-worker preflight snapshot.
///
/// # Panics
///
/// Panics if `poll_ready_work` panics. Queue adapters may also panic if the
/// caller-supplied ready-work runner panics after a task has been removed from
/// its queue.
pub fn claim_or_poll_ready_then_wait<'a, R, E>(
    cell: &'a ParallelThunkWaitCell,
    thunk_worker: ParallelThunkWorkerId,
    ready_worker_id: usize,
    mut poll_ready_work: impl FnMut() -> Result<ParallelReadyWorkPoll<R>, E>,
) -> Result<ParallelReadyWorkWait<'a>, ParallelReadyWorkWaitError<E>> {
    let mut park_readiness = None;
    let work_wait = cell
        .claim_or_try_run_ready_then_wait(thunk_worker, || {
            let poll = poll_ready_work().map_err(ParallelReadyWorkWaitError::ReadyWork)?;
            match &poll {
                ParallelReadyWorkPoll::RanLocal(_) | ParallelReadyWorkPoll::StolePeer(_) => {
                    park_readiness = None;
                }
                ParallelReadyWorkPoll::Idle(preflight) => {
                    park_readiness = Some(
                        preflight
                            .validate_idle_for_worker(ready_worker_id)
                            .map_err(ParallelReadyWorkWaitError::ParkReadiness)?,
                    );
                }
            }
            Ok(poll.ready_work())
        })
        .map_err(|error| match error {
            ParallelThunkReadyWorkWaitError::Wait(error) => ParallelReadyWorkWaitError::Wait(error),
            ParallelThunkReadyWorkWaitError::ReadyWork(error) => error,
        })?;

    if !work_wait.report().wait_registered() {
        park_readiness = None;
    }

    Ok(ParallelReadyWorkWait {
        work_wait,
        park_readiness,
    })
}

mod ready_work;
pub use ready_work::*;

fn worker_loop<T, R, F>(
    worker_id: usize,
    queues: &[Mutex<VecDeque<ParallelTopLevelTask<T>>>],
    results: &Mutex<Vec<ParallelTaskExecution<R>>>,
    worker: &F,
    worker_count: usize,
) -> Result<ParallelWorkerExecutionReport, ParallelTopLevelError>
where
    F: Fn(T) -> R,
{
    let mut report = ParallelWorkerExecutionReport::new(worker_id);

    while let Some(task) = take_next_task(queues, worker_id, worker_count, &mut report)? {
        let task_index = task.task_index;
        let initial_worker = task.initial_worker;
        let result = worker(task.payload);

        report.tasks_completed += 1;
        lock_results(results)?.push(ParallelTaskExecution {
            task_index,
            initial_worker,
            worker_id,
            result,
        });
    }

    Ok(report)
}

fn chase_lev_worker_loop<T, R, F>(
    queue: ParallelChaseLevWorkerQueue<T>,
    results: &Mutex<Vec<ParallelTaskExecution<R>>>,
    worker: &F,
) -> Result<ParallelWorkerExecutionReport, ParallelTopLevelError>
where
    F: Fn(T) -> R,
{
    let mut report = ParallelWorkerExecutionReport::new(queue.worker_id());

    while let Some(take) = queue.take_next_retrying() {
        match take.source() {
            ParallelChaseLevTaskSource::Local => report.local_pops += 1,
            ParallelChaseLevTaskSource::Stolen => report.steals += 1,
        }

        let task = take.into_task();
        let task_index = task.task_index();
        let initial_worker = task.initial_worker();
        let result = worker(task.into_payload());

        report.tasks_completed += 1;
        lock_results(results)?.push(ParallelTaskExecution {
            task_index,
            initial_worker,
            worker_id: report.worker_id,
            result,
        });
    }

    Ok(report)
}

fn take_next_task<T>(
    queues: &[Mutex<VecDeque<ParallelTopLevelTask<T>>>],
    worker_id: usize,
    worker_count: usize,
    report: &mut ParallelWorkerExecutionReport,
) -> Result<Option<ParallelTopLevelTask<T>>, ParallelTopLevelError> {
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
    queues: &[Mutex<VecDeque<ParallelTopLevelTask<T>>>],
    worker_id: usize,
) -> Result<MutexGuard<'_, VecDeque<ParallelTopLevelTask<T>>>, ParallelTopLevelError> {
    let queue = queues
        .get(worker_id)
        .ok_or(ParallelTopLevelError::WorkerQueueMissing { worker_id })?;
    queue
        .lock()
        .map_err(|_| ParallelTopLevelError::WorkerQueuePoisoned { worker_id })
}

fn lock_results<R>(
    results: &Mutex<Vec<ParallelTaskExecution<R>>>,
) -> Result<MutexGuard<'_, Vec<ParallelTaskExecution<R>>>, ParallelTopLevelError> {
    results
        .lock()
        .map_err(|_| ParallelTopLevelError::ResultBufferPoisoned)
}

struct ParallelTopLevelTask<T> {
    task_index: usize,
    initial_worker: usize,
    payload: T,
}

/// A deterministic task-to-worker seed plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelTopLevelSeedPlan {
    worker_count: usize,
    task_count: usize,
    placements: Vec<ParallelTaskPlacement>,
}

impl ParallelTopLevelSeedPlan {
    /// Returns the number of workers in the plan.
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Returns the number of tasks in the plan.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Returns task placements in stable task-index order.
    pub fn placements(&self) -> &[ParallelTaskPlacement] {
        &self.placements
    }
}

/// The initial worker selected for one top-level task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelTaskPlacement {
    task_index: usize,
    initial_worker: usize,
}

impl ParallelTaskPlacement {
    /// Returns the stable task index.
    pub const fn task_index(self) -> usize {
        self.task_index
    }

    /// Returns the worker queue that initially owns this task.
    pub const fn initial_worker(self) -> usize {
        self.initial_worker
    }
}

/// Execution counters for one scheduler worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelWorkerExecutionReport {
    worker_id: usize,
    local_pops: usize,
    steals: usize,
    tasks_completed: usize,
}

impl ParallelWorkerExecutionReport {
    const fn new(worker_id: usize) -> Self {
        Self {
            worker_id,
            local_pops: 0,
            steals: 0,
            tasks_completed: 0,
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

    /// Returns the number of tasks completed by this worker.
    pub const fn tasks_completed(self) -> usize {
        self.tasks_completed
    }
}

/// The result produced for one top-level task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelTaskExecution<R> {
    task_index: usize,
    initial_worker: usize,
    worker_id: usize,
    result: R,
}

impl<R> ParallelTaskExecution<R> {
    /// Returns the stable task index.
    pub const fn task_index(&self) -> usize {
        self.task_index
    }

    /// Returns the worker queue that initially owned the task.
    pub const fn initial_worker(&self) -> usize {
        self.initial_worker
    }

    /// Returns the worker that completed the task.
    pub const fn worker_id(&self) -> usize {
        self.worker_id
    }

    /// Returns the task result.
    pub const fn result(&self) -> &R {
        &self.result
    }
}

/// A complete report from the safe top-level scheduler precursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelTopLevelExecutionReport<R> {
    worker_count: usize,
    task_count: usize,
    results: Vec<ParallelTaskExecution<R>>,
    worker_reports: Vec<ParallelWorkerExecutionReport>,
}

impl<R> ParallelTopLevelExecutionReport<R> {
    /// Returns the number of workers used for this execution.
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Returns the number of executed top-level tasks.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Returns task executions sorted by stable task index.
    pub fn results(&self) -> &[ParallelTaskExecution<R>] {
        &self.results
    }

    /// Returns worker execution counters sorted by worker id.
    pub fn worker_reports(&self) -> &[ParallelWorkerExecutionReport] {
        &self.worker_reports
    }

    /// Consumes the report and returns results sorted by stable task index.
    pub fn into_results_in_task_order(self) -> Vec<R> {
        self.results
            .into_iter()
            .map(|execution| execution.result)
            .collect()
    }
}

/// A failure while executing safe top-level scheduler work.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParallelTopLevelError {
    /// A worker queue was addressed outside the configured worker set.
    #[error("parallel worker queue {worker_id} is not present")]
    WorkerQueueMissing {
        /// The missing worker queue index.
        worker_id: usize,
    },
    /// A worker queue mutex was poisoned.
    #[error("parallel worker queue {worker_id} is poisoned")]
    WorkerQueuePoisoned {
        /// The poisoned worker queue index.
        worker_id: usize,
    },
    /// The shared result buffer mutex was poisoned.
    #[error("parallel result buffer is poisoned")]
    ResultBufferPoisoned,
    /// A worker panicked while executing a task.
    #[error("parallel worker {worker_id} panicked while executing a task")]
    WorkerPanicked {
        /// The panicking worker index.
        worker_id: usize,
    },
}

/// A failure while running scheduler-backed ready work.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParallelReadyWorkError {
    /// A worker queue was addressed outside the configured worker set.
    #[error("parallel ready-work queue {worker_id} is not present")]
    WorkerQueueMissing {
        /// The missing worker queue index.
        worker_id: usize,
    },
    /// A worker queue mutex was poisoned.
    #[error("parallel ready-work queue {worker_id} is poisoned")]
    WorkerQueuePoisoned {
        /// The poisoned worker queue index.
        worker_id: usize,
    },
}

impl fmt::Display for ParallelTopLevelSeedPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} top-level task(s) seeded across {} worker(s)",
            self.task_count, self.worker_count
        )
    }
}

#[cfg(test)]
mod tests;
