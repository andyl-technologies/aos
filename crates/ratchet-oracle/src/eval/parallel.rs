//! Parallel top-level evaluation scheduling precursors.
//!
//! This module owns the first safe Phase 3.5 scheduling boundary for coarse
//! top-level work. It models the RFC-0007 L1 discipline: seed independent roots
//! across worker-owned queues, let workers pop local work from the hot end, let
//! idle workers steal older peer work from the opposite end, and collate results
//! by stable task index rather than completion order.
//!
//! The executor here deliberately uses safe standard-library synchronization.
//! It is a correctness/readiness layer for tests and future evaluator wiring,
//! not the final lock-free Chase-Lev deque implementation and not the L2 CAS
//! thunk protocol.

use std::{
    collections::VecDeque,
    fmt,
    num::NonZeroUsize,
    sync::{Mutex, MutexGuard},
    thread,
};

use thiserror::Error;

use super::thunk_wait::ParallelThunkReadyWork;

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

/// Worker-local ready-work queues for a blocked thunk owner or waiter.
///
/// This is a safe scheduler bridge for the L2 wait-or-steal precursor. It uses
/// standard-library mutexes and deterministic local-pop/peer-steal order; it is
/// not the final Chase-Lev deque implementation and does not hold a scheduler
/// park token.
#[derive(Debug)]
pub struct ParallelReadyWorkQueues<T> {
    worker_count: usize,
    task_count: usize,
    queues: Vec<Mutex<VecDeque<ParallelReadyWorkTask<T>>>>,
}

impl<T> ParallelReadyWorkQueues<T> {
    /// Returns the number of worker-local queues.
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Returns the number of tasks originally seeded into the queues.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Runs one ready-work item or returns an idle park-preflight snapshot.
    ///
    /// This is the hook-friendly form of [`Self::run_next`]. Local and stolen
    /// work are returned as single-task polls so a thunk wait path can recheck
    /// the contended thunk after every executed task. When no task is available,
    /// this captures [`Self::park_preflight_snapshot`] and returns it with the
    /// idle poll.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelReadyWorkError`] if `worker_id` is outside the worker
    /// set or if a ready queue mutex was poisoned.
    ///
    /// # Panics
    ///
    /// Panics if `run` panics. The task has already been removed from its queue
    /// before `run` is called.
    pub fn run_next_or_park_preflight<R>(
        &self,
        worker_id: usize,
        run: impl FnOnce(T) -> R,
    ) -> Result<ParallelReadyWorkPoll<R>, ParallelReadyWorkError> {
        match self.run_next(worker_id, run)? {
            ParallelReadyWorkStep::RanLocal(execution) => {
                Ok(ParallelReadyWorkPoll::RanLocal(execution))
            }
            ParallelReadyWorkStep::StolePeer(execution) => {
                Ok(ParallelReadyWorkPoll::StolePeer(execution))
            }
            ParallelReadyWorkStep::Idle => Ok(ParallelReadyWorkPoll::Idle(
                self.park_preflight_snapshot(worker_id)?,
            )),
        }
    }

    /// Captures queue depths before a worker enters the wait-cell park path.
    ///
    /// The snapshot is taken while holding every ready-work queue mutex in
    /// worker-id order, so [`ParallelReadyWorkParkPreflight::is_idle`] means no
    /// task was present in these safe queues at the observed instant. This is a
    /// diagnostic/preflight artifact only: it does not reserve a scheduler park
    /// token and does not prevent future ready work from being enqueued by a
    /// later scheduler implementation.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelReadyWorkError`] if `worker_id` is outside the worker
    /// set or if any ready queue mutex was poisoned.
    pub fn park_preflight_snapshot(
        &self,
        worker_id: usize,
    ) -> Result<ParallelReadyWorkParkPreflight, ParallelReadyWorkError> {
        if worker_id >= self.worker_count {
            return Err(ParallelReadyWorkError::WorkerQueueMissing { worker_id });
        }

        let mut queue_guards = Vec::with_capacity(self.worker_count);
        for queue_id in 0..self.worker_count {
            queue_guards.push(self.lock_queue(queue_id)?);
        }

        let queue_lengths = queue_guards
            .iter()
            .map(|queue| queue.len())
            .collect::<Vec<_>>();
        let ready_task_count = queue_lengths.iter().sum();

        Ok(ParallelReadyWorkParkPreflight {
            observing_worker: worker_id,
            worker_count: self.worker_count,
            task_count: self.task_count,
            queue_lengths,
            ready_task_count,
        })
    }

    /// Runs one local or stolen ready-work item for `worker_id`.
    ///
    /// The caller supplies `run` so this queue adapter can execute arbitrary
    /// ready work while preserving stable task metadata. Local work is popped
    /// from the back of the worker's own queue. If no local work exists, older
    /// peer work is stolen from the front of peer queues in deterministic worker
    /// order. When no work is available, this returns
    /// [`ParallelReadyWorkStep::Idle`].
    ///
    /// # Errors
    ///
    /// Returns [`ParallelReadyWorkError`] if `worker_id` is outside the worker
    /// set or if a ready queue mutex was poisoned.
    ///
    /// # Panics
    ///
    /// Panics if `run` panics. The task has already been removed from its queue
    /// before `run` is called.
    pub fn run_next<R>(
        &self,
        worker_id: usize,
        run: impl FnOnce(T) -> R,
    ) -> Result<ParallelReadyWorkStep<R>, ParallelReadyWorkError> {
        let Some((task, source)) = self.take_next_task(worker_id)? else {
            return Ok(ParallelReadyWorkStep::Idle);
        };
        let result = run(task.payload);
        let execution = ParallelReadyWorkExecution {
            task_index: task.task_index,
            initial_worker: task.initial_worker,
            worker_id,
            result,
        };
        Ok(match source {
            ParallelReadyWorkSource::Local => ParallelReadyWorkStep::RanLocal(execution),
            ParallelReadyWorkSource::Stolen => ParallelReadyWorkStep::StolePeer(execution),
        })
    }

    fn take_next_task(
        &self,
        worker_id: usize,
    ) -> Result<Option<(ParallelReadyWorkTask<T>, ParallelReadyWorkSource)>, ParallelReadyWorkError>
    {
        if worker_id >= self.worker_count {
            return Err(ParallelReadyWorkError::WorkerQueueMissing { worker_id });
        }

        {
            let mut own_queue = self.lock_queue(worker_id)?;
            if let Some(task) = own_queue.pop_back() {
                return Ok(Some((task, ParallelReadyWorkSource::Local)));
            }
        }

        for offset in 1..self.worker_count {
            let victim_id = (worker_id + offset) % self.worker_count;
            let mut victim_queue = self.lock_queue(victim_id)?;
            if let Some(task) = victim_queue.pop_front() {
                return Ok(Some((task, ParallelReadyWorkSource::Stolen)));
            }
        }

        Ok(None)
    }

    fn lock_queue(
        &self,
        worker_id: usize,
    ) -> Result<MutexGuard<'_, VecDeque<ParallelReadyWorkTask<T>>>, ParallelReadyWorkError> {
        let queue = self
            .queues
            .get(worker_id)
            .ok_or(ParallelReadyWorkError::WorkerQueueMissing { worker_id })?;
        queue
            .lock()
            .map_err(|_| ParallelReadyWorkError::WorkerQueuePoisoned { worker_id })
    }
}

#[derive(Debug)]
struct ParallelReadyWorkTask<T> {
    task_index: usize,
    initial_worker: usize,
    payload: T,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParallelReadyWorkSource {
    Local,
    Stolen,
}

/// One ready-work execution or idle report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParallelReadyWorkStep<R> {
    /// A task from the worker's own queue was executed.
    RanLocal(ParallelReadyWorkExecution<R>),
    /// A task from a peer queue was stolen and executed.
    StolePeer(ParallelReadyWorkExecution<R>),
    /// No local or peer ready work was available.
    Idle,
}

impl<R> ParallelReadyWorkStep<R> {
    /// Returns the wait-or-steal hook signal represented by this step.
    pub const fn ready_work(&self) -> ParallelThunkReadyWork {
        match self {
            Self::RanLocal(_) => ParallelThunkReadyWork::RanLocal,
            Self::StolePeer(_) => ParallelThunkReadyWork::StolePeer,
            Self::Idle => ParallelThunkReadyWork::Idle,
        }
    }

    /// Returns the task execution metadata, if a task ran.
    pub const fn execution(&self) -> Option<&ParallelReadyWorkExecution<R>> {
        match self {
            Self::RanLocal(execution) | Self::StolePeer(execution) => Some(execution),
            Self::Idle => None,
        }
    }
}

/// One ready-work execution or an idle park-preflight snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParallelReadyWorkPoll<R> {
    /// A task from the worker's own queue was executed.
    RanLocal(ParallelReadyWorkExecution<R>),
    /// A task from a peer queue was stolen and executed.
    StolePeer(ParallelReadyWorkExecution<R>),
    /// No local or peer ready work was available at the preflight snapshot.
    Idle(ParallelReadyWorkParkPreflight),
}

impl<R> ParallelReadyWorkPoll<R> {
    /// Returns the wait-or-steal hook signal represented by this poll.
    pub const fn ready_work(&self) -> ParallelThunkReadyWork {
        match self {
            Self::RanLocal(_) => ParallelThunkReadyWork::RanLocal,
            Self::StolePeer(_) => ParallelThunkReadyWork::StolePeer,
            Self::Idle(_) => ParallelThunkReadyWork::Idle,
        }
    }

    /// Returns the task execution metadata, if a task ran.
    pub const fn execution(&self) -> Option<&ParallelReadyWorkExecution<R>> {
        match self {
            Self::RanLocal(execution) | Self::StolePeer(execution) => Some(execution),
            Self::Idle(_) => None,
        }
    }

    /// Returns the park-preflight snapshot, if the poll was idle.
    pub const fn park_preflight(&self) -> Option<&ParallelReadyWorkParkPreflight> {
        match self {
            Self::RanLocal(_) | Self::StolePeer(_) => None,
            Self::Idle(preflight) => Some(preflight),
        }
    }
}

/// The result produced by one ready-work task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelReadyWorkExecution<R> {
    task_index: usize,
    initial_worker: usize,
    worker_id: usize,
    result: R,
}

impl<R> ParallelReadyWorkExecution<R> {
    /// Returns the stable task index.
    pub const fn task_index(&self) -> usize {
        self.task_index
    }

    /// Returns the worker queue that initially owned the task.
    pub const fn initial_worker(&self) -> usize {
        self.initial_worker
    }

    /// Returns the worker that executed the ready task.
    pub const fn worker_id(&self) -> usize {
        self.worker_id
    }

    /// Returns the ready-work result.
    pub const fn result(&self) -> &R {
        &self.result
    }
}

/// Queue-depth snapshot captured before a worker may park on a thunk.
///
/// This is a safe ready-work precursor for scheduler integration. It records a
/// same-instant view of the current mutex-backed queue adapter, not a final
/// Chase-Lev deque park token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelReadyWorkParkPreflight {
    observing_worker: usize,
    worker_count: usize,
    task_count: usize,
    queue_lengths: Vec<usize>,
    ready_task_count: usize,
}

impl ParallelReadyWorkParkPreflight {
    /// Returns the worker that requested the preflight snapshot.
    pub const fn observing_worker(&self) -> usize {
        self.observing_worker
    }

    /// Returns the number of ready-work queues observed.
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Returns the number of tasks originally seeded into the queues.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Returns the number of queued tasks observed across all workers.
    pub const fn ready_task_count(&self) -> usize {
        self.ready_task_count
    }

    /// Returns whether every observed ready-work queue was empty.
    pub const fn is_idle(&self) -> bool {
        self.ready_task_count == 0
    }

    /// Returns queue depths in worker-id order.
    pub fn queue_lengths(&self) -> &[usize] {
        &self.queue_lengths
    }

    /// Returns the observed queue depth for one worker.
    pub fn queue_length(&self, worker_id: usize) -> Option<usize> {
        self.queue_lengths.get(worker_id).copied()
    }
}

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
mod tests {
    use super::super::thunk_cas::{ParallelThunkTerminalState, ParallelThunkWorkerId};
    use super::super::thunk_wait::{ParallelThunkWait, ParallelThunkWaitCell};
    use super::*;

    fn workers(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("test worker count is nonzero")
    }

    fn worker(raw: u64) -> ParallelThunkWorkerId {
        ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
    }

    #[test]
    fn seed_plan_distributes_tasks_round_robin() {
        let plan = parallel_top_level_seed_plan(8, workers(3));

        assert_eq!(plan.worker_count(), 3);
        assert_eq!(plan.task_count(), 8);
        assert_eq!(
            plan.placements()
                .iter()
                .copied()
                .map(|placement| (placement.task_index(), placement.initial_worker()))
                .collect::<Vec<_>>(),
            vec![
                (0, 0),
                (1, 1),
                (2, 2),
                (3, 0),
                (4, 1),
                (5, 2),
                (6, 0),
                (7, 1)
            ]
        );
        assert_eq!(
            plan.to_string(),
            "8 top-level task(s) seeded across 3 worker(s)"
        );
    }

    #[test]
    fn top_level_executor_returns_results_in_stable_task_order() {
        let report =
            execute_parallel_top_level([3, 1, 4, 1, 5, 9], workers(3), |value| value * value)
                .expect("parallel execution succeeds");

        assert_eq!(report.worker_count(), 3);
        assert_eq!(report.task_count(), 6);
        assert_eq!(
            report.into_results_in_task_order(),
            vec![9, 1, 16, 1, 25, 81]
        );
    }

    #[test]
    fn top_level_executor_reports_every_task_once() {
        let report = execute_parallel_top_level(0..64, workers(4), |value| value + 10)
            .expect("parallel execution succeeds");
        let completed = report
            .worker_reports()
            .iter()
            .map(|worker| worker.tasks_completed())
            .sum::<usize>();
        let local_and_stolen = report
            .worker_reports()
            .iter()
            .map(|worker| worker.local_pops() + worker.steals())
            .sum::<usize>();

        assert_eq!(completed, 64);
        assert_eq!(local_and_stolen, 64);
        assert_eq!(report.results().len(), 64);
        assert!(
            report
                .results()
                .iter()
                .enumerate()
                .all(|(expected_index, execution)| {
                    execution.task_index() == expected_index
                        && execution.initial_worker() == expected_index % 4
                        && execution.worker_id() < 4
                        && *execution.result() == expected_index + 10
                })
        );
    }

    #[test]
    fn top_level_executor_handles_empty_task_sets() {
        let report =
            execute_parallel_top_level(std::iter::empty::<usize>(), workers(2), |value| value)
                .expect("empty execution succeeds");

        assert_eq!(report.worker_count(), 2);
        assert_eq!(report.task_count(), 0);
        assert!(report.results().is_empty());
        assert_eq!(report.worker_reports().len(), 2);
        assert!(report.worker_reports().iter().all(|worker| {
            worker.local_pops() == 0 && worker.steals() == 0 && worker.tasks_completed() == 0
        }));
    }

    #[test]
    fn ready_work_queues_run_local_before_stealing() {
        let queues = parallel_ready_work_queues([10, 20, 30, 40], workers(2));

        let first = queues
            .run_next(0, |value| value + 1)
            .expect("first ready work runs");
        assert_eq!(first.ready_work(), ParallelThunkReadyWork::RanLocal);
        let ParallelReadyWorkStep::RanLocal(execution) = first else {
            panic!("first task should be local");
        };
        assert_eq!(execution.task_index(), 2);
        assert_eq!(execution.initial_worker(), 0);
        assert_eq!(execution.worker_id(), 0);
        assert_eq!(*execution.result(), 31);

        let second = queues
            .run_next(0, |value| value + 1)
            .expect("second ready work runs");
        assert_eq!(second.ready_work(), ParallelThunkReadyWork::RanLocal);
        let ParallelReadyWorkStep::RanLocal(execution) = second else {
            panic!("second task should be local");
        };
        assert_eq!(execution.task_index(), 0);
        assert_eq!(execution.initial_worker(), 0);
        assert_eq!(execution.worker_id(), 0);
        assert_eq!(*execution.result(), 11);

        let third = queues
            .run_next(0, |value| value + 1)
            .expect("third ready work runs");
        assert_eq!(third.ready_work(), ParallelThunkReadyWork::StolePeer);
        let ParallelReadyWorkStep::StolePeer(execution) = third else {
            panic!("third task should be stolen");
        };
        assert_eq!(execution.task_index(), 1);
        assert_eq!(execution.initial_worker(), 1);
        assert_eq!(execution.worker_id(), 0);
        assert_eq!(*execution.result(), 21);

        let fourth = queues
            .run_next(0, |value| value + 1)
            .expect("fourth ready work runs");
        assert_eq!(fourth.ready_work(), ParallelThunkReadyWork::StolePeer);
        let ParallelReadyWorkStep::StolePeer(execution) = fourth else {
            panic!("fourth task should be stolen");
        };
        assert_eq!(execution.task_index(), 3);
        assert_eq!(execution.initial_worker(), 1);
        assert_eq!(execution.worker_id(), 0);
        assert_eq!(*execution.result(), 41);

        let fifth = queues
            .run_next(0, |value| value + 1)
            .expect("idle ready work succeeds");
        assert_eq!(fifth.ready_work(), ParallelThunkReadyWork::Idle);
        assert!(fifth.execution().is_none());
    }

    #[test]
    fn ready_work_park_preflight_snapshot_reports_seeded_depths() {
        let queues = parallel_ready_work_queues([10, 20, 30, 40, 50], workers(3));

        let snapshot = queues
            .park_preflight_snapshot(1)
            .expect("preflight snapshot succeeds");

        assert_eq!(snapshot.observing_worker(), 1);
        assert_eq!(snapshot.worker_count(), 3);
        assert_eq!(snapshot.task_count(), 5);
        assert_eq!(snapshot.ready_task_count(), 5);
        assert!(!snapshot.is_idle());
        assert_eq!(snapshot.queue_lengths(), &[2, 2, 1]);
        assert_eq!(snapshot.queue_length(0), Some(2));
        assert_eq!(snapshot.queue_length(1), Some(2));
        assert_eq!(snapshot.queue_length(2), Some(1));
        assert_eq!(snapshot.queue_length(3), None);
    }

    #[test]
    fn ready_work_park_preflight_snapshot_reports_idle_after_drain() {
        let queues = parallel_ready_work_queues([10, 20, 30], workers(2));
        let mut ran = Vec::new();

        while queues
            .run_next(0, |value| ran.push(value))
            .expect("ready work run succeeds")
            .ready_work()
            != ParallelThunkReadyWork::Idle
        {}

        let snapshot = queues
            .park_preflight_snapshot(0)
            .expect("preflight snapshot succeeds");

        assert_eq!(ran, vec![30, 10, 20]);
        assert_eq!(snapshot.ready_task_count(), 0);
        assert_eq!(snapshot.queue_lengths(), &[0, 0]);
        assert!(snapshot.is_idle());
    }

    #[test]
    fn ready_work_park_preflight_snapshot_feeds_wait_or_steal_idle_path() {
        let cell = ParallelThunkWaitCell::new();
        let ParallelThunkWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_terminal(worker(1))
            .expect("owner claims thunk")
        else {
            panic!("owner should claim suspended wait cell");
        };
        let mut owner_guard = Some(owner_guard);
        let queues = parallel_ready_work_queues([10, 20], workers(2));
        let mut ran = Vec::new();
        let mut preflight = None;

        let outcome = cell
            .claim_or_run_ready_then_wait(worker(2), || {
                let step = queues
                    .run_next(1, |value| ran.push(value))
                    .expect("ready queue run succeeds");
                if step.ready_work() == ParallelThunkReadyWork::Idle {
                    preflight = Some(
                        queues
                            .park_preflight_snapshot(1)
                            .expect("preflight snapshot succeeds"),
                    );
                    owner_guard
                        .take()
                        .expect("owner guard remains available")
                        .publish_forced()
                        .expect("owner publishes after idle preflight");
                }
                step.ready_work()
            })
            .expect("wait-or-steal hook completes");

        let (result, report) = outcome.into_parts();
        let snapshot = preflight.expect("idle preflight snapshot is captured");
        assert!(matches!(
            result,
            ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
        ));
        assert_eq!(ran, vec![20, 10]);
        assert_eq!(snapshot.observing_worker(), 1);
        assert_eq!(snapshot.ready_task_count(), 0);
        assert!(snapshot.is_idle());
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
    }

    #[test]
    fn ready_work_poll_runs_one_task_or_returns_idle_preflight() {
        let queues = parallel_ready_work_queues([10, 20, 30], workers(2));

        let first = queues
            .run_next_or_park_preflight(1, |value| value + 1)
            .expect("first ready work runs");
        assert_eq!(first.ready_work(), ParallelThunkReadyWork::RanLocal);
        assert!(first.park_preflight().is_none());
        let ParallelReadyWorkPoll::RanLocal(execution) = first else {
            panic!("first poll should run local work");
        };
        assert_eq!(execution.task_index(), 1);
        assert_eq!(execution.initial_worker(), 1);
        assert_eq!(execution.worker_id(), 1);
        assert_eq!(*execution.result(), 21);

        let second = queues
            .run_next_or_park_preflight(1, |value| value + 1)
            .expect("second ready work runs");
        assert_eq!(second.ready_work(), ParallelThunkReadyWork::StolePeer);
        let ParallelReadyWorkPoll::StolePeer(execution) = second else {
            panic!("second poll should steal peer work");
        };
        assert_eq!(execution.task_index(), 0);
        assert_eq!(execution.initial_worker(), 0);
        assert_eq!(execution.worker_id(), 1);
        assert_eq!(*execution.result(), 11);

        let third = queues
            .run_next_or_park_preflight(1, |value| value + 1)
            .expect("third ready work runs");
        assert_eq!(third.ready_work(), ParallelThunkReadyWork::StolePeer);
        let ParallelReadyWorkPoll::StolePeer(execution) = third else {
            panic!("third poll should steal peer work");
        };
        assert_eq!(execution.task_index(), 2);
        assert_eq!(execution.initial_worker(), 0);
        assert_eq!(execution.worker_id(), 1);
        assert_eq!(*execution.result(), 31);

        let fourth = queues
            .run_next_or_park_preflight(1, |value| value + 1)
            .expect("idle preflight succeeds");
        assert_eq!(fourth.ready_work(), ParallelThunkReadyWork::Idle);
        assert!(fourth.execution().is_none());
        let ParallelReadyWorkPoll::Idle(preflight) = fourth else {
            panic!("fourth poll should report idle preflight");
        };
        assert_eq!(preflight.observing_worker(), 1);
        assert_eq!(preflight.ready_task_count(), 0);
        assert_eq!(preflight.queue_lengths(), &[0, 0]);
        assert!(preflight.is_idle());
    }

    #[test]
    fn ready_work_poll_idle_preflight_does_not_call_runner() {
        let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));
        let runner_called = std::cell::Cell::new(false);

        let poll = queues
            .run_next_or_park_preflight(0, |value| {
                runner_called.set(true);
                value
            })
            .expect("idle preflight succeeds");

        assert!(!runner_called.get());
        let preflight = poll
            .park_preflight()
            .expect("idle poll carries preflight snapshot");
        assert_eq!(poll.ready_work(), ParallelThunkReadyWork::Idle);
        assert_eq!(preflight.observing_worker(), 0);
        assert!(preflight.is_idle());
    }

    #[test]
    fn ready_work_poll_rejects_unknown_worker() {
        let queues = parallel_ready_work_queues([1, 2], workers(2));

        let error = queues
            .run_next_or_park_preflight(2, |value| value)
            .expect_err("unknown worker is rejected");

        assert_eq!(
            error,
            ParallelReadyWorkError::WorkerQueueMissing { worker_id: 2 }
        );
    }

    #[test]
    fn ready_work_poll_reports_poisoned_queue() {
        let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(1));
        let poison = std::panic::catch_unwind(|| {
            let _guard = queues.queues[0].lock().expect("queue lock succeeds");
            panic!("poison ready-work queue");
        });
        assert!(poison.is_err());

        let error = queues
            .run_next_or_park_preflight(0, |value| value)
            .expect_err("poisoned queue is reported");

        assert_eq!(
            error,
            ParallelReadyWorkError::WorkerQueuePoisoned { worker_id: 0 }
        );
    }

    #[test]
    fn ready_work_poll_feeds_wait_or_steal_hook_with_preflight() {
        let cell = ParallelThunkWaitCell::new();
        let ParallelThunkWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_terminal(worker(1))
            .expect("owner claims thunk")
        else {
            panic!("owner should claim suspended wait cell");
        };
        let mut owner_guard = Some(owner_guard);
        let queues = parallel_ready_work_queues([10, 20], workers(2));
        let mut ran = Vec::new();
        let mut preflight = None;

        let outcome = cell
            .claim_or_run_ready_then_wait(worker(2), || {
                let poll = queues
                    .run_next_or_park_preflight(1, |value| ran.push(value))
                    .expect("ready queue poll succeeds");
                if let Some(snapshot) = poll.park_preflight() {
                    preflight = Some(snapshot.clone());
                    owner_guard
                        .take()
                        .expect("owner guard remains available")
                        .publish_forced()
                        .expect("owner publishes after idle preflight");
                }
                poll.ready_work()
            })
            .expect("wait-or-steal hook completes");

        let (result, report) = outcome.into_parts();
        let snapshot = preflight.expect("idle preflight snapshot is captured");
        assert!(matches!(
            result,
            ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
        ));
        assert_eq!(ran, vec![20, 10]);
        assert_eq!(snapshot.observing_worker(), 1);
        assert_eq!(snapshot.ready_task_count(), 0);
        assert!(snapshot.is_idle());
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
    }

    #[test]
    fn ready_work_queues_reject_unknown_worker() {
        let queues = parallel_ready_work_queues([1, 2], workers(2));

        let error = queues
            .run_next(2, |value| value)
            .expect_err("unknown worker is rejected");

        assert_eq!(
            error,
            ParallelReadyWorkError::WorkerQueueMissing { worker_id: 2 }
        );
    }

    #[test]
    fn ready_work_park_preflight_snapshot_rejects_unknown_worker() {
        let queues = parallel_ready_work_queues([1, 2], workers(2));

        let error = queues
            .park_preflight_snapshot(2)
            .expect_err("unknown worker is rejected");

        assert_eq!(
            error,
            ParallelReadyWorkError::WorkerQueueMissing { worker_id: 2 }
        );
    }

    #[test]
    fn ready_work_queues_report_poisoned_queue() {
        let queues = parallel_ready_work_queues([1], workers(1));
        let poison = std::panic::catch_unwind(|| {
            let _guard = queues.queues[0].lock().expect("queue lock succeeds");
            panic!("poison ready-work queue");
        });
        assert!(poison.is_err());

        let error = queues
            .run_next(0, |value| value)
            .expect_err("poisoned queue is reported");

        assert_eq!(
            error,
            ParallelReadyWorkError::WorkerQueuePoisoned { worker_id: 0 }
        );
    }

    #[test]
    fn ready_work_park_preflight_snapshot_reports_poisoned_queue() {
        let queues = parallel_ready_work_queues([1], workers(1));
        let poison = std::panic::catch_unwind(|| {
            let _guard = queues.queues[0].lock().expect("queue lock succeeds");
            panic!("poison ready-work queue");
        });
        assert!(poison.is_err());

        let error = queues
            .park_preflight_snapshot(0)
            .expect_err("poisoned queue is reported");

        assert_eq!(
            error,
            ParallelReadyWorkError::WorkerQueuePoisoned { worker_id: 0 }
        );
    }

    #[test]
    fn ready_work_queues_drop_popped_task_if_runner_panics() {
        let queues = parallel_ready_work_queues([1], workers(1));

        let panic = std::panic::catch_unwind(|| {
            let _ = queues.run_next(0, |_value| {
                panic!("ready-work runner panics after dequeue");
            });
        });
        assert!(panic.is_err());

        let next = queues
            .run_next(0, |value| value)
            .expect("queue remains usable after runner panic");
        assert_eq!(next.ready_work(), ParallelThunkReadyWork::Idle);
    }

    #[test]
    fn ready_work_queues_feed_thunk_wait_or_steal_hook() {
        let cell = ParallelThunkWaitCell::new();
        let ParallelThunkWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_terminal(worker(1))
            .expect("owner claims thunk")
        else {
            panic!("owner should claim suspended wait cell");
        };
        let mut owner_guard = Some(owner_guard);
        let queues = parallel_ready_work_queues([10, 20, 30], workers(2));
        let mut ran = Vec::new();
        let mut runs = 0usize;

        let outcome = cell
            .claim_or_run_ready_then_wait(worker(2), || {
                runs = runs.saturating_add(1);
                let step = queues
                    .run_next(1, |value| ran.push(value))
                    .expect("ready queue run succeeds");
                if runs == 2 {
                    owner_guard
                        .take()
                        .expect("owner guard remains available")
                        .publish_forced()
                        .expect("owner publishes during ready work");
                }
                step.ready_work()
            })
            .expect("wait-or-steal hook completes");

        let (result, report) = outcome.into_parts();
        assert!(matches!(
            result,
            ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
        ));
        assert_eq!(ran, vec![20, 10]);
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
    }

    #[test]
    fn nursery_ownership_bridge_rejects_incomplete_scheduler_report() {
        let report = ParallelTopLevelExecutionReport {
            worker_count: 2,
            task_count: 2,
            results: vec![ParallelTaskExecution {
                task_index: 0,
                initial_worker: 0,
                worker_id: 0,
                result: 10,
            }],
            worker_reports: vec![
                ParallelWorkerExecutionReport::new(0),
                ParallelWorkerExecutionReport::new(1),
            ],
        };
        let plan = super::super::parallel_heap::parallel_worker_nursery_plan(2, workers(2));

        let error =
            super::super::parallel_heap::parallel_task_nursery_ownership_from_top_level_report(
                &plan, &report,
            )
            .expect_err("incomplete scheduler report rejects");

        assert_eq!(
            error,
            super::super::parallel_heap::ParallelNurseryOwnershipError::IncompleteTaskReport {
                task_count: 2,
                completed_task_count: 1
            }
        );
    }

    #[test]
    fn top_level_executor_reports_worker_panic() {
        let error = execute_parallel_top_level(0..4, workers(2), |value| {
            assert_ne!(value, 2, "task panic is reported as worker failure");
            value
        })
        .expect_err("panicking task fails execution");

        assert!(matches!(
            error,
            ParallelTopLevelError::WorkerPanicked { worker_id } if worker_id < 2
        ));
    }

    #[test]
    fn top_level_executor_drains_join_handles_after_multiple_worker_panics() {
        let outcome = std::panic::catch_unwind(|| {
            execute_parallel_top_level(0..8, workers(4), |value| {
                panic!("task {value} panics");
            })
        });

        assert!(
            outcome.is_ok(),
            "executor returns an error instead of unwinding"
        );
        let error = outcome
            .expect("executor call did not unwind")
            .expect_err("panicking tasks fail execution");
        assert!(matches!(
            error,
            ParallelTopLevelError::WorkerPanicked { worker_id } if worker_id < 4
        ));
    }
}
