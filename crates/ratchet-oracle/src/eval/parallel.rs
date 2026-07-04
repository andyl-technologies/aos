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

/// Seeded owner-local Chase-Lev ready-work queues.
///
/// This is a Chase-Lev queue bridge for the L2 wait-or-steal precursor. It is
/// still only a readiness adapter: idle snapshots are observations over deque
/// lengths, not reserved scheduler park tokens.
pub struct ParallelChaseLevReadyWorkQueues<T> {
    queues: super::parallel_chase_lev::ParallelChaseLevWorkerQueues<T>,
}

impl<T> ParallelChaseLevReadyWorkQueues<T> {
    /// Returns the number of worker-local queues.
    pub const fn worker_count(&self) -> usize {
        self.queues.worker_count()
    }

    /// Returns the number of tasks originally seeded into the queues.
    pub const fn task_count(&self) -> usize {
        self.queues.task_count()
    }

    /// Consumes the pool and returns owner-local ready-work queue handles.
    pub fn into_worker_queues(self) -> Vec<ParallelChaseLevReadyWorkQueue<T>> {
        self.queues
            .into_worker_queues()
            .into_iter()
            .map(|queue| ParallelChaseLevReadyWorkQueue { queue })
            .collect()
    }
}

/// Owner-local Chase-Lev ready-work queue handle.
///
/// A handle owns one Chase-Lev worker deque and can steal from peer deques. It
/// is intended to be moved onto the worker that owns the local deque; callers
/// should not wrap it in a shared mutex because the underlying deque already
/// encodes the owner/stealer split.
pub struct ParallelChaseLevReadyWorkQueue<T> {
    queue: ParallelChaseLevWorkerQueue<T>,
}

impl<T> ParallelChaseLevReadyWorkQueue<T> {
    /// Returns this local worker's scheduler id.
    pub const fn worker_id(&self) -> usize {
        self.queue.worker_id()
    }

    /// Returns the number of worker-local queues.
    pub const fn worker_count(&self) -> usize {
        self.queue.worker_count()
    }

    /// Returns the number of tasks originally seeded into the queues.
    pub const fn task_count(&self) -> usize {
        self.queue.task_count()
    }

    /// Runs one ready-work item or returns an idle park-preflight observation.
    ///
    /// Local and stolen work are returned as single-task polls so a contended
    /// thunk can be rechecked after every executed task. When no task is
    /// available, this captures [`Self::park_preflight_snapshot`] and returns it
    /// with the idle poll. The idle snapshot is non-locking and does not reserve
    /// a scheduler park token.
    ///
    /// # Panics
    ///
    /// Panics if `run` panics. The task has already been removed from its deque
    /// before `run` is called.
    pub fn run_next_or_park_preflight<R>(
        &self,
        run: impl FnOnce(T) -> R,
    ) -> ParallelReadyWorkPoll<R> {
        match self.run_next(run) {
            ParallelReadyWorkStep::RanLocal(execution) => {
                ParallelReadyWorkPoll::RanLocal(execution)
            }
            ParallelReadyWorkStep::StolePeer(execution) => {
                ParallelReadyWorkPoll::StolePeer(execution)
            }
            ParallelReadyWorkStep::Idle => {
                ParallelReadyWorkPoll::Idle(self.park_preflight_snapshot())
            }
        }
    }

    /// Captures observed Chase-Lev queue depths before a worker may park.
    ///
    /// Unlike [`ParallelReadyWorkQueues::park_preflight_snapshot`], this does
    /// not lock every queue. It records the currently observed Chase-Lev deque
    /// lengths in worker-id order. Under concurrent workers, the snapshot can
    /// become stale immediately; it is a pre-token readiness artifact, not the
    /// final scheduler park-token protocol.
    pub fn park_preflight_snapshot(&self) -> ParallelReadyWorkParkPreflight {
        let queue_lengths = self.queue.queue_lengths_snapshot();
        let ready_task_count = queue_lengths.iter().sum();

        ParallelReadyWorkParkPreflight {
            observing_worker: self.worker_id(),
            worker_count: self.worker_count(),
            task_count: self.task_count(),
            queue_lengths,
            ready_task_count,
        }
    }

    /// Runs one local or stolen ready-work item.
    ///
    /// Local work is popped from this worker's owner end. If no local work is
    /// available, peer queues are stolen from in deterministic worker-id order.
    /// [`ParallelReadyWorkStep::Idle`] is returned only after retrying
    /// transient Chase-Lev steal races until a task or non-retry empty pass is
    /// observed.
    ///
    /// # Panics
    ///
    /// Panics if `run` panics. The task has already been removed from its deque
    /// before `run` is called.
    pub fn run_next<R>(&self, run: impl FnOnce(T) -> R) -> ParallelReadyWorkStep<R> {
        let Some(take) = self.queue.take_next_retrying() else {
            return ParallelReadyWorkStep::Idle;
        };

        let source = take.source();
        let task = take.into_task();
        let task_index = task.task_index();
        let initial_worker = task.initial_worker();
        let result = run(task.into_payload());
        let execution = ParallelReadyWorkExecution {
            task_index,
            initial_worker,
            worker_id: self.worker_id(),
            result,
        };

        match source {
            ParallelChaseLevTaskSource::Local => ParallelReadyWorkStep::RanLocal(execution),
            ParallelChaseLevTaskSource::Stolen => ParallelReadyWorkStep::StolePeer(execution),
        }
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

/// Result of a wait-cell operation driven by scheduler-backed ready-work polls.
#[must_use = "a claimed parallel thunk must be published as forced or failed"]
#[derive(Debug)]
pub struct ParallelReadyWorkWait<'a> {
    work_wait: ParallelThunkWorkWait<'a>,
    park_readiness: Option<ParallelReadyWorkParkReadiness>,
}

impl<'a> ParallelReadyWorkWait<'a> {
    /// Returns the claim, terminal state, or self-cycle classification.
    pub const fn result(&self) -> &ParallelThunkWait<'a> {
        self.work_wait.result()
    }

    /// Returns the wait-or-steal contention counters from the wait cell.
    pub const fn contention_report(&self) -> ParallelThunkContentionReport {
        self.work_wait.report()
    }

    /// Returns the validated idle preflight used for waiter registration.
    pub const fn park_readiness(&self) -> Option<&ParallelReadyWorkParkReadiness> {
        self.park_readiness.as_ref()
    }

    /// Consumes the outcome into the wait-cell result and optional readiness.
    pub fn into_parts(
        self,
    ) -> (
        ParallelThunkWorkWait<'a>,
        Option<ParallelReadyWorkParkReadiness>,
    ) {
        (self.work_wait, self.park_readiness)
    }
}

/// A failure while bridging scheduler-backed ready-work polls into a wait cell.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParallelReadyWorkWaitError<E> {
    /// The underlying wait-cell operation failed.
    #[error(transparent)]
    Wait(#[from] ParallelThunkWaitError),
    /// The ready-work poll failed before the wait-cell path could continue.
    #[error("parallel ready-work poll failed")]
    ReadyWork(E),
    /// An idle ready-work poll did not carry a valid park-preflight snapshot.
    #[error(transparent)]
    ParkReadiness(#[from] ParallelReadyWorkParkReadinessError),
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
/// This is a ready-work precursor for scheduler integration. Safe queue
/// snapshots are same-instant mutex-backed observations; Chase-Lev snapshots are
/// non-locking deque-depth observations. Neither form is a final scheduler park
/// token.
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

    /// Validates that this preflight can precede parking for `worker_id`.
    ///
    /// The returned readiness is only a typed ready-work observation. It proves
    /// that the captured snapshot was for the requested worker and that all
    /// queues were observed empty; it is not a scheduler park token and does not
    /// reserve future idle state.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelReadyWorkParkReadinessError::ObservingWorkerMismatch`]
    /// if the snapshot was captured by a different worker. Returns
    /// [`ParallelReadyWorkParkReadinessError::ReadyWorkRemaining`] if the
    /// snapshot still observed queued ready work.
    pub fn validate_idle_for_worker(
        &self,
        worker_id: usize,
    ) -> Result<ParallelReadyWorkParkReadiness, ParallelReadyWorkParkReadinessError> {
        if self.observing_worker != worker_id {
            return Err(
                ParallelReadyWorkParkReadinessError::ObservingWorkerMismatch {
                    expected_worker: worker_id,
                    observed_worker: self.observing_worker,
                },
            );
        }
        if !self.is_idle() {
            return Err(ParallelReadyWorkParkReadinessError::ReadyWorkRemaining {
                ready_task_count: self.ready_task_count,
            });
        }

        Ok(ParallelReadyWorkParkReadiness {
            preflight: self.clone(),
        })
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

/// A validated idle snapshot before a worker may enter the thunk park path.
///
/// This is a pre-token readiness artifact for ready-work queue adapters. It
/// carries the exact preflight snapshot that was checked, but it does not
/// reserve a scheduler park token or prevent future enqueues.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelReadyWorkParkReadiness {
    preflight: ParallelReadyWorkParkPreflight,
}

impl ParallelReadyWorkParkReadiness {
    /// Returns the checked preflight snapshot.
    pub const fn preflight(&self) -> &ParallelReadyWorkParkPreflight {
        &self.preflight
    }

    /// Returns the worker that requested the checked preflight snapshot.
    pub const fn observing_worker(&self) -> usize {
        self.preflight.observing_worker()
    }

    /// Returns the number of ready-work queues in the checked snapshot.
    pub const fn worker_count(&self) -> usize {
        self.preflight.worker_count()
    }

    /// Returns the number of tasks originally seeded into the queues.
    pub const fn task_count(&self) -> usize {
        self.preflight.task_count()
    }

    /// Returns the number of queued tasks observed across all workers.
    ///
    /// A constructed readiness always returns zero here.
    pub const fn ready_task_count(&self) -> usize {
        self.preflight.ready_task_count()
    }

    /// Returns queue depths in worker-id order.
    pub fn queue_lengths(&self) -> &[usize] {
        self.preflight.queue_lengths()
    }
}

/// A failure while validating an idle ready-work park preflight.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParallelReadyWorkParkReadinessError {
    /// The snapshot was captured for a different observing worker.
    #[error(
        "ready-work park preflight observed worker {observed_worker}, expected {expected_worker}"
    )]
    ObservingWorkerMismatch {
        /// Worker expected by the validator.
        expected_worker: usize,
        /// Worker recorded by the preflight snapshot.
        observed_worker: usize,
    },
    /// The snapshot still observed ready work in the safe queues.
    #[error("ready-work park preflight still has {ready_task_count} queued task(s)")]
    ReadyWorkRemaining {
        /// Total queued ready-work tasks observed by the snapshot.
        ready_task_count: usize,
    },
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
mod tests {
    use std::{
        sync::{
            Arc,
            mpsc::{self, RecvTimeoutError},
        },
        thread,
        time::{Duration, Instant},
    };

    use super::super::thunk_cas::{ParallelThunkTerminalState, ParallelThunkWorkerId};
    use super::super::thunk_wait::{ParallelThunkWait, ParallelThunkWaitCell};
    use super::*;

    fn workers(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("test worker count is nonzero")
    }

    fn worker(raw: u64) -> ParallelThunkWorkerId {
        ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
    }

    fn wait_until_registered(cell: &ParallelThunkWaitCell, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if cell
                .stats()
                .expect("stats are readable")
                .wait_registrations()
                >= expected
            {
                return;
            }
            thread::yield_now();
        }
        panic!("timed out waiting for {expected} waiter registration(s)");
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
    fn chase_lev_executor_returns_results_in_stable_task_order() {
        let report =
            execute_parallel_top_level_chase_lev([3, 1, 4, 1, 5, 9], workers(3), |value| {
                value * value
            })
            .expect("Chase-Lev execution succeeds");

        assert_eq!(report.worker_count(), 3);
        assert_eq!(report.task_count(), 6);
        assert_eq!(
            report.into_results_in_task_order(),
            vec![9, 1, 16, 1, 25, 81]
        );
    }

    #[test]
    fn chase_lev_executor_reports_every_task_once() {
        let report = execute_parallel_top_level_chase_lev(0..96, workers(4), |value| value + 10)
            .expect("Chase-Lev execution succeeds");
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

        assert_eq!(completed, 96);
        assert_eq!(local_and_stolen, 96);
        assert_eq!(report.results().len(), 96);
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
    fn chase_lev_executor_handles_empty_task_sets() {
        let report = execute_parallel_top_level_chase_lev(
            std::iter::empty::<usize>(),
            workers(2),
            |value| value,
        )
        .expect("empty Chase-Lev execution succeeds");

        assert_eq!(report.worker_count(), 2);
        assert_eq!(report.task_count(), 0);
        assert!(report.results().is_empty());
        assert_eq!(report.worker_reports().len(), 2);
        assert!(report.worker_reports().iter().all(|worker| {
            worker.local_pops() == 0 && worker.steals() == 0 && worker.tasks_completed() == 0
        }));
    }

    #[test]
    fn chase_lev_ready_work_queues_preserve_worker_and_task_counts() {
        let queues = parallel_chase_lev_ready_work_queues([10, 20, 30, 40, 50], workers(3));

        assert_eq!(queues.worker_count(), 3);
        assert_eq!(queues.task_count(), 5);

        let worker_queues = queues.into_worker_queues();
        assert_eq!(worker_queues.len(), 3);
        assert!(worker_queues.iter().enumerate().all(|(worker_id, queue)| {
            queue.worker_id() == worker_id && queue.worker_count() == 3 && queue.task_count() == 5
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
    fn chase_lev_ready_work_queue_runs_local_before_stealing() {
        let queues = parallel_chase_lev_ready_work_queues([10, 20, 30, 40], workers(2));
        let worker_queues = queues.into_worker_queues();
        let worker = &worker_queues[0];

        let first = worker.run_next(|value| value + 1);
        assert_eq!(first.ready_work(), ParallelThunkReadyWork::RanLocal);
        let ParallelReadyWorkStep::RanLocal(execution) = first else {
            panic!("first task should be local");
        };
        assert_eq!(execution.task_index(), 2);
        assert_eq!(execution.initial_worker(), 0);
        assert_eq!(execution.worker_id(), 0);
        assert_eq!(*execution.result(), 31);

        let second = worker.run_next(|value| value + 1);
        assert_eq!(second.ready_work(), ParallelThunkReadyWork::RanLocal);
        let ParallelReadyWorkStep::RanLocal(execution) = second else {
            panic!("second task should be local");
        };
        assert_eq!(execution.task_index(), 0);
        assert_eq!(execution.initial_worker(), 0);
        assert_eq!(execution.worker_id(), 0);
        assert_eq!(*execution.result(), 11);

        let third = worker.run_next(|value| value + 1);
        assert_eq!(third.ready_work(), ParallelThunkReadyWork::StolePeer);
        let ParallelReadyWorkStep::StolePeer(execution) = third else {
            panic!("third task should be stolen");
        };
        assert_eq!(execution.task_index(), 1);
        assert_eq!(execution.initial_worker(), 1);
        assert_eq!(execution.worker_id(), 0);
        assert_eq!(*execution.result(), 21);

        let fourth = worker.run_next(|value| value + 1);
        assert_eq!(fourth.ready_work(), ParallelThunkReadyWork::StolePeer);
        let ParallelReadyWorkStep::StolePeer(execution) = fourth else {
            panic!("fourth task should be stolen");
        };
        assert_eq!(execution.task_index(), 3);
        assert_eq!(execution.initial_worker(), 1);
        assert_eq!(execution.worker_id(), 0);
        assert_eq!(*execution.result(), 41);

        let fifth = worker.run_next(|value| value + 1);
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
    fn chase_lev_ready_work_park_preflight_snapshot_reports_seeded_depths() {
        let queues = parallel_chase_lev_ready_work_queues([10, 20, 30, 40, 50], workers(3));
        let worker_queues = queues.into_worker_queues();
        let snapshot = worker_queues[1].park_preflight_snapshot();

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
    fn chase_lev_ready_work_park_preflight_snapshot_reports_idle_after_drain() {
        let queues = parallel_chase_lev_ready_work_queues([10, 20, 30], workers(2));
        let worker_queues = queues.into_worker_queues();
        let worker = &worker_queues[0];
        let mut ran = Vec::new();

        while worker.run_next(|value| ran.push(value)).ready_work() != ParallelThunkReadyWork::Idle
        {
        }

        let snapshot = worker.park_preflight_snapshot();

        assert_eq!(ran, vec![30, 10, 20]);
        assert_eq!(snapshot.ready_task_count(), 0);
        assert_eq!(snapshot.queue_lengths(), &[0, 0]);
        assert!(snapshot.is_idle());
    }

    #[test]
    fn ready_work_park_readiness_accepts_idle_snapshot() {
        let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));

        let snapshot = queues
            .park_preflight_snapshot(1)
            .expect("preflight snapshot succeeds");
        let readiness = snapshot
            .validate_idle_for_worker(1)
            .expect("idle snapshot validates");

        assert_eq!(readiness.preflight(), &snapshot);
        assert_eq!(readiness.observing_worker(), 1);
        assert_eq!(readiness.worker_count(), 2);
        assert_eq!(readiness.task_count(), 0);
        assert_eq!(readiness.ready_task_count(), 0);
        assert_eq!(readiness.queue_lengths(), &[0, 0]);
    }

    #[test]
    fn chase_lev_ready_work_park_readiness_accepts_idle_snapshot() {
        let queues = parallel_chase_lev_ready_work_queues(std::iter::empty::<usize>(), workers(2));
        let worker_queues = queues.into_worker_queues();

        let snapshot = worker_queues[1].park_preflight_snapshot();
        let readiness = snapshot
            .validate_idle_for_worker(1)
            .expect("idle snapshot validates");

        assert_eq!(readiness.preflight(), &snapshot);
        assert_eq!(readiness.observing_worker(), 1);
        assert_eq!(readiness.worker_count(), 2);
        assert_eq!(readiness.task_count(), 0);
        assert_eq!(readiness.ready_task_count(), 0);
        assert_eq!(readiness.queue_lengths(), &[0, 0]);
    }

    #[test]
    fn ready_work_park_readiness_rejects_non_idle_snapshot() {
        let queues = parallel_ready_work_queues([10], workers(2));

        let snapshot = queues
            .park_preflight_snapshot(1)
            .expect("preflight snapshot succeeds");
        let error = snapshot
            .validate_idle_for_worker(1)
            .expect_err("non-idle snapshot is rejected");

        assert_eq!(
            error,
            ParallelReadyWorkParkReadinessError::ReadyWorkRemaining {
                ready_task_count: 1
            }
        );
    }

    #[test]
    fn chase_lev_ready_work_park_readiness_rejects_non_idle_snapshot() {
        let queues = parallel_chase_lev_ready_work_queues([10], workers(2));
        let worker_queues = queues.into_worker_queues();

        let snapshot = worker_queues[1].park_preflight_snapshot();
        let error = snapshot
            .validate_idle_for_worker(1)
            .expect_err("non-idle snapshot is rejected");

        assert_eq!(
            error,
            ParallelReadyWorkParkReadinessError::ReadyWorkRemaining {
                ready_task_count: 1
            }
        );
    }

    #[test]
    fn ready_work_park_readiness_rejects_observing_worker_mismatch() {
        let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));

        let snapshot = queues
            .park_preflight_snapshot(1)
            .expect("preflight snapshot succeeds");
        let error = snapshot
            .validate_idle_for_worker(0)
            .expect_err("worker mismatch is rejected");

        assert_eq!(
            error,
            ParallelReadyWorkParkReadinessError::ObservingWorkerMismatch {
                expected_worker: 0,
                observed_worker: 1
            }
        );
    }

    #[test]
    fn chase_lev_ready_work_park_readiness_rejects_observing_worker_mismatch() {
        let queues = parallel_chase_lev_ready_work_queues(std::iter::empty::<usize>(), workers(2));
        let worker_queues = queues.into_worker_queues();

        let snapshot = worker_queues[1].park_preflight_snapshot();
        let error = snapshot
            .validate_idle_for_worker(0)
            .expect_err("worker mismatch is rejected");

        assert_eq!(
            error,
            ParallelReadyWorkParkReadinessError::ObservingWorkerMismatch {
                expected_worker: 0,
                observed_worker: 1
            }
        );
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
    fn chase_lev_ready_work_poll_feeds_wait_or_steal_hook_with_preflight() {
        let cell = ParallelThunkWaitCell::new();
        let ParallelThunkWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_terminal(worker(1))
            .expect("owner claims thunk")
        else {
            panic!("owner should claim suspended wait cell");
        };
        let mut owner_guard = Some(owner_guard);
        let queues = parallel_chase_lev_ready_work_queues([10, 20], workers(2));
        let worker_queues = queues.into_worker_queues();
        let ready_worker = &worker_queues[1];
        let mut ran = Vec::new();
        let mut preflight = None;

        let outcome = cell
            .claim_or_run_ready_then_wait(worker(2), || {
                let poll = ready_worker.run_next_or_park_preflight(|value| ran.push(value));
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
    fn chase_lev_ready_work_poll_runs_one_task_or_returns_idle_preflight() {
        let queues = parallel_chase_lev_ready_work_queues([10, 20, 30], workers(2));
        let worker_queues = queues.into_worker_queues();
        let worker = &worker_queues[1];

        let first = worker.run_next_or_park_preflight(|value| value + 1);
        assert_eq!(first.ready_work(), ParallelThunkReadyWork::RanLocal);
        assert!(first.park_preflight().is_none());
        let ParallelReadyWorkPoll::RanLocal(execution) = first else {
            panic!("first poll should run local work");
        };
        assert_eq!(execution.task_index(), 1);
        assert_eq!(execution.initial_worker(), 1);
        assert_eq!(execution.worker_id(), 1);
        assert_eq!(*execution.result(), 21);

        let second = worker.run_next_or_park_preflight(|value| value + 1);
        assert_eq!(second.ready_work(), ParallelThunkReadyWork::StolePeer);
        let ParallelReadyWorkPoll::StolePeer(execution) = second else {
            panic!("second poll should steal peer work");
        };
        assert_eq!(execution.task_index(), 0);
        assert_eq!(execution.initial_worker(), 0);
        assert_eq!(execution.worker_id(), 1);
        assert_eq!(*execution.result(), 11);

        let third = worker.run_next_or_park_preflight(|value| value + 1);
        assert_eq!(third.ready_work(), ParallelThunkReadyWork::StolePeer);
        let ParallelReadyWorkPoll::StolePeer(execution) = third else {
            panic!("third poll should steal peer work");
        };
        assert_eq!(execution.task_index(), 2);
        assert_eq!(execution.initial_worker(), 0);
        assert_eq!(execution.worker_id(), 1);
        assert_eq!(*execution.result(), 31);

        let fourth = worker.run_next_or_park_preflight(|value| value + 1);
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
    fn chase_lev_ready_work_poll_idle_preflight_does_not_call_runner() {
        let queues = parallel_chase_lev_ready_work_queues(std::iter::empty::<usize>(), workers(2));
        let worker_queues = queues.into_worker_queues();
        let runner_called = std::cell::Cell::new(false);

        let poll = worker_queues[0].run_next_or_park_preflight(|value| {
            runner_called.set(true);
            value
        });

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
    fn ready_work_wait_bridge_records_park_readiness_when_waiter_registers() {
        let cell = Arc::new(ParallelThunkWaitCell::new());
        let ParallelThunkWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_terminal(worker(1))
            .expect("owner claims thunk")
        else {
            panic!("owner should claim suspended wait cell");
        };
        let waiter_cell = Arc::clone(&cell);
        let (result_tx, result_rx) = mpsc::channel();

        let waiter_thread = thread::spawn(move || {
            let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));
            let outcome = claim_or_poll_ready_then_wait(&waiter_cell, worker(2), 1, || {
                queues.run_next_or_park_preflight(1, |value| value)
            })
            .expect("ready-work wait bridge succeeds");
            let terminal_state = match outcome.result() {
                ParallelThunkWait::Terminal(terminal_state) => *terminal_state,
                _ => panic!("waiter should observe a terminal state"),
            };
            result_tx
                .send((
                    terminal_state,
                    outcome.contention_report(),
                    outcome.park_readiness().cloned(),
                ))
                .expect("result send succeeds");
        });

        wait_until_registered(&cell, 1);
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));

        owner_guard
            .publish_forced()
            .expect("owner publishes forced");
        let (terminal_state, report, park_readiness) = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");
        let park_readiness = park_readiness.expect("registered waiter carries park readiness");

        assert_eq!(terminal_state, ParallelThunkTerminalState::Forced);
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(report.wait_registered());
        assert_eq!(park_readiness.observing_worker(), 1);
        assert_eq!(park_readiness.worker_count(), 2);
        assert_eq!(park_readiness.task_count(), 0);
        assert_eq!(park_readiness.ready_task_count(), 0);
        assert_eq!(park_readiness.queue_lengths(), &[0, 0]);
        waiter_thread.join().expect("waiter joins");
    }

    #[test]
    fn ready_work_wait_bridge_rejects_mismatched_park_preflight_before_wait_registration() {
        let cell = ParallelThunkWaitCell::new();
        let ParallelThunkWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_terminal(worker(1))
            .expect("owner claims thunk")
        else {
            panic!("owner should claim suspended wait cell");
        };
        let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));

        let error = claim_or_poll_ready_then_wait(&cell, worker(2), 0, || {
            queues.run_next_or_park_preflight(1, |value| value)
        })
        .expect_err("wrong-worker idle preflight is rejected");

        assert_eq!(
            error,
            ParallelReadyWorkWaitError::ParkReadiness(
                ParallelReadyWorkParkReadinessError::ObservingWorkerMismatch {
                    expected_worker: 0,
                    observed_worker: 1,
                },
            )
        );
        assert_eq!(
            cell.stats()
                .expect("stats are readable")
                .wait_registrations(),
            0
        );

        owner_guard
            .publish_forced()
            .expect("owner remains publishable after preflight rejection");
    }

    #[test]
    fn ready_work_wait_bridge_rejects_non_idle_preflight_before_wait_registration() {
        let cell = ParallelThunkWaitCell::new();
        let ParallelThunkWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_terminal(worker(1))
            .expect("owner claims thunk")
        else {
            panic!("owner should claim suspended wait cell");
        };

        let error = claim_or_poll_ready_then_wait(&cell, worker(2), 1, || {
            Ok::<_, ParallelReadyWorkError>(ParallelReadyWorkPoll::<()>::Idle(
                ParallelReadyWorkParkPreflight {
                    observing_worker: 1,
                    worker_count: 2,
                    task_count: 1,
                    queue_lengths: vec![1, 0],
                    ready_task_count: 1,
                },
            ))
        })
        .expect_err("non-idle preflight is rejected");

        assert_eq!(
            error,
            ParallelReadyWorkWaitError::ParkReadiness(
                ParallelReadyWorkParkReadinessError::ReadyWorkRemaining {
                    ready_task_count: 1,
                },
            )
        );
        assert_eq!(
            cell.stats()
                .expect("stats are readable")
                .wait_registrations(),
            0
        );

        owner_guard
            .publish_forced()
            .expect("owner remains publishable after preflight rejection");
    }

    #[test]
    fn ready_work_wait_bridge_ready_work_error_returns_before_wait_registration() {
        let cell = ParallelThunkWaitCell::new();
        let ParallelThunkWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_terminal(worker(1))
            .expect("owner claims thunk")
        else {
            panic!("owner should claim suspended wait cell");
        };

        let error =
            claim_or_poll_ready_then_wait::<(), _>(&cell, worker(2), 1, || Err("queue failed"))
                .expect_err("ready-work errors are propagated");

        assert_eq!(error, ParallelReadyWorkWaitError::ReadyWork("queue failed"));
        assert_eq!(
            cell.stats()
                .expect("stats are readable")
                .wait_registrations(),
            0
        );

        owner_guard
            .publish_forced()
            .expect("owner remains publishable after ready-work error");
    }

    #[test]
    fn ready_work_wait_bridge_drops_park_readiness_when_terminal_wins_race() {
        let cell = ParallelThunkWaitCell::new();
        let ParallelThunkWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_terminal(worker(1))
            .expect("owner claims thunk")
        else {
            panic!("owner should claim suspended wait cell");
        };
        let mut owner_guard = Some(owner_guard);
        let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));

        let outcome = claim_or_poll_ready_then_wait(&cell, worker(2), 1, || {
            let poll = queues
                .run_next_or_park_preflight(1, |value| value)
                .expect("idle preflight succeeds");
            owner_guard
                .take()
                .expect("owner guard remains available")
                .publish_forced()
                .expect("owner publishes before wait registration");
            Ok::<_, ParallelReadyWorkError>(poll)
        })
        .expect("ready-work wait bridge observes terminal");

        assert!(matches!(
            outcome.result(),
            ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
        ));
        assert!(!outcome.contention_report().wait_registered());
        assert!(outcome.park_readiness().is_none());
        assert_eq!(
            cell.stats()
                .expect("stats are readable")
                .wait_registrations(),
            0
        );
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
    fn chase_lev_executor_reports_worker_panic() {
        let error = execute_parallel_top_level_chase_lev(0..4, workers(2), |value| {
            assert_ne!(value, 2, "task panic is reported as worker failure");
            value
        })
        .expect_err("panicking task fails Chase-Lev execution");

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

    #[test]
    fn chase_lev_executor_drains_join_handles_after_multiple_worker_panics() {
        let outcome = std::panic::catch_unwind(|| {
            execute_parallel_top_level_chase_lev(0..8, workers(4), |value| {
                panic!("task {value} panics");
            })
        });

        assert!(
            outcome.is_ok(),
            "Chase-Lev executor returns an error instead of unwinding"
        );
        let error = outcome
            .expect("executor call did not unwind")
            .expect_err("panicking tasks fail Chase-Lev execution");
        assert!(matches!(
            error,
            ParallelTopLevelError::WorkerPanicked { worker_id } if worker_id < 4
        ));
    }
}
