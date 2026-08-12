//! Ready-work queues and the wait-or-steal readiness protocol.
//!
//! Owns the seeded per-worker ready-work queues (mutex ring and Chase-Lev
//! variants), the step/poll/wait/execution result types their consumers
//! drive, and the park preflight/readiness snapshots the L2 wait-or-steal
//! precursor takes before parking a worker.

use super::*;

/// Seeded owner-local Chase-Lev ready-work queues.
///
/// This is a Chase-Lev queue bridge for the L2 wait-or-steal precursor. It is
/// still only a readiness adapter: idle snapshots are observations over deque
/// lengths, not reserved scheduler park tokens.
pub struct ParallelChaseLevReadyWorkQueues<T> {
    pub(crate) queues: crate::eval::parallel_chase_lev::ParallelChaseLevWorkerQueues<T>,
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
    pub(crate) worker_count: usize,
    pub(crate) task_count: usize,
    pub(crate) queues: Vec<Mutex<VecDeque<ParallelReadyWorkTask<T>>>>,
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
pub(crate) struct ParallelReadyWorkTask<T> {
    pub(crate) task_index: usize,
    pub(crate) initial_worker: usize,
    pub(crate) payload: T,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParallelReadyWorkSource {
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
    pub(crate) work_wait: ParallelThunkWorkWait<'a>,
    pub(crate) park_readiness: Option<ParallelReadyWorkParkReadiness>,
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
    pub(crate) observing_worker: usize,
    pub(crate) worker_count: usize,
    pub(crate) task_count: usize,
    pub(crate) queue_lengths: Vec<usize>,
    pub(crate) ready_task_count: usize,
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
