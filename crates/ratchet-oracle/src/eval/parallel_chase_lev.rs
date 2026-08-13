//! Chase-Lev work-stealing deque adapter for scheduler precursors.
//!
//! This module isolates the concrete deque primitive used by the Phase 3.5 L1
//! scheduler path. It wraps `crossbeam-deque`'s Chase-Lev worker/stealer pair
//! behind the stable task metadata that the oracle scheduler reports already
//! expose: round-robin initial ownership, local LIFO pops, and peer FIFO steals.
//! The adapter is still only a deque boundary; result collation, cancellation,
//! nursery ownership, and tree-walk execution remain owned by the caller.

use std::{hint, num::NonZeroUsize};

use crossbeam_deque::{Steal, Stealer, Worker};

/// Builds owner-local Chase-Lev worker deques for top-level scheduler work.
///
/// Tasks are seeded with the same round-robin rule as
/// [`crate::eval::parallel_top_level_seed_plan`]. Each worker deque uses a
/// local LIFO discipline through `crossbeam-deque`'s Chase-Lev
/// `Worker::new_lifo`, while peer workers steal from the opposite end and
/// therefore observe older work first. The returned queues are a deque
/// admission primitive only; callers still own result collation, cancellation,
/// nursery accounting, and evaluator execution.
pub fn parallel_chase_lev_worker_queues<I, T>(
    tasks: I,
    worker_count: NonZeroUsize,
) -> ParallelChaseLevWorkerQueues<T>
where
    I: IntoIterator<Item = T>,
{
    let worker_count = worker_count.get();
    let workers = (0..worker_count)
        .map(|_| Worker::new_lifo())
        .collect::<Vec<_>>();
    let stealers = workers.iter().map(Worker::stealer).collect::<Vec<_>>();
    let mut task_count = 0;

    for (task_index, payload) in tasks.into_iter().enumerate() {
        let initial_worker = task_index % worker_count;
        workers[initial_worker].push(ParallelChaseLevTask {
            task_index,
            initial_worker,
            payload,
        });
        task_count = task_index + 1;
    }

    ParallelChaseLevWorkerQueues {
        worker_count,
        task_count,
        workers,
        stealers,
    }
}

/// Seeded owner-local Chase-Lev worker deques.
pub struct ParallelChaseLevWorkerQueues<T> {
    worker_count: usize,
    task_count: usize,
    workers: Vec<Worker<ParallelChaseLevTask<T>>>,
    stealers: Vec<Stealer<ParallelChaseLevTask<T>>>,
}

impl<T> ParallelChaseLevWorkerQueues<T> {
    /// Returns the number of worker deques in this pool.
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Returns the number of tasks originally seeded into the pool.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Consumes the pool and returns owner-local worker queue handles.
    ///
    /// Each handle owns exactly one local Chase-Lev worker deque plus cloneable
    /// stealers for every peer. The handle is intended to be moved onto the
    /// corresponding scheduler thread; callers should not wrap local workers in
    /// shared locks because `crossbeam-deque` already models the owner/stealer
    /// split.
    pub fn into_worker_queues(self) -> Vec<ParallelChaseLevWorkerQueue<T>> {
        let Self {
            worker_count,
            task_count,
            workers,
            stealers,
        } = self;

        workers
            .into_iter()
            .enumerate()
            .map(|(worker_id, local)| ParallelChaseLevWorkerQueue {
                worker_id,
                worker_count,
                task_count,
                local,
                stealers: stealers.clone(),
            })
            .collect()
    }
}

/// Owner-local handle for one Chase-Lev worker deque.
pub struct ParallelChaseLevWorkerQueue<T> {
    worker_id: usize,
    worker_count: usize,
    task_count: usize,
    local: Worker<ParallelChaseLevTask<T>>,
    stealers: Vec<Stealer<ParallelChaseLevTask<T>>>,
}

impl<T> ParallelChaseLevWorkerQueue<T> {
    /// Returns this local worker's scheduler id.
    pub const fn worker_id(&self) -> usize {
        self.worker_id
    }

    /// Returns the number of worker deques in the pool.
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Returns the number of tasks originally seeded into the pool.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Returns observed queue depths in worker-id order.
    ///
    /// This is a non-locking observation over the underlying Chase-Lev deque
    /// lengths. Under concurrent workers, the returned depths can become stale
    /// immediately and are not a scheduler park token.
    pub fn queue_lengths_snapshot(&self) -> Vec<usize> {
        self.stealers.iter().map(Stealer::len).collect()
    }

    /// Attempts one local pop or peer-steal pass.
    ///
    /// Local work is popped from this worker's hot end. If no local work is
    /// available, peer stealers are probed in deterministic worker-id order
    /// starting after this worker. [`ParallelChaseLevTake::Retry`] preserves
    /// `crossbeam-deque`'s retry signal as distinct from
    /// [`ParallelChaseLevTake::Empty`], so a scheduler cannot mistake a
    /// transient steal race for global idleness.
    pub fn try_take_next(&self) -> ParallelChaseLevTake<T> {
        if let Some(task) = self.local.pop() {
            return ParallelChaseLevTake::Task(ParallelChaseLevTaskTake {
                task,
                source: ParallelChaseLevTaskSource::Local,
            });
        }

        for offset in 1..self.worker_count {
            let victim_id = (self.worker_id + offset) % self.worker_count;
            match self.stealers[victim_id].steal() {
                Steal::Success(task) => {
                    return ParallelChaseLevTake::Task(ParallelChaseLevTaskTake {
                        task,
                        source: ParallelChaseLevTaskSource::Stolen,
                    });
                }
                Steal::Empty => {}
                Steal::Retry => return ParallelChaseLevTake::Retry,
            }
        }

        ParallelChaseLevTake::Empty
    }

    /// Repeats [`Self::try_take_next`] until a task or non-retry empty pass is observed.
    pub fn take_next_retrying(&self) -> Option<ParallelChaseLevTaskTake<T>> {
        loop {
            match self.try_take_next() {
                ParallelChaseLevTake::Task(task) => return Some(task),
                ParallelChaseLevTake::Empty => return None,
                ParallelChaseLevTake::Retry => hint::spin_loop(),
            }
        }
    }
}

/// A task seeded into a Chase-Lev worker deque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelChaseLevTask<T> {
    task_index: usize,
    initial_worker: usize,
    payload: T,
}

impl<T> ParallelChaseLevTask<T> {
    /// Returns the stable task index.
    pub const fn task_index(&self) -> usize {
        self.task_index
    }

    /// Returns the worker queue that initially owned this task.
    pub const fn initial_worker(&self) -> usize {
        self.initial_worker
    }

    /// Returns the task payload.
    pub const fn payload(&self) -> &T {
        &self.payload
    }

    /// Consumes the task and returns its payload.
    pub fn into_payload(self) -> T {
        self.payload
    }
}

/// A successful local pop or peer steal from a Chase-Lev worker queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelChaseLevTaskTake<T> {
    task: ParallelChaseLevTask<T>,
    source: ParallelChaseLevTaskSource,
}

impl<T> ParallelChaseLevTaskTake<T> {
    /// Returns the task that was popped or stolen.
    pub const fn task(&self) -> &ParallelChaseLevTask<T> {
        &self.task
    }

    /// Returns whether the task came from the local deque or a peer deque.
    pub const fn source(&self) -> ParallelChaseLevTaskSource {
        self.source
    }

    /// Consumes the take and returns its task.
    pub fn into_task(self) -> ParallelChaseLevTask<T> {
        self.task
    }
}

/// One Chase-Lev worker-deque polling outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParallelChaseLevTake<T> {
    /// A local or stolen task was claimed.
    Task(ParallelChaseLevTaskTake<T>),
    /// All probed local and peer queues were empty for this pass.
    Empty,
    /// A concurrent steal race requested that the caller retry.
    Retry,
}

impl<T> ParallelChaseLevTake<T> {
    /// Returns whether this polling outcome requires a retry.
    pub const fn is_retry(&self) -> bool {
        matches!(self, Self::Retry)
    }

    /// Returns whether this polling outcome observed no task.
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

/// The source of a successful Chase-Lev task take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParallelChaseLevTaskSource {
    /// The owner popped from its local deque.
    Local,
    /// The owner stole from a peer deque.
    Stolen,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn workers(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("test worker count is nonzero")
    }

    #[test]
    fn chase_lev_queues_pop_local_lifo_and_steal_peer_fifo() {
        let queues = parallel_chase_lev_worker_queues([10, 20, 30, 40], workers(2));
        let worker_queues = queues.into_worker_queues();
        let worker = &worker_queues[0];

        let first = worker.take_next_retrying().expect("local task exists");
        assert_eq!(first.source(), ParallelChaseLevTaskSource::Local);
        assert_eq!(first.task().task_index(), 2);
        assert_eq!(first.task().initial_worker(), 0);
        assert_eq!(*first.task().payload(), 30);

        let second = worker
            .take_next_retrying()
            .expect("second local task exists");
        assert_eq!(second.source(), ParallelChaseLevTaskSource::Local);
        assert_eq!(second.task().task_index(), 0);
        assert_eq!(second.task().initial_worker(), 0);
        assert_eq!(*second.task().payload(), 10);

        let third = worker.take_next_retrying().expect("peer task is stealable");
        assert_eq!(third.source(), ParallelChaseLevTaskSource::Stolen);
        assert_eq!(third.task().task_index(), 1);
        assert_eq!(third.task().initial_worker(), 1);
        assert_eq!(*third.task().payload(), 20);

        let fourth = worker
            .take_next_retrying()
            .expect("second peer task is stealable");
        assert_eq!(fourth.source(), ParallelChaseLevTaskSource::Stolen);
        assert_eq!(fourth.task().task_index(), 3);
        assert_eq!(fourth.task().initial_worker(), 1);
        assert_eq!(*fourth.task().payload(), 40);

        assert!(worker.take_next_retrying().is_none());
    }

    #[test]
    fn chase_lev_queues_preserve_worker_and_task_counts() {
        let queues = parallel_chase_lev_worker_queues(0..7, workers(3));

        assert_eq!(queues.worker_count(), 3);
        assert_eq!(queues.task_count(), 7);
        let worker_queues = queues.into_worker_queues();
        assert_eq!(
            worker_queues
                .iter()
                .map(ParallelChaseLevWorkerQueue::worker_id)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(worker_queues.iter().all(|queue| queue.worker_count() == 3));
        assert!(worker_queues.iter().all(|queue| queue.task_count() == 7));
        assert_eq!(worker_queues[0].queue_lengths_snapshot(), vec![3, 2, 2]);
    }

    #[test]
    fn chase_lev_queues_handle_empty_task_sets() {
        let queues = parallel_chase_lev_worker_queues(std::iter::empty::<usize>(), workers(2));

        assert_eq!(queues.worker_count(), 2);
        assert_eq!(queues.task_count(), 0);
        assert!(
            queues
                .into_worker_queues()
                .iter()
                .all(|queue| queue.take_next_retrying().is_none())
        );
    }

    #[test]
    fn chase_lev_try_take_distinguishes_empty_from_retry() {
        let queues = parallel_chase_lev_worker_queues(std::iter::empty::<usize>(), workers(2));
        let worker_queues = queues.into_worker_queues();

        let take = worker_queues[0].try_take_next();

        assert!(take.is_empty());
        assert!(!take.is_retry());
    }

    #[test]
    fn chase_lev_concurrent_drain_completes_every_task_once() {
        let worker_queues =
            parallel_chase_lev_worker_queues(0..128, workers(4)).into_worker_queues();
        let completed = Mutex::new(Vec::new());

        std::thread::scope(|scope| {
            for queue in worker_queues {
                let completed = &completed;
                scope.spawn(move || {
                    while let Some(task) = queue.take_next_retrying() {
                        completed
                            .lock()
                            .expect("completed task list lock is healthy")
                            .push(task.into_task().task_index());
                    }
                });
            }
        });

        let mut completed = completed
            .into_inner()
            .expect("completed task list lock is healthy");
        completed.sort_unstable();

        assert_eq!(completed, (0..128).collect::<Vec<_>>());
    }
}
