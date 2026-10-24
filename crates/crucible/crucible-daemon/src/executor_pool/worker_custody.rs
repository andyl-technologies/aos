//! Main-owned semantic workers, independent of their borrowing thread handles.
//!
//! The permanent Main and pool retain this directory; neither the shared
//! supervisor actor nor a worker factory owns it. Worker-to-actor aliases
//! therefore cannot form a strong cycle back to these cells.

use super::*;
use crucible_host_resources::host_services::process_birth::{
    AuthenticatedNativePoolPurpose, AuthenticatedNativeSlotPurpose,
};
use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};
use std::sync::atomic::AtomicBool;

/// Separates physical worker-body closure from retained historical failure.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum WorkerRetirementRefusal {
    #[error("worker original refused: {0}")]
    Original(HostSupervisionError),
    #[error("worker is still running or borrowed")]
    Pending,
    #[error("worker resources remain retained; typed cause stays in its Main cell")]
    Resources,
    #[error("worker destruction panicked; Main custody remains occupied")]
    Destruction,
    #[error("worker physically retired after an earlier retained failure")]
    Historical,
}

trait RetainedPoolWorker: Send + Sync {
    fn verify_retired(&self) -> Result<(), WorkerRetirementRefusal>;

    fn try_retire_original(
        &self,
        original: &HostOperationGuard,
    ) -> Result<(), WorkerRetirementRefusal>;
}

struct WorkerState<W: LocalAttemptWorker> {
    worker: Option<W>,
    first: Option<W::Error>,
    after: Option<HostSupervisionError>,
    destruction_failed: bool,
    destroying: bool,
    history_reported: bool,
}

pub(super) struct WorkerCell<W: LocalAttemptWorker> {
    state: Mutex<WorkerState<W>>,
    borrowed: AtomicBool,
}

impl<W: LocalAttemptWorker> WorkerCell<W> {
    pub(super) fn scheduled(&self) {
        self.borrowed.store(true, Ordering::Release);
    }

    pub(super) fn spawn_failed(&self) {
        self.borrowed.store(false, Ordering::Release);
    }

    pub(super) fn run<L, V>(
        &self,
        shared: Arc<SharedExecutor<L, V>>,
        store: CampaignExecutorStore,
        retained_by_main: bool,
    ) where
        L: AssignmentLedger + Send + 'static,
        V: AttemptAdmissionValidator + Send + Sync + 'static,
    {
        let _exit = WorkerBorrowExit(&self.borrowed);
        let Ok(mut state) = self.state.lock() else {
            shared.poison();
            return;
        };
        let Some(worker) = state.worker.as_mut() else {
            shared.poison();
            return;
        };
        worker_loop(shared, store, worker);
        if retained_by_main {
            return;
        }

        // Component pools have no Main custody. Their thread must destroy the
        // model before publishing completion; funded models remain in Main.
        state.destroying = true;
        let worker = state.worker.take();
        drop(state);
        let destroyed = catch_unwind(AssertUnwindSafe(|| drop(worker)));
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poison) => poison.into_inner(),
        };
        state.destroying = false;
        if let Err(panic) = destroyed {
            state.destruction_failed = true;
            drop(state);
            std::panic::resume_unwind(panic);
        }
    }
}

/// Owns the same paid worker cells through partial spawn, exit and panic.
pub(crate) struct ExecutorWorkerCustody {
    workers: Mutex<Vec<Arc<dyn RetainedPoolWorker>>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    thread_panicked: AtomicBool,
    thread_history_reported: AtomicBool,
    _controls: Option<AuthenticatedNativePoolPurpose>,
    _metadata: Option<crucible_engine::owned_decode::DecodeCustody>,
    startup_closed: AtomicBool,
}

impl ExecutorWorkerCustody {
    pub(super) fn has_funded_workers(&self) -> bool {
        self._controls.is_some()
    }

    pub(super) fn thread_panicked(&self) -> bool {
        self.thread_panicked.load(Ordering::Acquire)
    }

    pub(super) fn retain_thread(&self, worker: JoinHandle<()>) {
        let mut threads = match self.threads.lock() {
            Ok(threads) => threads,
            Err(poison) => poison.into_inner(),
        };
        threads.push(worker);
    }

    pub(super) fn threads_finished(&self) -> bool {
        self.threads
            .try_lock()
            .is_ok_and(|threads| threads.iter().all(JoinHandle::is_finished))
    }

    #[cfg(test)]
    pub(super) fn retained_thread_count(&self) -> Result<usize, WorkerRetirementRefusal> {
        self.threads
            .try_lock()
            .map(|threads| threads.len())
            .map_err(|_| WorkerRetirementRefusal::Pending)
    }

    pub(super) fn join_finished(
        &self,
        original: &HostOperationGuard,
    ) -> Result<bool, WorkerRetirementRefusal> {
        loop {
            original
                .wait_slice()
                .map_err(WorkerRetirementRefusal::Original)?;
            let handle = {
                let mut threads = self
                    .threads
                    .try_lock()
                    .map_err(|_| WorkerRetirementRefusal::Pending)?;
                let Some(index) = threads.iter().position(JoinHandle::is_finished) else {
                    return Ok(threads.is_empty());
                };
                threads.swap_remove(index)
            };
            if handle.join().is_err() {
                self.thread_panicked.store(true, Ordering::Release);
            }
            original
                .wait_slice()
                .map_err(WorkerRetirementRefusal::Original)?;
        }
    }

    pub(super) fn join_components(&self) -> Result<bool, LocalExecutorPoolShutdownError> {
        if self.has_funded_workers() {
            return Err(LocalExecutorPoolShutdownError::CleanupPending);
        }
        let mut threads = self
            .threads
            .lock()
            .map_err(|_| LocalExecutorPoolShutdownError::SupervisorPoisoned)?;
        let mut panicked = false;
        for worker in threads.drain(..) {
            panicked |= worker.join().is_err();
        }
        Ok(panicked)
    }

    /// Observes joined handles and actual destroyed bodies without cleanup effects.
    pub(crate) fn verify_retired(&self) -> Result<(), WorkerRetirementRefusal> {
        if !self.startup_closed.load(Ordering::Acquire) {
            return Err(WorkerRetirementRefusal::Pending);
        }
        let threads = self
            .threads
            .try_lock()
            .map_err(|_| WorkerRetirementRefusal::Pending)?;
        if !threads.is_empty() {
            return Err(WorkerRetirementRefusal::Pending);
        }
        drop(threads);
        let workers = self
            .workers
            .try_lock()
            .map_err(|_| WorkerRetirementRefusal::Pending)?;
        for worker in workers.iter() {
            worker.verify_retired()?;
        }
        Ok(())
    }

    pub(crate) fn try_retire_original(
        &self,
        original: &HostOperationGuard,
    ) -> Result<(), WorkerRetirementRefusal> {
        if !self.startup_closed.load(Ordering::Acquire) {
            return Err(WorkerRetirementRefusal::Pending);
        }
        let mut first = match self.join_finished(original) {
            Ok(true) => None,
            Ok(false) => Some(WorkerRetirementRefusal::Pending),
            Err(cause) => Some(cause),
        };
        let count = self
            .workers
            .try_lock()
            .map_err(|_| WorkerRetirementRefusal::Pending)?
            .len();
        for index in 0..count {
            let worker = {
                let workers = self
                    .workers
                    .try_lock()
                    .map_err(|_| WorkerRetirementRefusal::Pending)?;
                Arc::clone(&workers[index])
            };
            if let Err(cause) = worker.try_retire_original(original) {
                first.get_or_insert(cause);
            }
        }
        if self.thread_panicked.load(Ordering::Acquire)
            && !self.thread_history_reported.swap(true, Ordering::AcqRel)
        {
            first.get_or_insert(WorkerRetirementRefusal::Historical);
        }
        first.map_or(Ok(()), Err)
    }
}

/// Prepares actual Main custody before any worker model or thread is born.
pub(crate) struct PreparedExecutorWorkers<W: LocalAttemptWorker> {
    cells: Vec<Arc<WorkerCell<W>>>,
    custody: Arc<ExecutorWorkerCustody>,
    capacity: usize,
    handed_off: bool,
}

impl<W> PreparedExecutorWorkers<W>
where
    W: LocalAttemptWorker + Send + 'static,
    W::Error: Send + 'static,
{
    /// Measures generic worker bodies and every new shared/vector allocation.
    pub(crate) fn control_bytes(count: usize, promotion_count: usize) -> Option<u64> {
        if count == 0
            || count > MAX_LOCAL_EXECUTOR_WORKERS
            || promotion_count > MAX_LOCAL_CHECKPOINT_PROMOTION_WORKERS
        {
            return None;
        }
        let workers = std::alloc::Layout::array::<Arc<WorkerCell<W>>>(count).ok()?;
        let erased = std::alloc::Layout::array::<Arc<dyn RetainedPoolWorker>>(count).ok()?;
        let joins =
            std::alloc::Layout::array::<JoinHandle<()>>(count.checked_add(promotion_count)?)
                .ok()?;
        arc_bytes::<WorkerCell<W>>()?
            .checked_mul(count.try_into().ok()?)?
            .checked_add(arc_bytes::<ExecutorWorkerCustody>()?)?
            .checked_add(workers.size().try_into().ok()?)?
            .checked_add(erased.size().try_into().ok()?)?
            .checked_add(joins.size().try_into().ok()?)
    }

    /// Debits and anchors the actual body before model construction or spawn.
    pub(crate) fn prepare(
        count: usize,
        promotion_count: usize,
        producer_bytes: u64,
        main: Option<&Arc<AuthenticatedNativeSlotPurpose>>,
        reserve: impl FnOnce(
            u64,
        ) -> Result<
            Option<AuthenticatedNativePoolPurpose>,
            crucible_qemu_host::QemuVmRealizationError,
        >,
    ) -> Result<Self, LocalExecutorPoolConfigError> {
        let bytes = Self::control_bytes(count, promotion_count)
            .and_then(|bytes| bytes.checked_add(producer_bytes))
            .ok_or(LocalExecutorPoolConfigError::WorkerControlGeometry)?;
        let controls =
            reserve(bytes).map_err(LocalExecutorPoolConfigError::WorkerControlAdmission)?;
        if main.is_some() != controls.is_some()
            || main
                .zip(controls.as_ref())
                .is_some_and(|(main, controls)| !controls.belongs_to_main(main))
        {
            return Err(LocalExecutorPoolConfigError::HostOperationalAdmission);
        }
        let custody = Arc::new(ExecutorWorkerCustody {
            workers: Mutex::new(Vec::with_capacity(count)),
            threads: Mutex::new(Vec::with_capacity(count + promotion_count)),
            thread_panicked: AtomicBool::new(false),
            thread_history_reported: AtomicBool::new(false),
            _controls: controls,
            _metadata: crucible_engine::owned_decode::current_custody(),
            startup_closed: AtomicBool::new(false),
        });
        if let Some(main) = main {
            crate::campaign_process::install_executor_worker_custody(main, Arc::clone(&custody))
                .map_err(LocalExecutorPoolConfigError::WorkerControlAdmission)?;
        }
        Ok(Self {
            cells: Vec::with_capacity(count),
            custody,
            capacity: count,
            handed_off: false,
        })
    }

    /// Borrows the actual returned payer without another reservation or grant.
    pub(crate) fn controls(&self) -> Option<&AuthenticatedNativePoolPurpose> {
        self.custody._controls.as_ref()
    }

    /// Moves a newly constructed worker into its already paid Main cell.
    ///
    /// # Panics
    /// Panics if the internal construction loop exceeds its validated count.
    pub(crate) fn push(&mut self, worker: W) {
        // Production iterates the already validated exact selected worker count.
        // Exceeding it is an internal invariant failure, never extra capacity.
        assert!(
            self.cells.len() < self.capacity,
            "worker construction exceeded admitted cells"
        );
        let cell = Arc::new(WorkerCell {
            state: Mutex::new(WorkerState {
                worker: Some(worker),
                first: None,
                after: None,
                destruction_failed: false,
                destroying: false,
                history_reported: false,
            }),
            borrowed: AtomicBool::new(false),
        });
        let mut workers = match self.custody.workers.lock() {
            Ok(workers) => workers,
            Err(poison) => poison.into_inner(),
        };
        workers.push(cell.clone());
        self.cells.push(cell);
    }

    /// Builds unissued component custody; no Main purpose or native pool exists.
    #[cfg(test)]
    pub(crate) fn unissued_component_custody(workers: Vec<W>) -> Arc<ExecutorWorkerCustody> {
        let prepared = Self::component(workers, 0);
        let custody = Arc::clone(&prepared.custody);
        drop(prepared);
        custody
    }

    pub(super) fn component(workers: Vec<W>, promotion_count: usize) -> Self {
        let count = workers.len();
        // Components carry no authenticated Main or production allocation claim.
        let custody = Arc::new(ExecutorWorkerCustody {
            workers: Mutex::new(Vec::with_capacity(count)),
            threads: Mutex::new(Vec::with_capacity(count + promotion_count)),
            thread_panicked: AtomicBool::new(false),
            thread_history_reported: AtomicBool::new(false),
            _controls: None,
            _metadata: crucible_engine::owned_decode::current_custody(),
            startup_closed: AtomicBool::new(false),
        });
        let mut prepared = Self {
            cells: Vec::with_capacity(count),
            custody,
            capacity: count,
            handed_off: false,
        };
        for worker in workers {
            prepared.push(worker);
        }
        prepared
    }

    pub(super) fn into_cells(mut self) -> (Vec<Arc<WorkerCell<W>>>, Arc<ExecutorWorkerCustody>) {
        self.handed_off = true;
        (std::mem::take(&mut self.cells), Arc::clone(&self.custody))
    }
}

impl<W: LocalAttemptWorker> Drop for PreparedExecutorWorkers<W> {
    fn drop(&mut self) {
        if !self.handed_off {
            self.custody.startup_closed.store(true, Ordering::Release);
        }
    }
}

pub(super) struct WorkerStartup(pub(super) Arc<ExecutorWorkerCustody>);

impl Drop for WorkerStartup {
    fn drop(&mut self) {
        self.0.startup_closed.store(true, Ordering::Release);
    }
}

pub(super) struct WorkerBorrowExit<'a>(pub(super) &'a AtomicBool);

impl Drop for WorkerBorrowExit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn arc_bytes<T>() -> Option<u64> {
    let (layout, _) = std::alloc::Layout::new::<(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    )>()
    .extend(std::alloc::Layout::new::<T>())
    .ok()?;
    layout.pad_to_align().size().try_into().ok()
}

impl<W> RetainedPoolWorker for WorkerCell<W>
where
    W: LocalAttemptWorker + Send + 'static,
    W::Error: Send + 'static,
{
    fn verify_retired(&self) -> Result<(), WorkerRetirementRefusal> {
        if self.borrowed.load(Ordering::Acquire) {
            return Err(WorkerRetirementRefusal::Pending);
        }
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(WorkerRetirementRefusal::Pending);
            }
        };
        if state.destruction_failed {
            return Err(WorkerRetirementRefusal::Destruction);
        }
        if state.destroying || state.worker.is_some() {
            return Err(WorkerRetirementRefusal::Pending);
        }
        Ok(())
    }

    fn try_retire_original(
        &self,
        original: &HostOperationGuard,
    ) -> Result<(), WorkerRetirementRefusal> {
        original
            .wait_slice()
            .map_err(WorkerRetirementRefusal::Original)?;
        if self.borrowed.load(Ordering::Acquire) {
            return Err(WorkerRetirementRefusal::Pending);
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(WorkerRetirementRefusal::Pending);
            }
        };
        if state.destruction_failed {
            return Err(WorkerRetirementRefusal::Destruction);
        }
        if state.destroying {
            return Err(WorkerRetirementRefusal::Pending);
        }
        if let Some(worker) = state.worker.as_mut() {
            let work = catch_unwind(AssertUnwindSafe(|| worker.try_retire_original(original)));
            let post = original.wait_slice().err();
            if let Some(post) = post {
                state.after.get_or_insert(post);
            }
            match work {
                Ok(Ok(())) if post.is_none() => {}
                Ok(Err(cause)) => {
                    state.first.get_or_insert(cause);
                    return Err(WorkerRetirementRefusal::Resources);
                }
                Ok(Ok(())) => {
                    if let Some(post) = post {
                        return Err(WorkerRetirementRefusal::Original(post));
                    }
                }
                Err(_) => {
                    state.destruction_failed = true;
                    return Err(WorkerRetirementRefusal::Destruction);
                }
            }
            state.destroying = true;
            let worker = state.worker.take();
            drop(state);
            let destroyed = catch_unwind(AssertUnwindSafe(|| drop(worker)));
            state = match self.state.lock() {
                Ok(state) => state,
                Err(poison) => poison.into_inner(),
            };
            state.destroying = false;
            if destroyed.is_err() {
                state.destruction_failed = true;
                return Err(WorkerRetirementRefusal::Destruction);
            }
            if let Err(post) = original.wait_slice() {
                state.after.get_or_insert(post);
                return Err(WorkerRetirementRefusal::Original(post));
            }
        }
        if !state.history_reported && (state.first.is_some() || state.after.is_some()) {
            state.history_reported = true;
            return Err(WorkerRetirementRefusal::Historical);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
