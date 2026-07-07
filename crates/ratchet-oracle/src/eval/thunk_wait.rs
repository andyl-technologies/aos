//! Safe waiter/wakeup precursor for parallel thunk forcing.
//!
//! This module builds on [`super::thunk_cas`] with a standard-library
//! [`Condvar`] and [`Mutex`] so the Phase 3.5 L2 no-lost-wakeup protocol can be
//! tested before the final lock-free waiter list and work-stealing scheduler
//! land. It intentionally does not store forced values or captured errors; it
//! only coordinates the terminal `Forced`/`Failed` state.
//!
//! The synchronization rule is deliberately conservative: a waiter holds the
//! waiter mutex while marking the thunk `Awaited` and while checking the
//! terminal predicate before sleeping. A publisher stores the terminal state
//! first, then takes the same mutex before notifying all waiters. That pairing
//! prevents the classic race where a waiter observes `Pending`, a publisher
//! notifies, and the waiter then parks forever.
//!
//! Waiter lock poisoning is reported to diagnostic readers, but the wait and
//! notify paths recover the poisoned lock and continue. Once a worker may be
//! parked, preserving terminal wakeup progress is more important than surfacing
//! the poison through the synchronization path.

use std::{
    convert::Infallible,
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
};

use thiserror::Error;

use super::thunk_cas::{
    ParallelThunkAwait, ParallelThunkClaim, ParallelThunkClaimGuard, ParallelThunkPublish,
    ParallelThunkState, ParallelThunkStateError, ParallelThunkStateWord,
    ParallelThunkTerminalState, ParallelThunkWorkerId,
};
use super::thunk_registry::{ParallelForceCycleRegistry, ParallelForceWaitRegistration};

/// A thunk CAS state word paired with safe waiter notification.
///
/// This is a correctness precursor for tests and future evaluator wiring. It is
/// not the final lock-free waiter-list representation and does not perform
/// work stealing before parking.
///
/// A cell may carry a shared [`ParallelForceCycleRegistry`]. When present, a
/// waiter registers its wait edge (and walks the cross-worker owner chain)
/// before parking, and terminal publication purges the cell's edges inside the
/// registry critical section; see the `thunk_registry` module docs for the
/// protocol. Cells without a registry keep the original park-unconditionally
/// behavior, which is only deadlock-free while a single worker forces the
/// graph.
#[derive(Debug)]
pub struct ParallelThunkWaitCell {
    state: ParallelThunkStateWord,
    waiters: Mutex<ParallelThunkWaitState>,
    terminal_ready: Condvar,
    cycle_registry: Option<Arc<ParallelForceCycleRegistry>>,
}

impl Default for ParallelThunkWaitCell {
    fn default() -> Self {
        Self::new()
    }
}

impl ParallelThunkWaitCell {
    /// Creates a suspended wait cell with no registered waiters.
    pub fn new() -> Self {
        Self::with_cycle_registry(None)
    }

    /// Creates a suspended wait cell bound to a shared cycle registry.
    ///
    /// Every cell of one shared demand graph must be bound to the same
    /// registry instance for cross-worker deadlock-cycle detection to see all
    /// wait edges.
    pub fn with_cycle_registry(cycle_registry: Option<Arc<ParallelForceCycleRegistry>>) -> Self {
        Self {
            state: ParallelThunkStateWord::new(),
            waiters: Mutex::new(ParallelThunkWaitState::default()),
            terminal_ready: Condvar::new(),
            cycle_registry,
        }
    }

    /// Creates a forced wait cell for relocating an already-terminal payload.
    pub(crate) fn forced_for_relocation(
        cycle_registry: Option<Arc<ParallelForceCycleRegistry>>,
    ) -> Self {
        Self {
            state: ParallelThunkStateWord::forced_for_relocation(),
            waiters: Mutex::new(ParallelThunkWaitState::default()),
            terminal_ready: Condvar::new(),
            cycle_registry,
        }
    }

    /// Creates a failed wait cell for relocating an already-terminal payload.
    pub(crate) fn failed_for_relocation(
        cycle_registry: Option<Arc<ParallelForceCycleRegistry>>,
    ) -> Self {
        Self {
            state: ParallelThunkStateWord::failed_for_relocation(),
            waiters: Mutex::new(ParallelThunkWaitState::default()),
            terminal_ready: Condvar::new(),
            cycle_registry,
        }
    }

    /// Returns the shared cycle registry this cell is bound to, if any.
    pub(crate) fn cycle_registry(&self) -> Option<&Arc<ParallelForceCycleRegistry>> {
        self.cycle_registry.as_ref()
    }

    /// Returns this cell's identity key in the shared cycle registry.
    ///
    /// The cell address is stable for the lifetime of the owning heap record:
    /// parallel cells live behind a `Box` inside an `Arc`-shared thunk record,
    /// and relocation writebacks refuse to clone a claimed cell, so a key is
    /// never observed for a moved cell while claims or waits reference it.
    fn cycle_registry_key(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    /// Loads the current state with acquire ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkWaitError::State`] if the private state word
    /// contains an unsupported encoding.
    pub fn state(&self) -> Result<ParallelThunkState, ParallelThunkWaitError> {
        Ok(self.state.state()?)
    }

    /// Returns waiter/wakeup counters for diagnostics and tests.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkWaitError::WaiterLockPoisoned`] if the waiter
    /// mutex was poisoned by a panic while locked.
    pub fn stats(&self) -> Result<ParallelThunkWaitStats, ParallelThunkWaitError> {
        let waiters = self.lock_waiters_for_read()?;
        Ok(waiters.stats())
    }

    /// Claims the thunk, returns a terminal state, or waits for the owner.
    ///
    /// When another worker owns the thunk, this method marks the state word as
    /// `Awaited`, registers the waiter under the condition-variable mutex, and
    /// sleeps until the owner publishes `Forced` or `Failed`. It is a blocking
    /// precursor for the future wait-or-steal path: callers should not use it
    /// as the final scheduler behavior because it parks immediately instead of
    /// draining local work or stealing peer work first.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkWaitError::State`] if the state word contains an
    /// unsupported encoding or reports an impossible transition. Waiter lock
    /// poisoning is deliberately recovered on this path so registered waiters
    /// can still observe terminal states.
    pub fn claim_or_wait_for_terminal(
        &self,
        worker: ParallelThunkWorkerId,
    ) -> Result<ParallelThunkWait<'_>, ParallelThunkWaitError> {
        loop {
            match self.state.try_claim(worker)? {
                ParallelThunkClaim::Claimed(guard) => {
                    return Ok(ParallelThunkWait::Claimed(ParallelThunkWaitGuard {
                        cell: self,
                        guard: Some(guard),
                    }));
                }
                ParallelThunkClaim::AlreadyForced => {
                    return Ok(ParallelThunkWait::Terminal(
                        ParallelThunkTerminalState::Forced,
                    ));
                }
                ParallelThunkClaim::AlreadyFailed => {
                    return Ok(ParallelThunkWait::Terminal(
                        ParallelThunkTerminalState::Failed,
                    ));
                }
                ParallelThunkClaim::SelfCycle { owner } => {
                    return Ok(ParallelThunkWait::SelfCycle { owner });
                }
                ParallelThunkClaim::ForeignPending { .. }
                | ParallelThunkClaim::ForeignAwaited { .. } => {
                    if let Some((result, _wait_registered)) =
                        self.wait_for_foreign_terminal(worker)?
                    {
                        return Ok(result);
                    }
                }
            }
        }
    }

    /// Claims the thunk, runs advisory ready work, then waits if still blocked.
    ///
    /// This is a small wait-or-steal ordering precursor for §3.3. When the
    /// thunk is owned by another worker, `run_ready_work` is called before this
    /// method enters the wait-cell path. The closure is responsible for the
    /// eventual scheduler policy: drain local work first, then attempt peer
    /// steals, and return [`ParallelThunkReadyWork::Idle`] only after its scan
    /// has no ready work. This type cannot prove that the scan was exhaustive or
    /// hold a scheduler park token; the final scheduler integration must supply
    /// those guarantees. After each reported local or stolen work item, the
    /// thunk state is rechecked. If the owner published a terminal state while
    /// that work ran, this method returns without registering a waiter.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkWaitError::State`] if the state word contains an
    /// unsupported encoding or reports an impossible transition. Waiter lock
    /// poisoning is deliberately recovered on this path so registered waiters
    /// can still observe terminal states.
    pub fn claim_or_run_ready_then_wait(
        &self,
        worker: ParallelThunkWorkerId,
        mut run_ready_work: impl FnMut() -> ParallelThunkReadyWork,
    ) -> Result<ParallelThunkWorkWait<'_>, ParallelThunkWaitError> {
        self.claim_or_try_run_ready_then_wait(worker, || Ok::<_, Infallible>(run_ready_work()))
            .map_err(|error| match error {
                ParallelThunkReadyWorkWaitError::Wait(error) => error,
                ParallelThunkReadyWorkWaitError::ReadyWork(never) => match never {},
            })
    }

    /// Claims the thunk, runs fallible advisory ready work, then waits if blocked.
    ///
    /// This is the fallible form of
    /// [`ParallelThunkWaitCell::claim_or_run_ready_then_wait`]. It preserves the
    /// same ordering rule: after each successful local or stolen ready-work
    /// report, the thunk state is rechecked before any waiter registration can
    /// happen. If `run_ready_work` returns an error, that error is returned
    /// immediately and the wait-cell path is not entered for that iteration.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkReadyWorkWaitError::Wait`] if the state word
    /// contains an unsupported encoding or reports an impossible transition.
    /// Returns [`ParallelThunkReadyWorkWaitError::ReadyWork`] if the ready-work
    /// hook fails. Waiter lock poisoning is deliberately recovered on the wait
    /// path so registered waiters can still observe terminal states.
    pub fn claim_or_try_run_ready_then_wait<E>(
        &self,
        worker: ParallelThunkWorkerId,
        mut run_ready_work: impl FnMut() -> Result<ParallelThunkReadyWork, E>,
    ) -> Result<ParallelThunkWorkWait<'_>, ParallelThunkReadyWorkWaitError<E>> {
        let mut report = ParallelThunkContentionReport::default();

        loop {
            match self
                .state
                .try_claim(worker)
                .map_err(ParallelThunkWaitError::from)?
            {
                ParallelThunkClaim::Claimed(guard) => {
                    return Ok(ParallelThunkWorkWait::new(
                        ParallelThunkWait::Claimed(ParallelThunkWaitGuard {
                            cell: self,
                            guard: Some(guard),
                        }),
                        report,
                    ));
                }
                ParallelThunkClaim::AlreadyForced => {
                    return Ok(ParallelThunkWorkWait::new(
                        ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced),
                        report,
                    ));
                }
                ParallelThunkClaim::AlreadyFailed => {
                    return Ok(ParallelThunkWorkWait::new(
                        ParallelThunkWait::Terminal(ParallelThunkTerminalState::Failed),
                        report,
                    ));
                }
                ParallelThunkClaim::SelfCycle { owner } => {
                    return Ok(ParallelThunkWorkWait::new(
                        ParallelThunkWait::SelfCycle { owner },
                        report,
                    ));
                }
                ParallelThunkClaim::ForeignPending { .. }
                | ParallelThunkClaim::ForeignAwaited { .. } => {
                    match run_ready_work().map_err(ParallelThunkReadyWorkWaitError::ReadyWork)? {
                        ParallelThunkReadyWork::RanLocal => {
                            report.local_work_runs = report.local_work_runs.saturating_add(1);
                        }
                        ParallelThunkReadyWork::StolePeer => {
                            report.stolen_work_runs = report.stolen_work_runs.saturating_add(1);
                        }
                        ParallelThunkReadyWork::Idle => {
                            if let Some((result, wait_registered)) =
                                self.wait_for_foreign_terminal(worker)?
                            {
                                report.wait_registered = wait_registered;
                                return Ok(ParallelThunkWorkWait::new(result, report));
                            }
                        }
                    }
                }
            }
        }
    }

    fn wait_for_foreign_terminal(
        &self,
        worker: ParallelThunkWorkerId,
    ) -> Result<Option<(ParallelThunkWait<'_>, bool)>, ParallelThunkWaitError> {
        let mut waiters = self.lock_waiters_for_wait();
        match self.state.mark_awaited(worker)? {
            ParallelThunkAwait::Unclaimed => Ok(None),
            ParallelThunkAwait::AlreadyForced => Ok(Some((
                ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced),
                false,
            ))),
            ParallelThunkAwait::AlreadyFailed => Ok(Some((
                ParallelThunkWait::Terminal(ParallelThunkTerminalState::Failed),
                false,
            ))),
            ParallelThunkAwait::SelfCycle { owner } => {
                Ok(Some((ParallelThunkWait::SelfCycle { owner }, false)))
            }
            ParallelThunkAwait::Awaited { owner, .. } => {
                if let Some(registry) = &self.cycle_registry {
                    // The registry lock is taken while holding the waiter
                    // mutex; publishers never nest the two (they release the
                    // registry lock before notifying), so this ordering is
                    // deadlock-free. The state re-read runs under the registry
                    // lock, making the decision race-free against concurrent
                    // terminal publication.
                    match registry.register_parked_waiter(
                        worker,
                        self.cycle_registry_key(),
                        || self.state.state(),
                    )? {
                        ParallelForceWaitRegistration::Cycle { owner }
                        | ParallelForceWaitRegistration::SelfOwned { owner } => {
                            // Parking would deadlock: the owner chain leads
                            // back to this worker. Surface the same outcome as
                            // direct same-worker re-entry so the evaluator
                            // raises its serial infinite-recursion error.
                            return Ok(Some((ParallelThunkWait::SelfCycle { owner }, false)));
                        }
                        ParallelForceWaitRegistration::Registered
                        | ParallelForceWaitRegistration::Terminal
                        | ParallelForceWaitRegistration::Unclaimed => {
                            // Terminal/unclaimed re-reads fall through to the
                            // wait loop, whose pre-sleep state check returns
                            // (or retries) immediately without sleeping.
                        }
                    }
                }
                waiters.wait_registrations = waiters.wait_registrations.saturating_add(1);
                let result = self.wait_until_terminal(waiters, worker, owner);
                if let Some(registry) = &self.cycle_registry {
                    registry.deregister_waiter(worker, self.cycle_registry_key());
                }
                result.map(|result| Some((result, true)))
            }
        }
    }

    fn wait_until_terminal<'a>(
        &'a self,
        mut waiters: MutexGuard<'_, ParallelThunkWaitState>,
        worker: ParallelThunkWorkerId,
        expected_owner: ParallelThunkWorkerId,
    ) -> Result<ParallelThunkWait<'a>, ParallelThunkWaitError> {
        loop {
            match self.state.state()? {
                ParallelThunkState::Forced => {
                    return Ok(ParallelThunkWait::Terminal(
                        ParallelThunkTerminalState::Forced,
                    ));
                }
                ParallelThunkState::Failed => {
                    return Ok(ParallelThunkWait::Terminal(
                        ParallelThunkTerminalState::Failed,
                    ));
                }
                ParallelThunkState::Pending { owner } | ParallelThunkState::Awaited { owner }
                    if owner == worker =>
                {
                    return Ok(ParallelThunkWait::SelfCycle { owner });
                }
                ParallelThunkState::Pending { owner } | ParallelThunkState::Awaited { owner }
                    if owner == expected_owner =>
                {
                    waiters = self
                        .terminal_ready
                        .wait(waiters)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                actual => {
                    return Err(ParallelThunkWaitError::State(
                        ParallelThunkStateError::UnexpectedState {
                            expected_owner,
                            actual,
                        },
                    ));
                }
            }
        }
    }

    /// Runs a terminal state-word transition inside the cycle-registry
    /// critical section, purging this cell's recorded wait edges first.
    ///
    /// Without a bound registry this is a plain call to `publish`. The purge
    /// plus in-lock publication is what keeps registered wait edges pointing
    /// only at live claims; see the `thunk_registry` module docs.
    fn publish_with_cycle_purge<R>(&self, publish: impl FnOnce() -> R) -> R {
        match &self.cycle_registry {
            Some(registry) => registry.publish_purged(self.cycle_registry_key(), publish),
            None => publish(),
        }
    }

    fn notify_after_publish(
        &self,
        report: ParallelThunkPublish,
    ) -> Result<(), ParallelThunkWaitError> {
        if report.had_waiters() {
            self.notify_waiters();
        }
        Ok(())
    }

    fn notify_waiters(&self) {
        let mut waiters = self.lock_waiters_for_notify();
        waiters.notifications = waiters.notifications.saturating_add(1);
        self.terminal_ready.notify_all();
    }

    fn lock_waiters_for_read(
        &self,
    ) -> Result<MutexGuard<'_, ParallelThunkWaitState>, ParallelThunkWaitError> {
        self.waiters
            .lock()
            .map_err(|_| ParallelThunkWaitError::WaiterLockPoisoned)
    }

    fn lock_waiters_for_wait(&self) -> MutexGuard<'_, ParallelThunkWaitState> {
        self.waiters.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_waiters_for_notify(&self) -> MutexGuard<'_, ParallelThunkWaitState> {
        self.waiters.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Ready work attempted while a foreign worker owns a thunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParallelThunkReadyWork {
    /// A local ready task was executed.
    RanLocal,
    /// A peer ready task was stolen and executed.
    StolePeer,
    /// The hook reports no local or stolen work is available.
    Idle,
}

/// Counters collected while handling contention on a foreign-owned thunk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParallelThunkContentionReport {
    local_work_runs: usize,
    stolen_work_runs: usize,
    wait_registered: bool,
}

impl ParallelThunkContentionReport {
    /// Returns how many local ready work items ran before returning.
    pub const fn local_work_runs(self) -> usize {
        self.local_work_runs
    }

    /// Returns how many peer work items were stolen before returning.
    pub const fn stolen_work_runs(self) -> usize {
        self.stolen_work_runs
    }

    /// Returns whether the wait-cell registration path was entered.
    pub const fn wait_registered(self) -> bool {
        self.wait_registered
    }
}

/// Result of claiming or waiting on a parallel thunk wait cell.
#[must_use = "a claimed parallel thunk must be published as forced or failed"]
#[derive(Debug)]
pub enum ParallelThunkWait<'a> {
    /// The caller owns thunk evaluation and must publish a terminal state.
    Claimed(ParallelThunkWaitGuard<'a>),
    /// The thunk has reached a terminal state.
    Terminal(ParallelThunkTerminalState),
    /// Forcing this thunk closes an ownership cycle back to the caller.
    ///
    /// This covers direct same-worker re-entry and, for cells bound to a
    /// [`ParallelForceCycleRegistry`], transitive cross-worker wait cycles
    /// detected before parking. Both are the evaluation-cycle condition that
    /// serial forcing reports as infinite recursion.
    SelfCycle {
        /// The worker that owns the claim on the directly awaited thunk.
        owner: ParallelThunkWorkerId,
    },
}

/// Result and contention report from a wait-or-steal precursor call.
///
/// This wrapper may carry a worker-affine claim guard and is intentionally not
/// [`Send`]:
///
/// ```compile_fail
/// use ratchet_oracle::eval::ParallelThunkWorkWait;
///
/// fn assert_send<T: Send>() {}
///
/// assert_send::<ParallelThunkWorkWait<'static>>();
/// ```
#[must_use = "a claimed parallel thunk must be published as forced or failed"]
#[derive(Debug)]
pub struct ParallelThunkWorkWait<'a> {
    result: ParallelThunkWait<'a>,
    report: ParallelThunkContentionReport,
}

impl<'a> ParallelThunkWorkWait<'a> {
    fn new(result: ParallelThunkWait<'a>, report: ParallelThunkContentionReport) -> Self {
        Self { result, report }
    }

    /// Returns the claim, terminal state, or self-cycle classification.
    pub const fn result(&self) -> &ParallelThunkWait<'a> {
        &self.result
    }

    /// Returns the contention-avoidance report.
    pub const fn report(&self) -> ParallelThunkContentionReport {
        self.report
    }

    /// Consumes the outcome into its result and report.
    pub fn into_parts(self) -> (ParallelThunkWait<'a>, ParallelThunkContentionReport) {
        (self.result, self.report)
    }
}

/// A live wait-cell claim that wakes registered waiters on publication.
///
/// Dropping the guard delegates to [`ParallelThunkClaimGuard`], publishing
/// `Failed`, and then notifies registered waiters. The guard remains
/// worker-affine because the wrapped CAS claim guard is not [`Send`]:
///
/// ```compile_fail
/// use ratchet_oracle::eval::ParallelThunkWaitGuard;
///
/// fn assert_send<T: Send>() {}
///
/// assert_send::<ParallelThunkWaitGuard<'static>>();
/// ```
#[must_use = "publish the claimed parallel thunk as forced or failed"]
#[derive(Debug)]
pub struct ParallelThunkWaitGuard<'a> {
    cell: &'a ParallelThunkWaitCell,
    guard: Option<ParallelThunkClaimGuard<'a>>,
}

impl ParallelThunkWaitGuard<'_> {
    /// Publishes a successful thunk result and wakes registered waiters.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkWaitError::State`] if the state word is no longer
    /// pending or awaited for this guard's owner, or if it contains an
    /// unsupported encoding. Waiter lock poisoning is deliberately recovered
    /// during notification so already-published terminal states still wake
    /// registered waiters.
    pub fn publish_forced(mut self) -> Result<ParallelThunkPublish, ParallelThunkWaitError> {
        let cell = self.cell;
        let guard = self.take_guard()?;
        let report = match cell.publish_with_cycle_purge(|| guard.publish_forced()) {
            Ok(report) => report,
            Err(error) => {
                cell.notify_waiters();
                return Err(ParallelThunkWaitError::State(error));
            }
        };
        cell.notify_after_publish(report)?;
        Ok(report)
    }

    /// Publishes a failed thunk result and wakes registered waiters.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkWaitError::State`] if the state word is no longer
    /// pending or awaited for this guard's owner, or if it contains an
    /// unsupported encoding. Waiter lock poisoning is deliberately recovered
    /// during notification so already-published terminal states still wake
    /// registered waiters.
    pub fn publish_failed(mut self) -> Result<ParallelThunkPublish, ParallelThunkWaitError> {
        let cell = self.cell;
        let guard = self.take_guard()?;
        let report = match cell.publish_with_cycle_purge(|| guard.publish_failed()) {
            Ok(report) => report,
            Err(error) => {
                cell.notify_waiters();
                return Err(ParallelThunkWaitError::State(error));
            }
        };
        cell.notify_after_publish(report)?;
        Ok(report)
    }

    fn take_guard(&mut self) -> Result<ParallelThunkClaimGuard<'_>, ParallelThunkWaitError> {
        self.guard
            .take()
            .ok_or(ParallelThunkWaitError::ClaimGuardMissing)
    }
}

impl Drop for ParallelThunkWaitGuard<'_> {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            // Dropping the inner CAS guard publishes `Failed`; route that
            // terminal transition through the registry purge so the cycle
            // registry invariant holds on the unwind path too.
            self.cell.publish_with_cycle_purge(|| drop(guard));
            self.cell.notify_waiters();
        }
    }
}

/// Waiter/wakeup counters for a parallel thunk wait cell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParallelThunkWaitStats {
    wait_registrations: usize,
    notifications: usize,
}

impl ParallelThunkWaitStats {
    /// Returns the number of registered wait attempts.
    pub const fn wait_registrations(self) -> usize {
        self.wait_registrations
    }

    /// Returns the number of terminal notifications sent to waiters.
    pub const fn notifications(self) -> usize {
        self.notifications
    }
}

#[derive(Debug, Default)]
struct ParallelThunkWaitState {
    wait_registrations: usize,
    notifications: usize,
}

impl ParallelThunkWaitState {
    const fn stats(&self) -> ParallelThunkWaitStats {
        ParallelThunkWaitStats {
            wait_registrations: self.wait_registrations,
            notifications: self.notifications,
        }
    }
}

/// A failure while running a fallible ready-work hook before waiting.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParallelThunkReadyWorkWaitError<E> {
    /// The underlying wait-cell operation failed.
    #[error(transparent)]
    Wait(#[from] ParallelThunkWaitError),
    /// The ready-work hook failed before the wait-cell path could continue.
    #[error("parallel thunk ready-work hook failed")]
    ReadyWork(#[source] E),
}

/// A failure while claiming, waiting for, or publishing a parallel thunk.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParallelThunkWaitError {
    /// The underlying CAS state word rejected an operation.
    #[error(transparent)]
    State(#[from] ParallelThunkStateError),
    /// The waiter mutex was poisoned by a panic.
    #[error("parallel thunk waiter lock is poisoned")]
    WaiterLockPoisoned,
    /// A wait-cell claim guard was consumed more than once.
    #[error("parallel thunk wait claim guard is missing")]
    ClaimGuardMissing,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Barrier,
            mpsc::{self, RecvTimeoutError},
        },
        thread,
        time::{Duration, Instant},
    };

    use super::*;

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
    fn suspended_wait_cell_claims_and_publishes_forced() {
        let cell = ParallelThunkWaitCell::new();
        let owner = worker(1);

        let ParallelThunkWait::Claimed(guard) = cell
            .claim_or_wait_for_terminal(owner)
            .expect("claim checks state")
        else {
            panic!("suspended wait cell should be claimed");
        };

        let report = guard.publish_forced().expect("publish succeeds");

        assert_eq!(report.terminal_state(), ParallelThunkTerminalState::Forced);
        assert_eq!(cell.state(), Ok(ParallelThunkState::Forced));
        assert_eq!(
            cell.stats().expect("stats are readable"),
            ParallelThunkWaitStats {
                wait_registrations: 0,
                notifications: 0,
            }
        );
    }

    #[test]
    fn foreign_waiter_blocks_until_forced_publish_and_wakes() {
        let cell = Arc::new(ParallelThunkWaitCell::new());
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = mpsc::channel();

        let owner_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            let publish_ready = Arc::clone(&publish_ready);
            thread::spawn(move || {
                let ParallelThunkWait::Claimed(guard) = cell
                    .claim_or_wait_for_terminal(worker(1))
                    .expect("owner claims")
                else {
                    panic!("owner should claim suspended cell");
                };
                owner_ready.wait();
                publish_ready.wait();
                guard.publish_forced().expect("owner publishes forced");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let result = cell
                    .claim_or_wait_for_terminal(worker(2))
                    .expect("waiter observes terminal");
                let ParallelThunkWait::Terminal(terminal_state) = result else {
                    panic!("waiter should observe a terminal state");
                };
                result_tx
                    .send(terminal_state)
                    .expect("result send succeeds");
            })
        };

        owner_ready.wait();
        wait_until_registered(&cell, 1);
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));

        publish_ready.wait();
        let result = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");

        assert_eq!(result, ParallelThunkTerminalState::Forced);
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
        assert_eq!(cell.state(), Ok(ParallelThunkState::Forced));
        assert_eq!(
            cell.stats().expect("stats are readable"),
            ParallelThunkWaitStats {
                wait_registrations: 1,
                notifications: 1,
            }
        );
    }

    #[test]
    fn ready_work_runs_before_parking_and_can_observe_terminal_publish() {
        let cell = ParallelThunkWaitCell::new();
        let owner = worker(1);

        let ParallelThunkWait::Claimed(guard) = cell
            .claim_or_wait_for_terminal(owner)
            .expect("owner claims")
        else {
            panic!("owner should claim suspended cell");
        };
        let mut owner_guard = Some(guard);
        let mut step = 0;

        let outcome = cell
            .claim_or_run_ready_then_wait(worker(2), || {
                step += 1;
                match step {
                    1 => ParallelThunkReadyWork::RanLocal,
                    2 => {
                        owner_guard
                            .take()
                            .expect("owner guard is present")
                            .publish_forced()
                            .expect("owner publishes while stolen work runs");
                        ParallelThunkReadyWork::StolePeer
                    }
                    _ => ParallelThunkReadyWork::Idle,
                }
            })
            .expect("wait-or-steal precursor completes");

        let (result, report) = outcome.into_parts();
        assert!(matches!(
            result,
            ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
        ));
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
        assert_eq!(
            cell.stats().expect("stats are readable"),
            ParallelThunkWaitStats {
                wait_registrations: 0,
                notifications: 0,
            }
        );
    }

    #[test]
    fn fallible_ready_work_runs_before_parking_and_preserves_report() {
        let cell = ParallelThunkWaitCell::new();
        let owner = worker(1);

        let ParallelThunkWait::Claimed(guard) = cell
            .claim_or_wait_for_terminal(owner)
            .expect("owner claims")
        else {
            panic!("owner should claim suspended cell");
        };
        let mut owner_guard = Some(guard);
        let mut step = 0;

        let outcome = cell
            .claim_or_try_run_ready_then_wait(worker(2), || {
                step += 1;
                match step {
                    1 => Ok::<_, &str>(ParallelThunkReadyWork::RanLocal),
                    2 => {
                        owner_guard
                            .take()
                            .expect("owner guard is present")
                            .publish_forced()
                            .expect("owner publishes while stolen work runs");
                        Ok(ParallelThunkReadyWork::StolePeer)
                    }
                    _ => Ok(ParallelThunkReadyWork::Idle),
                }
            })
            .expect("fallible wait-or-steal precursor completes");

        let (result, report) = outcome.into_parts();
        assert!(matches!(
            result,
            ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
        ));
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
        assert_eq!(
            cell.stats().expect("stats are readable"),
            ParallelThunkWaitStats {
                wait_registrations: 0,
                notifications: 0,
            }
        );
    }

    #[test]
    fn fallible_ready_work_error_returns_before_wait_registration() {
        let cell = ParallelThunkWaitCell::new();
        let ParallelThunkWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_terminal(worker(1))
            .expect("owner claims")
        else {
            panic!("owner should claim suspended cell");
        };
        let mut step = 0usize;

        let error = cell
            .claim_or_try_run_ready_then_wait(worker(2), || {
                step = step.saturating_add(1);
                match step {
                    1 => Ok(ParallelThunkReadyWork::RanLocal),
                    _ => Err("queue failed"),
                }
            })
            .expect_err("ready-work error is returned");

        assert_eq!(
            error,
            ParallelThunkReadyWorkWaitError::ReadyWork("queue failed")
        );
        assert_eq!(step, 2);
        assert_eq!(
            cell.stats().expect("stats are readable"),
            ParallelThunkWaitStats {
                wait_registrations: 0,
                notifications: 0,
            }
        );

        owner_guard
            .publish_forced()
            .expect("owner can still publish after ready-work error");
        let later = cell
            .claim_or_wait_for_terminal(worker(3))
            .expect("later worker observes terminal");
        assert!(matches!(
            later,
            ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
        ));
    }

    #[test]
    fn idle_after_terminal_publish_returns_without_wait_registration() {
        let cell = ParallelThunkWaitCell::new();
        let owner = worker(1);

        let ParallelThunkWait::Claimed(guard) = cell
            .claim_or_wait_for_terminal(owner)
            .expect("owner claims")
        else {
            panic!("owner should claim suspended cell");
        };
        let mut owner_guard = Some(guard);

        let outcome = cell
            .claim_or_run_ready_then_wait(worker(2), || {
                owner_guard
                    .take()
                    .expect("owner guard is present")
                    .publish_forced()
                    .expect("owner publishes before idle wait");
                ParallelThunkReadyWork::Idle
            })
            .expect("wait-or-steal precursor completes");

        let (result, report) = outcome.into_parts();
        assert!(matches!(
            result,
            ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
        ));
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(!report.wait_registered());
        assert_eq!(
            cell.stats().expect("stats are readable"),
            ParallelThunkWaitStats {
                wait_registrations: 0,
                notifications: 0,
            }
        );
    }

    #[test]
    fn idle_ready_work_parks_until_terminal_publish() {
        let cell = Arc::new(ParallelThunkWaitCell::new());
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = mpsc::channel();

        let owner_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            let publish_ready = Arc::clone(&publish_ready);
            thread::spawn(move || {
                let ParallelThunkWait::Claimed(guard) = cell
                    .claim_or_wait_for_terminal(worker(1))
                    .expect("owner claims")
                else {
                    panic!("owner should claim suspended cell");
                };
                owner_ready.wait();
                publish_ready.wait();
                guard.publish_forced().expect("owner publishes forced");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let outcome = cell
                    .claim_or_run_ready_then_wait(worker(2), || ParallelThunkReadyWork::Idle)
                    .expect("waiter observes terminal");
                let (result, report) = outcome.into_parts();
                let ParallelThunkWait::Terminal(terminal_state) = result else {
                    panic!("waiter should observe a terminal state");
                };
                result_tx
                    .send((terminal_state, report))
                    .expect("result send succeeds");
            })
        };

        owner_ready.wait();
        wait_until_registered(&cell, 1);
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));

        publish_ready.wait();
        let (terminal_state, report) = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");

        assert_eq!(terminal_state, ParallelThunkTerminalState::Forced);
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(report.wait_registered());
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
        assert_eq!(
            cell.stats().expect("stats are readable"),
            ParallelThunkWaitStats {
                wait_registrations: 1,
                notifications: 1,
            }
        );
    }

    #[test]
    fn ready_work_repeats_until_idle_before_wait_registration() {
        let cell = Arc::new(ParallelThunkWaitCell::new());
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = mpsc::channel();

        let owner_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            let publish_ready = Arc::clone(&publish_ready);
            thread::spawn(move || {
                let ParallelThunkWait::Claimed(guard) = cell
                    .claim_or_wait_for_terminal(worker(1))
                    .expect("owner claims")
                else {
                    panic!("owner should claim suspended cell");
                };
                owner_ready.wait();
                publish_ready.wait();
                guard.publish_forced().expect("owner publishes forced");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let mut step = 0;
                let outcome = cell
                    .claim_or_run_ready_then_wait(worker(2), || {
                        step += 1;
                        match step {
                            1 | 3 => ParallelThunkReadyWork::RanLocal,
                            2 => ParallelThunkReadyWork::StolePeer,
                            _ => ParallelThunkReadyWork::Idle,
                        }
                    })
                    .expect("waiter observes terminal");
                let (result, report) = outcome.into_parts();
                let ParallelThunkWait::Terminal(terminal_state) = result else {
                    panic!("waiter should observe a terminal state");
                };
                result_tx
                    .send((terminal_state, report))
                    .expect("result send succeeds");
            })
        };

        owner_ready.wait();
        wait_until_registered(&cell, 1);
        publish_ready.wait();
        let (terminal_state, report) = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");

        assert_eq!(terminal_state, ParallelThunkTerminalState::Forced);
        assert_eq!(report.local_work_runs(), 2);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(report.wait_registered());
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
    }

    #[test]
    fn dropped_owner_guard_wakes_waiter_with_failed_terminal() {
        let cell = Arc::new(ParallelThunkWaitCell::new());
        let owner_ready = Arc::new(Barrier::new(3));
        let drop_ready = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = mpsc::channel();

        let owner_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            let drop_ready = Arc::clone(&drop_ready);
            thread::spawn(move || {
                let ParallelThunkWait::Claimed(_guard) = cell
                    .claim_or_wait_for_terminal(worker(1))
                    .expect("owner claims")
                else {
                    panic!("owner should claim suspended cell");
                };
                owner_ready.wait();
                drop_ready.wait();
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let result = cell
                    .claim_or_wait_for_terminal(worker(2))
                    .expect("waiter observes terminal");
                let ParallelThunkWait::Terminal(terminal_state) = result else {
                    panic!("waiter should observe a terminal state");
                };
                result_tx
                    .send(terminal_state)
                    .expect("result send succeeds");
            })
        };

        owner_ready.wait();
        wait_until_registered(&cell, 1);
        drop_ready.wait();
        let result = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");

        assert_eq!(result, ParallelThunkTerminalState::Failed);
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
        assert_eq!(cell.state(), Ok(ParallelThunkState::Failed));
        assert_eq!(
            cell.stats().expect("stats are readable"),
            ParallelThunkWaitStats {
                wait_registrations: 1,
                notifications: 1,
            }
        );
    }

    #[test]
    fn owner_reentry_reports_self_cycle_without_waiting() {
        let cell = ParallelThunkWaitCell::new();
        let owner = worker(1);

        let ParallelThunkWait::Claimed(guard) = cell
            .claim_or_wait_for_terminal(owner)
            .expect("owner claims")
        else {
            panic!("owner should claim suspended cell");
        };

        assert!(matches!(
            cell.claim_or_wait_for_terminal(owner),
            Ok(ParallelThunkWait::SelfCycle { owner: actual }) if actual == owner
        ));

        guard.publish_failed().expect("cleanup publishes failure");
    }

    #[test]
    fn already_terminal_wait_cell_returns_without_registering_waiter() {
        let cell = ParallelThunkWaitCell::new();
        let owner = worker(1);

        let ParallelThunkWait::Claimed(guard) = cell
            .claim_or_wait_for_terminal(owner)
            .expect("owner claims")
        else {
            panic!("owner should claim suspended cell");
        };
        guard.publish_failed().expect("owner publishes failure");

        assert!(matches!(
            cell.claim_or_wait_for_terminal(worker(2)),
            Ok(ParallelThunkWait::Terminal(
                ParallelThunkTerminalState::Failed
            ))
        ));
        assert_eq!(
            cell.stats().expect("stats are readable"),
            ParallelThunkWaitStats {
                wait_registrations: 0,
                notifications: 0,
            }
        );
    }

    #[test]
    fn publish_still_notifies_after_waiter_lock_poison() {
        let cell = Arc::new(ParallelThunkWaitCell::new());
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = mpsc::channel();

        let owner_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            let publish_ready = Arc::clone(&publish_ready);
            thread::spawn(move || {
                let ParallelThunkWait::Claimed(guard) = cell
                    .claim_or_wait_for_terminal(worker(1))
                    .expect("owner claims")
                else {
                    panic!("owner should claim suspended cell");
                };
                owner_ready.wait();
                publish_ready.wait();
                guard.publish_forced().expect("publish still succeeds");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let result = cell
                    .claim_or_wait_for_terminal(worker(2))
                    .expect("waiter observes terminal");
                let ParallelThunkWait::Terminal(terminal_state) = result else {
                    panic!("waiter should observe a terminal state");
                };
                result_tx
                    .send(terminal_state)
                    .expect("result send succeeds");
            })
        };

        owner_ready.wait();
        wait_until_registered(&cell, 1);
        let poison_cell = Arc::clone(&cell);
        let poison_thread = thread::spawn(move || {
            let _poisoned = poison_cell
                .waiters
                .lock()
                .expect("waiter lock is available");
            panic!("poison waiter lock");
        });
        assert!(poison_thread.join().is_err());

        publish_ready.wait();
        let result = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes despite poison");

        assert_eq!(result, ParallelThunkTerminalState::Forced);
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
        assert_eq!(cell.state(), Ok(ParallelThunkState::Forced));
    }
}
