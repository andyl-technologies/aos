//! The evaluator-native parallel thunk cell over the generic payload cell.
//!
//! Bridges [`ParallelThunkPayloadCell`] to tree-walk types: terminal success
//! stores a [`Value`], terminal failure a [`TreeWalkError`], and the wait/
//! guard/outcome wrappers replay standard `Result` payloads to later claims.

use super::*;

/// A payload-backed parallel thunk cell using tree-walk evaluator payloads.
///
/// This is the narrow evaluator-native bridge over [`ParallelThunkPayloadCell`]:
/// terminal success stores a [`Value`], terminal failure stores a
/// [`TreeWalkError`], and waiters receive a standard
/// `Result<Value, TreeWalkError>` that can be replayed or re-raised by future
/// tree-walk scheduler wiring.
#[derive(Debug)]
pub struct TreeWalkParallelThunkCell {
    payload_cell: ParallelThunkPayloadCell<Value, TreeWalkError>,
}

impl TreeWalkParallelThunkCell {
    /// Creates a suspended tree-walk payload cell.
    ///
    /// `dropped_claim_error` is stored as the captured evaluator failure when a
    /// claimed thunk guard is dropped without publishing a value or error.
    pub fn new(dropped_claim_error: TreeWalkError) -> Self {
        Self::with_cycle_registry(dropped_claim_error, None)
    }

    /// Creates a suspended tree-walk payload cell bound to a cycle registry.
    ///
    /// Every parallel cell of one shared demand graph must share the same
    /// registry instance so a waiter about to park can walk the cross-worker
    /// owner chain and raise infinite recursion instead of deadlocking. See
    /// the `thunk_registry` module docs for the protocol.
    pub fn with_cycle_registry(
        dropped_claim_error: TreeWalkError,
        cycle_registry: Option<Arc<ParallelForceCycleRegistry>>,
    ) -> Self {
        Self {
            payload_cell: ParallelThunkPayloadCell::with_cycle_registry(
                dropped_claim_error,
                cycle_registry,
            ),
        }
    }

    /// Loads the current terminal status.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if the underlying wait cell reports
    /// an invalid state word.
    pub fn state(&self) -> Result<ParallelThunkTerminalStatus, ParallelThunkPayloadError> {
        self.payload_cell.state()
    }

    /// Returns waiter/wakeup counters for diagnostics and tests.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if the underlying waiter mutex was
    /// poisoned while being read.
    pub fn stats(&self) -> Result<ParallelThunkWaitStats, ParallelThunkPayloadError> {
        self.payload_cell.stats()
    }

    /// Returns the stored tree-walk terminal result, if any.
    pub fn terminal_result(&self) -> Option<Result<Value, TreeWalkError>> {
        self.payload_cell
            .terminal_payload()
            .map(ParallelThunkTerminalPayload::into_result)
    }

    /// Returns the forced terminal value, if this cell has one.
    pub(crate) fn forced_terminal_value(&self) -> Result<Option<Value>, ParallelThunkPayloadError> {
        self.payload_cell.forced_payload_value()
    }

    /// Returns the checked terminal evaluator result, if this cell has one.
    pub(crate) fn checked_terminal_result(
        &self,
    ) -> Result<Option<Result<Value, TreeWalkError>>, ParallelThunkPayloadError> {
        Ok(self
            .payload_cell
            .checked_terminal_payload()?
            .map(ParallelThunkTerminalPayload::into_result))
    }

    /// Clones this cell for relocating an owning heap record.
    pub(crate) fn clone_for_relocation(&self) -> Result<Self, ParallelThunkPayloadError> {
        Ok(Self {
            payload_cell: self.payload_cell.clone_for_relocation()?,
        })
    }

    /// Clones this forced cell with a relocated terminal value.
    pub(crate) fn relocated_forced_value(
        &self,
        value: Value,
    ) -> Result<Self, ParallelThunkPayloadError> {
        Ok(Self {
            payload_cell: self.payload_cell.relocated_forced_payload(value)?,
        })
    }

    /// Claims the thunk, returns its terminal result, or waits for the owner.
    ///
    /// A successful owner receives a [`TreeWalkParallelThunkGuard`] and must
    /// publish either a forced [`Value`] or captured [`TreeWalkError`]. A waiter
    /// receives `Ready(Ok(value))` for forced thunks or `Ready(Err(error))` for
    /// failed thunks.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if wait-cell synchronization fails
    /// or a terminal state is observed without a matching payload.
    pub fn claim_or_wait_for_result(
        &self,
        worker: ParallelThunkWorkerId,
    ) -> Result<TreeWalkParallelThunkWait<'_>, ParallelThunkPayloadError> {
        Ok(TreeWalkParallelThunkWait::from_payload_wait(
            self.payload_cell.claim_or_wait_for_payload(worker)?,
        ))
    }

    /// Claims the thunk, runs `body` for the winner, or replays the result.
    ///
    /// The supplied body is evaluated only when this worker wins the suspended
    /// thunk claim. Its `Ok(Value)` or `Err(TreeWalkError)` result is published
    /// before this method returns so waiters and later callers replay the same
    /// evaluator result. If the same worker re-enters a thunk it already owns,
    /// the body is not run and a self-cycle outcome is returned.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if wait-cell synchronization fails,
    /// a terminal state is observed without a matching payload, or terminal
    /// publication from the claim winner fails.
    ///
    /// # Panics
    ///
    /// Panics if `body` panics. During unwinding the active claim guard is
    /// dropped, which publishes the cell's configured dropped-claim
    /// [`TreeWalkError`] for waiters and later callers.
    pub fn force_or_wait_with(
        &self,
        worker: ParallelThunkWorkerId,
        body: impl FnOnce() -> Result<Value, TreeWalkError>,
    ) -> Result<TreeWalkParallelThunkForceOutcome, ParallelThunkPayloadError> {
        match self.claim_or_wait_for_result(worker)? {
            TreeWalkParallelThunkWait::Claimed(guard) => {
                let result = body();
                guard.publish_result(result.clone())?;
                Ok(TreeWalkParallelThunkForceOutcome::Ready(result))
            }
            TreeWalkParallelThunkWait::Ready(result) => {
                Ok(TreeWalkParallelThunkForceOutcome::Ready(result))
            }
            TreeWalkParallelThunkWait::SelfCycle { owner } => {
                Ok(TreeWalkParallelThunkForceOutcome::SelfCycle { owner })
            }
        }
    }

    /// Claims the thunk, runs advisory ready work, then forces or replays it.
    ///
    /// This combines [`TreeWalkParallelThunkCell::force_or_wait_with`] with the
    /// wait-or-steal ordering path. If this worker wins the thunk claim, the
    /// supplied body runs exactly once and the ready-work hook is not called. If
    /// another worker owns the thunk, `run_ready_work` is called by the existing
    /// wait-or-steal loop before this method blocks or observes a terminal
    /// result. The returned report preserves the local work, stolen work, and
    /// waiter-registration status from that loop.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if wait-cell synchronization fails,
    /// a terminal state is observed without a matching payload, or terminal
    /// publication from the claim winner fails.
    ///
    /// # Panics
    ///
    /// Panics if `body` or `run_ready_work` panics. If `body` panics after this
    /// worker has won the claim, the active claim guard is dropped during
    /// unwinding and publishes the cell's configured dropped-claim
    /// [`TreeWalkError`] for waiters and later callers.
    pub fn force_or_run_ready_then_wait_with(
        &self,
        worker: ParallelThunkWorkerId,
        run_ready_work: impl FnMut() -> ParallelThunkReadyWork,
        body: impl FnOnce() -> Result<Value, TreeWalkError>,
    ) -> Result<TreeWalkParallelThunkForceWorkOutcome, ParallelThunkPayloadError> {
        let wait = self.claim_or_run_ready_then_wait_for_result(worker, run_ready_work)?;
        let (result, report) = wait.into_parts();
        let outcome = match result {
            TreeWalkParallelThunkWait::Claimed(guard) => {
                let result = body();
                guard.publish_result(result.clone())?;
                TreeWalkParallelThunkForceOutcome::Ready(result)
            }
            TreeWalkParallelThunkWait::Ready(result) => {
                TreeWalkParallelThunkForceOutcome::Ready(result)
            }
            TreeWalkParallelThunkWait::SelfCycle { owner } => {
                TreeWalkParallelThunkForceOutcome::SelfCycle { owner }
            }
        };
        Ok(TreeWalkParallelThunkForceWorkOutcome { outcome, report })
    }

    /// Claims the thunk, polls scheduler-backed ready work, then forces it.
    ///
    /// This is the evaluator-native bridge for
    /// [`ParallelReadyWorkPoll`]. If this
    /// worker wins the thunk claim, the supplied body runs exactly once and the
    /// ready-work poll hook is not called. If another worker owns the thunk, each
    /// local or stolen ready-work poll is reported to the existing wait-or-steal
    /// loop so the thunk can be rechecked after every task. An idle poll records
    /// its [`ParallelReadyWorkParkPreflight`] snapshot in the returned outcome
    /// and validates that the snapshot is idle for this worker's zero-based
    /// ready-work queue before the wait-cell path can register a waiter. The
    /// poll is a caller-supplied scheduler report, so scheduler queue errors
    /// must be handled by the caller before returning a poll.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if wait-cell synchronization fails,
    /// a terminal state is observed without a matching payload, or terminal
    /// publication from the claim winner fails. Returns
    /// [`ParallelThunkPayloadError::ParkReadiness`] if an idle poll carries a
    /// preflight snapshot that cannot precede parking for this worker.
    ///
    /// # Panics
    ///
    /// Panics if `body` or `poll_ready_work` panics. A panic from
    /// `poll_ready_work` leaves thunk ownership with the existing owner. If
    /// `body` panics after this worker has won the claim, the active claim guard
    /// is dropped during
    /// unwinding and publishes the cell's configured dropped-claim
    /// [`TreeWalkError`] for waiters and later callers.
    pub fn force_or_poll_ready_then_wait_with<R>(
        &self,
        worker: ParallelThunkWorkerId,
        mut poll_ready_work: impl FnMut() -> ParallelReadyWorkPoll<R>,
        body: impl FnOnce() -> Result<Value, TreeWalkError>,
    ) -> Result<TreeWalkParallelThunkForcePollOutcome, ParallelThunkPayloadError> {
        self.force_or_try_poll_ready_then_wait_with(
            worker,
            || Ok::<_, Infallible>(poll_ready_work()),
            body,
        )
        .map_err(|error| match error {
            ParallelThunkPayloadReadyWorkError::Payload(error) => error,
            ParallelThunkPayloadReadyWorkError::ReadyWork(never) => match never {},
        })
    }

    /// Claims the thunk, polls one Chase-Lev ready task at a time, then forces it.
    ///
    /// This binds the evaluator-native poll/preflight bridge to an owner-local
    /// Chase-Lev ready-work queue. The nonzero thunk worker id must map to the
    /// supplied queue's zero-based owner id before any thunk claim, ready work,
    /// or body execution occurs. Contending workers then run at most one local
    /// pop or peer steal per wait-or-steal iteration through
    /// [`ParallelChaseLevReadyWorkQueue::run_next_or_park_preflight`]. Idle
    /// polls keep the queue's non-locking [`ParallelReadyWorkParkPreflight`]
    /// observation and validate it before the blocking wait-cell path can
    /// register a waiter.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if the worker id cannot be mapped
    /// to a ready-work queue id, if the supplied Chase-Lev queue belongs to a
    /// different worker, if wait-cell synchronization fails, if terminal replay
    /// has no matching payload, if terminal publication from the claim winner
    /// fails, or if an idle poll carries a preflight snapshot that cannot
    /// precede parking for this worker.
    ///
    /// # Panics
    ///
    /// Panics if `body` or `run_ready_work` panics. A panic from
    /// `run_ready_work` occurs after one ready task has been removed from its
    /// Chase-Lev deque and leaves thunk ownership with the existing owner. If
    /// `body` panics after this worker has won the claim, the active claim guard
    /// is dropped during unwinding and publishes the cell's configured
    /// dropped-claim [`TreeWalkError`] for waiters and later callers.
    pub fn force_or_chase_lev_ready_then_wait_with<T, R>(
        &self,
        worker: ParallelThunkWorkerId,
        ready_work: &ParallelChaseLevReadyWorkQueue<T>,
        mut run_ready_work: impl FnMut(T) -> R,
        body: impl FnOnce() -> Result<Value, TreeWalkError>,
    ) -> Result<TreeWalkParallelThunkForcePollOutcome, ParallelThunkPayloadError> {
        let ready_worker = ready_work_queue_worker_id(worker)?;
        if ready_worker != ready_work.worker_id() {
            return Err(ParallelThunkPayloadError::ReadyWorkQueueWorkerMismatch {
                worker,
                expected_queue_worker: ready_worker,
                queue_worker: ready_work.worker_id(),
            });
        }

        self.force_or_poll_ready_then_wait_with(
            worker,
            || ready_work.run_next_or_park_preflight(|task| run_ready_work(task)),
            body,
        )
    }

    /// Claims the thunk, tries scheduler-backed ready work, then forces it.
    ///
    /// This is the fallible form of
    /// [`TreeWalkParallelThunkCell::force_or_poll_ready_then_wait_with`]. The
    /// ready-work poll hook can return a typed scheduler error, which is
    /// propagated without entering the wait-cell path for that iteration. Local
    /// and stolen polls still feed the existing contention counters. Idle polls
    /// preserve their park-preflight snapshot in the returned outcome after
    /// validating that the snapshot is idle for this worker's zero-based
    /// ready-work queue before the wait-cell path can register a waiter.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadReadyWorkError::Payload`] if wait-cell
    /// synchronization fails, a terminal state is observed without a matching
    /// payload, terminal publication from the claim winner fails, or an idle
    /// poll carries a preflight snapshot that cannot precede parking for this
    /// worker. Returns [`ParallelThunkPayloadReadyWorkError::ReadyWork`] if the
    /// ready-work poll hook fails before the wait-cell path can continue.
    ///
    /// # Panics
    ///
    /// Panics if `body` or `poll_ready_work` panics. A panic from
    /// `poll_ready_work` leaves thunk ownership with the existing owner. If
    /// `body` panics after this worker has won the claim, the active claim guard
    /// is dropped during unwinding and publishes the cell's configured
    /// dropped-claim [`TreeWalkError`] for waiters and later callers.
    pub fn force_or_try_poll_ready_then_wait_with<R, E>(
        &self,
        worker: ParallelThunkWorkerId,
        mut poll_ready_work: impl FnMut() -> Result<ParallelReadyWorkPoll<R>, E>,
        body: impl FnOnce() -> Result<Value, TreeWalkError>,
    ) -> Result<TreeWalkParallelThunkForcePollOutcome, ParallelThunkPayloadReadyWorkError<E>> {
        let mut park_preflight = None;
        let wait = self
            .claim_or_try_run_ready_then_wait_for_result(worker, || {
                let poll = poll_ready_work()
                    .map_err(TreeWalkParallelThunkPollReadyWorkError::ReadyWork)?;
                if let Some(preflight) = poll.park_preflight() {
                    let ready_worker = ready_work_queue_worker_id(worker)
                        .map_err(TreeWalkParallelThunkPollReadyWorkError::Payload)?;
                    preflight
                        .validate_idle_for_worker(ready_worker)
                        .map_err(ParallelThunkPayloadError::from)
                        .map_err(TreeWalkParallelThunkPollReadyWorkError::Payload)?;
                    park_preflight = Some(preflight.clone());
                }
                Ok(poll.ready_work())
            })
            .map_err(|error| match error {
                ParallelThunkPayloadReadyWorkError::Payload(error) => {
                    ParallelThunkPayloadReadyWorkError::Payload(error)
                }
                ParallelThunkPayloadReadyWorkError::ReadyWork(
                    TreeWalkParallelThunkPollReadyWorkError::ReadyWork(error),
                ) => ParallelThunkPayloadReadyWorkError::ReadyWork(error),
                ParallelThunkPayloadReadyWorkError::ReadyWork(
                    TreeWalkParallelThunkPollReadyWorkError::Payload(error),
                ) => ParallelThunkPayloadReadyWorkError::Payload(error),
            })?;
        let (result, report) = wait.into_parts();
        let outcome = match result {
            TreeWalkParallelThunkWait::Claimed(guard) => {
                let result = body();
                guard
                    .publish_result(result.clone())
                    .map_err(ParallelThunkPayloadReadyWorkError::Payload)?;
                TreeWalkParallelThunkForceOutcome::Ready(result)
            }
            TreeWalkParallelThunkWait::Ready(result) => {
                TreeWalkParallelThunkForceOutcome::Ready(result)
            }
            TreeWalkParallelThunkWait::SelfCycle { owner } => {
                TreeWalkParallelThunkForceOutcome::SelfCycle { owner }
            }
        };
        Ok(TreeWalkParallelThunkForcePollOutcome {
            outcome,
            report,
            park_preflight,
        })
    }

    /// Claims the thunk, runs advisory ready work, then waits for the result.
    ///
    /// This preserves the generic wait-or-steal contention counters while
    /// exposing evaluator-native `Value`/`TreeWalkError` terminal replay.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if wait-cell synchronization fails
    /// or a terminal state is observed without a matching payload.
    pub fn claim_or_run_ready_then_wait_for_result(
        &self,
        worker: ParallelThunkWorkerId,
        run_ready_work: impl FnMut() -> ParallelThunkReadyWork,
    ) -> Result<TreeWalkParallelThunkWorkWait<'_>, ParallelThunkPayloadError> {
        let wait = self
            .payload_cell
            .claim_or_run_ready_then_wait_for_payload(worker, run_ready_work)?;
        let (result, report) = wait.into_parts();
        Ok(TreeWalkParallelThunkWorkWait {
            result: TreeWalkParallelThunkWait::from_payload_wait(result),
            report,
        })
    }

    /// Claims the thunk, runs fallible ready work, then waits for the result.
    ///
    /// This preserves the generic fallible wait-or-steal error boundary while
    /// exposing evaluator-native `Value`/`TreeWalkError` terminal replay.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadReadyWorkError::Payload`] if wait-cell
    /// synchronization fails or if a terminal state is observed without a
    /// matching payload. Returns
    /// [`ParallelThunkPayloadReadyWorkError::ReadyWork`] if the ready-work hook
    /// fails before the wait-cell path can continue.
    pub fn claim_or_try_run_ready_then_wait_for_result<E>(
        &self,
        worker: ParallelThunkWorkerId,
        run_ready_work: impl FnMut() -> Result<ParallelThunkReadyWork, E>,
    ) -> Result<TreeWalkParallelThunkWorkWait<'_>, ParallelThunkPayloadReadyWorkError<E>> {
        let wait = self
            .payload_cell
            .claim_or_try_run_ready_then_wait_for_payload(worker, run_ready_work)?;
        let (result, report) = wait.into_parts();
        Ok(TreeWalkParallelThunkWorkWait {
            result: TreeWalkParallelThunkWait::from_payload_wait(result),
            report,
        })
    }
}

/// Result of forcing or waiting on a tree-walk parallel thunk body.
#[derive(Clone, Debug)]
pub enum TreeWalkParallelThunkForceOutcome {
    /// The thunk has reached a terminal evaluator result.
    Ready(Result<Value, TreeWalkError>),
    /// Forcing this thunk closes an ownership cycle back to the caller.
    ///
    /// This covers direct same-worker re-entry and, for cells bound to a
    /// shared [`ParallelForceCycleRegistry`], transitive cross-worker wait
    /// cycles detected before parking. The evaluator maps both to its serial
    /// infinite-recursion error.
    SelfCycle {
        /// The worker that owns the claim on the directly awaited thunk.
        owner: ParallelThunkWorkerId,
    },
}

/// Result and contention report from a tree-walk force wait-or-steal call.
#[derive(Clone, Debug)]
pub struct TreeWalkParallelThunkForceWorkOutcome {
    outcome: TreeWalkParallelThunkForceOutcome,
    report: ParallelThunkContentionReport,
}

impl TreeWalkParallelThunkForceWorkOutcome {
    /// Returns the force outcome.
    pub const fn outcome(&self) -> &TreeWalkParallelThunkForceOutcome {
        &self.outcome
    }

    /// Returns the contention-avoidance report.
    pub const fn report(&self) -> ParallelThunkContentionReport {
        self.report
    }

    /// Consumes the outcome into its result and contention report.
    pub fn into_parts(
        self,
    ) -> (
        TreeWalkParallelThunkForceOutcome,
        ParallelThunkContentionReport,
    ) {
        (self.outcome, self.report)
    }
}

/// Result, contention report, and idle preflight from a tree-walk force poll.
#[derive(Clone, Debug)]
pub struct TreeWalkParallelThunkForcePollOutcome {
    outcome: TreeWalkParallelThunkForceOutcome,
    report: ParallelThunkContentionReport,
    park_preflight: Option<ParallelReadyWorkParkPreflight>,
}

impl TreeWalkParallelThunkForcePollOutcome {
    /// Returns the force outcome.
    pub const fn outcome(&self) -> &TreeWalkParallelThunkForceOutcome {
        &self.outcome
    }

    /// Returns the contention-avoidance report.
    pub const fn report(&self) -> ParallelThunkContentionReport {
        self.report
    }

    /// Returns the idle park-preflight snapshot captured before waiting.
    pub const fn park_preflight(&self) -> Option<&ParallelReadyWorkParkPreflight> {
        self.park_preflight.as_ref()
    }

    /// Validates the captured preflight for a registered park attempt.
    ///
    /// Returns `Ok(None)` unless this outcome both registered a waiter and
    /// captured an idle park-preflight snapshot. When both are present, the
    /// snapshot must have been observed by `worker_id` and must still be an
    /// idle snapshot according to
    /// [`ParallelReadyWorkParkPreflight::validate_idle_for_worker`].
    ///
    /// # Errors
    ///
    /// Returns [`ParallelReadyWorkParkReadinessError`] if the captured snapshot
    /// was observed by a different worker or was not idle.
    pub fn registered_park_readiness_for_worker(
        &self,
        worker_id: usize,
    ) -> Result<Option<ParallelReadyWorkParkReadiness>, ParallelReadyWorkParkReadinessError> {
        if !self.report.wait_registered() {
            return Ok(None);
        }

        self.park_preflight
            .as_ref()
            .map(|preflight| preflight.validate_idle_for_worker(worker_id))
            .transpose()
    }

    /// Consumes the outcome into its result, contention report, and preflight.
    pub fn into_parts(
        self,
    ) -> (
        TreeWalkParallelThunkForceOutcome,
        ParallelThunkContentionReport,
        Option<ParallelReadyWorkParkPreflight>,
    ) {
        (self.outcome, self.report, self.park_preflight)
    }
}

/// Result of claiming or waiting on a tree-walk parallel thunk.
#[must_use = "a claimed parallel thunk must be published as a value or error"]
#[derive(Debug)]
pub enum TreeWalkParallelThunkWait<'a> {
    /// The caller owns thunk evaluation and must publish a terminal result.
    Claimed(TreeWalkParallelThunkGuard<'a>),
    /// The thunk has reached a terminal state and the evaluator result is ready.
    Ready(Result<Value, TreeWalkError>),
    /// The same worker re-entered a thunk it already owns.
    SelfCycle {
        /// The worker that owns the recursive force.
        owner: ParallelThunkWorkerId,
    },
}

impl<'a> TreeWalkParallelThunkWait<'a> {
    fn from_payload_wait(wait: ParallelThunkPayloadWait<'a, Value, TreeWalkError>) -> Self {
        match wait {
            ParallelThunkPayloadWait::Claimed(guard) => {
                Self::Claimed(TreeWalkParallelThunkGuard { guard })
            }
            ParallelThunkPayloadWait::Terminal(payload) => Self::Ready(payload.into_result()),
            ParallelThunkPayloadWait::SelfCycle { owner } => Self::SelfCycle { owner },
        }
    }
}

/// Result and contention report from a tree-walk wait-or-steal precursor call.
///
/// This wrapper may carry a worker-affine claim guard and is intentionally not
/// [`Send`]:
///
/// ```compile_fail
/// use ratchet_oracle::eval::TreeWalkParallelThunkWorkWait;
///
/// fn assert_send<T: Send>() {}
///
/// assert_send::<TreeWalkParallelThunkWorkWait<'static>>();
/// ```
#[must_use = "a claimed parallel thunk must be published as a value or error"]
#[derive(Debug)]
pub struct TreeWalkParallelThunkWorkWait<'a> {
    result: TreeWalkParallelThunkWait<'a>,
    report: ParallelThunkContentionReport,
}

impl<'a> TreeWalkParallelThunkWorkWait<'a> {
    /// Returns the claim, terminal result, or self-cycle classification.
    pub const fn result(&self) -> &TreeWalkParallelThunkWait<'a> {
        &self.result
    }

    /// Returns the contention-avoidance report.
    pub const fn report(&self) -> ParallelThunkContentionReport {
        self.report
    }

    /// Consumes the outcome into its result and report.
    pub fn into_parts(self) -> (TreeWalkParallelThunkWait<'a>, ParallelThunkContentionReport) {
        (self.result, self.report)
    }
}

/// A live tree-walk parallel thunk claim.
///
/// The guard is worker-affine and intentionally not [`Send`]:
///
/// ```compile_fail
/// use ratchet_oracle::eval::TreeWalkParallelThunkGuard;
///
/// fn assert_send<T: Send>() {}
///
/// assert_send::<TreeWalkParallelThunkGuard<'static>>();
/// ```
#[must_use = "publish the claimed parallel thunk as a value or error"]
#[derive(Debug)]
pub struct TreeWalkParallelThunkGuard<'a> {
    guard: ParallelThunkPayloadGuard<'a, Value, TreeWalkError>,
}

impl TreeWalkParallelThunkGuard<'_> {
    /// Publishes a tree-walk thunk result and wakes waiters.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if a payload was already stored,
    /// if the guard has already been consumed, or if terminal publication fails.
    pub fn publish_result(
        self,
        result: Result<Value, TreeWalkError>,
    ) -> Result<ParallelThunkPublish, ParallelThunkPayloadError> {
        match result {
            Ok(value) => self.publish_value(value),
            Err(error) => self.publish_error(error),
        }
    }

    /// Publishes a successful tree-walk thunk value and wakes waiters.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if a payload was already stored,
    /// if the guard has already been consumed, or if terminal publication fails.
    pub fn publish_value(
        self,
        value: Value,
    ) -> Result<ParallelThunkPublish, ParallelThunkPayloadError> {
        self.guard.publish_forced(value)
    }

    /// Publishes a failed tree-walk thunk error and wakes waiters.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if a payload was already stored,
    /// if the guard has already been consumed, or if terminal publication fails.
    pub fn publish_error(
        self,
        error: TreeWalkError,
    ) -> Result<ParallelThunkPublish, ParallelThunkPayloadError> {
        self.guard.publish_failed(error)
    }
}
