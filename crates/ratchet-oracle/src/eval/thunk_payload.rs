//! Forced-value and error payloads for parallel thunk wait cells.
//!
//! This module layers typed terminal payload storage on top of
//! [`super::thunk_wait`]. The underlying wait cell still owns the no-lost-wakeup
//! state transition; this wrapper stores the forced value or captured failure
//! before publishing the terminal state so waiters can re-read the same payload
//! after waking.
//!
//! The payload is cloned for waiters. That keeps this precursor safe and
//! independent of the eventual evaluator value/error ownership model.

use std::sync::{Mutex, MutexGuard, PoisonError};

use thiserror::Error;

use crate::value::Value;

use super::thunk_cas::{ParallelThunkPublish, ParallelThunkTerminalState, ParallelThunkWorkerId};
use super::thunk_wait::{
    ParallelThunkContentionReport, ParallelThunkReadyWork, ParallelThunkWait,
    ParallelThunkWaitCell, ParallelThunkWaitError, ParallelThunkWaitGuard, ParallelThunkWaitStats,
};
use super::tree_walk::TreeWalkError;

/// A terminal payload published by a parallel thunk owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParallelThunkTerminalPayload<T, E> {
    /// The thunk body completed successfully.
    Forced(T),
    /// The thunk body failed and waiters should re-raise the captured error.
    Failed(E),
}

impl<T, E> ParallelThunkTerminalPayload<T, E> {
    /// Returns the terminal state represented by this payload.
    pub const fn terminal_state(&self) -> ParallelThunkTerminalState {
        match self {
            Self::Forced(_) => ParallelThunkTerminalState::Forced,
            Self::Failed(_) => ParallelThunkTerminalState::Failed,
        }
    }

    /// Converts this payload into a standard result.
    ///
    /// # Errors
    ///
    /// Returns the captured error when this payload is
    /// [`ParallelThunkTerminalPayload::Failed`].
    pub fn into_result(self) -> Result<T, E> {
        match self {
            Self::Forced(value) => Ok(value),
            Self::Failed(error) => Err(error),
        }
    }
}

/// A parallel thunk wait cell paired with one terminal payload slot.
#[derive(Debug)]
pub struct ParallelThunkPayloadCell<T: Clone, E: Clone> {
    wait_cell: ParallelThunkWaitCell,
    payload: Mutex<Option<ParallelThunkTerminalPayload<T, E>>>,
    dropped_claim_error: E,
}

impl<T: Clone, E: Clone> ParallelThunkPayloadCell<T, E> {
    /// Creates a suspended payload cell.
    ///
    /// `dropped_claim_error` is published as the captured failure when an owner
    /// guard is dropped without explicitly publishing a forced value or error.
    pub fn new(dropped_claim_error: E) -> Self {
        Self {
            wait_cell: ParallelThunkWaitCell::new(),
            payload: Mutex::new(None),
            dropped_claim_error,
        }
    }

    /// Loads the current thunk state.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError::Wait`] if the underlying wait cell
    /// reports an invalid state word.
    pub fn state(&self) -> Result<ParallelThunkTerminalStatus, ParallelThunkPayloadError> {
        Ok(match self.wait_cell.state()? {
            super::thunk_cas::ParallelThunkState::Suspended => {
                ParallelThunkTerminalStatus::Suspended
            }
            super::thunk_cas::ParallelThunkState::Pending { .. }
            | super::thunk_cas::ParallelThunkState::Awaited { .. } => {
                ParallelThunkTerminalStatus::Claimed
            }
            super::thunk_cas::ParallelThunkState::Forced => ParallelThunkTerminalStatus::Forced,
            super::thunk_cas::ParallelThunkState::Failed => ParallelThunkTerminalStatus::Failed,
        })
    }

    /// Returns waiter/wakeup counters for diagnostics and tests.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError::Wait`] if the underlying waiter
    /// mutex was poisoned while being read.
    pub fn stats(&self) -> Result<ParallelThunkWaitStats, ParallelThunkPayloadError> {
        Ok(self.wait_cell.stats()?)
    }

    /// Returns the currently stored terminal payload, if any.
    ///
    /// The payload mutex recovers from poisoning so terminal payload progress is
    /// preserved after panics in tests or future scheduler glue.
    pub fn terminal_payload(&self) -> Option<ParallelThunkTerminalPayload<T, E>> {
        self.lock_payload().clone()
    }

    /// Claims the thunk, returns the stored terminal payload, or waits for it.
    ///
    /// A successful owner receives a [`ParallelThunkPayloadGuard`] and must call
    /// [`ParallelThunkPayloadGuard::publish_forced`] or
    /// [`ParallelThunkPayloadGuard::publish_failed`]. A foreign waiter blocks
    /// through the underlying wait cell, then reads the payload matching the
    /// observed terminal state.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if the wait-cell synchronization
    /// fails, or if a terminal state is observed without a matching payload.
    pub fn claim_or_wait_for_payload(
        &self,
        worker: ParallelThunkWorkerId,
    ) -> Result<ParallelThunkPayloadWait<'_, T, E>, ParallelThunkPayloadError> {
        let wait = self.wait_cell.claim_or_wait_for_terminal(worker)?;
        self.payload_wait_from_terminal(wait)
    }

    /// Claims the thunk, runs advisory ready work, then waits for the payload.
    ///
    /// This mirrors [`ParallelThunkWaitCell::claim_or_run_ready_then_wait`] and
    /// preserves its contention report while adding payload re-read semantics for
    /// terminal states.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if the wait-cell synchronization
    /// fails, or if a terminal state is observed without a matching payload.
    pub fn claim_or_run_ready_then_wait_for_payload(
        &self,
        worker: ParallelThunkWorkerId,
        run_ready_work: impl FnMut() -> ParallelThunkReadyWork,
    ) -> Result<ParallelThunkPayloadWorkWait<'_, T, E>, ParallelThunkPayloadError> {
        let wait = self
            .wait_cell
            .claim_or_run_ready_then_wait(worker, run_ready_work)?;
        let (result, report) = wait.into_parts();
        Ok(ParallelThunkPayloadWorkWait::new(
            self.payload_wait_from_terminal(result)?,
            report,
        ))
    }

    fn payload_wait_from_terminal<'a>(
        &'a self,
        wait: ParallelThunkWait<'a>,
    ) -> Result<ParallelThunkPayloadWait<'a, T, E>, ParallelThunkPayloadError> {
        match wait {
            ParallelThunkWait::Claimed(guard) => Ok(ParallelThunkPayloadWait::Claimed(
                ParallelThunkPayloadGuard {
                    cell: self,
                    guard: Some(guard),
                },
            )),
            ParallelThunkWait::Terminal(terminal_state) => Ok(ParallelThunkPayloadWait::Terminal(
                self.payload_for_terminal(terminal_state)?,
            )),
            ParallelThunkWait::SelfCycle { owner } => {
                Ok(ParallelThunkPayloadWait::SelfCycle { owner })
            }
        }
    }

    fn payload_for_terminal(
        &self,
        terminal_state: ParallelThunkTerminalState,
    ) -> Result<ParallelThunkTerminalPayload<T, E>, ParallelThunkPayloadError> {
        let Some(payload) = self.lock_payload().clone() else {
            return Err(ParallelThunkPayloadError::MissingTerminalPayload { terminal_state });
        };
        if payload.terminal_state() != terminal_state {
            return Err(ParallelThunkPayloadError::TerminalPayloadMismatch {
                terminal_state,
                payload_state: payload.terminal_state(),
            });
        }
        Ok(payload)
    }

    fn store_terminal_payload(
        &self,
        payload: ParallelThunkTerminalPayload<T, E>,
    ) -> Result<(), ParallelThunkPayloadError> {
        let mut slot = self.lock_payload();
        if let Some(existing) = slot.as_ref() {
            return Err(ParallelThunkPayloadError::PayloadAlreadyStored {
                existing: existing.terminal_state(),
                attempted: payload.terminal_state(),
            });
        }
        *slot = Some(payload);
        Ok(())
    }

    fn store_dropped_claim_failure_if_empty(&self) {
        let mut slot = self.lock_payload();
        if slot.is_none() {
            *slot = Some(ParallelThunkTerminalPayload::Failed(
                self.dropped_claim_error.clone(),
            ));
        }
    }

    fn lock_payload(&self) -> MutexGuard<'_, Option<ParallelThunkTerminalPayload<T, E>>> {
        self.payload.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Coarse terminal status for diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParallelThunkTerminalStatus {
    /// The thunk has not been claimed.
    Suspended,
    /// The thunk is currently owned by a worker.
    Claimed,
    /// The thunk published a forced payload.
    Forced,
    /// The thunk published a failed payload.
    Failed,
}

/// Result of claiming or waiting on a payload-backed parallel thunk.
#[must_use = "a claimed parallel thunk must be published as forced or failed"]
#[derive(Debug)]
pub enum ParallelThunkPayloadWait<'a, T: Clone, E: Clone> {
    /// The caller owns thunk evaluation and must publish a terminal payload.
    Claimed(ParallelThunkPayloadGuard<'a, T, E>),
    /// The thunk has reached a terminal state and the matching payload was read.
    Terminal(ParallelThunkTerminalPayload<T, E>),
    /// The same worker re-entered a thunk it already owns.
    SelfCycle {
        /// The worker that owns the recursive force.
        owner: ParallelThunkWorkerId,
    },
}

/// Result and contention report from a payload wait-or-steal precursor call.
///
/// This wrapper may carry a worker-affine claim guard and is intentionally not
/// [`Send`]:
///
/// ```compile_fail
/// use ratchet_oracle::eval::ParallelThunkPayloadWorkWait;
///
/// fn assert_send<T: Send>() {}
///
/// assert_send::<ParallelThunkPayloadWorkWait<'static, u32, &'static str>>();
/// ```
#[must_use = "a claimed parallel thunk must be published as forced or failed"]
#[derive(Debug)]
pub struct ParallelThunkPayloadWorkWait<'a, T: Clone, E: Clone> {
    result: ParallelThunkPayloadWait<'a, T, E>,
    report: ParallelThunkContentionReport,
}

impl<'a, T: Clone, E: Clone> ParallelThunkPayloadWorkWait<'a, T, E> {
    fn new(
        result: ParallelThunkPayloadWait<'a, T, E>,
        report: ParallelThunkContentionReport,
    ) -> Self {
        Self { result, report }
    }

    /// Returns the claim, terminal payload, or self-cycle classification.
    pub const fn result(&self) -> &ParallelThunkPayloadWait<'a, T, E> {
        &self.result
    }

    /// Returns the contention-avoidance report.
    pub const fn report(&self) -> ParallelThunkContentionReport {
        self.report
    }

    /// Consumes the outcome into its result and report.
    pub fn into_parts(
        self,
    ) -> (
        ParallelThunkPayloadWait<'a, T, E>,
        ParallelThunkContentionReport,
    ) {
        (self.result, self.report)
    }
}

/// A live payload-backed thunk claim.
///
/// The guard remains worker-affine because the wrapped wait-cell claim guard is
/// not [`Send`]:
///
/// ```compile_fail
/// use ratchet_oracle::eval::ParallelThunkPayloadGuard;
///
/// fn assert_send<T: Send>() {}
///
/// assert_send::<ParallelThunkPayloadGuard<'static, u32, &'static str>>();
/// ```
#[must_use = "publish the claimed parallel thunk as forced or failed"]
#[derive(Debug)]
pub struct ParallelThunkPayloadGuard<'a, T: Clone, E: Clone> {
    cell: &'a ParallelThunkPayloadCell<T, E>,
    guard: Option<ParallelThunkWaitGuard<'a>>,
}

impl<T: Clone, E: Clone> ParallelThunkPayloadGuard<'_, T, E> {
    /// Publishes a successful thunk payload and wakes registered waiters.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if a payload was already stored,
    /// if the claim guard has already been consumed, or if the underlying wait
    /// cell rejects terminal publication.
    pub fn publish_forced(
        mut self,
        value: T,
    ) -> Result<ParallelThunkPublish, ParallelThunkPayloadError> {
        self.cell
            .store_terminal_payload(ParallelThunkTerminalPayload::Forced(value))?;
        let guard = self.take_guard()?;
        Ok(guard.publish_forced()?)
    }

    /// Publishes a failed thunk payload and wakes registered waiters.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if a payload was already stored,
    /// if the claim guard has already been consumed, or if the underlying wait
    /// cell rejects terminal publication.
    pub fn publish_failed(
        mut self,
        error: E,
    ) -> Result<ParallelThunkPublish, ParallelThunkPayloadError> {
        self.cell
            .store_terminal_payload(ParallelThunkTerminalPayload::Failed(error))?;
        let guard = self.take_guard()?;
        Ok(guard.publish_failed()?)
    }

    fn take_guard(&mut self) -> Result<ParallelThunkWaitGuard<'_>, ParallelThunkPayloadError> {
        self.guard
            .take()
            .ok_or(ParallelThunkPayloadError::ClaimGuardMissing)
    }
}

impl<T: Clone, E: Clone> Drop for ParallelThunkPayloadGuard<'_, T, E> {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            self.cell.store_dropped_claim_failure_if_empty();
            drop(guard);
        }
    }
}

/// A failure while claiming, waiting for, or publishing a payload-backed thunk.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParallelThunkPayloadError {
    /// The underlying wait-cell operation failed.
    #[error(transparent)]
    Wait(#[from] ParallelThunkWaitError),
    /// A terminal state was observed before a payload was available.
    #[error("parallel thunk reached {terminal_state:?} without a terminal payload")]
    MissingTerminalPayload {
        /// The terminal state observed through the wait cell.
        terminal_state: ParallelThunkTerminalState,
    },
    /// The stored payload did not match the observed terminal state.
    #[error("parallel thunk reached {terminal_state:?} but stored {payload_state:?} payload")]
    TerminalPayloadMismatch {
        /// The terminal state observed through the wait cell.
        terminal_state: ParallelThunkTerminalState,
        /// The terminal state represented by the stored payload.
        payload_state: ParallelThunkTerminalState,
    },
    /// A publisher tried to overwrite an existing terminal payload.
    #[error("parallel thunk payload already stored as {existing:?}, cannot store {attempted:?}")]
    PayloadAlreadyStored {
        /// The terminal state represented by the existing payload.
        existing: ParallelThunkTerminalState,
        /// The terminal state represented by the attempted payload.
        attempted: ParallelThunkTerminalState,
    },
    /// A payload guard was consumed more than once.
    #[error("parallel thunk payload claim guard is missing")]
    ClaimGuardMissing,
}

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
        Self {
            payload_cell: ParallelThunkPayloadCell::new(dropped_claim_error),
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

    use crate::{compile::ir::IrId, syntax::Span, value::Value};

    use super::super::tree_walk::{TreeWalkError, TreeWalkErrorKind};
    use super::*;

    fn worker(raw: u64) -> ParallelThunkWorkerId {
        ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
    }

    fn wait_until_registered<T: Clone, E: Clone>(
        cell: &ParallelThunkPayloadCell<T, E>,
        expected: usize,
    ) {
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

    fn terminal_payload<T: Clone, E: Clone>(
        wait: ParallelThunkPayloadWait<'_, T, E>,
    ) -> ParallelThunkTerminalPayload<T, E> {
        match wait {
            ParallelThunkPayloadWait::Terminal(payload) => payload,
            ParallelThunkPayloadWait::Claimed(_) => {
                panic!("expected terminal payload, found claim guard");
            }
            ParallelThunkPayloadWait::SelfCycle { owner } => {
                panic!("expected terminal payload, found self-cycle owned by {owner:?}");
            }
        }
    }

    fn tree_walk_error(raw: u32) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::DivisionByZero { id: IrId::new(raw) },
            Span::new(raw, raw.saturating_add(1)),
        )
    }

    fn ready_result(wait: TreeWalkParallelThunkWait<'_>) -> Result<Value, TreeWalkError> {
        match wait {
            TreeWalkParallelThunkWait::Ready(result) => result,
            TreeWalkParallelThunkWait::Claimed(_) => {
                panic!("expected ready tree-walk result, found claim guard");
            }
            TreeWalkParallelThunkWait::SelfCycle { owner } => {
                panic!("expected ready tree-walk result, found self-cycle owned by {owner:?}");
            }
        }
    }

    fn self_cycle_owner(wait: TreeWalkParallelThunkWait<'_>) -> ParallelThunkWorkerId {
        match wait {
            TreeWalkParallelThunkWait::SelfCycle { owner } => owner,
            TreeWalkParallelThunkWait::Ready(_) => {
                panic!("expected tree-walk self-cycle, found ready result");
            }
            TreeWalkParallelThunkWait::Claimed(_) => {
                panic!("expected tree-walk self-cycle, found claim guard");
            }
        }
    }

    fn claimed_guard(wait: TreeWalkParallelThunkWait<'_>) -> TreeWalkParallelThunkGuard<'_> {
        match wait {
            TreeWalkParallelThunkWait::Claimed(guard) => guard,
            TreeWalkParallelThunkWait::Ready(_) => {
                panic!("expected claimed tree-walk thunk, found ready result");
            }
            TreeWalkParallelThunkWait::SelfCycle { owner } => {
                panic!("expected claimed tree-walk thunk, found self-cycle owned by {owner:?}");
            }
        }
    }

    #[test]
    fn forced_payload_wakes_waiter_and_replays_to_later_claims() {
        let cell = Arc::new(ParallelThunkPayloadCell::<u32, &str>::new("dropped"));
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = mpsc::channel();

        let owner_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            let publish_ready = Arc::clone(&publish_ready);
            thread::spawn(move || {
                let ParallelThunkPayloadWait::Claimed(guard) = cell
                    .claim_or_wait_for_payload(worker(1))
                    .expect("owner claims")
                else {
                    panic!("owner should claim suspended payload cell");
                };
                owner_ready.wait();
                publish_ready.wait();
                guard.publish_forced(55).expect("owner publishes forced");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let result = cell
                    .claim_or_wait_for_payload(worker(2))
                    .expect("waiter observes payload");
                let ParallelThunkPayloadWait::Terminal(payload) = result else {
                    panic!("waiter should observe a terminal payload");
                };
                result_tx.send(payload).expect("payload send succeeds");
            })
        };

        owner_ready.wait();
        wait_until_registered(&cell, 1);
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));

        publish_ready.wait();
        let payload = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");

        assert_eq!(payload, ParallelThunkTerminalPayload::Forced(55));
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
        assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Forced));
        assert_eq!(
            terminal_payload(
                cell.claim_or_wait_for_payload(worker(3))
                    .expect("later claimant reads payload")
            ),
            ParallelThunkTerminalPayload::Forced(55)
        );
    }

    #[test]
    fn failed_payload_wakes_waiter_and_replays_to_later_claims() {
        let cell = Arc::new(ParallelThunkPayloadCell::<u32, &str>::new("dropped"));
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = mpsc::channel();

        let owner_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            let publish_ready = Arc::clone(&publish_ready);
            thread::spawn(move || {
                let ParallelThunkPayloadWait::Claimed(guard) = cell
                    .claim_or_wait_for_payload(worker(1))
                    .expect("owner claims")
                else {
                    panic!("owner should claim suspended payload cell");
                };
                owner_ready.wait();
                publish_ready.wait();
                guard
                    .publish_failed("boom")
                    .expect("owner publishes failure");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let result = cell
                    .claim_or_wait_for_payload(worker(2))
                    .expect("waiter observes payload");
                let ParallelThunkPayloadWait::Terminal(payload) = result else {
                    panic!("waiter should observe a terminal payload");
                };
                result_tx.send(payload).expect("payload send succeeds");
            })
        };

        owner_ready.wait();
        wait_until_registered(&cell, 1);
        publish_ready.wait();
        let payload = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");

        assert_eq!(payload, ParallelThunkTerminalPayload::Failed("boom"));
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
        assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
        assert_eq!(
            terminal_payload(
                cell.claim_or_wait_for_payload(worker(3))
                    .expect("later claimant reads payload")
            ),
            ParallelThunkTerminalPayload::Failed("boom")
        );
    }

    #[test]
    fn dropped_claim_publishes_configured_failure_payload() {
        let cell = ParallelThunkPayloadCell::<u32, &str>::new("dropped");

        {
            let ParallelThunkPayloadWait::Claimed(_guard) = cell
                .claim_or_wait_for_payload(worker(1))
                .expect("owner claims")
            else {
                panic!("owner should claim suspended payload cell");
            };
        }

        assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
        assert_eq!(
            cell.terminal_payload(),
            Some(ParallelThunkTerminalPayload::Failed("dropped"))
        );
        assert_eq!(
            terminal_payload(
                cell.claim_or_wait_for_payload(worker(2))
                    .expect("later claimant reads drop failure")
            ),
            ParallelThunkTerminalPayload::Failed("dropped")
        );
    }

    #[test]
    fn dropped_claim_wakes_registered_waiter_with_configured_failure_payload() {
        let cell = Arc::new(ParallelThunkPayloadCell::<u32, &str>::new("dropped"));
        let owner_ready = Arc::new(Barrier::new(3));
        let drop_ready = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = mpsc::channel();

        let owner_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            let drop_ready = Arc::clone(&drop_ready);
            thread::spawn(move || {
                let ParallelThunkPayloadWait::Claimed(guard) = cell
                    .claim_or_wait_for_payload(worker(1))
                    .expect("owner claims")
                else {
                    panic!("owner should claim suspended payload cell");
                };
                owner_ready.wait();
                drop_ready.wait();
                drop(guard);
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let payload = terminal_payload(
                    cell.claim_or_wait_for_payload(worker(2))
                        .expect("waiter observes drop failure"),
                );
                result_tx.send(payload).expect("payload send succeeds");
            })
        };

        owner_ready.wait();
        wait_until_registered(&cell, 1);
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));

        drop_ready.wait();
        let payload = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");

        assert_eq!(payload, ParallelThunkTerminalPayload::Failed("dropped"));
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
        assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));

        let stats = cell.stats().expect("stats are readable");
        assert_eq!(stats.wait_registrations(), 1);
        assert_eq!(stats.notifications(), 1);
    }

    #[test]
    fn ready_work_path_returns_payload_and_contention_report() {
        let cell = ParallelThunkPayloadCell::new("dropped");
        let ParallelThunkPayloadWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_payload(worker(1))
            .expect("owner claims")
        else {
            panic!("owner should claim suspended payload cell");
        };
        let mut owner_guard = Some(owner_guard);
        let mut step = 0usize;

        let outcome = cell
            .claim_or_run_ready_then_wait_for_payload(worker(2), || {
                step = step.saturating_add(1);
                match step {
                    1 => ParallelThunkReadyWork::RanLocal,
                    2 => {
                        owner_guard
                            .take()
                            .expect("owner guard remains available")
                            .publish_forced(99)
                            .expect("owner publishes during ready work");
                        ParallelThunkReadyWork::StolePeer
                    }
                    _ => ParallelThunkReadyWork::Idle,
                }
            })
            .expect("wait-or-steal payload path completes");

        let (result, report) = outcome.into_parts();
        assert_eq!(
            terminal_payload(result),
            ParallelThunkTerminalPayload::Forced(99)
        );
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
        let stats = cell.stats().expect("stats are readable");
        assert_eq!(stats.wait_registrations(), 0);
        assert_eq!(stats.notifications(), 0);
    }

    #[test]
    fn tree_walk_parallel_thunk_replays_forced_values_as_ok_results() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );

        guard
            .publish_value(Value::int(42))
            .expect("owner publishes value");

        let later = ready_result(
            cell.claim_or_wait_for_result(worker(2))
                .expect("later worker reads terminal value"),
        )
        .expect("forced value replays as Ok");

        assert_eq!(later.as_int(), Ok(42));
        assert_eq!(
            cell.terminal_result()
                .expect("terminal result is stored")
                .expect("stored result is Ok")
                .as_int(),
            Ok(42)
        );
        assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Forced));
    }

    #[test]
    fn tree_walk_parallel_thunk_forced_value_wakes_blocked_waiter() {
        let cell = Arc::new(TreeWalkParallelThunkCell::new(tree_walk_error(99)));
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = mpsc::channel();

        let owner_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            let publish_ready = Arc::clone(&publish_ready);
            thread::spawn(move || {
                let guard = claimed_guard(
                    cell.claim_or_wait_for_result(worker(1))
                        .expect("owner claims tree-walk thunk"),
                );
                owner_ready.wait();
                publish_ready.wait();
                guard
                    .publish_value(Value::int(123))
                    .expect("owner publishes tree-walk value");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let result = ready_result(
                    cell.claim_or_wait_for_result(worker(2))
                        .expect("waiter observes tree-walk value"),
                );
                result_tx.send(result).expect("result send succeeds");
            })
        };

        owner_ready.wait();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if cell
                .stats()
                .expect("stats are readable")
                .wait_registrations()
                >= 1
            {
                break;
            }
            thread::yield_now();
        }
        assert_eq!(
            cell.stats()
                .expect("stats are readable")
                .wait_registrations(),
            1
        );
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));

        publish_ready.wait();
        let result = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes")
            .expect("forced value replays as Ok");

        assert_eq!(result.as_int(), Ok(123));
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
        let stats = cell.stats().expect("stats are readable");
        assert_eq!(stats.wait_registrations(), 1);
        assert_eq!(stats.notifications(), 1);
    }

    #[test]
    fn tree_walk_parallel_thunk_replays_failures_as_err_results() {
        let expected = tree_walk_error(7);
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );

        guard
            .publish_error(expected.clone())
            .expect("owner publishes error");

        let later = ready_result(
            cell.claim_or_wait_for_result(worker(2))
                .expect("later worker reads terminal error"),
        )
        .expect_err("failed thunk replays as Err");

        assert_eq!(later, expected);
        assert_eq!(
            cell.terminal_result()
                .expect("terminal result is stored")
                .expect_err("stored result is Err"),
            expected
        );
        assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
    }

    #[test]
    fn tree_walk_parallel_thunk_publish_result_routes_ok_and_err() {
        let ok_cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        claimed_guard(
            ok_cell
                .claim_or_wait_for_result(worker(1))
                .expect("owner claims ok tree-walk thunk"),
        )
        .publish_result(Ok(Value::int(64)))
        .expect("owner publishes ok result");
        assert_eq!(
            ready_result(
                ok_cell
                    .claim_or_wait_for_result(worker(2))
                    .expect("later worker reads ok result")
            )
            .expect("stored result is ok")
            .as_int(),
            Ok(64)
        );

        let err_cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let expected = tree_walk_error(21);
        claimed_guard(
            err_cell
                .claim_or_wait_for_result(worker(1))
                .expect("owner claims err tree-walk thunk"),
        )
        .publish_result(Err(expected.clone()))
        .expect("owner publishes err result");
        assert_eq!(
            ready_result(
                err_cell
                    .claim_or_wait_for_result(worker(2))
                    .expect("later worker reads err result")
            )
            .expect_err("stored result is err"),
            expected
        );
    }

    #[test]
    fn tree_walk_parallel_thunk_preserves_self_cycle_classification() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let _guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );

        assert_eq!(
            self_cycle_owner(
                cell.claim_or_wait_for_result(worker(1))
                    .expect("same worker sees self-cycle")
            ),
            worker(1)
        );
        assert!(cell.terminal_result().is_none());
    }

    #[test]
    fn tree_walk_parallel_thunk_drop_publishes_configured_error() {
        let dropped = tree_walk_error(13);
        let cell = TreeWalkParallelThunkCell::new(dropped.clone());

        {
            let _guard = claimed_guard(
                cell.claim_or_wait_for_result(worker(1))
                    .expect("owner claims tree-walk thunk"),
            );
        }

        assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
        assert_eq!(
            cell.terminal_result()
                .expect("terminal result is stored")
                .expect_err("drop failure replays as Err"),
            dropped
        );
    }

    #[test]
    fn tree_walk_parallel_thunk_ready_work_preserves_contention_report() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let mut owner_guard = Some(owner_guard);
        let mut step = 0usize;

        let outcome = cell
            .claim_or_run_ready_then_wait_for_result(worker(2), || {
                step = step.saturating_add(1);
                match step {
                    1 => ParallelThunkReadyWork::RanLocal,
                    2 => {
                        owner_guard
                            .take()
                            .expect("owner guard remains available")
                            .publish_value(Value::int(77))
                            .expect("owner publishes during ready work");
                        ParallelThunkReadyWork::StolePeer
                    }
                    _ => ParallelThunkReadyWork::Idle,
                }
            })
            .expect("wait-or-steal tree-walk path completes");

        let (result, report) = outcome.into_parts();
        assert_eq!(
            ready_result(result)
                .expect("forced value replays as Ok")
                .as_int(),
            Ok(77)
        );
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
    }
}
