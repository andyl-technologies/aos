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

use std::{
    convert::Infallible,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use thiserror::Error;

use crate::value::Value;

use super::parallel::{
    ParallelChaseLevReadyWorkQueue, ParallelReadyWorkParkPreflight, ParallelReadyWorkParkReadiness,
    ParallelReadyWorkParkReadinessError, ParallelReadyWorkPoll,
};
use super::thunk_cas::{ParallelThunkPublish, ParallelThunkTerminalState, ParallelThunkWorkerId};
use super::thunk_registry::ParallelForceCycleRegistry;
use super::thunk_wait::{
    ParallelThunkContentionReport, ParallelThunkReadyWork, ParallelThunkReadyWorkWaitError,
    ParallelThunkWait, ParallelThunkWaitCell, ParallelThunkWaitError, ParallelThunkWaitGuard,
    ParallelThunkWaitStats,
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
        Self::with_cycle_registry(dropped_claim_error, None)
    }

    /// Creates a suspended payload cell bound to a shared cycle registry.
    ///
    /// Every cell of one shared demand graph must be bound to the same
    /// registry instance so cross-worker wait cycles are detected before a
    /// waiter parks. See the `thunk_registry` module docs.
    pub fn with_cycle_registry(
        dropped_claim_error: E,
        cycle_registry: Option<Arc<ParallelForceCycleRegistry>>,
    ) -> Self {
        Self {
            wait_cell: ParallelThunkWaitCell::with_cycle_registry(cycle_registry),
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

    /// Returns the terminal payload matching the current terminal state.
    ///
    /// Suspended and claimed cells return `Ok(None)`. Forced and failed cells
    /// must carry the matching payload before the terminal state can be replayed.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if wait-cell synchronization fails
    /// or if a terminal state is missing its matching payload.
    pub(crate) fn checked_terminal_payload(
        &self,
    ) -> Result<Option<ParallelThunkTerminalPayload<T, E>>, ParallelThunkPayloadError> {
        Ok(match self.state()? {
            ParallelThunkTerminalStatus::Suspended | ParallelThunkTerminalStatus::Claimed => None,
            ParallelThunkTerminalStatus::Forced => {
                Some(self.payload_for_terminal(ParallelThunkTerminalState::Forced)?)
            }
            ParallelThunkTerminalStatus::Failed => {
                Some(self.payload_for_terminal(ParallelThunkTerminalState::Failed)?)
            }
        })
    }

    /// Returns the forced terminal payload value, if the cell is forced.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if the wait-cell synchronization
    /// fails, or if a forced terminal state is observed without a matching
    /// forced payload.
    pub(crate) fn forced_payload_value(&self) -> Result<Option<T>, ParallelThunkPayloadError> {
        if self.state()? != ParallelThunkTerminalStatus::Forced {
            return Ok(None);
        }
        let ParallelThunkTerminalPayload::Forced(value) =
            self.payload_for_terminal(ParallelThunkTerminalState::Forced)?
        else {
            return Err(ParallelThunkPayloadError::TerminalPayloadMismatch {
                terminal_state: ParallelThunkTerminalState::Forced,
                payload_state: ParallelThunkTerminalState::Failed,
            });
        };
        Ok(Some(value))
    }

    /// Clones this payload cell for a relocating heap writeback.
    ///
    /// Claimed cells are rejected because the relocation snapshot cannot safely
    /// transfer live waiter ownership. Suspended and terminal cells are rebuilt
    /// with fresh synchronization storage and the same terminal payload, when
    /// present.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if the cell is currently claimed,
    /// if the wait-cell synchronization fails, or if a terminal state is
    /// observed without a matching terminal payload.
    pub(crate) fn clone_for_relocation(&self) -> Result<Self, ParallelThunkPayloadError> {
        match self.state()? {
            ParallelThunkTerminalStatus::Suspended => Ok(Self::with_cycle_registry(
                self.dropped_claim_error.clone(),
                self.wait_cell.cycle_registry().cloned(),
            )),
            ParallelThunkTerminalStatus::Claimed => Err(
                ParallelThunkPayloadError::RelocationRequiresIdleOrTerminalPayload {
                    status: ParallelThunkTerminalStatus::Claimed,
                },
            ),
            ParallelThunkTerminalStatus::Forced => {
                let ParallelThunkTerminalPayload::Forced(value) =
                    self.payload_for_terminal(ParallelThunkTerminalState::Forced)?
                else {
                    return Err(ParallelThunkPayloadError::TerminalPayloadMismatch {
                        terminal_state: ParallelThunkTerminalState::Forced,
                        payload_state: ParallelThunkTerminalState::Failed,
                    });
                };
                Ok(Self::forced_for_relocation(
                    value,
                    self.dropped_claim_error.clone(),
                ))
            }
            ParallelThunkTerminalStatus::Failed => {
                let ParallelThunkTerminalPayload::Failed(error) =
                    self.payload_for_terminal(ParallelThunkTerminalState::Failed)?
                else {
                    return Err(ParallelThunkPayloadError::TerminalPayloadMismatch {
                        terminal_state: ParallelThunkTerminalState::Failed,
                        payload_state: ParallelThunkTerminalState::Forced,
                    });
                };
                Ok(Self::failed_for_relocation(
                    error,
                    self.dropped_claim_error.clone(),
                ))
            }
        }
    }

    /// Rebuilds this forced payload cell with a relocated forced value.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadError`] if the cell is not forced, if the
    /// wait-cell synchronization fails, or if the forced state is missing its
    /// terminal forced payload.
    pub(crate) fn relocated_forced_payload(
        &self,
        value: T,
    ) -> Result<Self, ParallelThunkPayloadError> {
        let status = self.state()?;
        if status != ParallelThunkTerminalStatus::Forced {
            return Err(ParallelThunkPayloadError::RelocationRequiresForcedPayload { status });
        }
        self.payload_for_terminal(ParallelThunkTerminalState::Forced)?;
        Ok(Self::forced_for_relocation(
            value,
            self.dropped_claim_error.clone(),
        ))
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

    /// Claims the thunk, runs fallible ready work, then waits for the payload.
    ///
    /// This mirrors
    /// [`ParallelThunkWaitCell::claim_or_try_run_ready_then_wait`] and preserves
    /// its wait-or-steal ordering while adding typed terminal payload re-read
    /// semantics.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkPayloadReadyWorkError::Payload`] if wait-cell
    /// synchronization fails or if a terminal state is observed without a
    /// matching payload. Returns
    /// [`ParallelThunkPayloadReadyWorkError::ReadyWork`] if the ready-work hook
    /// fails before the wait-cell path can continue.
    pub fn claim_or_try_run_ready_then_wait_for_payload<R>(
        &self,
        worker: ParallelThunkWorkerId,
        run_ready_work: impl FnMut() -> Result<ParallelThunkReadyWork, R>,
    ) -> Result<ParallelThunkPayloadWorkWait<'_, T, E>, ParallelThunkPayloadReadyWorkError<R>> {
        let wait = self
            .wait_cell
            .claim_or_try_run_ready_then_wait(worker, run_ready_work)
            .map_err(ParallelThunkPayloadReadyWorkError::from_wait_error)?;
        let (result, report) = wait.into_parts();
        Ok(ParallelThunkPayloadWorkWait::new(
            self.payload_wait_from_terminal(result)
                .map_err(ParallelThunkPayloadReadyWorkError::Payload)?,
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

    fn forced_for_relocation(value: T, dropped_claim_error: E) -> Self {
        Self {
            wait_cell: ParallelThunkWaitCell::forced_for_relocation(None),
            payload: Mutex::new(Some(ParallelThunkTerminalPayload::Forced(value))),
            dropped_claim_error,
        }
    }

    fn failed_for_relocation(error: E, dropped_claim_error: E) -> Self {
        Self {
            wait_cell: ParallelThunkWaitCell::failed_for_relocation(None),
            payload: Mutex::new(Some(ParallelThunkTerminalPayload::Failed(error))),
            dropped_claim_error,
        }
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

/// A failure while running a fallible ready-work hook before payload replay.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParallelThunkPayloadReadyWorkError<E> {
    /// The underlying payload-backed wait-cell or park-readiness operation failed.
    #[error(transparent)]
    Payload(#[from] ParallelThunkPayloadError),
    /// The ready-work hook failed before payload replay could continue.
    #[error("parallel thunk payload ready-work hook failed")]
    ReadyWork(#[source] E),
}

impl<E> ParallelThunkPayloadReadyWorkError<E> {
    fn from_wait_error(error: ParallelThunkReadyWorkWaitError<E>) -> Self {
        match error {
            ParallelThunkReadyWorkWaitError::Wait(error) => Self::Payload(error.into()),
            ParallelThunkReadyWorkWaitError::ReadyWork(error) => Self::ReadyWork(error),
        }
    }
}

/// A failure while claiming, waiting for, validating, or publishing a payload-backed thunk.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParallelThunkPayloadError {
    /// The underlying wait-cell operation failed.
    #[error(transparent)]
    Wait(#[from] ParallelThunkWaitError),
    /// An idle ready-work poll did not carry a valid park-readiness snapshot.
    #[error(transparent)]
    ParkReadiness(#[from] ParallelReadyWorkParkReadinessError),
    /// The nonzero thunk worker id cannot be represented as a ready-work queue id.
    #[error("parallel thunk worker {worker:?} cannot be represented as a ready-work queue id")]
    ReadyWorkWorkerIdOutOfRange {
        /// The worker id that could not be converted to a zero-based queue id.
        worker: ParallelThunkWorkerId,
    },
    /// The thunk worker and ready-work queue belong to different workers.
    #[error(
        "parallel thunk worker {worker:?} maps to ready-work queue {expected_queue_worker}, got queue {queue_worker}"
    )]
    ReadyWorkQueueWorkerMismatch {
        /// The thunk worker id supplied to the force or wait call.
        worker: ParallelThunkWorkerId,
        /// The zero-based ready-work queue id expected for `worker`.
        expected_queue_worker: usize,
        /// The zero-based ready-work queue id supplied by the Chase-Lev handle.
        queue_worker: usize,
    },
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
    /// Payload relocation needs a suspended or terminal cell, not a live claim.
    #[error("parallel thunk payload relocation requires an idle or terminal cell, got {status:?}")]
    RelocationRequiresIdleOrTerminalPayload {
        /// The status observed before relocation.
        status: ParallelThunkTerminalStatus,
    },
    /// Forced-payload relocation needs an existing forced terminal payload.
    #[error("parallel thunk payload relocation requires a forced payload, got {status:?}")]
    RelocationRequiresForcedPayload {
        /// The status observed before forced-payload relocation.
        status: ParallelThunkTerminalStatus,
    },
}

enum TreeWalkParallelThunkPollReadyWorkError<E> {
    ReadyWork(E),
    Payload(ParallelThunkPayloadError),
}

fn ready_work_queue_worker_id(
    worker: ParallelThunkWorkerId,
) -> Result<usize, ParallelThunkPayloadError> {
    usize::try_from(worker.get() - 1)
        .map_err(|_| ParallelThunkPayloadError::ReadyWorkWorkerIdOutOfRange { worker })
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

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroUsize,
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            mpsc::{self, RecvTimeoutError},
        },
        thread,
        time::{Duration, Instant},
    };

    use crate::{compile::ir::IrId, syntax::Span, value::Value};

    use super::super::parallel::{
        parallel_chase_lev_ready_work_queues, parallel_ready_work_queues,
    };
    use super::super::tree_walk::{TreeWalkError, TreeWalkErrorKind};
    use super::*;

    fn worker(raw: u64) -> ParallelThunkWorkerId {
        ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
    }

    fn workers(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("test worker count is nonzero")
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

    fn ready_force_outcome(
        outcome: TreeWalkParallelThunkForceOutcome,
    ) -> Result<Value, TreeWalkError> {
        match outcome {
            TreeWalkParallelThunkForceOutcome::Ready(result) => result,
            TreeWalkParallelThunkForceOutcome::SelfCycle { owner } => {
                panic!(
                    "expected ready tree-walk force result, found self-cycle owned by {owner:?}"
                );
            }
        }
    }

    fn force_self_cycle_owner(outcome: TreeWalkParallelThunkForceOutcome) -> ParallelThunkWorkerId {
        match outcome {
            TreeWalkParallelThunkForceOutcome::SelfCycle { owner } => owner,
            TreeWalkParallelThunkForceOutcome::Ready(_) => {
                panic!("expected tree-walk force self-cycle, found ready result");
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
    fn payload_fallible_ready_work_error_returns_before_wait_registration() {
        let cell = ParallelThunkPayloadCell::new("dropped");
        let ParallelThunkPayloadWait::Claimed(owner_guard) = cell
            .claim_or_wait_for_payload(worker(1))
            .expect("owner claims")
        else {
            panic!("owner should claim suspended payload cell");
        };
        let mut step = 0usize;

        let error = cell
            .claim_or_try_run_ready_then_wait_for_payload(worker(2), || {
                step = step.saturating_add(1);
                match step {
                    1 => Ok(ParallelThunkReadyWork::RanLocal),
                    _ => Err("queue failed"),
                }
            })
            .expect_err("ready-work error is returned");

        assert_eq!(
            error,
            ParallelThunkPayloadReadyWorkError::ReadyWork("queue failed")
        );
        assert_eq!(step, 2);
        let stats = cell.stats().expect("stats are readable");
        assert_eq!(stats.wait_registrations(), 0);
        assert_eq!(stats.notifications(), 0);

        owner_guard
            .publish_forced(123)
            .expect("owner can publish after ready-work error");
        assert_eq!(
            terminal_payload(
                cell.claim_or_wait_for_payload(worker(3))
                    .expect("later claimant reads payload")
            ),
            ParallelThunkTerminalPayload::Forced(123)
        );
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
    fn tree_walk_parallel_thunk_force_body_runs_once_and_wakes_waiter() {
        let cell = Arc::new(TreeWalkParallelThunkCell::new(tree_walk_error(99)));
        let body_runs = Arc::new(AtomicUsize::new(0));
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (owner_tx, owner_rx) = mpsc::channel();
        let (waiter_tx, waiter_rx) = mpsc::channel();

        let owner_thread = {
            let cell = Arc::clone(&cell);
            let body_runs = Arc::clone(&body_runs);
            let owner_ready = Arc::clone(&owner_ready);
            let publish_ready = Arc::clone(&publish_ready);
            thread::spawn(move || {
                let outcome = cell
                    .force_or_wait_with(worker(1), || {
                        body_runs.fetch_add(1, AtomicOrdering::SeqCst);
                        owner_ready.wait();
                        publish_ready.wait();
                        Ok(Value::int(144))
                    })
                    .expect("owner forces tree-walk thunk body");
                owner_tx
                    .send(ready_force_outcome(outcome))
                    .expect("owner result send succeeds");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let outcome = cell
                    .force_or_wait_with(worker(2), || {
                        panic!("waiter must not evaluate the claimed thunk body");
                    })
                    .expect("waiter observes owner result");
                waiter_tx
                    .send(ready_force_outcome(outcome))
                    .expect("waiter result send succeeds");
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
            waiter_rx.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));

        publish_ready.wait();
        let owner_result = owner_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("owner returns")
            .expect("owner result is Ok");
        let waiter_result = waiter_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes")
            .expect("waiter result is Ok");

        assert_eq!(owner_result.as_int(), Ok(144));
        assert_eq!(waiter_result.as_int(), Ok(144));
        assert_eq!(body_runs.load(AtomicOrdering::SeqCst), 1);
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
    }

    #[test]
    fn tree_walk_parallel_thunk_force_body_publishes_error_result() {
        let expected = tree_walk_error(31);
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));

        let owner_result = ready_force_outcome(
            cell.force_or_wait_with(worker(1), || Err(expected.clone()))
                .expect("owner publishes body error"),
        )
        .expect_err("owner sees body error");
        assert_eq!(owner_result, expected);

        let later_result = ready_force_outcome(
            cell.force_or_wait_with(worker(2), || {
                panic!("later worker must not re-run failed body");
            })
            .expect("later worker replays body error"),
        )
        .expect_err("later worker sees body error");
        assert_eq!(later_result, expected);
        assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
    }

    #[test]
    fn tree_walk_parallel_thunk_force_body_preserves_self_cycle() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let _guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );

        let outcome = cell
            .force_or_wait_with(worker(1), || {
                panic!("self-cycle must not evaluate the thunk body");
            })
            .expect("self-cycle is classified");

        assert_eq!(force_self_cycle_owner(outcome), worker(1));
        assert!(cell.terminal_result().is_none());
    }

    #[test]
    fn tree_walk_parallel_thunk_force_ready_path_claim_owner_runs_body_without_ready_work() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));

        let outcome = cell
            .force_or_run_ready_then_wait_with(
                worker(1),
                || {
                    panic!("ready work should not run when this worker claims the thunk");
                },
                || Ok(Value::int(188)),
            )
            .expect("claim owner forces through ready path");

        let (result, report) = outcome.into_parts();
        assert_eq!(
            ready_force_outcome(result)
                .expect("claim owner result is Ok")
                .as_int(),
            Ok(188)
        );
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(!report.wait_registered());
    }

    #[test]
    fn tree_walk_parallel_thunk_force_ready_path_runs_ready_work_before_replay() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let mut owner_guard = Some(owner_guard);
        let mut step = 0usize;

        let outcome = cell
            .force_or_run_ready_then_wait_with(
                worker(2),
                || {
                    step = step.saturating_add(1);
                    match step {
                        1 => ParallelThunkReadyWork::RanLocal,
                        2 => {
                            owner_guard
                                .take()
                                .expect("owner guard remains available")
                                .publish_value(Value::int(233))
                                .expect("owner publishes during ready work");
                            ParallelThunkReadyWork::StolePeer
                        }
                        _ => ParallelThunkReadyWork::Idle,
                    }
                },
                || {
                    panic!("waiting worker must not evaluate the claimed thunk body");
                },
            )
            .expect("ready-work force path completes");

        let (result, report) = outcome.into_parts();
        assert_eq!(
            ready_force_outcome(result)
                .expect("replayed result is Ok")
                .as_int(),
            Ok(233)
        );
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
    }

    #[test]
    fn tree_walk_parallel_thunk_force_poll_path_claim_owner_runs_body_without_polling() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));

        let outcome = cell
            .force_or_poll_ready_then_wait_with::<()>(
                worker(1),
                || {
                    panic!("ready-work poll should not run when this worker claims the thunk");
                },
                || Ok(Value::int(258)),
            )
            .expect("claim owner forces through poll path");

        let (result, report, preflight) = outcome.into_parts();
        assert_eq!(
            ready_force_outcome(result)
                .expect("claim owner result is Ok")
                .as_int(),
            Ok(258)
        );
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(!report.wait_registered());
        assert!(preflight.is_none());
    }

    #[test]
    fn tree_walk_parallel_thunk_force_poll_path_captures_idle_preflight_before_replay() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let mut owner_guard = Some(owner_guard);
        let queues = parallel_ready_work_queues([10, 20], workers(2));
        let mut ran = Vec::new();

        let outcome = cell
            .force_or_poll_ready_then_wait_with(
                worker(2),
                || {
                    let poll = queues
                        .run_next_or_park_preflight(1, |value| ran.push(value))
                        .expect("ready-work poll succeeds");
                    if poll.ready_work() == ParallelThunkReadyWork::Idle {
                        owner_guard
                            .take()
                            .expect("owner guard remains available")
                            .publish_value(Value::int(1597))
                            .expect("owner publishes after idle preflight");
                    }
                    poll
                },
                || {
                    panic!("waiting worker must not evaluate the claimed thunk body");
                },
            )
            .expect("poll force path completes");

        assert!(
            outcome
                .registered_park_readiness_for_worker(1)
                .expect("captured replay preflight validates when checked")
                .is_none()
        );
        let (result, report, preflight) = outcome.into_parts();
        assert_eq!(
            ready_force_outcome(result)
                .expect("replayed result is Ok")
                .as_int(),
            Ok(1597)
        );
        let preflight = preflight.expect("idle preflight is captured");
        assert_eq!(ran, vec![20, 10]);
        assert_eq!(preflight.observing_worker(), 1);
        assert_eq!(preflight.ready_task_count(), 0);
        assert!(preflight.is_idle());
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
    }

    #[test]
    fn tree_walk_parallel_thunk_chase_lev_ready_path_claim_owner_runs_body_without_polling() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let worker_queues =
            parallel_chase_lev_ready_work_queues([10, 20], workers(2)).into_worker_queues();
        let mut ran = Vec::new();

        let outcome = cell
            .force_or_chase_lev_ready_then_wait_with(
                worker(2),
                &worker_queues[1],
                |value| ran.push(value),
                || Ok(Value::int(34)),
            )
            .expect("claim owner forces through Chase-Lev bridge");

        let (result, report, preflight) = outcome.into_parts();
        assert_eq!(
            ready_force_outcome(result)
                .expect("claim owner result is Ok")
                .as_int(),
            Ok(34)
        );
        assert!(ran.is_empty());
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(!report.wait_registered());
        assert!(preflight.is_none());
    }

    #[test]
    fn tree_walk_parallel_thunk_chase_lev_ready_path_runs_local_and_stolen_before_replay() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let mut owner_guard = Some(owner_guard);
        let worker_queues =
            parallel_chase_lev_ready_work_queues([10, 20], workers(2)).into_worker_queues();
        let mut ran = Vec::new();

        let outcome = cell
            .force_or_chase_lev_ready_then_wait_with(
                worker(2),
                &worker_queues[1],
                |value| {
                    ran.push(value);
                    if ran.len() == 2 {
                        owner_guard
                            .take()
                            .expect("owner guard remains available")
                            .publish_value(Value::int(55))
                            .expect("owner publishes during stolen ready work");
                    }
                },
                || {
                    panic!("waiting worker must not evaluate the claimed thunk body");
                },
            )
            .expect("Chase-Lev ready-work force path completes");
        let (result, report, preflight) = outcome.into_parts();
        assert_eq!(
            ready_force_outcome(result)
                .expect("replayed result is Ok")
                .as_int(),
            Ok(55)
        );
        assert_eq!(ran, vec![20, 10]);
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
        assert!(preflight.is_none());
    }

    #[test]
    fn tree_walk_parallel_thunk_chase_lev_ready_path_rechecks_after_one_local_task() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let mut owner_guard = Some(owner_guard);
        let worker_queues =
            parallel_chase_lev_ready_work_queues([10, 20], workers(2)).into_worker_queues();
        let mut ran = Vec::new();

        let outcome = cell
            .force_or_chase_lev_ready_then_wait_with(
                worker(2),
                &worker_queues[1],
                |value| {
                    ran.push(value);
                    owner_guard
                        .take()
                        .expect("owner guard remains available")
                        .publish_value(Value::int(144))
                        .expect("owner publishes during local ready work");
                },
                || {
                    panic!("waiting worker must not evaluate the claimed thunk body");
                },
            )
            .expect("Chase-Lev ready-work force path completes after one local task");
        let (result, report, preflight) = outcome.into_parts();
        assert_eq!(
            ready_force_outcome(result)
                .expect("replayed result is Ok")
                .as_int(),
            Ok(144)
        );
        assert_eq!(ran, vec![20]);
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(!report.wait_registered());
        assert!(preflight.is_none());
    }

    #[test]
    fn tree_walk_parallel_thunk_chase_lev_ready_path_captures_preflight_before_blocking_wait() {
        let cell = Arc::new(TreeWalkParallelThunkCell::new(tree_walk_error(99)));
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (waiter_tx, waiter_rx) = mpsc::channel();

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
                    .publish_value(Value::int(89))
                    .expect("owner publishes tree-walk value");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                let worker_queues =
                    parallel_chase_lev_ready_work_queues(std::iter::empty::<usize>(), workers(2))
                        .into_worker_queues();
                owner_ready.wait();
                let outcome = cell
                    .force_or_chase_lev_ready_then_wait_with(
                        worker(2),
                        &worker_queues[1],
                        |value| value,
                        || {
                            panic!("waiting worker must not evaluate the claimed thunk body");
                        },
                    )
                    .expect("waiter observes owner result");
                let readiness = outcome
                    .registered_park_readiness_for_worker(1)
                    .expect("registered park preflight validates")
                    .expect("waiter registration has a park readiness");
                let (result, report, preflight) = outcome.into_parts();
                waiter_tx
                    .send((ready_force_outcome(result), report, preflight, readiness))
                    .expect("waiter result send succeeds");
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
            waiter_rx.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));

        publish_ready.wait();
        let (result, report, preflight, readiness) = waiter_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");
        let value = result.expect("waiter result is Ok");
        let preflight = preflight.expect("idle preflight is captured before blocking");
        assert_eq!(value.as_int(), Ok(89));
        assert_eq!(readiness.preflight(), &preflight);
        assert_eq!(readiness.observing_worker(), 1);
        assert_eq!(readiness.ready_task_count(), 0);
        assert_eq!(preflight.observing_worker(), 1);
        assert_eq!(preflight.ready_task_count(), 0);
        assert!(preflight.is_idle());
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(report.wait_registered());
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
    }

    #[test]
    fn tree_walk_parallel_thunk_chase_lev_ready_path_rejects_queue_worker_mismatch() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let worker_queues =
            parallel_chase_lev_ready_work_queues([10, 20], workers(2)).into_worker_queues();
        let before = worker_queues[0].park_preflight_snapshot();
        let mut ready_work_ran = false;
        let mut body_ran = false;

        let error = cell
            .force_or_chase_lev_ready_then_wait_with(
                worker(2),
                &worker_queues[0],
                |value| {
                    ready_work_ran = true;
                    value
                },
                || {
                    body_ran = true;
                    Ok(Value::int(144))
                },
            )
            .expect_err("worker/queue mismatch is rejected");

        assert_eq!(
            error,
            ParallelThunkPayloadError::ReadyWorkQueueWorkerMismatch {
                worker: worker(2),
                expected_queue_worker: 1,
                queue_worker: 0
            }
        );
        assert!(!ready_work_ran);
        assert!(!body_ran);
        let after = worker_queues[0].park_preflight_snapshot();
        assert_eq!(after.queue_lengths(), before.queue_lengths());
        assert_eq!(after.ready_task_count(), before.ready_task_count());
        let stats = cell.stats().expect("stats are readable");
        assert_eq!(stats.wait_registrations(), 0);
        assert_eq!(stats.notifications(), 0);

        owner_guard
            .publish_value(Value::int(233))
            .expect("owner can publish after rejected mismatch");
    }

    #[test]
    fn tree_walk_parallel_thunk_chase_lev_ready_path_rejects_mismatch_before_claiming_suspended() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let worker_queues =
            parallel_chase_lev_ready_work_queues([10, 20], workers(2)).into_worker_queues();
        let before = worker_queues[0].park_preflight_snapshot();
        let mut ready_work_ran = false;
        let mut body_ran = false;

        let error = cell
            .force_or_chase_lev_ready_then_wait_with(
                worker(2),
                &worker_queues[0],
                |value| {
                    ready_work_ran = true;
                    value
                },
                || {
                    body_ran = true;
                    Ok(Value::int(377))
                },
            )
            .expect_err("worker/queue mismatch is rejected before claim");

        assert_eq!(
            error,
            ParallelThunkPayloadError::ReadyWorkQueueWorkerMismatch {
                worker: worker(2),
                expected_queue_worker: 1,
                queue_worker: 0
            }
        );
        assert!(!ready_work_ran);
        assert!(!body_ran);
        let after = worker_queues[0].park_preflight_snapshot();
        assert_eq!(after.queue_lengths(), before.queue_lengths());
        assert_eq!(after.ready_task_count(), before.ready_task_count());
        let stats = cell.stats().expect("stats are readable");
        assert_eq!(stats.wait_registrations(), 0);
        assert_eq!(stats.notifications(), 0);
        assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Suspended));
    }

    #[test]
    fn tree_walk_parallel_thunk_force_poll_path_captures_preflight_before_blocking_wait() {
        let cell = Arc::new(TreeWalkParallelThunkCell::new(tree_walk_error(99)));
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (waiter_tx, waiter_rx) = mpsc::channel();

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
                    .publish_value(Value::int(4181))
                    .expect("owner publishes tree-walk value");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));
                owner_ready.wait();
                let outcome = cell
                    .force_or_poll_ready_then_wait_with(
                        worker(2),
                        || {
                            queues
                                .run_next_or_park_preflight(1, |value| value)
                                .expect("idle preflight poll succeeds")
                        },
                        || {
                            panic!("waiting worker must not evaluate the claimed thunk body");
                        },
                    )
                    .expect("waiter observes owner result");
                let readiness = outcome
                    .registered_park_readiness_for_worker(1)
                    .expect("registered park preflight validates")
                    .expect("waiter registration has a park readiness");
                let (result, report, preflight) = outcome.into_parts();
                waiter_tx
                    .send((ready_force_outcome(result), report, preflight, readiness))
                    .expect("waiter result send succeeds");
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
            waiter_rx.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));

        publish_ready.wait();
        let (result, report, preflight, readiness) = waiter_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");
        let value = result.expect("waiter result is Ok");
        let preflight = preflight.expect("idle preflight is captured before blocking");
        assert_eq!(value.as_int(), Ok(4181));
        assert_eq!(readiness.preflight(), &preflight);
        assert_eq!(readiness.observing_worker(), 1);
        assert_eq!(readiness.ready_task_count(), 0);
        assert_eq!(preflight.observing_worker(), 1);
        assert_eq!(preflight.ready_task_count(), 0);
        assert!(preflight.is_idle());
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(report.wait_registered());
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
    }

    #[test]
    fn tree_walk_parallel_thunk_force_poll_path_replays_body_error() {
        let expected = tree_walk_error(43);
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));

        let owner = cell
            .force_or_poll_ready_then_wait_with::<()>(
                worker(1),
                || {
                    panic!("claim owner should not poll ready work");
                },
                || Err(expected.clone()),
            )
            .expect("owner publishes body error");
        assert_eq!(
            ready_force_outcome(owner.outcome().clone()).expect_err("owner sees body error"),
            expected
        );
        assert_eq!(owner.report().local_work_runs(), 0);
        assert_eq!(owner.report().stolen_work_runs(), 0);
        assert!(!owner.report().wait_registered());
        assert!(owner.park_preflight().is_none());

        let later = cell
            .force_or_poll_ready_then_wait_with::<()>(
                worker(2),
                || {
                    panic!("terminal replay should not poll ready work");
                },
                || {
                    panic!("terminal replay should not run body");
                },
            )
            .expect("later worker replays body error");
        assert_eq!(
            ready_force_outcome(later.outcome().clone()).expect_err("later sees body error"),
            expected
        );
        assert_eq!(later.report().local_work_runs(), 0);
        assert_eq!(later.report().stolen_work_runs(), 0);
        assert!(!later.report().wait_registered());
        assert!(later.park_preflight().is_none());
        assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
    }

    #[test]
    fn tree_walk_parallel_thunk_force_poll_path_rejects_non_idle_preflight_before_wait() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let queues = parallel_ready_work_queues([10], workers(2));
        let snapshot = queues
            .park_preflight_snapshot(1)
            .expect("non-idle preflight snapshot succeeds");

        let error = cell
            .force_or_poll_ready_then_wait_with(
                worker(2),
                || ParallelReadyWorkPoll::<()>::Idle(snapshot.clone()),
                || {
                    panic!("waiting worker must not evaluate the claimed thunk body");
                },
            )
            .expect_err("non-idle preflight is rejected");

        assert_eq!(
            error,
            ParallelThunkPayloadError::ParkReadiness(
                ParallelReadyWorkParkReadinessError::ReadyWorkRemaining {
                    ready_task_count: 1
                }
            )
        );
        let stats = cell.stats().expect("stats are readable");
        assert_eq!(stats.wait_registrations(), 0);
        assert_eq!(stats.notifications(), 0);

        owner_guard
            .publish_value(Value::int(6765))
            .expect("owner can publish after rejected preflight");
        assert_eq!(
            ready_result(
                cell.claim_or_wait_for_result(worker(3))
                    .expect("later worker reads terminal value")
            )
            .expect("later value replays as Ok")
            .as_int(),
            Ok(6765)
        );
    }

    #[test]
    fn tree_walk_parallel_thunk_try_poll_path_rejects_wrong_worker_preflight_before_wait() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));
        let snapshot = queues
            .park_preflight_snapshot(0)
            .expect("idle preflight snapshot succeeds");

        let error = cell
            .force_or_try_poll_ready_then_wait_with(
                worker(2),
                || {
                    Ok::<_, super::super::parallel::ParallelReadyWorkError>(
                        ParallelReadyWorkPoll::<()>::Idle(snapshot.clone()),
                    )
                },
                || {
                    panic!("waiting worker must not evaluate the claimed thunk body");
                },
            )
            .expect_err("wrong-worker preflight is rejected");

        assert_eq!(
            error,
            ParallelThunkPayloadReadyWorkError::Payload(ParallelThunkPayloadError::ParkReadiness(
                ParallelReadyWorkParkReadinessError::ObservingWorkerMismatch {
                    expected_worker: 1,
                    observed_worker: 0
                }
            ))
        );
        let stats = cell.stats().expect("stats are readable");
        assert_eq!(stats.wait_registrations(), 0);
        assert_eq!(stats.notifications(), 0);

        owner_guard
            .publish_value(Value::int(10946))
            .expect("owner can publish after rejected preflight");
        assert_eq!(
            ready_result(
                cell.claim_or_wait_for_result(worker(3))
                    .expect("later worker reads terminal value")
            )
            .expect("later value replays as Ok")
            .as_int(),
            Ok(10946)
        );
    }

    #[test]
    fn tree_walk_parallel_thunk_try_ready_work_error_returns_before_wait_registration() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let mut step = 0usize;

        let error = cell
            .claim_or_try_run_ready_then_wait_for_result(worker(2), || {
                step = step.saturating_add(1);
                match step {
                    1 => Ok(ParallelThunkReadyWork::RanLocal),
                    _ => Err("scheduler failed"),
                }
            })
            .expect_err("ready-work error is returned");

        assert_eq!(
            error,
            ParallelThunkPayloadReadyWorkError::ReadyWork("scheduler failed")
        );
        assert_eq!(step, 2);
        let stats = cell.stats().expect("stats are readable");
        assert_eq!(stats.wait_registrations(), 0);
        assert_eq!(stats.notifications(), 0);

        owner_guard
            .publish_value(Value::int(610))
            .expect("owner can publish after ready-work error");
        assert_eq!(
            ready_result(
                cell.claim_or_wait_for_result(worker(3))
                    .expect("later worker reads terminal value")
            )
            .expect("later value replays as Ok")
            .as_int(),
            Ok(610)
        );
    }

    #[test]
    fn tree_walk_parallel_thunk_try_poll_path_propagates_scheduler_queue_error() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let queues = parallel_ready_work_queues([10], workers(1));

        let error = cell
            .force_or_try_poll_ready_then_wait_with(
                worker(2),
                || queues.run_next_or_park_preflight(1, |value| value),
                || {
                    panic!("waiting worker must not evaluate the claimed thunk body");
                },
            )
            .expect_err("scheduler queue error is propagated");

        assert_eq!(
            error,
            ParallelThunkPayloadReadyWorkError::ReadyWork(
                super::super::parallel::ParallelReadyWorkError::WorkerQueueMissing { worker_id: 1 }
            )
        );
        let stats = cell.stats().expect("stats are readable");
        assert_eq!(stats.wait_registrations(), 0);
        assert_eq!(stats.notifications(), 0);

        owner_guard
            .publish_value(Value::int(987))
            .expect("owner can publish after scheduler queue error");
        assert_eq!(
            ready_result(
                cell.claim_or_wait_for_result(worker(3))
                    .expect("later worker reads terminal value")
            )
            .expect("later value replays as Ok")
            .as_int(),
            Ok(987)
        );
    }

    #[test]
    fn tree_walk_parallel_thunk_try_poll_path_captures_preflight_before_replay() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let owner_guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
        let mut owner_guard = Some(owner_guard);
        let queues = parallel_ready_work_queues([10, 20], workers(2));
        let mut ran = Vec::new();

        let outcome = cell
            .force_or_try_poll_ready_then_wait_with(
                worker(2),
                || {
                    let poll = queues.run_next_or_park_preflight(1, |value| ran.push(value))?;
                    if poll.ready_work() == ParallelThunkReadyWork::Idle {
                        owner_guard
                            .take()
                            .expect("owner guard remains available")
                            .publish_value(Value::int(2584))
                            .expect("owner publishes after idle preflight");
                    }
                    Ok::<_, super::super::parallel::ParallelReadyWorkError>(poll)
                },
                || {
                    panic!("waiting worker must not evaluate the claimed thunk body");
                },
            )
            .expect("fallible poll force path completes");

        let (result, report, preflight) = outcome.into_parts();
        assert_eq!(
            ready_force_outcome(result)
                .expect("replayed result is Ok")
                .as_int(),
            Ok(2584)
        );
        let preflight = preflight.expect("idle preflight is captured");
        assert_eq!(ran, vec![20, 10]);
        assert_eq!(preflight.observing_worker(), 1);
        assert_eq!(preflight.ready_task_count(), 0);
        assert!(preflight.is_idle());
        assert_eq!(report.local_work_runs(), 1);
        assert_eq!(report.stolen_work_runs(), 1);
        assert!(!report.wait_registered());
    }

    #[test]
    fn tree_walk_parallel_thunk_force_ready_path_reports_blocking_waiter_registration() {
        let cell = Arc::new(TreeWalkParallelThunkCell::new(tree_walk_error(99)));
        let owner_ready = Arc::new(Barrier::new(3));
        let publish_ready = Arc::new(Barrier::new(2));
        let (waiter_tx, waiter_rx) = mpsc::channel();

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
                    .publish_value(Value::int(377))
                    .expect("owner publishes tree-walk value");
            })
        };

        let waiter_thread = {
            let cell = Arc::clone(&cell);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                owner_ready.wait();
                let outcome = cell
                    .force_or_run_ready_then_wait_with(
                        worker(2),
                        || ParallelThunkReadyWork::Idle,
                        || {
                            panic!("waiting worker must not evaluate the claimed thunk body");
                        },
                    )
                    .expect("waiter observes owner result");
                let (result, report) = outcome.into_parts();
                waiter_tx
                    .send((ready_force_outcome(result), report))
                    .expect("waiter result send succeeds");
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
            waiter_rx.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));

        publish_ready.wait();
        let (result, report) = waiter_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter wakes");
        let value = result.expect("waiter result is Ok");
        assert_eq!(value.as_int(), Ok(377));
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(report.wait_registered());
        owner_thread.join().expect("owner joins");
        waiter_thread.join().expect("waiter joins");
    }

    #[test]
    fn tree_walk_parallel_thunk_force_ready_path_replays_body_error() {
        let expected = tree_walk_error(41);
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));

        let owner = cell
            .force_or_run_ready_then_wait_with(
                worker(1),
                || {
                    panic!("claim owner should not run ready work");
                },
                || Err(expected.clone()),
            )
            .expect("owner publishes body error");
        assert_eq!(
            ready_force_outcome(owner.outcome().clone()).expect_err("owner sees body error"),
            expected
        );
        assert_eq!(owner.report().local_work_runs(), 0);

        let later = cell
            .force_or_run_ready_then_wait_with(
                worker(2),
                || {
                    panic!("terminal replay should not run ready work");
                },
                || {
                    panic!("terminal replay should not run body");
                },
            )
            .expect("later worker replays body error");
        assert_eq!(
            ready_force_outcome(later.outcome().clone()).expect_err("later sees body error"),
            expected
        );
        assert_eq!(later.report().local_work_runs(), 0);
        assert_eq!(later.report().stolen_work_runs(), 0);
        assert!(!later.report().wait_registered());
    }

    #[test]
    fn tree_walk_parallel_thunk_force_ready_path_preserves_self_cycle() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let _guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );

        let outcome = cell
            .force_or_run_ready_then_wait_with(
                worker(1),
                || {
                    panic!("self-cycle should not run ready work");
                },
                || {
                    panic!("self-cycle should not run body");
                },
            )
            .expect("self-cycle is classified");

        let (result, report) = outcome.into_parts();
        assert_eq!(force_self_cycle_owner(result), worker(1));
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(!report.wait_registered());
    }

    #[test]
    fn tree_walk_parallel_thunk_force_poll_path_preserves_self_cycle_without_polling() {
        let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
        let _guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );

        let outcome = cell
            .force_or_poll_ready_then_wait_with::<()>(
                worker(1),
                || {
                    panic!("self-cycle should not poll ready work");
                },
                || {
                    panic!("self-cycle should not run body");
                },
            )
            .expect("self-cycle is classified");

        let (result, report, preflight) = outcome.into_parts();
        assert_eq!(force_self_cycle_owner(result), worker(1));
        assert_eq!(report.local_work_runs(), 0);
        assert_eq!(report.stolen_work_runs(), 0);
        assert!(!report.wait_registered());
        assert!(preflight.is_none());
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
