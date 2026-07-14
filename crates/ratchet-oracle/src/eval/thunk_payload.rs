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

mod tree_walk_cell;
pub use tree_walk_cell::*;

#[cfg(test)]
mod tests;
