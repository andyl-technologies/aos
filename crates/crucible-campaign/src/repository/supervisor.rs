//! Bounded single-host orchestration of one planner and local executor.
//!
//! The supervisor is an operational owner over the repository-backed planner
//! and executor drivers. Each call performs at most one component operation.
//! Durable lifecycle state is reloaded before every call, so restart constructs
//! a fresh supervisor without recovering volatile cursors or reservations.

use std::sync::Arc;

use super::*;
use crate::{
    ActiveAttemptPolicy, CampaignName, ExecutorControlService, ExecutorResumeService,
    PlannerService,
};

/// Maximum worker slots coordinated by one campaign supervisor.
pub const MAX_CAMPAIGN_SUPERVISOR_WORKER_SLOTS: u32 = 256;

/// Single-host coordinator over one campaign planner and local executor.
pub struct CampaignSupervisor<P, E> {
    repository: Arc<CampaignRepository>,
    campaign: CampaignName,
    planner: CampaignPlannerDriver<P>,
    executor: CampaignExecutorDriver<E>,
    worker_slots: u32,
    next_worker_slot: u32,
    planner_pending: bool,
}

impl<P, E> CampaignSupervisor<P, E> {
    /// Composes drivers sharing one exact repository instance.
    ///
    /// The worker-slot count is fixed for this supervisor incarnation and may
    /// not exceed the executor driver's reservation ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignSupervisorConfigError`] when the drivers do not share
    /// the supplied repository or the worker-slot count is zero, exceeds 256,
    /// or exceeds the executor reservation ceiling.
    pub fn new(
        repository: Arc<CampaignRepository>,
        campaign: CampaignName,
        planner: CampaignPlannerDriver<P>,
        executor: CampaignExecutorDriver<E>,
        worker_slots: u32,
    ) -> Result<Self, CampaignSupervisorConfigError> {
        if !Arc::ptr_eq(&repository, planner.repository())
            || !Arc::ptr_eq(&repository, executor.repository())
        {
            return Err(CampaignSupervisorConfigError::RepositoryMismatch);
        }
        if worker_slots == 0 {
            return Err(CampaignSupervisorConfigError::ZeroWorkerSlots);
        }
        if worker_slots > MAX_CAMPAIGN_SUPERVISOR_WORKER_SLOTS {
            return Err(CampaignSupervisorConfigError::TooManyWorkerSlots);
        }
        let worker_slots_usize = usize::try_from(worker_slots)
            .map_err(|_| CampaignSupervisorConfigError::TooManyWorkerSlots)?;
        if worker_slots_usize > executor.maximum_reservations() {
            return Err(CampaignSupervisorConfigError::WorkerSlotsExceedReservations);
        }
        Ok(Self {
            repository,
            campaign,
            planner,
            executor,
            worker_slots,
            next_worker_slot: 0,
            planner_pending: false,
        })
    }

    /// Advances the campaign by at most one checked component operation.
    ///
    /// Running campaigns poll or reserve executor work first. Only an executor
    /// scan that proves one slot has no unreserved claimable attempt enables a
    /// subsequent planner call, bounding the ready-attempt buffer to one. A
    /// paused `Drain` continues polling already accepted work but creates no new
    /// reservation. `CancelAndRetry` cancels or releases one held reservation
    /// per call. `ExactCheckpoint` never silently degrades to either behavior:
    /// while work remains it returns an explicit checkpoint-required outcome
    /// until the checkpoint owner is composed.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignSupervisorError::Repository`] when lifecycle intent
    /// cannot be authenticated, [`CampaignSupervisorError::Planner`] for one
    /// planner-driver failure, or [`CampaignSupervisorError::Executor`] for one
    /// executor-driver failure.
    pub fn step(
        &mut self,
    ) -> Result<CampaignSupervisorStepOutcome, CampaignSupervisorError<P::Error, E::Error>>
    where
        P: PlannerService,
        E: ExecutorControlService + ExecutorResumeService,
    {
        let (head, lifecycle) = self
            .repository
            .head_with_lifecycle(self.campaign.as_str())?;
        if lifecycle.state() == CampaignState::Running {
            return self.step_running();
        }

        self.planner_pending = false;
        let policy = lifecycle
            .active_attempt_policy()
            .unwrap_or(ActiveAttemptPolicy::Drain);
        match policy {
            ActiveAttemptPolicy::CancelAndRetry => {
                if self.executor.reservation_count() == 0 {
                    return Ok(CampaignSupervisorStepOutcome::Inactive {
                        snapshot: head.snapshot_id(),
                        lifecycle,
                    });
                }
                let outcome = self
                    .executor
                    .cancel_one(self.campaign.as_str())
                    .map_err(CampaignSupervisorError::Executor)?;
                Ok(CampaignSupervisorStepOutcome::Cancellation(outcome))
            }
            ActiveAttemptPolicy::Drain => {
                let Some(worker_slot) = self.executor.first_drain_worker_slot() else {
                    return Ok(CampaignSupervisorStepOutcome::Inactive {
                        snapshot: head.snapshot_id(),
                        lifecycle,
                    });
                };
                let outcome = self
                    .executor
                    .step(self.campaign.as_str(), worker_slot)
                    .map_err(CampaignSupervisorError::Executor)?;
                Ok(CampaignSupervisorStepOutcome::Executor {
                    worker_slot,
                    outcome,
                })
            }
            ActiveAttemptPolicy::ExactCheckpoint => {
                if self.executor.reservation_count() == 0 {
                    Ok(CampaignSupervisorStepOutcome::Inactive {
                        snapshot: head.snapshot_id(),
                        lifecycle,
                    })
                } else {
                    let outcome = self
                        .executor
                        .checkpoint_one(self.campaign.as_str())
                        .map_err(CampaignSupervisorError::Executor)?;
                    Ok(CampaignSupervisorStepOutcome::Checkpoint(outcome))
                }
            }
        }
    }

    /// Returns the number of volatile attempt reservations currently held.
    #[must_use]
    pub fn reservation_count(&self) -> usize {
        self.executor.reservation_count()
    }

    /// Returns the fixed worker-slot count for this supervisor incarnation.
    #[must_use]
    pub const fn worker_slots(&self) -> u32 {
        self.worker_slots
    }

    /// Consumes the supervisor and returns its component drivers.
    #[must_use]
    pub fn into_drivers(self) -> (CampaignPlannerDriver<P>, CampaignExecutorDriver<E>) {
        (self.planner, self.executor)
    }

    fn step_running(
        &mut self,
    ) -> Result<CampaignSupervisorStepOutcome, CampaignSupervisorError<P::Error, E::Error>>
    where
        P: PlannerService,
        E: ExecutorControlService + ExecutorResumeService,
    {
        if self.planner_pending {
            self.planner_pending = false;
            let outcome = self
                .planner
                .step(self.campaign.as_str())
                .map_err(CampaignSupervisorError::Planner)?;
            return Ok(CampaignSupervisorStepOutcome::Planner(outcome));
        }

        let worker_slot = self.take_worker_slot();
        let outcome = self
            .executor
            .step(self.campaign.as_str(), worker_slot)
            .map_err(CampaignSupervisorError::Executor)?;
        if matches!(outcome, CampaignExecutorStepOutcome::Idle { .. }) {
            if let Some(attempt) = self
                .repository
                .admit_initial_discovery_if_ready(self.campaign.as_str())?
            {
                return Ok(CampaignSupervisorStepOutcome::InitialDiscovery { attempt });
            }
            self.planner_pending = true;
        }
        Ok(CampaignSupervisorStepOutcome::Executor {
            worker_slot,
            outcome,
        })
    }

    fn take_worker_slot(&mut self) -> WorkerSlotId {
        let slot = WorkerSlotId::new(self.next_worker_slot);
        self.next_worker_slot = (self.next_worker_slot + 1) % self.worker_slots;
        slot
    }
}

/// Invalid static composition for a campaign supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CampaignSupervisorConfigError {
    /// The supplied drivers do not share the supervisor's repository instance.
    #[error("campaign supervisor drivers use another repository instance")]
    RepositoryMismatch,
    /// A supervisor was configured without a worker slot.
    #[error("campaign supervisor worker-slot count must be nonzero")]
    ZeroWorkerSlots,
    /// A supervisor was configured above the fixed 256-slot bound.
    #[error("campaign supervisor worker-slot count exceeds 256")]
    TooManyWorkerSlots,
    /// More worker slots were configured than the executor driver can reserve.
    #[error("campaign supervisor worker slots exceed executor reservation capacity")]
    WorkerSlotsExceedReservations,
}

/// One bounded single-host coordinator transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignSupervisorStepOutcome {
    /// The first budgeted genesis discovery was admitted durably.
    InitialDiscovery {
        /// Immutable discovery attempt, ready for normal executor reservation.
        attempt: AttemptId,
    },
    /// Durable lifecycle state currently prevents new planning or reservation.
    Inactive {
        /// Exact snapshot owning the lifecycle intent.
        snapshot: CampaignSnapshotId,
        /// Complete authenticated lifecycle intent.
        lifecycle: CampaignLifecycle,
    },
    /// One planner-driver transition was attempted.
    Planner(CampaignPlannerStepOutcome),
    /// One executor slot was advanced.
    Executor {
        /// Process-local slot selected for this step.
        worker_slot: WorkerSlotId,
        /// Checked executor-driver outcome.
        outcome: CampaignExecutorStepOutcome,
    },
    /// One held reservation was released, canceled, or completed.
    Cancellation(CampaignExecutorCancelOutcome),
    /// One exact-checkpoint request or status transition was performed.
    Checkpoint(CampaignExecutorCheckpointOutcome),
}

/// Failure while advancing one campaign supervisor step.
#[derive(Debug, thiserror::Error)]
pub enum CampaignSupervisorError<P, E> {
    /// Durable lifecycle intent could not be authenticated.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// The bounded planner driver failed.
    #[error("campaign planner driver failed")]
    Planner(CampaignPlannerDriverError<P>),
    /// The bounded executor driver failed.
    #[error("campaign executor driver failed")]
    Executor(CampaignExecutorDriverError<E>),
}
