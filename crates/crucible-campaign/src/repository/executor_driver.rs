//! Bounded coordinator handoff from claimable attempts to one local executor.
//!
//! The driver owns only volatile reservations and scan continuation. Campaign
//! attempts, completions, and non-modeled terminal dispositions remain
//! authoritative repository records, so restart discards this object and
//! rebuilds safely from the current snapshot.

use std::sync::Arc;

use super::*;
use crate::{
    AssignmentId, AttemptResourceLimits, ExecutionId, ExecutionRetentionIntent, ExecutorClient,
    ExecutorClientError, ExecutorRejection, ExecutorStatusService, GetAttemptExecutionDisposition,
    GetAttemptExecutionRequest,
};

/// Coordinator-owned bounded driver for one local executor component.
pub struct CampaignExecutorDriver<S> {
    repository: Arc<CampaignRepository>,
    executor: ExecutorClient<S>,
    queue: AttemptQueue,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
    scan_limit: usize,
    cursor: Option<AttemptQueueCursor>,
    settled_snapshot: Option<CampaignSnapshotId>,
    active_executions: BTreeMap<WorkerSlotId, ActiveExecutionPoll>,
}

#[derive(Clone)]
struct ActiveExecutionPoll {
    reservation: AttemptReservation,
    request: SubmitAttemptRequest,
    execution: ExecutionId,
}

impl<S> CampaignExecutorDriver<S> {
    /// Builds an empty restart-rebuildable assignment driver.
    ///
    /// # Errors
    ///
    /// Returns an error when reservation capacity is zero or the accounting
    /// scan bound is outside `1..=10,000`.
    pub fn new(
        repository: Arc<CampaignRepository>,
        executor: ExecutorClient<S>,
        daemon_epoch: DaemonEpoch,
        maximum_reservations: usize,
        resources: AttemptResourceLimits,
        retention: ExecutionRetentionIntent,
        scan_limit: usize,
    ) -> Result<Self, CampaignExecutorDriverConfigError> {
        if scan_limit == 0 || scan_limit > MAX_ATTEMPT_QUEUE_SCAN_PAGE_ITEMS {
            return Err(CampaignExecutorDriverConfigError::InvalidScanLimit);
        }
        Ok(Self {
            repository,
            executor,
            queue: AttemptQueue::new(daemon_epoch, maximum_reservations)?,
            resources,
            retention,
            scan_limit,
            cursor: None,
            settled_snapshot: None,
            active_executions: BTreeMap::new(),
        })
    }

    /// Advances one worker slot by at most one scan page and one executor call.
    ///
    /// New work is reserved only while the campaign is running. A reservation
    /// already handed to the executor is still polled while paused so drain
    /// policy can complete. The executor call occurs without repository
    /// mutation ownership; a concurrent head advance therefore produces an
    /// ordinary stale incorporation retry rather than blocking the owner.
    ///
    /// Transient backpressure and unavailable input release the lease so the
    /// next scan obtains the fresh assignment identity required by the executor
    /// protocol. A checked `Accepted` or `AlreadyRunning` response installs one
    /// bounded read-only status poll; later calls do not create assignment
    /// records. A transport or validation error retains the exact execution
    /// query for commit-indeterminate replay. Stable incompatibility closes
    /// through an explicit non-modeled owner fact.
    /// Authorization denial retains the lease but creates no semantic fact;
    /// replacing the locally misconfigured driver discards that volatile
    /// lease. Executor completion is independently authenticated before
    /// snapshot incorporation.
    ///
    /// # Errors
    ///
    /// Returns a repository, reservation, canonical request, or checked
    /// executor-client error. The exact reservation remains held unless the
    /// returned outcome explicitly incorporated, closed, resolved, or
    /// scheduled it under a fresh assignment.
    pub fn step(
        &mut self,
        campaign: &str,
        worker_slot: WorkerSlotId,
    ) -> Result<CampaignExecutorStepOutcome, CampaignExecutorDriverError<S::Error>>
    where
        S: ExecutorStatusService,
    {
        let (head, state) = self.repository.head_with_state(campaign)?;
        let reservation = match self.queue.reservation_for_slot(worker_slot) {
            Some(reservation) => reservation,
            None => {
                if state != CampaignState::Running {
                    return Ok(CampaignExecutorStepOutcome::Inactive {
                        snapshot: head.snapshot_id(),
                        state,
                    });
                }
                if self.settled_snapshot == Some(head.snapshot_id()) {
                    return Ok(CampaignExecutorStepOutcome::Idle {
                        snapshot: head.snapshot_id(),
                    });
                }
                if self
                    .cursor
                    .is_some_and(|cursor| cursor.snapshot() != head.snapshot_id())
                {
                    self.cursor = None;
                }
                let page = self.repository.project_claimable_attempts(
                    campaign,
                    self.cursor,
                    self.scan_limit,
                )?;
                if page.snapshot() != head.snapshot_id() {
                    self.cursor = None;
                    self.settled_snapshot = None;
                    return Ok(CampaignExecutorStepOutcome::ScanRestarted {
                        snapshot: page.snapshot(),
                    });
                }
                match self.queue.reserve_from_page(&page, worker_slot)? {
                    Some(reservation) => reservation,
                    None => {
                        self.cursor = page.next();
                        if self.cursor.is_none() {
                            self.settled_snapshot = Some(page.snapshot());
                            return Ok(CampaignExecutorStepOutcome::Idle {
                                snapshot: page.snapshot(),
                            });
                        }
                        return Ok(CampaignExecutorStepOutcome::ScanPending {
                            snapshot: page.snapshot(),
                        });
                    }
                }
            }
        };

        let roots = head.snapshot().roots();
        let already_observed = self
            .repository
            .merkle
            .get(
                roots.observations,
                map_key_content("observations.attempt", reservation.attempt().content_id()),
            )
            .map_err(CampaignRepositoryError::from)?;
        let already_closed = self
            .repository
            .merkle
            .get(
                roots.accounting,
                non_modeled_attempt_key(reservation.attempt()),
            )
            .map_err(CampaignRepositoryError::from)?;
        if already_observed.is_some() || already_closed.is_some() {
            self.queue.release(reservation)?;
            self.active_executions.remove(&worker_slot);
            self.reset_scan();
            return Ok(CampaignExecutorStepOutcome::AlreadyResolved {
                attempt: reservation.attempt(),
                snapshot: head.snapshot_id(),
            });
        }

        if let Some(active) = self
            .active_executions
            .get(&worker_slot)
            .filter(|active| active.reservation == reservation)
            .cloned()
        {
            return self.poll_execution(campaign, worker_slot, active);
        }
        self.active_executions.remove(&worker_slot);

        let request = self.request_for(reservation, head.snapshot().lineage())?;
        let response = self
            .executor
            .submit_attempt(&request)
            .map_err(CampaignExecutorDriverError::Executor)?;
        self.repository
            .validate_executor_response(&request, &response)?;

        match response.disposition() {
            SubmitAttemptDisposition::Accepted { execution } => {
                self.active_executions.insert(
                    worker_slot,
                    ActiveExecutionPoll {
                        reservation,
                        request,
                        execution,
                    },
                );
                Ok(CampaignExecutorStepOutcome::Running {
                    attempt: reservation.attempt(),
                    execution,
                    newly_accepted: true,
                })
            }
            SubmitAttemptDisposition::AlreadyRunning { execution } => {
                self.active_executions.insert(
                    worker_slot,
                    ActiveExecutionPoll {
                        reservation,
                        request,
                        execution,
                    },
                );
                Ok(CampaignExecutorStepOutcome::Running {
                    attempt: reservation.attempt(),
                    execution,
                    newly_accepted: false,
                })
            }
            SubmitAttemptDisposition::AlreadyCompleted { observation } => {
                let observation_record = self.repository.load_observation(observation)?;
                let expected = self.repository.head(campaign)?.snapshot_id();
                let result =
                    self.repository
                        .publish_observation(campaign, expected, &observation_record)?;
                self.queue.release(reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::Incorporated(result))
            }
            SubmitAttemptDisposition::Rejected {
                reason:
                    reason @ (ExecutorRejection::Backpressure | ExecutorRejection::UnavailableInput),
            } => {
                self.queue.release(reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::RetryScheduled {
                    attempt: reservation.attempt(),
                    reason,
                })
            }
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::ConflictingAssignment,
            } => {
                self.queue.release(reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::AssignmentRenewed {
                    attempt: reservation.attempt(),
                })
            }
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::Unauthorized,
            } => Ok(CampaignExecutorStepOutcome::Blocked {
                attempt: reservation.attempt(),
                reason: ExecutorRejection::Unauthorized,
            }),
            SubmitAttemptDisposition::Rejected { reason } => {
                let disposition = NonModeledAttemptDisposition::PermanentlyIncompatible;
                if reason != ExecutorRejection::Incompatible {
                    return Ok(CampaignExecutorStepOutcome::Blocked {
                        attempt: reservation.attempt(),
                        reason,
                    });
                }
                let expected = self.repository.head(campaign)?.snapshot_id();
                let result = self.repository.close_attempt_non_modeled(
                    campaign,
                    expected,
                    reservation.attempt(),
                    disposition,
                )?;
                self.queue.release(reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::Closed(result))
            }
        }
    }

    /// Returns the number of process-local attempt reservations currently held.
    #[must_use]
    pub fn reservation_count(&self) -> usize {
        self.queue.reservation_count()
    }

    /// Returns the checked executor client when coordinator ownership ends.
    #[must_use]
    pub fn into_executor(self) -> ExecutorClient<S> {
        self.executor
    }

    fn request_for(
        &self,
        reservation: AttemptReservation,
        lineage: CampaignLineageId,
    ) -> Result<SubmitAttemptRequest, CampaignCodecError> {
        let assignment =
            assignment_for_reservation(reservation, lineage, self.resources, self.retention)?;
        SubmitAttemptRequest::new(
            assignment,
            reservation.daemon_epoch(),
            lineage,
            reservation.attempt(),
            self.resources,
            self.retention,
        )
    }

    fn reset_scan(&mut self) {
        self.cursor = None;
        self.settled_snapshot = None;
    }

    fn poll_execution(
        &mut self,
        campaign: &str,
        worker_slot: WorkerSlotId,
        active: ActiveExecutionPoll,
    ) -> Result<CampaignExecutorStepOutcome, CampaignExecutorDriverError<S::Error>>
    where
        S: ExecutorStatusService,
    {
        let query = GetAttemptExecutionRequest::new(&active.request, active.execution)?;
        let response = self
            .executor
            .get_attempt_execution(&query)
            .map_err(CampaignExecutorDriverError::Executor)?;
        match response.disposition() {
            GetAttemptExecutionDisposition::Running => Ok(CampaignExecutorStepOutcome::Running {
                attempt: active.reservation.attempt(),
                execution: active.execution,
                newly_accepted: false,
            }),
            GetAttemptExecutionDisposition::Completed { observation } => {
                let observation_record = self.repository.load_observation(observation)?;
                let expected = self.repository.head(campaign)?.snapshot_id();
                let result =
                    self.repository
                        .publish_observation(campaign, expected, &observation_record)?;
                self.queue.release(active.reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::Incorporated(result))
            }
            GetAttemptExecutionDisposition::Canceled
            | GetAttemptExecutionDisposition::NotCurrent => {
                self.queue.release(active.reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::AssignmentRenewed {
                    attempt: active.reservation.attempt(),
                })
            }
        }
    }
}

fn assignment_for_reservation(
    reservation: AttemptReservation,
    lineage: CampaignLineageId,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
) -> Result<AssignmentId, CampaignCodecError> {
    let mut basis = Vec::new();
    basis.extend_from_slice(&reservation.daemon_epoch().as_bytes());
    basis.extend_from_slice(lineage.content_id().encode().as_bytes());
    basis.extend_from_slice(reservation.attempt().content_id().encode().as_bytes());
    basis.extend_from_slice(&reservation.worker_slot().get().to_be_bytes());
    basis.extend_from_slice(&reservation.generation().to_be_bytes());
    basis.extend_from_slice(&resources.maximum_vcpus().to_be_bytes());
    basis.extend_from_slice(&resources.maximum_resident_bytes().to_be_bytes());
    basis.extend_from_slice(&resources.maximum_disk_bytes().to_be_bytes());
    basis.extend_from_slice(&resources.maximum_execution_quanta().to_be_bytes());
    basis.push(match retention {
        ExecutionRetentionIntent::Discard => 0,
        ExecutionRetentionIntent::RetainOnFailure => 1,
        ExecutionRetentionIntent::RetainAlways => 2,
    });
    let digest =
        CampaignHash::derive("crucible.campaign.local-attempt-assignment.v1", &basis).as_bytes();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[0] |= 0x80;
    AssignmentId::from_bytes(bytes)
}

/// One bounded coordinator/executor driver transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignExecutorStepOutcome {
    /// The campaign is not running and no new reservation was created.
    Inactive {
        /// Exact lifecycle snapshot observed by the driver.
        snapshot: CampaignSnapshotId,
        /// Authenticated lifecycle state at that snapshot.
        state: CampaignState,
    },
    /// One bounded page had no reservable attempt and another page remains.
    ScanPending {
        /// Exact snapshot owning the continuation.
        snapshot: CampaignSnapshotId,
    },
    /// A concurrent head advance invalidated the page used by this call.
    ScanRestarted {
        /// New snapshot from which the next call restarts.
        snapshot: CampaignSnapshotId,
    },
    /// The current snapshot has no unreserved claimable work.
    Idle {
        /// Exact snapshot proven idle by the completed scan.
        snapshot: CampaignSnapshotId,
    },
    /// The executor accepted or still owns the exact assignment.
    Running {
        /// Immutable semantic attempt being executed.
        attempt: AttemptId,
        /// Local execution incarnation returned by the executor.
        execution: ExecutionId,
        /// Whether this call first admitted the execution.
        newly_accepted: bool,
    },
    /// A transient executor condition released the lease for a fresh assignment.
    RetryScheduled {
        /// Immutable semantic attempt that remains claimable.
        attempt: AttemptId,
        /// Stable retryable executor rejection.
        reason: ExecutorRejection,
    },
    /// A stable local authorization failure retained the lease without semantics.
    Blocked {
        /// Immutable semantic attempt still reserved.
        attempt: AttemptId,
        /// Stable local executor rejection requiring reconfiguration.
        reason: ExecutorRejection,
    },
    /// A conflicting operational assignment was released for fresh generation.
    AssignmentRenewed {
        /// Immutable attempt that remains semantically claimable.
        attempt: AttemptId,
    },
    /// Another coordinator transition resolved the held attempt first.
    AlreadyResolved {
        /// Immutable attempt whose volatile lease was released.
        attempt: AttemptId,
        /// Authenticated snapshot already containing its terminal owner state.
        snapshot: CampaignSnapshotId,
    },
    /// A completed executor observation advanced campaign state.
    Incorporated(ObservationResult),
    /// A stable non-modeled disposition closed the attempt ordinal.
    Closed(NonModeledAttemptResult),
}

/// Invalid static configuration for a campaign executor driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CampaignExecutorDriverConfigError {
    /// Reservation-table construction failed.
    #[error(transparent)]
    Queue(#[from] AttemptQueueError),
    /// The accounting scan page limit is zero or exceeds 10,000 entries.
    #[error("campaign executor scan limit must be in 1..=10,000")]
    InvalidScanLimit,
}

/// Failure while advancing one bounded campaign executor step.
#[derive(Debug, Error)]
pub enum CampaignExecutorDriverError<E> {
    /// Repository projection, validation, or owner publication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Volatile reservation state was invalid or exhausted.
    #[error(transparent)]
    Queue(#[from] AttemptQueueError),
    /// A canonical assignment request could not be constructed.
    #[error(transparent)]
    Protocol(#[from] CampaignCodecError),
    /// The checked executor component call failed.
    #[error("executor component call failed")]
    Executor(ExecutorClientError<E>),
}
