//! Bounded coordinator handoff from claimable attempts to one local executor.
//!
//! The driver owns only volatile reservations and scan continuation. Campaign
//! attempts, completions, and non-modeled terminal dispositions remain
//! authoritative repository records, so restart discards this object and
//! rebuilds safely from the current snapshot.

use std::sync::Arc;

use super::*;
use crate::{
    AssignmentId, AttemptResourceLimits, CancelAttemptExecutionDisposition,
    CancelAttemptExecutionRequest, CheckpointAttemptExecutionDisposition,
    CheckpointAttemptExecutionRequest, ExactCheckpointId, ExecutionId, ExecutionRetentionIntent,
    ExecutorClient, ExecutorClientError, ExecutorControlService, ExecutorRejection,
    ExecutorResumeService, GetAttemptExecutionDisposition, GetAttemptExecutionRequest,
    ResumeAttemptExecutionDisposition, ResumeAttemptExecutionRequest,
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
        S: ExecutorResumeService,
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
            return self.poll_execution(
                campaign,
                worker_slot,
                active,
                state == CampaignState::Running,
            );
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
            SubmitAttemptDisposition::AlreadyPaused {
                execution,
                checkpoint,
            } => {
                if state == CampaignState::Running {
                    return self.resume_paused(
                        campaign,
                        worker_slot,
                        reservation,
                        request,
                        execution,
                        checkpoint,
                    );
                }
                self.active_executions.insert(
                    worker_slot,
                    ActiveExecutionPoll {
                        reservation,
                        request,
                        execution,
                    },
                );
                Ok(CampaignExecutorStepOutcome::Checkpointed {
                    attempt: reservation.attempt(),
                    execution,
                    checkpoint,
                })
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

    /// Returns the fixed reservation ceiling configured for this driver.
    #[must_use]
    pub const fn maximum_reservations(&self) -> usize {
        self.queue.maximum_reservations()
    }

    /// Returns the number of exact executor incarnations being polled.
    #[must_use]
    pub fn active_execution_count(&self) -> usize {
        self.active_executions.len()
    }

    pub(super) fn first_drain_worker_slot(&self) -> Option<WorkerSlotId> {
        self.active_executions
            .first_key_value()
            .map(|(worker_slot, _)| *worker_slot)
            .or_else(|| {
                self.queue
                    .first_reservation()
                    .map(AttemptReservation::worker_slot)
            })
    }

    /// Releases or requests cancellation of at most one held reservation.
    ///
    /// Accepted executions are selected by lowest worker-slot identity;
    /// otherwise the lowest unaccepted reservation is released without an
    /// executor call. A transport or response-validation failure retains the
    /// exact reservation and execution basis for retry. Durable cancellation
    /// releases only the coordinator's volatile lease; the executor remains
    /// responsible for charging physical resources until its worker
    /// acknowledges exit.
    /// Completion that won the race is independently authenticated and
    /// incorporated through the ordinary observation owner transaction.
    ///
    /// # Errors
    ///
    /// Returns a checked executor-client, repository, or reservation error. The
    /// active poll remains owned unless the returned outcome explicitly
    /// canceled, resolved, or incorporated it.
    pub fn cancel_one(
        &mut self,
        campaign: &str,
    ) -> Result<CampaignExecutorCancelOutcome, CampaignExecutorDriverError<S::Error>>
    where
        S: ExecutorControlService,
    {
        let Some((worker_slot, active)) = self
            .active_executions
            .iter()
            .next()
            .map(|(worker_slot, active)| (*worker_slot, active.clone()))
        else {
            let Some(reservation) = self.queue.first_reservation() else {
                return Ok(CampaignExecutorCancelOutcome::Idle);
            };
            self.queue.release(reservation)?;
            self.reset_scan();
            return Ok(CampaignExecutorCancelOutcome::Released {
                attempt: reservation.attempt(),
            });
        };
        let request = CancelAttemptExecutionRequest::new(&active.request, active.execution)?;
        let response = self
            .executor
            .cancel_attempt_execution(&request)
            .map_err(CampaignExecutorDriverError::Executor)?;
        match response.disposition() {
            CancelAttemptExecutionDisposition::Canceled
            | CancelAttemptExecutionDisposition::AlreadyCanceled => {
                let already_canceled = matches!(
                    response.disposition(),
                    CancelAttemptExecutionDisposition::AlreadyCanceled
                );
                self.queue.release(active.reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorCancelOutcome::Canceled {
                    attempt: active.reservation.attempt(),
                    execution: active.execution,
                    already_canceled,
                })
            }
            CancelAttemptExecutionDisposition::AlreadyCompleted { observation } => {
                let observation_record = self.repository.load_observation(observation)?;
                let expected = self.repository.head(campaign)?.snapshot_id();
                let result =
                    self.repository
                        .publish_observation(campaign, expected, &observation_record)?;
                self.queue.release(active.reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorCancelOutcome::Incorporated(result))
            }
            CancelAttemptExecutionDisposition::NotCurrent => {
                self.queue.release(active.reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorCancelOutcome::AssignmentRenewed {
                    attempt: active.reservation.attempt(),
                })
            }
        }
    }

    /// Requests an exact checkpoint for at most one held execution.
    ///
    /// The lowest active worker slot is selected deterministically. A held
    /// reservation that has not reached the executor is released because it
    /// owns no guest state to preserve. Active reservations remain held through
    /// request, publication, and paused outcomes so the semantic attempt cannot
    /// be reassigned before its checkpoint is incorporated by the owner.
    ///
    /// # Errors
    ///
    /// Returns a checked executor-client, repository, or reservation error.
    pub fn checkpoint_one(
        &mut self,
        campaign: &str,
    ) -> Result<CampaignExecutorCheckpointOutcome, CampaignExecutorDriverError<S::Error>>
    where
        S: ExecutorControlService,
    {
        let Some((worker_slot, active)) = self
            .active_executions
            .iter()
            .next()
            .map(|(worker_slot, active)| (*worker_slot, active.clone()))
        else {
            let Some(reservation) = self.queue.first_reservation() else {
                return Ok(CampaignExecutorCheckpointOutcome::Idle);
            };
            self.queue.release(reservation)?;
            self.reset_scan();
            return Ok(CampaignExecutorCheckpointOutcome::Released {
                attempt: reservation.attempt(),
            });
        };
        let request = CheckpointAttemptExecutionRequest::new(&active.request, active.execution)?;
        let response = self
            .executor
            .checkpoint_attempt_execution(&request)
            .map_err(CampaignExecutorDriverError::Executor)?;
        match response.disposition() {
            CheckpointAttemptExecutionDisposition::Requested
            | CheckpointAttemptExecutionDisposition::AlreadyRequested => {
                Ok(CampaignExecutorCheckpointOutcome::Requested {
                    attempt: active.reservation.attempt(),
                    execution: active.execution,
                    already_requested: matches!(
                        response.disposition(),
                        CheckpointAttemptExecutionDisposition::AlreadyRequested
                    ),
                })
            }
            CheckpointAttemptExecutionDisposition::Publishing { checkpoint } => {
                Ok(CampaignExecutorCheckpointOutcome::Publishing {
                    attempt: active.reservation.attempt(),
                    execution: active.execution,
                    checkpoint,
                })
            }
            CheckpointAttemptExecutionDisposition::Paused { checkpoint } => {
                Ok(CampaignExecutorCheckpointOutcome::Paused {
                    attempt: active.reservation.attempt(),
                    execution: active.execution,
                    checkpoint,
                })
            }
            CheckpointAttemptExecutionDisposition::AlreadyCompleted { observation } => {
                let observation_record = self.repository.load_observation(observation)?;
                let expected = self.repository.head(campaign)?.snapshot_id();
                let result =
                    self.repository
                        .publish_observation(campaign, expected, &observation_record)?;
                self.queue.release(active.reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorCheckpointOutcome::Incorporated(result))
            }
            CheckpointAttemptExecutionDisposition::AlreadyCanceled
            | CheckpointAttemptExecutionDisposition::NotCurrent => {
                self.queue.release(active.reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorCheckpointOutcome::AssignmentRenewed {
                    attempt: active.reservation.attempt(),
                })
            }
        }
    }

    /// Returns the checked executor client when coordinator ownership ends.
    #[must_use]
    pub fn into_executor(self) -> ExecutorClient<S> {
        self.executor
    }

    pub(super) fn repository(&self) -> &Arc<CampaignRepository> {
        &self.repository
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
        resume_allowed: bool,
    ) -> Result<CampaignExecutorStepOutcome, CampaignExecutorDriverError<S::Error>>
    where
        S: ExecutorResumeService,
    {
        let query = GetAttemptExecutionRequest::new(&active.request, active.execution)?;
        let response = self
            .executor
            .get_attempt_execution(&query)
            .map_err(CampaignExecutorDriverError::Executor)?;
        match response.disposition() {
            GetAttemptExecutionDisposition::Running
            | GetAttemptExecutionDisposition::CheckpointRequested
            | GetAttemptExecutionDisposition::CheckpointPublishing { .. } => {
                Ok(CampaignExecutorStepOutcome::Running {
                    attempt: active.reservation.attempt(),
                    execution: active.execution,
                    newly_accepted: false,
                })
            }
            GetAttemptExecutionDisposition::Paused { checkpoint } => {
                if resume_allowed {
                    return self.resume_paused(
                        campaign,
                        worker_slot,
                        active.reservation,
                        active.request,
                        active.execution,
                        checkpoint,
                    );
                }
                Ok(CampaignExecutorStepOutcome::Checkpointed {
                    attempt: active.reservation.attempt(),
                    execution: active.execution,
                    checkpoint,
                })
            }
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

    fn resume_paused(
        &mut self,
        campaign: &str,
        worker_slot: WorkerSlotId,
        reservation: AttemptReservation,
        prior_request: SubmitAttemptRequest,
        prior_execution: ExecutionId,
        checkpoint: ExactCheckpointId,
    ) -> Result<CampaignExecutorStepOutcome, CampaignExecutorDriverError<S::Error>>
    where
        S: ExecutorResumeService,
    {
        let assignment = resume_assignment_for_reservation(
            reservation,
            prior_request.lineage(),
            self.resources,
            self.retention,
            prior_execution,
            checkpoint,
        )?;
        let resumed_assignment = SubmitAttemptRequest::new(
            assignment,
            reservation.daemon_epoch(),
            prior_request.lineage(),
            reservation.attempt(),
            self.resources,
            self.retention,
        )?;
        let request =
            ResumeAttemptExecutionRequest::new(&resumed_assignment, prior_execution, checkpoint)?;
        let response = self
            .executor
            .resume_attempt_execution(&request)
            .map_err(CampaignExecutorDriverError::Executor)?;
        match response.disposition() {
            ResumeAttemptExecutionDisposition::Accepted { execution }
            | ResumeAttemptExecutionDisposition::AlreadyRunning { execution } => {
                let newly_accepted = matches!(
                    response.disposition(),
                    ResumeAttemptExecutionDisposition::Accepted { .. }
                );
                self.active_executions.insert(
                    worker_slot,
                    ActiveExecutionPoll {
                        reservation,
                        request: resumed_assignment,
                        execution,
                    },
                );
                Ok(CampaignExecutorStepOutcome::Running {
                    attempt: reservation.attempt(),
                    execution,
                    newly_accepted,
                })
            }
            ResumeAttemptExecutionDisposition::AlreadyCompleted { observation } => {
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
            ResumeAttemptExecutionDisposition::AlreadyCanceled
            | ResumeAttemptExecutionDisposition::NotCurrent => {
                self.queue.release(reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::AssignmentRenewed {
                    attempt: reservation.attempt(),
                })
            }
            ResumeAttemptExecutionDisposition::Rejected {
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
            ResumeAttemptExecutionDisposition::Rejected {
                reason: ExecutorRejection::ConflictingAssignment,
            } => {
                self.queue.release(reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::AssignmentRenewed {
                    attempt: reservation.attempt(),
                })
            }
            ResumeAttemptExecutionDisposition::Rejected {
                reason: ExecutorRejection::Unauthorized,
            } => Ok(CampaignExecutorStepOutcome::Blocked {
                attempt: reservation.attempt(),
                reason: ExecutorRejection::Unauthorized,
            }),
            ResumeAttemptExecutionDisposition::Rejected { reason } => {
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
                    NonModeledAttemptDisposition::PermanentlyIncompatible,
                )?;
                self.queue.release(reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::Closed(result))
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

fn resume_assignment_for_reservation(
    reservation: AttemptReservation,
    lineage: CampaignLineageId,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
    prior_execution: ExecutionId,
    checkpoint: ExactCheckpointId,
) -> Result<AssignmentId, CampaignCodecError> {
    let initial = assignment_for_reservation(reservation, lineage, resources, retention)?;
    let mut basis = Vec::new();
    basis.extend_from_slice(&initial.as_bytes());
    basis.extend_from_slice(&prior_execution.as_bytes());
    basis.extend_from_slice(checkpoint.content_id().encode().as_bytes());
    let digest = CampaignHash::derive(
        "crucible.campaign.local-attempt-resume-assignment.v1",
        &basis,
    )
    .as_bytes();
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
    /// The exact execution stopped at a complete durable checkpoint.
    Checkpointed {
        /// Immutable semantic attempt that was paused.
        attempt: AttemptId,
        /// Local execution incarnation that produced the checkpoint.
        execution: ExecutionId,
        /// Complete durable exact-checkpoint root.
        checkpoint: ExactCheckpointId,
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

/// One bounded coordinator exact-checkpoint transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignExecutorCheckpointOutcome {
    /// No reservation remains to checkpoint.
    Idle,
    /// A not-yet-executing reservation was released without guest work.
    Released {
        /// Immutable attempt made claimable after resume.
        attempt: AttemptId,
    },
    /// The exact worker has durably latched the checkpoint request.
    Requested {
        /// Immutable semantic attempt being paused.
        attempt: AttemptId,
        /// Exact local execution incarnation.
        execution: ExecutionId,
        /// Whether an earlier call had already latched the request.
        already_requested: bool,
    },
    /// Checkpoint bytes are publishing under a retained root.
    Publishing {
        /// Immutable semantic attempt being paused.
        attempt: AttemptId,
        /// Exact local execution incarnation.
        execution: ExecutionId,
        /// Root retained before publication began.
        checkpoint: ExactCheckpointId,
    },
    /// The execution stopped at a complete durable checkpoint.
    Paused {
        /// Immutable semantic attempt that was paused.
        attempt: AttemptId,
        /// Exact local execution incarnation.
        execution: ExecutionId,
        /// Complete durable exact-checkpoint root.
        checkpoint: ExactCheckpointId,
    },
    /// Completion won and advanced authoritative campaign state.
    Incorporated(ObservationResult),
    /// Cancellation or a stale execution requires a fresh assignment on resume.
    AssignmentRenewed {
        /// Immutable attempt that remains semantically claimable.
        attempt: AttemptId,
    },
}

/// One bounded coordinator cancellation transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignExecutorCancelOutcome {
    /// No accepted local execution remains to cancel.
    Idle,
    /// A reservation not yet accepted by an executor was released locally.
    Released {
        /// Immutable attempt made claimable again for a later resume.
        attempt: AttemptId,
    },
    /// Cancellation is durable for one exact executor incarnation.
    Canceled {
        /// Immutable attempt made claimable again for a later resume.
        attempt: AttemptId,
        /// Exact local execution incarnation that was canceled.
        execution: ExecutionId,
        /// Whether the executor had already accepted the same cancellation.
        already_canceled: bool,
    },
    /// The execution was no longer current and its lease was released.
    AssignmentRenewed {
        /// Immutable attempt that remains semantically claimable.
        attempt: AttemptId,
    },
    /// Canonical completion won and advanced campaign state.
    Incorporated(ObservationResult),
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
    Executor(#[source] ExecutorClientError<E>),
}
