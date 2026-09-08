//! Bounded coordinator handoff from claimable attempts to one local executor.
//!
//! The driver owns only volatile reservations and scan continuation. Campaign
//! attempts, completions, and non-modeled terminal dispositions remain
//! authoritative repository records, so restart discards this object and
//! rebuilds safely from the current snapshot.

use std::{collections::BTreeSet, sync::Arc};

use super::*;
use crate::{
    AssignmentId, AttemptResourceLimits, CampaignCommandId, CancelAttemptExecutionDisposition,
    CancelAttemptExecutionRequest, CheckpointAttemptExecutionDisposition,
    CheckpointAttemptExecutionRequest, ExactCheckpointId, ExecutionId, ExecutionRetentionIntent,
    ExecutorClient, ExecutorClientError, ExecutorControlService, ExecutorRejection,
    ExecutorResumeService, ExecutorStatusService, GetAttemptExecutionDisposition,
    GetAttemptExecutionRequest, GetAttemptExecutionResponse, ResumeAttemptExecutionDisposition,
    ResumeAttemptExecutionRequest, SavepointCaptureOutcome, SavepointCaptureRequest,
    SavepointCaptureResolution,
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
    capture_cursor: Option<SavepointCaptureCursor>,
    capture_settled_snapshot: Option<CampaignSnapshotId>,
    capture_scan_requires_full_pass: bool,
    capture_next_generation: u64,
    prefer_capture_new_work: bool,
    deferred_capture_requests: BTreeSet<CampaignFactId>,
    capture_by_request: BTreeMap<CampaignFactId, SavepointCaptureReservation>,
    capture_by_slot: BTreeMap<WorkerSlotId, CampaignFactId>,
    active_captures: BTreeMap<WorkerSlotId, ActiveSavepointCapturePoll>,
}

#[derive(Clone)]
struct ActiveExecutionPoll {
    reservation: AttemptReservation,
    request: SubmitAttemptRequest,
    execution: ExecutionId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SavepointCaptureReservation {
    request: CampaignFactId,
    capture: SavepointCaptureRequest,
    scan_after: SavepointCaptureCursor,
    daemon_epoch: DaemonEpoch,
    worker_slot: WorkerSlotId,
    generation: u64,
}

#[derive(Clone)]
struct ActiveSavepointCapturePoll {
    reservation: SavepointCaptureReservation,
    assignment: SubmitAttemptRequest,
    execution: ExecutionId,
    cancellation_requested: bool,
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
            capture_cursor: None,
            capture_settled_snapshot: None,
            capture_scan_requires_full_pass: false,
            capture_next_generation: 1,
            prefer_capture_new_work: true,
            deferred_capture_requests: BTreeSet::new(),
            capture_by_request: BTreeMap::new(),
            capture_by_slot: BTreeMap::new(),
            active_captures: BTreeMap::new(),
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

        // An already-owned semantic attempt keeps polling priority. A capture
        // reservation also stays with its slot until it resolves. New capture
        // and semantic admissions alternate after transient capture failures.
        if self.queue.reservation_for_slot(worker_slot).is_none() {
            if let Some(reservation) = self.capture_reservation_for_slot(worker_slot) {
                return self.step_savepoint_capture(campaign, reservation);
            }
            if state == CampaignState::Running
                && self.prefer_capture_new_work
                && self.capture_settled_snapshot != Some(head.snapshot_id())
            {
                if self
                    .capture_cursor
                    .is_some_and(|cursor| cursor.snapshot() != head.snapshot_id())
                {
                    self.capture_cursor = self
                        .capture_cursor
                        .map(|cursor| cursor.rebase(head.snapshot_id()));
                    self.capture_scan_requires_full_pass = true;
                }
                let page = self.repository.project_pending_savepoint_captures(
                    campaign,
                    self.capture_cursor,
                    self.scan_limit,
                )?;
                if page.snapshot() != head.snapshot_id() {
                    self.reset_capture_scan();
                    return Ok(CampaignExecutorStepOutcome::ScanRestarted {
                        snapshot: page.snapshot(),
                    });
                }
                if let Some(reservation) =
                    self.reserve_savepoint_capture_from_page(&page, worker_slot)?
                {
                    return self.step_savepoint_capture(campaign, reservation);
                }
                self.capture_cursor = page.next();
                if self.capture_cursor.is_none() {
                    if self.capture_scan_requires_full_pass {
                        // A head advance can insert a lower-key request behind
                        // the retained cursor. Finish the old suffix, then make
                        // one fresh pass before declaring the new head settled.
                        self.capture_scan_requires_full_pass = false;
                        self.deferred_capture_requests.clear();
                        self.prefer_capture_new_work = false;
                    } else if self.deferred_capture_requests.is_empty() {
                        self.capture_settled_snapshot = Some(page.snapshot());
                    } else {
                        // Every transient request gets skipped once before the
                        // scan cycles. Give semantic work a turn between cycles.
                        self.deferred_capture_requests.clear();
                        self.prefer_capture_new_work = false;
                    }
                } else {
                    self.prefer_capture_new_work = false;
                    return Ok(CampaignExecutorStepOutcome::CaptureScanPending {
                        snapshot: page.snapshot(),
                    });
                }
            }
        }

        let reservation = match self.queue.reservation_for_slot(worker_slot) {
            Some(reservation) => reservation,
            None => {
                self.prefer_capture_new_work = true;
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
                if self.reservation_count() >= self.maximum_reservations() {
                    return Err(AttemptQueueError::CapacityExhausted.into());
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
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::TerminalFailure,
            } => {
                let expected = self.repository.head(campaign)?.snapshot_id();
                let result = self.repository.close_attempt_non_modeled(
                    campaign,
                    expected,
                    reservation.attempt(),
                    NonModeledAttemptDisposition::TerminalWorkerFailure,
                )?;
                self.queue.release(reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::Closed(result))
            }
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
        self.queue.reservation_count() + self.capture_by_request.len()
    }

    /// Returns the fixed reservation ceiling configured for this driver.
    #[must_use]
    pub const fn maximum_reservations(&self) -> usize {
        self.queue.maximum_reservations()
    }

    /// Returns the number of exact executor incarnations being polled.
    #[must_use]
    pub fn active_execution_count(&self) -> usize {
        self.active_executions.len() + self.active_captures.len()
    }

    pub(super) fn first_drain_worker_slot(&self) -> Option<WorkerSlotId> {
        [
            self.active_executions
                .first_key_value()
                .map(|(worker_slot, _)| *worker_slot),
            self.active_captures
                .first_key_value()
                .map(|(worker_slot, _)| *worker_slot),
            self.queue
                .first_reservation()
                .map(AttemptReservation::worker_slot),
            self.capture_by_slot
                .first_key_value()
                .map(|(worker_slot, _)| *worker_slot),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn capture_reservation_for_slot(
        &self,
        worker_slot: WorkerSlotId,
    ) -> Option<SavepointCaptureReservation> {
        self.capture_by_slot
            .get(&worker_slot)
            .and_then(|request| self.capture_by_request.get(request))
            .cloned()
    }

    fn reserve_savepoint_capture_from_page(
        &mut self,
        page: &PendingSavepointCapturePage,
        worker_slot: WorkerSlotId,
    ) -> Result<Option<SavepointCaptureReservation>, AttemptQueueError> {
        if let Some(reservation) = self.capture_reservation_for_slot(worker_slot) {
            return Ok(Some(reservation));
        }
        let Some(pending) = page.captures().iter().find(|pending| {
            !self.capture_by_request.contains_key(&pending.request())
                && !self.deferred_capture_requests.contains(&pending.request())
        }) else {
            return Ok(None);
        };
        if self.reservation_count() >= self.maximum_reservations() {
            return Err(AttemptQueueError::CapacityExhausted);
        }
        let generation = self.capture_next_generation;
        self.capture_next_generation = generation
            .checked_add(1)
            .ok_or(AttemptQueueError::GenerationExhausted)?;
        let reservation = SavepointCaptureReservation {
            request: pending.request(),
            capture: pending.capture().clone(),
            scan_after: SavepointCaptureCursor::after_request(page.snapshot(), pending.request()),
            daemon_epoch: self.queue.daemon_epoch(),
            worker_slot,
            generation,
        };
        self.capture_by_request
            .insert(reservation.request, reservation.clone());
        self.capture_by_slot
            .insert(worker_slot, reservation.request);
        Ok(Some(reservation))
    }

    fn release_savepoint_capture(
        &mut self,
        reservation: &SavepointCaptureReservation,
    ) -> Result<(), AttemptQueueError> {
        if reservation.daemon_epoch != self.queue.daemon_epoch()
            || self.capture_by_request.get(&reservation.request) != Some(reservation)
            || self.capture_by_slot.get(&reservation.worker_slot) != Some(&reservation.request)
        {
            return Err(AttemptQueueError::ReservationMismatch);
        }
        self.capture_by_request.remove(&reservation.request);
        self.capture_by_slot.remove(&reservation.worker_slot);
        self.active_captures.remove(&reservation.worker_slot);
        Ok(())
    }

    fn step_savepoint_capture(
        &mut self,
        campaign: &str,
        reservation: SavepointCaptureReservation,
    ) -> Result<CampaignExecutorStepOutcome, CampaignExecutorDriverError<S::Error>>
    where
        S: ExecutorResumeService,
    {
        let head = self.repository.head(campaign)?;
        if self
            .repository
            .savepoint_capture_resolution_at(head.snapshot_id(), reservation.request)?
            .is_some()
        {
            self.release_savepoint_capture(&reservation)?;
            self.reset_capture_scan();
            return Ok(CampaignExecutorStepOutcome::CaptureAlreadyResolved {
                request: reservation.request,
                snapshot: head.snapshot_id(),
            });
        }

        if let Some(active) = self
            .active_captures
            .get(&reservation.worker_slot)
            .filter(|active| active.reservation == reservation)
            .cloned()
        {
            return self.poll_savepoint_capture(campaign, active);
        }
        self.active_captures.remove(&reservation.worker_slot);

        let assignment = self.capture_request_for(&reservation, head.snapshot().lineage())?;
        let response = self
            .executor
            .submit_attempt(&assignment)
            .map_err(CampaignExecutorDriverError::Executor)?;
        self.repository
            .validate_executor_response(&assignment, &response)?;

        match response.disposition() {
            SubmitAttemptDisposition::Accepted { execution }
            | SubmitAttemptDisposition::AlreadyRunning { execution }
            | SubmitAttemptDisposition::AlreadyPaused { execution, .. } => {
                let newly_accepted = matches!(
                    response.disposition(),
                    SubmitAttemptDisposition::Accepted { .. }
                );
                self.active_captures.insert(
                    reservation.worker_slot,
                    ActiveSavepointCapturePoll {
                        reservation: reservation.clone(),
                        assignment,
                        execution,
                        cancellation_requested: false,
                    },
                );
                Ok(CampaignExecutorStepOutcome::CaptureRunning {
                    request: reservation.request,
                    attempt: reservation.capture.attempt,
                    execution,
                    newly_accepted,
                })
            }
            SubmitAttemptDisposition::Rejected {
                reason:
                    reason @ (ExecutorRejection::Backpressure | ExecutorRejection::UnavailableInput),
            }
            | SubmitAttemptDisposition::Rejected {
                reason: reason @ ExecutorRejection::ConflictingAssignment,
            } => {
                self.release_savepoint_capture(&reservation)?;
                self.defer_savepoint_capture(reservation.request, reservation.scan_after);
                Ok(CampaignExecutorStepOutcome::CaptureRetryScheduled {
                    request: reservation.request,
                    attempt: reservation.capture.attempt,
                    reason,
                })
            }
            SubmitAttemptDisposition::Rejected { reason } => {
                Ok(CampaignExecutorStepOutcome::CaptureBlocked {
                    request: reservation.request,
                    attempt: reservation.capture.attempt,
                    reason,
                })
            }
            SubmitAttemptDisposition::AlreadyCompleted { observation } => {
                Ok(CampaignExecutorStepOutcome::CaptureUnexpectedCompletion {
                    request: reservation.request,
                    attempt: reservation.capture.attempt,
                    observation,
                })
            }
        }
    }

    fn poll_savepoint_capture(
        &mut self,
        campaign: &str,
        active: ActiveSavepointCapturePoll,
    ) -> Result<CampaignExecutorStepOutcome, CampaignExecutorDriverError<S::Error>>
    where
        S: ExecutorStatusService,
    {
        let query = GetAttemptExecutionRequest::new(&active.assignment, active.execution)?;
        let status = self
            .executor
            .get_attempt_execution(&query)
            .map_err(CampaignExecutorDriverError::Executor)?;
        match status.disposition() {
            GetAttemptExecutionDisposition::Running
            | GetAttemptExecutionDisposition::CheckpointRequested
            | GetAttemptExecutionDisposition::CheckpointPublishing { .. } => {
                Ok(CampaignExecutorStepOutcome::CaptureRunning {
                    request: active.reservation.request,
                    attempt: active.reservation.capture.attempt,
                    execution: active.execution,
                    newly_accepted: false,
                })
            }
            GetAttemptExecutionDisposition::Paused { checkpoint } => self
                .resolve_savepoint_capture(
                    campaign,
                    active,
                    status,
                    SavepointCaptureOutcome::Ready,
                    Some(checkpoint),
                ),
            GetAttemptExecutionDisposition::Canceled => self.resolve_savepoint_capture(
                campaign,
                active,
                status,
                SavepointCaptureOutcome::Canceled,
                None,
            ),
            GetAttemptExecutionDisposition::TerminalFailure => self.resolve_savepoint_capture(
                campaign,
                active,
                status,
                SavepointCaptureOutcome::Failed,
                None,
            ),
            GetAttemptExecutionDisposition::NotCurrent => {
                self.release_savepoint_capture(&active.reservation)?;
                self.defer_savepoint_capture(
                    active.reservation.request,
                    active.reservation.scan_after,
                );
                Ok(CampaignExecutorStepOutcome::CaptureAssignmentRenewed {
                    request: active.reservation.request,
                    attempt: active.reservation.capture.attempt,
                })
            }
            GetAttemptExecutionDisposition::Completed { observation } => {
                Ok(CampaignExecutorStepOutcome::CaptureUnexpectedCompletion {
                    request: active.reservation.request,
                    attempt: active.reservation.capture.attempt,
                    observation,
                })
            }
        }
    }

    fn resolve_savepoint_capture(
        &mut self,
        campaign: &str,
        active: ActiveSavepointCapturePoll,
        status: GetAttemptExecutionResponse,
        outcome: SavepointCaptureOutcome,
        checkpoint: Option<ExactCheckpointId>,
    ) -> Result<CampaignExecutorStepOutcome, CampaignExecutorDriverError<S::Error>>
    where
        S: ExecutorStatusService,
    {
        let head = self.repository.head(campaign)?;
        let command = savepoint_resolution_command(
            active.reservation.request,
            active.execution,
            outcome,
            head.snapshot_id(),
        );
        let resolution = SavepointCaptureResolution {
            command,
            expected_snapshot: head.snapshot_id(),
            request: active.reservation.request,
            outcome,
        };
        let result = self.repository.resolve_savepoint_capture(
            campaign,
            &resolution,
            &active.assignment,
            &status,
        )?;
        self.release_savepoint_capture(&active.reservation)?;
        self.reset_scan();
        self.reset_capture_scan();
        Ok(CampaignExecutorStepOutcome::CaptureResolved {
            result,
            attempt: active.reservation.capture.attempt,
            execution: active.execution,
            checkpoint,
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
        let semantic_active = self
            .active_executions
            .iter()
            .next()
            .map(|(worker_slot, active)| (*worker_slot, active.clone()));
        let capture_active = self
            .active_captures
            .first_key_value()
            .map(|(worker_slot, active)| (*worker_slot, active.clone()));
        if capture_active.as_ref().is_some_and(|(capture_slot, _)| {
            semantic_active
                .as_ref()
                .is_none_or(|(semantic_slot, _)| capture_slot < semantic_slot)
        }) {
            let (_, active) = capture_active.ok_or(AttemptQueueError::ReservationMismatch)?;
            return self.cancel_savepoint_capture(campaign, active);
        }
        let Some((worker_slot, active)) = semantic_active else {
            let semantic_reservation = self.queue.first_reservation();
            let capture_reservation = self
                .capture_by_slot
                .first_key_value()
                .and_then(|(worker_slot, _)| self.capture_reservation_for_slot(*worker_slot));
            if capture_reservation.as_ref().is_some_and(|capture| {
                semantic_reservation
                    .is_none_or(|semantic| capture.worker_slot < semantic.worker_slot())
            }) {
                let reservation =
                    capture_reservation.ok_or(AttemptQueueError::ReservationMismatch)?;
                self.release_savepoint_capture(&reservation)?;
                self.reset_capture_scan();
                return Ok(CampaignExecutorCancelOutcome::CaptureReleased {
                    request: reservation.request,
                    attempt: reservation.capture.attempt,
                });
            }
            if let Some(reservation) = semantic_reservation {
                self.queue.release(reservation)?;
                self.reset_scan();
                return Ok(CampaignExecutorCancelOutcome::Released {
                    attempt: reservation.attempt(),
                });
            }
            return Ok(CampaignExecutorCancelOutcome::Idle);
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
        let semantic_active = self
            .active_executions
            .iter()
            .next()
            .map(|(worker_slot, active)| (*worker_slot, active.clone()));
        let capture_active = self
            .active_captures
            .first_key_value()
            .map(|(worker_slot, active)| (*worker_slot, active.clone()));
        if capture_active.as_ref().is_some_and(|(capture_slot, _)| {
            semantic_active
                .as_ref()
                .is_none_or(|(semantic_slot, _)| capture_slot < semantic_slot)
        }) {
            let (_, active) = capture_active.ok_or(AttemptQueueError::ReservationMismatch)?;
            let outcome = self.poll_savepoint_capture(campaign, active)?;
            return capture_step_as_checkpoint(outcome).map_err(Into::into);
        }
        let Some((worker_slot, active)) = semantic_active else {
            let semantic_reservation = self.queue.first_reservation();
            let capture_reservation = self
                .capture_by_slot
                .first_key_value()
                .and_then(|(worker_slot, _)| self.capture_reservation_for_slot(*worker_slot));
            if capture_reservation.as_ref().is_some_and(|capture| {
                semantic_reservation
                    .is_none_or(|semantic| capture.worker_slot < semantic.worker_slot())
            }) {
                let reservation =
                    capture_reservation.ok_or(AttemptQueueError::ReservationMismatch)?;
                self.release_savepoint_capture(&reservation)?;
                self.reset_capture_scan();
                return Ok(CampaignExecutorCheckpointOutcome::CaptureReleased {
                    request: reservation.request,
                    attempt: reservation.capture.attempt,
                });
            }
            if let Some(reservation) = semantic_reservation {
                self.queue.release(reservation)?;
                self.reset_scan();
                return Ok(CampaignExecutorCheckpointOutcome::Released {
                    attempt: reservation.attempt(),
                });
            }
            return Ok(CampaignExecutorCheckpointOutcome::Idle);
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

    fn capture_request_for(
        &self,
        reservation: &SavepointCaptureReservation,
        lineage: CampaignLineageId,
    ) -> Result<SubmitAttemptRequest, CampaignCodecError> {
        let retention = ExecutionRetentionIntent::RetainAlways;
        let assignment =
            assignment_for_savepoint_capture(reservation, lineage, self.resources, retention)?;
        SubmitAttemptRequest::new_savepoint_capture(
            assignment,
            reservation.daemon_epoch,
            lineage,
            reservation.capture.attempt,
            self.resources,
            retention,
            reservation.request,
            reservation.capture.configuration,
        )
    }

    fn reset_scan(&mut self) {
        self.cursor = None;
        self.settled_snapshot = None;
    }

    fn reset_capture_scan(&mut self) {
        self.capture_cursor = None;
        self.capture_settled_snapshot = None;
        self.capture_scan_requires_full_pass = false;
    }

    fn defer_savepoint_capture(
        &mut self,
        request: CampaignFactId,
        scan_after: SavepointCaptureCursor,
    ) {
        if self.deferred_capture_requests.len() == self.scan_limit {
            self.deferred_capture_requests.clear();
        }
        self.deferred_capture_requests.insert(request);
        self.prefer_capture_new_work = false;
        self.capture_cursor = Some(scan_after);
        self.capture_settled_snapshot = None;
    }

    fn cancel_savepoint_capture(
        &mut self,
        campaign: &str,
        active: ActiveSavepointCapturePoll,
    ) -> Result<CampaignExecutorCancelOutcome, CampaignExecutorDriverError<S::Error>>
    where
        S: ExecutorControlService,
    {
        if active.cancellation_requested {
            let outcome = self.poll_savepoint_capture(campaign, active)?;
            return capture_step_as_cancel(outcome).map_err(Into::into);
        }
        let request = CancelAttemptExecutionRequest::new(&active.assignment, active.execution)?;
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
                let Some(held) = self
                    .active_captures
                    .get_mut(&active.reservation.worker_slot)
                else {
                    return Err(AttemptQueueError::ReservationMismatch.into());
                };
                held.cancellation_requested = true;
                Ok(
                    CampaignExecutorCancelOutcome::CaptureCancellationRequested {
                        request: active.reservation.request,
                        attempt: active.reservation.capture.attempt,
                        execution: active.execution,
                        already_canceled,
                    },
                )
            }
            CancelAttemptExecutionDisposition::AlreadyCompleted { observation } => {
                Ok(CampaignExecutorCancelOutcome::CaptureUnexpectedCompletion {
                    request: active.reservation.request,
                    attempt: active.reservation.capture.attempt,
                    observation,
                })
            }
            CancelAttemptExecutionDisposition::NotCurrent => {
                self.release_savepoint_capture(&active.reservation)?;
                self.defer_savepoint_capture(
                    active.reservation.request,
                    active.reservation.scan_after,
                );
                Ok(CampaignExecutorCancelOutcome::CaptureAssignmentRenewed {
                    request: active.reservation.request,
                    attempt: active.reservation.capture.attempt,
                })
            }
        }
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
            GetAttemptExecutionDisposition::TerminalFailure => {
                let expected = self.repository.head(campaign)?.snapshot_id();
                let result = self.repository.close_attempt_non_modeled(
                    campaign,
                    expected,
                    active.reservation.attempt(),
                    NonModeledAttemptDisposition::TerminalWorkerFailure,
                )?;
                self.queue.release(active.reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::Closed(result))
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
            ResumeAttemptExecutionDisposition::Rejected {
                reason: ExecutorRejection::TerminalFailure,
            } => {
                let expected = self.repository.head(campaign)?.snapshot_id();
                let result = self.repository.close_attempt_non_modeled(
                    campaign,
                    expected,
                    reservation.attempt(),
                    NonModeledAttemptDisposition::TerminalWorkerFailure,
                )?;
                self.queue.release(reservation)?;
                self.active_executions.remove(&worker_slot);
                self.reset_scan();
                Ok(CampaignExecutorStepOutcome::Closed(result))
            }
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

fn capture_step_as_cancel(
    outcome: CampaignExecutorStepOutcome,
) -> Result<CampaignExecutorCancelOutcome, CampaignRepositoryError> {
    match outcome {
        CampaignExecutorStepOutcome::CaptureRunning {
            request,
            attempt,
            execution,
            ..
        } => Ok(CampaignExecutorCancelOutcome::CaptureCancellationPending {
            request,
            attempt,
            execution,
        }),
        CampaignExecutorStepOutcome::CaptureResolved {
            result,
            attempt,
            execution,
            ..
        } => Ok(CampaignExecutorCancelOutcome::CaptureResolved {
            result,
            attempt,
            execution,
        }),
        CampaignExecutorStepOutcome::CaptureAssignmentRenewed { request, attempt } => {
            Ok(CampaignExecutorCancelOutcome::CaptureAssignmentRenewed { request, attempt })
        }
        CampaignExecutorStepOutcome::CaptureUnexpectedCompletion {
            request,
            attempt,
            observation,
        } => Ok(CampaignExecutorCancelOutcome::CaptureUnexpectedCompletion {
            request,
            attempt,
            observation,
        }),
        CampaignExecutorStepOutcome::CaptureAlreadyResolved { .. }
        | CampaignExecutorStepOutcome::CaptureBlocked { .. }
        | CampaignExecutorStepOutcome::CaptureRetryScheduled { .. }
        | CampaignExecutorStepOutcome::CaptureScanPending { .. }
        | CampaignExecutorStepOutcome::Inactive { .. }
        | CampaignExecutorStepOutcome::ScanPending { .. }
        | CampaignExecutorStepOutcome::ScanRestarted { .. }
        | CampaignExecutorStepOutcome::Idle { .. }
        | CampaignExecutorStepOutcome::Running { .. }
        | CampaignExecutorStepOutcome::Checkpointed { .. }
        | CampaignExecutorStepOutcome::RetryScheduled { .. }
        | CampaignExecutorStepOutcome::Blocked { .. }
        | CampaignExecutorStepOutcome::AssignmentRenewed { .. }
        | CampaignExecutorStepOutcome::AlreadyResolved { .. }
        | CampaignExecutorStepOutcome::Incorporated(_)
        | CampaignExecutorStepOutcome::Closed(_) => Err(CampaignRepositoryError::InvalidRequest {
            reason: "savepoint-capture-cancellation-produced-invalid-driver-outcome",
        }),
    }
}

fn capture_step_as_checkpoint(
    outcome: CampaignExecutorStepOutcome,
) -> Result<CampaignExecutorCheckpointOutcome, CampaignRepositoryError> {
    match outcome {
        CampaignExecutorStepOutcome::CaptureRunning {
            request,
            attempt,
            execution,
            ..
        } => Ok(CampaignExecutorCheckpointOutcome::CaptureInProgress {
            request,
            attempt,
            execution,
        }),
        CampaignExecutorStepOutcome::CaptureResolved {
            result,
            attempt,
            execution,
            checkpoint,
        } => Ok(CampaignExecutorCheckpointOutcome::CaptureResolved {
            result,
            attempt,
            execution,
            checkpoint,
        }),
        CampaignExecutorStepOutcome::CaptureAssignmentRenewed { request, attempt } => {
            Ok(CampaignExecutorCheckpointOutcome::CaptureAssignmentRenewed { request, attempt })
        }
        CampaignExecutorStepOutcome::CaptureUnexpectedCompletion {
            request,
            attempt,
            observation,
        } => Ok(
            CampaignExecutorCheckpointOutcome::CaptureUnexpectedCompletion {
                request,
                attempt,
                observation,
            },
        ),
        CampaignExecutorStepOutcome::CaptureAlreadyResolved { .. }
        | CampaignExecutorStepOutcome::CaptureBlocked { .. }
        | CampaignExecutorStepOutcome::CaptureRetryScheduled { .. }
        | CampaignExecutorStepOutcome::CaptureScanPending { .. }
        | CampaignExecutorStepOutcome::Inactive { .. }
        | CampaignExecutorStepOutcome::ScanPending { .. }
        | CampaignExecutorStepOutcome::ScanRestarted { .. }
        | CampaignExecutorStepOutcome::Idle { .. }
        | CampaignExecutorStepOutcome::Running { .. }
        | CampaignExecutorStepOutcome::Checkpointed { .. }
        | CampaignExecutorStepOutcome::RetryScheduled { .. }
        | CampaignExecutorStepOutcome::Blocked { .. }
        | CampaignExecutorStepOutcome::AssignmentRenewed { .. }
        | CampaignExecutorStepOutcome::AlreadyResolved { .. }
        | CampaignExecutorStepOutcome::Incorporated(_)
        | CampaignExecutorStepOutcome::Closed(_) => Err(CampaignRepositoryError::InvalidRequest {
            reason: "savepoint-capture-checkpoint-produced-invalid-driver-outcome",
        }),
    }
}

fn assignment_for_savepoint_capture(
    reservation: &SavepointCaptureReservation,
    lineage: CampaignLineageId,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
) -> Result<AssignmentId, CampaignCodecError> {
    let mut basis = Vec::new();
    basis.extend_from_slice(&reservation.daemon_epoch.as_bytes());
    basis.extend_from_slice(lineage.content_id().encode().as_bytes());
    basis.extend_from_slice(reservation.request.content_id().encode().as_bytes());
    basis.extend_from_slice(reservation.capture.attempt.content_id().encode().as_bytes());
    basis.extend_from_slice(
        reservation
            .capture
            .configuration
            .content_id()
            .encode()
            .as_bytes(),
    );
    basis.extend_from_slice(&reservation.worker_slot.get().to_be_bytes());
    basis.extend_from_slice(&reservation.generation.to_be_bytes());
    basis.extend_from_slice(&resources.maximum_vcpus().to_be_bytes());
    basis.extend_from_slice(&resources.maximum_resident_bytes().to_be_bytes());
    basis.extend_from_slice(&resources.maximum_disk_bytes().to_be_bytes());
    basis.extend_from_slice(&resources.maximum_execution_quanta().to_be_bytes());
    basis.push(match retention {
        ExecutionRetentionIntent::Discard => 0,
        ExecutionRetentionIntent::RetainOnFailure => 1,
        ExecutionRetentionIntent::RetainAlways => 2,
    });
    let digest = CampaignHash::derive(
        "crucible.campaign.local-savepoint-capture-assignment.v1",
        &basis,
    )
    .as_bytes();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[0] |= 0x80;
    AssignmentId::from_bytes(bytes)
}

fn savepoint_resolution_command(
    request: CampaignFactId,
    execution: ExecutionId,
    outcome: SavepointCaptureOutcome,
    snapshot: CampaignSnapshotId,
) -> CampaignCommandId {
    let mut basis = Vec::new();
    basis.extend_from_slice(request.content_id().encode().as_bytes());
    basis.extend_from_slice(&execution.as_bytes());
    basis.push(match outcome {
        SavepointCaptureOutcome::Ready => 0,
        SavepointCaptureOutcome::Canceled => 1,
        SavepointCaptureOutcome::Failed => 2,
        SavepointCaptureOutcome::Discarded => 3,
    });
    basis.extend_from_slice(snapshot.content_id().encode().as_bytes());
    CampaignCommandId::from_hash(CampaignHash::derive(
        "crucible.campaign.local-savepoint-capture-resolution-command.v1",
        &basis,
    ))
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
    /// One bounded capture page was consumed before semantic queue scanning.
    CaptureScanPending {
        /// Exact snapshot owning the operational projection.
        snapshot: CampaignSnapshotId,
    },
    /// The executor accepted or still owns one scoped savepoint capture.
    CaptureRunning {
        /// Immutable fact that owns the operational execution scope.
        request: CampaignFactId,
        /// Existing semantic attempt being independently reexecuted.
        attempt: AttemptId,
        /// Exact local execution incarnation returned by the executor.
        execution: ExecutionId,
        /// Whether this call first admitted the scoped execution.
        newly_accepted: bool,
    },
    /// One authenticated scoped status resolved a savepoint capture.
    CaptureResolved {
        /// Durable campaign resolution fact and successor snapshot.
        result: SavepointCaptureResolutionResult,
        /// Existing semantic attempt that was independently reexecuted.
        attempt: AttemptId,
        /// Exact local execution incarnation whose status was authenticated.
        execution: ExecutionId,
        /// Ready capture root, absent for canceled or failed outcomes.
        checkpoint: Option<ExactCheckpointId>,
    },
    /// Another owner already resolved a held scoped capture.
    CaptureAlreadyResolved {
        /// Immutable capture request whose lease was released.
        request: CampaignFactId,
        /// Authenticated snapshot containing its resolution.
        snapshot: CampaignSnapshotId,
    },
    /// A transient executor condition released a capture for fresh assignment.
    CaptureRetryScheduled {
        /// Immutable fact that remains pending.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
        /// Retryable executor rejection.
        reason: ExecutorRejection,
    },
    /// A stable executor rejection retained the scoped capture lease.
    CaptureBlocked {
        /// Immutable fact whose operational execution could not start.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
        /// Stable executor rejection requiring operator or configuration action.
        reason: ExecutorRejection,
    },
    /// A stale scoped execution released the capture for a fresh generation.
    CaptureAssignmentRenewed {
        /// Immutable fact that remains pending.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
    },
    /// A scoped capture returned an ordinary observation instead of pausing.
    CaptureUnexpectedCompletion {
        /// Immutable fact whose executor violated the capture contract.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
        /// Unexpected ordinary observation retained by the executor.
        observation: ObservationId,
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
    /// A scoped capture reservation had not reached the executor and was released.
    CaptureReleased {
        /// Immutable capture request that remains pending for campaign resume.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
    },
    /// A scoped capture remains active under its already-latched checkpoint request.
    CaptureInProgress {
        /// Immutable capture request being driven to its modeled stop.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
        /// Exact local execution incarnation.
        execution: ExecutionId,
    },
    /// An authenticated terminal status resolved one scoped capture.
    CaptureResolved {
        /// Durable campaign resolution fact and successor snapshot.
        result: SavepointCaptureResolutionResult,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
        /// Exact local execution incarnation.
        execution: ExecutionId,
        /// Ready capture root, absent for canceled or failed outcomes.
        checkpoint: Option<ExactCheckpointId>,
    },
    /// A stale scoped execution released the capture for fresh assignment.
    CaptureAssignmentRenewed {
        /// Immutable capture request that remains pending.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
    },
    /// A scoped capture unexpectedly returned an ordinary observation.
    CaptureUnexpectedCompletion {
        /// Immutable capture request whose executor violated the contract.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
        /// Unexpected observation retained by the executor.
        observation: ObservationId,
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
    /// A scoped capture reservation had not reached the executor and was released.
    CaptureReleased {
        /// Immutable capture request that remains pending for campaign resume.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
    },
    /// The executor durably accepted cancellation of one scoped capture.
    CaptureCancellationRequested {
        /// Immutable capture request being canceled.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
        /// Exact local execution incarnation.
        execution: ExecutionId,
        /// Whether cancellation had already been accepted.
        already_canceled: bool,
    },
    /// A canceled capture is awaiting a terminal authenticated status.
    CaptureCancellationPending {
        /// Immutable capture request being canceled.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
        /// Exact local execution incarnation.
        execution: ExecutionId,
    },
    /// An authenticated terminal status resolved one capture during cancellation.
    CaptureResolved {
        /// Durable campaign resolution fact and successor snapshot.
        result: SavepointCaptureResolutionResult,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
        /// Exact local execution incarnation.
        execution: ExecutionId,
    },
    /// A stale scoped execution released the capture for fresh assignment.
    CaptureAssignmentRenewed {
        /// Immutable capture request that remains pending.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
    },
    /// A scoped capture unexpectedly returned an ordinary observation.
    CaptureUnexpectedCompletion {
        /// Immutable capture request whose executor violated the contract.
        request: CampaignFactId,
        /// Existing semantic attempt named by the capture.
        attempt: AttemptId,
        /// Unexpected observation retained by the executor.
        observation: ObservationId,
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
