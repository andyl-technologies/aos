//! Executor transition outcomes and failure types.

use super::*;

/// Complete campaign transition produced by one executor completion.
///
/// The observation publication may be followed by an atomic finding
/// incorporation. [`Self::final_snapshot`] names the head after both durable
/// transitions. Callers inspect the observation transition separately through
/// [`Self::observation_result`] so an intermediate snapshot cannot be mistaken
/// for the final completion head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignCompletionResult {
    pub(super) observation: ObservationResult,
    pub(super) finding: Option<FindingPublicationResult>,
}

impl CampaignCompletionResult {
    /// Returns the canonical observation publication result.
    #[must_use]
    pub const fn observation_result(&self) -> &ObservationResult {
        &self.observation
    }

    /// Returns the exact campaign head after the complete executor handoff.
    #[must_use]
    pub fn final_snapshot(&self) -> CampaignSnapshotId {
        self.finding
            .map_or(self.observation.new_snapshot, |finding| {
                finding.new_snapshot
            })
    }
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
    Incorporated(CampaignCompletionResult),
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
    Incorporated(CampaignCompletionResult),
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
    Incorporated(CampaignCompletionResult),
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
