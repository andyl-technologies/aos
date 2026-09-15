//! Prepared attempt results and their owned publication state.

use super::*;

mod operations;

pub use operations::*;

/// Result of reconciling one finished worker operation with supervision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptWorkerReconcileOutcome {
    /// An immutable observation was published and reconciled with supervision.
    Reconciled {
        /// Published canonical observation candidate.
        observation: ObservationId,
        /// Durable operational completion race outcome.
        completion: CompletionOutcome,
    },
    /// Publication was skipped because cancellation or staleness already won.
    Discarded {
        /// Deterministic candidate identity that was not written by this phase.
        observation: ObservationId,
        /// Cancellation or stale-execution disposition.
        completion: CompletionOutcome,
    },
}

/// Already-executed candidate retained for publication retry without guest work.
#[derive(Debug)]
pub struct PendingAttemptResult {
    queued: QueuedAttempt,
    result: PreparedSemanticAttemptResult,
}

/// Captured checkpoint retained for no-write preparation retry.
#[derive(Debug)]
pub struct PendingCheckpointResult {
    queued: QueuedAttempt,
    checkpoint: AttemptCheckpointResult,
}

impl PendingCheckpointResult {
    /// Returns the exact execution whose capture awaits preparation.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the captured metadata and opaque VMState source.
    #[must_use]
    pub const fn checkpoint(&self) -> &AttemptCheckpointResult {
        &self.checkpoint
    }

    /// Consumes the pending value into its execution token and capture.
    #[must_use]
    pub fn into_parts(self) -> (QueuedAttempt, AttemptCheckpointResult) {
        (self.queued, self.checkpoint)
    }
}

/// Read-only-preflighted result ready for a short publication-root CAS.
#[derive(Debug)]
pub struct PreparedAttemptResult {
    queued: QueuedAttempt,
    result: PreparedAttemptResultOwner,
    observation: ObservationId,
    finding_candidate: Option<crucible_campaign::FindingCandidateBundleId>,
}

#[derive(Debug)]
enum PreparedAttemptResultOwner {
    Volatile(PreparedSemanticAttemptResult),
    Journal(DirectoryPreparedResultJournal),
}

impl PreparedAttemptResultOwner {
    const fn result(&self) -> &PreparedSemanticAttemptResult {
        match self {
            Self::Volatile(result) => result,
            Self::Journal(journal) => journal.result(),
        }
    }

    fn into_journal(self) -> Option<DirectoryPreparedResultJournal> {
        match self {
            Self::Volatile(_) => None,
            Self::Journal(journal) => Some(journal),
        }
    }
}

impl PreparedAttemptResult {
    /// Returns the exact execution token.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the preflighted immutable observation identity.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }

    /// Returns the finding root that must be staged with the observation.
    #[must_use]
    pub const fn finding_candidate(&self) -> Option<crucible_campaign::FindingCandidateBundleId> {
        self.finding_candidate
    }

    /// Returns the exact prepared semantic closure.
    #[must_use]
    pub const fn result(&self) -> &PreparedSemanticAttemptResult {
        self.result.result()
    }

    /// Recovers the execution token when durable journal ownership was never acquired.
    pub(crate) fn into_queued_without_journal(self) -> Result<QueuedAttempt, Box<Self>> {
        let Self {
            queued,
            result,
            observation,
            finding_candidate,
        } = self;
        match result {
            PreparedAttemptResultOwner::Volatile(_) => Ok(queued),
            PreparedAttemptResultOwner::Journal(journal) => Err(Box::new(Self {
                queued,
                result: PreparedAttemptResultOwner::Journal(journal),
                observation,
                finding_candidate,
            })),
        }
    }

    pub(crate) fn remove_journal(&self) -> Result<(), PreparedResultJournalError> {
        match &self.result {
            PreparedAttemptResultOwner::Volatile(_) => Ok(()),
            PreparedAttemptResultOwner::Journal(journal) => journal.remove(),
        }
    }
}

/// Result of probing durable prepared-result recovery before guest execution.
#[derive(Debug)]
pub enum PreparedAttemptRecoveryOutcome {
    /// No complete journal exists; the fresh execution token remains runnable.
    Missing(Box<QueuedAttempt>),
    /// A producer result was recovered and must be published without guest work.
    Prepared(Box<PreparedAttemptResult>),
}

/// Durable journal creation failure retaining the complete prepared token.
#[derive(Debug, thiserror::Error)]
#[error("local prepared-result journal creation failed")]
pub struct AttemptResultJournalError {
    /// Prepared result retained for exact journal creation retry.
    pub prepared: Box<PreparedAttemptResult>,
    /// Durable journal failure.
    pub source: Box<PreparedResultJournalError>,
}

/// Durable prepared-result recovery failure retaining the fresh execution token.
#[derive(Debug, thiserror::Error)]
#[error("local prepared-result journal recovery failed")]
pub struct AttemptResultRecoveryError {
    /// Fresh supervisor execution token that has not run guest work.
    pub queued: Box<QueuedAttempt>,
    /// Journal or semantic authentication failure.
    pub source: Box<AttemptResultRecoveryFailure>,
}

/// Failure while reopening and authenticating one durable prepared result.
#[derive(Debug, thiserror::Error)]
pub enum AttemptResultRecoveryFailure {
    /// Durable journal authentication failed.
    #[error(transparent)]
    Journal(#[from] PreparedResultJournalError),
    /// Recovered semantic content failed repository or scenario authentication.
    #[error(transparent)]
    Preparation(#[from] AttemptResultPreparationFailure),
}

/// Candidate whose immutable objects were published outside the supervisor actor.
#[derive(Debug)]
pub struct PublishedAttemptResult {
    queued: QueuedAttempt,
    observation: ObservationId,
    finding_candidate: Option<crucible_campaign::FindingCandidateBundleId>,
    journal: Option<DirectoryPreparedResultJournal>,
}

/// Linear token proving the durable publication root was installed first.
#[derive(Debug)]
pub struct StagedAttemptResult {
    prepared: PreparedAttemptResult,
}

/// Prepared exact checkpoint bound to the sole execution reconciliation token.
#[derive(Debug)]
pub struct PreparedCheckpointResult {
    queued: QueuedAttempt,
    checkpoint: PreparedAttemptCheckpoint,
}

/// Read-only-prepared worker result ready for its short supervisor phase.
#[derive(Debug)]
pub enum PreparedAttemptWorkResult {
    /// Canonical observation candidate ready for publication-root staging.
    Observation(Box<PreparedAttemptResult>),
    /// Exact checkpoint root ready for checkpoint-publication staging.
    ExactCheckpoint(Box<PreparedCheckpointResult>),
}

impl PreparedCheckpointResult {
    /// Binds a no-write checkpoint preparation to its consumed worker token.
    #[must_use]
    pub const fn new(queued: QueuedAttempt, checkpoint: PreparedAttemptCheckpoint) -> Self {
        Self { queued, checkpoint }
    }

    /// Returns the exact execution token.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the exact root that must be staged before publication.
    #[must_use]
    pub const fn root(&self) -> crucible_campaign::ExactCheckpointId {
        self.checkpoint.root()
    }

    pub(crate) fn native_retirement(
        &self,
    ) -> Option<crucible_api::ProductionExactCheckpointRetirement> {
        self.checkpoint.native_retirement()
    }
}

/// Linear proof that a checkpoint publication root is durable.
#[derive(Debug)]
pub struct StagedCheckpointResult {
    prepared: PreparedCheckpointResult,
}

impl StagedCheckpointResult {
    /// Returns the exact execution token owned by this publication phase.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.prepared.queued
    }

    /// Returns the exact staged checkpoint root.
    #[must_use]
    pub const fn root(&self) -> crucible_campaign::ExactCheckpointId {
        self.prepared.root()
    }
}

/// Complete durable checkpoint awaiting the final paused-state CAS.
#[derive(Debug)]
pub struct PublishedCheckpointResult {
    queued: QueuedAttempt,
    publication: ProductionExactCheckpointPublication,
}

impl PublishedCheckpointResult {
    /// Returns the exact execution token owned by paused-state reconciliation.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the complete durable exact-checkpoint root.
    #[must_use]
    pub const fn root(&self) -> crucible_campaign::ExactCheckpointId {
        self.publication.root()
    }
}

/// Actor result of consuming one prepared exact checkpoint.
#[derive(Debug)]
pub enum CheckpointResultStageOutcome {
    /// Immutable publication may proceed outside the supervisor actor.
    Publish(Box<StagedCheckpointResult>),
    /// Another idempotent or terminal state won without further writes.
    Finished {
        /// Prepared token retained so redundant native state can be retired.
        prepared: Box<PreparedCheckpointResult>,
        /// Exact deterministic checkpoint root that was not republished.
        checkpoint: crucible_campaign::ExactCheckpointId,
        /// Durable stage disposition.
        outcome: CheckpointPublicationOutcome,
    },
}

/// Checkpoint-root staging failure retaining the sole prepared token.
#[derive(Debug, thiserror::Error)]
#[error("local exact-checkpoint root staging failed")]
pub struct CheckpointResultStagingError<L> {
    /// Prepared checkpoint retained for exact actor retry.
    pub prepared: Box<PreparedCheckpointResult>,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

/// Checkpoint publication failure retaining the staged token.
#[derive(Debug, thiserror::Error)]
#[error("local exact-checkpoint publication failed")]
pub struct CheckpointResultPublicationError {
    /// Staged checkpoint retained for direct publication retry.
    pub staged: Box<StagedCheckpointResult>,
    /// Immutable-store failure.
    pub source: ExactCheckpointStoreError,
}

/// Paused-state reconciliation failure retaining the published root token.
#[derive(Debug, thiserror::Error)]
#[error("local exact-checkpoint reconciliation failed")]
pub struct CheckpointResultReconcileError<L> {
    /// Published checkpoint retained for exact actor retry.
    pub published: Box<PublishedCheckpointResult>,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

/// Any post-capture checkpoint phase that can be explicitly abandoned.
#[derive(Debug)]
pub enum CheckpointResultAbortToken {
    /// The checkpoint is prepared but has no durable publication root.
    Prepared(Box<PreparedCheckpointResult>),
    /// The root is durable but immutable publication is incomplete.
    Staged(Box<StagedCheckpointResult>),
    /// Immutable publication completed but paused-state reconciliation did not.
    Published(Box<PublishedCheckpointResult>),
}

impl CheckpointResultAbortToken {
    fn queued(&self) -> &QueuedAttempt {
        match self {
            Self::Prepared(prepared) => prepared.queued(),
            Self::Staged(staged) => staged.queued(),
            Self::Published(published) => published.queued(),
        }
    }

    pub(crate) fn native_retirement(
        &self,
    ) -> Option<crucible_api::ProductionExactCheckpointRetirement> {
        match self {
            Self::Prepared(prepared) => prepared.native_retirement(),
            Self::Staged(staged) => staged.prepared.native_retirement(),
            Self::Published(_) => None,
        }
    }
}

/// Explicit checkpoint-abort failure retaining the complete phase token.
#[derive(Debug, thiserror::Error)]
#[error("local exact-checkpoint abort failed")]
pub struct CheckpointResultAbortError<L> {
    /// Captured checkpoint retained for exact cancellation retry.
    pub token: CheckpointResultAbortToken,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

impl StagedAttemptResult {
    pub(crate) const fn new(prepared: PreparedAttemptResult) -> Self {
        Self { prepared }
    }

    /// Returns the exact execution token owned by this publication phase.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        self.prepared.queued()
    }

    pub(crate) fn remove_journal(&self) -> Result<(), PreparedResultJournalError> {
        self.prepared.remove_journal()
    }
}

impl PublishedAttemptResult {
    /// Returns the exact execution token owned by this completion phase.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the published finding candidate retained with completion.
    #[must_use]
    pub const fn finding_candidate(&self) -> Option<crucible_campaign::FindingCandidateBundleId> {
        self.finding_candidate
    }

    pub(crate) fn remove_journal(&self) -> Result<(), PreparedResultJournalError> {
        match &self.journal {
            Some(journal) => journal.remove(),
            None => Ok(()),
        }
    }
}

/// Actor result of consuming one prepared candidate.
#[derive(Debug)]
pub enum AttemptResultStageOutcome {
    /// Immutable publication may now proceed outside the actor.
    Publish(Box<StagedAttemptResult>),
    /// Publication must not run because another operational outcome won.
    Finished {
        /// Prepared ownership retained until journal cleanup is durable.
        prepared: Box<PreparedAttemptResult>,
        /// Stable operational outcome that prevented publication.
        outcome: AttemptWorkerReconcileOutcome,
    },
}

impl PendingAttemptResult {
    /// Returns the exact execution whose result awaits publication.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the already-modeled immutable candidate.
    #[must_use]
    pub const fn candidate(&self) -> &ObservationCandidate {
        self.result.observation()
    }

    /// Returns the prepared finding closure retained with the observation.
    #[must_use]
    pub const fn finding(&self) -> Option<&PreparedCrucibleFindingCandidate> {
        self.result.finding()
    }

    /// Consumes the pending value into its linear token and immutable records.
    #[must_use]
    pub fn into_parts(self) -> (QueuedAttempt, ObservationCandidate) {
        let candidate = self.result.into_parts().0;
        (self.queued, candidate)
    }
}

/// Failure while reconciling a worker result with its supervisor.
#[derive(Debug, thiserror::Error)]
pub enum AttemptWorkerReconcileError<W, L> {
    /// A retryable guest failure left the accepted assignment queued.
    #[error("local attempt worker failed")]
    Worker(AttemptWorkerFailure<W>),
    /// A canceled or terminal failure was durably stopped without retry.
    #[error("local attempt worker stopped without retry")]
    Stopped {
        /// Stable worker-failure classification and diagnostic payload.
        failure: AttemptWorkerFailure<W>,
        /// Durable operational cancellation race outcome.
        cancellation: CancellationOutcome,
    },
    /// A non-retryable failure was durably retained without retry.
    #[error("local attempt worker failed terminally without retry")]
    TerminalStopped {
        /// Stable worker-failure classification and diagnostic payload.
        failure: AttemptWorkerFailure<W>,
        /// Durable terminal-state publication race outcome.
        terminal_failure: TerminalFailureOutcome,
    },
    /// Failure-stop staging did not take ownership; retry with this exact token.
    #[error("local executor failure reconciliation is pending")]
    FailurePending {
        /// Linear execution token not yet owned by supervisor pending state.
        queued: Box<QueuedAttempt>,
        /// Stable worker failure that must not be lost or rerun incorrectly.
        failure: AttemptWorkerFailure<W>,
        /// Supervisor or operational-ledger failure.
        source: L,
    },
    /// Completion staging did not finish; retry with this exact published token.
    #[error("local executor completion reconciliation is pending")]
    CompletionPending {
        /// Published result retained for exact completion retry.
        published: Box<PublishedAttemptResult>,
        /// Supervisor or operational-ledger failure.
        source: L,
    },
    /// Completion is durable but prepared-result journal cleanup must retry.
    #[error("local prepared-result journal cleanup is pending")]
    JournalCleanupPending {
        /// Published result retaining the journal lock for exact cleanup retry.
        published: Box<PublishedAttemptResult>,
        /// Durable journal removal failure.
        source: Box<PreparedResultJournalError>,
    },
}

/// Read-only candidate preflight failure before the supervisor actor is borrowed.
#[derive(Debug, thiserror::Error)]
pub enum AttemptResultPreparationError<W> {
    /// Guest execution failed and still needs short actor reconciliation.
    #[error("local attempt worker failed")]
    Worker {
        /// Exact execution token returned by the worker.
        queued: Box<QueuedAttempt>,
        /// Stable retry, cancellation, or terminal classification.
        failure: AttemptWorkerFailure<W>,
    },
    /// Candidate preflight failed without writing immutable objects.
    #[error("local attempt result preflight failed")]
    Candidate {
        /// Already-executed candidate retained for direct retry.
        pending: Box<PendingAttemptResult>,
        /// Repository failure from the read-only preflight.
        source: Box<AttemptResultPreparationFailure>,
    },
    /// Exact capture preparation failed without publishing immutable objects.
    #[error("local exact-checkpoint preparation failed")]
    Checkpoint {
        /// Captured checkpoint retained for direct preparation retry.
        pending: Box<PendingCheckpointResult>,
        /// Exact-checkpoint store failure from the no-write preparation phase.
        source: Box<ExactCheckpointStoreError>,
    },
}

/// Failure to authenticate a prepared semantic closure before publication.
#[derive(Debug, thiserror::Error)]
pub enum AttemptResultPreparationFailure {
    /// Required immutable campaign input was unavailable or inconsistent.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Authenticated Crucible scenario decoding failed.
    #[error(transparent)]
    Artifact(#[from] crate::CrucibleArtifactError),
    /// A retained raw measurement leaf has an invalid canonical identity.
    #[error(transparent)]
    Measurement(#[from] crate::CrucibleMeasurementError),
    /// Crucible scenario or prepared-result replay validation failed.
    #[error(transparent)]
    Result(#[from] PreparedSemanticResultCodecError),
}

impl AttemptResultPreparationFailure {
    /// Returns the stable executor classification for this preflight failure.
    #[must_use]
    pub fn executor_rejection(&self) -> ExecutorRejection {
        match self {
            Self::Repository(error) => error.executor_rejection(),
            Self::Artifact(_) | Self::Measurement(_) | Self::Result(_) => {
                ExecutorRejection::Incompatible
            }
        }
    }
}

/// Immutable publication failure retaining the preflighted candidate.
#[derive(Debug, thiserror::Error)]
#[error("local attempt result publication failed")]
pub struct AttemptResultPublicationError {
    /// Staged candidate retained for direct publication retry.
    pub staged: Box<StagedAttemptResult>,
    /// Repository failure from immutable publication.
    pub source: AttemptResultPublicationFailure,
}

/// Failure while publishing a verified prepared-result closure.
#[derive(Debug, thiserror::Error)]
pub enum AttemptResultPublicationFailure {
    /// Immutable repository publication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// A retained raw leaf could not reproduce its canonical identity.
    #[error(transparent)]
    Measurement(#[from] crate::CrucibleMeasurementError),
}

impl AttemptResultPublicationFailure {
    /// Returns the stable executor classification for this publication failure.
    #[must_use]
    pub fn executor_rejection(&self) -> ExecutorRejection {
        match self {
            Self::Repository(error) => error.executor_rejection(),
            Self::Measurement(_) => ExecutorRejection::Incompatible,
        }
    }

    /// Returns whether the exact publication can be retried without guest work.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Repository(error)
                if error.executor_rejection() == ExecutorRejection::UnavailableInput
        )
    }
}

/// Publication-root staging failure retaining the sole prepared token.
#[derive(Debug, thiserror::Error)]
#[error("local attempt publication-root staging failed")]
pub struct AttemptResultStagingError<L> {
    /// Preflighted candidate retained for exact actor retry.
    pub prepared: Box<PreparedAttemptResult>,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

/// Stable publication-abort failure retaining the staged candidate token.
#[derive(Debug, thiserror::Error)]
#[error("local attempt publication abort failed")]
pub struct AttemptResultAbortError<L> {
    /// Staged candidate retained for an exact cancellation retry.
    pub staged: Box<StagedAttemptResult>,
    /// Supervisor or operational-ledger failure.
    pub source: LocalExecutorError<L>,
}

/// Stable completion-abort failure retaining the published candidate token.
#[derive(Debug, thiserror::Error)]
#[error("local attempt completion abort failed")]
pub struct PublishedAttemptResultAbortError<L> {
    /// Published candidate retained for an exact cancellation retry.
    pub published: Box<PublishedAttemptResult>,
    /// Supervisor or operational-ledger failure.
    pub source: LocalExecutorError<L>,
}
