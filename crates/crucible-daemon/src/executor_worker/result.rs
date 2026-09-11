//! Attempt-result preparation, journaling, publication, and reconciliation.

use super::*;

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
    result: PendingAttemptResultOwner,
    finding_exact_retention: Option<PreparedFindingExactRetention>,
}

#[derive(Debug)]
enum PendingAttemptResultOwner {
    Legacy {
        observation: ObservationCandidate,
        finding: Option<PreparedCrucibleFindingCandidate>,
    },
    Prepared(PreparedSemanticAttemptResult),
}

impl PendingAttemptResultOwner {
    const fn observation(&self) -> &ObservationCandidate {
        match self {
            Self::Legacy { observation, .. } => observation,
            Self::Prepared(result) => result.observation(),
        }
    }

    const fn finding(&self) -> Option<&PreparedCrucibleFindingCandidate> {
        match self {
            Self::Legacy { finding, .. } => finding.as_ref(),
            Self::Prepared(result) => result.finding(),
        }
    }

    fn prepare(&self) -> Result<PreparedSemanticAttemptResult, PreparedSemanticResultCodecError> {
        match self {
            Self::Legacy {
                observation,
                finding,
            } => PreparedSemanticAttemptResult::new(observation.clone(), finding.clone()),
            Self::Prepared(result) => Ok(result.clone()),
        }
    }
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
    finding_exact_retention: Option<PreparedFindingExactRetention>,
}

#[derive(Debug)]
enum PreparedAttemptResultOwner {
    Volatile(Box<PreparedSemanticAttemptResult>),
    Journal(Box<DirectoryPreparedResultJournal>),
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
            Self::Journal(journal) => Some(*journal),
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

    /// Returns portable replay capture roots already bound into the candidate.
    #[must_use]
    pub fn finding_replay_captures(&self) -> Option<crucible_campaign::FindingReplayCaptureSet> {
        self.result()
            .finding()
            .and_then(|finding| finding.bundle().replay_captures())
    }

    /// Returns selected exact roots that must survive candidate publication.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] if automatic selection
    /// produced more roots than the daemon's three canonical boundary roles.
    pub fn finding_exact_retention_roots(
        &self,
    ) -> Result<[Option<ExactCheckpointId>; 3], PreparedSemanticResultCodecError> {
        let Some(bundle) = self.result().finding().map(|finding| finding.bundle()) else {
            return Ok([None; 3]);
        };
        if !bundle.exact_retention().is_some_and(|retention| {
            retention.disposition() == FindingExactRetentionDisposition::Complete
        }) {
            return Ok([None; 3]);
        }

        let mut roots = [None; 3];
        for (index, checkpoint) in bundle.exact_pins().all().iter().copied().enumerate() {
            let Some(slot) = roots.get_mut(index) else {
                return Err(PreparedSemanticResultCodecError::Inconsistent {
                    component: "automatic finding exact retention root count",
                });
            };
            *slot = Some(checkpoint);
        }
        Ok(roots)
    }

    /// Returns the pending automatic exact-retention handoff, when present.
    #[must_use]
    pub const fn finding_exact_retention(&self) -> Option<&PreparedFindingExactRetention> {
        self.finding_exact_retention.as_ref()
    }

    /// Removes the linear automatic exact-retention handoff for guarded processing.
    pub(crate) fn take_finding_exact_retention(&mut self) -> Option<PreparedFindingExactRetention> {
        self.finding_exact_retention.take()
    }

    /// Encodes transient production captures before any repository write.
    ///
    /// # Errors
    ///
    /// Returns an error when a complete capture no longer authenticates or
    /// exceeds its scenario-derived encoding bound.
    pub(crate) fn production_replay_capture_inputs(
        &self,
    ) -> Result<
        Option<[crate::FindingReplayCaptureInput; 4]>,
        crate::FindingProductionReplayCaptureError,
    > {
        self.result().production_replay_capture_inputs()
    }

    /// Rebuilds a volatile prepared finding around durable capture roots.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when this token already
    /// owns a journal or the rebuilt finding candidate is inconsistent.
    pub(crate) fn bind_production_replay_captures(
        &mut self,
        captures: crucible_campaign::FindingReplayCaptureSet,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        let PreparedAttemptResultOwner::Volatile(current) = &self.result else {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay captures attached after journaling",
            });
        };
        let finding = current.prepare_bound_production_replay_finding(captures)?;
        let finding_candidate = Some(finding.id()?);

        let PreparedAttemptResultOwner::Volatile(result) = &mut self.result else {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay capture owner changed during binding",
            });
        };
        result.commit_bound_production_replay_finding(finding);
        self.finding_candidate = finding_candidate;
        Ok(())
    }

    /// Rebuilds the volatile finding around selected exact pins and retention evidence.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when this token already
    /// owns a journal or the rebuilt finding is inconsistent.
    pub(crate) fn bind_finding_exact_retention(
        &mut self,
        exact_pins: FindingExactPins,
        retention: FindingExactRetention,
        evidence: Option<crucible_campaign::FindingExactRetentionEvidence>,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        let PreparedAttemptResultOwner::Volatile(current) = &self.result else {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding exact retention attached after journaling",
            });
        };
        let finding =
            current.prepare_bound_finding_exact_retention(exact_pins, retention, evidence)?;
        let finding_candidate = Some(finding.id()?);

        let PreparedAttemptResultOwner::Volatile(result) = &mut self.result else {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding exact retention owner changed during binding",
            });
        };
        result.commit_bound_production_replay_finding(finding);
        self.finding_candidate = finding_candidate;
        Ok(())
    }

    /// Returns the exact prepared semantic closure.
    #[must_use]
    pub const fn result(&self) -> &PreparedSemanticAttemptResult {
        self.result.result()
    }

    /// Returns the digest that binds the complete prepared recovery payload.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when the result cannot be
    /// encoded under its format ceiling.
    pub(crate) fn prepared_result_digest(
        &self,
    ) -> Result<CampaignHash, PreparedSemanticResultCodecError> {
        match &self.result {
            PreparedAttemptResultOwner::Volatile(result) => Ok(CampaignHash::derive(
                "crucible.executor.prepared-result-ledger-binding.v1",
                &result.canonical_bytes()?,
            )),
            PreparedAttemptResultOwner::Journal(journal) => Ok(journal.prepared_result_digest()),
        }
    }

    /// Recovers the execution token when durable journal ownership was never acquired.
    pub(crate) fn into_queued_without_journal(self) -> Result<QueuedAttempt, Box<Self>> {
        let Self {
            queued,
            result,
            observation,
            finding_candidate,
            finding_exact_retention,
        } = self;
        match result {
            PreparedAttemptResultOwner::Volatile(_) => Ok(queued),
            PreparedAttemptResultOwner::Journal(journal) => Err(Box::new(Self {
                queued,
                result: PreparedAttemptResultOwner::Journal(journal),
                observation,
                finding_candidate,
                finding_exact_retention,
            })),
        }
    }

    pub(crate) fn remove_journal(&self) -> Result<(), PreparedResultJournalError> {
        match &self.result {
            PreparedAttemptResultOwner::Volatile(_) => Ok(()),
            PreparedAttemptResultOwner::Journal(journal) => journal.remove(),
        }
    }

    /// Promotes a hidden prepared-result journal after publication-root staging.
    pub(crate) fn commit_staged_journal(mut self) -> Result<Self, AttemptResultJournalError> {
        if let PreparedAttemptResultOwner::Journal(journal) = &mut self.result
            && let Err(source) = journal.commit_staged()
        {
            return Err(AttemptResultJournalError {
                prepared: Box::new(self),
                source,
            });
        }
        Ok(self)
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
    pub source: PreparedResultJournalError,
}

/// Durable prepared-result recovery failure retaining the fresh execution token.
#[derive(Debug, thiserror::Error)]
#[error("local prepared-result journal recovery failed")]
pub struct AttemptResultRecoveryError {
    /// Fresh supervisor execution token that has not run guest work.
    pub queued: Box<QueuedAttempt>,
    /// Journal or semantic authentication failure.
    pub source: AttemptResultRecoveryFailure,
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
    /// Portable capture manifests or chunks were absent or inconsistent.
    #[error(transparent)]
    CaptureStore(#[from] crate::FindingReplayCaptureStoreError),
    /// Reassembled production replay bytes failed canonical authentication.
    #[error(transparent)]
    ProductionReplay(#[from] crate::FindingProductionReplayCaptureError),
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

#[cfg(test)]
#[allow(clippy::expect_used)]
impl StagedAttemptResult {
    pub(crate) fn from_test_parts(
        queued: QueuedAttempt,
        result: PreparedSemanticAttemptResult,
    ) -> Self {
        let observation = result
            .observation()
            .observation()
            .id()
            .expect("test staged observation ID");
        let finding_candidate = result
            .finding()
            .map(PreparedCrucibleFindingCandidate::id)
            .transpose()
            .expect("test staged finding candidate ID");
        Self {
            prepared: PreparedAttemptResult {
                queued,
                result: PreparedAttemptResultOwner::Volatile(Box::new(result)),
                observation,
                finding_candidate,
                finding_exact_retention: None,
            },
        }
    }
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
    publication: AttemptCheckpointPublication,
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
    /// Returns the exact execution token owned by this publication phase.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        self.prepared.queued()
    }

    /// Returns the prepared token after an early publication-root transition.
    #[must_use]
    pub(crate) fn into_prepared(self) -> PreparedAttemptResult {
        self.prepared
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

    /// Consumes the pending value into its linear token, candidate, and capture owner.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        QueuedAttempt,
        ObservationCandidate,
        Option<PreparedFindingExactRetention>,
    ) {
        let candidate = match self.result {
            PendingAttemptResultOwner::Legacy { observation, .. } => observation,
            PendingAttemptResultOwner::Prepared(result) => result.into_parts().0,
        };
        (self.queued, candidate, self.finding_exact_retention)
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
        source: PreparedResultJournalError,
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
        /// Native capture authority rejected after model execution.
        retirement: Option<NativeCheckpointCleanup>,
    },
    /// Candidate preflight failed without writing immutable objects.
    #[error("local attempt result preflight failed")]
    Candidate {
        /// Already-executed candidate retained for direct retry.
        pending: Box<PendingAttemptResult>,
        /// Repository failure from the read-only preflight.
        source: AttemptResultPreparationFailure,
    },
    /// Exact capture preparation failed without publishing immutable objects.
    #[error("local exact-checkpoint preparation failed")]
    Checkpoint {
        /// Captured checkpoint retained for direct preparation retry.
        pending: Box<PendingCheckpointResult>,
        /// Exact-checkpoint store failure from the no-write preparation phase.
        source: ExactCheckpointStoreError,
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
    pub source: L,
}

/// Stable completion-abort failure retaining the published candidate token.
#[derive(Debug, thiserror::Error)]
#[error("local attempt completion abort failed")]
pub struct PublishedAttemptResultAbortError<L> {
    /// Published candidate retained for an exact cancellation retry.
    pub published: Box<PublishedAttemptResult>,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

/// Installs the durable checkpoint root with a short supervisor CAS.
///
/// The consumed token is returned on every actor failure, so a ledger error
/// never forces QEMU execution or checkpoint capture to repeat.
///
/// # Errors
///
/// Returns [`CheckpointResultStagingError`] with the complete prepared token
/// when the operational ledger cannot safely establish the root.
pub fn stage_prepared_checkpoint_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    prepared: PreparedCheckpointResult,
) -> Result<CheckpointResultStageOutcome, CheckpointResultStagingError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let checkpoint = prepared.root();
    let stage = match supervisor.stage_checkpoint_publication(prepared.queued(), checkpoint) {
        Ok(stage) => stage,
        Err(source) => {
            return Err(CheckpointResultStagingError {
                prepared: Box::new(prepared),
                source,
            });
        }
    };
    match stage {
        CheckpointPublicationOutcome::Staged | CheckpointPublicationOutcome::AlreadyStaged => Ok(
            CheckpointResultStageOutcome::Publish(Box::new(StagedCheckpointResult { prepared })),
        ),
        CheckpointPublicationOutcome::AlreadyPaused | CheckpointPublicationOutcome::NotCurrent => {
            Ok(CheckpointResultStageOutcome::Finished {
                prepared: Box::new(prepared),
                checkpoint,
                outcome: stage,
            })
        }
    }
}

/// Publishes every exact-checkpoint child and its root outside actor ownership.
///
/// # Errors
///
/// Returns [`CheckpointResultPublicationError`] with the staged token when any
/// exact durable placement or authentication step fails.
pub fn publish_staged_checkpoint_result(
    store: &ExactCheckpointStore,
    staged: StagedCheckpointResult,
) -> Result<PublishedCheckpointResult, CheckpointResultPublicationError> {
    let publication = match store.publish_attempt_checkpoint(&staged.prepared.checkpoint) {
        Ok(publication) => publication,
        Err(source) => {
            return Err(CheckpointResultPublicationError {
                staged: Box::new(staged),
                source,
            });
        }
    };
    if let PreparedAttemptCheckpoint::Production(prepared) = &staged.prepared.checkpoint
        && let Err(source) = prepared.retire_native_source()
    {
        return Err(CheckpointResultPublicationError {
            staged: Box::new(staged),
            source,
        });
    }
    Ok(PublishedCheckpointResult {
        queued: staged.prepared.queued,
        publication,
    })
}

/// Promotes one fully published checkpoint to durable paused state.
///
/// The worker/session owner must call this only after QEMU teardown has
/// attested physical process exit. Capacity is released by the successful or
/// idempotent paused-state transition, never merely by publishing bytes.
///
/// # Errors
///
/// Returns [`CheckpointResultReconcileError`] with the published token when
/// the operational ledger cannot safely reconcile the paused state.
pub fn reconcile_published_checkpoint_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    published: PublishedCheckpointResult,
) -> Result<CheckpointCompletionOutcome, CheckpointResultReconcileError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let checkpoint = published.root();
    match supervisor.complete_checkpoint(&published.queued, checkpoint) {
        Ok(outcome) => Ok(outcome),
        Err(source) => Err(CheckpointResultReconcileError {
            published: Box::new(published),
            source,
        }),
    }
}

/// Explicitly abandons one captured checkpoint without re-running the guest.
///
/// Cancellation removes any staged checkpoint root only after the worker has
/// physically returned. Partial immutable objects then become ordinary
/// collection candidates; no active capacity or linear result token is lost.
///
/// # Errors
///
/// Returns [`CheckpointResultAbortError`] with the complete phase token when
/// durable cancellation cannot be reconciled safely.
pub fn abort_checkpoint_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    token: CheckpointResultAbortToken,
) -> Result<CancellationOutcome, CheckpointResultAbortError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(token.queued()) {
        Ok(outcome) => Ok(outcome),
        Err(source) => Err(CheckpointResultAbortError { token, source }),
    }
}

/// Preflights one independently executed worker result outside supervision.
///
/// The caller first obtains [`QueuedAttempt`] with
/// [`LocalExecutorSupervisor::next_queued`], moves that value to a worker
/// thread, and later calls this function without borrowing the supervisor.
/// Repository closure traversal can therefore never block submission or
/// cancellation handling on the actor thread.
///
/// # Errors
///
/// Returns the linear worker token with either its classified worker failure or
/// its candidate when read-only preflight fails.
pub fn prepare_attempt_result<W>(
    store: &CampaignExecutorStore,
    checkpoints: &ExactCheckpointStore,
    work: AttemptWorkResult<W>,
) -> Result<PreparedAttemptWorkResult, AttemptResultPreparationError<W>> {
    let AttemptWorkResult {
        queued,
        result,
        abandoned_checkpoint,
    } = work;
    let product = match result {
        Ok(product) => product,
        Err(failure) => {
            return Err(AttemptResultPreparationError::Worker {
                queued: Box::new(queued),
                failure,
                retirement: abandoned_checkpoint,
            });
        }
    };
    match product {
        AttemptExecutionProduct::Observation(candidate) => prepare_pending_attempt_result(
            store,
            PendingAttemptResult {
                queued,
                result: PendingAttemptResultOwner::Legacy {
                    observation: *candidate,
                    finding: None,
                },
                finding_exact_retention: None,
            },
        )
        .map(|prepared| PreparedAttemptWorkResult::Observation(Box::new(prepared))),
        AttemptExecutionProduct::ObservationWithFinding {
            observation,
            finding,
        } => prepare_pending_attempt_result(
            store,
            PendingAttemptResult {
                queued,
                result: PendingAttemptResultOwner::Legacy {
                    observation: *observation,
                    finding: Some(*finding),
                },
                finding_exact_retention: None,
            },
        )
        .map(|prepared| PreparedAttemptWorkResult::Observation(Box::new(prepared))),
        AttemptExecutionProduct::PreparedSemantic(result) => prepare_pending_attempt_result(
            store,
            PendingAttemptResult {
                queued,
                result: PendingAttemptResultOwner::Prepared(*result),
                finding_exact_retention: None,
            },
        )
        .map(|prepared| PreparedAttemptWorkResult::Observation(Box::new(prepared))),
        AttemptExecutionProduct::PreparedSemanticWithExactRetention { result, retention } => {
            prepare_pending_attempt_result(
                store,
                PendingAttemptResult {
                    queued,
                    result: PendingAttemptResultOwner::Prepared(*result),
                    finding_exact_retention: Some(*retention),
                },
            )
            .map(|prepared| PreparedAttemptWorkResult::Observation(Box::new(prepared)))
        }
        AttemptExecutionProduct::ExactCheckpoint(capture) => prepare_pending_checkpoint_result(
            checkpoints,
            PendingCheckpointResult {
                queued,
                checkpoint: *capture,
            },
        )
        .map(|prepared| PreparedAttemptWorkResult::ExactCheckpoint(Box::new(prepared))),
    }
}

/// Retries read-only preflight of an already-executed candidate.
///
/// # Errors
///
/// Returns the same candidate error with the linear pending token retained.
pub fn retry_pending_attempt_result<W>(
    store: &CampaignExecutorStore,
    pending: PendingAttemptResult,
) -> Result<PreparedAttemptResult, AttemptResultPreparationError<W>> {
    prepare_pending_attempt_result(store, pending)
}

/// Persists a preflighted semantic result before publication can be staged.
///
/// An existing journal must contain the exact same result and producer
/// execution. The returned token owns the per-attempt journal lock until
/// completion or cancellation becomes durable.
///
/// # Errors
///
/// Returns [`AttemptResultJournalError`] with the complete prepared token when
/// journal creation, reopening, authentication, or durability fails.
pub fn journal_prepared_attempt_result(
    namespace: impl AsRef<Path>,
    maximum_payload_bytes: usize,
    prepared: PreparedAttemptResult,
) -> Result<
    (
        PreparedAttemptResult,
        PreparedResultJournalCreateDisposition,
    ),
    AttemptResultJournalError,
> {
    let (prepared, disposition) =
        stage_prepared_attempt_result_journal(namespace, maximum_payload_bytes, prepared)?;
    Ok((prepared.commit_staged_journal()?, disposition))
}

pub(crate) fn stage_prepared_attempt_result_journal(
    namespace: impl AsRef<Path>,
    maximum_payload_bytes: usize,
    mut prepared: PreparedAttemptResult,
) -> Result<
    (
        PreparedAttemptResult,
        PreparedResultJournalCreateDisposition,
    ),
    AttemptResultJournalError,
> {
    let key = crate::AttemptExecutionKey::for_request(prepared.queued.request());
    let execution = prepared.queued.execution();
    let result = prepared.result().clone();
    let (journal, disposition) = match DirectoryPreparedResultJournal::prepare_staged(
        namespace,
        key,
        execution,
        maximum_payload_bytes,
        result,
    ) {
        Ok(created) => created,
        Err(source) => {
            return Err(AttemptResultJournalError {
                prepared: Box::new(prepared),
                source,
            });
        }
    };
    prepared.result = PreparedAttemptResultOwner::Journal(Box::new(journal));
    Ok((prepared, disposition))
}

/// Reopens a complete producer journal before allowing fresh guest execution.
///
/// The fresh `queued` token remains the supervisor reconciliation authority;
/// the journal retains its separately authenticated producer execution ID.
/// Recovered semantic bytes are rechecked against immutable repository input
/// and authenticated scenario measurement definitions.
///
/// # Errors
///
/// Returns [`AttemptResultRecoveryError`] with the fresh execution token when
/// journal or semantic authentication fails.
pub fn recover_prepared_attempt_result(
    store: &CampaignExecutorStore,
    namespace: impl AsRef<Path>,
    maximum_payload_bytes: usize,
    queued: QueuedAttempt,
) -> Result<PreparedAttemptRecoveryOutcome, AttemptResultRecoveryError> {
    let key = crate::AttemptExecutionKey::for_request(queued.request());
    let journal = match DirectoryPreparedResultJournal::open_for_recovery(
        namespace,
        key,
        maximum_payload_bytes,
    ) {
        Ok(Some(journal)) => journal,
        Ok(None) => return Ok(PreparedAttemptRecoveryOutcome::Missing(Box::new(queued))),
        Err(source) => {
            return Err(AttemptResultRecoveryError {
                queued: Box::new(queued),
                source: source.into(),
            });
        }
    };
    let observation = match journal.result().observation().observation().id() {
        Ok(observation) => observation,
        Err(source) => {
            return Err(AttemptResultRecoveryError {
                queued: Box::new(queued),
                source: AttemptResultPreparationFailure::Repository(
                    CampaignRepositoryError::Codec(source),
                )
                .into(),
            });
        }
    };
    let finding_candidate = match journal.result().finding() {
        Some(finding) => match finding.id() {
            Ok(finding) => Some(finding),
            Err(source) => {
                return Err(AttemptResultRecoveryError {
                    queued: Box::new(queued),
                    source: AttemptResultPreparationFailure::Repository(
                        CampaignRepositoryError::Codec(source),
                    )
                    .into(),
                });
            }
        },
        None => None,
    };
    if let Err(source) = validate_prepared_semantic_attempt_result(
        store,
        crate::AttemptExecutionKey::for_request(queued.request()),
        journal.result(),
    ) {
        return Err(AttemptResultRecoveryError {
            queued: Box::new(queued),
            source: source.into(),
        });
    }
    if let Some(captures) = journal
        .result()
        .finding()
        .and_then(|finding| finding.bundle().replay_captures())
    {
        let guard = match store.acquire_finding_replay_publication_guard() {
            Ok(guard) => guard,
            Err(source) => {
                return Err(AttemptResultRecoveryError {
                    queued: Box::new(queued),
                    source: crate::FindingReplayCaptureStoreError::from(source).into(),
                });
            }
        };
        let loaded = match crate::FindingReplayCaptureStore::load_set(&guard, captures) {
            Ok(loaded) => loaded,
            Err(source) => {
                return Err(AttemptResultRecoveryError {
                    queued: Box::new(queued),
                    source: source.into(),
                });
            }
        };
        if let Err(source) = validate_recovered_finding_replay_captures(journal.result(), &loaded) {
            return Err(AttemptResultRecoveryError {
                queued: Box::new(queued),
                source,
            });
        }
    }

    Ok(PreparedAttemptRecoveryOutcome::Prepared(Box::new(
        PreparedAttemptResult {
            queued,
            result: PreparedAttemptResultOwner::Journal(Box::new(journal)),
            observation,
            finding_candidate,
            finding_exact_retention: None,
        },
    )))
}

fn validate_recovered_finding_replay_captures(
    result: &PreparedSemanticAttemptResult,
    loaded: &[crate::LoadedFindingReplayCapture; 4],
) -> Result<(), AttemptResultRecoveryFailure> {
    let finding = result.finding().ok_or({
        AttemptResultPreparationFailure::Result(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay captures without finding",
        })
    })?;
    let limits = finding
        .production_replay_capture_limits()
        .map_err(AttemptResultPreparationFailure::Result)?;
    let bindings = finding
        .production_replay_capture_bindings()
        .map_err(CampaignRepositoryError::Codec)
        .map_err(AttemptResultPreparationFailure::Repository)?;

    for (capture, (reproduction, observed_signature)) in loaded.iter().zip(bindings) {
        let crate::LoadedFindingReplayCapture::Complete {
            bytes,
            content_hash,
        } = capture
        else {
            continue;
        };
        let capture = crate::FindingProductionReplayCapture::from_canonical_bytes(bytes, limits)?;
        if capture.content_hash(limits)? != *content_hash {
            return Err(crate::FindingProductionReplayCaptureError::CaptureBinding.into());
        }
        capture.validate_binding(reproduction, observed_signature)?;
    }
    Ok(())
}

/// Retries no-write preparation of an already-captured exact checkpoint.
///
/// # Errors
///
/// Returns the same checkpoint error with the linear capture token retained.
pub fn retry_pending_checkpoint_result<W>(
    checkpoints: &ExactCheckpointStore,
    pending: PendingCheckpointResult,
) -> Result<PreparedCheckpointResult, AttemptResultPreparationError<W>> {
    prepare_pending_checkpoint_result(checkpoints, pending)
}

fn prepare_pending_attempt_result<W>(
    store: &CampaignExecutorStore,
    pending: PendingAttemptResult,
) -> Result<PreparedAttemptResult, AttemptResultPreparationError<W>> {
    let observation = match pending.candidate().observation().id() {
        Ok(observation) => observation,
        Err(error) => {
            return Err(AttemptResultPreparationError::Candidate {
                pending: Box::new(pending),
                source: CampaignRepositoryError::Codec(error).into(),
            });
        }
    };
    let finding_candidate = match pending.finding() {
        Some(finding) => {
            if finding.bundle().observation() != observation {
                return Err(AttemptResultPreparationError::Candidate {
                    pending: Box::new(pending),
                    source: CampaignRepositoryError::Integrity {
                        reason: "prepared-finding-observation-mismatch",
                    }
                    .into(),
                });
            }
            match finding.id() {
                Ok(candidate) => Some(candidate),
                Err(error) => {
                    return Err(AttemptResultPreparationError::Candidate {
                        pending: Box::new(pending),
                        source: CampaignRepositoryError::Codec(error).into(),
                    });
                }
            }
        }
        None => None,
    };
    let result = match pending.result.prepare() {
        Ok(result) => result,
        Err(source) => {
            return Err(AttemptResultPreparationError::Candidate {
                pending: Box::new(pending),
                source: source.into(),
            });
        }
    };
    let PendingAttemptResult {
        queued,
        result: _,
        finding_exact_retention,
    } = pending;
    if let Err(source) = validate_prepared_semantic_attempt_result(
        store,
        crate::AttemptExecutionKey::for_request(queued.request()),
        &result,
    ) {
        return Err(AttemptResultPreparationError::Candidate {
            pending: Box::new(PendingAttemptResult {
                queued,
                result: PendingAttemptResultOwner::Prepared(result),
                finding_exact_retention,
            }),
            source,
        });
    }
    Ok(PreparedAttemptResult {
        queued,
        result: PreparedAttemptResultOwner::Volatile(Box::new(result)),
        observation,
        finding_candidate,
        finding_exact_retention,
    })
}

fn validate_prepared_observation_candidate(
    store: &CampaignExecutorStore,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), AttemptResultPreparationFailure> {
    let observation_trace_leaves = result
        .observation()
        .measurements()
        .evaluation()
        .into_iter()
        .flat_map(|evaluation| evaluation.evidence().iter().copied())
        .filter(|content| content.kind() == ObjectKind::Trace)
        .collect::<BTreeSet<_>>();
    let owned_trace_leaves = result
        .measurement_replay_evidence()
        .iter()
        .filter_map(|evidence| match evidence.id() {
            Ok(content) if observation_trace_leaves.contains(&content) => Some(
                evidence
                    .canonical_bytes()
                    .map(|bytes| (content, evidence.schema_version(), bytes)),
            ),
            Ok(_) => None,
            Err(source) => Some(Err(source)),
        })
        .collect::<Result<Vec<_>, crate::CrucibleMeasurementError>>()?;
    let owned_trace_leaf_bytes = owned_trace_leaves
        .iter()
        .map(|(content, schema_version, bytes)| (*content, *schema_version, bytes.as_slice()))
        .collect::<Vec<_>>();
    store.validate_observation_candidate_with_owned_trace_leaf_bytes(
        result.observation(),
        &owned_trace_leaf_bytes,
    )?;
    Ok(())
}

/// Authenticates one prepared semantic result against its exact execution key.
///
/// # Errors
///
/// Returns an error when the key is not semantic, the observation differs from
/// the assigned attempt or lineage, or any scenario, measurement, or closure
/// dependency fails authentication.
pub(crate) fn validate_prepared_semantic_attempt_result(
    store: &CampaignExecutorStore,
    expected: crate::AttemptExecutionKey,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), AttemptResultPreparationFailure> {
    if expected.scope() != crucible_campaign::AttemptExecutionScope::Semantic {
        return Err(CampaignRepositoryError::Integrity {
            reason: "prepared-result-nonsemantic-scope",
        }
        .into());
    }
    let lineage = store.load_lineage(expected.lineage())?;
    let observation = result.observation();
    if observation.observation().attempt() != expected.attempt() {
        return Err(CampaignRepositoryError::Integrity {
            reason: "prepared-result-attempt-mismatch",
        }
        .into());
    }
    if observation.child().scenario() != lineage.scenario()
        || observation.child().scenario_artifact() != lineage.scenario_content()
    {
        return Err(CampaignRepositoryError::Integrity {
            reason: "prepared-result-lineage-mismatch",
        }
        .into());
    }
    authenticate_prepared_measurements(store, &lineage, result)?;
    validate_prepared_observation_candidate(store, result)
}

fn authenticate_prepared_measurements(
    store: &CampaignExecutorStore,
    lineage: &CampaignLineage,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), AttemptResultPreparationFailure> {
    let artifact = store.load_scenario_artifact(lineage.scenario_content())?;
    let scenario = crate::decode_crucible_scenario_artifact(&artifact)?;
    result.verify_measurement_publications(&scenario)?;
    result.verify_terminal_fingerprints(&scenario)?;
    Ok(())
}

fn prepare_pending_checkpoint_result<W>(
    checkpoints: &ExactCheckpointStore,
    pending: PendingCheckpointResult,
) -> Result<PreparedCheckpointResult, AttemptResultPreparationError<W>> {
    if !pending.queued.checkpoint_request().is_requested() {
        return Err(AttemptResultPreparationError::Checkpoint {
            pending: Box::new(pending),
            source: ExactCheckpointStoreError::InvalidRoot {
                reason: "execution returned an unsolicited exact checkpoint",
            },
        });
    }
    let PendingCheckpointResult { queued, checkpoint } = pending;
    match checkpoint.into_state() {
        AttemptCheckpointResultState::Prepared(checkpoint) => {
            Ok(PreparedCheckpointResult::new(queued, checkpoint))
        }
        AttemptCheckpointResultState::Captured(capture) => {
            match checkpoints.prepare_attempt_checkpoint(capture.reopenable_copy()) {
                Ok(checkpoint) => Ok(PreparedCheckpointResult::new(queued, checkpoint)),
                Err(source) => Err(AttemptResultPreparationError::Checkpoint {
                    pending: Box::new(PendingCheckpointResult {
                        queued,
                        checkpoint: capture.into(),
                    }),
                    source,
                }),
            }
        }
    }
}

/// Reconciles a worker failure using only short supervisor operations.
///
/// # Errors
///
/// Returns the classified worker failure after requeue or durable stop, or a
/// supervisor error if operational reconciliation fails.
pub fn reconcile_attempt_failure<L, V, W>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    queued: QueuedAttempt,
    failure: AttemptWorkerFailure<W>,
) -> Result<(), AttemptWorkerReconcileError<W, LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            let failure = AttemptWorkerFailure::Retryable(error);
            if queued.cancellation().is_canceled() {
                let cancellation = supervisor.stage_and_reconcile_cancellation(&queued);
                let cancellation = match cancellation {
                    Ok(cancellation) => cancellation,
                    Err(source) => {
                        return Err(AttemptWorkerReconcileError::FailurePending {
                            queued: Box::new(queued),
                            failure,
                            source,
                        });
                    }
                };
                return Err(AttemptWorkerReconcileError::Stopped {
                    failure,
                    cancellation,
                });
            }
            supervisor.requeue(queued);
            Err(AttemptWorkerReconcileError::Worker(failure))
        }
        failure @ AttemptWorkerFailure::Canceled(_) => {
            let cancellation = supervisor.stage_and_reconcile_cancellation(&queued);
            let cancellation = match cancellation {
                Ok(cancellation) => cancellation,
                Err(source) => {
                    return Err(AttemptWorkerReconcileError::FailurePending {
                        queued: Box::new(queued),
                        failure,
                        source,
                    });
                }
            };
            Err(AttemptWorkerReconcileError::Stopped {
                failure,
                cancellation,
            })
        }
        failure @ AttemptWorkerFailure::Terminal(_) => {
            let terminal_failure = supervisor.stage_and_reconcile_terminal_failure(&queued);
            let terminal_failure = match terminal_failure {
                Ok(terminal_failure) => terminal_failure,
                Err(source) => {
                    return Err(AttemptWorkerReconcileError::FailurePending {
                        queued: Box::new(queued),
                        failure,
                        source,
                    });
                }
            };
            Err(AttemptWorkerReconcileError::TerminalStopped {
                failure,
                terminal_failure,
            })
        }
    }
}

/// Establishes the durable publication root with a short supervisor CAS.
///
/// # Errors
///
/// Returns [`LocalExecutorError`] for stale, conflicting, or unavailable
/// operational ledger state.
pub fn stage_prepared_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    prepared: PreparedAttemptResult,
) -> Result<AttemptResultStageOutcome, AttemptResultStagingError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let observation = prepared.observation();
    let finding_candidate = prepared.finding_candidate();
    let finding_replay_captures = prepared.finding_replay_captures();
    if finding_candidate.is_none() && finding_replay_captures.is_some() {
        return Err(AttemptResultStagingError {
            prepared: Box::new(prepared),
            source: LocalExecutorError::LedgerInvariant {
                reason: "finding replay captures have no finding candidate",
            },
        });
    }
    let finding_exact_retention_roots = match prepared.finding_exact_retention_roots() {
        Ok(roots) => roots,
        Err(_) => {
            return Err(AttemptResultStagingError {
                prepared: Box::new(prepared),
                source: LocalExecutorError::LedgerInvariant {
                    reason: "automatic finding exact retention exceeds publication root bound",
                },
            });
        }
    };
    let prepared_result_digest = match prepared.prepared_result_digest() {
        Ok(digest) => Some(digest),
        Err(_) => {
            return Err(AttemptResultStagingError {
                prepared: Box::new(prepared),
                source: LocalExecutorError::LedgerInvariant {
                    reason: "prepared result cannot produce a recovery binding",
                },
            });
        }
    };
    if finding_candidate.is_none() && finding_exact_retention_roots != [None; 3] {
        return Err(AttemptResultStagingError {
            prepared: Box::new(prepared),
            source: LocalExecutorError::LedgerInvariant {
                reason: "finding exact retention roots have no finding candidate",
            },
        });
    }
    let stage_result = supervisor.stage_observation_publication_with_candidate(
        prepared.queued(),
        observation,
        finding_candidate,
        finding_replay_captures,
        finding_exact_retention_roots,
        prepared_result_digest,
    );
    let stage = match stage_result {
        Ok(stage) => stage,
        Err(source) => {
            return Err(AttemptResultStagingError {
                prepared: Box::new(prepared),
                source,
            });
        }
    };
    match stage {
        ObservationPublicationOutcome::Staged | ObservationPublicationOutcome::AlreadyStaged => Ok(
            AttemptResultStageOutcome::Publish(Box::new(StagedAttemptResult { prepared })),
        ),
        ObservationPublicationOutcome::Canceled => Ok(AttemptResultStageOutcome::Finished {
            prepared: Box::new(prepared),
            outcome: AttemptWorkerReconcileOutcome::Discarded {
                observation,
                completion: CompletionOutcome::Canceled,
            },
        }),
        ObservationPublicationOutcome::NotCurrent => Ok(AttemptResultStageOutcome::Finished {
            prepared: Box::new(prepared),
            outcome: AttemptWorkerReconcileOutcome::Discarded {
                observation,
                completion: CompletionOutcome::NotCurrent,
            },
        }),
        ObservationPublicationOutcome::AlreadyCompleted => {
            Ok(AttemptResultStageOutcome::Finished {
                prepared: Box::new(prepared),
                outcome: AttemptWorkerReconcileOutcome::Reconciled {
                    observation,
                    completion: CompletionOutcome::AlreadyCompleted,
                },
            })
        }
    }
}

/// Publishes a preflighted candidate without borrowing the supervisor actor.
///
/// # Errors
///
/// Returns [`AttemptResultPublicationError`] with the complete prepared bundle
/// when immutable storage is temporarily or stably unavailable.
pub fn publish_prepared_attempt_result(
    store: &CampaignExecutorStore,
    staged: Box<StagedAttemptResult>,
) -> Result<PublishedAttemptResult, AttemptResultPublicationError> {
    let _gc_exclusion = if staged.prepared.result().finding().is_some_and(|finding| {
        finding.bundle().replay_captures().is_some() || finding.bundle().exact_retention().is_some()
    }) {
        match store.acquire_finding_replay_publication_guard() {
            Ok(guard) => Some(guard),
            Err(source) => {
                return Err(AttemptResultPublicationError {
                    staged,
                    source: source.into(),
                });
            }
        }
    } else {
        None
    };
    if let Err(source) = publish_prepared_semantic_attempt_result(store, staged.prepared.result()) {
        return Err(AttemptResultPublicationError { staged, source });
    }
    let StagedAttemptResult { prepared } = *staged;
    Ok(PublishedAttemptResult {
        queued: prepared.queued,
        observation: prepared.observation,
        finding_candidate: prepared.finding_candidate,
        journal: prepared.result.into_journal(),
    })
}

/// Publishes a preflighted semantic closure in dependency order.
///
/// Callers must first complete [`validate_prepared_semantic_attempt_result`].
/// Packaged callers retain the staged publication owner while this function
/// writes; the synchronous standalone caller owns its private repository.
///
/// # Errors
///
/// Returns an error when raw evidence cannot derive its declared identity or
/// any trace, observation, or finding object cannot be published exactly.
pub(crate) fn publish_prepared_semantic_attempt_result(
    store: &CampaignExecutorStore,
    result: &PreparedSemanticAttemptResult,
) -> Result<ObservationId, AttemptResultPublicationFailure> {
    for evidence in result.measurement_replay_evidence() {
        let expected = match evidence.id() {
            Ok(expected) => expected,
            Err(source) => return Err(AttemptResultPublicationFailure::Measurement(source)),
        };
        let bytes = match evidence.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(source) => return Err(AttemptResultPublicationFailure::Measurement(source)),
        };
        store.publish_executor_trace_leaf(expected, evidence.schema_version(), &bytes)?;
    }
    let observation = store.publish_observation_candidate(result.observation())?;
    if let Some(finding) = result.finding() {
        finding.publish_for_executor(store)?;
    }
    Ok(observation)
}

/// Aborts a stably conflicting prepared publication before immutable writes.
///
/// # Errors
///
/// Returns [`AttemptResultStagingError`] with the linear prepared token when
/// durable cancellation cannot yet be reconciled.
pub fn abort_prepared_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    prepared: PreparedAttemptResult,
) -> Result<
    (CancellationOutcome, PreparedAttemptResult),
    AttemptResultStagingError<LocalExecutorError<L::Error>>,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(prepared.queued()) {
        Ok(outcome) => Ok((outcome, prepared)),
        Err(source) => Err(AttemptResultStagingError {
            prepared: Box::new(prepared),
            source,
        }),
    }
}

/// Result of attempting to cancel one staged result without losing its owner.
pub type AttemptResultAbortOutcome<E> = Result<
    (CancellationOutcome, Box<StagedAttemptResult>),
    AttemptResultAbortError<LocalExecutorError<E>>,
>;

/// Aborts a stably failed staged publication without re-running the guest.
///
/// # Errors
///
/// Returns [`AttemptResultAbortError`] with the linear staged token when the
/// durable cancellation cannot yet be reconciled.
pub fn abort_staged_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    staged: Box<StagedAttemptResult>,
) -> AttemptResultAbortOutcome<L::Error>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(staged.prepared.queued()) {
        Ok(outcome) => Ok((outcome, staged)),
        Err(source) => Err(AttemptResultAbortError { staged, source }),
    }
}

/// Aborts a published result after stable completion reconciliation failure.
///
/// The immutable candidate remains content-addressed and may be collected when
/// its canceled publication root is no longer retained. This operation changes
/// only operational execution state and never fabricates campaign meaning.
///
/// # Errors
///
/// Returns [`PublishedAttemptResultAbortError`] with the linear published token
/// when durable cancellation cannot yet be reconciled.
pub fn abort_published_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    published: PublishedAttemptResult,
) -> Result<
    (CancellationOutcome, PublishedAttemptResult),
    PublishedAttemptResultAbortError<LocalExecutorError<L::Error>>,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(&published.queued) {
        Ok(outcome) => Ok((outcome, published)),
        Err(source) => Err(PublishedAttemptResultAbortError {
            published: Box::new(published),
            source,
        }),
    }
}

/// Reconciles one already-published result with a short supervisor operation.
///
/// # Errors
///
/// Returns [`AttemptWorkerReconcileError::CompletionPending`] when durable
/// completion validation or ledger reconciliation fails.
pub fn reconcile_published_attempt_result<L, V, W>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    published: PublishedAttemptResult,
) -> Result<
    AttemptWorkerReconcileOutcome,
    AttemptWorkerReconcileError<W, LocalExecutorError<L::Error>>,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let observation = published.observation;
    let completion = match supervisor.stage_and_reconcile_completion_with_finding_candidate(
        &published.queued,
        published.observation,
        published.finding_candidate,
    ) {
        Ok(completion) => completion,
        Err(source) => {
            return Err(AttemptWorkerReconcileError::CompletionPending {
                published: Box::new(published),
                source,
            });
        }
    };
    if let Err(source) = published.remove_journal() {
        return Err(AttemptWorkerReconcileError::JournalCleanupPending {
            published: Box::new(published),
            source,
        });
    }
    Ok(AttemptWorkerReconcileOutcome::Reconciled {
        observation,
        completion,
    })
}
