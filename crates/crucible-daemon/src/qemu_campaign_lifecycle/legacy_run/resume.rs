//! Selection-free legacy checkpoint admission through campaign ownership.
//!
//! This module authenticates a v3 logical checkpoint, retains the exact
//! source observation and physical capture, and verifies the typed `Ready`
//! and continuation facts before exposing a resume proof to CLI callers.

use super::*;

pub(super) struct GuardedDefaultCampaignResumeSource {
    pub(super) checkpoint: Checkpoint,
    pub(super) final_stop: StopCondition,
    pub(super) checkpoints: Arc<ExactCheckpointStore>,
}

/// Authenticated source admission for a legacy checkpoint resumed by the campaign owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedDefaultCampaignResumeProof {
    source_checkpoint: crucible::ContentHash,
    source_configuration: crucible_campaign::ConfigurationId,
    source_frontier: VirtualTime,
    source_observation: ObservationId,
    source_savepoint: Option<GuardedDefaultCampaignSavepoint>,
    ready: Option<CampaignFactId>,
    selection: Option<CampaignFactId>,
    continuation: Option<crucible_campaign::AttemptId>,
}

impl GuardedDefaultCampaignResumeProof {
    /// Returns the authenticated logical checkpoint supplied by the legacy reader.
    #[must_use]
    pub const fn source_checkpoint(&self) -> crucible::ContentHash {
        self.source_checkpoint
    }

    /// Returns the campaign configuration accepted at the source boundary.
    #[must_use]
    pub const fn source_configuration(&self) -> crucible_campaign::ConfigurationId {
        self.source_configuration
    }

    /// Returns the exact scheduler frontier accepted for the source checkpoint.
    #[must_use]
    pub const fn source_frontier(&self) -> VirtualTime {
        self.source_frontier
    }

    /// Returns the semantic observation that authenticated the source boundary.
    #[must_use]
    pub const fn source_observation(&self) -> ObservationId {
        self.source_observation
    }

    /// Returns the exact source capture used by a continuation, if one was needed.
    #[must_use]
    pub const fn source_savepoint(&self) -> Option<&GuardedDefaultCampaignSavepoint> {
        self.source_savepoint.as_ref()
    }

    /// Returns the exact Ready resolution authorizing continuation, if present.
    #[must_use]
    pub const fn ready(&self) -> Option<CampaignFactId> {
        self.ready
    }

    /// Returns the accepted continuation-selection fact, if present.
    #[must_use]
    pub const fn selection(&self) -> Option<CampaignFactId> {
        self.selection
    }

    /// Returns the authenticated continuation admitted after source capture.
    #[must_use]
    pub const fn continuation(&self) -> Option<crucible_campaign::AttemptId> {
        self.continuation
    }
}

pub(super) struct DefaultRunResumeProof {
    pub(super) source_checkpoint: crucible::ContentHash,
    pub(super) source_configuration: crucible_campaign::ConfigurationId,
    pub(super) source_frontier: VirtualTime,
    pub(super) source_observation: ObservationId,
    pub(super) source_evidence: QemuAttemptExecutionEvidenceSnapshot,
    pub(super) source_capture: Option<DefaultRunSavepointCapture>,
    pub(super) ready_snapshot: Option<CampaignSnapshotId>,
    pub(super) ready: Option<CampaignFactId>,
    pub(super) selection: Option<CampaignFactId>,
    pub(super) continuation: Option<crucible_campaign::AttemptId>,
}

pub(super) enum DefaultRunResumeProgress {
    AwaitingSource,
    Capturing,
    Continuing(Box<DefaultRunResumeProof>),
}

pub(super) fn validate_resume_source<E>(
    request: &GuardedDefaultCampaignRunRequest,
) -> Result<(), GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let Some(source) = &request.resume_source else {
        return Ok(());
    };
    if request.capture_reached_stop.is_some() {
        return Err(GuardedDefaultCampaignInvariantError::ConflictingCheckpointModes.into());
    }
    if !matches!(
        source.final_stop,
        StopCondition::NextChoice
            | StopCondition::Terminal
            | StopCondition::VirtualTimeNanoseconds(_)
    ) {
        return Err(GuardedDefaultCampaignInvariantError::UnsupportedResumeStop.into());
    }
    if request.discovery_stop
        != StopCondition::VirtualTimeNanoseconds(source.checkpoint.virtual_time.ticks)
    {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch.into());
    }
    if request.initial_schedule.decisions().iter().any(|decision| {
        !matches!(
            decision,
            crucible::Decision::DeliveryOrder(_)
                | crucible::Decision::RngDraw(_)
                | crucible::Decision::Preemption(_)
        )
    }) {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch.into());
    }
    let empty_closure =
        GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&request.initial_schedule)
            .map_err(GuardedDefaultCampaignRunError::ReplayClosure)?;
    if request.initial_replay_closure.as_ref() != Some(&empty_closure) {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch.into());
    }
    if request
        .initial_schedule
        .recorded_virtual_time()
        .is_some_and(|latest| source.checkpoint.virtual_time > latest)
    {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch.into());
    }

    // Reconstruct the legacy v3 checkpoint rather than trusting caller-owned
    // state, blob references, metadata, or continuation closure fields.
    let configuration = Configuration {
        def: request.scenario.scenario_def(),
        schedule: request.initial_schedule.clone(),
    };
    let parent = if configuration.schedule.is_empty() {
        None
    } else {
        Some(Configuration {
            def: configuration.def.clone(),
            schedule: configuration
                .schedule
                .prefix(configuration.schedule.len().saturating_sub(1))
                .map_err(crucible::EngineError::SchedulePrefix)
                .map_err(GuardedDefaultCampaignRunError::ResumeCheckpoint)?,
        })
    };
    let expected = Checkpoint::from_recorded_configuration(
        &configuration,
        parent.as_ref(),
        source.checkpoint.virtual_time,
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .map_err(GuardedDefaultCampaignRunError::ResumeCheckpoint)?;
    if source.checkpoint != expected {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch.into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn materialize_resume_proof<E>(
    repository: &Arc<CampaignRepository>,
    final_snapshot: CampaignSnapshotId,
    lineage: &CampaignLineage,
    observations: &[GuardedDefaultCampaignObservation],
    terminal: &GuardedDefaultCampaignObservation,
    terminal_evidence: &QemuAttemptExecutionEvidenceSnapshot,
    proof: Option<DefaultRunResumeProof>,
    source: Option<&GuardedDefaultCampaignResumeSource>,
) -> Result<Option<GuardedDefaultCampaignResumeProof>, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let (proof, source) = match (proof, source) {
        (Some(proof), Some(source)) => (proof, source),
        (None, None) => return Ok(None),
        _ => return Err(GuardedDefaultCampaignInvariantError::MissingResumeProof.into()),
    };
    let expected_configuration = crucible_campaign::ConfigurationId::from_hash(
        CampaignHash::from_bytes(source.checkpoint.configuration.bytes),
    );
    let source_observation = observations
        .iter()
        .find(|observation| observation.id() == proof.source_observation)
        .ok_or(GuardedDefaultCampaignInvariantError::MissingResumeProof)?;
    if proof.source_checkpoint != source.checkpoint.id
        || proof.source_configuration != expected_configuration
        || proof.source_frontier != source.checkpoint.virtual_time
        || proof.source_evidence.frontier() != source.checkpoint.virtual_time
        || source_observation.virtual_time_ticks() != source.checkpoint.virtual_time.ticks
        || source_observation.observation().child() != expected_configuration
        || source_observation.observation().child_content() != lineage.genesis_content()
    {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceObservationMismatch.into());
    }

    let source_savepoint = match proof.source_capture {
        Some(capture) => {
            let (Some(ready_snapshot), Some(ready), Some(selection), Some(continuation)) = (
                proof.ready_snapshot,
                proof.ready,
                proof.selection,
                proof.continuation,
            ) else {
                return Err(
                    GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch.into(),
                );
            };
            let request = repository
                .savepoint_capture_request_at(final_snapshot, capture.request)
                .map_err(GuardedDefaultCampaignRunError::Repository)?
                .ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
            let resolution = repository
                .savepoint_capture_resolution_at(final_snapshot, capture.request)
                .map_err(GuardedDefaultCampaignRunError::Repository)?
                .ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
            let continuation_attempt = repository
                .load_attempt(continuation)
                .map_err(GuardedDefaultCampaignRunError::Repository)?;
            let continuation_source = repository
                .savepoint_continuation_source_at(final_snapshot, continuation)
                .map_err(GuardedDefaultCampaignRunError::Repository)?
                .ok_or(GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch)?;
            if request != capture.description
                || resolution.request != capture.request
                || resolution.outcome != SavepointCaptureOutcome::Ready
                || CampaignFact::SavepointCaptureResolved(resolution.clone())
                    .id()
                    .map_err(GuardedDefaultCampaignRunError::Codec)?
                    != ready
                || capture.reached != expected_configuration
                || capture.evidence != proof.source_evidence
                || continuation_attempt.stop() != &source.final_stop
                || continuation_source.selection() != selection
                || continuation_source.provenance().request != capture.request
                || continuation_source.provenance().ready != ready
                || continuation_source.provenance().continuation != continuation
                || continuation_source.provenance().expected_snapshot != ready_snapshot
            {
                return Err(
                    GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch.into(),
                );
            }
            let AttemptStart::AfterAttempt { origin, reached } = continuation_attempt.start()
            else {
                return Err(
                    GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch.into(),
                );
            };
            if origin != capture.description.attempt
                || reached != source_observation.observation().child_content()
            {
                return Err(
                    GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch.into(),
                );
            }

            let checkpoint = source
                .checkpoints
                .load_attempt_checkpoint(capture.checkpoint)
                .map_err(GuardedDefaultCampaignRunError::ExactCheckpoint)?;
            if checkpoint.root() != capture.checkpoint
                || checkpoint.scenario().bytes != lineage.scenario().as_hash().as_bytes()
                || checkpoint.configuration().bytes != expected_configuration.as_hash().as_bytes()
                || !capture_evidence_reaches_stop(&capture.evidence, &capture.description.stop)
            {
                return Err(
                    GuardedDefaultCampaignInvariantError::SavepointCheckpointMismatch.into(),
                );
            }
            Some(GuardedDefaultCampaignSavepoint {
                request: capture.request,
                attempt: capture.description.attempt,
                checkpoint: capture.checkpoint,
                configuration: capture.reached,
                stop: capture.description.stop,
                evidence: capture.evidence,
            })
        }
        None => {
            if proof.ready_snapshot.is_some()
                || proof.ready.is_some()
                || proof.selection.is_some()
                || proof.continuation.is_some()
            {
                return Err(
                    GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch.into(),
                );
            }
            if terminal.id() != proof.source_observation
                || terminal_evidence != &proof.source_evidence
                || matches!(terminal.observation().stop(), StopOutcome::Reached(_))
            {
                return Err(GuardedDefaultCampaignInvariantError::MissingResumeProof.into());
            }
            None
        }
    };

    Ok(Some(GuardedDefaultCampaignResumeProof {
        source_checkpoint: proof.source_checkpoint,
        source_configuration: proof.source_configuration,
        source_frontier: proof.source_frontier,
        source_observation: proof.source_observation,
        source_savepoint,
        ready: proof.ready,
        selection: proof.selection,
        continuation: proof.continuation,
    }))
}
