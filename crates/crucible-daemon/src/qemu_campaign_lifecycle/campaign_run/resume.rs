//! Guarded checkpoint admission through campaign ownership.
//!
//! This module authenticates a modeled checkpoint, retains the exact
//! source observation and physical capture, and verifies the typed `Ready`
//! and continuation facts before exposing a resume proof to CLI callers.

use super::*;

pub(super) struct GuardedDefaultCampaignResumeSource {
    pub(super) checkpoint: Checkpoint,
    pub(super) final_stop: StopCondition,
    pub(super) checkpoints: Arc<ExactCheckpointStore>,
    pub(super) source_observation_proof: Option<ObservationStopProof>,
    pub(super) source_observation_evidence: Option<crate::CrucibleMeasurementReplayEvidence>,
    pub(super) capture_only: bool,
}

/// Authenticated source admission for a recorded checkpoint resumed by the campaign owner.
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
    /// Returns the authenticated logical checkpoint supplied by the resume request.
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
            | StopCondition::Observation(_)
    ) {
        return Err(GuardedDefaultCampaignInvariantError::UnsupportedResumeStop.into());
    }
    let source_stop_matches = source.source_observation_proof.as_ref().map_or_else(
        || {
            request.discovery_stop
                == StopCondition::VirtualTimeNanoseconds(source.checkpoint.virtual_time.ticks)
        },
        |proof| {
            request.discovery_stop == StopCondition::Observation(proof.condition().clone())
                && proof.child().as_hash().as_bytes() == source.checkpoint.configuration.bytes
                && proof.boundary().frontier_nanoseconds() == source.checkpoint.virtual_time.ticks
        },
    );
    if !source_stop_matches {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch.into());
    }
    match (
        source.source_observation_proof.as_ref(),
        source.source_observation_evidence.as_ref(),
    ) {
        (Some(proof), Some(evidence)) => evidence
            .verify_observation_stop_proof(proof)
            .map_err(GuardedDefaultCampaignRunError::Measurement)?,
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            return Err(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch.into());
        }
    }
    let closure = request
        .initial_replay_closure
        .as_ref()
        .ok_or(GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch)?;
    if request.initial_schedule.decisions().iter().any(|decision| {
        !matches!(
            decision,
            crucible::Decision::DeliveryOrder(_)
                | crucible::Decision::RngDraw(_)
                | crucible::Decision::Preemption(_)
                | crucible::Decision::Selection(_)
        )
    }) {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch.into());
    }
    closure
        .validate_for_schedule(&request.scenario, &request.initial_schedule)
        .map_err(GuardedDefaultCampaignRunError::ReplayClosure)?;
    if request.initial_schedule.decisions().iter().any(|decision| {
        let crucible::Decision::Selection(decision) = decision else {
            return false;
        };
        decision.selection().is_ok_and(|selection| {
            matches!(
                selection.origin(),
                crucible_campaign::SelectionOrigin::ModelSample(_)
            )
        })
    }) {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch.into());
    }
    if request
        .initial_schedule
        .recorded_virtual_time()
        .is_some_and(|latest| source.checkpoint.virtual_time > latest)
    {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch.into());
    }

    // Reconstruct the authenticated checkpoint rather than trusting caller-owned
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

pub(super) struct ResumeProofMaterialization<'a> {
    pub(super) repository: &'a Arc<CampaignRepository>,
    pub(super) final_snapshot: CampaignSnapshotId,
    pub(super) lineage: &'a CampaignLineage,
    pub(super) observations: &'a [GuardedDefaultCampaignObservation],
    pub(super) terminal: &'a GuardedDefaultCampaignObservation,
    pub(super) terminal_evidence: &'a QemuAttemptExecutionEvidenceSnapshot,
    pub(super) proof: Option<DefaultRunResumeProof>,
    pub(super) source: Option<&'a GuardedDefaultCampaignResumeSource>,
}

pub(super) fn materialize_resume_proof<E>(
    input: ResumeProofMaterialization<'_>,
) -> Result<Option<GuardedDefaultCampaignResumeProof>, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let ResumeProofMaterialization {
        repository,
        final_snapshot,
        lineage,
        observations,
        terminal,
        terminal_evidence,
        proof,
        source,
    } = input;
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
    if let Some(expected) = source.source_observation_proof.as_ref()
        && !matches!(
            source_observation.observation().stop(),
            StopOutcome::ObservationReached(actual) if actual.as_ref() == expected
        )
    {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceObservationMismatch.into());
    }

    if source.capture_only {
        let capture = proof
            .source_capture
            .as_ref()
            .ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
        let (None, None, None, None) = (
            proof.ready_snapshot,
            proof.ready,
            proof.selection,
            proof.continuation,
        ) else {
            return Err(GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch.into());
        };
        let request = repository
            .savepoint_capture_request_at(final_snapshot, capture.request)
            .map_err(GuardedDefaultCampaignRunError::Repository)?
            .ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
        let resolution = repository
            .savepoint_capture_resolution_at(final_snapshot, capture.request)
            .map_err(GuardedDefaultCampaignRunError::Repository)?
            .ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
        if request != capture.description
            || resolution.request != capture.request
            || resolution.outcome != SavepointCaptureOutcome::Ready
            || capture.reached != expected_configuration
            || capture.evidence != proof.source_evidence
            || terminal.id() != proof.source_observation
            || terminal_evidence != &proof.source_evidence
        {
            return Err(GuardedDefaultCampaignInvariantError::ResumeContinuationMismatch.into());
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
            return Err(GuardedDefaultCampaignInvariantError::SavepointCheckpointMismatch.into());
        }
        return Ok(Some(GuardedDefaultCampaignResumeProof {
            source_checkpoint: proof.source_checkpoint,
            source_configuration: proof.source_configuration,
            source_frontier: proof.source_frontier,
            source_observation: proof.source_observation,
            source_savepoint: Some(GuardedDefaultCampaignSavepoint {
                request: capture.request,
                attempt: capture.description.attempt,
                checkpoint: capture.checkpoint,
                configuration: capture.reached,
                stop: capture.description.stop.clone(),
                evidence: capture.evidence.clone(),
            }),
            ready: None,
            selection: None,
            continuation: None,
        }));
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
                || continuation_attempt.continuation_input().is_some()
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
