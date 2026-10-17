//! Campaign completion, watch-frame, and retained-evidence materialization.
//!
//! Each accepted observation is materialized once, when the attempt is
//! incorporated, and handed to the run's sink; only the latest one survives
//! to become the terminal observation of the result.

use super::*;

pub(super) fn complete_default_campaign<S, E>(
    context: &DefaultRunContext<'_, S>,
    snapshot: CampaignSnapshotId,
    supervisor_iteration: usize,
    state_updates: &mut Vec<CampaignState>,
) -> Result<CampaignSnapshotId, GuardedDefaultCampaignRunError<E>>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
    E: Error + 'static,
{
    let command_ordinal = 2_u64
        .checked_add(
            u64::try_from(supervisor_iteration)
                .map_err(|_| GuardedDefaultCampaignInvariantError::CommandOrdinalOverflow)?,
        )
        .ok_or(GuardedDefaultCampaignInvariantError::CommandOrdinalOverflow)?;
    let final_snapshot = apply_campaign_control(
        context.client,
        context.principal,
        context.campaign,
        snapshot,
        command_ordinal,
        CampaignControlAction::Complete,
    )?;
    state_updates.push(
        context
            .repository
            .state(context.campaign.as_str())
            .map_err(GuardedDefaultCampaignRunError::Repository)?,
    );
    Ok(final_snapshot)
}

/// Campaign lifecycle states and the caller's sink for streamed progress.
pub(super) struct DefaultRunProgress<'a> {
    pub(super) state_updates: Vec<CampaignState>,
    pub(super) sink: &'a mut dyn GuardedCampaignRunSink,
}

impl DefaultRunProgress<'_> {
    pub(super) fn deliver_watch_frame<S, E>(
        &mut self,
        context: &DefaultRunContext<'_, S>,
        snapshot: CampaignSnapshotId,
        evidence: &QemuAttemptExecutionEvidenceSnapshot,
        observation: Option<ObservationId>,
    ) -> Result<(), GuardedDefaultCampaignRunError<E>>
    where
        E: Error + 'static,
    {
        if !context.collect_watch_frames {
            return Ok(());
        }
        let frame = campaign_watch_frame(
            context.repository,
            context.campaign,
            snapshot,
            evidence,
            observation,
        )?;
        self.sink
            .on_watch_frame(&frame)
            .map_err(GuardedDefaultCampaignRunError::Sink)
    }

    /// Completes the campaign and delivers the final watch frame.
    pub(super) fn complete<S, E>(
        &mut self,
        context: &DefaultRunContext<'_, S>,
        snapshot: CampaignSnapshotId,
        supervisor_iteration: usize,
        evidence: &QemuAttemptExecutionEvidenceSnapshot,
    ) -> Result<CampaignSnapshotId, GuardedDefaultCampaignRunError<E>>
    where
        S: crucible_campaign::CampaignService,
        S::Error: crucible_campaign::CampaignServiceFailureSource,
        E: Error + 'static,
    {
        let final_snapshot = complete_default_campaign(
            context,
            snapshot,
            supervisor_iteration,
            &mut self.state_updates,
        )?;
        self.deliver_watch_frame(context, final_snapshot, evidence, None)?;
        Ok(final_snapshot)
    }
}

pub(super) fn campaign_watch_frame<E>(
    repository: &CampaignRepository,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    evidence: &QemuAttemptExecutionEvidenceSnapshot,
    observation: Option<ObservationId>,
) -> Result<GuardedDefaultCampaignWatchFrame, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let state = repository
        .state_at_snapshot(snapshot)
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    Ok(GuardedDefaultCampaignWatchFrame {
        campaign: campaign.clone(),
        snapshot,
        state,
        frontier: evidence.frontier(),
        quanta: evidence.quanta(),
        observation,
    })
}

/// Materializes one incorporated observation for the sink and the result.
pub(super) fn materialize_observation<S, E>(
    context: &DefaultRunContext<'_, S>,
    accepted: DefaultRunAcceptedObservation,
    observation: Observation,
) -> Result<GuardedDefaultCampaignObservation, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let repository = context.repository;
    let child = repository
        .load_configuration_artifact(observation.child_content())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let configuration = decode_crucible_configuration_artifact_with_selections(
        context.scenario,
        context.scenario_artifact,
        &child,
        context.executor_store,
    )
    .map_err(GuardedDefaultCampaignRunError::Artifact)?;
    let supplemental_finding =
        evaluate_supplemental_finding(context, &observation, &configuration)?;
    let properties = repository
        .load_property_verdict_set(observation.properties())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let coverage = repository
        .load_coverage_projection(observation.coverage())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let replay_closure = GuardedCampaignReplayClosure::collect(
        context.executor_store,
        context.scenario,
        &configuration.schedule,
    )
    .map_err(GuardedDefaultCampaignRunError::ReplayClosure)?;
    let observation_evidence = load_observation_stop_evidence(repository, &observation)?;
    let timeout =
        authenticated_timeout_evidence(repository, accepted.id, &observation, &accepted.evidence)?;

    Ok(GuardedDefaultCampaignObservation {
        id: accepted.id,
        observation,
        virtual_time_ticks: accepted.virtual_time_ticks,
        configuration,
        properties,
        coverage,
        evidence: accepted.evidence,
        observation_evidence,
        replay_closure,
        supplemental_finding,
        timeout,
    })
}

pub(super) fn materialize_result<E>(
    repository: &Arc<CampaignRepository>,
    campaign: CampaignName,
    execution: DefaultRunExecution,
    finding_export: GuardedCampaignFindingExport,
    checkpoints: Option<&ExactCheckpointStore>,
    resume_source: Option<&GuardedDefaultCampaignResumeSource>,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let head = repository
        .head(campaign.as_str())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let lineage = repository
        .load_lineage(head.snapshot().lineage())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let DefaultRunTally {
        observation_count,
        branch_request_count,
        terminal,
    } = execution.tally;
    let terminal =
        terminal.ok_or(GuardedDefaultCampaignInvariantError::MissingTerminalObservation)?;
    let terminal_execution_evidence = terminal.evidence.clone();
    let terminal_configuration = terminal.configuration.clone();
    let (savepoint, evidence) = match execution.savepoint {
        Some(capture) => {
            let checkpoints =
                checkpoints.ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
            let request = repository
                .savepoint_capture_request_at(execution.final_snapshot, capture.request)
                .map_err(GuardedDefaultCampaignRunError::Repository)?
                .ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
            let resolution = repository
                .savepoint_capture_resolution_at(execution.final_snapshot, capture.request)
                .map_err(GuardedDefaultCampaignRunError::Repository)?
                .ok_or(GuardedDefaultCampaignInvariantError::MissingSavepointCapture)?;
            let attempt = repository
                .load_attempt(capture.description.attempt)
                .map_err(GuardedDefaultCampaignRunError::Repository)?;
            if request != capture.description
                || resolution.request != capture.request
                || resolution.outcome != SavepointCaptureOutcome::Ready
                || attempt.stop() != &capture.description.stop
                || capture.description.attempt != terminal.observation.attempt()
                || capture.reached != terminal.observation.child()
                || capture.evidence != terminal_execution_evidence
            {
                return Err(GuardedDefaultCampaignInvariantError::SavepointCaptureMismatch.into());
            }

            let checkpoint = checkpoints
                .load_attempt_checkpoint(capture.checkpoint)
                .map_err(GuardedDefaultCampaignRunError::ExactCheckpoint)?;
            if checkpoint.root() != capture.checkpoint
                || checkpoint.scenario().bytes != lineage.scenario().as_hash().as_bytes()
                || checkpoint.configuration().bytes
                    != terminal.observation.child().as_hash().as_bytes()
                || !capture_evidence_reaches_stop(&capture.evidence, &capture.description.stop)
            {
                return Err(
                    GuardedDefaultCampaignInvariantError::SavepointCheckpointMismatch.into(),
                );
            }

            let evidence = capture.evidence.clone();
            let savepoint = GuardedDefaultCampaignSavepoint {
                request: capture.request,
                attempt: capture.description.attempt,
                checkpoint: capture.checkpoint,
                configuration: capture.reached,
                stop: capture.description.stop,
                evidence: capture.evidence,
            };
            (Some(savepoint), evidence)
        }
        None => {
            if checkpoints.is_some() && resume_source.is_none() {
                return Err(GuardedDefaultCampaignInvariantError::MissingSavepointCapture.into());
            }
            (None, terminal_execution_evidence)
        }
    };
    let resume = materialize_resume_proof(ResumeProofMaterialization {
        repository,
        final_snapshot: execution.final_snapshot,
        lineage: &lineage,
        terminal: &terminal,
        terminal_evidence: &evidence,
        proof: execution.resume,
        source: resume_source,
    })?;
    // The terminal observation already carries its exact choice closure.
    let replay_closure = terminal.replay_closure.clone();
    Ok(GuardedDefaultCampaignRun {
        campaign,
        final_snapshot: execution.final_snapshot,
        finding_export,
        observation_count,
        terminal,
        terminal_configuration,
        branch_request_count,
        exploration_completion: execution.exploration_completion,
        state_updates: execution.state_updates,
        evidence,
        replay_closure,
        savepoint,
        resume,
    })
}

pub(super) fn load_observation_stop_evidence<E>(
    repository: &Arc<CampaignRepository>,
    observation: &Observation,
) -> Result<Option<crate::CrucibleMeasurementEvidenceBundle>, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let StopOutcome::ObservationReached(proof) = observation.stop() else {
        return Ok(None);
    };
    let store = CampaignExecutorStore::new(Arc::clone(repository));
    let measurements = repository
        .load_measurement_set(observation.measurements())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let retained = measurements.evaluation();
    let evidence_id = crate::measurement_replay_leaf_id(retained.evidence())
        .ok_or(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch)?;
    let bytes = store
        .read_measurement_evidence_leaf(
            observation.measurements(),
            evidence_id,
            MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES as u64,
        )
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let evidence = crate::CrucibleMeasurementReplayEvidence::from_canonical_bytes(&bytes)
        .map_err(GuardedDefaultCampaignRunError::Measurement)?;
    if evidence
        .id()
        .map_err(GuardedDefaultCampaignRunError::Measurement)?
        != evidence_id
        || &evidence
            .evidence_ids()
            .map_err(GuardedDefaultCampaignRunError::Measurement)?
            != retained.evidence()
    {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch.into());
    }

    // The run's private repository is dropped with the run, so the result
    // keeps the segments the leaf references alongside it.
    let segments = crate::MeasurementSetSegmentSource::new(&store, observation.measurements());
    let bundle = crate::CrucibleMeasurementEvidenceBundle::collect(evidence, &segments)
        .map_err(GuardedDefaultCampaignRunError::Measurement)?;
    bundle
        .evidence()
        .verify_observation_stop_proof(bundle.segments(), proof)
        .map_err(GuardedDefaultCampaignRunError::Measurement)?;

    Ok(Some(bundle))
}

pub(super) fn authenticated_timeout_evidence<E>(
    repository: &CampaignRepository,
    observation_id: ObservationId,
    observation: &Observation,
    evidence: &QemuAttemptExecutionEvidenceSnapshot,
) -> Result<Option<GuardedCampaignTimeoutEvidence>, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let bounded_proof = match observation.stop() {
        StopOutcome::BoundedPrimaryTimeout { proof, .. } => Some(proof),
        StopOutcome::ModeledTimeout(name) if name == "execution-quanta" => None,
        StopOutcome::ModeledTimeout(_) => {
            return Err(GuardedDefaultCampaignInvariantError::TimeoutEvidenceMismatch.into());
        }
        _ => return Ok(None),
    };
    let attempt = repository
        .load_attempt(observation.attempt())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let StopCondition::NextChoiceOrExecutionQuanta { execution_quanta } = attempt.stop().primary()
    else {
        return Err(GuardedDefaultCampaignInvariantError::TimeoutEvidenceMismatch.into());
    };
    if evidence.quanta() < *execution_quanta
        || bounded_proof.is_some_and(|proof| {
            proof.completed_quanta() != evidence.quanta()
                || proof.frontier_picoseconds() != evidence.frontier().ticks
        })
    {
        return Err(GuardedDefaultCampaignInvariantError::TimeoutEvidenceMismatch.into());
    }
    Ok(Some(GuardedCampaignTimeoutEvidence {
        observation: observation_id,
        execution_quanta_limit: *execution_quanta,
        observed_execution_quanta: evidence.quanta(),
        frontier: evidence.frontier(),
    }))
}

pub(super) fn capture_evidence_reaches_stop(
    evidence: &QemuAttemptExecutionEvidenceSnapshot,
    stop: &StopCondition,
) -> bool {
    match stop {
        StopCondition::Bounded {
            primary,
            virtual_time_picoseconds,
            execution_quanta,
        } => {
            virtual_time_picoseconds.is_some_and(|deadline| evidence.frontier().ticks >= deadline)
                || execution_quanta.is_some_and(|deadline| evidence.quanta() >= deadline)
                || capture_evidence_reaches_stop(evidence, primary)
        }
        StopCondition::VirtualTimePicoseconds(deadline) => evidence.frontier().ticks >= *deadline,
        StopCondition::ExecutionQuanta(bound) => evidence.quanta() >= *bound,
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_picoseconds,
            execution_quanta,
        } => {
            evidence.frontier().ticks >= *virtual_time_picoseconds
                || evidence.quanta() >= *execution_quanta
        }
        StopCondition::NextChoice
        | StopCondition::NextChoiceOrExecutionQuanta { .. }
        | StopCondition::Observation(_)
        | StopCondition::NamedBoundary(_)
        | StopCondition::EventCount(_)
        | StopCondition::Terminal => true,
    }
}

impl<E> From<GuardedDefaultCampaignInvariantError> for GuardedDefaultCampaignRunError<E>
where
    E: Error + 'static,
{
    fn from(error: GuardedDefaultCampaignInvariantError) -> Self {
        Self::Invariant(error)
    }
}
