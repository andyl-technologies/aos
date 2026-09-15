//! Campaign completion, watch-frame, and retained-evidence materialization.

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
    let scenario_artifact = repository
        .load_scenario_artifact(lineage.scenario_content())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let scenario = crate::decode_crucible_scenario_artifact(&scenario_artifact)
        .map_err(GuardedDefaultCampaignRunError::Artifact)?;
    let store = CampaignExecutorStore::new(Arc::clone(repository));
    let mut observations = Vec::new();
    observations
        .try_reserve(execution.observations.len())
        .map_err(GuardedDefaultCampaignRunError::Allocation)?;
    let observation_count = execution.observations.len();
    let terminal_execution_evidence = execution
        .observations
        .last()
        .map(|accepted| accepted.evidence.clone())
        .ok_or(GuardedDefaultCampaignInvariantError::MissingTerminalObservation)?;
    let mut terminal_configuration = None;
    for (index, accepted) in execution.observations.into_iter().enumerate() {
        let observation = repository
            .load_observation(accepted.id)
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        let child = repository
            .load_configuration_artifact(observation.child_content())
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        let configuration = decode_crucible_configuration_artifact_with_selections(
            &scenario,
            &scenario_artifact,
            &child,
            &store,
        )
        .map_err(GuardedDefaultCampaignRunError::Artifact)?;
        let properties = repository
            .load_property_verdict_set(observation.properties())
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        let coverage = repository
            .load_coverage_projection(observation.coverage())
            .map_err(GuardedDefaultCampaignRunError::Repository)?;
        let replay_closure =
            GuardedCampaignReplayClosure::collect(&store, &scenario, &configuration.schedule)
                .map_err(GuardedDefaultCampaignRunError::ReplayClosure)?;
        let observation_evidence = load_observation_stop_evidence(repository, &observation)?;
        let timeout = authenticated_timeout_evidence(
            repository,
            accepted.id,
            &observation,
            &accepted.evidence,
        )?;
        if index + 1 == observation_count {
            terminal_configuration = Some(configuration.clone());
        }
        observations.push(GuardedDefaultCampaignObservation {
            id: accepted.id,
            observation,
            virtual_time_ticks: accepted.virtual_time_ticks,
            configuration,
            properties,
            coverage,
            evidence: accepted.evidence,
            observation_evidence,
            replay_closure,
            supplemental_finding: accepted.supplemental_finding,
            timeout,
        });
    }
    let terminal = observations
        .last()
        .cloned()
        .ok_or(GuardedDefaultCampaignInvariantError::MissingTerminalObservation)?;
    let terminal_configuration = terminal_configuration
        .ok_or(GuardedDefaultCampaignInvariantError::MissingTerminalObservation)?;
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
        observations: &observations,
        terminal: &terminal,
        terminal_evidence: &evidence,
        proof: execution.resume,
        source: resume_source,
    })?;
    let replay_closure =
        GuardedCampaignReplayClosure::collect(&store, &scenario, &terminal_configuration.schedule)
            .map_err(GuardedDefaultCampaignRunError::ReplayClosure)?;
    Ok(GuardedDefaultCampaignRun {
        campaign,
        final_snapshot: execution.final_snapshot,
        finding_export,
        observations,
        terminal,
        terminal_configuration,
        branch_request_count: execution.branch_request_count,
        branch_acceptances: execution.branch_acceptances,
        exploration_completion: execution.exploration_completion,
        state_updates: execution.state_updates,
        watch_frames: execution.watch_frames,
        evidence,
        replay_closure,
        savepoint,
        resume,
    })
}

pub(super) fn load_observation_stop_evidence<E>(
    repository: &Arc<CampaignRepository>,
    observation: &Observation,
) -> Result<Option<CrucibleMeasurementReplayEvidence>, GuardedDefaultCampaignRunError<E>>
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
    let mut evidence_ids = retained.evidence().iter();
    let evidence_id = evidence_ids
        .next()
        .copied()
        .ok_or(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch)?;
    if evidence_ids.next().is_some() {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch.into());
    }
    let bytes = store
        .read_measurement_evidence_leaf(
            observation.measurements(),
            evidence_id,
            MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES as u64,
        )
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let evidence = CrucibleMeasurementReplayEvidence::from_canonical_bytes(&bytes)
        .map_err(GuardedDefaultCampaignRunError::Measurement)?;
    if evidence
        .id()
        .map_err(GuardedDefaultCampaignRunError::Measurement)?
        != evidence_id
    {
        return Err(GuardedDefaultCampaignInvariantError::ResumeSourceEvidenceMismatch.into());
    }
    evidence
        .verify_observation_stop_proof(proof)
        .map_err(GuardedDefaultCampaignRunError::Measurement)?;

    Ok(Some(evidence))
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
    let StopOutcome::ModeledTimeout(name) = observation.stop() else {
        return Ok(None);
    };
    let attempt = repository
        .load_attempt(observation.attempt())
        .map_err(GuardedDefaultCampaignRunError::Repository)?;
    let StopCondition::NextChoiceOrExecutionQuanta { execution_quanta } = attempt.stop() else {
        return Err(GuardedDefaultCampaignInvariantError::TimeoutEvidenceMismatch.into());
    };
    if name != "execution-quanta" || evidence.quanta() < *execution_quanta {
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
        StopCondition::VirtualTimeNanoseconds(deadline) => evidence.frontier().ticks >= *deadline,
        StopCondition::ExecutionQuanta(bound) => evidence.quanta() >= *bound,
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds,
            execution_quanta,
        } => {
            evidence.frontier().ticks >= *virtual_time_nanoseconds
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
