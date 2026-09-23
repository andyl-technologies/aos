//! Canonical scenario and configuration artifact codecs.

use super::*;

/// Encodes one validated Crucible scenario form as a campaign artifact.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] when the bounded campaign artifact cannot
/// be constructed.
pub fn encode_crucible_scenario_artifact(
    scenario: &ScenarioDefForm,
) -> Result<ScenarioArtifact, CrucibleArtifactError> {
    ScenarioArtifact::new(
        campaign_scenario_id(scenario.id()),
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3,
        scenario.to_compact_binary(),
    )
    .map_err(Into::into)
}

/// Strictly decodes and authenticates one Crucible scenario artifact.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] for an unsupported payload schema,
/// malformed compact bytes, or a semantic identity mismatch.
pub fn decode_crucible_scenario_artifact(
    artifact: &ScenarioArtifact,
) -> Result<ScenarioDefForm, CrucibleArtifactError> {
    match artifact.payload_schema() {
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3
            if artifact
                .payload()
                .starts_with(b"crucible.scenario-def-form.v7\0") => {}
        actual => {
            return Err(CrucibleArtifactError::UnsupportedPayloadSchema {
                artifact: "scenario",
                actual,
                expected: CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3,
            });
        }
    }
    let scenario = ScenarioDefForm::from_compact_binary(artifact.payload()).map_err(|source| {
        CrucibleArtifactError::InvalidPayload {
            artifact: "scenario",
            source: Box::new(source),
        }
    })?;
    if campaign_scenario_id(scenario.id()) != artifact.scenario() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "scenario",
        });
    }
    Ok(scenario)
}

/// Encodes one Crucible schedule as an exact campaign configuration artifact.
///
/// The supplied scenario artifact is decoded again so callers cannot pair a
/// valid schedule with unverified or drifted scenario bytes.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] when scenario authentication or bounded
/// campaign artifact construction fails.
pub fn encode_crucible_configuration_artifact(
    scenario_artifact: &ScenarioArtifact,
    schedule: &Schedule,
) -> Result<ConfigurationArtifact, CrucibleArtifactError> {
    let scenario = decode_crucible_scenario_artifact(scenario_artifact)?;
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: schedule.clone(),
    };
    ConfigurationArtifact::new(
        scenario_artifact.scenario(),
        scenario_artifact.id()?,
        campaign_configuration_id(configuration.id()),
        CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V3,
        schedule.to_compact_binary(),
    )
    .map_err(Into::into)
}

/// Strictly decodes and authenticates one Crucible configuration artifact.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] for unsupported or malformed payloads,
/// scenario-reference drift, or a re-derived semantic identity mismatch.
pub fn decode_crucible_configuration_artifact(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
) -> Result<Configuration, CrucibleArtifactError> {
    let configuration =
        decode_crucible_configuration_artifact_structural(scenario, scenario_artifact, artifact)?;
    if configuration
        .schedule
        .decisions()
        .iter()
        .any(|decision| matches!(decision, Decision::Selection(_)))
    {
        return Err(CrucibleArtifactError::UnresolvedSelectionDecision);
    }
    Ok(configuration)
}

/// Strictly decodes a configuration and resolves every embedded selection.
///
/// Each selection must equal its authenticated repository record. Branch
/// provenance is recomputed from the exact schedule prefix and opportunity.
/// Model-sampled selections are accepted only when the authenticated records
/// reconstruct Crucible's standardized app-random uniform model; every other
/// model remains fail-closed until its pure verifier is implemented.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] for the structural failures documented by
/// [`decode_crucible_configuration_artifact`], missing or inconsistent
/// selection records, invalid prefix provenance, or unverified model sampling.
pub fn decode_crucible_configuration_artifact_with_selections(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    store: &CampaignExecutorStore,
) -> Result<Configuration, CrucibleArtifactError> {
    decode_crucible_configuration_artifact_with_resolver(
        scenario,
        scenario_artifact,
        artifact,
        store,
    )
    .map(|(configuration, _)| configuration)
}

/// Decodes a configuration through the full repository selection verifier.
pub(crate) fn decode_crucible_configuration_artifact_from_repository(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    repository: &CampaignRepository,
) -> Result<Configuration, CrucibleArtifactError> {
    decode_crucible_configuration_artifact_with_resolver(
        scenario,
        scenario_artifact,
        artifact,
        repository,
    )
    .map(|(configuration, _)| configuration)
}

/// Strictly decodes a configuration and retains authenticated signal-fault replay.
///
/// This performs the same complete selection validation as
/// [`decode_crucible_configuration_artifact_with_selections`]. In addition, it
/// reconstructs every standardized promoted signal-fault branch, requires its
/// selection and optional override to occur at the exact target prefix, and
/// returns the bounded ordered plan consumed by the production lifecycle.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] for malformed artifacts, unresolved or
/// inconsistent selection records, uncovered signal-fault overrides, or an
/// invalid replay plan.
pub fn decode_crucible_configuration_artifact_with_signal_fault_replay(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    store: &CampaignExecutorStore,
) -> Result<(Configuration, SignalFaultCampaignReplayPlan), CrucibleArtifactError> {
    decode_crucible_configuration_artifact_with_resolver(
        scenario,
        scenario_artifact,
        artifact,
        store,
    )
}

/// Decodes an unpublished observation child for one private finding replay.
///
/// The current observation may own selections that have not entered the
/// repository. This verifier resolves those values from the already checked
/// candidate and resolves inherited selections through the executor store. It
/// returns the exact resolved selection closure alongside the signal-fault plan
/// so private replay evidence can retain every starting decision.
pub(crate) fn decode_crucible_configuration_artifact_with_owned_candidate(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    store: &CampaignExecutorStore,
    owned: &crucible_campaign::ObservationCandidate,
) -> Result<
    (
        Configuration,
        SignalFaultCampaignReplayPlan,
        Vec<ResolvedSelection>,
    ),
    CrucibleArtifactError,
> {
    let configuration =
        decode_crucible_configuration_artifact_structural(scenario, scenario_artifact, artifact)?;
    let mut retained = Vec::new();
    let replay = resolve_selection_decisions(&configuration, artifact, None, |ids, _| {
        retained = store
            .resolve_selections_with_owned_candidate(ids, owned)
            .map_err(CrucibleArtifactError::SelectionRepository)?;
        Ok(retained.clone())
    })?;
    Ok((configuration, replay, retained))
}

fn decode_crucible_configuration_artifact_with_resolver(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    resolver: &impl ConfigurationSelectionResolver,
) -> Result<(Configuration, SignalFaultCampaignReplayPlan), CrucibleArtifactError> {
    let configuration =
        decode_crucible_configuration_artifact_structural(scenario, scenario_artifact, artifact)?;
    let replay = resolve_selection_decisions(&configuration, artifact, None, |ids, _| {
        resolver
            .resolve_configuration_selections(ids)
            .map_err(Into::into)
    })?;
    Ok((configuration, replay))
}

pub(crate) fn decode_crucible_configuration_artifact_with_signal_fault_replay_guarded(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    store: &CampaignExecutorStore,
    retained_memory_guard: Option<&mut RetainedConfigurationMemoryGuard<'_>>,
) -> Result<(Configuration, SignalFaultCampaignReplayPlan), CrucibleArtifactError> {
    let configuration =
        decode_crucible_configuration_artifact_structural(scenario, scenario_artifact, artifact)?;
    let replay = resolve_selection_decisions(
        &configuration,
        artifact,
        retained_memory_guard,
        |ids, selection_resolution_limit| match selection_resolution_limit {
            Some(maximum_canonical_bytes) => store
                .resolve_selections_with_canonical_byte_limit(ids, maximum_canonical_bytes)
                .map_err(|error| match error {
                    CampaignRepositoryError::SelectionResolutionBudgetExceeded { .. } => {
                        CrucibleArtifactError::ResourceLimit {
                            resource: "selected-origin-decoded-resident-bytes",
                        }
                    }
                    error => CrucibleArtifactError::SelectionRepository(error),
                }),
            None => store.resolve_selections(ids).map_err(Into::into),
        },
    )?;
    Ok((configuration, replay))
}

trait ConfigurationSelectionResolver {
    fn resolve_configuration_selections(
        &self,
        ids: &[SelectionId],
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError>;
}

impl ConfigurationSelectionResolver for CampaignExecutorStore {
    fn resolve_configuration_selections(
        &self,
        ids: &[SelectionId],
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError> {
        self.resolve_selections(ids)
    }
}

impl ConfigurationSelectionResolver for CampaignRepository {
    fn resolve_configuration_selections(
        &self,
        ids: &[SelectionId],
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError> {
        self.resolve_distinct_selections(ids)
    }
}

fn decode_crucible_configuration_artifact_structural(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
) -> Result<Configuration, CrucibleArtifactError> {
    let authenticated_scenario = decode_crucible_scenario_artifact(scenario_artifact)?;
    if &authenticated_scenario != scenario || artifact.scenario() != scenario_artifact.scenario() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "configuration scenario",
        });
    }
    if artifact.scenario_artifact() != scenario_artifact.id()? {
        return Err(CrucibleArtifactError::ScenarioArtifactMismatch);
    }
    require_schema(
        "configuration",
        artifact.payload_schema(),
        CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V3,
    )?;
    if !artifact.payload().starts_with(CRUCIBLE_SCHEDULE_V3_MAGIC) {
        return Err(CrucibleArtifactError::UnsupportedScheduleEncoding);
    }
    let schedule = Schedule::from_compact_binary(artifact.payload()).map_err(|source| {
        CrucibleArtifactError::InvalidPayload {
            artifact: "configuration",
            source: Box::new(source),
        }
    })?;
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule,
    };
    validate_preemption_branch_schedule(&configuration).map_err(|source| {
        CrucibleArtifactError::InvalidPayload {
            artifact: "configuration",
            source: Box::new(source),
        }
    })?;
    if campaign_configuration_id(configuration.id()) != artifact.configuration() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "configuration",
        });
    }
    Ok(configuration)
}

fn resolve_selection_decisions<R>(
    configuration: &Configuration,
    artifact: &ConfigurationArtifact,
    retained_memory_guard: Option<&mut RetainedConfigurationMemoryGuard<'_>>,
    resolve: R,
) -> Result<SignalFaultCampaignReplayPlan, CrucibleArtifactError>
where
    R: FnOnce(
        &[SelectionId],
        Option<usize>,
    ) -> Result<Vec<ResolvedSelection>, CrucibleArtifactError>,
{
    let mut selections = Vec::new();
    let mut campaign_branch_count = 0usize;
    for (index, decision) in configuration.schedule.decisions().iter().enumerate() {
        let Decision::Selection(decision) = decision else {
            continue;
        };
        let selection = decision.selection()?;
        selections.push((index, selection));
        if selections.len() > MAX_CONFIGURATION_SELECTION_DECISIONS {
            return Err(CrucibleArtifactError::SelectionResolutionLimit);
        }
        if matches!(
            selections.last().map(|(_, selection)| selection.origin()),
            Some(SelectionOrigin::CampaignBranch { .. })
        ) {
            campaign_branch_count = campaign_branch_count
                .checked_add(1)
                .ok_or(CrucibleArtifactError::SelectionResolutionLimit)?;
        }
    }
    let branch_prefix_bytes = artifact
        .payload()
        .len()
        .checked_mul(campaign_branch_count)
        .ok_or(CrucibleArtifactError::SelectionResolutionLimit)?;
    if branch_prefix_bytes > MAX_CONFIGURATION_BRANCH_PREFIX_BYTES {
        return Err(CrucibleArtifactError::SelectionResolutionLimit);
    }
    let selection_resolution_limit = retained_memory_guard
        .map(|guard| guard(configuration, campaign_branch_count))
        .transpose()?;
    if selections.is_empty() {
        if configuration.schedule.decisions().iter().any(|decision| {
            matches!(decision, Decision::Override(override_decision) if override_decision.point.key.starts_with("signal-fault/"))
        }) {
            return Err(CrucibleArtifactError::UnboundSignalFaultOverride);
        }
        return Ok(SignalFaultCampaignReplayPlan::empty(configuration.clone()));
    }

    let selection_ids = selections
        .iter()
        .map(|(_, selection)| selection.id())
        .collect::<Result<Vec<_>, _>>()?;
    let resolved = resolve(&selection_ids, selection_resolution_limit)?;
    let mut signal_fault_branches = Vec::new();
    let mut covered_signal_fault_overrides = BTreeSet::new();
    for ((index, selection), resolved) in selections.into_iter().zip(resolved) {
        if resolved.selection() != &selection
            || resolved.opportunity().scenario() != artifact.scenario()
        {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "configuration selection",
            });
        }
        match selection.origin() {
            SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
                selection.validate_replay(resolved.opportunity(), resolved.domain())?;
            }
            SelectionOrigin::CampaignBranch { .. } => {
                let parent = Configuration {
                    def: configuration.def.clone(),
                    schedule: configuration.schedule.prefix(index)?,
                };
                selection.validate_branch_replay(
                    resolved.opportunity(),
                    resolved.domain(),
                    resolved
                        .opportunity()
                        .branch_point_id(campaign_configuration_id(parent.id())),
                )?;
                if matches!(
                    resolved.opportunity().source(),
                    crucible_campaign::ChoiceSource::Environment { adapter, .. }
                        if adapter == crucible::SIGNAL_FAULT_CAMPAIGN_ADAPTER
                ) {
                    let selectable = SignalFaultSelectable::from_records(
                        &parent,
                        resolved.declaration(),
                        resolved.opportunity(),
                        resolved.domain(),
                    )?;
                    let branch = selectable.resolve_branch(&selection)?;
                    let end = index
                        .checked_add(branch.decisions().len())
                        .ok_or(CrucibleArtifactError::SelectionResolutionLimit)?;
                    if end > configuration.schedule.len()
                        || configuration.schedule.decisions()[index..end] != *branch.decisions()
                    {
                        return Err(CrucibleArtifactError::SignalFaultScheduleMismatch);
                    }
                    if branch.decisions().len() == 2 {
                        covered_signal_fault_overrides.insert(index + 1);
                    }
                    signal_fault_branches.push(branch);
                }
            }
            SelectionOrigin::ModelSample(_) => {
                crucible::validate_app_random_model_selection(
                    &selection,
                    resolved.declaration(),
                    resolved.opportunity(),
                    resolved.domain(),
                )
                .map_err(|_| CrucibleArtifactError::UnverifiedModelSelection)?;
            }
        }
    }
    if configuration
        .schedule
        .decisions()
        .iter()
        .enumerate()
        .any(|(index, decision)| {
            matches!(decision, Decision::Override(override_decision) if override_decision.point.key.starts_with("signal-fault/"))
                && !covered_signal_fault_overrides.contains(&index)
        })
    {
        return Err(CrucibleArtifactError::UnboundSignalFaultOverride);
    }
    SignalFaultCampaignReplayPlan::new(configuration.clone(), signal_fault_branches)
        .map_err(Into::into)
}

fn require_schema(
    artifact: &'static str,
    actual: u32,
    expected: u32,
) -> Result<(), CrucibleArtifactError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CrucibleArtifactError::UnsupportedPayloadSchema {
            artifact,
            actual,
            expected,
        })
    }
}

pub(crate) fn campaign_scenario_id(id: crucible::ContentHash) -> ScenarioDefId {
    ScenarioDefId::from_hash(CampaignHash::from_bytes(id.bytes))
}

pub(crate) fn campaign_configuration_id(id: crucible::ContentHash) -> ConfigurationId {
    ConfigurationId::from_hash(CampaignHash::from_bytes(id.bytes))
}
