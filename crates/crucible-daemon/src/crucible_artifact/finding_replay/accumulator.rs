//! Deduplicated replay-record accumulation and validation.

use super::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::crucible_artifact) struct ReplayRecordAccumulator {
    pub(super) ids: BTreeSet<crucible_cas::content_store::ContentId>,
    configurations: Vec<ConfigurationArtifact>,
    measurements: Vec<MeasurementSet>,
    properties: Vec<PropertyVerdictSet>,
    coverage: Vec<CoverageProjection>,
    declarations: Vec<SelectableDeclaration>,
    domains: Vec<ChoiceDomain>,
    opportunities: Vec<ChoiceOpportunity>,
    selections: Vec<Selection>,
    pub(super) canonical_bytes: usize,
}

impl ReplayRecordAccumulator {
    pub(super) const fn new() -> Self {
        Self {
            ids: BTreeSet::new(),
            configurations: Vec::new(),
            measurements: Vec::new(),
            properties: Vec::new(),
            coverage: Vec::new(),
            declarations: Vec::new(),
            domains: Vec::new(),
            opportunities: Vec::new(),
            selections: Vec::new(),
            canonical_bytes: 0,
        }
    }

    pub(super) fn record_outcome(
        &mut self,
        candidate: &FindingReproductionArtifact,
        replay: AutomaticFindingReplayOutcome,
    ) -> Result<RecordedFindingReplay, CrucibleArtifactError> {
        match replay {
            AutomaticFindingReplayOutcome::Observed { evidence, .. } => {
                validate_replay_configuration(candidate, &evidence)?;
                self.record_observed(*evidence)
            }
            AutomaticFindingReplayOutcome::DeterministicallyIncompatible {
                configuration,
                reason,
            } => {
                validate_incompatible_configuration(candidate, &configuration)?;
                let configuration_id = configuration.id()?;
                let canonical_bytes = configuration.canonical_bytes().len();
                if self.ids.insert(configuration_id.content_id()) {
                    self.canonical_bytes = self
                        .canonical_bytes
                        .checked_add(canonical_bytes)
                        .ok_or(CampaignCodecError::LimitExceeded {
                            limit: "finding-replay-retained-record-bytes",
                        })?;
                    if self.ids.len() > MAX_CRUCIBLE_FINDING_REPLAY_RECORDS
                        || self.canonical_bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES
                    {
                        return Err(CampaignCodecError::LimitExceeded {
                            limit: "finding-replay-retained-record-bytes",
                        }
                        .into());
                    }
                    self.configurations.push(configuration);
                }
                Ok(RecordedFindingReplay::DeterministicallyIncompatible {
                    configuration: configuration_id,
                    reason,
                })
            }
        }
    }

    pub(super) fn record_observed(
        &mut self,
        replay: CrucibleFindingReplayEvidence,
    ) -> Result<RecordedFindingReplay, CrucibleArtifactError> {
        replay.validate_signature_ownership()?;
        let configuration = replay.configuration.id()?;
        let measurements = replay.measurements.id()?;
        let properties = replay.properties.id()?;
        let coverage = replay.coverage.id()?;
        let opportunities = replay
            .opportunities
            .iter()
            .map(ChoiceOpportunity::id)
            .collect::<Result<Vec<_>, _>>()?;
        let selections = replay
            .selections
            .iter()
            .map(Selection::id)
            .collect::<Result<Vec<_>, _>>()?;
        let next_canonical_bytes = self.preflight(&replay)?;
        let recorded = RecordedFindingReplay::Observed {
            signature: replay.signature.map(Box::new),
            configuration,
            measurements,
            properties,
            coverage,
            opportunities,
            selections,
        };

        if self.ids.insert(configuration.content_id()) {
            self.configurations.push(replay.configuration);
        }
        if self.ids.insert(replay.measurements.id()?.content_id()) {
            self.measurements.push(replay.measurements);
        }
        if self.ids.insert(replay.properties.id()?.content_id()) {
            self.properties.push(replay.properties);
        }
        if self.ids.insert(replay.coverage.id()?.content_id()) {
            self.coverage.push(replay.coverage);
        }
        for declaration in replay.declarations {
            if self.ids.insert(declaration.id()?.content_id()) {
                self.declarations.push(declaration);
            }
        }
        for domain in replay.domains {
            if self.ids.insert(domain.id()?.content_id()) {
                self.domains.push(domain);
            }
        }
        for opportunity in replay.opportunities {
            if self.ids.insert(opportunity.id()?.content_id()) {
                self.opportunities.push(opportunity);
            }
        }
        for selection in replay.selections {
            if self.ids.insert(selection.id()?.content_id()) {
                self.selections.push(selection);
            }
        }
        self.canonical_bytes = next_canonical_bytes;
        Ok(recorded)
    }

    pub(super) fn preflight(
        &self,
        replay: &CrucibleFindingReplayEvidence,
    ) -> Result<usize, CrucibleArtifactError> {
        let mut candidate_records = BTreeMap::from([
            (
                replay.configuration.id()?.content_id(),
                replay.configuration.canonical_bytes().len(),
            ),
            (
                replay.measurements.id()?.content_id(),
                replay.measurements.canonical_bytes().len(),
            ),
            (
                replay.properties.id()?.content_id(),
                replay.properties.canonical_bytes().len(),
            ),
            (
                replay.coverage.id()?.content_id(),
                replay.coverage.canonical_bytes().len(),
            ),
        ]);
        for declaration in &replay.declarations {
            candidate_records.insert(
                declaration.id()?.content_id(),
                declaration.canonical_bytes().len(),
            );
        }
        for domain in &replay.domains {
            candidate_records.insert(domain.id()?.content_id(), domain.canonical_bytes().len());
        }
        for opportunity in &replay.opportunities {
            candidate_records.insert(
                opportunity.id()?.content_id(),
                opportunity.canonical_bytes().len(),
            );
        }
        for selection in &replay.selections {
            candidate_records.insert(
                selection.id()?.content_id(),
                selection.canonical_bytes().len(),
            );
        }

        let new_records = candidate_records
            .keys()
            .filter(|id| !self.ids.contains(id))
            .count();
        if self
            .ids
            .len()
            .checked_add(new_records)
            .is_none_or(|count| count > MAX_CRUCIBLE_FINDING_REPLAY_RECORDS)
        {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-replay-retained-record-count",
            }
            .into());
        }
        let record_bytes = candidate_records
            .iter()
            .filter(|(id, _)| !self.ids.contains(id))
            .try_fold(0usize, |total, (_, bytes)| total.checked_add(*bytes))
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "finding-replay-retained-record-bytes",
            })?;
        let signature_bytes = replay
            .signature
            .as_ref()
            .map_or(0, |signature| signature.canonical_bytes().len());
        let next_bytes = self
            .canonical_bytes
            .checked_add(record_bytes)
            .and_then(|bytes| bytes.checked_add(signature_bytes))
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "finding-replay-retained-record-bytes",
            })?;
        if next_bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-replay-retained-record-bytes",
            }
            .into());
        }
        Ok(next_bytes)
    }

    pub(in crate::crucible_artifact) fn finish(self) -> PreparedFindingReplayRecords {
        PreparedFindingReplayRecords {
            configurations: self.configurations,
            measurements: self.measurements,
            properties: self.properties,
            coverage: self.coverage,
            declarations: self.declarations,
            domains: self.domains,
            opportunities: self.opportunities,
            selections: self.selections,
            record_count: self.ids.len(),
            canonical_bytes: self.canonical_bytes,
        }
    }
}

pub(super) fn validate_replay_configuration(
    candidate: &FindingReproductionArtifact,
    replay: &CrucibleFindingReplayEvidence,
) -> Result<(), CrucibleArtifactError> {
    let scenario = candidate.artifact.scenario_form();
    let scenario_artifact = encode_crucible_scenario_artifact(scenario)?;
    let expected =
        encode_crucible_configuration_artifact(&scenario_artifact, candidate.artifact.schedule())?;
    if replay.configuration != expected {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding replay candidate configuration",
        });
    }
    validate_owned_replay_selections(candidate, replay)?;
    replay.validate_signature_ownership()
}

pub(super) fn validate_incompatible_configuration(
    candidate: &FindingReproductionArtifact,
    replay: &ConfigurationArtifact,
) -> Result<(), CrucibleArtifactError> {
    let scenario = candidate.artifact.scenario_form();
    let scenario_artifact = encode_crucible_scenario_artifact(scenario)?;
    let expected =
        encode_crucible_configuration_artifact(&scenario_artifact, candidate.artifact.schedule())?;
    if replay != &expected {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding incompatible replay candidate configuration",
        });
    }
    Ok(())
}

pub(super) fn validate_owned_replay_selections(
    candidate: &FindingReproductionArtifact,
    replay: &CrucibleFindingReplayEvidence,
) -> Result<(), CrucibleArtifactError> {
    let declarations = replay
        .declarations
        .iter()
        .map(|value| value.id().map(|id| (id, value)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let domains = replay
        .domains
        .iter()
        .map(|value| value.id().map(|id| (id, value)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut choices = BTreeMap::new();
    for opportunity in &replay.opportunities {
        let declaration = declarations.get(&opportunity.declaration()).ok_or(
            CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay choice declaration",
            },
        )?;
        let domain = domains.get(&opportunity.domain()).ok_or(
            CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay choice domain",
            },
        )?;
        opportunity.validate_references(declaration, domain)?;
        if opportunity.scenario() != replay.configuration.scenario() {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay choice scenario",
            });
        }
        choices.insert(opportunity.id()?, (opportunity, declaration, domain));
    }

    let selections = replay
        .selections
        .iter()
        .map(|selection| selection.id().map(|id| (id, selection)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut embedded = BTreeSet::new();
    let mut covered_signal_fault_overrides = BTreeSet::new();
    let configuration = Configuration {
        def: candidate.artifact.scenario_def().clone(),
        schedule: candidate.artifact.schedule().clone(),
    };
    let selection_count = configuration
        .schedule
        .decisions()
        .iter()
        .filter(|decision| matches!(decision, Decision::Selection(_)))
        .count();
    if selection_count > MAX_CONFIGURATION_SELECTION_DECISIONS {
        return Err(CrucibleArtifactError::SelectionResolutionLimit);
    }
    let campaign_branch_count = replay
        .selections
        .iter()
        .filter(|selection| matches!(selection.origin(), SelectionOrigin::CampaignBranch { .. }))
        .count();
    if replay
        .configuration
        .payload()
        .len()
        .checked_mul(campaign_branch_count)
        .is_none_or(|bytes| bytes > MAX_CONFIGURATION_BRANCH_PREFIX_BYTES)
    {
        return Err(CrucibleArtifactError::SelectionResolutionLimit);
    }
    for (index, decision) in configuration.schedule.decisions().iter().enumerate() {
        let Decision::Selection(decision) = decision else {
            continue;
        };
        let decoded = decision.selection()?;
        let id = decoded.id()?;
        let selection =
            selections
                .get(&id)
                .ok_or(CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding replay embedded selection",
                })?;
        if **selection != decoded || !embedded.insert(id) {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay embedded selection",
            });
        }
        let (opportunity, declaration, domain) = choices.get(&selection.opportunity()).ok_or(
            CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay selection opportunity",
            },
        )?;
        match selection.origin() {
            SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
                selection.validate_replay(opportunity, domain)?;
            }
            SelectionOrigin::CampaignBranch { .. } => {
                let parent = Configuration {
                    def: configuration.def.clone(),
                    schedule: configuration.schedule.prefix(index)?,
                };
                selection.validate_branch_replay(
                    opportunity,
                    domain,
                    opportunity.branch_point_id(campaign_configuration_id(parent.id())),
                )?;
                if matches!(
                    opportunity.source(),
                    crucible_campaign::ChoiceSource::Environment { adapter, .. }
                        if adapter == crucible::SIGNAL_FAULT_CAMPAIGN_ADAPTER
                ) {
                    let selectable = SignalFaultSelectable::from_records(
                        &parent,
                        declaration,
                        opportunity,
                        domain,
                    )?;
                    let branch = selectable.resolve_branch(selection)?;
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
                }
            }
            SelectionOrigin::ModelSample(_) => {
                crucible::validate_app_random_model_selection(
                    selection,
                    declaration,
                    opportunity,
                    domain,
                )
                .map_err(|_| CrucibleArtifactError::UnverifiedModelSelection)?;
            }
        }
    }
    if embedded.len() != selections.len() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding replay selection set",
        });
    }
    if configuration
        .schedule
        .decisions()
        .iter()
        .enumerate()
        .any(|(index, decision)| {
            matches!(decision, Decision::Override(override_decision)
                if override_decision.point.key.starts_with("signal-fault/")
                    && !covered_signal_fault_overrides.contains(&index))
        })
    {
        return Err(CrucibleArtifactError::UnboundSignalFaultOverride);
    }
    Ok(())
}

pub(crate) fn validate_recorded_replay_configuration(
    candidate: &FindingReproductionArtifact,
    replay: &RecordedFindingReplay,
) -> Result<(), CrucibleArtifactError> {
    let scenario = encode_crucible_scenario_artifact(candidate.artifact.scenario_form())?;
    let expected =
        encode_crucible_configuration_artifact(&scenario, candidate.artifact.schedule())?;
    if replay.configuration() != expected.id()? {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding replay candidate configuration",
        });
    }
    Ok(())
}
