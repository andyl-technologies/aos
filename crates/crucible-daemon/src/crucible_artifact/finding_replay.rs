//! Bounded typed evidence retained from internal finding-minimizer replays.
//!
//! These records are private validation provenance. They deliberately exclude
//! admitted attempts and graph observations while preserving every typed object
//! that a raw replay signature may reference.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    CrucibleArtifactError, MAX_CONFIGURATION_BRANCH_PREFIX_BYTES,
    MAX_CONFIGURATION_SELECTION_DECISIONS, MAX_CRUCIBLE_FINDING_REPLAY_BYTES,
    MAX_CRUCIBLE_FINDING_REPLAY_RECORDS, MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS,
    campaign_configuration_id, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact,
};
use crucible::{Configuration, Decision, FindingReproductionArtifact, SignalFaultSelectable};
use crucible_campaign::{
    CampaignCodecError, ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity, ChoiceOpportunityId,
    ConfigurationArtifact, ConfigurationArtifactId, CoverageProjection, CoverageProjectionId,
    FindingKind, FindingSignature, FindingTarget, MeasurementSet, MeasurementSetId,
    PropertyVerdict, PropertyVerdictSet, PropertyVerdictSetId, SelectableDeclaration, Selection,
    SelectionId, SelectionOrigin,
};
use crucible_cas::content_store::ContentId;

/// Actual model evidence produced by one internal finding replay.
///
/// This value deliberately excludes an [`crucible_campaign::Observation`]:
/// minimizer replays validate a candidate privately and do not create admitted
/// campaign attempts or graph observations. It owns every new typed record that
/// a replay signature may name. Scenario artifacts and transitive evidence
/// children referenced by the measurement, property, and coverage records must
/// already be authenticated repository objects before publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleFindingReplayEvidence {
    signature: Option<FindingSignature>,
    configuration: ConfigurationArtifact,
    measurements: MeasurementSet,
    properties: PropertyVerdictSet,
    coverage: CoverageProjection,
    declarations: Vec<SelectableDeclaration>,
    domains: Vec<ChoiceDomain>,
    opportunities: Vec<ChoiceOpportunity>,
    selections: Vec<Selection>,
}

impl CrucibleFindingReplayEvidence {
    /// Builds one self-contained typed replay-evidence set.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when choice records are duplicated or
    /// inconsistent, or when the signature names a target or causal record not
    /// owned by this exact replay.
    // crucible-lint: allow rust-allow -- every typed evidence class remains explicit at this boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signature: Option<FindingSignature>,
        configuration: ConfigurationArtifact,
        measurements: MeasurementSet,
        properties: PropertyVerdictSet,
        coverage: CoverageProjection,
        discoveries: Vec<ChoiceDiscovery>,
        selections: Vec<Selection>,
    ) -> Result<Self, CrucibleArtifactError> {
        preflight_single_replay(
            signature.as_ref(),
            &configuration,
            &measurements,
            &properties,
            &coverage,
            &discoveries,
            &selections,
        )?;

        let mut declarations = BTreeMap::new();
        let mut domains = BTreeMap::new();
        let mut opportunities = BTreeMap::new();
        for discovery in discoveries {
            discovery
                .opportunity()
                .validate_references(discovery.declaration(), discovery.domain())?;
            let opportunity_id = discovery.opportunity().id()?;
            if opportunities
                .insert(opportunity_id, discovery.opportunity().clone())
                .is_some()
            {
                return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding replay duplicate choice opportunity",
                });
            }
            declarations
                .entry(discovery.declaration().id()?)
                .or_insert_with(|| discovery.declaration().clone());
            domains
                .entry(discovery.domain().id()?)
                .or_insert_with(|| discovery.domain().clone());
        }

        let opportunities = opportunities.into_values().collect::<Vec<_>>();
        let opportunity_ids = opportunities
            .iter()
            .map(ChoiceOpportunity::id)
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut selection_ids = BTreeSet::new();
        for selection in &selections {
            if !selection_ids.insert(selection.id()?)
                || !opportunity_ids.contains(&selection.opportunity())
            {
                return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding replay selection closure",
                });
            }
        }

        let value = Self {
            signature,
            configuration,
            measurements,
            properties,
            coverage,
            declarations: declarations.into_values().collect(),
            domains: domains.into_values().collect(),
            opportunities,
            selections,
        };
        value.validate_signature_ownership()?;
        Ok(value)
    }

    /// Returns the complete signature observed by this replay, when any.
    #[must_use]
    pub const fn signature(&self) -> Option<&FindingSignature> {
        self.signature.as_ref()
    }

    /// Returns the exact candidate configuration that was replayed.
    #[must_use]
    pub const fn configuration(&self) -> &ConfigurationArtifact {
        &self.configuration
    }

    fn validate_signature_ownership(&self) -> Result<(), CrucibleArtifactError> {
        let Some(signature) = &self.signature else {
            return Ok(());
        };
        let configuration = self.configuration.id()?;
        let opportunity_ids = self
            .opportunities
            .iter()
            .map(ChoiceOpportunity::id)
            .collect::<Result<BTreeSet<_>, _>>()?;
        match signature.target() {
            Some(FindingTarget::Configuration(target)) if target != configuration => {
                return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding replay configuration target",
                });
            }
            Some(FindingTarget::ChoiceOpportunity(target))
                if !opportunity_ids.contains(&target) =>
            {
                return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding replay choice target",
                });
            }
            _ => {}
        }
        if signature.kind() == FindingKind::PropertyViolation {
            let property =
                signature
                    .property()
                    .ok_or(CrucibleArtifactError::SemanticIdentityMismatch {
                        artifact: "finding replay property signature",
                    })?;
            if self
                .properties
                .properties()
                .get(property)
                .is_none_or(|evidence| evidence.verdict() != PropertyVerdict::Failed)
            {
                return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding replay failed property evidence",
                });
            }
        }

        let mut owned = BTreeSet::from([
            configuration.content_id(),
            self.measurements.id()?.content_id(),
            self.properties.id()?.content_id(),
            self.coverage.id()?.content_id(),
        ]);
        owned.extend(opportunity_ids.into_iter().map(|id| id.content_id()));
        owned.extend(
            self.selections
                .iter()
                .map(Selection::id)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|id| id.content_id()),
        );
        if !signature.causal_evidence().is_subset(&owned) {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay causal evidence",
            });
        }
        Ok(())
    }
}

// Preflight before ChoiceDiscovery dependencies are cloned into normalized vectors.
// crucible-lint: allow rust-allow -- replay preflight checks each independently bound finding component.
#[allow(clippy::too_many_arguments)]
fn preflight_single_replay(
    signature: Option<&FindingSignature>,
    configuration: &ConfigurationArtifact,
    measurements: &MeasurementSet,
    properties: &PropertyVerdictSet,
    coverage: &CoverageProjection,
    discoveries: &[ChoiceDiscovery],
    selections: &[Selection],
) -> Result<(), CrucibleArtifactError> {
    let mut records = BTreeMap::<ContentId, usize>::from([
        (
            configuration.id()?.content_id(),
            configuration.canonical_bytes().len(),
        ),
        (
            measurements.id()?.content_id(),
            measurements.canonical_bytes().len(),
        ),
        (
            properties.id()?.content_id(),
            properties.canonical_bytes().len(),
        ),
        (
            coverage.id()?.content_id(),
            coverage.canonical_bytes().len(),
        ),
    ]);
    for discovery in discoveries {
        records.insert(
            discovery.declaration().id()?.content_id(),
            discovery.declaration().canonical_bytes().len(),
        );
        records.insert(
            discovery.domain().id()?.content_id(),
            discovery.domain().canonical_bytes().len(),
        );
        records.insert(
            discovery.opportunity().id()?.content_id(),
            discovery.opportunity().canonical_bytes().len(),
        );
    }
    for selection in selections {
        records.insert(
            selection.id()?.content_id(),
            selection.canonical_bytes().len(),
        );
    }
    if records.len() > MAX_CRUCIBLE_FINDING_REPLAY_RECORDS {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "finding-replay-retained-record-count",
        }
        .into());
    }
    let signature_bytes = signature.map_or(0, |value| value.canonical_bytes().len());
    let total_bytes = records
        .values()
        .try_fold(signature_bytes, |total, bytes| total.checked_add(*bytes))
        .ok_or(CampaignCodecError::LimitExceeded {
            limit: "finding-replay-retained-record-bytes",
        })?;
    if total_bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "finding-replay-retained-record-bytes",
        }
        .into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PreparedFindingReplayRecords {
    pub(super) configurations: Vec<ConfigurationArtifact>,
    pub(super) measurements: Vec<MeasurementSet>,
    pub(super) properties: Vec<PropertyVerdictSet>,
    pub(super) coverage: Vec<CoverageProjection>,
    pub(super) declarations: Vec<SelectableDeclaration>,
    pub(super) domains: Vec<ChoiceDomain>,
    pub(super) opportunities: Vec<ChoiceOpportunity>,
    pub(super) selections: Vec<Selection>,
    pub(super) record_count: usize,
    pub(super) canonical_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecordedFindingReplay {
    pub(super) signature: Option<FindingSignature>,
    pub(super) configuration: ConfigurationArtifactId,
    pub(super) measurements: MeasurementSetId,
    pub(super) properties: PropertyVerdictSetId,
    pub(super) coverage: CoverageProjectionId,
    pub(super) opportunities: Vec<ChoiceOpportunityId>,
    pub(super) selections: Vec<SelectionId>,
}

/// Incrementally bounded raw oracle transcript for both minimization passes.
///
/// Recording consumes each replay's owned typed records, deduplicates them by
/// authenticated identity, and checks the cumulative object and byte limits
/// before retaining the lightweight pass entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CrucibleFindingReplayTranscript {
    pub(super) minimization_pass: Vec<RecordedFindingReplay>,
    pub(super) verification_pass: Vec<RecordedFindingReplay>,
    pub(super) records: ReplayRecordAccumulator,
}

impl CrucibleFindingReplayTranscript {
    /// Creates an empty two-pass transcript.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            minimization_pass: Vec::new(),
            verification_pass: Vec::new(),
            records: ReplayRecordAccumulator::new(),
        }
    }

    /// Records one oracle result in the minimization pass.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when typed identities fail or the
    /// cumulative retained-record limit is exceeded.
    pub fn record_minimization(
        &mut self,
        candidate: &FindingReproductionArtifact,
        replay: CrucibleFindingReplayEvidence,
    ) -> Result<(), CrucibleArtifactError> {
        if self.minimization_pass.len() == MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-minimization-replay-count",
            }
            .into());
        }
        validate_replay_configuration(candidate, &replay)?;
        let recorded = self.records.record(replay)?;
        self.minimization_pass.push(recorded);
        Ok(())
    }

    /// Records one oracle result in the independent verification pass.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when typed identities fail or the
    /// cumulative retained-record limit is exceeded.
    pub fn record_verification(
        &mut self,
        candidate: &FindingReproductionArtifact,
        replay: CrucibleFindingReplayEvidence,
    ) -> Result<(), CrucibleArtifactError> {
        if self.verification_pass.len() == MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-verification-replay-count",
            }
            .into());
        }
        validate_replay_configuration(candidate, &replay)?;
        let recorded = self.records.record(replay)?;
        self.verification_pass.push(recorded);
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ReplayRecordAccumulator {
    ids: BTreeSet<crucible_cas::content_store::ContentId>,
    configurations: Vec<ConfigurationArtifact>,
    measurements: Vec<MeasurementSet>,
    properties: Vec<PropertyVerdictSet>,
    coverage: Vec<CoverageProjection>,
    declarations: Vec<SelectableDeclaration>,
    domains: Vec<ChoiceDomain>,
    opportunities: Vec<ChoiceOpportunity>,
    selections: Vec<Selection>,
    canonical_bytes: usize,
}

impl ReplayRecordAccumulator {
    const fn new() -> Self {
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

    fn record(
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
        let recorded = RecordedFindingReplay {
            signature: replay.signature,
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

    fn preflight(
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

    pub(super) fn finish(self) -> PreparedFindingReplayRecords {
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

fn validate_owned_replay_selections(
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

pub(super) fn validate_recorded_replay_configuration(
    candidate: &FindingReproductionArtifact,
    replay: &RecordedFindingReplay,
) -> Result<(), CrucibleArtifactError> {
    let scenario = encode_crucible_scenario_artifact(candidate.artifact.scenario_form())?;
    let expected =
        encode_crucible_configuration_artifact(&scenario, candidate.artifact.schedule())?;
    if replay.configuration != expected.id()? {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding replay candidate configuration",
        });
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- exact fixture failures should stop these accounting tests.
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crucible::{
        Configuration, ContentHash, FindingDiscoveryPath, FindingReproductionArtifact, Schedule,
    };
    use crucible_campaign::{FindingKind, MeasurementSet, PropertyVerdictSet};

    use super::*;

    fn replay_fixture() -> (
        FindingReproductionArtifact,
        CrucibleFindingReplayEvidence,
        usize,
    ) {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let configuration = Configuration {
            def: scenario.scenario_def(),
            schedule: Schedule::empty(),
        };
        let fingerprint = ContentHash::from_bytes(b"replay-accounting-fingerprint");
        let finding = FindingReproductionArtifact::capture(
            FindingDiscoveryPath::StateSpaceSearch,
            fingerprint,
            &scenario,
            &configuration,
        )
        .expect("finding reproduction");
        let scenario_record =
            encode_crucible_scenario_artifact(&scenario).expect("scenario record");
        let configuration_record =
            encode_crucible_configuration_artifact(&scenario_record, &Schedule::empty())
                .expect("configuration record");
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            crucible_campaign::CampaignHash::from_bytes(fingerprint.bytes),
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )
        .expect("finding signature");
        let signature_bytes = signature.canonical_bytes().len();
        let replay = CrucibleFindingReplayEvidence::new(
            Some(signature),
            configuration_record,
            MeasurementSet::new(BTreeMap::new()).expect("measurements"),
            PropertyVerdictSet::new(BTreeMap::new()).expect("properties"),
            CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage"),
            Vec::new(),
            Vec::new(),
        )
        .expect("replay evidence");
        (finding, replay, signature_bytes)
    }

    #[test]
    fn duplicate_replays_charge_each_raw_signature_but_deduplicate_records() {
        let (_finding, replay, signature_bytes) = replay_fixture();
        let mut records = ReplayRecordAccumulator::new();

        records.record(replay.clone()).expect("first replay");
        let first_count = records.ids.len();
        let first_bytes = records.canonical_bytes;
        records.record(replay).expect("duplicate replay");

        assert_eq!(records.ids.len(), first_count);
        assert_eq!(records.canonical_bytes, first_bytes + signature_bytes);
    }

    #[test]
    fn failed_byte_admission_is_atomic_and_the_same_replay_can_retry() {
        let (_finding, replay, _signature_bytes) = replay_fixture();
        let mut records = ReplayRecordAccumulator::new();
        records.canonical_bytes = MAX_CRUCIBLE_FINDING_REPLAY_BYTES;
        let before = records.clone();

        assert!(matches!(
            records.record(replay.clone()),
            Err(CrucibleArtifactError::Campaign(
                CampaignCodecError::LimitExceeded {
                    limit: "finding-replay-retained-record-bytes"
                }
            ))
        ));
        assert_eq!(records, before);

        records.canonical_bytes = 0;
        records.record(replay).expect("retry admitted replay");
        assert_eq!(records.ids.len(), 4);
    }

    #[test]
    fn duplicate_evidence_cannot_bypass_the_per_pass_entry_limit() {
        let (finding, replay, _signature_bytes) = replay_fixture();
        let mut transcript = CrucibleFindingReplayTranscript::new();
        for _ in 0..MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS {
            transcript
                .record_minimization(&finding, replay.clone())
                .expect("bounded duplicate replay");
        }
        let records_before = transcript.records.clone();

        assert!(matches!(
            transcript.record_minimization(&finding, replay),
            Err(CrucibleArtifactError::Campaign(
                CampaignCodecError::LimitExceeded {
                    limit: "finding-minimization-replay-count"
                }
            ))
        ));
        assert_eq!(transcript.records, records_before);
        assert_eq!(
            transcript.minimization_pass.len(),
            MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS
        );
    }
}
