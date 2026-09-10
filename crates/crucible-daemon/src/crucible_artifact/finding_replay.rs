//! Bounded typed evidence retained from internal finding-minimizer replays.
//!
//! These records are private validation provenance. They deliberately exclude
//! admitted attempts and graph observations while preserving every typed object
//! that a raw replay signature may reference.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use super::{
    CrucibleArtifactError, FindingReplayPass, MAX_CONFIGURATION_BRANCH_PREFIX_BYTES,
    MAX_CONFIGURATION_SELECTION_DECISIONS, MAX_CRUCIBLE_FINDING_REPLAY_BYTES,
    MAX_CRUCIBLE_FINDING_REPLAY_RECORDS, MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS,
    campaign_configuration_id, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact,
};
use crucible::{
    Configuration, Decision, FailureTriageReplayEvidence, FindingReproductionArtifact,
    SignalFaultSelectable,
};
use crucible_campaign::{
    CampaignCodecError, ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity, ChoiceOpportunityId,
    ConfigurationArtifact, ConfigurationArtifactId, CoverageProjection, CoverageProjectionId,
    FindingKind, FindingSignature, FindingTarget, MeasurementSet, MeasurementSetId,
    PropertyVerdict, PropertyVerdictSet, PropertyVerdictSetId, ResolvedSelection,
    SelectableDeclaration, Selection, SelectionId, SelectionOrigin,
};
use crucible_cas::content_store::ContentId;

/// Producer result retained before durable replay identities are available.
pub type FindingProductionReplayMaterialOutcome = crate::FindingProductionReplayCaptureOutcome<
    Arc<crate::FindingProductionReplayCaptureMaterial>,
>;

/// Stable reason that an exact minimization candidate could not be materialized.
///
/// These outcomes are deterministic properties of the candidate and its
/// authenticated replay prefix. Operational launch, cancellation, and resource
/// failures remain execution errors and never enter this enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingReplayIncompatibility {
    /// Prefix replay diverged before reaching the candidate boundary.
    PrefixDiverged,
    /// Prefix replay reached a modeled terminal state before the boundary.
    PrefixTerminated,
    /// A replayed selection did not match the candidate's choice closure.
    SelectionMismatch,
}

/// Actual result of privately replaying one exact minimization candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutomaticFindingReplayOutcome {
    /// The candidate boundary was reached and evaluated with real model evidence.
    Observed {
        /// Typed semantic evidence evaluated at the exact candidate boundary.
        evidence: Box<CrucibleFindingReplayEvidence>,
        /// Raw measurement leaves needed to reauthenticate `evidence`.
        measurement_replay_evidence: Vec<crate::CrucibleMeasurementReplayEvidence>,
        /// Native full-signature evidence retained from this exact replay.
        triage_evidence: Option<Box<FailureTriageReplayEvidence>>,
        /// Path-free production replay content captured before lifecycle teardown.
        production_replay: Option<FindingProductionReplayMaterialOutcome>,
    },
    /// The exact candidate was deterministically incompatible with its replay prefix.
    DeterministicallyIncompatible {
        /// The exact candidate configuration that could not be materialized.
        configuration: ConfigurationArtifact,
        /// Closed deterministic incompatibility reason.
        reason: FindingReplayIncompatibility,
    },
}

impl AutomaticFindingReplayOutcome {
    /// Wraps one observed replay and its raw measurement leaves.
    #[must_use]
    pub fn observed(
        evidence: CrucibleFindingReplayEvidence,
        measurement_replay_evidence: Vec<crate::CrucibleMeasurementReplayEvidence>,
    ) -> Self {
        Self::Observed {
            evidence: Box::new(evidence),
            measurement_replay_evidence,
            triage_evidence: None,
            production_replay: None,
        }
    }

    /// Wraps one observed replay with independently reconstructed triage evidence.
    #[must_use]
    pub fn observed_with_triage(
        evidence: CrucibleFindingReplayEvidence,
        measurement_replay_evidence: Vec<crate::CrucibleMeasurementReplayEvidence>,
        triage_evidence: FailureTriageReplayEvidence,
    ) -> Self {
        Self::Observed {
            evidence: Box::new(evidence),
            measurement_replay_evidence,
            triage_evidence: Some(Box::new(triage_evidence)),
            production_replay: None,
        }
    }

    /// Attaches a producer-owned production replay capture result.
    #[must_use]
    pub(crate) fn with_production_replay(
        mut self,
        production_replay: FindingProductionReplayMaterialOutcome,
    ) -> Self {
        if let Self::Observed {
            production_replay: retained,
            ..
        } = &mut self
        {
            *retained = Some(production_replay);
        }
        self
    }

    /// Returns the path-free production replay result retained before binding.
    #[must_use]
    pub fn production_replay(&self) -> Option<&FindingProductionReplayMaterialOutcome> {
        match self {
            Self::Observed {
                production_replay, ..
            } => production_replay.as_ref(),
            Self::DeterministicallyIncompatible { .. } => None,
        }
    }

    /// Returns native full-signature evidence when this replay produced it.
    #[must_use]
    pub fn triage_evidence(&self) -> Option<&FailureTriageReplayEvidence> {
        match self {
            Self::Observed {
                triage_evidence, ..
            } => triage_evidence.as_deref(),
            Self::DeterministicallyIncompatible { .. } => None,
        }
    }

    /// Returns the independently observed signature, when a boundary was reached.
    #[must_use]
    pub const fn signature(&self) -> Option<&FindingSignature> {
        match self {
            Self::Observed { evidence, .. } => evidence.signature(),
            Self::DeterministicallyIncompatible { .. } => None,
        }
    }
}

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

    /// Returns the independently evaluated property verdict set.
    #[must_use]
    pub const fn properties(&self) -> &PropertyVerdictSet {
        &self.properties
    }

    /// Returns the independently projected coverage set.
    #[must_use]
    pub const fn coverage(&self) -> &CoverageProjection {
        &self.coverage
    }

    /// Returns retained replay choice opportunities in test builds.
    #[cfg(test)]
    pub(crate) fn opportunities(&self) -> &[ChoiceOpportunity] {
        &self.opportunities
    }

    /// Returns retained replay selections in test builds.
    #[cfg(test)]
    pub(crate) fn selections(&self) -> &[Selection] {
        &self.selections
    }

    /// Binds an independently derived finding signature to this replay.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] if a signature is already present or
    /// the supplied target, property, or causal evidence is not owned by this
    /// exact replay.
    pub fn with_signature(
        mut self,
        signature: FindingSignature,
    ) -> Result<Self, CrucibleArtifactError> {
        if self.signature.is_some() {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay duplicate signature",
            });
        }
        self.signature = Some(signature);
        self.validate_signature_ownership()?;
        Ok(self)
    }

    /// Adds repository-authenticated selections used to reconstruct the candidate prefix.
    ///
    /// Raw replay evidence contains choices discovered while the fresh process
    /// is running. Candidate schedules can also name choices resolved before
    /// launch, including scheduler, application-random, signal-fault, and
    /// environment selections. This merge retains both sources and requires
    /// byte-identical records wherever they overlap.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when an existing replay choice cannot
    /// be reconstructed or a starting record conflicts with replay evidence.
    pub(crate) fn with_resolved_starting_selections(
        self,
        starting: &[ResolvedSelection],
    ) -> Result<Self, CrucibleArtifactError> {
        let declarations = self
            .declarations
            .iter()
            .map(|declaration| declaration.id().map(|id| (id, declaration)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let domains = self
            .domains
            .iter()
            .map(|domain| domain.id().map(|id| (id, domain)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let mut discoveries = BTreeMap::new();
        for opportunity in &self.opportunities {
            let declaration = declarations.get(&opportunity.declaration()).ok_or(
                CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding replay choice declaration closure",
                },
            )?;
            let domain = domains.get(&opportunity.domain()).ok_or(
                CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding replay choice domain closure",
                },
            )?;
            let discovery = ChoiceDiscovery::new(
                (*declaration).clone(),
                (*domain).clone(),
                opportunity.clone(),
            )?;
            discoveries.insert(opportunity.id()?, discovery);
        }
        let mut selections = self
            .selections
            .iter()
            .map(|selection| selection.id().map(|id| (id, selection.clone())))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        for resolved in starting {
            resolved
                .selection()
                .validate_resolved_references(resolved.opportunity(), resolved.domain())?;
            let discovery = ChoiceDiscovery::new(
                resolved.declaration().clone(),
                resolved.domain().clone(),
                resolved.opportunity().clone(),
            )?;
            let opportunity = discovery.opportunity().id()?;
            match discoveries.entry(opportunity) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(discovery);
                }
                std::collections::btree_map::Entry::Occupied(entry)
                    if entry.get() == &discovery => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                        artifact: "finding replay starting choice conflict",
                    });
                }
            }

            let selection = resolved.selection().clone();
            match selections.entry(selection.id()?) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(selection);
                }
                std::collections::btree_map::Entry::Occupied(entry)
                    if entry.get() == &selection => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                        artifact: "finding replay starting selection conflict",
                    });
                }
            }
        }

        Self::new(
            self.signature,
            self.configuration,
            self.measurements,
            self.properties,
            self.coverage,
            discoveries.into_values().collect(),
            selections.into_values().collect(),
        )
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
pub(super) enum RecordedFindingReplay {
    Observed {
        signature: Option<Box<FindingSignature>>,
        configuration: ConfigurationArtifactId,
        measurements: MeasurementSetId,
        properties: PropertyVerdictSetId,
        coverage: CoverageProjectionId,
        opportunities: Vec<ChoiceOpportunityId>,
        selections: Vec<SelectionId>,
    },
    DeterministicallyIncompatible {
        configuration: ConfigurationArtifactId,
        reason: FindingReplayIncompatibility,
    },
}

impl RecordedFindingReplay {
    pub(super) fn signature(&self) -> Option<&FindingSignature> {
        match self {
            Self::Observed { signature, .. } => signature.as_deref(),
            Self::DeterministicallyIncompatible { .. } => None,
        }
    }

    pub(super) const fn configuration(&self) -> ConfigurationArtifactId {
        match self {
            Self::Observed { configuration, .. }
            | Self::DeterministicallyIncompatible { configuration, .. } => *configuration,
        }
    }

    pub(super) fn observed_components(&self) -> Option<RecordedFindingReplayComponents<'_>> {
        match self {
            Self::Observed {
                measurements,
                properties,
                coverage,
                opportunities,
                selections,
                ..
            } => Some((
                *measurements,
                *properties,
                *coverage,
                opportunities,
                selections,
            )),
            Self::DeterministicallyIncompatible { .. } => None,
        }
    }

    pub(super) const fn incompatibility(&self) -> Option<FindingReplayIncompatibility> {
        match self {
            Self::Observed { .. } => None,
            Self::DeterministicallyIncompatible { reason, .. } => Some(*reason),
        }
    }
}

type RecordedFindingReplayComponents<'a> = (
    MeasurementSetId,
    PropertyVerdictSetId,
    CoverageProjectionId,
    &'a [ChoiceOpportunityId],
    &'a [SelectionId],
);

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
    pub(super) triage: RetainedFindingTriageEvidence,
    pub(super) production: RetainedFindingProductionReplayEvidence,
}

impl CrucibleFindingReplayTranscript {
    /// Creates an empty two-pass transcript.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            minimization_pass: Vec::new(),
            verification_pass: Vec::new(),
            records: ReplayRecordAccumulator::new(),
            triage: RetainedFindingTriageEvidence::new(),
            production: RetainedFindingProductionReplayEvidence::new(),
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
        self.record_minimization_outcome(
            candidate,
            AutomaticFindingReplayOutcome::observed(replay, Vec::new()),
        )
    }

    /// Records one typed oracle outcome in the minimization pass.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when the outcome does not name the
    /// exact candidate or the cumulative retained-record limit is exceeded.
    pub fn record_minimization_outcome(
        &mut self,
        candidate: &FindingReproductionArtifact,
        replay: AutomaticFindingReplayOutcome,
    ) -> Result<(), CrucibleArtifactError> {
        let preserves_signature = replay.signature().is_some();
        self.record_minimization_outcome_with_acceptance(candidate, replay, preserves_signature)
    }

    pub(super) fn record_minimization_outcome_with_acceptance(
        &mut self,
        candidate: &FindingReproductionArtifact,
        replay: AutomaticFindingReplayOutcome,
        preserves_signature: bool,
    ) -> Result<(), CrucibleArtifactError> {
        if self.minimization_pass.len() == MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-minimization-replay-count",
            }
            .into());
        }
        let original = self.minimization_pass.is_empty();
        let mut production = self.production.clone();
        production.record(
            FindingReplayPass::Minimization,
            original,
            preserves_signature,
            replay.production_replay().cloned(),
            replay.signature().cloned(),
        )?;
        let mut triage = self.triage.clone();
        triage.record(
            FindingReplayPass::Minimization,
            original,
            preserves_signature,
            candidate,
            replay.triage_evidence().cloned(),
            replay.signature().cloned(),
        )?;
        let recorded = self.records.record_outcome(candidate, replay)?;

        self.production = production;
        self.triage = triage;
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
        self.record_verification_outcome(
            candidate,
            AutomaticFindingReplayOutcome::observed(replay, Vec::new()),
        )
    }

    /// Records one typed oracle outcome in the independent verification pass.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when the outcome does not name the
    /// exact candidate or the cumulative retained-record limit is exceeded.
    pub fn record_verification_outcome(
        &mut self,
        candidate: &FindingReproductionArtifact,
        replay: AutomaticFindingReplayOutcome,
    ) -> Result<(), CrucibleArtifactError> {
        let preserves_signature = replay.signature().is_some();
        self.record_verification_outcome_with_acceptance(candidate, replay, preserves_signature)
    }

    pub(super) fn record_verification_outcome_with_acceptance(
        &mut self,
        candidate: &FindingReproductionArtifact,
        replay: AutomaticFindingReplayOutcome,
        preserves_signature: bool,
    ) -> Result<(), CrucibleArtifactError> {
        if self.verification_pass.len() == MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-verification-replay-count",
            }
            .into());
        }
        let original = self.verification_pass.is_empty();
        let mut production = self.production.clone();
        production.record(
            FindingReplayPass::Verification,
            original,
            preserves_signature,
            replay.production_replay().cloned(),
            replay.signature().cloned(),
        )?;
        let mut triage = self.triage.clone();
        triage.record(
            FindingReplayPass::Verification,
            original,
            preserves_signature,
            candidate,
            replay.triage_evidence().cloned(),
            replay.signature().cloned(),
        )?;
        let recorded = self.records.record_outcome(candidate, replay)?;

        self.production = production;
        self.triage = triage;
        self.verification_pass.push(recorded);
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RetainedFindingProductionReplayEvidence {
    minimization_original: Option<Box<RetainedFindingProductionReplay>>,
    minimization_selected: Option<Box<RetainedFindingProductionReplay>>,
    verification_original: Option<Box<RetainedFindingProductionReplay>>,
    verification_selected: Option<Box<RetainedFindingProductionReplay>>,
    has_capture: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RetainedFindingProductionReplay {
    pub(super) capture: FindingProductionReplayMaterialOutcome,
    pub(super) observed_signature: FindingSignature,
}

impl RetainedFindingProductionReplayEvidence {
    const fn new() -> Self {
        Self {
            minimization_original: None,
            minimization_selected: None,
            verification_original: None,
            verification_selected: None,
            has_capture: false,
        }
    }

    fn record(
        &mut self,
        pass: FindingReplayPass,
        original: bool,
        preserves_signature: bool,
        capture: Option<FindingProductionReplayMaterialOutcome>,
        observed_signature: Option<FindingSignature>,
    ) -> Result<(), CrucibleArtifactError> {
        self.has_capture |= capture.is_some();
        if !original && !preserves_signature {
            return Ok(());
        }
        let capture = match (capture, observed_signature) {
            (Some(capture), Some(observed_signature)) => {
                Some(Box::new(RetainedFindingProductionReplay {
                    capture,
                    observed_signature,
                }))
            }
            (Some(_), None) => {
                return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding production replay signature",
                });
            }
            (None, _) => None,
        };

        match pass {
            FindingReplayPass::Minimization => {
                if original {
                    self.minimization_original = capture.clone();
                }
                if preserves_signature {
                    self.minimization_selected = capture;
                }
            }
            FindingReplayPass::Verification => {
                if original {
                    self.verification_original = capture.clone();
                }
                if preserves_signature {
                    self.verification_selected = capture;
                }
            }
        }
        Ok(())
    }

    pub(super) fn into_parts(
        self,
    ) -> Result<
        Option<(
            RetainedFindingProductionReplay,
            RetainedFindingProductionReplay,
            RetainedFindingProductionReplay,
            RetainedFindingProductionReplay,
        )>,
        CrucibleArtifactError,
    > {
        if !self.has_capture {
            return Ok(None);
        }
        let (
            Some(minimization_original),
            Some(minimization_selected),
            Some(verification_original),
            Some(verification_selected),
        ) = (
            self.minimization_original,
            self.minimization_selected,
            self.verification_original,
            self.verification_selected,
        )
        else {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "incomplete finding production replay evidence",
            });
        };
        Ok(Some((
            *minimization_original,
            *minimization_selected,
            *verification_original,
            *verification_selected,
        )))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RetainedFindingTriageEvidence {
    minimization_original: Option<Box<RetainedFindingTriageReplay>>,
    minimization_selected: Option<Box<RetainedFindingTriageReplay>>,
    verification_original: Option<Box<RetainedFindingTriageReplay>>,
    verification_selected: Option<Box<RetainedFindingTriageReplay>>,
    has_rich_evidence: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RetainedFindingTriageReplay {
    pub(super) evidence: FailureTriageReplayEvidence,
    pub(super) observed_signature: FindingSignature,
}

impl RetainedFindingTriageEvidence {
    const fn new() -> Self {
        Self {
            minimization_original: None,
            minimization_selected: None,
            verification_original: None,
            verification_selected: None,
            has_rich_evidence: false,
        }
    }

    fn record(
        &mut self,
        pass: FindingReplayPass,
        original: bool,
        preserves_signature: bool,
        candidate: &FindingReproductionArtifact,
        evidence: Option<FailureTriageReplayEvidence>,
        observed_signature: Option<FindingSignature>,
    ) -> Result<(), CrucibleArtifactError> {
        if evidence
            .as_ref()
            .is_some_and(|evidence| evidence.finding() != candidate)
        {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding triage replay candidate",
            });
        }
        self.has_rich_evidence |= evidence.is_some();
        let evidence = match (evidence, observed_signature) {
            (Some(evidence), Some(observed_signature)) => {
                Some(Box::new(RetainedFindingTriageReplay {
                    evidence,
                    observed_signature,
                }))
            }
            (Some(_), None) => {
                return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding triage replay signature",
                });
            }
            (None, _) => None,
        };

        match pass {
            FindingReplayPass::Minimization => {
                if original {
                    self.minimization_original = evidence.clone();
                }
                if preserves_signature {
                    self.minimization_selected = evidence;
                }
            }
            FindingReplayPass::Verification => {
                if original {
                    self.verification_original = evidence.clone();
                }
                if preserves_signature {
                    self.verification_selected = evidence;
                }
            }
        }
        Ok(())
    }

    pub(super) fn into_parts(
        self,
    ) -> Result<
        Option<(
            RetainedFindingTriageReplay,
            RetainedFindingTriageReplay,
            RetainedFindingTriageReplay,
            RetainedFindingTriageReplay,
        )>,
        CrucibleArtifactError,
    > {
        if !self.has_rich_evidence {
            return Ok(None);
        }
        let (
            Some(minimization_original),
            Some(minimization_selected),
            Some(verification_original),
            Some(verification_selected),
        ) = (
            self.minimization_original,
            self.minimization_selected,
            self.verification_original,
            self.verification_selected,
        )
        else {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "incomplete finding triage replay evidence",
            });
        };
        Ok(Some((
            *minimization_original,
            *minimization_selected,
            *verification_original,
            *verification_selected,
        )))
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

    #[cfg(test)]
    fn record(
        &mut self,
        replay: CrucibleFindingReplayEvidence,
    ) -> Result<RecordedFindingReplay, CrucibleArtifactError> {
        self.record_observed(replay)
    }

    fn record_outcome(
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

    fn record_observed(
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

fn validate_incompatible_configuration(
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
    if replay.configuration() != expected.id()? {
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
    use std::sync::Arc;

    use crucible::model::{BindingSearchChoice, SearchChoiceId};
    use crucible::{
        AppRandomSelectable, Configuration, ContentHash, Decision, FindingDiscoveryPath,
        FindingReproductionArtifact, NodeId, RngStreamId, Schedule, SearchFrontierChoices,
        SearchRuntimeFrontier, SelectionDecision, SignalFaultSelectable, VirtualTime,
    };
    use crucible_campaign::{
        CampaignExecutorStore, CampaignRepository, ChoiceDiscovery, FindingKind, MeasurementSet,
        PropertyVerdictSet, ResolvedSelection,
    };
    use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

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

    fn resolved_selection(
        label: &str,
        discovery: &ChoiceDiscovery,
        selection: &Selection,
    ) -> ResolvedSelection {
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(label, u64::MAX)),
            Arc::new(MemoryRefBackend::new()),
        ));
        repository
            .publish_choice_domain(discovery.domain())
            .expect("publish choice domain");
        repository
            .publish_selectable(discovery.declaration())
            .expect("publish selectable declaration");
        repository
            .publish_choice_opportunity(discovery.opportunity())
            .expect("publish choice opportunity");
        repository
            .publish_selection(selection)
            .expect("publish selection");
        let id = selection.id().expect("selection ID");
        CampaignExecutorStore::new(repository)
            .resolve_selections(&[id])
            .expect("resolve selection closure")
            .pop()
            .expect("one resolved selection")
    }

    fn unsigned_replay(
        scenario: &crucible::ScenarioDefForm,
        configuration: &Configuration,
    ) -> CrucibleFindingReplayEvidence {
        let scenario_record = encode_crucible_scenario_artifact(scenario).expect("scenario record");
        let configuration_record =
            encode_crucible_configuration_artifact(&scenario_record, &configuration.schedule)
                .expect("configuration record");
        CrucibleFindingReplayEvidence::new(
            None,
            configuration_record,
            MeasurementSet::new(BTreeMap::new()).expect("measurements"),
            PropertyVerdictSet::new(BTreeMap::new()).expect("properties"),
            CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage"),
            Vec::new(),
            Vec::new(),
        )
        .expect("unsigned replay")
    }

    fn reproduction(
        scenario: &crucible::ScenarioDefForm,
        configuration: &Configuration,
        fingerprint: &[u8],
    ) -> FindingReproductionArtifact {
        FindingReproductionArtifact::capture(
            FindingDiscoveryPath::StateSpaceSearch,
            ContentHash::from_bytes(fingerprint),
            scenario,
            configuration,
        )
        .expect("finding reproduction")
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

    fn replay_with_production_capture(
        replay: CrucibleFindingReplayEvidence,
    ) -> AutomaticFindingReplayOutcome {
        AutomaticFindingReplayOutcome::observed(replay, Vec::new()).with_production_replay(
            crate::FindingProductionReplayCaptureOutcome::Incomplete(
                crate::FindingProductionReplayIncomplete::MissingEventLogPrefix,
            ),
        )
    }

    fn record_transcript_pass(
        transcript: &mut CrucibleFindingReplayTranscript,
        pass: FindingReplayPass,
        candidate: &FindingReproductionArtifact,
        replay: AutomaticFindingReplayOutcome,
    ) -> Result<(), CrucibleArtifactError> {
        match pass {
            FindingReplayPass::Minimization => {
                transcript.record_minimization_outcome(candidate, replay)
            }
            FindingReplayPass::Verification => {
                transcript.record_verification_outcome(candidate, replay)
            }
        }
    }

    #[test]
    fn transcript_admission_is_atomic_across_identity_failure_and_retry() {
        let (finding, replay, _) = replay_fixture();
        let wrong_scenario = crucible::crash_restart_scenario()
            .expect("crash-restart scenario")
            .scenario;
        let wrong_configuration = Configuration {
            def: wrong_scenario.scenario_def(),
            schedule: Schedule::empty(),
        };
        let wrong_finding = reproduction(
            &wrong_scenario,
            &wrong_configuration,
            b"wrong-replay-candidate",
        );

        for pass in [
            FindingReplayPass::Minimization,
            FindingReplayPass::Verification,
        ] {
            let outcome = replay_with_production_capture(replay.clone());
            let mut transcript = CrucibleFindingReplayTranscript::new();
            let before = transcript.clone();

            assert!(matches!(
                record_transcript_pass(&mut transcript, pass, &wrong_finding, outcome.clone()),
                Err(CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding replay candidate configuration"
                })
            ));
            assert_eq!(transcript, before);

            record_transcript_pass(&mut transcript, pass, &finding, outcome)
                .expect("identical replay admitted after corrected candidate identity");
            assert!(transcript.production.has_capture);
            assert_eq!(
                transcript.minimization_pass.len() + transcript.verification_pass.len(),
                1
            );
        }
    }

    #[test]
    fn transcript_admission_is_atomic_across_byte_failure_and_retry() {
        let (finding, replay, _) = replay_fixture();

        for pass in [
            FindingReplayPass::Minimization,
            FindingReplayPass::Verification,
        ] {
            let outcome = replay_with_production_capture(replay.clone());
            let mut transcript = CrucibleFindingReplayTranscript::new();
            transcript.records.canonical_bytes = MAX_CRUCIBLE_FINDING_REPLAY_BYTES;
            let before = transcript.clone();

            assert!(matches!(
                record_transcript_pass(&mut transcript, pass, &finding, outcome.clone()),
                Err(CrucibleArtifactError::Campaign(
                    CampaignCodecError::LimitExceeded {
                        limit: "finding-replay-retained-record-bytes"
                    }
                ))
            ));
            assert_eq!(transcript, before);

            transcript.records.canonical_bytes = 0;
            record_transcript_pass(&mut transcript, pass, &finding, outcome)
                .expect("identical replay admitted after byte capacity became available");
            assert!(transcript.production.has_capture);
            assert_eq!(
                transcript.minimization_pass.len() + transcript.verification_pass.len(),
                1
            );
        }
    }

    #[test]
    fn production_replay_retention_selects_the_four_named_required_outcomes() {
        let (_finding, replay, _) = replay_fixture();
        let signature = replay.signature().expect("signed replay").clone();
        let mut retained = RetainedFindingProductionReplayEvidence::new();
        let outcome = |reason| {
            Some(crate::FindingProductionReplayCaptureOutcome::Incomplete(
                reason,
            ))
        };

        retained
            .record(
                FindingReplayPass::Minimization,
                true,
                true,
                outcome(crate::FindingProductionReplayIncomplete::MissingEventLogPrefix),
                Some(signature.clone()),
            )
            .expect("minimization original");
        retained
            .record(
                FindingReplayPass::Minimization,
                false,
                false,
                outcome(crate::FindingProductionReplayIncomplete::MissingTerminalFingerprints),
                Some(signature.clone()),
            )
            .expect("discarded minimization candidate");
        retained
            .record(
                FindingReplayPass::Minimization,
                false,
                true,
                outcome(crate::FindingProductionReplayIncomplete::MissingSignalArtifactStore),
                Some(signature.clone()),
            )
            .expect("selected minimization candidate");
        retained
            .record(
                FindingReplayPass::Verification,
                true,
                true,
                outcome(crate::FindingProductionReplayIncomplete::MissingWorldArtifactStore),
                Some(signature.clone()),
            )
            .expect("verification original");
        retained
            .record(
                FindingReplayPass::Verification,
                false,
                true,
                outcome(crate::FindingProductionReplayIncomplete::PublicationLimitExceeded),
                Some(signature),
            )
            .expect("verification selected");

        let Some((min_original, min_selected, verify_original, verify_selected)) =
            retained.into_parts().expect("complete required replay set")
        else {
            panic!("production replay retention was unexpectedly disabled")
        };
        assert_eq!(
            min_original.capture,
            crate::FindingProductionReplayCaptureOutcome::Incomplete(
                crate::FindingProductionReplayIncomplete::MissingEventLogPrefix
            )
        );
        assert_eq!(
            min_selected.capture,
            crate::FindingProductionReplayCaptureOutcome::Incomplete(
                crate::FindingProductionReplayIncomplete::MissingSignalArtifactStore
            )
        );
        assert_eq!(
            verify_original.capture,
            crate::FindingProductionReplayCaptureOutcome::Incomplete(
                crate::FindingProductionReplayIncomplete::MissingWorldArtifactStore
            )
        );
        assert_eq!(
            verify_selected.capture,
            crate::FindingProductionReplayCaptureOutcome::Incomplete(
                crate::FindingProductionReplayIncomplete::PublicationLimitExceeded
            )
        );
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

    #[test]
    fn starting_app_random_selection_is_retained_in_exact_replay_closure() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let selectable = AppRandomSelectable::new(
            &scenario.scenario_def(),
            NodeId {
                name: String::from("node-a"),
            },
            RngStreamId::for_node("finding-replay-app-random"),
            11,
            16,
        )
        .expect("app-random selectable");
        let selection = selectable
            .sampled_selection(0x1234_5678_9abc_def0)
            .expect("sampled selection");
        let discovery = selectable.into_discovery().expect("app-random discovery");
        let configuration = Configuration {
            def: scenario.scenario_def(),
            schedule: Schedule::empty()
                .appended(Decision::Selection(SelectionDecision::new(&selection))),
        };
        let finding = reproduction(&scenario, &configuration, b"app-random-replay-closure");
        let resolved = resolved_selection("app-random-replay-closure", &discovery, &selection);

        let replay = unsigned_replay(&scenario, &configuration)
            .with_resolved_starting_selections(&[resolved])
            .expect("merge app-random closure");

        validate_replay_configuration(&finding, &replay)
            .expect("app-random selection remains independently verifiable");
        assert_eq!(replay.opportunities, vec![discovery.opportunity().clone()]);
        assert_eq!(replay.selections, vec![selection]);
    }

    #[test]
    fn starting_signal_fault_selection_is_retained_in_exact_replay_closure() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let parent = Configuration::genesis(scenario.scenario_def());
        let choice = BindingSearchChoice {
            id: SearchChoiceId::from_content_hash(ContentHash::from_bytes(
                b"finding-replay-signal-choice",
            )),
            candidates_digest: ContentHash::from_bytes(b"finding-replay-signal-candidates"),
            candidate_count: 2,
            selected_index: None,
            overridden: false,
        };
        let frontier = SearchRuntimeFrontier {
            configuration: parent.clone(),
            at: VirtualTime { ticks: 17 },
            choices: SearchFrontierChoices::from_decisions(
                choice
                    .override_decisions(parent.id())
                    .into_iter()
                    .map(Decision::Override),
            ),
        };
        let selectable =
            SignalFaultSelectable::from_frontier(&frontier).expect("signal-fault selectable");
        let selection = selectable
            .branch_selection(&parent, 1)
            .expect("signal-fault selection");
        let discovery = selectable.discovery().expect("signal-fault discovery");
        let branch = selectable
            .resolve_branch(&selection)
            .expect("signal-fault branch");
        let configuration = branch.selected().clone();
        let finding = reproduction(&scenario, &configuration, b"signal-fault-replay-closure");
        let resolved = resolved_selection("signal-fault-replay-closure", &discovery, &selection);

        let replay = unsigned_replay(&scenario, &configuration)
            .with_resolved_starting_selections(&[resolved])
            .expect("merge signal-fault closure");

        validate_replay_configuration(&finding, &replay)
            .expect("signal-fault selection remains independently verifiable");
        assert_eq!(replay.opportunities, vec![discovery.opportunity().clone()]);
        assert_eq!(replay.selections, vec![selection]);
    }
}
