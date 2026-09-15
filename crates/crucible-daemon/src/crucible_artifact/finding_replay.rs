//! Bounded typed evidence retained from internal finding-minimizer replays.
//!
//! These records are private validation provenance. They deliberately exclude
//! admitted attempts and graph observations while preserving every typed object
//! that a raw replay signature may reference.

use std::collections::{BTreeMap, BTreeSet};

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

mod accumulator;
use accumulator::ReplayRecordAccumulator;
pub(crate) use accumulator::validate_recorded_replay_configuration;
#[cfg(test)]
use accumulator::validate_replay_configuration;

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
    pub(crate) fn with_signature(
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
        self.triage.record(
            FindingReplayPass::Minimization,
            self.minimization_pass.is_empty(),
            preserves_signature,
            candidate,
            replay.triage_evidence().cloned(),
            replay.signature().cloned(),
        )?;
        let recorded = self.records.record_outcome(candidate, replay)?;
        self.minimization_pass.push(recorded);
        Ok(())
    }

    pub(crate) fn record_verification_outcome_with_acceptance(
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
        self.triage.record(
            FindingReplayPass::Verification,
            self.verification_pass.is_empty(),
            preserves_signature,
            candidate,
            replay.triage_evidence().cloned(),
            replay.signature().cloned(),
        )?;
        let recorded = self.records.record_outcome(candidate, replay)?;
        self.verification_pass.push(recorded);
        Ok(())
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
        CampaignExecutorStore, CampaignRepository, ChoiceDiscovery, FindingKind,
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
            crate::crucible_measurement::empty_test_measurement_set(),
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
            crate::crucible_measurement::empty_test_measurement_set(),
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

        records
            .record_observed(replay.clone())
            .expect("first replay");
        let first_count = records.ids.len();
        let first_bytes = records.canonical_bytes;
        records.record_observed(replay).expect("duplicate replay");

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
            records.record_observed(replay.clone()),
            Err(CrucibleArtifactError::Campaign(
                CampaignCodecError::LimitExceeded {
                    limit: "finding-replay-retained-record-bytes"
                }
            ))
        ));
        assert_eq!(records, before);

        records.canonical_bytes = 0;
        records
            .record_observed(replay)
            .expect("retry admitted replay");
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
            candidate_semantics: crucible::model::BindingSearchCandidateSemantics::Outcome,
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
