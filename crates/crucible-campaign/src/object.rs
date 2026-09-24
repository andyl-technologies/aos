//! Record-specific campaign validation over generic content envelopes.
//!
//! [`ContentEnvelope`] lives in `crucible-cas`, below campaign semantics, so a
//! generic store can walk child references. This module seals construction and
//! derives the exact child table from each decoded campaign record. Callers
//! cannot attach extra retention edges or omit referenced content.

use std::collections::BTreeSet;

use crucible_cas::content_envelope::{ContentChild, ContentEnvelope};
use crucible_cas::content_store::{ContentId, ObjectKind};

use crate::choice::{
    ChoiceDomain, ChoiceGroup, ChoiceOpportunity, SelectableDeclaration, Selection,
};
use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    Attempt, AttemptAdmission, BranchPath, BranchRequest, CampaignArchiveInventoryPage,
    CampaignArchiveManifest, CampaignCodecError, CampaignControlAction, CampaignFact,
    CampaignLineage, CampaignPlanningView, CampaignPolicy, CampaignSnapshot, ConfigurationArtifact,
    ContinuationProjection, CoverageProjection, ExpansionCredit, ExpansionState, Finding,
    FindingCandidateBundle, FindingTriageReplayEvidence, MeasurementSet, ObjectiveEvaluation,
    Observation, PlannerEngine, PlannerInvocation, PlannerRequest, PlannerState, PlannerStep,
    PolicyArtifact, PropertyVerdictSet, Proposal, RankingExplanation, ReproductionArtifact,
    ScenarioArtifact, SurvivorSelection,
};

mod validation;

pub(crate) use validation::content_children;
use validation::{fact_children, snapshot_children};

pub use crucible_cas::content_envelope::ContentChild as ChildReference;

const RECORD_SCHEMA_VERSION: u32 = 1;

/// Closed canonical record kind stored in a campaign object envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CampaignRecordKind {
    /// Compatibility lineage descriptor.
    Lineage,
    /// Immutable campaign policy revision.
    Policy,
    /// Immutable campaign snapshot.
    Snapshot,
    /// One causal campaign fact.
    Fact,
    /// Complete bounded planning view.
    PlanningView,
    /// Pure planner engine descriptor.
    PlannerEngine,
    /// Reproducible policy artifact descriptor.
    PolicyArtifact,
    /// Bounded portable planner state.
    PlannerState,
    /// Complete planner invocation basis.
    PlannerInvocation,
    /// Typed choice domain.
    ChoiceDomain,
    /// Reusable selectable declaration.
    SelectableDeclaration,
    /// Stable runtime choice occurrence.
    ChoiceOpportunity,
    /// Atomic choice group.
    ChoiceGroup,
    /// Recorded modeled selection.
    Selection,
    /// Persistent Merkle map/set node.
    MerkleNode,
    /// Closed versioned candidate-generator specification.
    CandidateGeneratorSpec,
    /// Exact scenario-definition artifact retained by the lineage.
    ScenarioArtifact,
    /// Exact genesis or branch configuration retained by the graph.
    ConfigurationArtifact,
    /// Additive finite or generated source at one branch point.
    BranchRequest,
    /// One value proposed from a branch request.
    Proposal,
    /// Authenticated ordered semantic edge path.
    BranchPath,
    /// Immutable semantic execution attempt.
    Attempt,
    /// Immutable execution basis or additional cause.
    AttemptAdmission,
    /// Coordinator-accepted pure planner step.
    PlannerStep,
    /// Rebuildable branch-point expansion projection.
    ExpansionState,
    /// Exact bounded measurement samples and aggregates.
    MeasurementSet,
    /// Exact property verdicts and retained evidence.
    PropertyVerdictSet,
    /// Grow-only coverage identities and derivation evidence.
    CoverageProjection,
    /// Canonical modeled result of one admitted attempt.
    Observation,
    /// Exact policy-bound objective vector and admissibility evidence.
    ObjectiveEvaluation,
    /// Deterministic per-candidate ranking explanation.
    RankingExplanation,
    /// Bounded survivor selection over an exact considered set.
    SurvivorSelection,
    /// Retained canonical pure-planner component request.
    RetainedPlannerRequest,
    /// Authenticated per-request continuation projection.
    ContinuationProjection,
    /// Idempotent observation visit credited to one branch point.
    ExpansionCredit,
    /// Verifier-backed self-contained finding reproduction.
    ReproductionArtifact,
    /// Canonical stable finding cluster.
    Finding,
    /// Snapshot-bound fixed-point guidance for one planner candidate.
    PlannerCandidateGuidance,
    /// Exact aggregate grants and spending under the budget-ledger contract.
    BudgetLedger,
    /// Snapshot-bound budget eligibility for one exact planner offer.
    PlannerCandidateBudget,
    /// Snapshot-bound Beam membership for one frontier candidate.
    PlannerBeamCandidate,
    /// Snapshot-bound graph-search ordering key for one frontier candidate.
    PlannerSearchCandidate,
    /// Exact replay inputs for reconstructing one observed finding signature.
    FindingTriageReplayEvidence,
    /// One bounded opaque payload segment owned by replay-evidence manifest.
    FindingTriageReplayEvidenceChunk,
    /// Durable executor-produced finding candidate handoff.
    FindingCandidateBundle,
    /// Authenticated partial or complete campaign archive boundary.
    ArchiveManifest,
    /// Bounded direct-object inventory page owned by an archive manifest.
    ArchiveInventoryPage,
}

impl CampaignRecordKind {
    /// Every campaign record schema admitted by this crate.
    pub const ALL: [Self; 47] = [
        Self::Lineage,
        Self::Policy,
        Self::Snapshot,
        Self::Fact,
        Self::PlanningView,
        Self::PlannerEngine,
        Self::PolicyArtifact,
        Self::PlannerState,
        Self::PlannerInvocation,
        Self::ChoiceDomain,
        Self::SelectableDeclaration,
        Self::ChoiceOpportunity,
        Self::ChoiceGroup,
        Self::Selection,
        Self::MerkleNode,
        Self::CandidateGeneratorSpec,
        Self::ScenarioArtifact,
        Self::ConfigurationArtifact,
        Self::BranchRequest,
        Self::Proposal,
        Self::BranchPath,
        Self::Attempt,
        Self::AttemptAdmission,
        Self::PlannerStep,
        Self::ExpansionState,
        Self::MeasurementSet,
        Self::PropertyVerdictSet,
        Self::CoverageProjection,
        Self::Observation,
        Self::ObjectiveEvaluation,
        Self::RankingExplanation,
        Self::SurvivorSelection,
        Self::RetainedPlannerRequest,
        Self::ContinuationProjection,
        Self::ExpansionCredit,
        Self::ReproductionArtifact,
        Self::Finding,
        Self::PlannerCandidateGuidance,
        Self::BudgetLedger,
        Self::PlannerCandidateBudget,
        Self::FindingCandidateBundle,
        Self::ArchiveManifest,
        Self::ArchiveInventoryPage,
        Self::PlannerBeamCandidate,
        Self::PlannerSearchCandidate,
        Self::FindingTriageReplayEvidence,
        Self::FindingTriageReplayEvidenceChunk,
    ];

    /// Returns the globally registered canonical schema name.
    #[must_use]
    pub const fn schema_name(self) -> &'static str {
        match self {
            Self::Lineage => "crucible.campaign.lineage",
            Self::Policy => "crucible.campaign.policy",
            Self::Snapshot => "crucible.campaign.snapshot",
            Self::Fact => "crucible.campaign.fact",
            Self::PlanningView => "crucible.campaign.planning-view",
            Self::PlannerEngine => "crucible.campaign.planner-engine",
            Self::PolicyArtifact => "crucible.campaign.policy-artifact",
            Self::PlannerState => "crucible.campaign.planner-state",
            Self::PlannerInvocation => "crucible.campaign.planner-invocation",
            Self::ChoiceDomain => "crucible.campaign.choice-domain",
            Self::SelectableDeclaration => "crucible.campaign.selectable-declaration",
            Self::ChoiceOpportunity => "crucible.campaign.choice-opportunity",
            Self::ChoiceGroup => "crucible.campaign.choice-group",
            Self::Selection => "crucible.campaign.selection",
            Self::MerkleNode => "crucible.campaign.merkle-node",
            Self::CandidateGeneratorSpec => "crucible.campaign.candidate-generator-spec",
            Self::ScenarioArtifact => "crucible.campaign.scenario-artifact",
            Self::ConfigurationArtifact => "crucible.campaign.configuration-artifact",
            Self::BranchRequest => "crucible.campaign.branch-request",
            Self::Proposal => "crucible.campaign.proposal",
            Self::BranchPath => "crucible.campaign.branch-path",
            Self::Attempt => "crucible.campaign.attempt",
            Self::AttemptAdmission => "crucible.campaign.attempt-admission",
            Self::PlannerStep => "crucible.campaign.planner-step",
            Self::ExpansionState => "crucible.campaign.expansion-state",
            Self::MeasurementSet => "crucible.campaign.measurement-set",
            Self::PropertyVerdictSet => "crucible.campaign.property-verdict-set",
            Self::CoverageProjection => "crucible.campaign.coverage-projection",
            Self::Observation => "crucible.campaign.observation",
            Self::ObjectiveEvaluation => "crucible.campaign.objective-evaluation",
            Self::RankingExplanation => "crucible.campaign.ranking-explanation",
            Self::SurvivorSelection => "crucible.campaign.survivor-selection",
            Self::RetainedPlannerRequest => "crucible.campaign.retained-planner-request",
            Self::ContinuationProjection => "crucible.campaign.continuation-projection",
            Self::ExpansionCredit => "crucible.campaign.expansion-credit",
            Self::ReproductionArtifact => "crucible.campaign.reproduction-artifact",
            Self::Finding => "crucible.campaign.finding",
            Self::PlannerCandidateGuidance => "crucible.campaign.planner-candidate-guidance",
            Self::BudgetLedger => "crucible.campaign.budget-ledger",
            Self::PlannerCandidateBudget => "crucible.campaign.planner-candidate-budget",
            Self::PlannerBeamCandidate => "crucible.campaign.planner-beam-candidate",
            Self::PlannerSearchCandidate => "crucible.campaign.planner-search-candidate",
            Self::FindingTriageReplayEvidence => "crucible.campaign.finding-triage-replay-evidence",
            Self::FindingTriageReplayEvidenceChunk => {
                "crucible.campaign.finding-triage-replay-evidence-chunk"
            }
            Self::FindingCandidateBundle => "crucible.campaign.finding-candidate-bundle",
            Self::ArchiveManifest => "crucible.campaign.archive-manifest",
            Self::ArchiveInventoryPage => "crucible.campaign.archive-inventory-page",
        }
    }

    /// Returns the canonical schema version supported for this record.
    #[must_use]
    pub const fn schema_version(self) -> u32 {
        match self {
            Self::Policy => 5,
            Self::Snapshot => 3,
            Self::Fact => 15,
            Self::PlannerInvocation => 2,
            Self::PlannerStep => 4,
            Self::ExpansionState => 2,
            Self::ChoiceDomain => 2,
            Self::ChoiceGroup => 3,
            Self::BranchRequest => 10,
            Self::Proposal => 3,
            Self::BranchPath => 2,
            Self::Attempt => 9,
            Self::AttemptAdmission => 3,
            Self::MeasurementSet => 2,
            Self::Observation => 14,
            Self::ObjectiveEvaluation | Self::RankingExplanation => 2,
            Self::ReproductionArtifact => 2,
            Self::Finding => 4,
            Self::FindingCandidateBundle => 7,
            Self::FindingTriageReplayEvidence => 2,
            Self::ArchiveManifest | Self::ArchiveInventoryPage => RECORD_SCHEMA_VERSION,
            Self::PlannerCandidateGuidance | Self::PlannerCandidateBudget | Self::BudgetLedger => 2,
            Self::PlannerBeamCandidate => 2,
            _ => RECORD_SCHEMA_VERSION,
        }
    }

    fn parse_schema_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.schema_name() == value)
    }

    /// Returns the storage-domain kind that separates this record's content ID.
    #[must_use]
    pub const fn object_kind(self) -> ObjectKind {
        match self {
            Self::Policy
            | Self::PlannerEngine
            | Self::PolicyArtifact
            | Self::PlannerState
            | Self::PlannerInvocation
            | Self::CandidateGeneratorSpec => ObjectKind::Policy,
            Self::Snapshot => ObjectKind::CampaignSnapshot,
            Self::MerkleNode => ObjectKind::MerkleNode,
            Self::ScenarioArtifact => ObjectKind::Scenario,
            Self::ConfigurationArtifact => ObjectKind::Configuration,
            Self::ExpansionState
            | Self::ContinuationProjection
            | Self::PlannerCandidateGuidance
            | Self::PlannerCandidateBudget
            | Self::PlannerBeamCandidate
            | Self::PlannerSearchCandidate
            | Self::CoverageProjection
            | Self::RankingExplanation => ObjectKind::Projection,
            Self::ArchiveManifest | Self::ArchiveInventoryPage => ObjectKind::Projection,
            Self::MeasurementSet
            | Self::PropertyVerdictSet
            | Self::Observation
            | Self::ObjectiveEvaluation => ObjectKind::Observation,
            Self::ReproductionArtifact
            | Self::Finding
            | Self::FindingCandidateBundle
            | Self::FindingTriageReplayEvidence
            | Self::FindingTriageReplayEvidenceChunk => ObjectKind::Finding,
            Self::Lineage
            | Self::BudgetLedger
            | Self::Fact
            | Self::PlanningView
            | Self::ChoiceDomain
            | Self::SelectableDeclaration
            | Self::ChoiceOpportunity
            | Self::ChoiceGroup
            | Self::Selection
            | Self::BranchRequest
            | Self::Proposal
            | Self::BranchPath
            | Self::Attempt
            | Self::AttemptAdmission
            | Self::PlannerStep
            | Self::ExpansionCredit
            | Self::SurvivorSelection => ObjectKind::CampaignFact,
            Self::RetainedPlannerRequest => ObjectKind::Policy,
        }
    }
}

impl Canonical for CampaignRecordKind {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Lineage => 0,
            Self::Policy => 1,
            Self::Snapshot => 2,
            Self::Fact => 3,
            Self::PlanningView => 4,
            Self::PlannerEngine => 5,
            Self::PolicyArtifact => 6,
            Self::PlannerState => 7,
            Self::PlannerInvocation => 8,
            Self::ChoiceDomain => 9,
            Self::SelectableDeclaration => 10,
            Self::ChoiceOpportunity => 11,
            Self::ChoiceGroup => 12,
            Self::Selection => 13,
            Self::MerkleNode => 14,
            Self::CandidateGeneratorSpec => 15,
            Self::ScenarioArtifact => 16,
            Self::ConfigurationArtifact => 17,
            Self::BranchRequest => 18,
            Self::Proposal => 19,
            Self::BranchPath => 20,
            Self::Attempt => 21,
            Self::AttemptAdmission => 22,
            Self::PlannerStep => 23,
            Self::ExpansionState => 24,
            Self::MeasurementSet => 25,
            Self::PropertyVerdictSet => 26,
            Self::CoverageProjection => 27,
            Self::Observation => 28,
            Self::RetainedPlannerRequest => 29,
            Self::ContinuationProjection => 30,
            Self::ExpansionCredit => 31,
            Self::ReproductionArtifact => 32,
            Self::Finding => 33,
            Self::ObjectiveEvaluation => 34,
            Self::RankingExplanation => 35,
            Self::SurvivorSelection => 36,
            Self::PlannerCandidateGuidance => 37,
            Self::BudgetLedger => 38,
            Self::PlannerCandidateBudget => 39,
            Self::FindingCandidateBundle => 40,
            Self::ArchiveManifest => 41,
            Self::ArchiveInventoryPage => 42,
            Self::PlannerBeamCandidate => 43,
            Self::PlannerSearchCandidate => 44,
            Self::FindingTriageReplayEvidence => 45,
            Self::FindingTriageReplayEvidenceChunk => 46,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Lineage),
            1 => Ok(Self::Policy),
            2 => Ok(Self::Snapshot),
            3 => Ok(Self::Fact),
            4 => Ok(Self::PlanningView),
            5 => Ok(Self::PlannerEngine),
            6 => Ok(Self::PolicyArtifact),
            7 => Ok(Self::PlannerState),
            8 => Ok(Self::PlannerInvocation),
            9 => Ok(Self::ChoiceDomain),
            10 => Ok(Self::SelectableDeclaration),
            11 => Ok(Self::ChoiceOpportunity),
            12 => Ok(Self::ChoiceGroup),
            13 => Ok(Self::Selection),
            14 => Ok(Self::MerkleNode),
            15 => Ok(Self::CandidateGeneratorSpec),
            16 => Ok(Self::ScenarioArtifact),
            17 => Ok(Self::ConfigurationArtifact),
            18 => Ok(Self::BranchRequest),
            19 => Ok(Self::Proposal),
            20 => Ok(Self::BranchPath),
            21 => Ok(Self::Attempt),
            22 => Ok(Self::AttemptAdmission),
            23 => Ok(Self::PlannerStep),
            24 => Ok(Self::ExpansionState),
            25 => Ok(Self::MeasurementSet),
            26 => Ok(Self::PropertyVerdictSet),
            27 => Ok(Self::CoverageProjection),
            28 => Ok(Self::Observation),
            29 => Ok(Self::RetainedPlannerRequest),
            30 => Ok(Self::ContinuationProjection),
            31 => Ok(Self::ExpansionCredit),
            32 => Ok(Self::ReproductionArtifact),
            33 => Ok(Self::Finding),
            34 => Ok(Self::ObjectiveEvaluation),
            35 => Ok(Self::RankingExplanation),
            36 => Ok(Self::SurvivorSelection),
            37 => Ok(Self::PlannerCandidateGuidance),
            38 => Ok(Self::BudgetLedger),
            39 => Ok(Self::PlannerCandidateBudget),
            40 => Ok(Self::FindingCandidateBundle),
            41 => Ok(Self::ArchiveManifest),
            42 => Ok(Self::ArchiveInventoryPage),
            43 => Ok(Self::PlannerBeamCandidate),
            44 => Ok(Self::PlannerSearchCandidate),
            45 => Ok(Self::FindingTriageReplayEvidence),
            46 => Ok(Self::FindingTriageReplayEvidenceChunk),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-record-kind",
                tag,
            }),
        }
    }
}

/// Strict record-specific view of a generic child-bearing envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectEnvelope {
    record_kind: CampaignRecordKind,
    envelope: ContentEnvelope,
}

impl ObjectEnvelope {
    /// Builds an archive manifest whose child table contains only inventory pages.
    ///
    /// Selected campaign objects are deliberately direct inventory entries,
    /// rather than transitive envelope children, because a partial archive
    /// declares omitted descendants explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the manifest or child table is invalid.
    pub fn for_archive_manifest(
        value: &CampaignArchiveManifest,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            CampaignRecordKind::ArchiveManifest,
            value.schema_version(),
            content_children(value.content_children())?,
            value.canonical_bytes(),
        )
    }

    /// Builds one childless archive inventory page.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the page is invalid.
    pub fn for_archive_inventory_page(
        value: &CampaignArchiveInventoryPage,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            CampaignRecordKind::ArchiveInventoryPage,
            value.schema_version(),
            BTreeSet::new(),
            value.canonical_bytes(),
        )
    }

    /// Builds a budget envelope with the exact versioned request-spending child.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn for_budget_ledger(
        value: &crate::CampaignBudgetLedger,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            CampaignRecordKind::BudgetLedger,
            value.schema_version(),
            content_children(value.content_children())?,
            value.canonical_bytes(),
        )
    }

    /// Builds a lineage envelope with its exact empty child table.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the resulting object exceeds bounds.
    pub fn for_lineage(value: &CampaignLineage) -> Result<Self, CampaignCodecError> {
        Self::new(
            CampaignRecordKind::Lineage,
            content_children(value.content_children())?,
            value.canonical_bytes(),
        )
    }

    /// Builds a policy envelope with its exact child table.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the resulting object exceeds bounds.
    pub fn for_policy(value: &CampaignPolicy) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            CampaignRecordKind::Policy,
            value.schema_version(),
            content_children(value.content_children())?,
            value.canonical_bytes(),
        )
    }

    /// Builds a snapshot envelope with every authoritative root discoverable.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a generated role or envelope is invalid.
    pub fn for_snapshot(value: &CampaignSnapshot) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            CampaignRecordKind::Snapshot,
            value.schema_version(),
            snapshot_children(value)?,
            value.canonical_bytes(),
        )
    }

    /// Builds a candidate-budget envelope while preserving its schema version.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a generated role or envelope is invalid.
    pub fn for_candidate_budget(
        value: &crate::PlannerCandidateBudget,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            CampaignRecordKind::PlannerCandidateBudget,
            value.schema_version(),
            content_children(value.content_children())?,
            value.canonical_bytes(),
        )
    }

    /// Builds a Beam candidate envelope while preserving its schema version.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub(crate) fn for_beam_candidate(
        value: &crate::PlannerBeamCandidate,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            CampaignRecordKind::PlannerBeamCandidate,
            value.schema_version(),
            content_children(value.content_children())?,
            value.canonical_bytes(),
        )
    }

    /// Builds a causal-fact envelope with exact referenced objects.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a generated role or envelope is invalid.
    pub fn for_fact(value: &CampaignFact) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            CampaignRecordKind::Fact,
            value.schema_version(),
            fact_children(value)?,
            value.canonical_bytes(),
        )
    }

    /// Builds a branch-path envelope preserving its exact body version.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the resulting envelope exceeds a
    /// canonical bound.
    pub(crate) fn for_branch_path(value: &BranchPath) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            CampaignRecordKind::BranchPath,
            value.schema_version(),
            BTreeSet::new(),
            value.canonical_bytes(),
        )
    }

    /// Builds an exact configuration-artifact envelope.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the generated child table or envelope
    /// is invalid.
    pub fn for_configuration_artifact(
        value: &ConfigurationArtifact,
    ) -> Result<Self, CampaignCodecError> {
        Self::new(
            CampaignRecordKind::ConfigurationArtifact,
            content_children(value.content_children())?,
            value.canonical_bytes(),
        )
    }

    /// Builds a measurement-set envelope preserving its body schema version.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the generated child table or envelope
    /// exceeds a canonical bound.
    pub(crate) fn for_measurement_set(value: &MeasurementSet) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            CampaignRecordKind::MeasurementSet,
            value.schema_version(),
            content_children(value.content_children())?,
            value.canonical_bytes(),
        )
    }

    pub(crate) fn for_record(
        record_kind: CampaignRecordKind,
        children: BTreeSet<ContentChild>,
        body: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        Self::new(record_kind, children, body)
    }

    pub(crate) fn for_record_versioned(
        record_kind: CampaignRecordKind,
        schema_version: u32,
        children: BTreeSet<ContentChild>,
        body: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(record_kind, schema_version, children, body)
    }

    fn new(
        record_kind: CampaignRecordKind,
        children: BTreeSet<ContentChild>,
        body: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(record_kind, record_kind.schema_version(), children, body)
    }

    fn new_versioned(
        record_kind: CampaignRecordKind,
        schema_version: u32,
        children: BTreeSet<ContentChild>,
        body: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        let envelope =
            ContentEnvelope::new(record_kind.schema_name(), schema_version, children, body)?;
        Ok(Self {
            record_kind,
            envelope,
        })
    }

    /// Returns the closed record kind.
    #[must_use]
    pub const fn record_kind(&self) -> CampaignRecordKind {
        self.record_kind
    }

    /// Returns the complete sorted child-reference table.
    #[must_use]
    pub fn children(&self) -> &BTreeSet<ContentChild> {
        self.envelope.children()
    }

    /// Returns the strict record body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.envelope.body()
    }

    /// Returns the record schema version carried by the generic envelope.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.envelope.schema_version()
    }

    /// Returns strict canonical envelope bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.envelope.canonical_bytes()
    }

    /// Returns the backend-independent immutable content identity.
    #[must_use]
    pub fn content_id(&self) -> ContentId {
        self.envelope.content_id(self.record_kind.object_kind())
    }

    /// Decodes and validates a strict record-specific envelope.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed framing/body, an unknown
    /// schema, or a missing, extra, or wrong-role child reference.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        let decoded = Self::decode_structural(bytes)?;
        if decoded.record_kind == CampaignRecordKind::MerkleNode {
            return Err(CampaignCodecError::InvalidValue {
                reason: "Merkle node envelopes require the owning map validator",
            });
        }
        decoded.validate_record_body()?;
        Ok(decoded)
    }

    pub(crate) fn from_canonical_bytes_for_owner(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        let decoded = Self::decode_structural(bytes)?;
        if decoded.record_kind != CampaignRecordKind::MerkleNode {
            return Err(CampaignCodecError::InvalidValue {
                reason: "owner-only envelope decode was used for a non-Merkle record",
            });
        }
        Ok(decoded)
    }

    pub(crate) fn from_canonical_bytes_for_profile(
        bytes: &[u8],
    ) -> Result<Self, CampaignCodecError> {
        let decoded = Self::decode_structural(bytes)?;
        if decoded.record_kind != CampaignRecordKind::MerkleNode {
            decoded.validate_record_body()?;
        }
        Ok(decoded)
    }

    fn decode_structural(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        let envelope = ContentEnvelope::from_canonical_bytes(bytes)?;
        let record_kind = CampaignRecordKind::parse_schema_name(envelope.schema_name()).ok_or(
            CampaignCodecError::InvalidValue {
                reason: "unknown campaign record schema name",
            },
        )?;
        if envelope.schema_version() != record_kind.schema_version() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported campaign record schema version",
            });
        }
        Ok(Self {
            record_kind,
            envelope,
        })
    }
}
