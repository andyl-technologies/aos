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
    Attempt, AttemptAdmission, BranchPath, BranchRequest, CampaignCodecError,
    CampaignControlAction, CampaignFact, CampaignLineage, CampaignPlanningView, CampaignPolicy,
    CampaignSnapshot, ConfigurationArtifact, ExpansionState, PlannerEngine, PlannerInvocation,
    PlannerState, PlannerStep, PolicyArtifact, Proposal, ScenarioArtifact,
};

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
}

impl CampaignRecordKind {
    /// Every campaign record schema admitted by this crate.
    pub const ALL: [Self; 25] = [
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
        }
    }

    /// Returns the canonical schema version supported for this record.
    #[must_use]
    pub const fn schema_version(self) -> u32 {
        match self {
            Self::Snapshot => 2,
            Self::PlannerInvocation => 2,
            Self::PlannerStep => 3,
            Self::ExpansionState => 2,
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
            Self::ExpansionState => ObjectKind::Projection,
            Self::Lineage
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
            | Self::PlannerStep => ObjectKind::CampaignFact,
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
        Self::new(
            CampaignRecordKind::Policy,
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
        Self::new(
            CampaignRecordKind::Snapshot,
            snapshot_children(value)?,
            value.canonical_bytes(),
        )
    }

    /// Builds a causal-fact envelope with exact referenced objects.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a generated role or envelope is invalid.
    pub fn for_fact(value: &CampaignFact) -> Result<Self, CampaignCodecError> {
        Self::new(
            CampaignRecordKind::Fact,
            fact_children(value)?,
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

    fn new(
        record_kind: CampaignRecordKind,
        children: BTreeSet<ContentChild>,
        body: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        let envelope = ContentEnvelope::new(
            record_kind.schema_name(),
            record_kind.schema_version(),
            children,
            body,
        )?;
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

    fn validate_record_body(&self) -> Result<(), CampaignCodecError> {
        let expected = expected_children(self.record_kind, self.envelope.body())?;
        if expected != *self.envelope.children() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign record child table disagrees with its body",
            });
        }
        Ok(())
    }
}

fn expected_children(
    kind: CampaignRecordKind,
    body: &[u8],
) -> Result<BTreeSet<ContentChild>, CampaignCodecError> {
    match kind {
        CampaignRecordKind::Lineage => {
            let value = CampaignLineage::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::Policy => {
            let value = CampaignPolicy::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::Snapshot => {
            snapshot_children(&CampaignSnapshot::from_canonical_bytes(body)?)
        }
        CampaignRecordKind::Fact => fact_children(&CampaignFact::from_canonical_bytes(body)?),
        CampaignRecordKind::PlanningView => {
            let value = codec::decode::<CampaignPlanningView>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::PlannerEngine => {
            codec::decode::<PlannerEngine>(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::PolicyArtifact => {
            let value = codec::decode::<PolicyArtifact>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::PlannerState => {
            let value = codec::decode::<PlannerState>(body)?;
            content_children([("engine", value.engine().content_id())])
        }
        CampaignRecordKind::PlannerInvocation => {
            let value = codec::decode::<PlannerInvocation>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ChoiceDomain => {
            ChoiceDomain::from_canonical_bytes(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::SelectableDeclaration => {
            SelectableDeclaration::from_canonical_bytes(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::ChoiceOpportunity => {
            let value = codec::decode::<ChoiceOpportunity>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ChoiceGroup => {
            let value = codec::decode::<ChoiceGroup>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::Selection => {
            let value = Selection::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::CandidateGeneratorSpec => {
            let value = crate::CandidateGeneratorSpec::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ScenarioArtifact => {
            ScenarioArtifact::from_canonical_bytes(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::ConfigurationArtifact => {
            let value = ConfigurationArtifact::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::BranchRequest => {
            let value = BranchRequest::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::Proposal => {
            let value = Proposal::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::BranchPath => {
            codec::decode::<BranchPath>(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::Attempt => {
            let value = codec::decode::<Attempt>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::AttemptAdmission => {
            let value = codec::decode::<AttemptAdmission>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::PlannerStep => {
            let value = PlannerStep::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ExpansionState => {
            let value = codec::decode::<ExpansionState>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::MerkleNode => Err(CampaignCodecError::InvalidValue {
            reason: "opaque campaign record requires its owning validator",
        }),
    }
}

fn snapshot_children(
    snapshot: &CampaignSnapshot,
) -> Result<BTreeSet<ContentChild>, CampaignCodecError> {
    let roots = snapshot.roots();
    let mut children = vec![
        ("lineage", snapshot.lineage().content_id()),
        ("active-policy", snapshot.active_policy().content_id()),
        ("root.graph", roots.graph),
        ("root.exploration", roots.exploration),
        ("root.observations", roots.observations),
        ("root.corpus", roots.corpus),
        ("root.coverage", roots.coverage),
        ("root.findings", roots.findings),
        ("root.pins", roots.pins),
        ("root.accounting", roots.accounting),
        ("root.coordination", roots.coordination),
    ];
    if let Some(parent) = snapshot.parent() {
        children.push(("parent", parent.content_id()));
    }
    if let Some(transition) = snapshot.transition() {
        children.push(("transition", transition.content_id()));
    }
    content_children(children)
}

fn fact_children(fact: &CampaignFact) -> Result<BTreeSet<ContentChild>, CampaignCodecError> {
    let children = match fact {
        CampaignFact::ChoiceOpportunityDiscovered(id) => {
            vec![("choice-opportunity", id.content_id())]
        }
        CampaignFact::BranchRequestIssued(id) => vec![("branch-request", id.content_id())],
        CampaignFact::PlannerAdvanced(id) => vec![("planner-step", id.content_id())],
        CampaignFact::ProposalIssued(id) => vec![("proposal", id.content_id())],
        CampaignFact::AttemptAdmitted(admission) => {
            vec![("attempt-admission", admission.content_id())]
        }
        CampaignFact::AttemptClosed { attempt, .. } => vec![("attempt", attempt.content_id())],
        CampaignFact::ObservationPublished(id) => vec![("observation", id.content_id())],
        CampaignFact::FindingPublished(id) => vec![("finding", id.content_id())],
        CampaignFact::PolicyActivated(activation) => vec![
            ("prior-policy", activation.prior().content_id()),
            ("next-policy", activation.next().content_id()),
        ],
        CampaignFact::BudgetGranted(_) | CampaignFact::PinChanged(_) => Vec::new(),
        CampaignFact::ControlRequested(request) => {
            let mut values = vec![("expected-snapshot", request.expected_snapshot.content_id())];
            if let CampaignControlAction::ActivatePolicy(policy) = &request.action {
                values.push(("requested-policy", policy.content_id()));
            }
            values
        }
    };
    content_children(children)
}

pub(crate) fn content_children<I, R>(
    children: I,
) -> Result<BTreeSet<ContentChild>, CampaignCodecError>
where
    I: IntoIterator<Item = (R, ContentId)>,
    R: Into<String>,
{
    children
        .into_iter()
        .map(|(role, id)| ContentChild::new(role, id).map_err(CampaignCodecError::from))
        .collect()
}
