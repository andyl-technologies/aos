//! Portable evidence used to replay statistical estimates without repository access.
//!
//! The evidence contains every record needed for semantic replay. A transport
//! authenticates the record bodies and the root memberships returned by
//! [`FiniteStatisticalEvidence::required_root_lookups`] or
//! [`SequentialMonteCarloEvidence::required_root_lookups`] before calling the
//! pure verifiers in this module.

use std::collections::BTreeMap;

use crucible_cas::content_store::ContentId;

use crate::codec::{Canonical, Decoder, Encoder};
use crate::{
    Attempt, AttemptAdmission, BranchPath, BranchRequest, CampaignCodecError, CampaignHash,
    CampaignLineage, CampaignPlanningView, CampaignPolicy, CampaignSnapshot, ChoiceDomain,
    ChoiceOpportunity, ConfigurationArtifact, Observation, Proposal, SelectableDeclaration,
    Selection,
};

mod verify;

pub use verify::{verify_finite_statistical_evidence, verify_sequential_monte_carlo_evidence};

const MAX_EVIDENCE_ITEMS: usize = 65_536;

/// Identifies one snapshot root used by statistical evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StatisticalRoot {
    /// The configuration graph root.
    Graph,
    /// The branch-request root.
    Exploration,
    /// The canonical-observation root.
    Observations,
    /// The proposal and admission root.
    Accounting,
}

impl Canonical for StatisticalRoot {
    fn encode(&self, encoder: &mut Encoder) {
        let tag = match self {
            Self::Graph => 0_u8,
            Self::Exploration => 1,
            Self::Observations => 2,
            Self::Accounting => 3,
        };
        tag.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Graph),
            1 => Ok(Self::Exploration),
            2 => Ok(Self::Observations),
            3 => Ok(Self::Accounting),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "statistical-root",
                tag,
            }),
        }
    }
}

/// One exact key/value membership required from a snapshot root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatisticalRootLookup {
    root: StatisticalRoot,
    key: CampaignHash,
    value: ContentId,
}

impl StatisticalRootLookup {
    fn new(root: StatisticalRoot, key: CampaignHash, value: ContentId) -> Self {
        Self { root, key, value }
    }

    /// Returns the snapshot root containing this membership.
    #[must_use]
    pub const fn root(&self) -> StatisticalRoot {
        self.root
    }

    /// Returns the exact authenticated map key.
    #[must_use]
    pub const fn key(&self) -> CampaignHash {
        self.key
    }

    /// Returns the expected object identity at the key.
    #[must_use]
    pub const fn object(&self) -> ContentId {
        self.value
    }
}

impl Canonical for StatisticalRootLookup {
    fn encode(&self, encoder: &mut Encoder) {
        self.root.encode(encoder);
        self.key.encode(encoder);
        Canonical::encode(&self.value, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            StatisticalRoot::decode(decoder)?,
            CampaignHash::decode(decoder)?,
            ContentId::decode(decoder)?,
        ))
    }
}

/// An opportunity and the immutable records needed to validate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalOpportunityEvidence {
    opportunity: ChoiceOpportunity,
    declaration: SelectableDeclaration,
    domain: ChoiceDomain,
}

impl StatisticalOpportunityEvidence {
    /// Builds a complete opportunity closure.
    #[must_use]
    pub const fn new(
        opportunity: ChoiceOpportunity,
        declaration: SelectableDeclaration,
        domain: ChoiceDomain,
    ) -> Self {
        Self {
            opportunity,
            declaration,
            domain,
        }
    }

    /// Returns the runtime opportunity.
    #[must_use]
    pub const fn opportunity(&self) -> &ChoiceOpportunity {
        &self.opportunity
    }

    /// Returns the reusable selectable declaration.
    #[must_use]
    pub const fn declaration(&self) -> &SelectableDeclaration {
        &self.declaration
    }

    /// Returns the effective runtime domain.
    #[must_use]
    pub const fn domain(&self) -> &ChoiceDomain {
        &self.domain
    }
}

impl Canonical for StatisticalOpportunityEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.opportunity.encode(encoder);
        self.declaration.encode(encoder);
        self.domain.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            ChoiceOpportunity::decode(decoder)?,
            SelectableDeclaration::decode(decoder)?,
            ChoiceDomain::decode(decoder)?,
        ))
    }
}

/// A selection and the immutable records needed to validate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalChoiceEvidence {
    selection: Selection,
    opportunity: StatisticalOpportunityEvidence,
}

impl StatisticalChoiceEvidence {
    /// Builds a complete selection closure.
    #[must_use]
    pub const fn new(selection: Selection, opportunity: StatisticalOpportunityEvidence) -> Self {
        Self {
            selection,
            opportunity,
        }
    }

    /// Returns the selected choice.
    #[must_use]
    pub const fn selection(&self) -> &Selection {
        &self.selection
    }

    /// Returns the selected opportunity closure.
    #[must_use]
    pub const fn opportunity(&self) -> &StatisticalOpportunityEvidence {
        &self.opportunity
    }
}

impl Canonical for StatisticalChoiceEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.selection.encode(encoder);
        self.opportunity.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            Selection::decode(decoder)?,
            StatisticalOpportunityEvidence::decode(decoder)?,
        ))
    }
}

/// The independent, non-intervention admission that authorized an attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalExecutionBasisEvidence {
    admission: AttemptAdmission,
    proposal: Proposal,
    request: BranchRequest,
}

impl StatisticalExecutionBasisEvidence {
    /// Builds an execution-basis closure.
    #[must_use]
    pub const fn new(
        admission: AttemptAdmission,
        proposal: Proposal,
        request: BranchRequest,
    ) -> Self {
        Self {
            admission,
            proposal,
            request,
        }
    }

    /// Returns the execution-basis admission.
    #[must_use]
    pub const fn admission(&self) -> &AttemptAdmission {
        &self.admission
    }

    /// Returns the execution-basis proposal.
    #[must_use]
    pub const fn proposal(&self) -> &Proposal {
        &self.proposal
    }

    /// Returns the execution-basis request.
    #[must_use]
    pub const fn request(&self) -> &BranchRequest {
        &self.request
    }
}

impl Canonical for StatisticalExecutionBasisEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.admission.encode(encoder);
        self.proposal.encode(encoder);
        self.request.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            AttemptAdmission::decode(decoder)?,
            Proposal::decode(decoder)?,
            BranchRequest::decode(decoder)?,
        ))
    }
}

/// Complete records for one admitted statistical branch execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalExecutionEvidence {
    request: BranchRequest,
    parent: ConfigurationArtifact,
    request_opportunity: StatisticalOpportunityEvidence,
    proposal: Proposal,
    proposal_admission: AttemptAdmission,
    execution_basis: StatisticalExecutionBasisEvidence,
    attempt: Attempt,
    choice: StatisticalChoiceEvidence,
    path: BranchPath,
    observation: Observation,
    child: ConfigurationArtifact,
    discovered_opportunities: Vec<StatisticalOpportunityEvidence>,
}

impl StatisticalExecutionEvidence {
    /// Builds the complete record closure for one statistical execution.
    // crucible-lint: allow rust-allow -- evidence construction keeps each authenticated record explicit.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        request: BranchRequest,
        parent: ConfigurationArtifact,
        request_opportunity: StatisticalOpportunityEvidence,
        proposal: Proposal,
        proposal_admission: AttemptAdmission,
        execution_basis: StatisticalExecutionBasisEvidence,
        attempt: Attempt,
        choice: StatisticalChoiceEvidence,
        path: BranchPath,
        observation: Observation,
        child: ConfigurationArtifact,
        discovered_opportunities: Vec<StatisticalOpportunityEvidence>,
    ) -> Self {
        Self {
            request,
            parent,
            request_opportunity,
            proposal,
            proposal_admission,
            execution_basis,
            attempt,
            choice,
            path,
            observation,
            child,
            discovered_opportunities,
        }
    }

    /// Returns the branch request.
    #[must_use]
    pub const fn request(&self) -> &BranchRequest {
        &self.request
    }
    /// Returns the request parent artifact.
    #[must_use]
    pub const fn parent(&self) -> &ConfigurationArtifact {
        &self.parent
    }
    /// Returns the requested opportunity closure.
    #[must_use]
    pub const fn request_opportunity(&self) -> &StatisticalOpportunityEvidence {
        &self.request_opportunity
    }
    /// Returns the selected proposal.
    #[must_use]
    pub const fn proposal(&self) -> &Proposal {
        &self.proposal
    }
    /// Returns the proposal-linked admission.
    #[must_use]
    pub const fn proposal_admission(&self) -> &AttemptAdmission {
        &self.proposal_admission
    }
    /// Returns the attempt execution basis.
    #[must_use]
    pub const fn execution_basis(&self) -> &StatisticalExecutionBasisEvidence {
        &self.execution_basis
    }
    /// Returns the admitted attempt.
    #[must_use]
    pub const fn attempt(&self) -> &Attempt {
        &self.attempt
    }
    /// Returns the attempt selection closure.
    #[must_use]
    pub const fn choice(&self) -> &StatisticalChoiceEvidence {
        &self.choice
    }
    /// Returns the resulting branch path.
    #[must_use]
    pub const fn path(&self) -> &BranchPath {
        &self.path
    }
    /// Returns the canonical observation.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }
    /// Returns the observation child artifact.
    #[must_use]
    pub const fn child(&self) -> &ConfigurationArtifact {
        &self.child
    }
    /// Returns every discovered opportunity closure in identity order.
    #[must_use]
    pub fn discovered_opportunities(&self) -> &[StatisticalOpportunityEvidence] {
        &self.discovered_opportunities
    }
}

impl Canonical for StatisticalExecutionEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.request.encode(encoder);
        self.parent.encode(encoder);
        self.request_opportunity.encode(encoder);
        self.proposal.encode(encoder);
        self.proposal_admission.encode(encoder);
        self.execution_basis.encode(encoder);
        self.attempt.encode(encoder);
        self.choice.encode(encoder);
        self.path.encode(encoder);
        self.observation.encode(encoder);
        self.child.encode(encoder);
        self.discovered_opportunities.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            BranchRequest::decode(decoder)?,
            ConfigurationArtifact::decode(decoder)?,
            StatisticalOpportunityEvidence::decode(decoder)?,
            Proposal::decode(decoder)?,
            AttemptAdmission::decode(decoder)?,
            StatisticalExecutionBasisEvidence::decode(decoder)?,
            Attempt::decode(decoder)?,
            StatisticalChoiceEvidence::decode(decoder)?,
            BranchPath::decode(decoder)?,
            Observation::decode(decoder)?,
            ConfigurationArtifact::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_EVIDENCE_ITEMS,
                "statistical-discovered-opportunity-count",
                StatisticalOpportunityEvidence::decode,
            )?,
        ))
    }
}

/// Complete semantic evidence for one finite draw coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalDrawEvidence {
    coordinate: u64,
    execution: StatisticalExecutionEvidence,
}

impl StatisticalDrawEvidence {
    /// Builds one coordinate-bearing finite draw.
    #[must_use]
    pub const fn new(coordinate: u64, execution: StatisticalExecutionEvidence) -> Self {
        Self {
            coordinate,
            execution,
        }
    }

    /// Returns the zero-based planned coordinate.
    #[must_use]
    pub const fn coordinate(&self) -> u64 {
        self.coordinate
    }
    /// Returns the draw execution closure.
    #[must_use]
    pub const fn execution(&self) -> &StatisticalExecutionEvidence {
        &self.execution
    }

    /// Derives the snapshot-root memberships required by this draw.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when an object identity cannot be formed
    /// or two bodies claim different values for one root key.
    pub fn required_root_lookups(&self) -> Result<Vec<StatisticalRootLookup>, CampaignCodecError> {
        let mut lookups = BTreeMap::new();
        collect_execution_lookups(
            &mut lookups,
            statistical_draw_request_key(self.coordinate),
            statistical_draw_proposal_key(self.coordinate),
            &self.execution,
        )?;
        finish_lookups(lookups)
    }
}

impl Canonical for StatisticalDrawEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.coordinate.encode(encoder);
        self.execution.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            u64::decode(decoder)?,
            StatisticalExecutionEvidence::decode(decoder)?,
        ))
    }
}

/// Complete evidence for replaying one finite statistical estimate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiniteStatisticalEvidence {
    snapshot: CampaignSnapshot,
    planning_view: CampaignPlanningView,
    policy: CampaignPolicy,
    lineage: CampaignLineage,
    draws: Vec<StatisticalDrawEvidence>,
}

impl FiniteStatisticalEvidence {
    /// Builds a complete finite statistical evidence bundle.
    #[must_use]
    pub fn new(
        snapshot: CampaignSnapshot,
        planning_view: CampaignPlanningView,
        policy: CampaignPolicy,
        lineage: CampaignLineage,
        draws: Vec<StatisticalDrawEvidence>,
    ) -> Self {
        Self {
            snapshot,
            planning_view,
            policy,
            lineage,
            draws,
        }
    }

    /// Returns the pinned snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &CampaignSnapshot {
        &self.snapshot
    }
    /// Returns the planning view bound into proposals.
    #[must_use]
    pub const fn planning_view(&self) -> &CampaignPlanningView {
        &self.planning_view
    }
    /// Returns the active policy.
    #[must_use]
    pub const fn policy(&self) -> &CampaignPolicy {
        &self.policy
    }
    /// Returns the campaign lineage.
    #[must_use]
    pub const fn lineage(&self) -> &CampaignLineage {
        &self.lineage
    }
    /// Returns finite draws in coordinate order.
    #[must_use]
    pub fn draws(&self) -> &[StatisticalDrawEvidence] {
        &self.draws
    }

    /// Derives all required snapshot-root memberships from the evidence bodies.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when an object identity cannot be formed
    /// or two bodies claim different values for one root key.
    pub fn required_root_lookups(&self) -> Result<Vec<StatisticalRootLookup>, CampaignCodecError> {
        let mut lookups = BTreeMap::new();
        for draw in &self.draws {
            collect_execution_lookups(
                &mut lookups,
                statistical_draw_request_key(draw.coordinate),
                statistical_draw_proposal_key(draw.coordinate),
                &draw.execution,
            )?;
        }
        finish_lookups(lookups)
    }
}

impl Canonical for FiniteStatisticalEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.snapshot.encode(encoder);
        self.planning_view.encode(encoder);
        self.policy.encode(encoder);
        self.lineage.encode(encoder);
        self.draws.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            CampaignSnapshot::decode(decoder)?,
            CampaignPlanningView::decode(decoder)?,
            CampaignPolicy::decode(decoder)?,
            CampaignLineage::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_EVIDENCE_ITEMS,
                "finite-statistical-evidence-draw-count",
                StatisticalDrawEvidence::decode,
            )?,
        ))
    }
}

/// Complete semantic evidence for one SMC stage and particle slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmcTransitionEvidence {
    stage: u32,
    slot: u32,
    execution: StatisticalExecutionEvidence,
}

impl SmcTransitionEvidence {
    /// Builds one coordinate-bearing SMC transition.
    #[must_use]
    pub const fn new(stage: u32, slot: u32, execution: StatisticalExecutionEvidence) -> Self {
        Self {
            stage,
            slot,
            execution,
        }
    }

    /// Returns the one-based transition stage.
    #[must_use]
    pub const fn stage(&self) -> u32 {
        self.stage
    }
    /// Returns the stable slot within the stage.
    #[must_use]
    pub const fn slot(&self) -> u32 {
        self.slot
    }
    /// Returns the transition execution closure.
    #[must_use]
    pub const fn execution(&self) -> &StatisticalExecutionEvidence {
        &self.execution
    }

    /// Derives the snapshot-root memberships required by this transition.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when an object identity cannot be formed
    /// or two bodies claim different values for one root key.
    pub fn required_root_lookups(&self) -> Result<Vec<StatisticalRootLookup>, CampaignCodecError> {
        let mut lookups = BTreeMap::new();
        collect_execution_lookups(
            &mut lookups,
            smc_transition_request_key(self.stage, self.slot),
            smc_transition_proposal_key(self.stage, self.slot),
            &self.execution,
        )?;
        finish_lookups(lookups)
    }
}

impl Canonical for SmcTransitionEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.stage.encode(encoder);
        self.slot.encode(encoder);
        self.execution.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            u32::decode(decoder)?,
            u32::decode(decoder)?,
            StatisticalExecutionEvidence::decode(decoder)?,
        ))
    }
}

/// Complete evidence for replaying a sequential Monte Carlo estimate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequentialMonteCarloEvidence {
    initial: FiniteStatisticalEvidence,
    transitions: Vec<SmcTransitionEvidence>,
}

impl SequentialMonteCarloEvidence {
    /// Builds an SMC bundle from its initial flight and ordered transitions.
    #[must_use]
    pub const fn new(
        initial: FiniteStatisticalEvidence,
        transitions: Vec<SmcTransitionEvidence>,
    ) -> Self {
        Self {
            initial,
            transitions,
        }
    }

    /// Returns the complete initial finite flight.
    #[must_use]
    pub const fn initial(&self) -> &FiniteStatisticalEvidence {
        &self.initial
    }
    /// Returns transitions ordered by stage and slot.
    #[must_use]
    pub fn transitions(&self) -> &[SmcTransitionEvidence] {
        &self.transitions
    }

    /// Derives all required snapshot-root memberships from the evidence bodies.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when an object identity cannot be formed
    /// or two bodies claim different values for one root key.
    pub fn required_root_lookups(&self) -> Result<Vec<StatisticalRootLookup>, CampaignCodecError> {
        let mut lookups = BTreeMap::new();
        for draw in &self.initial.draws {
            collect_execution_lookups(
                &mut lookups,
                statistical_draw_request_key(draw.coordinate),
                statistical_draw_proposal_key(draw.coordinate),
                &draw.execution,
            )?;
        }
        for transition in &self.transitions {
            collect_execution_lookups(
                &mut lookups,
                smc_transition_request_key(transition.stage, transition.slot),
                smc_transition_proposal_key(transition.stage, transition.slot),
                &transition.execution,
            )?;
        }
        finish_lookups(lookups)
    }
}

impl Canonical for SequentialMonteCarloEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.initial.encode(encoder);
        self.transitions.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            FiniteStatisticalEvidence::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_EVIDENCE_ITEMS,
                "SMC-evidence-transition-count",
                SmcTransitionEvidence::decode,
            )?,
        ))
    }
}

type LookupMap = BTreeMap<(StatisticalRoot, CampaignHash), ContentId>;

fn collect_execution_lookups(
    lookups: &mut LookupMap,
    request_key: CampaignHash,
    proposal_key: CampaignHash,
    evidence: &StatisticalExecutionEvidence,
) -> Result<(), CampaignCodecError> {
    let request_id = evidence.request.id()?;
    let proposal_id = evidence.proposal.id()?;
    let proposal_admission_id = evidence.proposal_admission.id()?;
    let attempt_id = evidence.attempt.id()?;
    let basis_admission_id = evidence.execution_basis.admission.id()?;
    let observation_id = evidence.observation.id()?;
    let parent_id = evidence.parent.id()?;
    let child_id = evidence.child.id()?;
    let request_opportunity_id = evidence.request_opportunity.opportunity.id()?;

    let basis = &evidence.execution_basis;
    let basis_request_id = basis.request.id()?;
    let basis_proposal_id = basis.proposal.id()?;
    let (basis_request_key, basis_proposal_key) = execution_root_keys(basis.request.source())?;

    insert_lookup(
        lookups,
        StatisticalRoot::Exploration,
        request_key,
        request_id.content_id(),
    )?;
    insert_lookup(
        lookups,
        StatisticalRoot::Accounting,
        proposal_key,
        proposal_id.content_id(),
    )?;
    insert_lookup(
        lookups,
        StatisticalRoot::Accounting,
        map_key_content("accounting.proposal-admission", proposal_id.content_id()),
        proposal_admission_id.content_id(),
    )?;
    insert_lookup(
        lookups,
        StatisticalRoot::Exploration,
        basis_request_key,
        basis_request_id.content_id(),
    )?;
    insert_lookup(
        lookups,
        StatisticalRoot::Accounting,
        basis_proposal_key,
        basis_proposal_id.content_id(),
    )?;
    insert_lookup(
        lookups,
        StatisticalRoot::Accounting,
        map_key_content(
            "accounting.proposal-admission",
            basis_proposal_id.content_id(),
        ),
        basis_admission_id.content_id(),
    )?;
    insert_lookup(
        lookups,
        StatisticalRoot::Accounting,
        map_key_content(
            "accounting.attempt-execution-basis",
            attempt_id.content_id(),
        ),
        basis_admission_id.content_id(),
    )?;
    insert_lookup(
        lookups,
        StatisticalRoot::Observations,
        map_key_content("observations.attempt", attempt_id.content_id()),
        observation_id.content_id(),
    )?;
    insert_lookup(
        lookups,
        StatisticalRoot::Graph,
        map_key_hash(
            "graph.configuration",
            evidence.parent.configuration().as_hash(),
        ),
        parent_id.content_id(),
    )?;
    insert_lookup(
        lookups,
        StatisticalRoot::Graph,
        map_key_hash(
            "graph.configuration",
            evidence.child.configuration().as_hash(),
        ),
        child_id.content_id(),
    )?;
    insert_lookup(
        lookups,
        StatisticalRoot::Graph,
        branch_point_opportunity_key(evidence.request.branch_point(), request_opportunity_id),
        request_opportunity_id.content_id(),
    )?;
    for opportunity in &evidence.discovered_opportunities {
        let opportunity_id = opportunity.opportunity.id()?;
        let branch_point = opportunity
            .opportunity
            .branch_point_id(evidence.observation.child());
        insert_lookup(
            lookups,
            StatisticalRoot::Graph,
            branch_point_opportunity_key(branch_point, opportunity_id),
            opportunity_id.content_id(),
        )?;
    }
    Ok(())
}

fn execution_root_keys(
    source: &crate::CandidateSource,
) -> Result<(CampaignHash, CampaignHash), CampaignCodecError> {
    match source {
        crate::CandidateSource::StatisticalFinite(source) => Ok((
            statistical_draw_request_key(source.coordinate()),
            statistical_draw_proposal_key(source.coordinate()),
        )),
        crate::CandidateSource::StatisticalSmc(source) => Ok((
            smc_transition_request_key(source.stage(), source.slot()),
            smc_transition_proposal_key(source.stage(), source.slot()),
        )),
        _ => Err(CampaignCodecError::InvalidValue {
            reason: "statistical execution basis is not a statistical request",
        }),
    }
}

fn insert_lookup(
    lookups: &mut LookupMap,
    root: StatisticalRoot,
    key: CampaignHash,
    value: ContentId,
) -> Result<(), CampaignCodecError> {
    if lookups
        .insert((root, key), value)
        .is_some_and(|prior| prior != value)
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "statistical evidence assigns conflicting values to one root key",
        });
    }
    Ok(())
}

fn finish_lookups(lookups: LookupMap) -> Result<Vec<StatisticalRootLookup>, CampaignCodecError> {
    Ok(lookups
        .into_iter()
        .map(|((root, key), value)| StatisticalRootLookup::new(root, key, value))
        .collect())
}

fn map_key_hash(namespace: &str, id: CampaignHash) -> CampaignHash {
    let mut bytes = Vec::with_capacity(namespace.len() + 40);
    bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(&id.as_bytes());
    CampaignHash::derive("crucible.campaign-map-key.v1", &bytes)
}

fn map_key_content(namespace: &str, id: ContentId) -> CampaignHash {
    let encoded = id.encode();
    let mut bytes = Vec::with_capacity(namespace.len() + encoded.len() + 16);
    bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(encoded.as_bytes());
    CampaignHash::derive("crucible.campaign-map-key.v1", &bytes)
}

fn statistical_draw_request_key(coordinate: u64) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign.statistical-draw-request.v1",
        &coordinate.to_be_bytes(),
    )
}

fn statistical_draw_proposal_key(coordinate: u64) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign.statistical-draw-proposal.v1",
        &coordinate.to_be_bytes(),
    )
}

fn smc_transition_request_key(stage: u32, slot: u32) -> CampaignHash {
    let mut coordinate = [0_u8; 8];
    coordinate[..4].copy_from_slice(&stage.to_be_bytes());
    coordinate[4..].copy_from_slice(&slot.to_be_bytes());
    CampaignHash::derive("crucible.campaign.smc-transition-request.v1", &coordinate)
}

fn smc_transition_proposal_key(stage: u32, slot: u32) -> CampaignHash {
    let mut coordinate = [0_u8; 8];
    coordinate[..4].copy_from_slice(&stage.to_be_bytes());
    coordinate[4..].copy_from_slice(&slot.to_be_bytes());
    CampaignHash::derive("crucible.campaign.smc-transition-proposal.v1", &coordinate)
}

fn branch_point_opportunity_key(
    branch_point: crate::BranchPointId,
    opportunity: crate::ChoiceOpportunityId,
) -> CampaignHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&branch_point.as_hash().as_bytes());
    bytes.extend_from_slice(opportunity.content_id().encode().as_bytes());
    CampaignHash::derive("crucible.campaign-branch-point-opportunity.v1", &bytes)
}
