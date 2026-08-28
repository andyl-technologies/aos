//! Transactional campaign snapshots over immutable objects and one mutable ref.
//!
//! A mutation publishes every immutable object first and advances exactly one
//! campaign ref last. A crash before the compare-and-swap leaves only harmless
//! unreachable objects. Accepted command facts remain in the accounting Merkle
//! root, so retry checks command identity before snapshot staleness and can
//! reconstruct the original prior/new response from linear snapshot ancestry.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName, RefPublicationGuard, StoreError,
};
use thiserror::Error;

use crate::{
    ActiveAttemptPolicy, AdmissionOrdinal, Attempt, AttemptAdmission, AttemptAdmissionId,
    AttemptAdmissionRole, AttemptId, AttemptStart, BranchPath, BranchPathId, BranchRequest,
    BranchRequestCause, BranchRequestId, CampaignCodecError, CampaignControlAction,
    CampaignDerivation, CampaignFact, CampaignFactId, CampaignHash, CampaignLineage,
    CampaignLineageId, CampaignMode, CampaignPlanningView, CampaignPolicy, CampaignPolicyId,
    CampaignSnapshot, CampaignSnapshotId, CampaignState, CampaignStoreError,
    CandidateGeneratorAlgorithm, CandidateGeneratorSpec, CandidateGeneratorSpecId, CandidateSource,
    CanonicalFrontierPlanner, CanonicalPuctPlanner, ChoiceDomain, ChoiceDomainId, ChoiceGroup,
    ChoiceGroupId, ChoiceOpportunity, ChoiceOpportunityId, ConfigurationArtifact,
    ConfigurationArtifactId, ConfigurationId, ContinuationProjection, ControlRequest,
    CoverageProjection, CoverageProjectionId, DaemonEpoch, DebuggerAuthorityKey,
    DebuggerSubmission, ExecutorCompatibilityProfile, ExecutorRejection, ExpansionCredit,
    ExpansionState, ExpansionStateId, Finding, FindingId, FindingMinimizationEvidence,
    FindingOccurrenceSet, MeasurementSet, MeasurementSetId, MerkleMap, MerkleMapLookupProof,
    MerkleMapPage, MerkleMapPageProof, MerkleMapRoot, NonModeledAttemptDisposition, ObjectEnvelope,
    ObjectiveEvaluation, ObjectiveEvaluationId, Observation, ObservationId, PinRequest,
    PlannerAuthorityKey, PlannerDisposition, PlannerEngine, PlannerInvocation, PlannerInvocationId,
    PlannerProposalDisposition, PlannerRequest, PlannerState, PlannerStep, PlannerStepId,
    PlannerStepProposal, PlanningAccounting, PlanningBudget, PlanningScanPage,
    PlanningScanPosition, PlanningUsage, PolicyActivation, PolicyArtifact, PropertyVerdict,
    PropertyVerdictSet, PropertyVerdictSetId, Proposal, ProposalId, PurePlannerEngine,
    RankingExplanation, RankingExplanationId, ReproductionArtifact, ReproductionArtifactId,
    RetainedPlannerRequestId, ScenarioArtifact, ScenarioArtifactId, ScenarioDefId,
    SelectableDeclaration, SelectableId, Selection, SelectionId, StopCondition, StopOutcome,
    SubmitAttemptDisposition, SubmitAttemptRequest, SubmitAttemptResponse, SurvivorSelection,
    SurvivorSelectionBundle, SurvivorSelectionId,
};

const MAX_ENVELOPE_BYTES: u64 = crate::codec::MAX_CANONICAL_BYTES as u64;
const MAX_SNAPSHOT_ANCESTRY: usize = 1_000_001;
/// Maximum unique object-position work charged to one authenticated closure.
pub const MAX_CAMPAIGN_CLOSURE_OBJECTS: usize = 64_000_000;
const MAX_ISSUE_GENERATOR_VALIDATION_OBJECTS: usize = 1_000_000;
const PLANNER_SCAN_STORAGE_PAGE_ITEMS: usize = 10_000;
/// Maximum source positions served by one coordinator planner page.
pub const MAX_PLANNER_SCAN_PAGE_ITEMS: u32 = 10_000;
const MAX_VALIDATED_HEADS: usize = 1_024;
const MAX_CHOICE_VALIDATION_CACHE_ENTRIES: usize = 65_536;
const MAX_SELECTION_RESOLUTION_RECORDS: usize = 4_096;
const MAX_SELECTION_RESOLUTION_BYTES: usize = 128 * 1024 * 1024;
const _: () =
    assert!(MAX_CHOICE_VALIDATION_CACHE_ENTRIES >= crate::observation::MAX_DISCOVERED_CHOICES);
const MAX_SIMPLE_SUCCESSOR_GROWTH: usize = 1_024;
const MAX_PLANNER_ISSUE_SUCCESSOR_GROWTH: usize = 4_000_000;
// One observation may wake at most this many indexed feedback continuations.
const MAX_FEEDBACK_FRONTIER_UPDATES: usize = 65_536;
// One fixed-depth trie insertion rewrites at most one node per digest nibble.
const MERKLE_UPDATE_NODE_UPPER: usize = 64;
// Graph has three fixed keys, observations six, corpus/coverage/coordination one
// each, and strict accounting three. Every discovered choice adds two graph keys
// plus one nested choice-index insertion. Every credited branch point adds one
// nested credit insertion, one outer observation-index update, and one immutable
// credit record.
const OBSERVATION_FIXED_OWNER_UPSERTS: usize = 15;
const MAX_OBSERVATION_SUCCESSOR_GROWTH: usize = ((3 * crate::observation::MAX_DISCOVERED_CHOICES
    + OBSERVATION_FIXED_OWNER_UPSERTS)
    * MERKLE_UPDATE_NODE_UPPER)
    + (crate::exploration::MAX_BRANCH_PATH_EDGES * ((2 * MERKLE_UPDATE_NODE_UPPER) + 1))
    + (MAX_FEEDBACK_FRONTIER_UPDATES * (MERKLE_UPDATE_NODE_UPPER + 1))
    + MERKLE_UPDATE_NODE_UPPER
    + (2 * MERKLE_UPDATE_NODE_UPPER)
    + 1;

/// Authenticated current value of one named campaign ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignHead {
    name: String,
    snapshot_id: CampaignSnapshotId,
    snapshot: CampaignSnapshot,
}

/// One bounded, stable page of authenticated named campaign heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignHeadPage {
    heads: Vec<CampaignHead>,
    next_after: Option<String>,
    visited_refs: u64,
}

impl CampaignHeadPage {
    /// Returns campaign heads in strict canonical name order.
    #[must_use]
    pub fn heads(&self) -> &[CampaignHead] {
        &self.heads
    }

    /// Returns the exclusive campaign-name cursor for another page.
    #[must_use]
    pub fn next_after(&self) -> Option<&str> {
        self.next_after.as_deref()
    }

    /// Returns authoritative reference entries inspected by the backend scan.
    #[must_use]
    pub const fn visited_refs(&self) -> u64 {
        self.visited_refs
    }
}

/// Authenticated lifecycle intent projected from one exact campaign snapshot.
///
/// The active-attempt policy is present after a `Pause` command until a later
/// `Resume` or `Complete` command supersedes it. It remains visible while a
/// paused campaign is sealed so the daemon can finish the declared handling of
/// work that was already active when the pause became authoritative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignLifecycle {
    state: CampaignState,
    active_attempt_policy: Option<ActiveAttemptPolicy>,
}

impl CampaignLifecycle {
    /// Returns the visible durable campaign state.
    #[must_use]
    pub const fn state(self) -> CampaignState {
        self.state
    }

    /// Returns the policy governing attempts active at the latest pause.
    #[must_use]
    pub const fn active_attempt_policy(self) -> Option<ActiveAttemptPolicy> {
        self.active_attempt_policy
    }
}

impl CampaignHead {
    /// Returns the user-facing campaign name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the immutable snapshot's generic content identity.
    #[must_use]
    pub const fn content_id(&self) -> ContentId {
        self.snapshot_id.content_id()
    }

    /// Returns the typed campaign snapshot identity.
    #[must_use]
    pub const fn snapshot_id(&self) -> CampaignSnapshotId {
        self.snapshot_id
    }

    /// Returns the authenticated immutable snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &CampaignSnapshot {
        &self.snapshot
    }
}

/// Stable response for an accepted or idempotently replayed campaign command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignCommandResult {
    /// Snapshot named by the accepted command's precondition.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot first produced by the accepted command.
    pub new_snapshot: CampaignSnapshotId,
    /// Whether this call observed a previously committed command.
    pub replayed: bool,
}

/// Stable response for a newly derived or idempotently replayed campaign ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignDerivationResult {
    /// Exact authenticated source snapshot.
    pub source_snapshot: CampaignSnapshotId,
    /// First snapshot owned by the derived ref.
    pub new_snapshot: CampaignSnapshotId,
    /// Policy active at the derived snapshot.
    pub active_policy: CampaignPolicyId,
    /// Whether this call observed a previously committed derivation.
    pub replayed: bool,
}

/// Stable response for an accepted or idempotently replayed branch request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchRequestResult {
    /// Snapshot that first accepted this request.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot first produced by accepting this request.
    pub new_snapshot: CampaignSnapshotId,
    /// Exact immutable request identity.
    pub request: BranchRequestId,
    /// Whether this call observed a previously committed request.
    pub replayed: bool,
}

/// Stable response for an authoritative choice-opportunity discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceDiscoveryResult {
    /// Snapshot before the discovery transition, or the current snapshot when
    /// the opportunity was already authoritative through another owner.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot produced by discovery, or the unchanged current snapshot.
    pub new_snapshot: CampaignSnapshotId,
    /// Exact parent artifact at which the opportunity became authoritative.
    pub parent: ConfigurationArtifactId,
    /// Semantic branch point derived from the parent and opportunity.
    pub branch_point: crate::BranchPointId,
    /// Exact immutable opportunity made authoritative.
    pub opportunity: ChoiceOpportunityId,
    /// Whether no new transition was needed.
    pub replayed: bool,
}

/// Stable response for an accepted or idempotently replayed proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalResult {
    /// Snapshot that first accepted this proposal.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot first produced by accepting this proposal.
    pub new_snapshot: CampaignSnapshotId,
    /// Exact immutable proposal identity.
    pub proposal: ProposalId,
    /// Whether this call observed a previously committed proposal.
    pub replayed: bool,
}

/// Stable response for an accepted or idempotently replayed attempt admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptAdmissionResult {
    /// Snapshot that first accepted this admission.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot first produced by accepting this admission.
    pub new_snapshot: CampaignSnapshotId,
    /// Proposal receiving its unique admission disposition.
    pub proposal: ProposalId,
    /// Semantic attempt admitted or reused.
    pub attempt: AttemptId,
    /// Exact execution-basis or additional-cause record.
    pub admission: AttemptAdmissionId,
    /// Whether this call observed a previously committed admission.
    pub replayed: bool,
}

/// Stable response for an accepted or idempotently replayed planner step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerStepResult {
    /// Snapshot that first accepted this planner step.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot first produced by accepting this planner step.
    pub new_snapshot: CampaignSnapshotId,
    /// Exact coordinator-accepted planner-step identity.
    pub step: PlannerStepId,
    /// Whether this call observed a previously committed invocation result.
    pub replayed: bool,
}

/// Canonical or conflicting disposition of a published attempt observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationDisposition {
    /// This observation is the attempt's canonical modeled completion.
    Canonical,
    /// Another observation was already selected canonically for the attempt.
    DeterminismConflict {
        /// The immutable canonical observation selected earlier.
        canonical: ObservationId,
    },
}

/// Stable response for accepted or idempotently replayed observation publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationResult {
    /// Snapshot used as the transition parent.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot that retained the canonical or conflicting observation.
    pub new_snapshot: CampaignSnapshotId,
    /// Exact published observation.
    pub observation: ObservationId,
    /// Canonical completion or determinism-conflict evidence.
    pub disposition: ObservationDisposition,
    /// Whether an existing transition was returned.
    pub replayed: bool,
}

/// Self-contained immutable records for one dynamically discovered choice.
///
/// Carrying all three values lets the executor hand off a new producer contract
/// without receiving a general-purpose repository publication capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceDiscovery {
    declaration: Arc<SelectableDeclaration>,
    domain: Arc<ChoiceDomain>,
    opportunity: ChoiceOpportunity,
}

impl ChoiceDiscovery {
    /// Builds one self-contained choice discovery record set.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the opportunity does not bind the
    /// exact declaration and domain.
    pub fn new(
        declaration: SelectableDeclaration,
        domain: ChoiceDomain,
        opportunity: ChoiceOpportunity,
    ) -> Result<Self, CampaignCodecError> {
        Self::from_shared(Arc::new(declaration), Arc::new(domain), opportunity)
    }

    /// Builds one discovery by sharing immutable declaration and domain values.
    ///
    /// This form avoids copying large records when many opportunities share one
    /// producer contract.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the opportunity does not bind the
    /// exact declaration and domain.
    pub fn from_shared(
        declaration: Arc<SelectableDeclaration>,
        domain: Arc<ChoiceDomain>,
        opportunity: ChoiceOpportunity,
    ) -> Result<Self, CampaignCodecError> {
        opportunity.validate_references(&declaration, &domain)?;
        Ok(Self {
            declaration,
            domain,
            opportunity,
        })
    }

    /// Returns the reusable selectable declaration.
    #[must_use]
    pub fn declaration(&self) -> &SelectableDeclaration {
        self.declaration.as_ref()
    }

    /// Returns the exact offered domain.
    #[must_use]
    pub fn domain(&self) -> &ChoiceDomain {
        self.domain.as_ref()
    }

    /// Returns the dynamic opportunity.
    #[must_use]
    pub const fn opportunity(&self) -> &ChoiceOpportunity {
        &self.opportunity
    }

    /// Reuses dependencies from another validated discovery with the same contract.
    ///
    /// Both values were validated when constructed. This operation compares
    /// their compact content-addressed reference contract before sharing the
    /// already-authenticated immutable values, avoiding repeated hashing of a
    /// large domain used by many opportunities.
    ///
    /// # Errors
    ///
    /// Returns an error when the discoveries name different declaration or
    /// domain records, or when their copied reference contracts differ.
    pub fn share_dependencies_from(&mut self, validated: &Self) -> Result<(), CampaignCodecError> {
        if self.opportunity.declaration() != validated.opportunity.declaration()
            || self.opportunity.domain() != validated.opportunity.domain()
            || self.opportunity.reference_contract_hash()
                != validated.opportunity.reference_contract_hash()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice discoveries do not share one validated dependency contract",
            });
        }
        self.declaration = Arc::clone(&validated.declaration);
        self.domain = Arc::clone(&validated.domain);
        Ok(())
    }
}

/// Maximum aggregate canonical bytes for unique choice records in one candidate.
pub const MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES: usize = 128 * 1024 * 1024;
/// Maximum number of choice discoveries carried by one candidate.
pub const MAX_OBSERVATION_CHOICE_DISCOVERIES: usize = crate::observation::MAX_DISCOVERED_CHOICES;

fn charge_choice_discovery_record(
    charged_records: &mut BTreeSet<ContentId>,
    charged_bytes: &mut usize,
    id: ContentId,
    encoded_bytes: impl FnOnce() -> usize,
) -> Result<(), CampaignCodecError> {
    if !charged_records.insert(id) {
        return Ok(());
    }
    *charged_bytes =
        charged_bytes
            .checked_add(encoded_bytes())
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "observation-choice-discovery-bytes",
            })?;
    if *charged_bytes > MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "observation-choice-discovery-bytes",
        });
    }
    Ok(())
}

/// Complete immutable executor result published before campaign admission.
///
/// The bundle keeps the child configuration and modeled evidence values beside
/// the observation that names them. Newly discovered choices carry their exact
/// declaration and domain so a dynamic producer never needs ambient immutable
/// publication authority. A repository validates the complete bundle and every
/// already-published evidence dependency before writing any member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationCandidate {
    child: ConfigurationArtifact,
    measurements: MeasurementSet,
    properties: PropertyVerdictSet,
    coverage: CoverageProjection,
    discovered_choices: Vec<ChoiceDiscovery>,
    observation: Observation,
}

impl ObservationCandidate {
    /// Builds one executor-produced immutable result bundle.
    ///
    /// # Errors
    ///
    /// Returns an error when discovered records exceed the observation count or
    /// aggregate-byte bound, contain duplicate opportunity IDs, disagree with
    /// one another, or do not exactly match the observation's choice set.
    pub fn new(
        child: ConfigurationArtifact,
        measurements: MeasurementSet,
        properties: PropertyVerdictSet,
        coverage: CoverageProjection,
        discovered_choices: Vec<ChoiceDiscovery>,
        observation: Observation,
    ) -> Result<Self, CampaignCodecError> {
        if discovered_choices.len() > MAX_OBSERVATION_CHOICE_DISCOVERIES {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation candidate has too many discovered choices",
            });
        }
        let mut discovered_ids = BTreeSet::new();
        let mut shared_declarations: BTreeMap<SelectableId, Arc<SelectableDeclaration>> =
            BTreeMap::new();
        let mut shared_domains: BTreeMap<ChoiceDomainId, Arc<ChoiceDomain>> = BTreeMap::new();
        let mut validated_contracts = BTreeMap::new();
        let mut charged_records = BTreeSet::new();
        let mut charged_bytes = 0usize;
        let mut discovered_choices = discovered_choices;
        for discovery in &mut discovered_choices {
            let declaration = discovery.opportunity.declaration();
            let domain = discovery.opportunity.domain();
            let contract = discovery.opportunity.reference_contract_hash();
            match validated_contracts.get(&(declaration, domain)) {
                Some(validated) if *validated == contract => {}
                Some(_) => {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "choice opportunities sharing references disagree on their contract",
                    });
                }
                None => {
                    discovery
                        .opportunity
                        .validate_references(&discovery.declaration, &discovery.domain)?;
                    validated_contracts.insert((declaration, domain), contract);
                }
            }
            let opportunity = discovery.opportunity.id()?;
            if !discovered_ids.insert(opportunity) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "observation candidate contains duplicate choice opportunities",
                });
            }
            if let Some(existing) = shared_declarations.get(&declaration) {
                discovery.declaration = Arc::clone(existing);
            } else {
                shared_declarations.insert(declaration, Arc::clone(&discovery.declaration));
            }
            if let Some(existing) = shared_domains.get(&domain) {
                discovery.domain = Arc::clone(existing);
            } else {
                shared_domains.insert(domain, Arc::clone(&discovery.domain));
            }
            charge_choice_discovery_record(
                &mut charged_records,
                &mut charged_bytes,
                declaration.content_id(),
                || discovery.declaration.canonical_bytes().len(),
            )?;
            charge_choice_discovery_record(
                &mut charged_records,
                &mut charged_bytes,
                domain.content_id(),
                || discovery.domain.canonical_bytes().len(),
            )?;
            charge_choice_discovery_record(
                &mut charged_records,
                &mut charged_bytes,
                opportunity.content_id(),
                || discovery.opportunity.canonical_bytes().len(),
            )?;
        }
        if &discovered_ids != observation.discovered_choices() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation candidate choice bodies differ from observation IDs",
            });
        }
        Ok(Self {
            child,
            measurements,
            properties,
            coverage,
            discovered_choices,
            observation,
        })
    }

    /// Returns the exact child configuration artifact.
    #[must_use]
    pub const fn child(&self) -> &ConfigurationArtifact {
        &self.child
    }

    /// Returns the exact modeled measurements.
    #[must_use]
    pub const fn measurements(&self) -> &MeasurementSet {
        &self.measurements
    }

    /// Returns the exact property verdicts.
    #[must_use]
    pub const fn properties(&self) -> &PropertyVerdictSet {
        &self.properties
    }

    /// Returns the exact coverage projection.
    #[must_use]
    pub const fn coverage(&self) -> &CoverageProjection {
        &self.coverage
    }

    /// Returns exact declaration/domain/opportunity records discovered by the
    /// execution.
    #[must_use]
    pub fn discovered_choices(&self) -> &[ChoiceDiscovery] {
        &self.discovered_choices
    }

    /// Returns the canonical observation that binds every bundle member.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }
}

/// Selection and exact choice records authenticated together by a repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSelection {
    selection: Selection,
    opportunity: Arc<ChoiceOpportunity>,
    declaration: Arc<SelectableDeclaration>,
    domain: Arc<ChoiceDomain>,
}

/// Narrow immutable-record capability supplied to a local campaign executor.
///
/// This facade deliberately exposes no campaign head, mutable-ref, owner
/// projection, or coordinator transaction methods. It can authenticate the
/// records needed to execute one attempt and publish a content-addressed
/// observation candidate for later coordinator admission.
#[derive(Clone)]
pub struct CampaignExecutorStore {
    repository: Arc<CampaignRepository>,
}

impl CampaignExecutorStore {
    /// Creates a narrow executor capability over one campaign repository.
    #[must_use]
    pub const fn new(repository: Arc<CampaignRepository>) -> Self {
        Self { repository }
    }

    /// Loads and authenticates one campaign compatibility lineage.
    ///
    /// # Errors
    ///
    /// Returns an error when the lineage is missing, corrupt, or inconsistent.
    pub fn load_lineage(
        &self,
        id: CampaignLineageId,
    ) -> Result<CampaignLineage, CampaignRepositoryError> {
        self.repository.load_lineage(id)
    }

    /// Loads and authenticates one execution-model scenario artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is missing, corrupt, or inconsistent.
    pub fn load_scenario_artifact(
        &self,
        id: ScenarioArtifactId,
    ) -> Result<ScenarioArtifact, CampaignRepositoryError> {
        self.repository.load_scenario_artifact(id)
    }

    /// Loads and authenticates one semantic attempt closure.
    ///
    /// # Errors
    ///
    /// Returns an error when the attempt or one of its references is missing,
    /// corrupt, or inconsistent.
    pub fn load_attempt(&self, id: AttemptId) -> Result<Attempt, CampaignRepositoryError> {
        self.repository.load_attempt(id)
    }

    /// Loads and authenticates one semantic branch path.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is missing, corrupt, or inconsistent.
    pub fn load_branch_path(
        &self,
        id: BranchPathId,
    ) -> Result<BranchPath, CampaignRepositoryError> {
        self.repository.load_branch_path(id)
    }

    /// Loads and authenticates one exact configuration artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is missing, corrupt, or inconsistent.
    pub fn load_configuration_artifact(
        &self,
        id: ConfigurationArtifactId,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        self.repository.load_configuration_artifact(id)
    }

    /// Resolves one selection with its authenticated opportunity and domain.
    ///
    /// # Errors
    ///
    /// Returns an error when any exact selection reference is missing, corrupt,
    /// or semantically inconsistent.
    pub fn resolve_selection(
        &self,
        id: SelectionId,
    ) -> Result<ResolvedSelection, CampaignRepositoryError> {
        self.repository.resolve_selection(id)
    }

    /// Resolves a bounded batch of selections with shared authenticated dependencies.
    ///
    /// Repeated opportunities, declarations, and domains are decoded once. The
    /// aggregate unique canonical record bodies are bounded independently of
    /// the number and ordering of selections.
    ///
    /// # Errors
    ///
    /// Returns an error when the batch exceeds its record or byte bound, or
    /// when any exact selection reference is missing, corrupt, or inconsistent.
    pub fn resolve_selections(
        &self,
        ids: &[SelectionId],
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError> {
        self.repository.resolve_selections(ids)
    }

    /// Publishes a validated immutable observation candidate without advancing a campaign.
    ///
    /// # Errors
    ///
    /// Returns an error before writing when the bundle or any already-published
    /// dependency is missing, corrupt, oversized, or inconsistent. A storage
    /// failure after publication starts may leave unreachable immutable data.
    pub fn publish_observation_candidate(
        &self,
        candidate: &ObservationCandidate,
    ) -> Result<ObservationId, CampaignRepositoryError> {
        self.repository.publish_observation_candidate(candidate)
    }

    /// Validates an observation candidate without writing any bundle member.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundle or an already-published dependency is
    /// missing, corrupt, oversized, or inconsistent.
    pub fn validate_observation_candidate(
        &self,
        candidate: &ObservationCandidate,
    ) -> Result<(), CampaignRepositoryError> {
        self.repository.validate_observation_candidate(candidate)
    }
}

impl ResolvedSelection {
    /// Returns the authenticated recorded selection.
    #[must_use]
    pub const fn selection(&self) -> &Selection {
        &self.selection
    }

    /// Returns the authenticated opportunity selected from.
    #[must_use]
    pub fn opportunity(&self) -> &ChoiceOpportunity {
        self.opportunity.as_ref()
    }

    /// Returns the authenticated reusable selectable declaration.
    #[must_use]
    pub fn declaration(&self) -> &SelectableDeclaration {
        self.declaration.as_ref()
    }

    /// Returns the authenticated effective choice domain.
    #[must_use]
    pub fn domain(&self) -> &ChoiceDomain {
        self.domain.as_ref()
    }
}

/// Failure while resolving or transactionally advancing a campaign.
#[derive(Debug, Error)]
pub enum CampaignRepositoryError {
    /// An immutable or mutable store operation failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Canonical campaign bytes failed validation.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// A Merkle collection operation failed.
    #[error(transparent)]
    Merkle(#[from] crate::CampaignStoreError),
    /// A campaign with this name already exists.
    #[error("campaign already exists")]
    AlreadyExists,
    /// No campaign exists under this name.
    #[error("campaign was not found")]
    NotFound,
    /// The expected semantic snapshot is not the current head.
    #[error("campaign command used stale snapshot {expected}; current snapshot is {current}")]
    Stale {
        /// Snapshot supplied by the caller.
        expected: CampaignSnapshotId,
        /// Current authoritative snapshot.
        current: CampaignSnapshotId,
    },
    /// A command ID was reused for different canonical input.
    #[error("campaign command id was reused with another request")]
    CommandReuse,
    /// The authoritative ref changed during a mutation.
    #[error("campaign ref changed during transaction")]
    RefConflict {
        /// Current physical ref value observed by compare-and-swap.
        current: Option<ContentId>,
    },
    /// Caller-supplied semantic input does not name an admissible operation.
    #[error("campaign request is invalid: {reason}")]
    InvalidRequest {
        /// Stable invalid-input category.
        reason: &'static str,
    },
    /// An object closure or snapshot transition is internally inconsistent.
    #[error("campaign repository integrity failure: {reason}")]
    Integrity {
        /// Stable integrity-failure category.
        reason: &'static str,
    },
    /// The lifecycle action is not legal from the projected state.
    #[error("campaign action is invalid from state {state:?}")]
    InvalidTransition {
        /// Projected state that rejected the action.
        state: CampaignState,
    },
    /// A local coordinator synchronization primitive was poisoned.
    #[error("campaign coordinator lock was poisoned")]
    Poisoned,
}

impl CampaignRepositoryError {
    /// Maps read-only executor validation failure into the wire rejection vocabulary.
    ///
    /// Missing or temporarily unreadable immutable input remains retryable under
    /// a fresh assignment. Authenticated incompatibility and corrupt canonical
    /// structure fail stably, while backend authorization remains distinct.
    #[must_use]
    pub fn executor_rejection(&self) -> ExecutorRejection {
        match self {
            Self::Store(error) => store_executor_rejection(error),
            Self::Merkle(crate::CampaignStoreError::Store(error)) => {
                store_executor_rejection(error)
            }
            Self::NotFound | Self::Poisoned => ExecutorRejection::UnavailableInput,
            Self::Codec(_)
            | Self::Merkle(_)
            | Self::AlreadyExists
            | Self::Stale { .. }
            | Self::CommandReuse
            | Self::RefConflict { .. }
            | Self::InvalidRequest { .. }
            | Self::Integrity { .. }
            | Self::InvalidTransition { .. } => ExecutorRejection::Incompatible,
        }
    }
}

fn store_executor_rejection(error: &StoreError) -> ExecutorRejection {
    match error {
        StoreError::NotFound { .. }
        | StoreError::Quota
        | StoreError::Unavailable
        | StoreError::Poisoned { .. }
        | StoreError::Io { .. }
        | StoreError::StreamIo { .. } => ExecutorRejection::UnavailableInput,
        StoreError::Unauthorized => ExecutorRejection::Unauthorized,
        StoreError::Corrupt { .. }
        | StoreError::InvalidId
        | StoreError::InvalidRefName { .. }
        | StoreError::InvalidRange { .. }
        | StoreError::InvalidComposition { .. }
        | StoreError::InvalidGraph { .. }
        | StoreError::DurabilityUnsatisfied { .. }
        | StoreError::Incompatible
        | StoreError::InvalidSourceLength { .. }
        | StoreError::MultipartCleanupRequired
        | StoreError::Unsupported { .. } => ExecutorRejection::Incompatible,
    }
}

/// Repository and sole-writer transaction boundary for local campaigns.
pub struct CampaignRepository {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    merkle: MerkleMap,
    mutation_lock: Mutex<()>,
    // Immutable heads are promoted only after a complete validation or from a
    // validated parent through one of the repository's exact owner mutations.
    // The map is optional bounded acceleration state, never campaign truth.
    validated_heads: Mutex<BTreeMap<ContentId, ValidationCheckpoint>>,
    planner_authority: Option<PlannerAuthorityKey>,
    debugger_authority: Option<DebuggerAuthorityKey>,
}

struct RepositoryMutationGuard<'a> {
    _local: MutexGuard<'a, ()>,
    _publication: Box<dyn RefPublicationGuard + 'a>,
}

mod ancestry;
mod attempt_closure;
mod closure;
mod execution;
mod executor_driver;
mod finding;
mod objective;
mod observation;
mod planner_driver;
mod planner_issue;
mod projection;
mod queue;
mod records;
mod retention;
mod supervisor;
mod transactions;

use attempt_closure::non_modeled_attempt_key;
use finding::finding_occurrence_key;
pub(crate) use finding::finding_signature_key;

pub use attempt_closure::NonModeledAttemptResult;
pub use executor_driver::{
    CampaignExecutorCancelOutcome, CampaignExecutorCheckpointOutcome, CampaignExecutorDriver,
    CampaignExecutorDriverConfigError, CampaignExecutorDriverError, CampaignExecutorStepOutcome,
};
pub use finding::FindingPublicationResult;
pub use objective::ObjectiveEvaluationPublicationResult;
pub use planner_driver::{
    CampaignPlannerDriver, CampaignPlannerDriverConfigError, CampaignPlannerDriverError,
    CampaignPlannerStepOutcome,
};
pub use queue::{
    AttemptQueue, AttemptQueueCursor, AttemptQueueError, AttemptReservation, ClaimableAttemptPage,
    MAX_ATTEMPT_QUEUE_SCAN_PAGE_ITEMS, WorkerSlotId,
};
pub use retention::{CampaignPinRetentionRecord, CampaignPinRetentionSummary};
pub use supervisor::{
    CampaignSupervisor, CampaignSupervisorConfigError, CampaignSupervisorError,
    CampaignSupervisorStepOutcome, MAX_CAMPAIGN_SUPERVISOR_WORKER_SLOTS,
};

struct LoadedSnapshot {
    envelope: ObjectEnvelope,
    snapshot: CampaignSnapshot,
}

#[derive(Default)]
struct ChoiceValidationCache {
    contracts: BTreeMap<(ContentId, ContentId), CampaignHash>,
    insertion_order: VecDeque<(ContentId, ContentId)>,
    objective_contracts: BTreeMap<CampaignPolicyId, CampaignHash>,
    objective_insertion_order: VecDeque<CampaignPolicyId>,
}

impl ChoiceValidationCache {
    fn get(&self, key: &(ContentId, ContentId)) -> Option<CampaignHash> {
        self.contracts.get(key).copied()
    }

    fn insert(&mut self, key: (ContentId, ContentId), contract: CampaignHash) {
        if self.contracts.contains_key(&key) {
            return;
        }
        if self.contracts.len() >= MAX_CHOICE_VALIDATION_CACHE_ENTRIES
            && let Some(evicted) = self.insertion_order.pop_front()
        {
            self.contracts.remove(&evicted);
        }
        self.contracts.insert(key, contract);
        self.insertion_order.push_back(key);
    }

    fn objective_contract(&self, policy: CampaignPolicyId) -> Option<CampaignHash> {
        self.objective_contracts.get(&policy).copied()
    }

    fn insert_objective_contract(&mut self, policy: CampaignPolicyId, contract: CampaignHash) {
        if self.objective_contracts.contains_key(&policy) {
            return;
        }
        if self.objective_contracts.len() >= MAX_CHOICE_VALIDATION_CACHE_ENTRIES
            && let Some(evicted) = self.objective_insertion_order.pop_front()
        {
            self.objective_contracts.remove(&evicted);
        }
        self.objective_contracts.insert(policy, contract);
        self.objective_insertion_order.push_back(policy);
    }
}

#[derive(Clone, Copy)]
struct ProjectedState {
    visible: CampaignState,
    sealed_prior: Option<CampaignState>,
    active_attempt_policy: Option<ActiveAttemptPolicy>,
}

#[derive(Clone, Copy)]
struct ValidationCheckpoint {
    ancestry_depth: usize,
    closure_objects: usize,
    lifecycle: ProjectedState,
    genesis: ContentId,
    derived_branch: Option<DerivedBranchCheckpoint>,
}

#[derive(Clone, Copy)]
struct DerivedBranchCheckpoint {
    snapshot: ContentId,
    derivation: CampaignDerivation,
}

impl ProjectedState {
    const fn new() -> Self {
        Self {
            visible: CampaignState::Created,
            sealed_prior: None,
            active_attempt_policy: None,
        }
    }

    fn apply(&mut self, action: &CampaignControlAction) -> Result<(), CampaignRepositoryError> {
        let state = self.visible;
        match action {
            CampaignControlAction::Resume
                if matches!(
                    state,
                    CampaignState::Created | CampaignState::Paused | CampaignState::Completed
                ) =>
            {
                self.visible = CampaignState::Running;
                self.active_attempt_policy = None;
            }
            CampaignControlAction::Pause(policy) if state == CampaignState::Running => {
                self.visible = CampaignState::Paused;
                self.active_attempt_policy = Some(*policy);
            }
            CampaignControlAction::Complete if state != CampaignState::Sealed => {
                self.visible = CampaignState::Completed;
                self.active_attempt_policy = None;
            }
            CampaignControlAction::Seal if state != CampaignState::Sealed => {
                self.sealed_prior = Some(state);
                self.visible = CampaignState::Sealed;
            }
            CampaignControlAction::Unseal if state == CampaignState::Sealed => {
                self.visible = self.sealed_prior.take().unwrap_or(CampaignState::Completed);
            }
            CampaignControlAction::ActivatePolicy(_) | CampaignControlAction::GrantBudget(_)
                if state != CampaignState::Sealed =>
            {
                if state == CampaignState::Completed {
                    self.visible = CampaignState::Paused;
                    self.active_attempt_policy = None;
                }
            }
            _ => return Err(CampaignRepositoryError::InvalidTransition { state }),
        }
        Ok(())
    }
}

fn campaign_ref(name: &str) -> Result<RefName, CampaignRepositoryError> {
    RefName::new(format!("campaigns/{name}")).map_err(CampaignRepositoryError::from)
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

fn mutation_result_hash_key(namespace: &str, id: CampaignHash) -> CampaignHash {
    map_key_hash(&format!("coordination.result.{namespace}"), id)
}

fn mutation_result_content_key(namespace: &str, id: ContentId) -> CampaignHash {
    map_key_content(&format!("coordination.result.{namespace}"), id)
}

fn pin_configuration_key(configuration: ConfigurationId) -> CampaignHash {
    map_key_hash("pins.configuration", configuration.as_hash())
}

fn proposal_ordinal_key(request: BranchRequestId, ordinal: u64) -> CampaignHash {
    let request = request.content_id().encode();
    let mut bytes = Vec::with_capacity(request.len() + 8);
    bytes.extend_from_slice(request.as_bytes());
    bytes.extend_from_slice(&ordinal.to_be_bytes());
    CampaignHash::derive("crucible.campaign-proposal-request-ordinal.v1", &bytes)
}

fn proposal_value_key(request: BranchRequestId, value: &crate::ChoiceValue) -> CampaignHash {
    let request = request.content_id().encode();
    let value = crate::codec::encode(value);
    let mut bytes = Vec::with_capacity(request.len() + value.len() + 8);
    bytes.extend_from_slice(request.as_bytes());
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&value);
    CampaignHash::derive("crucible.campaign-proposal-request-value.v1", &bytes)
}

pub(crate) fn planner_step_key(step: PlannerStepId) -> CampaignHash {
    map_key_content("coordination.planner-step", step.content_id())
}

pub(crate) fn planner_invocation_result_key(invocation: PlannerInvocationId) -> CampaignHash {
    map_key_content(
        "coordination.planner-invocation-result",
        invocation.content_id(),
    )
}

fn planner_head_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-coordination-planner-head.v1", b"")
}

fn admission_sequence_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-admission-sequence.v1", b"")
}

fn admission_ordinal_key(ordinal: AdmissionOrdinal) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign-admission-ordinal.v1",
        &ordinal.value().to_be_bytes(),
    )
}

fn observation_sequence_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-observation-sequence.v1", b"")
}

pub(crate) fn attempt_index_key(attempt: AttemptId) -> CampaignHash {
    map_key_content("accounting.attempt", attempt.content_id())
}

pub(crate) fn attempt_execution_basis_key(attempt: AttemptId) -> CampaignHash {
    map_key_content("accounting.attempt-execution-basis", attempt.content_id())
}

pub(crate) fn proposal_index_key(proposal: ProposalId) -> CampaignHash {
    map_key_content("exploration.proposal", proposal.content_id())
}

pub(crate) fn attempt_observation_key(attempt: AttemptId) -> CampaignHash {
    map_key_content("observations.attempt", attempt.content_id())
}

pub(crate) fn objective_evaluation_key(
    policy: CampaignPolicyId,
    observation: ObservationId,
) -> CampaignHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(policy.content_id().encode().as_bytes());
    bytes.extend_from_slice(observation.content_id().encode().as_bytes());
    CampaignHash::derive("crucible.campaign-objective-evaluation.v1", &bytes)
}

pub(crate) fn authoritative_choice_key(opportunity: ChoiceOpportunityId) -> CampaignHash {
    map_key_content("graph.choice-opportunity", opportunity.content_id())
}

pub(crate) fn choice_index_anchor_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-graph-choice-index.v1", b"")
}

pub(crate) fn choice_index_order_key(opportunity: ChoiceOpportunityId) -> CampaignHash {
    CampaignHash::from_bytes(opportunity.content_id().digest())
}

pub(crate) fn frontier_index_anchor_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b"")
}

pub(crate) fn frontier_index_order_key(request: BranchRequestId) -> CampaignHash {
    CampaignHash::from_bytes(request.content_id().digest())
}

fn branch_request_index_anchor_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-exploration-branch-request-index.v1", b"")
}

/// Derives the nested request-index slot for one semantic branch point.
fn branch_request_index_branch_key(branch_point: crate::BranchPointId) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign-exploration-branch-request-point.v1",
        &branch_point.as_hash().as_bytes(),
    )
}

fn branch_request_index_membership_key(request: BranchRequestId) -> CampaignHash {
    map_key_content("exploration.feedback-branch-request", request.content_id())
}

fn choice_discovery_result_key(
    parent: ConfigurationArtifactId,
    opportunity: ChoiceOpportunityId,
) -> CampaignHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(parent.content_id().encode().as_bytes());
    bytes.extend_from_slice(opportunity.content_id().encode().as_bytes());
    CampaignHash::derive("crucible.campaign-choice-discovery-result.v1", &bytes)
}

fn observation_conflict_key(attempt: AttemptId, observation: ObservationId) -> CampaignHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(attempt.content_id().encode().as_bytes());
    bytes.extend_from_slice(observation.content_id().encode().as_bytes());
    CampaignHash::derive("crucible.campaign-observation-conflict.v1", &bytes)
}

fn branch_point_opportunity_key(
    branch_point: crate::BranchPointId,
    opportunity: ChoiceOpportunityId,
) -> CampaignHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&branch_point.as_hash().as_bytes());
    bytes.extend_from_slice(opportunity.content_id().encode().as_bytes());
    CampaignHash::derive("crucible.campaign-branch-point-opportunity.v1", &bytes)
}

fn branch_credit_index_key(branch_point: crate::BranchPointId) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign-branch-credit-index.v1",
        &branch_point.as_hash().as_bytes(),
    )
}

fn configuration_path_index_key(configuration: ConfigurationArtifactId) -> CampaignHash {
    map_key_content(
        "observations.configuration-path-index",
        configuration.content_id(),
    )
}

fn path_index_order_key(path: BranchPathId) -> CampaignHash {
    CampaignHash::from_bytes(path.content_id().digest())
}

fn observation_successor_growth(
    choice_count: usize,
    credit_count: usize,
    indexes_path: bool,
    frontier_update_count: usize,
) -> Result<usize, CampaignRepositoryError> {
    let owner_upserts = choice_count
        .checked_mul(3)
        .and_then(|choices| choices.checked_add(OBSERVATION_FIXED_OWNER_UPSERTS))
        .ok_or_else(|| integrity("observation-successor-growth-overflow"))?;
    let growth = owner_upserts
        .checked_mul(MERKLE_UPDATE_NODE_UPPER)
        .and_then(|nodes| {
            credit_count
                .checked_mul((2 * MERKLE_UPDATE_NODE_UPPER) + 1)
                .and_then(|credits| nodes.checked_add(credits))
        })
        .and_then(|nodes| {
            let path_nodes = if indexes_path {
                2 * MERKLE_UPDATE_NODE_UPPER
            } else {
                0
            };
            path_nodes.checked_add(nodes)
        })
        .and_then(|nodes| {
            frontier_update_count
                .checked_mul(MERKLE_UPDATE_NODE_UPPER + 1)
                .and_then(|updates| nodes.checked_add(updates))
        })
        .and_then(|nodes| {
            if frontier_update_count == 0 {
                Some(nodes)
            } else {
                nodes.checked_add(MERKLE_UPDATE_NODE_UPPER)
            }
        })
        .and_then(|nodes| nodes.checked_add(1))
        .ok_or_else(|| integrity("observation-successor-growth-overflow"))?;
    if growth > MAX_OBSERVATION_SUCCESSOR_GROWTH {
        return Err(integrity("observation-successor-growth-exceeds-schema"));
    }
    Ok(growth)
}

fn attempt_admission_upserts(
    admission_content: ContentId,
    admission: AttemptAdmission,
) -> Result<BTreeMap<CampaignHash, ContentId>, CampaignRepositoryError> {
    let attempt = admission.attempt().content_id();
    let proposal = match admission.role() {
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposal),
            admission_ordinal,
            ..
        } => {
            let mut upserts = BTreeMap::from([
                (map_key_content("accounting.attempt", attempt), attempt),
                (
                    map_key_content("accounting.attempt-execution-basis", attempt),
                    admission_content,
                ),
                (admission_ordinal_key(admission_ordinal), admission_content),
                (admission_sequence_key(), admission_content),
            ]);
            upserts.insert(
                map_key_content("accounting.attempt-admission", admission_content),
                admission_content,
            );
            upserts.insert(
                map_key_content("accounting.proposal-admission", proposal.content_id()),
                admission_content,
            );
            return Ok(upserts);
        }
        AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
        AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
            return Err(integrity("proposal-admission-is-discovery-basis"));
        }
    };
    Ok(BTreeMap::from([
        (
            map_key_content("accounting.attempt-admission", admission_content),
            admission_content,
        ),
        (
            map_key_content("accounting.proposal-admission", proposal.content_id()),
            admission_content,
        ),
    ]))
}

fn required_child(
    envelope: &ObjectEnvelope,
    role: &'static str,
) -> Result<ContentId, CampaignRepositoryError> {
    optional_child(envelope, role).ok_or_else(|| integrity("required-child-missing"))
}

fn optional_child(envelope: &ObjectEnvelope, role: &str) -> Option<ContentId> {
    envelope
        .children()
        .iter()
        .find(|child| child.role() == role)
        .map(crate::ChildReference::id)
}

fn snapshot_roots(snapshot: &CampaignSnapshot) -> [ContentId; 9] {
    let roots = snapshot.roots();
    [
        roots.graph,
        roots.exploration,
        roots.observations,
        roots.corpus,
        roots.coverage,
        roots.findings,
        roots.pins,
        roots.accounting,
        roots.coordination,
    ]
}

const fn is_opaque_campaign_leaf(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::RamExtent
            | ObjectKind::DiskExtent
            | ObjectKind::DeviceState
            | ObjectKind::Trace
    )
}

const fn is_campaign_record_kind(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::CampaignFact
            | ObjectKind::CampaignSnapshot
            | ObjectKind::MerkleNode
            | ObjectKind::Policy
            | ObjectKind::Scenario
            | ObjectKind::Configuration
            | ObjectKind::Finding
            | ObjectKind::Observation
            | ObjectKind::Projection
    )
}

const fn integrity(reason: &'static str) -> CampaignRepositoryError {
    CampaignRepositoryError::Integrity { reason }
}

#[cfg(test)]
mod tests;
