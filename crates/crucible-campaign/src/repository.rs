//! Transactional campaign snapshots over immutable objects and one mutable ref.
//!
//! A mutation publishes every immutable object first and advances exactly one
//! campaign ref last. A crash before the compare-and-swap leaves only harmless
//! unreachable objects. Accepted command facts remain in the accounting Merkle
//! root, so retry checks command identity before snapshot staleness and can
//! reconstruct the original prior/new response from linear snapshot ancestry.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName, StoreError,
};
use thiserror::Error;

use crate::{
    Attempt, AttemptAdmission, AttemptAdmissionRole, AttemptStart, BranchPath, BranchRequest,
    BranchRequestCause, BranchRequestId, CampaignCodecError, CampaignControlAction, CampaignFact,
    CampaignHash, CampaignLineage, CampaignLineageId, CampaignPolicy, CampaignPolicyId,
    CampaignSnapshot, CampaignSnapshotId, CampaignState, CandidateGeneratorAlgorithm,
    CandidateGeneratorSpec, CandidateGeneratorSpecId, CandidateSource, ChoiceDomain,
    ChoiceDomainId, ChoiceGroup, ChoiceGroupId, ChoiceOpportunity, ChoiceOpportunityId,
    ConfigurationArtifact, ConfigurationArtifactId, ConfigurationId, ControlRequest,
    ExpansionState, MerkleMap, MerkleMapRoot, ObjectEnvelope, PlannerInvocation,
    PlannerInvocationId, PlannerState, PlannerStep, PolicyActivation, PolicyArtifact, Proposal,
    ScenarioArtifact, ScenarioArtifactId, ScenarioDefId, SelectableDeclaration, SelectableId,
    Selection, SelectionId,
};

const MAX_ENVELOPE_BYTES: u64 = crate::codec::MAX_CANONICAL_BYTES as u64;
const MAX_SNAPSHOT_ANCESTRY: usize = 100_000;
const MAX_CLOSURE_OBJECTS: usize = 1_000_000;

/// Authenticated current value of one named campaign ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignHead {
    name: String,
    snapshot_id: CampaignSnapshotId,
    snapshot: CampaignSnapshot,
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

/// Selection and exact choice records authenticated together by a repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSelection {
    selection: Selection,
    opportunity: ChoiceOpportunity,
    domain: ChoiceDomain,
}

impl ResolvedSelection {
    /// Returns the authenticated recorded selection.
    #[must_use]
    pub const fn selection(&self) -> &Selection {
        &self.selection
    }

    /// Returns the authenticated opportunity selected from.
    #[must_use]
    pub const fn opportunity(&self) -> &ChoiceOpportunity {
        &self.opportunity
    }

    /// Returns the authenticated effective choice domain.
    #[must_use]
    pub const fn domain(&self) -> &ChoiceDomain {
        &self.domain
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

/// Repository and sole-writer transaction boundary for local campaigns.
pub struct CampaignRepository {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    merkle: MerkleMap,
    mutation_lock: Mutex<()>,
}

impl CampaignRepository {
    /// Builds a repository over independently composable blob and ref backends.
    #[must_use]
    pub fn new(blobs: Arc<dyn ImmutableBlobBackend>, refs: Arc<dyn MutableRefBackend>) -> Self {
        let merkle = MerkleMap::new(blobs.clone());
        Self {
            blobs,
            refs,
            merkle,
            mutation_lock: Mutex::new(()),
        }
    }

    /// Creates a campaign with a canonical genesis snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name, scenario/policy mismatch, existing
    /// ref, failed object publication, or failed authoritative ref creation.
    pub fn create(
        &self,
        name: &str,
        lineage: &CampaignLineage,
        policy: &CampaignPolicy,
        generators: &BTreeMap<CandidateGeneratorSpecId, CandidateGeneratorSpec>,
    ) -> Result<CampaignHead, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        if self.refs.read_ref(&campaign_ref)?.is_some() {
            return Err(CampaignRepositoryError::AlreadyExists);
        }
        if lineage.scenario() != policy.scenario() {
            return Err(integrity("lineage-policy-scenario-mismatch"));
        }
        let scenario_artifact =
            self.read_scenario_artifact(lineage.scenario_content().content_id())?;
        let genesis_artifact =
            self.read_configuration_artifact(lineage.genesis_content().content_id())?;
        if scenario_artifact.scenario() != lineage.scenario()
            || scenario_artifact.payload_schema() != lineage.scenario_schema()
            || genesis_artifact.scenario() != lineage.scenario()
            || genesis_artifact.scenario_artifact() != lineage.scenario_content()
            || genesis_artifact.configuration() != lineage.genesis()
        {
            return Err(integrity("lineage-execution-model-artifact-mismatch"));
        }

        for (expected, generator) in generators {
            if generator.id()? != *expected {
                return Err(integrity("candidate-generator-map-key-mismatch"));
            }
            self.put_generator(generator)?;
        }
        for child in policy.content_children() {
            let generator = CandidateGeneratorSpecId::from_content_id(child.1)?;
            if !generators.contains_key(&generator) {
                return Err(integrity("campaign-policy-generator-was-not-supplied"));
            }
        }

        let lineage_content = self.put_lineage(lineage)?;
        let policy_content = self.put_policy(policy)?;
        let empty = self.merkle.empty()?.content_id();
        let graph = self.merkle.insert(
            empty,
            map_key_hash("graph.configuration", lineage.genesis().as_hash()),
            lineage.genesis_content().content_id(),
        )?;
        let corpus = self.merkle.insert(
            empty,
            map_key_hash("corpus.configuration", lineage.genesis().as_hash()),
            lineage.genesis_content().content_id(),
        )?;
        let snapshot = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(lineage_content)?,
            CampaignPolicyId::from_content_id(policy_content)?,
            crate::CampaignRoots {
                graph: graph.content_id(),
                exploration: empty,
                observations: empty,
                corpus: corpus.content_id(),
                coverage: empty,
                findings: empty,
                pins: empty,
                accounting: empty,
            },
        )?;
        let content_id = self.put_snapshot(&snapshot)?;
        self.validate_complete_head(content_id)?;
        match self
            .refs
            .compare_exchange(&campaign_ref, None, content_id)?
        {
            RefCasOutcome::Advanced { .. } => Ok(CampaignHead {
                name: name.to_owned(),
                snapshot_id: CampaignSnapshotId::from_content_id(content_id)?,
                snapshot,
            }),
            RefCasOutcome::Conflict { .. } => Err(CampaignRepositoryError::AlreadyExists),
        }
    }

    /// Resolves and authenticates the current campaign head and its lineage and
    /// policy references.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::NotFound`] for an absent name or an
    /// integrity/store error for an invalid reachable closure.
    pub fn head(&self, name: &str) -> Result<CampaignHead, CampaignRepositoryError> {
        let campaign_ref = campaign_ref(name)?;
        let content_id = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let loaded = self.read_snapshot(content_id)?;
        self.validate_complete_head(content_id)?;
        Ok(CampaignHead {
            name: name.to_owned(),
            snapshot_id: CampaignSnapshotId::from_content_id(content_id)?,
            snapshot: loaded.snapshot,
        })
    }

    /// Projects durable lifecycle intent from authenticated snapshot ancestry.
    ///
    /// # Errors
    ///
    /// Returns an integrity error for a cycle, excessive ancestry, malformed
    /// transition, or invalid historical state transition.
    pub fn state(&self, name: &str) -> Result<CampaignState, CampaignRepositoryError> {
        let head = self.head(name)?;
        self.project_state(head.content_id())
            .map(|state| state.visible)
    }

    /// Loads an exact scenario artifact and authenticates its stored identity.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, corrupt, or
    /// wrongly typed record.
    pub fn load_scenario_artifact(
        &self,
        id: ScenarioArtifactId,
    ) -> Result<ScenarioArtifact, CampaignRepositoryError> {
        self.read_scenario_artifact(id.content_id())
    }

    /// Loads a configuration and validates its exact scenario-artifact binding.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for an invalid record or
    /// cross-record semantic mismatch.
    pub fn load_configuration_artifact(
        &self,
        id: ConfigurationArtifactId,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        self.read_configuration_artifact(id.content_id())
    }

    /// Loads an exact selectable declaration.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, corrupt, or
    /// wrongly typed declaration.
    pub fn load_selectable(
        &self,
        id: SelectableId,
    ) -> Result<SelectableDeclaration, CampaignRepositoryError> {
        self.read_selectable(id.content_id())
    }

    /// Loads an exact choice domain.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, corrupt, or
    /// wrongly typed domain.
    pub fn load_choice_domain(
        &self,
        id: ChoiceDomainId,
    ) -> Result<ChoiceDomain, CampaignRepositoryError> {
        self.read_choice_domain(id.content_id())
    }

    /// Loads and resolves a choice opportunity against its declaration/domain.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the opportunity or any
    /// of its exact references is missing, corrupt, or inconsistent.
    pub fn load_choice_opportunity(
        &self,
        id: ChoiceOpportunityId,
    ) -> Result<ChoiceOpportunity, CampaignRepositoryError> {
        self.read_opportunity(id.content_id())
    }

    /// Loads a choice group and validates every exact member declaration.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the group closure is
    /// missing, corrupt, or semantically inconsistent.
    pub fn load_choice_group(
        &self,
        id: ChoiceGroupId,
    ) -> Result<ChoiceGroup, CampaignRepositoryError> {
        self.read_group(id.content_id())
    }

    /// Loads a selection with the opportunity and domain needed to trust it.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for missing/corrupt records,
    /// illegal values, or invalid self-contained provenance. Model samples
    /// still require their pure model verifier before execution.
    pub fn resolve_selection(
        &self,
        id: SelectionId,
    ) -> Result<ResolvedSelection, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id.content_id(), crate::CampaignRecordKind::Selection)?;
        let selection = Selection::from_canonical_bytes(envelope.body())?;
        if selection.id()? != id {
            return Err(integrity("selection-envelope-shape"));
        }
        let opportunity = self.read_opportunity(required_child(&envelope, "opportunity")?)?;
        let domain = self.read_choice_domain(required_child(&envelope, "domain")?)?;
        selection.validate_resolved_references(&opportunity, &domain)?;
        Ok(ResolvedSelection {
            selection,
            opportunity,
            domain,
        })
    }

    /// Loads a planner invocation after validating all engine and input links.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the invocation basis is
    /// missing, corrupt, or binds records from different planner engines.
    pub fn load_planner_invocation(
        &self,
        id: PlannerInvocationId,
    ) -> Result<PlannerInvocation, CampaignRepositoryError> {
        let envelope = self.require_record_kind(
            id.content_id(),
            crate::CampaignRecordKind::PlannerInvocation,
        )?;
        let invocation = crate::codec::decode::<PlannerInvocation>(envelope.body())?;
        if invocation.id()? != id {
            return Err(integrity("planner-invocation-envelope-shape"));
        }
        self.validate_planner_invocation_references(&envelope)?;
        Ok(invocation)
    }

    /// Submits one additive, lazily consumed branch request.
    ///
    /// Acceptance stores the request in the exploration root and records one
    /// transition fact. It does not enumerate candidates, create proposals, or
    /// admit attempts. Repeating an already accepted exact request returns its
    /// original transition even when later snapshots are current.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid request closure, a parent configuration
    /// outside the campaign graph, a stale precondition, publication failure,
    /// or final authoritative-ref conflict.
    pub fn submit_branch_request(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        request: &BranchRequest,
    ) -> Result<BranchRequestResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let request_id = request.id()?;
        if let Some(result) = self.find_branch_request_result(current_content, request_id)? {
            return Ok(result);
        }
        if let BranchRequestCause::Operator(command) = request.cause()
            && self.mutation_command_exists(current_content, command)?
        {
            return Err(CampaignRepositoryError::CommandReuse);
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }
        let parent = self.validate_branch_request_references(request)?;
        self.validate_branch_request_campaign_scope(&current, request, &parent)?;

        let request_content = self.put_branch_request(request)?;
        if request_content != request_id.content_id() {
            return Err(integrity("branch-request-publication-id-mismatch"));
        }
        let request_key = map_key_content("exploration.branch-request", request_content);
        if self
            .merkle
            .get(current.snapshot.roots().exploration, request_key)?
            .is_some()
        {
            return Err(integrity("branch-request-index-has-no-ancestry-transition"));
        }
        let exploration = self.merkle.insert(
            current.snapshot.roots().exploration,
            request_key,
            request_content,
        )?;

        let fact = CampaignFact::BranchRequestIssued(request_id);
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        roots.exploration = exploration.content_id();
        let next = CampaignSnapshot::successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            crate::CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        self.validate_complete_head(next_content)?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => Ok(BranchRequestResult {
                prior_snapshot: current_id,
                new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                request: request_id,
                replayed: false,
            }),
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Applies one idempotent lifecycle, policy, or budget command.
    ///
    /// Command lookup happens before stale-precondition checking. Replaying the
    /// same command and payload therefore returns the original transition even
    /// after later snapshots; reusing an ID for another payload fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid closure/action, command-ID reuse, stale
    /// precondition, object publication failure, or final ref CAS conflict.
    pub fn apply_control(
        &self,
        name: &str,
        request: &ControlRequest,
    ) -> Result<CampaignCommandResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let command_key = map_key_hash("accounting.command", request.command.as_hash());
        if let Some(fact_content) = self
            .merkle
            .get(current.snapshot.roots().accounting, command_key)?
        {
            let fact = self.read_fact(fact_content)?;
            let CampaignFact::ControlRequested(prior_request) = fact else {
                return Err(integrity("command-index-value-is-not-control-fact"));
            };
            if prior_request != *request {
                return Err(CampaignRepositoryError::CommandReuse);
            }
            return self.find_command_result(current_content, request, true);
        }
        if self.mutation_command_exists(current_content, request.command)? {
            return Err(CampaignRepositoryError::CommandReuse);
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if request.expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: request.expected_snapshot,
                current: current_id,
            });
        }
        let mut projected = self.project_state(current_content)?;
        projected.apply(&request.action)?;

        let control_fact = CampaignFact::ControlRequested(request.clone());
        let control_content = self.put_fact(&control_fact)?;
        let mut accounting = self.merkle.insert(
            current.snapshot.roots().accounting,
            command_key,
            control_content,
        )?;

        let mut active_policy = current.snapshot.active_policy();
        match request.action {
            CampaignControlAction::ActivatePolicy(next) => {
                let next_content = next.content_id();
                let policy = self.read_policy(next_content)?;
                let lineage_content = required_child(&current.envelope, "lineage")?;
                let lineage = self.read_lineage(lineage_content)?;
                if policy.scenario() != lineage.scenario() {
                    return Err(integrity("activated-policy-scenario-mismatch"));
                }
                let activation =
                    CampaignFact::PolicyActivated(PolicyActivation::new(active_policy, next)?);
                let activation_content = self.put_fact(&activation)?;
                accounting = self.insert_fact(accounting, &activation, activation_content)?;
                active_policy = next;
            }
            CampaignControlAction::GrantBudget(grant) => {
                let budget = CampaignFact::BudgetGranted(grant);
                let budget_content = self.put_fact(&budget)?;
                accounting = self.insert_fact(accounting, &budget, budget_content)?;
            }
            _ => {}
        }

        let mut roots = current.snapshot.roots();
        roots.accounting = accounting.content_id();
        let next = CampaignSnapshot::successor(
            current_id,
            current.snapshot.lineage(),
            active_policy,
            roots,
            crate::CampaignFactId::from_content_id(control_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        self.validate_complete_head(next_content)?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => Ok(CampaignCommandResult {
                prior_snapshot: current_id,
                new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                replayed: false,
            }),
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Publishes a policy object so a later activation command can name it.
    ///
    /// # Errors
    ///
    /// Returns a canonical or store error if the policy cannot be placed.
    pub fn publish_policy(
        &self,
        policy: &CampaignPolicy,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let content = self.put_policy(policy)?;
        self.verify_campaign_closure(content)?;
        Ok(content)
    }

    /// Publishes a closed candidate-generator specification.
    ///
    /// Child specifications named by an ordered mixture must already exist;
    /// callers normally publish a dependency-ordered set before a policy.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or closure error if the specification cannot
    /// be authenticated and placed.
    pub fn publish_generator(
        &self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<CandidateGeneratorSpecId, CampaignRepositoryError> {
        let content = self.put_generator(generator)?;
        self.verify_campaign_closure(content)?;
        CandidateGeneratorSpecId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes exact canonical scenario bytes for use by a lineage.
    ///
    /// The execution-model adapter remains responsible for proving that these
    /// bytes produce the lineage's semantic [`crate::ScenarioDefId`].
    ///
    /// # Errors
    ///
    /// Returns a store error if the artifact cannot be authenticated and placed.
    pub fn publish_scenario_artifact(
        &self,
        scenario: ScenarioDefId,
        payload_schema: u32,
        bytes: Vec<u8>,
    ) -> Result<ScenarioArtifactId, CampaignRepositoryError> {
        let artifact = ScenarioArtifact::new(scenario, payload_schema, bytes)?;
        let content = self.put_scenario_artifact(&artifact)?;
        self.verify_campaign_closure(content)?;
        ScenarioArtifactId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes exact canonical configuration bytes for use by a lineage.
    ///
    /// The execution-model adapter remains responsible for proving that these
    /// bytes produce the lineage's semantic [`crate::ConfigurationId`].
    ///
    /// # Errors
    ///
    /// Returns a store error if the artifact cannot be authenticated and placed.
    pub fn publish_configuration_artifact(
        &self,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        payload_schema: u32,
        bytes: Vec<u8>,
    ) -> Result<ConfigurationArtifactId, CampaignRepositoryError> {
        let artifact = ConfigurationArtifact::new(
            scenario,
            scenario_artifact,
            configuration,
            payload_schema,
            bytes,
        )?;
        let content = self.put_configuration_artifact(&artifact)?;
        self.verify_campaign_closure(content)?;
        ConfigurationArtifactId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes an exact choice domain.
    ///
    /// # Errors
    ///
    /// Returns a canonical or store error if the domain cannot be placed and
    /// authenticated.
    pub fn publish_choice_domain(
        &self,
        domain: &ChoiceDomain,
    ) -> Result<ChoiceDomainId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceDomain,
            BTreeSet::new(),
            domain.canonical_bytes(),
        )?)?;
        self.verify_campaign_closure(content)?;
        ChoiceDomainId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes an exact selectable declaration.
    ///
    /// # Errors
    ///
    /// Returns a canonical or store error if the declaration cannot be placed
    /// and authenticated.
    pub fn publish_selectable(
        &self,
        selectable: &SelectableDeclaration,
    ) -> Result<SelectableId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::SelectableDeclaration,
            BTreeSet::new(),
            selectable.canonical_bytes(),
        )?)?;
        self.verify_campaign_closure(content)?;
        SelectableId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a choice opportunity after resolving its declaration/domain.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or integrity error if either dependency is
    /// absent or the opportunity's copied semantic fields disagree.
    pub fn publish_choice_opportunity(
        &self,
        opportunity: &ChoiceOpportunity,
    ) -> Result<ChoiceOpportunityId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceOpportunity,
            crate::object::content_children(opportunity.content_children())?,
            crate::codec::encode(opportunity),
        )?)?;
        self.verify_campaign_closure(content)?;
        ChoiceOpportunityId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a simultaneous choice group after resolving every declaration.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or integrity error if a declaration is
    /// absent or disagrees with the group's effective domain.
    pub fn publish_choice_group(
        &self,
        group: &ChoiceGroup,
    ) -> Result<ChoiceGroupId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceGroup,
            crate::object::content_children(group.content_children())?,
            crate::codec::encode(group),
        )?)?;
        self.verify_campaign_closure(content)?;
        ChoiceGroupId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a selection after validating its opportunity and legal domain.
    ///
    /// Model-sampled selections remain subject to their pure model verifier at
    /// execution time; their self-contained model identity is checked here.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or integrity error for an absent dependency,
    /// illegal value, or invalid origin evidence.
    pub fn publish_selection(
        &self,
        selection: &Selection,
    ) -> Result<SelectionId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::Selection,
            crate::object::content_children(selection.content_children())?,
            selection.canonical_bytes(),
        )?)?;
        self.verify_campaign_closure(content)?;
        SelectionId::from_content_id(content).map_err(Into::into)
    }

    fn insert_fact(
        &self,
        root: MerkleMapRoot,
        fact: &CampaignFact,
        content: ContentId,
    ) -> Result<MerkleMapRoot, CampaignRepositoryError> {
        self.merkle
            .insert(
                root.content_id(),
                map_key_content("accounting.fact", fact.id()?.content_id()),
                content,
            )
            .map_err(CampaignRepositoryError::from)
    }

    fn find_command_result(
        &self,
        mut content_id: ContentId,
        request: &ControlRequest,
        replayed: bool,
    ) -> Result<CampaignCommandResult, CampaignRepositoryError> {
        let mut visited = BTreeSet::new();
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if !visited.insert(content_id) {
                return Err(integrity("snapshot-ancestry-cycle"));
            }
            let loaded = self.read_snapshot(content_id)?;
            if let Some(transition_content) = optional_child(&loaded.envelope, "transition") {
                let transition = self.read_fact(transition_content)?;
                if let CampaignFact::ControlRequested(candidate) = transition
                    && candidate.command == request.command
                {
                    if candidate != *request {
                        return Err(CampaignRepositoryError::CommandReuse);
                    }
                    return Ok(CampaignCommandResult {
                        prior_snapshot: request.expected_snapshot,
                        new_snapshot: CampaignSnapshotId::from_content_id(content_id)?,
                        replayed,
                    });
                }
            }
            let Some(parent) = optional_child(&loaded.envelope, "parent") else {
                return Err(integrity("command-index-entry-has-no-ancestry-transition"));
            };
            content_id = parent;
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    fn find_branch_request_result(
        &self,
        mut content_id: ContentId,
        request: BranchRequestId,
    ) -> Result<Option<BranchRequestResult>, CampaignRepositoryError> {
        let mut visited = BTreeSet::new();
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if !visited.insert(content_id) {
                return Err(integrity("snapshot-ancestry-cycle"));
            }
            let loaded = self.read_snapshot(content_id)?;
            if let Some(transition_content) = optional_child(&loaded.envelope, "transition") {
                let transition = self.read_fact(transition_content)?;
                if transition == CampaignFact::BranchRequestIssued(request) {
                    let prior_snapshot = loaded
                        .snapshot
                        .parent()
                        .ok_or_else(|| integrity("branch-request-transition-has-no-parent"))?;
                    return Ok(Some(BranchRequestResult {
                        prior_snapshot,
                        new_snapshot: CampaignSnapshotId::from_content_id(content_id)?,
                        request,
                        replayed: true,
                    }));
                }
            }
            let Some(parent) = optional_child(&loaded.envelope, "parent") else {
                return Ok(None);
            };
            content_id = parent;
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    fn mutation_command_exists(
        &self,
        mut content_id: ContentId,
        command: crate::CampaignCommandId,
    ) -> Result<bool, CampaignRepositoryError> {
        let mut visited = BTreeSet::new();
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if !visited.insert(content_id) {
                return Err(integrity("snapshot-ancestry-cycle"));
            }
            let loaded = self.read_snapshot(content_id)?;
            if let Some(transition_content) = optional_child(&loaded.envelope, "transition") {
                match self.read_fact(transition_content)? {
                    CampaignFact::ControlRequested(request) if request.command == command => {
                        return Ok(true);
                    }
                    CampaignFact::BranchRequestIssued(request) => {
                        let request = self.read_branch_request(request.content_id())?;
                        if request.cause() == BranchRequestCause::Operator(command) {
                            return Ok(true);
                        }
                    }
                    _ => {}
                }
            }
            let Some(parent) = optional_child(&loaded.envelope, "parent") else {
                return Ok(false);
            };
            content_id = parent;
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    fn project_state(
        &self,
        mut content_id: ContentId,
    ) -> Result<ProjectedState, CampaignRepositoryError> {
        let mut actions = Vec::new();
        let mut visited = BTreeSet::new();
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if !visited.insert(content_id) {
                return Err(integrity("snapshot-ancestry-cycle"));
            }
            let loaded = self.read_snapshot(content_id)?;
            let parent_id = loaded.snapshot.parent();
            let parent_content = optional_child(&loaded.envelope, "parent");
            let transition_content = optional_child(&loaded.envelope, "transition");
            match (parent_id, parent_content, transition_content) {
                (None, None, None) => {
                    actions.reverse();
                    let mut projected = ProjectedState::new();
                    for action in &actions {
                        projected.apply(action)?;
                    }
                    return Ok(projected);
                }
                (Some(parent_id), Some(parent_content), Some(transition_content)) => {
                    self.read_snapshot(parent_content)?;
                    if CampaignSnapshotId::from_content_id(parent_content)? != parent_id {
                        return Err(integrity("parent-logical-id-mismatch"));
                    }
                    let transition = self.read_fact(transition_content)?;
                    match transition {
                        CampaignFact::ControlRequested(request) => {
                            if request.expected_snapshot != parent_id {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            actions.push(request.action);
                        }
                        CampaignFact::BranchRequestIssued(_) => {}
                        _ => {
                            return Err(integrity("snapshot-transition-type-is-not-implemented"));
                        }
                    }
                    content_id = parent_content;
                }
                _ => return Err(integrity("snapshot-parent-transition-shape")),
            }
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    fn put_lineage(&self, lineage: &CampaignLineage) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_lineage(lineage)?)
    }

    fn put_policy(&self, policy: &CampaignPolicy) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_policy(policy)?)
    }

    fn put_generator(
        &self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CandidateGeneratorSpec,
            crate::object::content_children(generator.content_children())?,
            generator.canonical_bytes(),
        )?)
    }

    fn put_branch_request(
        &self,
        request: &BranchRequest,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::BranchRequest,
            crate::object::content_children(request.content_children())?,
            request.canonical_bytes(),
        )?)
    }

    fn put_scenario_artifact(
        &self,
        artifact: &ScenarioArtifact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ScenarioArtifact,
            BTreeSet::new(),
            artifact.canonical_bytes(),
        )?)
    }

    fn put_configuration_artifact(
        &self,
        artifact: &ConfigurationArtifact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ConfigurationArtifact,
            crate::object::content_children(artifact.content_children())?,
            artifact.canonical_bytes(),
        )?)
    }

    fn put_fact(&self, fact: &CampaignFact) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_fact(fact)?)
    }

    fn put_snapshot(
        &self,
        snapshot: &CampaignSnapshot,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let envelope = ObjectEnvelope::for_snapshot(snapshot)?;
        self.put_envelope(envelope)
    }

    fn put_envelope(&self, envelope: ObjectEnvelope) -> Result<ContentId, CampaignRepositoryError> {
        let id = envelope.content_id();
        let receipt = self
            .blobs
            .put_if_absent(id, &BlobHandle::from_bytes(envelope.canonical_bytes()))?;
        if receipt.id != id {
            return Err(integrity("store-receipt-id-mismatch"));
        }
        Ok(id)
    }

    fn read_envelope(&self, id: ContentId) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        let bytes = self.blobs.read(id, None)?.read_all(MAX_ENVELOPE_BYTES)?;
        let envelope = ObjectEnvelope::from_canonical_bytes(&bytes)?;
        if envelope.content_id() != id {
            return Err(integrity("envelope-content-id-mismatch"));
        }
        Ok(envelope)
    }

    fn read_snapshot(&self, id: ContentId) -> Result<LoadedSnapshot, CampaignRepositoryError> {
        if id.kind() != ObjectKind::CampaignSnapshot {
            return Err(integrity("snapshot-content-kind"));
        }
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Snapshot {
            return Err(integrity("snapshot-record-kind"));
        }
        let snapshot = CampaignSnapshot::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_snapshot(&snapshot)? != envelope || snapshot.id()?.content_id() != id
        {
            return Err(integrity("snapshot-child-table-mismatch"));
        }
        Ok(LoadedSnapshot { envelope, snapshot })
    }

    fn validate_complete_head(&self, head: ContentId) -> Result<(), CampaignRepositoryError> {
        self.validate_snapshot_ancestry(head)?;
        self.verify_campaign_closure(head)
    }

    fn validate_snapshot_ancestry(
        &self,
        mut content_id: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        let mut snapshots = BTreeSet::new();
        let mut verified_roots = BTreeSet::new();
        let mut seen_commands = BTreeSet::new();
        let mut expected_lineage = None;
        let mut actions = Vec::new();

        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if !snapshots.insert(content_id) {
                return Err(integrity("snapshot-ancestry-cycle"));
            }
            let loaded = self.read_snapshot(content_id)?;
            self.validate_snapshot_references_once(&loaded, &mut verified_roots)?;

            match expected_lineage {
                None => expected_lineage = Some(loaded.snapshot.lineage()),
                Some(lineage) if lineage != loaded.snapshot.lineage() => {
                    return Err(integrity("snapshot-ancestry-lineage-mismatch"));
                }
                Some(_) => {}
            }

            match (loaded.snapshot.parent(), loaded.snapshot.transition()) {
                (None, None) => {
                    self.validate_genesis_snapshot(&loaded)?;
                    actions.reverse();
                    let mut projected = ProjectedState::new();
                    for action in &actions {
                        projected.apply(action)?;
                    }
                    return Ok(());
                }
                (Some(parent), Some(transition)) => {
                    let transition_fact = self.read_fact(transition.content_id())?;
                    let parent_snapshot = self.read_snapshot(parent.content_id())?;
                    match transition_fact {
                        CampaignFact::ControlRequested(request) => {
                            if !seen_commands.insert(request.command) {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_control_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                &request,
                            )?;
                            actions.push(request.action);
                        }
                        CampaignFact::BranchRequestIssued(request) => {
                            let request_record = self.read_branch_request(request.content_id())?;
                            if let BranchRequestCause::Operator(command) = request_record.cause()
                                && !seen_commands.insert(command)
                            {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            self.validate_branch_request_successor(
                                &parent_snapshot,
                                &loaded,
                                request,
                            )?;
                        }
                        _ => {
                            return Err(integrity("snapshot-transition-type-is-not-implemented"));
                        }
                    }
                    content_id = parent.content_id();
                }
                _ => return Err(integrity("snapshot-parent-transition-shape")),
            }
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    fn validate_genesis_snapshot(
        &self,
        loaded: &LoadedSnapshot,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage = self.read_lineage(required_child(&loaded.envelope, "lineage")?)?;
        let roots = loaded.snapshot.roots();
        let expected_genesis = lineage.genesis_content().content_id();
        for (root, namespace) in [
            (roots.graph, "graph.configuration"),
            (roots.corpus, "corpus.configuration"),
        ] {
            let inspected = self.merkle.inspect_shallow(root)?;
            if inspected.entry_count() != 1
                || self
                    .merkle
                    .get(root, map_key_hash(namespace, lineage.genesis().as_hash()))?
                    != Some(expected_genesis)
            {
                return Err(integrity("genesis-configuration-root-mismatch"));
            }
        }

        let empty_roots = [
            roots.exploration,
            roots.observations,
            roots.coverage,
            roots.findings,
            roots.pins,
            roots.accounting,
        ];
        for root in empty_roots {
            if self.merkle.inspect_shallow(root)?.entry_count() != 0 {
                return Err(integrity("genesis-nonconfiguration-root-is-not-empty"));
            }
        }
        if empty_roots.windows(2).any(|pair| pair[0] != pair[1]) {
            return Err(integrity("genesis-empty-roots-are-not-canonical"));
        }
        Ok(())
    }

    fn validate_control_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        transition_content: ContentId,
        request: &ControlRequest,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage() {
            return Err(integrity("snapshot-transition-changed-lineage"));
        }

        let expected_policy = match request.action {
            CampaignControlAction::ActivatePolicy(policy) => policy,
            _ => parent.snapshot.active_policy(),
        };
        if child.snapshot.active_policy() != expected_policy {
            return Err(integrity("snapshot-transition-active-policy-mismatch"));
        }

        let prior_roots = parent.snapshot.roots();
        let next_roots = child.snapshot.roots();
        if prior_roots.graph != next_roots.graph
            || prior_roots.exploration != next_roots.exploration
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
        {
            return Err(integrity("control-transition-changed-nonaccounting-root"));
        }

        let command_key = map_key_hash("accounting.command", request.command.as_hash());
        if self
            .merkle
            .get(prior_roots.accounting, command_key)?
            .is_some()
        {
            return Err(integrity("control-transition-reused-command"));
        }
        let mut upserts = BTreeMap::from([(command_key, transition_content)]);
        let auxiliary = match request.action {
            CampaignControlAction::ActivatePolicy(next) => Some(CampaignFact::PolicyActivated(
                PolicyActivation::new(parent.snapshot.active_policy(), next)?,
            )),
            CampaignControlAction::GrantBudget(grant) => Some(CampaignFact::BudgetGranted(grant)),
            _ => None,
        };
        if let Some(fact) = auxiliary {
            let content = fact.id()?.content_id();
            upserts.insert(map_key_content("accounting.fact", content), content);
        }
        if !self.merkle.equals_after_upserts(
            prior_roots.accounting,
            next_roots.accounting,
            &upserts,
        )? {
            return Err(integrity("control-transition-accounting-root-mismatch"));
        }
        Ok(())
    }

    fn validate_branch_request_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        request: BranchRequestId,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity(
                "branch-request-transition-changed-campaign-basis",
            ));
        }

        let prior_roots = parent.snapshot.roots();
        let next_roots = child.snapshot.roots();
        if prior_roots.graph != next_roots.graph
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
            || prior_roots.accounting != next_roots.accounting
        {
            return Err(integrity(
                "branch-request-transition-changed-unrelated-root",
            ));
        }

        let request_content = request.content_id();
        let request_record = self.read_branch_request(request_content)?;
        let parent_configuration =
            self.read_configuration_artifact(request_record.parent().content_id())?;
        self.validate_branch_request_campaign_scope(
            parent,
            &request_record,
            &parent_configuration,
        )?;
        let request_key = map_key_content("exploration.branch-request", request_content);
        if self
            .merkle
            .get(prior_roots.exploration, request_key)?
            .is_some()
        {
            return Err(integrity("branch-request-transition-reused-request"));
        }
        let upserts = BTreeMap::from([(request_key, request_content)]);
        if !self.merkle.equals_after_upserts(
            prior_roots.exploration,
            next_roots.exploration,
            &upserts,
        )? {
            return Err(integrity(
                "branch-request-transition-exploration-root-mismatch",
            ));
        }
        Ok(())
    }

    fn validate_snapshot_references_once(
        &self,
        loaded: &LoadedSnapshot,
        verified_roots: &mut BTreeSet<ContentId>,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage = self.read_lineage(required_child(&loaded.envelope, "lineage")?)?;
        if lineage.id()? != loaded.snapshot.lineage() {
            return Err(integrity("snapshot-lineage-logical-id"));
        }
        let policy = self.read_policy(required_child(&loaded.envelope, "active-policy")?)?;
        if policy.id()? != loaded.snapshot.active_policy()
            || policy.scenario() != lineage.scenario()
        {
            return Err(integrity("snapshot-policy-logical-id-or-scenario"));
        }
        for root in snapshot_roots(&loaded.snapshot) {
            if verified_roots.insert(root) {
                self.merkle.verify_closure(root)?;
            }
        }
        Ok(())
    }

    fn verify_campaign_closure(&self, root: ContentId) -> Result<(), CampaignRepositoryError> {
        let mut stack = vec![root];
        let mut visited = BTreeSet::new();

        while let Some(id) = stack.pop() {
            if !visited.insert(id) {
                continue;
            }
            if visited.len() > MAX_CLOSURE_OBJECTS {
                return Err(integrity("campaign-closure-object-limit"));
            }

            if id.kind() == ObjectKind::MerkleNode {
                let verified = self.merkle.verify_closure_objects(id)?;
                stack.extend(verified.values);
                continue;
            }

            let handle = self.blobs.read(id, None)?;
            if is_opaque_campaign_leaf(id.kind()) {
                let mut sink = std::io::sink();
                handle.copy_to(&mut sink)?;
                continue;
            }
            let bytes = handle.read_all(MAX_ENVELOPE_BYTES)?;
            if !is_campaign_record_kind(id.kind()) {
                let envelope = ContentEnvelope::from_canonical_bytes(&bytes)
                    .map_err(CampaignCodecError::from)?;
                if envelope.content_id(id.kind()) != id {
                    return Err(integrity("campaign-closure-envelope-id-mismatch"));
                }
                stack.extend(envelope.children().iter().map(crate::ChildReference::id));
                continue;
            }
            let envelope = ObjectEnvelope::from_canonical_bytes(&bytes)?;
            if envelope.content_id() != id {
                return Err(integrity("campaign-closure-envelope-id-mismatch"));
            }

            match envelope.record_kind() {
                crate::CampaignRecordKind::Lineage => {
                    self.read_lineage(id)?;
                }
                crate::CampaignRecordKind::Policy => {
                    self.read_policy(id)?;
                }
                crate::CampaignRecordKind::Fact => {
                    self.read_fact(id)?;
                }
                crate::CampaignRecordKind::CandidateGeneratorSpec => {
                    self.read_generator(id)?;
                }
                crate::CampaignRecordKind::ScenarioArtifact => {
                    self.read_scenario_artifact(id)?;
                }
                crate::CampaignRecordKind::ConfigurationArtifact => {
                    self.read_configuration_artifact(id)?;
                }
                crate::CampaignRecordKind::BranchRequest => {
                    self.read_branch_request(id)?;
                }
                crate::CampaignRecordKind::Proposal => {
                    self.read_proposal(id)?;
                }
                crate::CampaignRecordKind::Attempt => {
                    self.read_attempt(id)?;
                }
                crate::CampaignRecordKind::AttemptAdmission => {
                    self.read_attempt_admission(id)?;
                }
                crate::CampaignRecordKind::PlannerStep => {
                    self.read_planner_step(id)?;
                }
                crate::CampaignRecordKind::ExpansionState => {
                    self.read_expansion_state(id)?;
                }
                crate::CampaignRecordKind::PolicyArtifact => {
                    self.validate_policy_artifact_references(&envelope)?;
                }
                crate::CampaignRecordKind::PlannerState => {
                    self.validate_planner_state_references(&envelope)?;
                }
                crate::CampaignRecordKind::PlannerInvocation => {
                    self.validate_planner_invocation_references(&envelope)?;
                }
                crate::CampaignRecordKind::ChoiceOpportunity => {
                    self.validate_opportunity_references(&envelope)?;
                }
                crate::CampaignRecordKind::ChoiceGroup => {
                    self.validate_group_references(&envelope)?;
                }
                crate::CampaignRecordKind::Selection => {
                    self.validate_selection_references(&envelope)?;
                }
                _ => {}
            }
            stack.extend(envelope.children().iter().map(crate::ChildReference::id));
        }
        Ok(())
    }

    fn read_lineage(&self, id: ContentId) -> Result<CampaignLineage, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Lineage {
            return Err(integrity("lineage-envelope-shape"));
        }
        let lineage = CampaignLineage::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_lineage(&lineage)? != envelope || lineage.id()?.content_id() != id {
            return Err(integrity("lineage-envelope-shape"));
        }
        let scenario = self.read_scenario_artifact(lineage.scenario_content().content_id())?;
        let genesis = self.read_configuration_artifact(lineage.genesis_content().content_id())?;
        if scenario.scenario() != lineage.scenario()
            || scenario.payload_schema() != lineage.scenario_schema()
            || genesis.scenario() != lineage.scenario()
            || genesis.scenario_artifact() != lineage.scenario_content()
            || genesis.configuration() != lineage.genesis()
        {
            return Err(integrity("lineage-execution-model-artifact-mismatch"));
        }
        Ok(lineage)
    }

    fn read_scenario_artifact(
        &self,
        id: ContentId,
    ) -> Result<ScenarioArtifact, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ScenarioArtifact {
            return Err(integrity("scenario-artifact-envelope-shape"));
        }
        let artifact = ScenarioArtifact::from_canonical_bytes(envelope.body())?;
        if artifact.id()?.content_id() != id {
            return Err(integrity("scenario-artifact-envelope-shape"));
        }
        Ok(artifact)
    }

    fn read_configuration_artifact(
        &self,
        id: ContentId,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ConfigurationArtifact {
            return Err(integrity("configuration-artifact-envelope-shape"));
        }
        let artifact = ConfigurationArtifact::from_canonical_bytes(envelope.body())?;
        if artifact.id()?.content_id() != id {
            return Err(integrity("configuration-artifact-envelope-shape"));
        }
        let scenario = self.read_scenario_artifact(artifact.scenario_artifact().content_id())?;
        if scenario.scenario() != artifact.scenario() {
            return Err(integrity("configuration-scenario-artifact-mismatch"));
        }
        Ok(artifact)
    }

    fn read_policy(&self, id: ContentId) -> Result<CampaignPolicy, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Policy {
            return Err(integrity("policy-envelope-shape"));
        }
        let policy = CampaignPolicy::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_policy(&policy)? != envelope || policy.id()?.content_id() != id {
            return Err(integrity("policy-envelope-shape"));
        }
        for (_, child) in policy.content_children() {
            self.require_record_kind(child, crate::CampaignRecordKind::CandidateGeneratorSpec)?;
        }
        Ok(policy)
    }

    fn read_generator(
        &self,
        id: ContentId,
    ) -> Result<CandidateGeneratorSpec, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::CandidateGeneratorSpec {
            return Err(integrity("candidate-generator-envelope-shape"));
        }
        let generator = CandidateGeneratorSpec::from_canonical_bytes(envelope.body())?;
        let expected = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CandidateGeneratorSpec,
            crate::object::content_children(generator.content_children())?,
            generator.canonical_bytes(),
        )?;
        if expected != envelope || generator.id()?.content_id() != id {
            return Err(integrity("candidate-generator-envelope-shape"));
        }
        for (_, child) in generator.content_children() {
            self.require_record_kind(child, crate::CampaignRecordKind::CandidateGeneratorSpec)?;
        }
        Ok(generator)
    }

    fn read_fact(&self, id: ContentId) -> Result<CampaignFact, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Fact {
            return Err(integrity("fact-envelope-shape"));
        }
        let fact = CampaignFact::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_fact(&fact)? != envelope || fact.id()?.content_id() != id {
            return Err(integrity("fact-envelope-shape"));
        }
        self.validate_fact_references(&fact)?;
        Ok(fact)
    }

    fn validate_fact_references(&self, fact: &CampaignFact) -> Result<(), CampaignRepositoryError> {
        match fact {
            CampaignFact::ChoiceOpportunityDiscovered(id) => {
                self.require_record_kind(
                    id.content_id(),
                    crate::CampaignRecordKind::ChoiceOpportunity,
                )?;
            }
            CampaignFact::PolicyActivated(activation) => {
                self.require_record_kind(
                    activation.prior().content_id(),
                    crate::CampaignRecordKind::Policy,
                )?;
                self.require_record_kind(
                    activation.next().content_id(),
                    crate::CampaignRecordKind::Policy,
                )?;
            }
            CampaignFact::ControlRequested(request) => {
                self.require_record_kind(
                    request.expected_snapshot.content_id(),
                    crate::CampaignRecordKind::Snapshot,
                )?;
                if let CampaignControlAction::ActivatePolicy(policy) = request.action {
                    self.require_record_kind(
                        policy.content_id(),
                        crate::CampaignRecordKind::Policy,
                    )?;
                }
            }
            CampaignFact::BranchRequestIssued(id) => {
                self.read_branch_request(id.content_id())?;
            }
            CampaignFact::PlannerAdvanced(id) => {
                self.read_planner_step(id.content_id())?;
            }
            CampaignFact::ProposalIssued(id) => {
                self.read_proposal(id.content_id())?;
            }
            CampaignFact::AttemptAdmitted(admission) => {
                self.read_attempt_admission(admission.content_id())?;
            }
            CampaignFact::AttemptClosed { attempt, .. } => {
                self.require_record_kind(attempt.content_id(), crate::CampaignRecordKind::Attempt)?;
            }
            CampaignFact::ObservationPublished(_) | CampaignFact::FindingPublished(_) => {
                return Err(integrity("campaign-fact-record-type-is-not-implemented"));
            }
            CampaignFact::BudgetGranted(_) | CampaignFact::PinChanged(_) => {}
        }
        Ok(())
    }

    fn read_branch_request(&self, id: ContentId) -> Result<BranchRequest, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::BranchRequest)?;
        let request = BranchRequest::from_canonical_bytes(envelope.body())?;
        if request.id()?.content_id() != id {
            return Err(integrity("branch-request-envelope-shape"));
        }
        self.validate_branch_request_references(&request)?;
        Ok(request)
    }

    fn validate_branch_request_references(
        &self,
        request: &BranchRequest,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        let parent = self.read_configuration_artifact(request.parent().content_id())?;
        let opportunity = self.read_opportunity(request.opportunity().content_id())?;
        let domain = self.read_choice_domain(request.domain().content_id())?;
        request.validate_resolved(&parent, &opportunity, &domain)?;
        match request.source() {
            CandidateSource::Finite(_) => {}
            CandidateSource::Generated(generator) => {
                self.validate_generator_for_domain(*generator, &domain)?;
            }
        }
        match request.cause() {
            BranchRequestCause::Planner(invocation) => {
                self.load_planner_invocation(invocation)?;
            }
            BranchRequestCause::ExhaustivePolicy(policy) => {
                self.read_policy(policy.content_id())?;
            }
            BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_) => {}
        }
        Ok(parent)
    }

    fn validate_generator_for_domain(
        &self,
        root: CandidateGeneratorSpecId,
        domain: &ChoiceDomain,
    ) -> Result<(), CampaignRepositoryError> {
        let mut stack = vec![(root, 0_usize)];
        let mut visited = BTreeSet::new();
        while let Some((id, depth)) = stack.pop() {
            if depth > 1024 || visited.len() >= MAX_CLOSURE_OBJECTS {
                return Err(integrity("candidate-generator-validation-limit"));
            }
            if !visited.insert(id) {
                continue;
            }
            let generator = self.read_generator(id.content_id())?;
            match generator.algorithm() {
                CandidateGeneratorAlgorithm::All
                    if matches!(domain, ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_)) => {}
                CandidateGeneratorAlgorithm::WeightedCategorical { weights } => {
                    let ChoiceDomain::Discrete(discrete) = domain else {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    };
                    if weights
                        .keys()
                        .any(|alternative| !discrete.alternatives().contains_key(alternative))
                    {
                        return Err(integrity(
                            "candidate-generator-discrete-alternative-mismatch",
                        ));
                    }
                }
                CandidateGeneratorAlgorithm::StratifiedInteger { .. }
                | CandidateGeneratorAlgorithm::BoundaryInteger
                | CandidateGeneratorAlgorithm::LogInteger { .. }
                | CandidateGeneratorAlgorithm::PermutedInteger
                | CandidateGeneratorAlgorithm::ProgressiveInteger { .. }
                | CandidateGeneratorAlgorithm::MutateNearCorpus { .. }
                    if matches!(domain, ChoiceDomain::Integer(_)) => {}
                CandidateGeneratorAlgorithm::OrderedMixture { components } => {
                    stack.extend(
                        components
                            .iter()
                            .rev()
                            .map(|component| (component.generator(), depth + 1)),
                    );
                }
                _ => return Err(integrity("candidate-generator-domain-family-mismatch")),
            }
        }
        Ok(())
    }

    fn validate_branch_request_campaign_scope(
        &self,
        snapshot: &LoadedSnapshot,
        request: &BranchRequest,
        parent: &ConfigurationArtifact,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        if parent.scenario() != lineage.scenario() {
            return Err(integrity("branch-request-parent-scenario-mismatch"));
        }
        let expected_parent = self.merkle.get(
            snapshot.snapshot.roots().graph,
            map_key_hash("graph.configuration", parent.configuration().as_hash()),
        )?;
        if expected_parent != Some(request.parent().content_id()) {
            return Err(integrity("branch-request-parent-is-not-in-campaign-graph"));
        }

        match request.cause() {
            BranchRequestCause::Planner(invocation) => {
                let invocation = self.load_planner_invocation(invocation)?;
                if invocation.policy() != snapshot.snapshot.active_policy() {
                    return Err(integrity("branch-request-planner-policy-is-not-active"));
                }
                if invocation.input_view() != snapshot.snapshot.planning_view().id()? {
                    return Err(integrity("branch-request-planner-view-is-not-current"));
                }
            }
            BranchRequestCause::ExhaustivePolicy(policy)
                if policy != snapshot.snapshot.active_policy() =>
            {
                return Err(integrity("branch-request-policy-is-not-active"));
            }
            BranchRequestCause::ExhaustivePolicy(_)
            | BranchRequestCause::Operator(_)
            | BranchRequestCause::Debugger(_) => {}
        }

        if let CandidateSource::Generated(generator) = request.source()
            && matches!(
                request.cause(),
                BranchRequestCause::Planner(_) | BranchRequestCause::ExhaustivePolicy(_)
            )
        {
            let opportunity = self.read_opportunity(request.opportunity().content_id())?;
            let declaration = self.read_selectable(opportunity.declaration().content_id())?;
            let policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
            let selected = policy.choice_policies().get(declaration.name());
            if selected.map(crate::ChoicePolicy::generator) != Some(*generator) {
                return Err(integrity(
                    "branch-request-generator-is-not-selected-by-active-policy",
                ));
            }
        }
        Ok(())
    }

    fn read_proposal(&self, id: ContentId) -> Result<Proposal, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Proposal)?;
        let proposal = Proposal::from_canonical_bytes(envelope.body())?;
        if proposal.id()?.content_id() != id {
            return Err(integrity("proposal-envelope-shape"));
        }
        let request = self.read_branch_request(proposal.request().content_id())?;
        let domain = self.read_choice_domain(proposal.domain().content_id())?;
        proposal.validate_resolved(&request, &domain)?;
        self.read_policy(proposal.policy().content_id())?;
        self.require_record_kind(
            proposal.guidance_basis().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        if let Some(invocation) = proposal.planner_invocation() {
            let invocation = self.load_planner_invocation(invocation)?;
            if invocation.policy() != proposal.policy()
                || invocation.input_view() != proposal.guidance_basis()
            {
                return Err(integrity("proposal-planner-invocation-mismatch"));
            }
        }
        Ok(proposal)
    }

    fn read_attempt(&self, id: ContentId) -> Result<Attempt, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Attempt)?;
        let attempt = crate::codec::decode::<Attempt>(envelope.body())?;
        if attempt.id()?.content_id() != id {
            return Err(integrity("attempt-envelope-shape"));
        }
        let path = self.read_branch_path(attempt.path().content_id())?;
        match attempt.start() {
            AttemptStart::Discover { configuration } => {
                self.read_configuration_artifact(configuration.content_id())?;
            }
            AttemptStart::Branch {
                edge,
                parent,
                selection,
            } => {
                if path.edges().last() != Some(&edge) {
                    return Err(integrity("attempt-branch-path-terminal-edge-mismatch"));
                }
                let parent = self.read_configuration_artifact(parent.content_id())?;
                let resolved = self.resolve_selection(selection)?;
                let branch_point = resolved
                    .opportunity()
                    .branch_point_id(parent.configuration());
                resolved.selection().validate_branch_replay(
                    resolved.opportunity(),
                    resolved.domain(),
                    branch_point,
                )?;
                if let crate::SelectionOrigin::CampaignBranch {
                    edge: selected_edge,
                    ..
                } = resolved.selection().origin()
                    && selected_edge != edge
                {
                    return Err(integrity("attempt-branch-edge-mismatch"));
                }
            }
        }
        Ok(attempt)
    }

    fn read_branch_path(&self, id: ContentId) -> Result<BranchPath, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::BranchPath)?;
        let path = crate::codec::decode::<BranchPath>(envelope.body())?;
        if path.id()?.content_id() != id {
            return Err(integrity("branch-path-envelope-shape"));
        }
        Ok(path)
    }

    fn validate_proposal_attempt_equivalence(
        &self,
        proposal: &Proposal,
        attempt: &Attempt,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let request = self.read_branch_request(proposal.request().content_id())?;
        let AttemptStart::Branch {
            edge: _,
            parent,
            selection,
        } = attempt.start()
        else {
            return Err(integrity("proposal-cannot-admit-discovery-attempt"));
        };
        let resolved = self.resolve_selection(selection)?;
        if parent != request.parent()
            || attempt.stop() != request.stop()
            || resolved.opportunity().id()? != request.opportunity()
            || resolved.domain().id()? != request.domain()
            || resolved.selection().value() != proposal.value()
        {
            return Err(integrity("proposal-attempt-semantic-mismatch"));
        }
        Ok(request)
    }

    fn read_attempt_admission(
        &self,
        id: ContentId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::AttemptAdmission)?;
        let admission = crate::codec::decode::<AttemptAdmission>(envelope.body())?;
        if admission.id()?.content_id() != id {
            return Err(integrity("attempt-admission-envelope-shape"));
        }
        let attempt = self.read_attempt(admission.attempt().content_id())?;
        match admission.role() {
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal),
                cause,
                ..
            } => {
                let proposal = self.read_proposal(proposal.content_id())?;
                let request = self.validate_proposal_attempt_equivalence(&proposal, &attempt)?;
                if request.cause() != cause {
                    return Err(integrity("attempt-execution-basis-mismatch"));
                }
            }
            AttemptAdmissionRole::ExecutionBasis { proposal: None, .. }
                if !matches!(attempt.start(), AttemptStart::Discover { .. }) =>
            {
                return Err(integrity("branch-attempt-execution-basis-has-no-proposal"));
            }
            AttemptAdmissionRole::ExecutionBasis { .. } => {}
            AttemptAdmissionRole::AdditionalCause { proposal } => {
                let proposal = self.read_proposal(proposal.content_id())?;
                self.validate_proposal_attempt_equivalence(&proposal, &attempt)?;
            }
        }
        Ok(admission)
    }

    fn read_planner_step(&self, id: ContentId) -> Result<PlannerStep, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::PlannerStep)?;
        let step = crate::codec::decode::<PlannerStep>(envelope.body())?;
        if step.id()?.content_id() != id {
            return Err(integrity("planner-step-envelope-shape"));
        }
        let invocation = self.load_planner_invocation(step.invocation())?;
        if invocation.engine() != step.engine()
            || invocation.policy_artifact() != step.policy_artifact()
            || invocation.policy() != step.policy()
            || invocation.input_view() != step.input_view()
        {
            return Err(integrity("planner-step-invocation-mismatch"));
        }
        let source = self.read_branch_request(step.selected_source().content_id())?;
        if source.branch_point() != step.selected_branch_point() {
            return Err(integrity("planner-step-source-branch-point-mismatch"));
        }
        for proposal in step.issued_proposals() {
            let proposal = self.read_proposal(proposal.content_id())?;
            if proposal.request() != step.selected_source()
                || proposal.planner_invocation() != Some(step.invocation())
            {
                return Err(integrity("planner-step-proposal-mismatch"));
            }
        }
        self.require_record_kind(
            step.next_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        if let Some(parent) = step.parent() {
            self.require_record_kind(parent.content_id(), crate::CampaignRecordKind::PlannerStep)?;
        }
        Err(integrity(
            "planner-step-coordinator-validation-is-not-implemented",
        ))
    }

    fn read_expansion_state(
        &self,
        id: ContentId,
    ) -> Result<ExpansionState, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::ExpansionState)?;
        let state = crate::codec::decode::<ExpansionState>(envelope.body())?;
        if state.id()?.content_id() != id {
            return Err(integrity("expansion-state-envelope-shape"));
        }
        for request in state.continuations().keys() {
            let request = self.read_branch_request(request.content_id())?;
            if request.branch_point() != state.branch_point() {
                return Err(integrity("expansion-state-request-branch-point-mismatch"));
            }
        }
        Err(integrity(
            "expansion-state-projector-validation-is-not-implemented",
        ))
    }

    fn require_record_kind(
        &self,
        id: ContentId,
        expected: crate::CampaignRecordKind,
    ) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != expected {
            return Err(integrity("campaign-child-record-kind-mismatch"));
        }
        Ok(envelope)
    }

    fn validate_policy_artifact_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let artifact = crate::codec::decode::<PolicyArtifact>(envelope.body())?;
        self.require_record_kind(
            artifact.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        Ok(())
    }

    fn validate_planner_state_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let state = crate::codec::decode::<PlannerState>(envelope.body())?;
        self.require_record_kind(
            state.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        Ok(())
    }

    fn validate_planner_invocation_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let invocation = crate::codec::decode::<PlannerInvocation>(envelope.body())?;
        self.require_record_kind(
            invocation.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        let artifact_envelope = self.require_record_kind(
            invocation.policy_artifact().content_id(),
            crate::CampaignRecordKind::PolicyArtifact,
        )?;
        let artifact = crate::codec::decode::<PolicyArtifact>(artifact_envelope.body())?;
        self.require_record_kind(
            invocation.policy().content_id(),
            crate::CampaignRecordKind::Policy,
        )?;
        let state_envelope = self.require_record_kind(
            invocation.planner_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        let state = crate::codec::decode::<PlannerState>(state_envelope.body())?;
        self.require_record_kind(
            invocation.input_view().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        if artifact.engine() != invocation.engine() || state.engine() != invocation.engine() {
            return Err(integrity("planner-invocation-engine-mismatch"));
        }
        Ok(())
    }

    fn read_selectable(
        &self,
        id: ContentId,
    ) -> Result<SelectableDeclaration, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::SelectableDeclaration {
            return Err(integrity("selectable-envelope-shape"));
        }
        let selectable = SelectableDeclaration::from_canonical_bytes(envelope.body())?;
        if selectable.id()?.content_id() != id {
            return Err(integrity("selectable-envelope-shape"));
        }
        Ok(selectable)
    }

    fn read_choice_domain(&self, id: ContentId) -> Result<ChoiceDomain, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ChoiceDomain {
            return Err(integrity("choice-domain-envelope-shape"));
        }
        let domain = ChoiceDomain::from_canonical_bytes(envelope.body())?;
        if domain.id()?.content_id() != id {
            return Err(integrity("choice-domain-envelope-shape"));
        }
        Ok(domain)
    }

    fn validate_opportunity_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(envelope.body())?;
        let declaration = self.read_selectable(required_child(envelope, "declaration")?)?;
        let domain = self.read_choice_domain(required_child(envelope, "domain")?)?;
        opportunity.validate_references(&declaration, &domain)?;
        Ok(())
    }

    fn validate_group_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let group = crate::codec::decode::<ChoiceGroup>(envelope.body())?;
        let mut declarations = BTreeMap::new();
        for id in group.members() {
            declarations.insert(*id, self.read_selectable(id.content_id())?);
        }
        group.validate_declarations(&declarations)?;
        Ok(())
    }

    fn read_group(&self, id: ContentId) -> Result<ChoiceGroup, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::ChoiceGroup)?;
        let group = crate::codec::decode::<ChoiceGroup>(envelope.body())?;
        if group.id()?.content_id() != id {
            return Err(integrity("choice-group-envelope-shape"));
        }
        self.validate_group_references(&envelope)?;
        Ok(group)
    }

    fn read_opportunity(
        &self,
        id: ContentId,
    ) -> Result<ChoiceOpportunity, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ChoiceOpportunity {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(envelope.body())?;
        if opportunity.id()?.content_id() != id {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let declaration = self.read_selectable(opportunity.declaration().content_id())?;
        let domain = self.read_choice_domain(opportunity.domain().content_id())?;
        opportunity.validate_references(&declaration, &domain)?;
        Ok(opportunity)
    }

    fn validate_selection_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let selection = Selection::from_canonical_bytes(envelope.body())?;
        let opportunity = self.read_opportunity(required_child(envelope, "opportunity")?)?;
        let domain = self.read_choice_domain(required_child(envelope, "domain")?)?;
        selection.validate_resolved_references(&opportunity, &domain)?;
        Ok(())
    }

    fn lock_mutation(&self) -> Result<MutexGuard<'_, ()>, CampaignRepositoryError> {
        self.mutation_lock
            .lock()
            .map_err(|_| CampaignRepositoryError::Poisoned)
    }
}

struct LoadedSnapshot {
    envelope: ObjectEnvelope,
    snapshot: CampaignSnapshot,
}

#[derive(Clone, Copy)]
struct ProjectedState {
    visible: CampaignState,
    sealed_prior: Option<CampaignState>,
}

impl ProjectedState {
    const fn new() -> Self {
        Self {
            visible: CampaignState::Created,
            sealed_prior: None,
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
            }
            CampaignControlAction::Pause(_) if state == CampaignState::Running => {
                self.visible = CampaignState::Paused;
            }
            CampaignControlAction::Complete if state != CampaignState::Sealed => {
                self.visible = CampaignState::Completed;
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

fn snapshot_roots(snapshot: &CampaignSnapshot) -> [ContentId; 8] {
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
            | ObjectKind::Projection
    )
}

const fn integrity(reason: &'static str) -> CampaignRepositoryError {
    CampaignRepositoryError::Integrity { reason }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

    use crate::{
        BooleanDomain, BranchBudget, BudgetGrant, CampaignFactId, CampaignMode,
        CampaignPlanningView, CampaignSeed, CandidateGeneratorAlgorithm, ChoiceClassContext,
        ChoiceCoordinate, ChoicePolicy, ChoiceSource, ChoiceValue, ConfigurationId, ExplorerPolicy,
        FairnessPolicy, PlannerEngine, PlanningBudget, ProgressiveWideningPolicy, PuctPolicy,
        RetentionPolicy, ScenarioDefId, StopCondition, WeightedGenerator,
    };

    fn fixture() -> (CampaignRepository, CampaignLineage, CampaignPolicy) {
        let scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", b"scenario"));
        let genesis = ConfigurationId::from_hash(CampaignHash::derive("test", b"genesis"));
        let blobs = Arc::new(MemoryBlobBackend::new("campaign", 64 * 1024 * 1024));
        let refs = Arc::new(MemoryRefBackend::new());
        let repository = CampaignRepository::new(blobs, refs);
        let scenario_content = repository
            .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
            .expect("scenario artifact");
        let genesis_content = repository
            .publish_configuration_artifact(
                scenario,
                scenario_content,
                genesis,
                1,
                b"genesis".to_vec(),
            )
            .expect("genesis artifact");
        let lineage = CampaignLineage::new(
            scenario,
            scenario_content,
            genesis,
            genesis_content,
            "crucible-test",
            "qemu-test",
            BTreeMap::from([("control".to_owned(), 1)]),
            1,
            1,
        )
        .expect("lineage");
        let widening = ProgressiveWideningPolicy::new(
            crate::ExactRational::new(1, 1).expect("rational"),
            crate::ExactRational::new(1, 2).expect("rational"),
            1,
            100,
            1,
        )
        .expect("widening");
        let explorer = ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        };
        let policy = CampaignPolicy::new(
            scenario,
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            explorer,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        )
        .expect("policy");
        (repository, lineage, policy)
    }

    fn command(
        id: &str,
        expected_snapshot: CampaignSnapshotId,
        action: CampaignControlAction,
    ) -> ControlRequest {
        ControlRequest {
            command: crate::CampaignCommandId::from_hash(CampaignHash::derive(
                "test",
                id.as_bytes(),
            )),
            expected_snapshot,
            action,
        }
    }

    fn policy_with_generator(
        scenario: ScenarioDefId,
        generator: CandidateGeneratorSpecId,
    ) -> CampaignPolicy {
        CampaignPolicy::new(
            scenario,
            CampaignSeed::from_bytes([9; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 64,
            },
            BTreeMap::from([(
                "product.recovery".to_owned(),
                ChoicePolicy::new("product.recovery", generator, true).expect("choice policy"),
            )]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        )
        .expect("generator policy")
    }

    fn branch_request(
        repository: &CampaignRepository,
        lineage: &CampaignLineage,
        parent: ConfigurationArtifactId,
        parent_configuration: ConfigurationId,
        command: &str,
    ) -> BranchRequest {
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
        let declaration = SelectableDeclaration::new(
            "product.network.retry",
            ChoiceSource::Workload {
                producer: "network-product".to_owned(),
            },
            domain.clone(),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::from(["network-recovery".to_owned()]))
                .expect("choice class"),
            BTreeSet::new(),
            true,
        )
        .expect("declaration");
        repository
            .publish_choice_domain(&domain)
            .expect("publish domain");
        repository
            .publish_selectable(&declaration)
            .expect("publish declaration");
        let opportunity = ChoiceOpportunity::new(
            lineage.scenario(),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("test", command.as_bytes()),
                producer: CampaignHash::derive("test", b"network-product"),
            },
            command,
            None,
        )
        .expect("opportunity");
        repository
            .publish_choice_opportunity(&opportunity)
            .expect("publish opportunity");

        BranchRequest::new(
            opportunity.branch_point_id(parent_configuration),
            parent,
            opportunity.id().expect("opportunity id"),
            domain.id().expect("domain id"),
            CandidateSource::finite(BTreeSet::from([
                ChoiceValue::Boolean(false),
                ChoiceValue::Boolean(true),
            ]))
            .expect("finite source"),
            BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                CampaignHash::derive("test", command.as_bytes()),
            )),
            BranchBudget::new(2, 2).expect("branch budget"),
            StopCondition::NextChoice,
        )
        .expect("branch request")
    }

    #[test]
    fn create_and_control_form_linear_authenticated_history() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("network-recovery", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        assert_eq!(
            repository.state("network-recovery").expect("state"),
            CampaignState::Created
        );

        let resume = command(
            "resume",
            genesis.snapshot_id(),
            CampaignControlAction::Resume,
        );
        let resumed = repository
            .apply_control("network-recovery", &resume)
            .expect("resume");
        assert_eq!(resumed.prior_snapshot, genesis.snapshot_id());
        assert_eq!(
            repository.state("network-recovery").expect("state"),
            CampaignState::Running
        );

        let pause = command(
            "pause",
            resumed.new_snapshot,
            CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
        );
        let paused = repository
            .apply_control("network-recovery", &pause)
            .expect("pause");
        assert_eq!(
            repository.state("network-recovery").expect("state"),
            CampaignState::Paused
        );
        assert_ne!(paused.new_snapshot, resumed.new_snapshot);
    }

    #[test]
    fn branch_request_is_one_lazy_exact_root_delta_and_replays() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("lazy", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "retry-choice",
        );

        let accepted = repository
            .submit_branch_request("lazy", genesis.snapshot_id(), &request)
            .expect("submit request");
        assert!(!accepted.replayed);
        assert_eq!(accepted.prior_snapshot, genesis.snapshot_id());
        assert_eq!(accepted.request, request.id().expect("request id"));

        let requested = repository.head("lazy").expect("requested head");
        let prior_roots = genesis.snapshot().roots();
        let next_roots = requested.snapshot().roots();
        assert_eq!(prior_roots.graph, next_roots.graph);
        assert_eq!(prior_roots.observations, next_roots.observations);
        assert_eq!(prior_roots.corpus, next_roots.corpus);
        assert_eq!(prior_roots.coverage, next_roots.coverage);
        assert_eq!(prior_roots.findings, next_roots.findings);
        assert_eq!(prior_roots.pins, next_roots.pins);
        assert_eq!(prior_roots.accounting, next_roots.accounting);
        assert_ne!(prior_roots.exploration, next_roots.exploration);
        let entries = repository
            .merkle
            .verify_closure_objects(next_roots.exploration)
            .expect("exploration closure");
        assert_eq!(
            entries.values,
            BTreeSet::from([accepted.request.content_id()])
        );

        let resume = command(
            "resume-after-request",
            accepted.new_snapshot,
            CampaignControlAction::Resume,
        );
        repository.apply_control("lazy", &resume).expect("resume");
        let replay = repository
            .submit_branch_request("lazy", genesis.snapshot_id(), &request)
            .expect("replay request");
        assert!(replay.replayed);
        assert_eq!(replay.prior_snapshot, accepted.prior_snapshot);
        assert_eq!(replay.new_snapshot, accepted.new_snapshot);

        let reused_command = BranchRequest::new(
            request.branch_point(),
            request.parent(),
            request.opportunity(),
            request.domain(),
            CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
                .expect("changed finite source"),
            request.cause(),
            BranchBudget::new(1, 1).expect("changed budget"),
            StopCondition::Terminal,
        )
        .expect("changed request");
        let current = repository.head("lazy").expect("current head");
        assert!(matches!(
            repository.submit_branch_request("lazy", current.snapshot_id(), &reused_command),
            Err(CampaignRepositoryError::CommandReuse)
        ));

        let BranchRequestCause::Operator(command_id) = request.cause() else {
            panic!("operator request")
        };
        let reused_control = ControlRequest {
            command: command_id,
            expected_snapshot: current.snapshot_id(),
            action: CampaignControlAction::Complete,
        };
        assert!(matches!(
            repository.apply_control("lazy", &reused_control),
            Err(CampaignRepositoryError::CommandReuse)
        ));
    }

    #[test]
    fn branch_request_staleness_and_campaign_scope_fail_before_ref_advance() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("scope", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "stale-request",
        );
        let stale = CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            1,
            b"stale-request",
        ))
        .expect("stale id");
        assert!(matches!(
            repository.submit_branch_request("scope", stale, &request),
            Err(CampaignRepositoryError::Stale { .. })
        ));
        assert_eq!(
            repository.head("scope").expect("head").snapshot_id(),
            genesis.snapshot_id()
        );

        let outside_configuration =
            ConfigurationId::from_hash(CampaignHash::derive("test", b"outside-configuration"));
        let outside = repository
            .publish_configuration_artifact(
                lineage.scenario(),
                lineage.scenario_content(),
                outside_configuration,
                1,
                b"outside".to_vec(),
            )
            .expect("outside configuration");
        let outside_request = branch_request(
            &repository,
            &lineage,
            outside,
            outside_configuration,
            "outside-request",
        );
        assert!(matches!(
            repository.submit_branch_request("scope", genesis.snapshot_id(), &outside_request),
            Err(CampaignRepositoryError::Integrity {
                reason: "branch-request-parent-is-not-in-campaign-graph"
            })
        ));
        assert_eq!(
            repository.head("scope").expect("head").snapshot_id(),
            genesis.snapshot_id()
        );
    }

    #[test]
    fn generated_branch_requests_validate_the_complete_domain_compatible_spec() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("generators", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let finite = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "generator-opportunity",
        );
        let integer = CandidateGeneratorSpec::new(
            1,
            CandidateGeneratorAlgorithm::ProgressiveInteger {
                initial_strata: 2,
                feedback_interval: 1,
            },
        )
        .expect("integer generator");
        let integer_id = repository
            .publish_generator(&integer)
            .expect("publish integer generator");
        let incompatible = BranchRequest::new(
            finite.branch_point(),
            finite.parent(),
            finite.opportunity(),
            finite.domain(),
            CandidateSource::generated(integer_id),
            BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                CampaignHash::derive("test", b"incompatible-generator"),
            )),
            BranchBudget::new(2, 2).expect("budget"),
            StopCondition::NextChoice,
        )
        .expect("incompatible request");
        assert!(matches!(
            repository.submit_branch_request("generators", genesis.snapshot_id(), &incompatible,),
            Err(CampaignRepositoryError::Integrity {
                reason: "candidate-generator-domain-family-mismatch"
            })
        ));

        let mixture = CandidateGeneratorSpec::new(
            1,
            CandidateGeneratorAlgorithm::OrderedMixture {
                components: vec![WeightedGenerator::new(integer_id, 1).expect("component")],
            },
        )
        .expect("mixture");
        let mixture_id = repository
            .publish_generator(&mixture)
            .expect("publish mixture");
        let incompatible_mixture = BranchRequest::new(
            finite.branch_point(),
            finite.parent(),
            finite.opportunity(),
            finite.domain(),
            CandidateSource::generated(mixture_id),
            BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                CampaignHash::derive("test", b"incompatible-mixture"),
            )),
            BranchBudget::new(2, 2).expect("budget"),
            StopCondition::NextChoice,
        )
        .expect("mixture request");
        assert!(matches!(
            repository.submit_branch_request(
                "generators",
                genesis.snapshot_id(),
                &incompatible_mixture,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "candidate-generator-domain-family-mismatch"
            })
        ));

        let all = CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All)
            .expect("all generator");
        let all_id = repository
            .publish_generator(&all)
            .expect("publish all generator");
        let valid = BranchRequest::new(
            finite.branch_point(),
            finite.parent(),
            finite.opportunity(),
            finite.domain(),
            CandidateSource::generated(all_id),
            BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                CampaignHash::derive("test", b"valid-generator"),
            )),
            BranchBudget::new(2, 2).expect("budget"),
            StopCondition::NextChoice,
        )
        .expect("valid generated request");
        repository
            .submit_branch_request("generators", genesis.snapshot_id(), &valid)
            .expect("accept compatible generator");
    }

    #[test]
    fn ancestry_rejects_branch_request_with_an_unrelated_root_change() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("forged-request", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "forged-request",
        );
        let request_content = repository
            .put_branch_request(&request)
            .expect("put request");
        let request_id = BranchRequestId::from_content_id(request_content).expect("request id");
        let transition_content = repository
            .put_fact(&CampaignFact::BranchRequestIssued(request_id))
            .expect("put transition");
        let mut roots = genesis.snapshot().roots();
        roots.exploration = repository
            .merkle
            .insert(
                roots.exploration,
                map_key_content("exploration.branch-request", request_content),
                request_content,
            )
            .expect("request root")
            .content_id();
        roots.accounting = repository
            .merkle
            .insert(
                roots.accounting,
                map_key_content("accounting.forged", request_content),
                request_content,
            )
            .expect("forged accounting root")
            .content_id();
        let forged = CampaignSnapshot::successor(
            genesis.snapshot_id(),
            genesis.snapshot().lineage(),
            genesis.snapshot().active_policy(),
            roots,
            CampaignFactId::from_content_id(transition_content).expect("transition id"),
        )
        .expect("forged snapshot");
        let forged_content = repository
            .put_snapshot(&forged)
            .expect("put forged snapshot");

        assert!(matches!(
            repository.validate_complete_head(forged_content),
            Err(CampaignRepositoryError::Integrity {
                reason: "branch-request-transition-changed-unrelated-root"
            })
        ));
    }

    #[test]
    fn imported_ancestry_rejects_cross_type_mutation_command_reuse() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("duplicate-command", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "shared-command",
        );
        let accepted = repository
            .submit_branch_request("duplicate-command", genesis.snapshot_id(), &request)
            .expect("accept request");
        let head = repository.head("duplicate-command").expect("head");
        let BranchRequestCause::Operator(command_id) = request.cause() else {
            panic!("operator request")
        };
        let control = ControlRequest {
            command: command_id,
            expected_snapshot: accepted.new_snapshot,
            action: CampaignControlAction::Resume,
        };
        let transition_content = repository
            .put_fact(&CampaignFact::ControlRequested(control.clone()))
            .expect("put control");
        let mut roots = head.snapshot().roots();
        roots.accounting = repository
            .merkle
            .insert(
                roots.accounting,
                map_key_hash("accounting.command", command_id.as_hash()),
                transition_content,
            )
            .expect("accounting root")
            .content_id();
        let forged = CampaignSnapshot::successor(
            accepted.new_snapshot,
            head.snapshot().lineage(),
            head.snapshot().active_policy(),
            roots,
            CampaignFactId::from_content_id(transition_content).expect("transition id"),
        )
        .expect("forged snapshot");
        let forged_content = repository
            .put_snapshot(&forged)
            .expect("put forged snapshot");
        let campaign_ref = campaign_ref("duplicate-command").expect("campaign ref");
        repository
            .refs
            .compare_exchange(&campaign_ref, Some(head.content_id()), forged_content)
            .expect("forge ref");

        assert!(matches!(
            repository.head("duplicate-command"),
            Err(CampaignRepositoryError::Integrity {
                reason: "snapshot-ancestry-reused-mutation-command"
            })
        ));
    }

    #[test]
    fn command_replay_precedes_stale_check_and_preserves_response() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("test", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let resume = command(
            "resume",
            genesis.snapshot_id(),
            CampaignControlAction::Resume,
        );
        let first = repository.apply_control("test", &resume).expect("resume");
        let pause = command(
            "pause",
            first.new_snapshot,
            CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
        );
        repository.apply_control("test", &pause).expect("pause");

        let replay = repository.apply_control("test", &resume).expect("replay");
        assert!(replay.replayed);
        assert_eq!(replay.prior_snapshot, first.prior_snapshot);
        assert_eq!(replay.new_snapshot, first.new_snapshot);

        let reused = ControlRequest {
            command: resume.command,
            expected_snapshot: resume.expected_snapshot,
            action: CampaignControlAction::Complete,
        };
        assert!(matches!(
            repository.apply_control("test", &reused),
            Err(CampaignRepositoryError::CommandReuse)
        ));
    }

    #[test]
    fn stale_and_invalid_transitions_do_not_advance_head() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("test", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let stale = command(
            "stale",
            CampaignSnapshotId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignSnapshot,
                1,
                b"stale",
            ))
            .expect("stale snapshot id"),
            CampaignControlAction::Resume,
        );
        assert!(matches!(
            repository.apply_control("test", &stale),
            Err(CampaignRepositoryError::Stale { .. })
        ));
        assert_eq!(
            repository.head("test").expect("head").snapshot_id(),
            genesis.snapshot_id()
        );

        let invalid = command(
            "invalid",
            genesis.snapshot_id(),
            CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
        );
        assert!(matches!(
            repository.apply_control("test", &invalid),
            Err(CampaignRepositoryError::InvalidTransition {
                state: CampaignState::Created
            })
        ));
        assert_eq!(
            repository.head("test").expect("head").snapshot_id(),
            genesis.snapshot_id()
        );
    }

    #[test]
    fn nonempty_policy_round_trips_and_missing_generator_fails_before_ref_publication() {
        let (repository, lineage, _) = fixture();
        let generator =
            CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("generator");
        let generator_id = generator.id().expect("generator id");
        let policy = policy_with_generator(lineage.scenario(), generator_id);
        let generators = BTreeMap::from([(generator_id, generator)]);

        let created = repository
            .create("with-generator", &lineage, &policy, &generators)
            .expect("create with generator");
        assert_eq!(
            repository
                .head("with-generator")
                .expect("authenticated head")
                .snapshot_id(),
            created.snapshot_id()
        );

        let missing = CandidateGeneratorSpecId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"missing-generator",
        ))
        .expect("missing generator id");
        let missing_policy = policy_with_generator(lineage.scenario(), missing);
        assert!(matches!(
            repository.create(
                "missing-generator",
                &lineage,
                &missing_policy,
                &BTreeMap::new(),
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "campaign-policy-generator-was-not-supplied"
            })
        ));
        assert!(matches!(
            repository.head("missing-generator"),
            Err(CampaignRepositoryError::NotFound)
        ));
    }

    #[test]
    fn closure_walker_rejects_missing_generator_grandchildren() {
        let (repository, lineage, _) = fixture();
        let missing = CandidateGeneratorSpecId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"missing-mixture-child",
        ))
        .expect("missing child");
        let mixture = CandidateGeneratorSpec::new(
            1,
            CandidateGeneratorAlgorithm::OrderedMixture {
                components: vec![WeightedGenerator::new(missing, 1).expect("weighted child")],
            },
        )
        .expect("mixture");
        let mixture_id = mixture.id().expect("mixture id");
        let policy = policy_with_generator(lineage.scenario(), mixture_id);

        assert!(matches!(
            repository.create(
                "incomplete-closure",
                &lineage,
                &policy,
                &BTreeMap::from([(mixture_id, mixture)]),
            ),
            Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
        ));
        assert!(matches!(
            repository.head("incomplete-closure"),
            Err(CampaignRepositoryError::NotFound)
        ));
    }

    #[test]
    fn head_rejects_a_snapshot_with_missing_parent_and_transition() {
        let (repository, lineage, policy) = fixture();
        let created = repository
            .create("damaged", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let missing_parent = CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            1,
            b"missing-parent",
        ))
        .expect("parent id");
        let missing_transition = crate::CampaignFactId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"missing-transition",
        ))
        .expect("transition id");
        let damaged = CampaignSnapshot::successor(
            missing_parent,
            created.snapshot().lineage(),
            created.snapshot().active_policy(),
            created.snapshot().roots(),
            missing_transition,
        )
        .expect("damaged snapshot");
        let damaged_content = repository.put_snapshot(&damaged).expect("put damaged");
        let campaign_ref = campaign_ref("damaged").expect("campaign ref");
        assert!(matches!(
            repository
                .refs
                .compare_exchange(&campaign_ref, Some(created.content_id()), damaged_content)
                .expect("advance ref"),
            RefCasOutcome::Advanced { .. }
        ));

        assert!(matches!(
            repository.head("damaged"),
            Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
        ));
    }

    #[test]
    fn head_rejects_forged_control_successors_and_noncontrol_transitions() {
        let (repository, lineage, policy) = fixture();
        let created = repository
            .create("forged", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let request = command(
            "forged-resume",
            created.snapshot_id(),
            CampaignControlAction::Resume,
        );
        let transition = CampaignFact::ControlRequested(request.clone());
        let transition_content = repository.put_fact(&transition).expect("put transition");
        let accounting = repository
            .merkle
            .insert(
                created.snapshot().roots().accounting,
                map_key_hash("accounting.command", request.command.as_hash()),
                transition_content,
            )
            .expect("accounting root");
        let mut changed_roots = created.snapshot().roots();
        changed_roots.accounting = accounting.content_id();
        changed_roots.coverage = changed_roots.graph;
        let forged = CampaignSnapshot::successor(
            created.snapshot_id(),
            created.snapshot().lineage(),
            created.snapshot().active_policy(),
            changed_roots,
            CampaignFactId::from_content_id(transition_content).expect("transition id"),
        )
        .expect("forged snapshot");
        let forged_content = repository
            .put_snapshot(&forged)
            .expect("put forged snapshot");
        let forged_ref = campaign_ref("forged").expect("campaign ref");
        repository
            .refs
            .compare_exchange(&forged_ref, Some(created.content_id()), forged_content)
            .expect("advance ref");
        assert!(matches!(
            repository.head("forged"),
            Err(CampaignRepositoryError::Integrity {
                reason: "control-transition-changed-nonaccounting-root"
            })
        ));

        let (repository, lineage, policy) = fixture();
        let created = repository
            .create("noncontrol", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let noncontrol = CampaignFact::BudgetGranted(BudgetGrant::new(1, 0).expect("grant"));
        let transition_content = repository.put_fact(&noncontrol).expect("put fact");
        let forged = CampaignSnapshot::successor(
            created.snapshot_id(),
            created.snapshot().lineage(),
            created.snapshot().active_policy(),
            created.snapshot().roots(),
            CampaignFactId::from_content_id(transition_content).expect("transition id"),
        )
        .expect("forged snapshot");
        let forged_content = repository
            .put_snapshot(&forged)
            .expect("put forged snapshot");
        let noncontrol_ref = campaign_ref("noncontrol").expect("campaign ref");
        repository
            .refs
            .compare_exchange(&noncontrol_ref, Some(created.content_id()), forged_content)
            .expect("advance ref");
        assert!(matches!(
            repository.head("noncontrol"),
            Err(CampaignRepositoryError::Integrity {
                reason: "snapshot-transition-type-is-not-implemented"
            })
        ));
    }

    #[test]
    fn head_rejects_genesis_without_canonical_configuration_membership() {
        let (repository, lineage, policy) = fixture();
        let lineage_content = repository.put_lineage(&lineage).expect("lineage");
        let policy_content = repository.put_policy(&policy).expect("policy");
        let empty = repository.merkle.empty().expect("empty root").content_id();
        let malformed = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(lineage_content).expect("lineage id"),
            CampaignPolicyId::from_content_id(policy_content).expect("policy id"),
            crate::CampaignRoots {
                graph: empty,
                exploration: empty,
                observations: empty,
                corpus: empty,
                coverage: empty,
                findings: empty,
                pins: empty,
                accounting: empty,
            },
        )
        .expect("malformed genesis");
        let content = repository.put_snapshot(&malformed).expect("snapshot");
        let campaign_ref = campaign_ref("missing-genesis").expect("campaign ref");
        repository
            .refs
            .compare_exchange(&campaign_ref, None, content)
            .expect("publish malformed head");
        assert!(matches!(
            repository.head("missing-genesis"),
            Err(CampaignRepositoryError::Integrity {
                reason: "genesis-configuration-root-mismatch"
            })
        ));
    }

    #[test]
    fn imported_lineages_revalidate_scenario_and_configuration_bindings() {
        let (repository, lineage, _) = fixture();
        let other_scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", b"other"));
        let mismatched_lineage = CampaignLineage::new(
            other_scenario,
            lineage.scenario_content(),
            lineage.genesis(),
            lineage.genesis_content(),
            lineage.crucible_version(),
            lineage.qemu_build(),
            lineage.protocol_versions().clone(),
            lineage.scenario_schema(),
            lineage.exact_closure_schema(),
        )
        .expect("structurally valid lineage");
        let content = repository
            .put_lineage(&mismatched_lineage)
            .expect("put mismatched lineage");
        assert!(matches!(
            repository.read_lineage(content),
            Err(CampaignRepositoryError::Integrity {
                reason: "lineage-execution-model-artifact-mismatch"
            })
        ));

        let mismatched_configuration = ConfigurationArtifact::new(
            other_scenario,
            lineage.scenario_content(),
            lineage.genesis(),
            1,
            b"mismatched configuration".to_vec(),
        )
        .expect("configuration");
        let content = repository
            .put_configuration_artifact(&mismatched_configuration)
            .expect("put configuration");
        assert!(matches!(
            repository.read_configuration_artifact(content),
            Err(CampaignRepositoryError::Integrity {
                reason: "configuration-scenario-artifact-mismatch"
            })
        ));
    }

    #[test]
    fn every_reachable_merkle_root_uses_the_owner_validator() {
        let (repository, _, _) = fixture();
        let malformed = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::MerkleNode,
            BTreeSet::new(),
            vec![0],
        )
        .expect("structural malformed node");
        let malformed_content = repository
            .put_envelope(malformed)
            .expect("put malformed node");
        let empty = repository.merkle.empty().expect("empty root").content_id();
        let view =
            CampaignPlanningView::new(malformed_content, empty, empty, empty, empty, empty, empty)
                .expect("planning view");
        let view_envelope = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlanningView,
            crate::object::content_children(view.content_children()).expect("children"),
            view.canonical_bytes(),
        )
        .expect("view envelope");
        let view_content = repository.put_envelope(view_envelope).expect("put view");
        assert!(matches!(
            repository.verify_campaign_closure(view_content),
            Err(CampaignRepositoryError::Merkle(_))
        ));
    }

    #[test]
    fn planner_invocations_bind_artifact_and_state_to_one_engine() {
        let (repository, _, policy) = fixture();
        let engine_a = PlannerEngine::new("engine-a", 1, 1, BTreeSet::new()).expect("engine A");
        let engine_b = PlannerEngine::new("engine-b", 1, 1, BTreeSet::new()).expect("engine B");
        for engine in [&engine_a, &engine_b] {
            repository
                .put_envelope(
                    ObjectEnvelope::for_record(
                        crate::CampaignRecordKind::PlannerEngine,
                        BTreeSet::new(),
                        crate::codec::encode(engine),
                    )
                    .expect("engine envelope"),
                )
                .expect("put engine");
        }

        let dependency_bytes = b"planner dependency".to_vec();
        let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
        repository
            .blobs
            .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
            .expect("put dependency");
        let artifact = PolicyArtifact::new(
            engine_a.id().expect("engine A id"),
            1,
            dependency,
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .expect("artifact");
        repository
            .put_envelope(
                ObjectEnvelope::for_record(
                    crate::CampaignRecordKind::PolicyArtifact,
                    crate::object::content_children(artifact.content_children())
                        .expect("artifact children"),
                    crate::codec::encode(&artifact),
                )
                .expect("artifact envelope"),
            )
            .expect("put artifact");
        let state = PlannerState::new(
            engine_b.id().expect("engine B id"),
            "test-state",
            1,
            Vec::new(),
        )
        .expect("state");
        repository
            .put_envelope(
                ObjectEnvelope::for_record(
                    crate::CampaignRecordKind::PlannerState,
                    crate::object::content_children([("engine", state.engine().content_id())])
                        .expect("state children"),
                    crate::codec::encode(&state),
                )
                .expect("state envelope"),
            )
            .expect("put state");
        repository.put_policy(&policy).expect("put policy");

        let empty = repository.merkle.empty().expect("empty root").content_id();
        let view = CampaignPlanningView::new(empty, empty, empty, empty, empty, empty, empty)
            .expect("view");
        repository
            .put_envelope(
                ObjectEnvelope::for_record(
                    crate::CampaignRecordKind::PlanningView,
                    crate::object::content_children(view.content_children())
                        .expect("view children"),
                    view.canonical_bytes(),
                )
                .expect("view envelope"),
            )
            .expect("put view");
        let invocation = PlannerInvocation::new(
            engine_a.id().expect("engine A id"),
            artifact.id().expect("artifact id"),
            policy.id().expect("policy id"),
            state.id().expect("state id"),
            view.id().expect("view id"),
            PlanningBudget::new(1, 1, 1, 1, 1).expect("budget"),
        )
        .expect("invocation");
        let invocation_content = repository
            .put_envelope(
                ObjectEnvelope::for_record(
                    crate::CampaignRecordKind::PlannerInvocation,
                    crate::object::content_children(invocation.content_children())
                        .expect("invocation children"),
                    crate::codec::encode(&invocation),
                )
                .expect("invocation envelope"),
            )
            .expect("put invocation");
        assert!(matches!(
            repository.verify_campaign_closure(invocation_content),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-invocation-engine-mismatch"
            })
        ));
    }

    #[test]
    fn unowned_fact_reference_families_fail_closed() {
        let (repository, lineage, _) = fixture();
        let lineage_content = repository.put_lineage(&lineage).expect("lineage");
        let asserted_branch_request = crate::BranchRequestId::from_content_id(lineage_content)
            .expect("same broad-kind asserted ID");
        let fact = CampaignFact::BranchRequestIssued(asserted_branch_request);
        let fact_content = repository.put_fact(&fact).expect("put fact");
        assert!(matches!(
            repository.verify_campaign_closure(fact_content),
            Err(CampaignRepositoryError::Integrity {
                reason: "campaign-child-record-kind-mismatch"
            })
        ));
    }
}
