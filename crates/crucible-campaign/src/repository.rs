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
    AdmissionOrdinal, Attempt, AttemptAdmission, AttemptAdmissionId, AttemptAdmissionRole,
    AttemptId, AttemptStart, BranchPath, BranchPathId, BranchRequest, BranchRequestCause,
    BranchRequestId, CampaignCodecError, CampaignControlAction, CampaignFact, CampaignHash,
    CampaignLineage, CampaignLineageId, CampaignPlanningView, CampaignPolicy, CampaignPolicyId,
    CampaignSnapshot, CampaignSnapshotId, CampaignState, CandidateGeneratorAlgorithm,
    CandidateGeneratorSpec, CandidateGeneratorSpecId, CandidateSource, ChoiceDomain,
    ChoiceDomainId, ChoiceGroup, ChoiceGroupId, ChoiceOpportunity, ChoiceOpportunityId,
    ConfigurationArtifact, ConfigurationArtifactId, ConfigurationId, ControlRequest,
    ExpansionState, ExpansionStateId, MerkleMap, MerkleMapRoot, ObjectEnvelope, PlannerDisposition,
    PlannerEngine, PlannerInvocation, PlannerInvocationId, PlannerProposalDisposition,
    PlannerState, PlannerStep, PlannerStepId, PlannerStepProposal, PlanningAccounting,
    PlanningBudget, PlanningScanPage, PlanningScanPosition, PlanningUsage, PolicyActivation,
    PolicyArtifact, Proposal, ProposalId, ScenarioArtifact, ScenarioArtifactId, ScenarioDefId,
    SelectableDeclaration, SelectableId, Selection, SelectionId,
};

const MAX_ENVELOPE_BYTES: u64 = crate::codec::MAX_CANONICAL_BYTES as u64;
const MAX_SNAPSHOT_ANCESTRY: usize = 100_000;
const MAX_CLOSURE_OBJECTS: usize = 1_000_000;
const PLANNER_SCAN_STORAGE_PAGE_ITEMS: usize = 10_000;

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

mod ancestry;
mod closure;
mod projection;
mod records;
mod transactions;

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

fn planner_step_key(step: PlannerStepId) -> CampaignHash {
    map_key_content("coordination.planner-step", step.content_id())
}

fn planner_invocation_result_key(invocation: PlannerInvocationId) -> CampaignHash {
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
        ChoiceCoordinate, ChoicePolicy, ChoiceSource, ChoiceValue, ConfigurationId,
        ContinuationState, ExplorerPolicy, FairnessPolicy, GuidanceEvidence, PlannerEngine,
        PlannerProposalDisposition, PlannerState, PlannerStepProposal, PlanningBudget,
        PlanningUsage, PolicyArtifact, ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy,
        ScenarioDefId, StopCondition, WeightedGenerator,
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

    fn finite_proposal(
        request: &BranchRequest,
        policy: &CampaignPolicy,
        head: &CampaignHead,
        value: ChoiceValue,
        ordinal: u64,
    ) -> Proposal {
        Proposal::new(
            request.branch_point(),
            request.id().expect("request id"),
            request.domain(),
            value,
            policy.id().expect("policy id"),
            None,
            ordinal,
            head.snapshot().planning_view().id().expect("planning view"),
        )
        .expect("proposal")
    }

    fn branch_attempt(
        repository: &CampaignRepository,
        request: &BranchRequest,
        proposal: &Proposal,
    ) -> (Selection, BranchPath, Attempt) {
        let opportunity = repository
            .load_choice_opportunity(request.opportunity())
            .expect("opportunity");
        let domain = repository
            .load_choice_domain(request.domain())
            .expect("domain");
        let selection = Selection::new_campaign_branch(
            &opportunity,
            &domain,
            proposal.value().clone(),
            request.branch_point(),
        )
        .expect("branch selection");
        let crate::SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
            panic!("campaign branch selection")
        };
        let path = BranchPath::new(vec![edge]).expect("branch path");
        let attempt = Attempt::new(
            AttemptStart::Branch {
                edge,
                parent: request.parent(),
                selection: selection.id().expect("selection id"),
            },
            path.id().expect("path id"),
            request.stop().clone(),
        )
        .expect("attempt");
        (selection, path, attempt)
    }

    fn planner_basis(
        repository: &CampaignRepository,
        name: &str,
        snapshot: CampaignSnapshotId,
        state: PlannerState,
    ) -> (PlannerEngine, PolicyArtifact, PlannerInvocation) {
        planner_basis_with_page(repository, name, snapshot, state, None, 16)
    }

    fn planner_basis_with_page(
        repository: &CampaignRepository,
        name: &str,
        snapshot: CampaignSnapshotId,
        state: PlannerState,
        scan_after: Option<PlanningScanPosition>,
        scan_limit: u32,
    ) -> (PlannerEngine, PolicyArtifact, PlannerInvocation) {
        let engine =
            PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
        assert_eq!(state.engine(), engine.id().expect("engine id"));
        let dependency_bytes = b"closed planner dependency".to_vec();
        let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
        repository
            .blobs
            .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
            .expect("planner dependency");
        let artifact = PolicyArtifact::new(
            engine.id().expect("engine id"),
            1,
            dependency,
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .expect("planner artifact");
        let invocation = repository
            .prepare_planner_invocation(
                name,
                snapshot,
                &engine,
                &artifact,
                &state,
                scan_after,
                scan_limit,
                PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
            )
            .expect("prepare planner invocation");
        (engine, artifact, invocation)
    }

    fn no_work_proposal(
        invocation: PlannerInvocationId,
        next_state: PlannerState,
    ) -> PlannerStepProposal {
        PlannerStepProposal::new(
            invocation,
            next_state,
            PlanningUsage {
                branch_requests: 0,
                proposals: 0,
                input_objects: 8,
                input_bytes: 512,
                fuel: 4,
            },
            GuidanceEvidence::new(BTreeMap::from([("score".to_owned(), 1000)]))
                .expect("planner evidence"),
            PlannerProposalDisposition::NoWork,
        )
        .expect("no-work proposal")
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
    fn planner_no_work_is_owned_replayable_and_state_continuous() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("planner-owner", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let engine =
            PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
        let initial_state = PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![0],
        )
        .expect("initial state");
        let (engine, artifact, invocation) = planner_basis(
            &repository,
            "planner-owner",
            genesis.snapshot_id(),
            initial_state,
        );
        let next_state = PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![1],
        )
        .expect("next state");
        let proposal =
            no_work_proposal(invocation.id().expect("invocation id"), next_state.clone());
        let measured = PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: 0,
            input_bytes: 0,
            fuel: 5,
        };
        let accepted = repository
            .accept_planner_step("planner-owner", genesis.snapshot_id(), &proposal, measured)
            .expect("accept planner step");
        assert!(!accepted.replayed);
        let step = repository
            .load_planner_step(accepted.step)
            .expect("load accepted step");
        assert_eq!(step.parent(), None);
        assert_eq!(step.usage_claim(), proposal.usage_claim());
        assert_eq!(step.accounting().input_objects, measured.input_objects);
        assert_eq!(step.accounting().input_bytes, measured.input_bytes);
        assert_eq!(step.accounting().fuel, measured.fuel);

        let accepted_head = repository.head("planner-owner").expect("accepted head");
        assert_eq!(
            accepted_head
                .snapshot()
                .planning_view()
                .id()
                .expect("accepted planning view"),
            invocation.input_view()
        );
        assert_eq!(
            repository
                .merkle
                .inspect_shallow(accepted_head.snapshot().roots().coordination)
                .expect("planner coordination root")
                .entry_count(),
            3
        );
        let replay = repository
            .accept_planner_step("planner-owner", genesis.snapshot_id(), &proposal, measured)
            .expect("replay planner step");
        assert!(replay.replayed);
        assert_eq!(replay.step, accepted.step);
        assert_eq!(replay.new_snapshot, accepted.new_snapshot);

        let conflicting = no_work_proposal(
            invocation.id().expect("invocation id"),
            PlannerState::new(
                engine.id().expect("engine id"),
                "closed-rust-state",
                1,
                vec![9],
            )
            .expect("conflicting state"),
        );
        assert!(matches!(
            repository.accept_planner_step(
                "planner-owner",
                genesis.snapshot_id(),
                &conflicting,
                measured,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-invocation-result-conflict"
            })
        ));
        let oversized = PlanningUsage {
            input_bytes: 8193,
            ..measured
        };
        assert!(matches!(
            repository.accept_planner_step(
                "planner-owner",
                genesis.snapshot_id(),
                &proposal,
                oversized,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-step-invocation-budget-exceeded"
            })
        ));

        let request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "planner-state-continuity",
        );
        let requested = repository
            .submit_branch_request("planner-owner", accepted.new_snapshot, &request)
            .expect("submit intervening request");
        let wrong_input_state = PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![99],
        )
        .expect("wrong input state");
        assert!(matches!(
            repository.prepare_planner_invocation(
                "planner-owner",
                requested.new_snapshot,
                &engine,
                &artifact,
                &wrong_input_state,
                None,
                16,
                PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-step-parent-state-discontinuity"
            })
        ));

        let (_, _, next_invocation) = planner_basis(
            &repository,
            "planner-owner",
            requested.new_snapshot,
            next_state.clone(),
        );
        assert_eq!(
            next_invocation.policy_artifact(),
            artifact.id().expect("artifact id")
        );
        let final_state = PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![2],
        )
        .expect("final state");
        let second_proposal = no_work_proposal(
            next_invocation.id().expect("next invocation id"),
            final_state.clone(),
        );
        let second_measured = PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: next_invocation.scan_page().input_objects(),
            input_bytes: next_invocation.scan_page().input_bytes(),
            fuel: measured.fuel,
        };
        let second = repository
            .accept_planner_step(
                "planner-owner",
                requested.new_snapshot,
                &second_proposal,
                second_measured,
            )
            .expect("second planner step");
        assert_eq!(
            repository
                .load_planner_step(second.step)
                .expect("second step")
                .parent(),
            Some(accepted.step)
        );

        let missing_invocation = PlannerInvocationId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            2,
            b"missing parent invocation",
        ))
        .expect("missing invocation id");
        let accepted_accounting = PlanningAccounting {
            branch_requests: 0,
            proposals: 0,
            attempts: 0,
            deduplicated: 0,
            input_objects: second_measured.input_objects,
            input_bytes: second_measured.input_bytes,
            fuel: second_measured.fuel,
        };
        let incomplete_parent = PlannerStep::new(
            None,
            missing_invocation,
            next_invocation.policy(),
            next_invocation.engine(),
            next_invocation.policy_artifact(),
            next_invocation.input_view(),
            PlannerDisposition::NoWork,
            next_invocation.planner_state(),
            second_proposal.usage_claim(),
            accepted_accounting,
            second_proposal.explanation().clone(),
        )
        .expect("incomplete parent");
        let incomplete_parent_content = repository
            .put_planner_step(&incomplete_parent)
            .expect("put incomplete parent");
        let incomplete_parent_id =
            PlannerStepId::from_content_id(incomplete_parent_content).expect("parent id");
        let child = PlannerStep::new(
            Some(incomplete_parent_id),
            next_invocation.id().expect("next invocation id"),
            next_invocation.policy(),
            next_invocation.engine(),
            next_invocation.policy_artifact(),
            next_invocation.input_view(),
            PlannerDisposition::NoWork,
            final_state.id().expect("final state id"),
            second_proposal.usage_claim(),
            accepted_accounting,
            second_proposal.explanation().clone(),
        )
        .expect("child step");
        let child_content = repository.put_planner_step(&child).expect("put child");
        let child_id = PlannerStepId::from_content_id(child_content).expect("child id");
        assert!(matches!(
            repository.load_planner_step(child_id),
            Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
        ));
    }

    #[test]
    fn planner_scan_results_are_bound_to_exact_served_pages() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("planner-pages", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let first_request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "first-planner-page-request",
        );
        let first = repository
            .submit_branch_request("planner-pages", genesis.snapshot_id(), &first_request)
            .expect("first request");
        let second_request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "second-planner-page-request",
        );
        let second = repository
            .submit_branch_request("planner-pages", first.new_snapshot, &second_request)
            .expect("second request");

        let mut expected_positions = [
            PlanningScanPosition::new(
                first_request.branch_point(),
                first_request.id().expect("first request id"),
            ),
            PlanningScanPosition::new(
                second_request.branch_point(),
                second_request.id().expect("second request id"),
            ),
        ];
        expected_positions.sort();
        let engine =
            PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
        let initial_state = PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![0],
        )
        .expect("initial state");
        let (engine, artifact, invocation) = planner_basis_with_page(
            &repository,
            "planner-pages",
            second.new_snapshot,
            initial_state.clone(),
            None,
            1,
        );
        assert_eq!(invocation.scan_page().positions(), &expected_positions[..1]);
        assert!(!invocation.scan_page().complete());
        assert!(matches!(
            repository.prepare_planner_invocation(
                "planner-pages",
                second.new_snapshot,
                &engine,
                &artifact,
                &initial_state,
                Some(expected_positions[0]),
                1,
                PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-invocation-scan-start-mismatch"
            })
        ));
        let measured = PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: invocation.scan_page().input_objects(),
            input_bytes: invocation.scan_page().input_bytes(),
            fuel: 1,
        };
        let next_state = PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![1],
        )
        .expect("next state");
        repository
            .put_planner_state(&next_state)
            .expect("put forged-step state");
        let false_eof_page = PlanningScanPage::new(
            None,
            invocation.scan_page().limit(),
            invocation.scan_page().positions().to_vec(),
            true,
            invocation.scan_page().input_bytes(),
        )
        .expect("false EOF page");
        let false_eof_invocation = PlannerInvocation::new(
            invocation.engine(),
            invocation.policy_artifact(),
            invocation.policy(),
            invocation.planner_state(),
            invocation.input_view(),
            false_eof_page,
            invocation.budget(),
        )
        .expect("false EOF invocation");
        repository
            .put_planner_invocation(&false_eof_invocation)
            .expect("put false EOF invocation");
        let false_eof_accounting = PlanningAccounting {
            branch_requests: 0,
            proposals: 0,
            attempts: 0,
            deduplicated: 0,
            input_objects: false_eof_invocation.scan_page().input_objects(),
            input_bytes: false_eof_invocation.scan_page().input_bytes(),
            fuel: 1,
        };
        let false_eof_step = PlannerStep::new(
            None,
            false_eof_invocation.id().expect("false EOF invocation id"),
            false_eof_invocation.policy(),
            false_eof_invocation.engine(),
            false_eof_invocation.policy_artifact(),
            false_eof_invocation.input_view(),
            PlannerDisposition::NoWork,
            next_state.id().expect("next state id"),
            measured,
            false_eof_accounting,
            GuidanceEvidence::new(BTreeMap::new()).expect("false EOF evidence"),
        )
        .expect("false EOF step");
        let false_eof_step_content = repository
            .put_planner_step(&false_eof_step)
            .expect("put false EOF step");
        assert!(matches!(
            repository.load_planner_step(
                PlannerStepId::from_content_id(false_eof_step_content).expect("false EOF step id"),
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-invocation-scan-page-mismatch"
            })
        ));
        let jump = PlannerStepProposal::new(
            invocation.id().expect("invocation id"),
            next_state.clone(),
            measured,
            GuidanceEvidence::new(BTreeMap::new()).expect("jump evidence"),
            PlannerProposalDisposition::ContinueScan {
                cursor: crate::PlanningScanCursor::new(
                    invocation.input_view(),
                    Some(expected_positions[1]),
                ),
            },
        )
        .expect("jump proposal");
        assert!(matches!(
            repository.accept_planner_step("planner-pages", second.new_snapshot, &jump, measured,),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-step-disposition-does-not-match-served-page"
            })
        ));

        let false_eof =
            no_work_proposal(invocation.id().expect("invocation id"), next_state.clone());
        assert!(matches!(
            repository.accept_planner_step(
                "planner-pages",
                second.new_snapshot,
                &false_eof,
                measured,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-step-disposition-does-not-match-served-page"
            })
        ));

        let continuation = PlannerStepProposal::new(
            invocation.id().expect("invocation id"),
            next_state.clone(),
            measured,
            GuidanceEvidence::new(BTreeMap::new()).expect("continuation evidence"),
            PlannerProposalDisposition::ContinueScan {
                cursor: crate::PlanningScanCursor::new(
                    invocation.input_view(),
                    Some(expected_positions[0]),
                ),
            },
        )
        .expect("continuation proposal");
        let continued = repository
            .accept_planner_step(
                "planner-pages",
                second.new_snapshot,
                &continuation,
                measured,
            )
            .expect("accept continuation");
        let next_invocation = repository
            .prepare_planner_invocation(
                "planner-pages",
                continued.new_snapshot,
                &engine,
                &artifact,
                &next_state,
                Some(expected_positions[0]),
                1,
                PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
            )
            .expect("prepare final page");
        assert_eq!(
            next_invocation.scan_page().positions(),
            &expected_positions[1..]
        );
        assert!(next_invocation.scan_page().complete());
        let final_measured = PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: next_invocation.scan_page().input_objects(),
            input_bytes: next_invocation.scan_page().input_bytes(),
            fuel: 1,
        };
        let done = no_work_proposal(
            next_invocation.id().expect("next invocation id"),
            PlannerState::new(
                engine.id().expect("engine id"),
                "closed-rust-state",
                1,
                vec![2],
            )
            .expect("done state"),
        );
        let finished = repository
            .accept_planner_step(
                "planner-pages",
                continued.new_snapshot,
                &done,
                final_measured,
            )
            .expect("accept EOF");
        assert!(matches!(
            repository.prepare_planner_invocation(
                "planner-pages",
                finished.new_snapshot,
                &engine,
                &artifact,
                done.next_state(),
                None,
                1,
                PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-invocation-reopens-complete-view"
            })
        ));
    }

    #[test]
    fn planner_cursor_and_imported_root_fail_closed() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("planner-forgery", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let engine =
            PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
        let initial_state = PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![0],
        )
        .expect("initial state");
        let (engine, _, invocation) = planner_basis(
            &repository,
            "planner-forgery",
            genesis.snapshot_id(),
            initial_state,
        );
        let fabricated_source = BranchRequestId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"fabricated planner cursor",
        ))
        .expect("fabricated source");
        let cursor_proposal = PlannerStepProposal::new(
            invocation.id().expect("invocation id"),
            PlannerState::new(
                engine.id().expect("engine id"),
                "closed-rust-state",
                1,
                vec![1],
            )
            .expect("next state"),
            PlanningUsage {
                branch_requests: 0,
                proposals: 0,
                input_objects: 1,
                input_bytes: 1,
                fuel: 1,
            },
            GuidanceEvidence::new(BTreeMap::new()).expect("cursor evidence"),
            PlannerProposalDisposition::ContinueScan {
                cursor: crate::PlanningScanCursor::new(
                    invocation.input_view(),
                    Some(crate::PlanningScanPosition::new(
                        crate::BranchPointId::from_hash(CampaignHash::derive(
                            "test",
                            b"fabricated branch point",
                        )),
                        fabricated_source,
                    )),
                ),
            },
        )
        .expect("cursor proposal");
        let measured = PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: 0,
            input_bytes: 0,
            fuel: 1,
        };
        assert!(matches!(
            repository.accept_planner_step(
                "planner-forgery",
                genesis.snapshot_id(),
                &cursor_proposal,
                measured,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-step-scan-cursor-is-not-authoritative"
            })
        ));

        let accepted_proposal = no_work_proposal(
            invocation.id().expect("invocation id"),
            cursor_proposal.next_state().clone(),
        );
        let accepted = repository
            .accept_planner_step(
                "planner-forgery",
                genesis.snapshot_id(),
                &accepted_proposal,
                measured,
            )
            .expect("accept no-work step");
        let accepted_head = repository.head("planner-forgery").expect("accepted head");
        let extra_key = CampaignHash::derive("test", b"forged planner index");
        let forged_coordination = repository
            .merkle
            .insert(
                accepted_head.snapshot().roots().coordination,
                extra_key,
                accepted.step.content_id(),
            )
            .expect("forged root")
            .content_id();
        let mut forged_roots = accepted_head.snapshot().roots();
        forged_roots.coordination = forged_coordination;
        let transition = repository
            .put_fact(&CampaignFact::PlannerAdvanced(accepted.step))
            .expect("planner fact");
        let forged = CampaignSnapshot::successor(
            genesis.snapshot_id(),
            genesis.snapshot().lineage(),
            genesis.snapshot().active_policy(),
            forged_roots,
            CampaignFactId::from_content_id(transition).expect("fact id"),
        )
        .expect("forged snapshot");
        let forged_content = repository
            .put_snapshot(&forged)
            .expect("put forged snapshot");
        assert!(matches!(
            repository.validate_complete_head(forged_content),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-step-transition-coordination-root-mismatch"
            })
        ));
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
    fn finite_proposal_is_an_exact_indexed_delta_and_replays_before_staleness() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("finite-proposal", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "finite-proposal",
        );
        let requested = repository
            .submit_branch_request("finite-proposal", genesis.snapshot_id(), &request)
            .expect("submit request");
        let request_head = repository.head("finite-proposal").expect("request head");

        let wrong_order = finite_proposal(
            &request,
            &policy,
            &request_head,
            ChoiceValue::Boolean(true),
            1,
        );
        assert!(matches!(
            repository.issue_proposal("finite-proposal", requested.new_snapshot, &wrong_order,),
            Err(CampaignRepositoryError::Integrity {
                reason: "proposal-value-does-not-match-finite-source-order"
            })
        ));

        let first = finite_proposal(
            &request,
            &policy,
            &request_head,
            ChoiceValue::Boolean(false),
            1,
        );
        let accepted = repository
            .issue_proposal("finite-proposal", requested.new_snapshot, &first)
            .expect("issue proposal");
        assert!(!accepted.replayed);
        assert_eq!(accepted.proposal, first.id().expect("proposal id"));
        assert_eq!(
            repository
                .load_proposal(accepted.proposal)
                .expect("load proposal"),
            first
        );

        let proposal_head = repository.head("finite-proposal").expect("proposal head");
        let prior = request_head.snapshot().roots();
        let next = proposal_head.snapshot().roots();
        assert_ne!(prior.exploration, next.exploration);
        assert_eq!(prior.graph, next.graph);
        assert_eq!(prior.observations, next.observations);
        assert_eq!(prior.corpus, next.corpus);
        assert_eq!(prior.coverage, next.coverage);
        assert_eq!(prior.findings, next.findings);
        assert_eq!(prior.pins, next.pins);
        assert_eq!(prior.accounting, next.accounting);
        assert_eq!(
            repository
                .merkle
                .inspect_shallow(next.exploration)
                .expect("exploration root")
                .entry_count(),
            4
        );

        let replay = repository
            .issue_proposal("finite-proposal", genesis.snapshot_id(), &first)
            .expect("replay proposal");
        assert!(replay.replayed);
        assert_eq!(replay.prior_snapshot, accepted.prior_snapshot);
        assert_eq!(replay.new_snapshot, accepted.new_snapshot);
    }

    #[test]
    fn attempt_admission_assigns_one_basis_and_deduplicates_later_causes() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("admission", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "admission-first",
        );
        let requested = repository
            .submit_branch_request("admission", genesis.snapshot_id(), &request)
            .expect("request");
        let request_head = repository.head("admission").expect("request head");
        let proposal = finite_proposal(
            &request,
            &policy,
            &request_head,
            ChoiceValue::Boolean(false),
            1,
        );
        let proposed = repository
            .issue_proposal("admission", requested.new_snapshot, &proposal)
            .expect("proposal");
        let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
        let admitted = repository
            .admit_proposal(
                "admission",
                proposed.new_snapshot,
                proposed.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admission");
        assert!(!admitted.replayed);
        let basis = repository
            .load_attempt_admission(admitted.admission)
            .expect("basis");
        assert_eq!(
            basis.role(),
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposed.proposal),
                cause: request.cause(),
                admission_ordinal: AdmissionOrdinal::new(1),
            }
        );
        let basis_head = repository.head("admission").expect("basis head");
        assert_eq!(
            repository
                .merkle
                .inspect_shallow(basis_head.snapshot().roots().accounting)
                .expect("accounting root")
                .entry_count(),
            6
        );

        let valid_admission_snapshot = repository
            .read_snapshot(admitted.new_snapshot.content_id())
            .expect("valid admission snapshot");
        let mut forged_roots = valid_admission_snapshot.snapshot.roots();
        forged_roots.accounting = repository
            .merkle
            .insert(
                forged_roots.accounting,
                map_key_content("accounting.forged", admitted.admission.content_id()),
                admitted.admission.content_id(),
            )
            .expect("forged accounting root")
            .content_id();
        let forged = CampaignSnapshot::successor(
            valid_admission_snapshot
                .snapshot
                .parent()
                .expect("admission parent"),
            valid_admission_snapshot.snapshot.lineage(),
            valid_admission_snapshot.snapshot.active_policy(),
            forged_roots,
            valid_admission_snapshot
                .snapshot
                .transition()
                .expect("admission transition"),
        )
        .expect("forged admission successor");
        let forged_content = repository
            .put_snapshot(&forged)
            .expect("put forged admission successor");
        assert!(matches!(
            repository.validate_complete_head(forged_content),
            Err(CampaignRepositoryError::Integrity {
                reason: "attempt-admission-transition-accounting-root-mismatch"
            })
        ));

        let replay = repository
            .admit_proposal(
                "admission",
                genesis.snapshot_id(),
                proposed.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("replay admission");
        assert!(replay.replayed);
        assert_eq!(replay.new_snapshot, admitted.new_snapshot);
        let wrong_path = BranchPath::new(Vec::new()).expect("wrong path");
        assert!(matches!(
            repository.admit_proposal(
                "admission",
                genesis.snapshot_id(),
                proposed.proposal,
                &selection,
                &wrong_path,
                &attempt,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "proposal-admission-input-closure-mismatch"
            })
        ));

        let second_proposal = finite_proposal(
            &request,
            &policy,
            &basis_head,
            ChoiceValue::Boolean(true),
            2,
        );
        let second_proposed = repository
            .issue_proposal("admission", basis_head.snapshot_id(), &second_proposal)
            .expect("second proposal");
        let (second_selection, second_path, second_attempt) =
            branch_attempt(&repository, &request, &second_proposal);
        let second_admitted = repository
            .admit_proposal(
                "admission",
                second_proposed.new_snapshot,
                second_proposed.proposal,
                &second_selection,
                &second_path,
                &second_attempt,
            )
            .expect("second admission");
        assert_eq!(
            repository
                .load_attempt_admission(second_admitted.admission)
                .expect("second basis")
                .role(),
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(second_proposed.proposal),
                cause: request.cause(),
                admission_ordinal: AdmissionOrdinal::new(2),
            }
        );
        let second_head = repository.head("admission").expect("second head");
        assert_eq!(
            repository
                .merkle
                .inspect_shallow(second_head.snapshot().roots().accounting)
                .expect("second accounting root")
                .entry_count(),
            11
        );

        let duplicate_request = BranchRequest::new(
            request.branch_point(),
            request.parent(),
            request.opportunity(),
            request.domain(),
            request.source().clone(),
            BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                CampaignHash::derive("test", b"admission-duplicate"),
            )),
            request.budget(),
            request.stop().clone(),
        )
        .expect("duplicate request");
        let duplicate_requested = repository
            .submit_branch_request("admission", second_head.snapshot_id(), &duplicate_request)
            .expect("duplicate request transition");
        let duplicate_request_head = repository
            .head("admission")
            .expect("duplicate request head");
        let duplicate_proposal = finite_proposal(
            &duplicate_request,
            &policy,
            &duplicate_request_head,
            ChoiceValue::Boolean(false),
            1,
        );
        let duplicate_proposed = repository
            .issue_proposal(
                "admission",
                duplicate_requested.new_snapshot,
                &duplicate_proposal,
            )
            .expect("duplicate proposal");
        let (duplicate_selection, duplicate_path, duplicate_attempt) =
            branch_attempt(&repository, &duplicate_request, &duplicate_proposal);
        assert_eq!(
            duplicate_attempt.id().expect("duplicate attempt id"),
            admitted.attempt
        );
        let deduplicated = repository
            .admit_proposal(
                "admission",
                duplicate_proposed.new_snapshot,
                duplicate_proposed.proposal,
                &duplicate_selection,
                &duplicate_path,
                &duplicate_attempt,
            )
            .expect("deduplicated admission");
        assert_eq!(
            repository
                .load_attempt_admission(deduplicated.admission)
                .expect("additional cause")
                .role(),
            AttemptAdmissionRole::AdditionalCause {
                proposal: duplicate_proposed.proposal,
            }
        );
        let deduplicated_head = repository.head("admission").expect("deduplicated head");
        assert_eq!(
            repository
                .merkle
                .inspect_shallow(deduplicated_head.snapshot().roots().accounting)
                .expect("deduplicated accounting root")
                .entry_count(),
            13
        );
        assert_eq!(
            repository
                .merkle
                .get(
                    deduplicated_head.snapshot().roots().accounting,
                    admission_sequence_key(),
                )
                .expect("sequence lookup"),
            Some(second_admitted.admission.content_id())
        );
    }

    #[test]
    fn attempt_admission_enforces_request_budget_without_materializing_accounting() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("admission-budget", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let base = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "admission-budget",
        );
        let request = BranchRequest::new(
            base.branch_point(),
            base.parent(),
            base.opportunity(),
            base.domain(),
            base.source().clone(),
            base.cause(),
            BranchBudget::new(2, 1).expect("limited budget"),
            base.stop().clone(),
        )
        .expect("limited request");
        let requested = repository
            .submit_branch_request("admission-budget", genesis.snapshot_id(), &request)
            .expect("request");
        let request_head = repository.head("admission-budget").expect("request head");
        let first = finite_proposal(
            &request,
            &policy,
            &request_head,
            ChoiceValue::Boolean(false),
            1,
        );
        let first_proposed = repository
            .issue_proposal("admission-budget", requested.new_snapshot, &first)
            .expect("first proposal");
        let (first_selection, first_path, first_attempt) =
            branch_attempt(&repository, &request, &first);
        repository
            .admit_proposal(
                "admission-budget",
                first_proposed.new_snapshot,
                first_proposed.proposal,
                &first_selection,
                &first_path,
                &first_attempt,
            )
            .expect("first admission");

        let first_head = repository.head("admission-budget").expect("first head");
        let second = finite_proposal(
            &request,
            &policy,
            &first_head,
            ChoiceValue::Boolean(true),
            2,
        );
        let second_proposed = repository
            .issue_proposal("admission-budget", first_head.snapshot_id(), &second)
            .expect("second proposal");
        let (second_selection, second_path, second_attempt) =
            branch_attempt(&repository, &request, &second);
        assert!(matches!(
            repository.admit_proposal(
                "admission-budget",
                second_proposed.new_snapshot,
                second_proposed.proposal,
                &second_selection,
                &second_path,
                &second_attempt,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "branch-request-attempt-budget-exhausted"
            })
        ));
        assert_eq!(
            repository
                .head("admission-budget")
                .expect("unchanged head")
                .snapshot_id(),
            second_proposed.new_snapshot
        );
    }

    #[test]
    fn finite_expansion_pages_are_snapshot_bound_admission_backed_and_owner_recomputed() {
        let (repository, lineage, policy) = fixture();
        let genesis = repository
            .create("finite-expansion", &lineage, &policy, &BTreeMap::new())
            .expect("create");
        let first_request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "finite-expansion",
        );
        let first_requested = repository
            .submit_branch_request("finite-expansion", genesis.snapshot_id(), &first_request)
            .expect("first request");
        let second_request = BranchRequest::new(
            first_request.branch_point(),
            first_request.parent(),
            first_request.opportunity(),
            first_request.domain(),
            first_request.source().clone(),
            BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                CampaignHash::derive("test", b"finite-expansion-second"),
            )),
            first_request.budget(),
            first_request.stop().clone(),
        )
        .expect("second request");
        let second_requested = repository
            .submit_branch_request(
                "finite-expansion",
                first_requested.new_snapshot,
                &second_request,
            )
            .expect("second request transition");

        let first_page_id = repository
            .project_finite_expansion(
                second_requested.new_snapshot,
                first_request.branch_point(),
                None,
                1,
            )
            .expect("first projection page");
        let first_page = repository
            .load_expansion_state(first_page_id)
            .expect("load first page");
        assert_eq!(first_page.continuations().len(), 1);
        assert_eq!(
            first_page
                .continuations()
                .values()
                .copied()
                .collect::<Vec<_>>(),
            vec![ContinuationState::Ready]
        );
        assert_eq!(
            repository
                .merkle
                .inspect_shallow(first_page.request_root())
                .expect("request projection root")
                .entry_count(),
            2
        );
        let cursor = first_page.next_after().expect("second page cursor");
        assert_eq!(
            first_page
                .continuations()
                .last_key_value()
                .map(|entry| *entry.0),
            Some(cursor)
        );

        let second_page_id = repository
            .project_finite_expansion(
                second_requested.new_snapshot,
                first_request.branch_point(),
                Some(cursor),
                1,
            )
            .expect("second projection page");
        let second_page = repository
            .load_expansion_state(second_page_id)
            .expect("load second page");
        assert_eq!(second_page.continuations().len(), 1);
        assert_eq!(second_page.next_after(), None);
        assert_eq!(first_page.request_root(), second_page.request_root());
        let whole_page_id = repository
            .project_finite_expansion(
                second_requested.new_snapshot,
                first_request.branch_point(),
                None,
                10,
            )
            .expect("whole projection page");
        let whole_page = repository
            .load_expansion_state(whole_page_id)
            .expect("load whole page");
        let paged_requests = first_page
            .continuations()
            .keys()
            .chain(second_page.continuations().keys())
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            paged_requests,
            whole_page
                .continuations()
                .keys()
                .copied()
                .collect::<Vec<_>>()
        );
        assert_ne!(
            first_page
                .continuations()
                .first_key_value()
                .map(|entry| *entry.0),
            second_page
                .continuations()
                .first_key_value()
                .map(|entry| *entry.0)
        );

        let foreign = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            "finite-expansion-foreign",
        );
        assert!(matches!(
            repository.project_finite_expansion(
                second_requested.new_snapshot,
                first_request.branch_point(),
                Some(foreign.id().expect("foreign request id")),
                1,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "expansion-page-cursor-is-not-in-request-root"
            })
        ));

        let request_head = repository.head("finite-expansion").expect("request head");
        let first_proposal = finite_proposal(
            &first_request,
            &policy,
            &request_head,
            ChoiceValue::Boolean(false),
            1,
        );
        let first_proposed = repository
            .issue_proposal(
                "finite-expansion",
                request_head.snapshot_id(),
                &first_proposal,
            )
            .expect("first proposal");
        let pending_id = repository
            .project_finite_expansion(
                first_proposed.new_snapshot,
                first_request.branch_point(),
                None,
                10,
            )
            .expect("pending projection");
        let pending = repository
            .load_expansion_state(pending_id)
            .expect("load pending projection");
        assert_eq!(
            pending
                .continuations()
                .get(&first_request.id().expect("first request id")),
            Some(&ContinuationState::Open)
        );
        assert_eq!(pending.statistics().admitted_children, 0);

        let (selection, path, attempt) =
            branch_attempt(&repository, &first_request, &first_proposal);
        let first_admitted = repository
            .admit_proposal(
                "finite-expansion",
                first_proposed.new_snapshot,
                first_proposed.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("first admission");
        let ready_id = repository
            .project_finite_expansion(
                first_admitted.new_snapshot,
                first_request.branch_point(),
                None,
                10,
            )
            .expect("ready projection");
        let ready = repository
            .load_expansion_state(ready_id)
            .expect("load ready projection");
        assert_eq!(
            ready
                .continuations()
                .get(&first_request.id().expect("first request id")),
            Some(&ContinuationState::Ready)
        );
        assert_eq!(ready.statistics().admitted_children, 1);

        let admitted_head = repository.head("finite-expansion").expect("admitted head");
        let second_proposal = finite_proposal(
            &first_request,
            &policy,
            &admitted_head,
            ChoiceValue::Boolean(true),
            2,
        );
        let second_proposed = repository
            .issue_proposal(
                "finite-expansion",
                admitted_head.snapshot_id(),
                &second_proposal,
            )
            .expect("second proposal");
        let (second_selection, second_path, second_attempt) =
            branch_attempt(&repository, &first_request, &second_proposal);
        let second_admitted = repository
            .admit_proposal(
                "finite-expansion",
                second_proposed.new_snapshot,
                second_proposed.proposal,
                &second_selection,
                &second_path,
                &second_attempt,
            )
            .expect("second admission");
        let exhausted_id = repository
            .project_finite_expansion(
                second_admitted.new_snapshot,
                first_request.branch_point(),
                None,
                10,
            )
            .expect("exhausted projection");
        let exhausted = repository
            .load_expansion_state(exhausted_id)
            .expect("load exhausted projection");
        assert_eq!(
            exhausted
                .continuations()
                .get(&first_request.id().expect("first request id")),
            Some(&ContinuationState::Exhausted)
        );
        assert_eq!(exhausted.statistics().admitted_children, 2);
        assert_eq!(
            repository
                .merkle
                .inspect_shallow(exhausted.proposal_root())
                .expect("proposal projection root")
                .entry_count(),
            2
        );
        assert_eq!(
            repository
                .merkle
                .inspect_shallow(exhausted.admission_root())
                .expect("admission projection root")
                .entry_count(),
            2
        );

        let empty = repository.merkle.empty().expect("empty root").content_id();
        let forged = ExpansionState::new(
            exhausted.source_snapshot(),
            exhausted.input_view(),
            exhausted.branch_point(),
            empty,
            exhausted.proposal_root(),
            exhausted.admission_root(),
            exhausted.observation_root(),
            exhausted.statistics(),
            exhausted.page_after(),
            exhausted.page_size(),
            exhausted.next_after(),
            exhausted.continuations().clone(),
        )
        .expect("structurally valid forged projection");
        let forged_content = repository
            .put_expansion_state(&forged)
            .expect("put forged projection");
        assert!(matches!(
            repository.load_expansion_state(
                ExpansionStateId::from_content_id(forged_content).expect("forged expansion id")
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "expansion-state-owner-recomputation-mismatch"
            })
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
            2,
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
        let generated = repository
            .submit_branch_request("generators", genesis.snapshot_id(), &valid)
            .expect("accept compatible generator");
        assert!(matches!(
            repository.project_finite_expansion(
                generated.new_snapshot,
                valid.branch_point(),
                None,
                10,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "generated-expansion-projector-is-not-implemented"
            })
        ));
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
                2,
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
            2,
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
                coordination: empty,
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
            PlanningScanPage::new(None, 1, Vec::new(), true, 0).expect("scan page"),
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
