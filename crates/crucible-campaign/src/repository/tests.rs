//! Repository coordination, execution, and validation test module wiring.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use super::*;
use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

use crate::{
    AlternativeId, AssignmentId, AttemptResourceLimits, BooleanDomain, BranchBudget, BudgetGrant,
    CampaignAuthorizationError, CampaignFactId, CampaignFindingObject, CampaignFindingObjectKind,
    CampaignMode, CampaignName, CampaignPlanningBundle, CampaignPlanningView, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignSeed, CampaignServiceOperation,
    CandidateGeneratorAlgorithm, CanonicalFrontierPlanner, CanonicalPuctPlanner,
    ChoiceClassContext, ChoiceCoordinate, ChoicePolicy, ChoiceSource, ChoiceValue, ConfigurationId,
    ContinuationState, DebugSessionId, DiscreteAlternative, DiscreteDomain, ExecutionId,
    ExecutionRetentionIntent, ExplainCampaignAttemptRequest, ExplorerPolicy, FairnessPolicy,
    GetCampaignFindingObjectRequest, GetCampaignFrontierObjectRequest, GuidanceEvidence,
    GuidanceWeight, MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS, MeasurementSeries, MetricValue,
    PlannerEngine, PlannerProposalDisposition, PlannerRequest, PlannerResponse, PlannerState,
    PlannerStepProposal, PlannerSubmission, PlanningBudget, PlanningUsage, PolicyArtifact,
    ProbabilityModelId, ProgressiveWideningPolicy, PropertyEvidence, PuctPolicy, PurePlannerEngine,
    QueryCampaignFindingsRequest, QueryCampaignFrontierRequest, RepositoryCampaignService,
    RetentionPolicy, ScenarioDefId, StopCondition, WeightedGenerator,
};

struct AllowCampaignQueries;

impl CampaignRepository {
    /// Creates an explicitly funded fixture for tests that issue semantic work.
    fn create_funded(
        &self,
        name: &str,
        lineage: &CampaignLineage,
        policy: &CampaignPolicy,
        generators: &BTreeMap<CandidateGeneratorSpecId, CandidateGeneratorSpec>,
    ) -> Result<CampaignHead, CampaignRepositoryError> {
        let head = self.create(name, lineage, policy, generators)?;
        self.apply_control(
            name,
            &command(
                "fixture-initial-budget",
                head.snapshot_id(),
                CampaignControlAction::GrantBudget(BudgetGrant::new(1_000_000, 1_000_000)?),
            ),
        )?;
        self.head(name)
    }
}

impl CampaignPrincipalAuthorizer for AllowCampaignQueries {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }
}

trait TestBranchSubmission {
    fn submit_known_branch_request(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        request: &BranchRequest,
    ) -> Result<BranchRequestResult, CampaignRepositoryError>;
}

impl TestBranchSubmission for CampaignRepository {
    fn submit_known_branch_request(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        request: &BranchRequest,
    ) -> Result<BranchRequestResult, CampaignRepositoryError> {
        let head = self.head(name)?;
        if self.merkle.get(
            head.snapshot().roots().graph,
            branch_point_opportunity_key(request.branch_point(), request.opportunity()),
        )? != Some(request.opportunity().content_id())
        {
            self.discover_choice_opportunity(
                name,
                expected_snapshot,
                request.parent(),
                request.opportunity(),
            )?;
        }
        let current = self.head(name)?.snapshot_id();
        self.submit_branch_request(name, current, request)
    }
}

struct ConflictAfterCreateRefBackend {
    inner: MemoryRefBackend,
    conflict_mutations: Mutex<bool>,
}

impl ConflictAfterCreateRefBackend {
    fn new() -> Self {
        Self {
            inner: MemoryRefBackend::new(),
            conflict_mutations: Mutex::new(false),
        }
    }

    fn arm(&self) {
        *self.conflict_mutations.lock().expect("conflict flag") = true;
    }
}

impl MutableRefBackend for ConflictAfterCreateRefBackend {
    fn capabilities(&self) -> crucible_cas::content_store::RefBackendCapabilities {
        self.inner.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        self.inner.acquire_publication_guard()
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.inner.read_ref(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<crucible_cas::content_store::RefScanPage, StoreError> {
        self.inner.scan_refs(namespace, after, limit)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        if expected.is_some()
            && *self
                .conflict_mutations
                .lock()
                .map_err(|_| StoreError::Poisoned {
                    operation: "test-conflict-flag",
                })?
        {
            return Ok(RefCasOutcome::Conflict {
                expected,
                current: self.inner.read_ref(name)?,
            });
        }
        self.inner.compare_exchange(name, expected, next)
    }
}

/// Reconstructs the historical empty exploration root for fixed identity vectors.
fn legacy_genesis_roots(
    repository: &CampaignRepository,
    mut roots: crate::CampaignRoots,
) -> crate::CampaignRoots {
    let empty = repository.merkle.empty().expect("empty").content_id();
    let frontier = repository
        .merkle
        .insert(empty, frontier_index_anchor_key(), empty)
        .expect("legacy frontier");
    roots.exploration = repository
        .merkle
        .insert(
            frontier.content_id(),
            branch_request_index_anchor_key(),
            empty,
        )
        .expect("legacy requests")
        .content_id();
    roots
}

fn fixture() -> (CampaignRepository, CampaignLineage, CampaignPolicy) {
    let (repository, lineage, policy, _) = counted_fixture();
    (repository, lineage, policy)
}

fn counted_fixture() -> (
    CampaignRepository,
    CampaignLineage,
    CampaignPolicy,
    Arc<MemoryBlobBackend>,
) {
    fixture_with_quota(64 * 1024 * 1024)
}

fn fixture_with_quota(
    max_logical_bytes: u64,
) -> (
    CampaignRepository,
    CampaignLineage,
    CampaignPolicy,
    Arc<MemoryBlobBackend>,
) {
    fixture_with_quota_and_authorities(max_logical_bytes, None)
}

fn authorized_fixture() -> (
    CampaignRepository,
    CampaignLineage,
    CampaignPolicy,
    Arc<MemoryBlobBackend>,
    PlannerAuthorityKey,
    DebuggerAuthorityKey,
) {
    let planner = PlannerAuthorityKey::from_bytes([17; 32]).expect("planner authority");
    let debugger = DebuggerAuthorityKey::from_bytes([23; 32]).expect("debugger authority");
    let (repository, lineage, policy, blobs) = fixture_with_quota_and_authorities(
        64 * 1024 * 1024,
        Some((planner.clone(), debugger.clone())),
    );
    (repository, lineage, policy, blobs, planner, debugger)
}

fn fixture_with_quota_and_authorities(
    max_logical_bytes: u64,
    authorities: Option<(PlannerAuthorityKey, DebuggerAuthorityKey)>,
) -> (
    CampaignRepository,
    CampaignLineage,
    CampaignPolicy,
    Arc<MemoryBlobBackend>,
) {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", b"scenario"));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive("test", b"genesis"));
    let blobs = Arc::new(MemoryBlobBackend::new("campaign", max_logical_bytes));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = if let Some((planner, debugger)) = authorities {
        CampaignRepository::with_component_authorities(blobs.clone(), refs, planner, debugger)
            .expect("distinct component authorities")
    } else {
        CampaignRepository::new(blobs.clone(), refs)
    };
    let scenario_content = repository
        .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let genesis_content = repository
        .publish_configuration_artifact(scenario, scenario_content, genesis, 1, b"genesis".to_vec())
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
    (repository, lineage, policy, blobs)
}

fn command(
    id: &str,
    expected_snapshot: CampaignSnapshotId,
    action: CampaignControlAction,
) -> ControlRequest {
    ControlRequest {
        command: crate::CampaignCommandId::from_hash(CampaignHash::derive("test", id.as_bytes())),
        expected_snapshot,
        action,
    }
}

fn policy_with_generator(
    scenario: ScenarioDefId,
    generator: CandidateGeneratorSpecId,
) -> CampaignPolicy {
    exhaustive_policy_with_generator(scenario, generator, "product.recovery", 64)
}

fn exhaustive_policy_with_generator(
    scenario: ScenarioDefId,
    generator: CandidateGeneratorSpecId,
    selectable: &str,
    maximum_cardinality: u64,
) -> CampaignPolicy {
    CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([9; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality,
        },
        BTreeMap::from([(
            selectable.to_owned(),
            ChoicePolicy::new(selectable, generator, true).expect("choice policy"),
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
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            command.as_bytes(),
        ))),
        BranchBudget::new(2, 2).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("branch request")
}

fn modeled_branch_request(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    parent: ConfigurationArtifactId,
    parent_configuration: ConfigurationId,
    command: &str,
    model: ProbabilityModelId,
    prior_weights: BTreeMap<ChoiceValue, u64>,
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
        Some(model),
    )
    .expect("modeled opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish modeled opportunity");

    BranchRequest::new(
        opportunity.branch_point_id(parent_configuration),
        parent,
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::modeled_finite(model, prior_weights).expect("modeled finite source"),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            command.as_bytes(),
        ))),
        BranchBudget::new(2, 2).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("modeled branch request")
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
    let path = BranchPath::new(vec![crate::BranchPathSegment::new(
        request.branch_point(),
        edge,
    )])
    .expect("branch path");
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

#[test]
fn selection_batch_resolution_shares_dependencies_and_bounds_records() {
    let (repository, lineage, _) = fixture();
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.test.selection-batch",
        ChoiceSource::Workload {
            producer: "selection-batch".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
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

    let mut ids = Vec::new();
    for ordinal in 0u16..256 {
        let material = ordinal.to_le_bytes();
        let opportunity = ChoiceOpportunity::new(
            lineage.scenario(),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("test.selection-batch", &material),
                producer: CampaignHash::derive("test", b"selection-batch"),
            },
            format!("selection-{ordinal}"),
            None,
        )
        .expect("opportunity");
        repository
            .publish_choice_opportunity(&opportunity)
            .expect("publish opportunity");
        let selection = Selection::new(
            &opportunity,
            &domain,
            ChoiceValue::Boolean(false),
            crate::SelectionOrigin::Default,
        )
        .expect("selection");
        ids.push(
            repository
                .publish_selection(&selection)
                .expect("publish selection"),
        );
    }

    let resolved = repository
        .resolve_selections(&ids)
        .expect("resolve shared selection dependencies");
    assert_eq!(resolved.len(), ids.len());
    assert!(
        resolved
            .iter()
            .all(|selection| std::ptr::eq(selection.domain(), resolved[0].domain()))
    );

    let oversized = vec![ids[0]; MAX_SELECTION_RESOLUTION_RECORDS + 1];
    assert!(matches!(
        repository.resolve_selections(&oversized),
        Err(CampaignRepositoryError::Codec(
            CampaignCodecError::InvalidValue {
                reason: "selection resolution batch exceeds record limit"
            }
        ))
    ));
}

fn admitted_observation_fixture(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    policy: &CampaignPolicy,
    name: &str,
) -> (CampaignSnapshotId, AttemptAdmissionResult, Observation) {
    let genesis = repository
        .create_funded(name, lineage, policy, &BTreeMap::new())
        .expect("create observation campaign");
    let request = branch_request(
        repository,
        lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        name,
    );
    let requested = repository
        .submit_known_branch_request(name, genesis.snapshot_id(), &request)
        .expect("submit observation request");
    let proposal = finite_proposal(
        &request,
        policy,
        &repository.head(name).expect("request head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let proposed = repository
        .issue_proposal(name, requested.new_snapshot, &proposal)
        .expect("issue observation proposal");
    let (selection, path, attempt) = branch_attempt(repository, &request, &proposal);
    let admitted = repository
        .admit_proposal(
            name,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit observation attempt");

    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "test-observation-child",
        name.as_bytes(),
    ));
    let child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            format!("child:{name}").into_bytes(),
        )
        .expect("publish child artifact");
    let measurements = MeasurementSet::new(BTreeMap::from([(
        "latency".to_owned(),
        MeasurementSeries::new(
            vec![MetricValue::Unsigned(7)],
            MetricValue::Unsigned(7),
            BTreeSet::new(),
        )
        .expect("measurement series"),
    )]))
    .expect("measurement set");
    let measurement_id = repository
        .publish_measurement_set(&measurements)
        .expect("publish measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::from([(
        "network-recovers".to_owned(),
        PropertyEvidence::new(PropertyVerdict::Passed, BTreeSet::new()).expect("property evidence"),
    )]))
    .expect("property verdict set");
    let property_id = repository
        .publish_property_verdict_set(&properties)
        .expect("publish properties");
    let coverage = CoverageProjection::new(
        BTreeSet::from([CampaignHash::derive(
            "test-observation-coverage",
            name.as_bytes(),
        )]),
        BTreeSet::new(),
    )
    .expect("coverage projection");
    let coverage_id = repository
        .publish_coverage_projection(&coverage)
        .expect("publish coverage");
    let observation = Observation::new(
        admitted.attempt,
        child,
        child_content,
        path.id().expect("path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurement_id,
        property_id,
        coverage_id,
        BTreeSet::from([request.opportunity()]),
    )
    .expect("observation");
    (genesis.snapshot_id(), admitted, observation)
}

fn choice_discovery_fixture(
    repository: &CampaignRepository,
    id: ChoiceOpportunityId,
) -> ChoiceDiscovery {
    let opportunity = repository
        .load_choice_opportunity(id)
        .expect("load discovered choice");
    let declaration = repository
        .load_selectable(opportunity.declaration())
        .expect("load discovered declaration");
    let domain = repository
        .load_choice_domain(opportunity.domain())
        .expect("load discovered domain");
    ChoiceDiscovery::new(declaration, domain, opportunity).expect("choice discovery fixture")
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
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
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

fn canonical_planner_basis_with_page(
    repository: &CampaignRepository,
    name: &str,
    snapshot: CampaignSnapshotId,
    state: &PlannerState,
    scan_after: Option<PlanningScanPosition>,
    scan_limit: u32,
) -> (PlannerEngine, PolicyArtifact, PlannerInvocation) {
    let engine = CanonicalFrontierPlanner::descriptor().expect("canonical planner engine");
    assert_eq!(state.engine(), engine.id().expect("canonical engine id"));
    let dependency_bytes = b"canonical frontier planner dependency".to_vec();
    let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
    repository
        .blobs
        .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
        .expect("canonical planner dependency");
    let artifact = PolicyArtifact::new(
        engine.id().expect("canonical engine id"),
        1,
        dependency,
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("canonical planner artifact");
    let invocation = repository
        .prepare_planner_invocation(
            name,
            snapshot,
            &engine,
            &artifact,
            state,
            scan_after,
            scan_limit,
            PlanningBudget::new(4, 4, 16, 8192, 100).expect("canonical planner budget"),
        )
        .expect("prepare canonical planner invocation");
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

fn test_planner_request_digest(invocation: PlannerInvocationId) -> CampaignHash {
    CampaignHash::derive(
        "crucible.test.planner-request-digest.v1",
        invocation.content_id().encode().as_bytes(),
    )
}

mod budget;
mod budget_enforcement;
mod coordination;
mod discovery;
mod execution;
mod planner_scan_index;
mod request_budget_scale;
mod scenario_default;
mod validation;
