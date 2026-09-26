//! Implements `gate:lazy-frontier` over the public campaign surfaces.
//!
//! The gate exercises cardinality-independent generated-source validation and
//! polling, feedback-driven suspension and recovery, finite-source deduplication
//! and backpressure, bounded exhaustive refusal, idempotent completion, and
//! deterministic strict/streaming completion behavior. The million-continuation
//! Merkle fixture lives beside the sorted-map owner implementation and is run by
//! the gate's raw Nix derivation.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible_campaign::{
    AlternativeId, Attempt, AttemptAdmissionResult, AttemptAdmissionRole, AttemptQueue,
    AttemptStart, BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION, BooleanDomain,
    BranchAcceptanceCount, BranchBudget, BranchPath, BranchPathSegment, BranchRequest,
    BranchRequestCause, BudgetGrant, CampaignAuthorizationError, CampaignCodecError,
    CampaignCommandId, CampaignControlAction, CampaignHash, CampaignHead, CampaignLineage,
    CampaignMode, CampaignName, CampaignPlannerDriver, CampaignPlannerStepOutcome, CampaignPolicy,
    CampaignPrincipal, CampaignPrincipalAuthorizer, CampaignRepository, CampaignRepositoryError,
    CampaignSeed, CampaignService, CampaignServiceOperation, CampaignSnapshotId, CampaignViewId,
    CandidateGeneratorAlgorithm, CandidateGeneratorSpec, CandidateGeneratorSpecId, CandidateSource,
    CanonicalFrontierPlanner, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
    ChoiceOpportunity, ChoiceOpportunityId, ChoicePolicy, ChoiceSource, ChoiceValue,
    ContinuationState, ControlRequest, CoverageProjection, DaemonEpoch, DebuggerAuthorityKey,
    DiscreteAlternative, DiscreteDomain, ExactRational, ExplorerPolicy, FairnessPolicy,
    FeedbackWait, IntegerDomain, IntegerRepresentation, IntegerValue, MeasurementSet, Observation,
    PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION, PlannerAuthorityKey, PlannerDisposition,
    PlannerExecutionSupervisor, PlannerProposalDisposition, PlannerRequest, PlannerStepId,
    PlanningBudget, ProgressiveWideningPolicy, PropertyVerdictSet, Proposal, PuctPolicy,
    PurePlannerEngine, RepositoryCampaignService, RepositoryCampaignServiceError, RetentionPolicy,
    STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION, ScenarioDefId, SelectableDeclaration, Selection,
    SelectionOrigin, StopCondition, StopOutcome, SubmitCampaignBranchRequest,
    SupervisedPlannerExecution, WorkerSlotId,
};
use crucible_cas::content_store::{BlobStoreAdmin, MemoryBlobBackend, MemoryRefBackend};

struct CountingAllocator;

static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_MEASUREMENT_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    static MEASURING_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: every operation forwards the original pointer, layout, and size to
// `System` unchanged. The additional atomics neither inspect nor retain any
// allocation, so they do not alter the allocator contract.
unsafe impl GlobalAlloc for CountingAllocator {
    // SAFETY: the caller's layout is forwarded unchanged to `System`.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: the caller supplied `layout` under the `GlobalAlloc` contract
        // and it is forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    // SAFETY: the caller's layout is forwarded unchanged to `System`.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: the caller supplied `layout` under the `GlobalAlloc` contract
        // and it is forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    // SAFETY: the caller's pointer and layout are forwarded unchanged to `System`.
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the exact pointer and layout are returned to the allocator
        // that produced them.
        unsafe { System.dealloc(pointer, layout) }
    }

    // SAFETY: the caller's pointer, layout, and new size are forwarded unchanged to `System`.
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation(new_size);
        // SAFETY: the exact prior pointer/layout and requested new size are
        // forwarded unchanged to the system allocator.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Clone, Copy, Debug)]
struct AllocationMeasurement {
    allocations: usize,
    bytes: usize,
}

fn record_allocation(bytes: usize) {
    if MEASURING_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) {
        ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(bytes, Ordering::Relaxed);
    }
}

fn measure_allocations<T>(operation: impl FnOnce() -> T) -> (T, AllocationMeasurement) {
    let _serial = match ALLOCATION_MEASUREMENT_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    ALLOCATION_COUNT.store(0, Ordering::SeqCst);
    ALLOCATED_BYTES.store(0, Ordering::SeqCst);
    MEASURING_ALLOCATIONS.with(|measuring| assert!(!measuring.replace(true)));

    struct MeasurementGuard;

    impl Drop for MeasurementGuard {
        fn drop(&mut self) {
            MEASURING_ALLOCATIONS.with(|measuring| measuring.set(false));
        }
    }

    let guard = MeasurementGuard;
    let result = operation();
    drop(guard);
    let measurement = AllocationMeasurement {
        allocations: ALLOCATION_COUNT.load(Ordering::SeqCst),
        bytes: ALLOCATED_BYTES.load(Ordering::SeqCst),
    };
    (result, measurement)
}

struct GateFixture {
    repository: CampaignRepository,
    blobs: Arc<MemoryBlobBackend>,
    refs: Arc<MemoryRefBackend>,
    lineage: CampaignLineage,
    policy: CampaignPolicy,
    planner_authority: PlannerAuthorityKey,
    debugger_authority: DebuggerAuthorityKey,
}

impl GateFixture {
    fn new(
        label: &str,
        mode: CampaignMode,
        explorer: ExplorerPolicy,
        generators: &BTreeMap<CandidateGeneratorSpecId, CandidateGeneratorSpec>,
    ) -> Result<Self, Box<dyn Error>> {
        let blobs = Arc::new(MemoryBlobBackend::new(label, 512 * 1024 * 1024));
        let refs = Arc::new(MemoryRefBackend::new());
        let planner_authority = PlannerAuthorityKey::from_bytes([0x71; 32])?;
        let debugger_authority = DebuggerAuthorityKey::from_bytes([0x72; 32])?;
        let repository = CampaignRepository::with_component_authorities(
            blobs.clone(),
            refs.clone(),
            planner_authority.clone(),
            debugger_authority.clone(),
        )?;
        let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
            "gate.lazy-frontier.scenario",
            label.as_bytes(),
        ));
        let genesis = crucible_campaign::ConfigurationId::from_hash(CampaignHash::derive(
            "gate.lazy-frontier.genesis",
            label.as_bytes(),
        ));
        let scenario_content = repository.publish_scenario_artifact(
            scenario,
            1,
            format!("lazy-frontier scenario {label}").into_bytes(),
        )?;
        let genesis_content = repository.publish_configuration_artifact(
            scenario,
            scenario_content,
            genesis,
            1,
            format!("lazy-frontier genesis {label}").into_bytes(),
        )?;
        let lineage = CampaignLineage::new(
            scenario,
            scenario_content,
            genesis,
            genesis_content,
            "crucible-lazy-frontier-gate",
            "qemu-lazy-frontier-gate",
            BTreeMap::from([(String::from("control"), 1)]),
            1,
            1,
        )?;
        let choice_policies = generators
            .keys()
            .enumerate()
            .map(|(index, generator)| {
                let selectable = format!("gate.lazy-frontier.generator-{index}");
                ChoicePolicy::new(&selectable, *generator, true).map(|policy| (selectable, policy))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let policy = CampaignPolicy::new(
            CampaignPolicy::identity(
                scenario,
                CampaignSeed::from_bytes([0x73; 32]),
                mode,
                explorer,
            ),
            CampaignPolicy::rules(
                choice_policies,
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                FairnessPolicy::new(0, 0)?,
                RetentionPolicy::new(true, 1, true, true),
                true,
            ),
        )?;

        Ok(Self {
            repository,
            blobs,
            refs,
            lineage,
            policy,
            planner_authority,
            debugger_authority,
        })
    }

    fn create_funded_running(
        &self,
        campaign: &str,
        generators: &BTreeMap<CandidateGeneratorSpecId, CandidateGeneratorSpec>,
        allowance: u64,
    ) -> Result<CampaignHead, CampaignRepositoryError> {
        let created = self
            .repository
            .create(campaign, &self.lineage, &self.policy, generators)?;
        let funded = self.repository.apply_control(
            campaign,
            &ControlRequest {
                command: command_id(campaign, "fund"),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(BudgetGrant::new(allowance, allowance)?),
            },
        )?;
        let resumed = self.repository.apply_control(
            campaign,
            &ControlRequest {
                command: command_id(campaign, "resume"),
                expected_snapshot: funded.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )?;
        self.repository.head(campaign).inspect(|head| {
            assert_eq!(head.snapshot_id(), resumed.new_snapshot);
        })
    }
}

fn tree_search_explorer() -> Result<ExplorerPolicy, CampaignCodecError> {
    Ok(ExplorerPolicy::TreeSearch {
        widening: Some(ProgressiveWideningPolicy::new(
            ExactRational::new(1, 1)?,
            ExactRational::new(1, 2)?,
            1,
            100,
            1,
        )?),
        puct: PuctPolicy::new(1_000_000, 1, 0),
    })
}

fn command_id(campaign: &str, action: &str) -> CampaignCommandId {
    CampaignCommandId::from_hash(CampaignHash::derive(
        "gate.lazy-frontier.command",
        format!("{campaign}:{action}").as_bytes(),
    ))
}

fn integer_domain(maximum: u64) -> Result<ChoiceDomain, CampaignCodecError> {
    Ok(ChoiceDomain::Integer(IntegerDomain::new(
        1,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(0),
        IntegerValue::Unsigned(maximum),
        1,
        None,
        ExactRational::new(1, 1)?,
        Vec::new(),
    )?))
}

fn discrete_domain(
    label: &str,
    count: usize,
) -> Result<(ChoiceDomain, Vec<AlternativeId>), CampaignCodecError> {
    let alternatives = (0..count)
        .map(|index| {
            let id = AlternativeId::from_hash(CampaignHash::derive(
                "gate.lazy-frontier.alternative",
                format!("{label}:{index}").as_bytes(),
            ));
            DiscreteAlternative::new(id, format!("alternative-{index}"), None)
                .map(|alternative| (id, alternative))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let order = alternatives.keys().copied().collect::<Vec<_>>();
    Ok((
        ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives)?),
        order,
    ))
}

fn request_for_source(
    fixture: &GateFixture,
    domain: &ChoiceDomain,
    default: ChoiceValue,
    source: CandidateSource,
    cause: BranchRequestCause,
    label: &str,
    budget: BranchBudget,
) -> Result<BranchRequest, Box<dyn Error>> {
    let declaration = SelectableDeclaration::new(
        format!("gate.lazy-frontier.{label}"),
        ChoiceSource::Workload {
            producer: String::from("lazy-frontier-gate"),
        },
        domain.clone(),
        default,
        ChoiceClassContext::new(BTreeSet::new())?,
        BTreeSet::new(),
        true,
    )?;
    fixture.repository.publish_choice_domain(domain)?;
    fixture.repository.publish_selectable(&declaration)?;
    let opportunity = ChoiceOpportunity::new(
        fixture.lineage.scenario(),
        &declaration,
        domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("gate.lazy-frontier.scheduler", label.as_bytes()),
            producer: CampaignHash::derive("gate.lazy-frontier.producer", label.as_bytes()),
        },
        label,
        None,
    )?;
    fixture
        .repository
        .publish_choice_opportunity(&opportunity)?;

    Ok(BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(fixture.lineage.genesis()),
            fixture.lineage.genesis_content(),
            opportunity.id()?,
            domain.id()?,
        ),
        source,
        cause,
        budget,
        StopCondition::NextChoice,
    )?)
}

fn generated_integer_request(
    fixture: &GateFixture,
    domain: &ChoiceDomain,
    generator: CandidateGeneratorSpecId,
    label: &str,
    budget: u64,
) -> Result<BranchRequest, Box<dyn Error>> {
    request_for_source(
        fixture,
        domain,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        CandidateSource::generated(generator),
        BranchRequestCause::Operator(command_id(label, "request")),
        label,
        BranchBudget::new(budget, budget)?,
    )
}

fn discover_and_submit(
    fixture: &GateFixture,
    campaign: &str,
    expected: crucible_campaign::CampaignSnapshotId,
    request: &BranchRequest,
) -> Result<crucible_campaign::BranchRequestResult, CampaignRepositoryError> {
    let discovered = fixture.repository.discover_operator_choice_opportunity(
        campaign,
        expected,
        request.parent(),
        request.opportunity(),
    )?;
    fixture
        .repository
        .submit_operator_branch_request(campaign, discovered.new_snapshot, request)
}

fn proposal(
    fixture: &GateFixture,
    repository: &CampaignRepository,
    campaign: &str,
    request: &BranchRequest,
    value: ChoiceValue,
    ordinal: u64,
) -> Result<Proposal, Box<dyn Error>> {
    let head = repository.head(campaign)?;
    Ok(Proposal::new(
        request.branch_point(),
        request.id()?,
        request.domain(),
        value,
        fixture.policy.id()?,
        None,
        ordinal,
        head.snapshot().planning_view().id()?,
    )?)
}

fn branch_attempt(
    repository: &CampaignRepository,
    request: &BranchRequest,
    proposal: &Proposal,
) -> Result<(Selection, BranchPath, Attempt), Box<dyn Error>> {
    let opportunity = repository.load_choice_opportunity(request.opportunity())?;
    let domain = repository.load_choice_domain(request.domain())?;
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        request.branch_point(),
    )?;
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        return Err("campaign selection lost its branch edge".into());
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(request.branch_point(), edge)])?;
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: request.parent(),
            selection: selection.id()?,
        },
        path.id()?,
        request.stop().clone(),
    )?;
    Ok((selection, path, attempt))
}

fn issue_and_admit(
    fixture: &GateFixture,
    repository: &CampaignRepository,
    campaign: &str,
    request: &BranchRequest,
    expected: crucible_campaign::CampaignSnapshotId,
    value: ChoiceValue,
    ordinal: u64,
) -> Result<(AttemptAdmissionResult, BranchPath), Box<dyn Error>> {
    let proposal = proposal(fixture, repository, campaign, request, value, ordinal)?;
    let issued = repository.issue_proposal(campaign, expected, &proposal)?;
    let (selection, path, attempt) = branch_attempt(repository, request, &proposal)?;
    let admitted = repository.admit_proposal(
        campaign,
        issued.new_snapshot,
        issued.proposal,
        &selection,
        &path,
        &attempt,
    )?;
    Ok((admitted, path))
}

fn observation(
    fixture: &GateFixture,
    admission: &AttemptAdmissionResult,
    path: &BranchPath,
    opportunity: ChoiceOpportunityId,
    label: &str,
) -> Result<Observation, Box<dyn Error>> {
    let child = crucible_campaign::ConfigurationId::from_hash(CampaignHash::derive(
        "gate.lazy-frontier.child",
        label.as_bytes(),
    ));
    let child_content = fixture.repository.publish_configuration_artifact(
        fixture.lineage.scenario(),
        fixture.lineage.scenario_content(),
        child,
        1,
        format!("lazy-frontier child {label}").into_bytes(),
    )?;
    let measurements =
        fixture
            .repository
            .publish_measurement_set(&MeasurementSet::from_evaluation(
                CampaignHash::derive("test.measurement", b"lazy-frontier.measurement-definitions"),
                1,
                CampaignHash::derive("test.measurement", b"lazy-frontier.measurement-evaluation"),
                b"lazy-frontier-measurements".to_vec(),
                BTreeSet::new(),
            )?)?;
    let properties = fixture
        .repository
        .publish_property_verdict_set(&PropertyVerdictSet::new(BTreeMap::new())?)?;
    let coverage = fixture
        .repository
        .publish_coverage_projection(&CoverageProjection::new(BTreeSet::new(), BTreeSet::new())?)?;
    Ok(Observation::new(
        admission.attempt,
        Observation::outcome(
            child,
            child_content,
            path.id()?,
            StopOutcome::Reached(StopCondition::NextChoice),
            measurements,
            properties,
            coverage,
        ),
        BTreeSet::from([opportunity]),
    )?)
}

#[derive(Clone, Copy)]
struct DirectPlannerSupervisor;

impl PlannerExecutionSupervisor<CanonicalFrontierPlanner> for DirectPlannerSupervisor {
    type Error = Infallible;

    fn execute(
        &mut self,
        engine: &mut CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let result = engine.plan(request);
        let output_count = match result
            .as_ref()
            .map(|output| output.proposal().disposition())
        {
            Ok(PlannerProposalDisposition::Issue {
                branch_requests,
                proposals,
                ..
            }) => (branch_requests.len() + proposals.len()).max(1) as u64,
            _ => 1,
        };
        let measured_fuel =
            request.invocation().scan_page().positions().len() as u64 + output_count;
        Ok(SupervisedPlannerExecution::new(result, measured_fuel))
    }
}

struct AllowGatePrincipal;

impl CampaignPrincipalAuthorizer for AllowGatePrincipal {
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

fn planner_driver(
    fixture: &GateFixture,
) -> Result<
    CampaignPlannerDriver<
        crucible_campaign::AuthorizedPlannerService<
            CanonicalFrontierPlanner,
            DirectPlannerSupervisor,
        >,
    >,
    Box<dyn Error>,
> {
    planner_driver_with_proposal_limit(fixture, 1)
}

fn planner_driver_with_proposal_limit(
    fixture: &GateFixture,
    proposal_limit: u32,
) -> Result<
    CampaignPlannerDriver<
        crucible_campaign::AuthorizedPlannerService<
            CanonicalFrontierPlanner,
            DirectPlannerSupervisor,
        >,
    >,
    Box<dyn Error>,
> {
    let basis = fixture
        .repository
        .publish_canonical_frontier_planner_basis()?;
    let (engine, artifact, initial_state) = basis.into_parts();
    let client = crucible_campaign::PlannerClient::new(
        crucible_campaign::AuthorizedPlannerService::new(
            CanonicalFrontierPlanner,
            DirectPlannerSupervisor,
            fixture.planner_authority.clone(),
        ),
        fixture.planner_authority.clone(),
    );
    Ok(CampaignPlannerDriver::new(
        Arc::new(CampaignRepository::with_component_authorities(
            fixture.blobs.clone(),
            fixture.refs.clone(),
            fixture.planner_authority.clone(),
            fixture.debugger_authority.clone(),
        )?),
        client,
        engine,
        artifact,
        initial_state,
        16,
        PlanningBudget::new(1, proposal_limit, 64, 64 * 1024, 10_000)?,
    )?
    .require_tree_search_policy())
}

#[test]
fn finite_frontier_issues_one_ordered_bounded_vector() -> Result<(), Box<dyn Error>> {
    let fixture = GateFixture::new(
        "finite-vector-issue",
        CampaignMode::Strict,
        tree_search_explorer()?,
        &BTreeMap::new(),
    )?;
    let campaign = "finite-vector-issue";
    let head = fixture.create_funded_running(campaign, &BTreeMap::new(), 16)?;
    let domain = integer_domain(15)?;
    let values = (0..16_u64)
        .map(|value| ChoiceValue::Integer(IntegerValue::Unsigned(value)))
        .collect::<BTreeSet<_>>();
    let request = request_for_source(
        &fixture,
        &domain,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        CandidateSource::finite(values.clone())?,
        BranchRequestCause::Operator(command_id(campaign, "request")),
        campaign,
        BranchBudget::new(16, 16)?,
    )?;
    let requested = discover_and_submit(&fixture, campaign, head.snapshot_id(), &request)?;
    let mut driver = planner_driver_with_proposal_limit(&fixture, 16)?;

    let CampaignPlannerStepOutcome::Advanced {
        result,
        disposition: PlannerDisposition::Issue {
            issued_proposals, ..
        },
        ..
    } = driver.step(campaign)?
    else {
        return Err("finite frontier did not issue its ordered vector".into());
    };
    assert_ne!(result.new_snapshot, requested.new_snapshot);
    assert_eq!(issued_proposals.len(), 16);
    for (index, proposal_id) in issued_proposals.into_iter().enumerate() {
        let proposal = fixture.repository.load_proposal(proposal_id)?;
        assert_eq!(proposal.ordinal(), index as u64 + 1);
        assert_eq!(
            proposal.value(),
            values.iter().nth(index).ok_or("missing value")?
        );
    }
    let claimable = fixture
        .repository
        .project_claimable_attempts(campaign, None, 32)?;
    assert_eq!(claimable.attempts().len(), 16);
    Ok(())
}

#[test]
fn huge_integer_validation_and_polling_are_cardinality_independent() -> Result<(), Box<dyn Error>> {
    fn prepare(
        label: &str,
        maximum: u64,
    ) -> Result<
        (
            GateFixture,
            String,
            BranchRequest,
            crucible_campaign::CampaignSnapshotId,
        ),
        Box<dyn Error>,
    > {
        let generator = CandidateGeneratorSpec::new(
            STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
            CandidateGeneratorAlgorithm::All,
        )?;
        let generator_id = generator.id()?;
        let generators = BTreeMap::from([(generator_id, generator)]);
        let fixture = GateFixture::new(
            label,
            CampaignMode::Strict,
            tree_search_explorer()?,
            &generators,
        )?;
        let campaign = format!("{label}-campaign");
        let head = fixture.create_funded_running(&campaign, &generators, 16)?;
        let domain = integer_domain(maximum)?;
        let request = generated_integer_request(&fixture, &domain, generator_id, label, 4)?;
        let discovered = fixture.repository.discover_operator_choice_opportunity(
            &campaign,
            head.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )?;
        Ok((fixture, campaign, request, discovered.new_snapshot))
    }

    let (small, small_campaign, small_request, small_snapshot) = prepare("allocation-small", 9)?;
    let (large, large_campaign, large_request, large_snapshot) =
        prepare("allocation-huge", u64::from(u32::MAX) + 8)?;
    assert!(
        large
            .repository
            .load_choice_domain(large_request.domain())?
            .cardinality()
            > u128::from(u32::MAX)
    );

    // All fixture objects and allocator warmup are complete before measurement.
    // Only the semantic request-validation transition is counted here.
    let (small_result, small_validation) = measure_allocations(|| {
        small.repository.submit_operator_branch_request(
            &small_campaign,
            small_snapshot,
            &small_request,
        )
    });
    let small_result = small_result?;
    let (large_result, large_validation) = measure_allocations(|| {
        large.repository.submit_operator_branch_request(
            &large_campaign,
            large_snapshot,
            &large_request,
        )
    });
    let large_result = large_result?;
    assert_eq!(
        small_result.summary.validated_cardinality(),
        BranchAcceptanceCount::Exact(4)
    );
    assert_eq!(
        large_result.summary.validated_cardinality(),
        BranchAcceptanceCount::Exact(4)
    );
    assert!(
        large_validation.allocations <= small_validation.allocations + 128,
        "validation allocations: small={small_validation:?}, large={large_validation:?}"
    );
    assert!(
        large_validation.bytes <= small_validation.bytes + 64 * 1024,
        "validation bytes: small={small_validation:?}, large={large_validation:?}"
    );

    let mut small_driver = planner_driver(&small)?;
    let mut large_driver = planner_driver(&large)?;
    let (small_poll, small_poll_allocations) =
        measure_allocations(|| small_driver.step(&small_campaign));
    let (large_poll, large_poll_allocations) =
        measure_allocations(|| large_driver.step(&large_campaign));
    assert!(matches!(
        small_poll?,
        CampaignPlannerStepOutcome::Advanced {
            disposition: PlannerDisposition::Issue { .. },
            ..
        }
    ));
    assert!(matches!(
        large_poll?,
        CampaignPlannerStepOutcome::Advanced {
            disposition: PlannerDisposition::Issue { .. },
            ..
        }
    ));
    assert!(
        large_poll_allocations.allocations
            <= small_poll_allocations.allocations + small_poll_allocations.allocations / 20 + 256,
        "poll allocations: small={small_poll_allocations:?}, large={large_poll_allocations:?}"
    );
    assert!(
        large_poll_allocations.bytes
            <= small_poll_allocations.bytes + small_poll_allocations.bytes / 20 + 64 * 1024,
        "poll bytes: small={small_poll_allocations:?}, large={large_poll_allocations:?}"
    );

    Ok(())
}

#[test]
fn discrete_all_and_maximum_finite_requests_remain_lazy_under_one_slot()
-> Result<(), Box<dyn Error>> {
    let all = CandidateGeneratorSpec::new(
        STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )?;
    let all_id = all.id()?;
    let generators = BTreeMap::from([(all_id, all)]);
    let discrete_fixture = GateFixture::new(
        "discrete-ten",
        CampaignMode::Strict,
        tree_search_explorer()?,
        &generators,
    )?;
    let discrete_campaign = "discrete-ten";
    let discrete_head =
        discrete_fixture.create_funded_running(discrete_campaign, &generators, 16)?;
    let (discrete, alternatives) = discrete_domain("ten", 10)?;
    let discrete_request = request_for_source(
        &discrete_fixture,
        &discrete,
        ChoiceValue::Discrete(alternatives[0]),
        CandidateSource::generated(all_id),
        BranchRequestCause::Operator(command_id(discrete_campaign, "request")),
        "discrete-ten",
        BranchBudget::new(10, 10)?,
    )?;
    let discrete_requested = discover_and_submit(
        &discrete_fixture,
        discrete_campaign,
        discrete_head.snapshot_id(),
        &discrete_request,
    )?;
    assert_eq!(
        discrete_requested.summary.validated_cardinality(),
        BranchAcceptanceCount::Exact(10)
    );
    let mut discrete_driver = planner_driver(&discrete_fixture)?;
    let CampaignPlannerStepOutcome::Advanced {
        disposition: PlannerDisposition::Issue {
            issued_proposals, ..
        },
        ..
    } = discrete_driver.step(discrete_campaign)?
    else {
        return Err("ten-alternative source did not issue one bounded proposal".into());
    };
    assert_eq!(issued_proposals.len(), 1);

    let finite_fixture = GateFixture::new(
        "maximum-finite",
        CampaignMode::Strict,
        tree_search_explorer()?,
        &BTreeMap::new(),
    )?;
    let finite_campaign = "maximum-finite";
    let finite_head = finite_fixture.create_funded_running(finite_campaign, &BTreeMap::new(), 8)?;
    let huge_domain = integer_domain(u64::from(u32::MAX) + 8)?;
    let finite_values = (0..4_096_u64)
        .map(|value| ChoiceValue::Integer(IntegerValue::Unsigned(value)))
        .collect::<BTreeSet<_>>();
    let finite_request = request_for_source(
        &finite_fixture,
        &huge_domain,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        CandidateSource::finite(finite_values)?,
        BranchRequestCause::Operator(command_id(finite_campaign, "request")),
        "maximum-finite",
        BranchBudget::new(4_096, 4_096)?,
    )?;
    let finite_requested = discover_and_submit(
        &finite_fixture,
        finite_campaign,
        finite_head.snapshot_id(),
        &finite_request,
    )?;
    assert_eq!(
        finite_requested.summary.validated_cardinality(),
        BranchAcceptanceCount::Exact(4_096)
    );
    assert!(
        finite_fixture
            .repository
            .project_claimable_attempts(finite_campaign, None, 10_000)?
            .attempts()
            .is_empty(),
        "request publication must not create an attempt batch"
    );

    let mut finite_driver = planner_driver(&finite_fixture)?;
    let CampaignPlannerStepOutcome::Advanced {
        disposition: PlannerDisposition::Issue {
            issued_proposals, ..
        },
        ..
    } = finite_driver.step(finite_campaign)?
    else {
        return Err("maximum finite source did not issue one bounded proposal".into());
    };
    assert_eq!(issued_proposals.len(), 1);
    let claimable =
        finite_fixture
            .repository
            .project_claimable_attempts(finite_campaign, None, 10_000)?;
    assert_eq!(claimable.attempts().len(), 1);
    let mut queue = AttemptQueue::new(DaemonEpoch::from_bytes([0x91; 16])?, 1)?;
    let reservation = queue
        .reserve_from_page(&claimable, WorkerSlotId::new(0))?
        .ok_or("one admitted attempt was not claimable")?;
    assert_eq!(queue.reservation_count(), 1);
    assert_eq!(
        queue.reserve_from_page(&claimable, WorkerSlotId::new(0))?,
        Some(reservation)
    );

    Ok(())
}

#[test]
fn finite_request_deduplicates_a_generated_attempt_on_a_huge_domain() -> Result<(), Box<dyn Error>>
{
    let boundary = CandidateGeneratorSpec::new(
        BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::BoundaryInteger,
    )?;
    let boundary_id = boundary.id()?;
    let generators = BTreeMap::from([(boundary_id, boundary)]);
    let fixture = GateFixture::new(
        "finite-generated-dedup",
        CampaignMode::Strict,
        tree_search_explorer()?,
        &generators,
    )?;
    let campaign = "finite-generated-dedup";
    let head = fixture.create_funded_running(campaign, &generators, 16)?;
    let maximum = u64::from(u32::MAX) + 8;
    let domain = integer_domain(maximum)?;
    let generated =
        generated_integer_request(&fixture, &domain, boundary_id, "dedup-generated", 1)?;
    let generated_requested =
        discover_and_submit(&fixture, campaign, head.snapshot_id(), &generated)?;
    let (generated_admission, _) = issue_and_admit(
        &fixture,
        &fixture.repository,
        campaign,
        &generated,
        generated_requested.new_snapshot,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        1,
    )?;
    assert!(matches!(
        fixture
            .repository
            .load_attempt_admission(generated_admission.admission)?
            .role(),
        AttemptAdmissionRole::ExecutionBasis { .. }
    ));

    let finite = BranchRequest::new(
        BranchRequest::identity(
            generated.branch_point(),
            generated.parent(),
            generated.opportunity(),
            generated.domain(),
        ),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Integer(IntegerValue::Unsigned(0)),
            ChoiceValue::Integer(IntegerValue::Unsigned(maximum - 1)),
            ChoiceValue::Integer(IntegerValue::Unsigned(maximum)),
        ]))?,
        BranchRequestCause::Operator(command_id(campaign, "finite-request")),
        BranchBudget::new(3, 3)?,
        StopCondition::NextChoice,
    )?;
    let finite_requested = fixture.repository.submit_operator_branch_request(
        campaign,
        generated_admission.new_snapshot,
        &finite,
    )?;
    let (deduplicated, _) = issue_and_admit(
        &fixture,
        &fixture.repository,
        campaign,
        &finite,
        finite_requested.new_snapshot,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        1,
    )?;
    assert_eq!(deduplicated.attempt, generated_admission.attempt);
    assert!(matches!(
        fixture
            .repository
            .load_attempt_admission(deduplicated.admission)?
            .role(),
        AttemptAdmissionRole::AdditionalCause { .. }
    ));
    let expansion = fixture.repository.project_finite_expansion(
        deduplicated.new_snapshot,
        finite.branch_point(),
        None,
        16,
    )?;
    assert_eq!(
        fixture
            .repository
            .load_expansion_state(expansion)?
            .statistics()
            .admitted_children,
        1
    );

    Ok(())
}

#[path = "gate_lazy_frontier/scale.rs"]
mod scale;

#[path = "gate_lazy_frontier/cold_validation.rs"]
mod cold_validation;
