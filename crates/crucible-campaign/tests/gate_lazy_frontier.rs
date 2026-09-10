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
    PlannerExecutionSupervisor, PlannerRequest, PlannerStepId, PlanningBudget,
    ProgressiveWideningPolicy, PropertyVerdictSet, Proposal, PuctPolicy, PurePlannerEngine,
    RepositoryCampaignService, RepositoryCampaignServiceError, RetentionPolicy,
    STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION, ScenarioDefId, SelectableDeclaration, Selection,
    SelectionOrigin, StopCondition, StopOutcome, SubmitCampaignBranchRequest,
    SupervisedPlannerExecution, WorkerSlotId,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

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
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: the caller supplied `layout` under the `GlobalAlloc` contract
        // and it is forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: the caller supplied `layout` under the `GlobalAlloc` contract
        // and it is forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the exact pointer and layout are returned to the allocator
        // that produced them.
        unsafe { System.dealloc(pointer, layout) }
    }

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
            scenario,
            CampaignSeed::from_bytes([0x73; 32]),
            mode,
            explorer,
            choice_policies,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0)?,
            RetentionPolicy::new(true, 1, true, true),
            true,
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
        opportunity.branch_point_id(fixture.lineage.genesis()),
        fixture.lineage.genesis_content(),
        opportunity.id()?,
        domain.id()?,
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
    let measurements = fixture
        .repository
        .publish_measurement_set(&MeasurementSet::new(BTreeMap::new())?)?;
    let properties = fixture
        .repository
        .publish_property_verdict_set(&PropertyVerdictSet::new(BTreeMap::new())?)?;
    let coverage = fixture
        .repository
        .publish_coverage_projection(&CoverageProjection::new(BTreeSet::new(), BTreeSet::new())?)?;
    Ok(Observation::new(
        admission.attempt,
        child,
        child_content,
        path.id()?,
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
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
        Ok(SupervisedPlannerExecution::new(
            engine.plan(request),
            request.invocation().scan_page().input_objects() + 1,
        ))
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
        PlanningBudget::new(1, 1, 64, 64 * 1024, 10_000)?,
    )?
    .require_tree_search_policy())
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
        generated.branch_point(),
        generated.parent(),
        generated.opportunity(),
        generated.domain(),
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

#[test]
fn exhaustive_all_above_the_policy_ceiling_rejects_without_writes() -> Result<(), Box<dyn Error>> {
    let all = CandidateGeneratorSpec::new(
        STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )?;
    let all_id = all.id()?;
    let generators = BTreeMap::from([(all_id, all)]);
    let fixture = GateFixture::new(
        "exhaustive-ceiling",
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 9,
        },
        &generators,
    )?;
    let campaign = "exhaustive-ceiling";
    let head = fixture.create_funded_running(campaign, &generators, 16)?;
    let (domain, alternatives) = discrete_domain("exhaustive-ceiling", 10)?;
    let request = request_for_source(
        &fixture,
        &domain,
        ChoiceValue::Discrete(alternatives[0]),
        CandidateSource::generated(all_id),
        BranchRequestCause::ExhaustivePolicy(fixture.policy.id()?),
        "exhaustive-ceiling",
        BranchBudget::new(10, 10)?,
    )?;
    let discovered = fixture.repository.discover_operator_choice_opportunity(
        campaign,
        head.snapshot_id(),
        request.parent(),
        request.opportunity(),
    )?;
    let objects_before = fixture.blobs.object_count()?;
    let service = RepositoryCampaignService::new(&fixture.repository, AllowGatePrincipal);
    let submission = SubmitCampaignBranchRequest::new(
        CampaignPrincipal::new("lazy-frontier-gate")?,
        CampaignName::new(campaign)?,
        discovered.new_snapshot,
        request,
    )?;
    assert!(matches!(
        service.submit_branch_request(&submission),
        Err(RepositoryCampaignServiceError::Repository(
            CampaignRepositoryError::Integrity {
                reason: "exhaustive-branch-request-domain-exceeds-policy"
            }
        ))
    ));
    assert_eq!(fixture.blobs.object_count()?, objects_before);
    assert_eq!(
        fixture.repository.head(campaign)?.snapshot_id(),
        discovered.new_snapshot
    );

    Ok(())
}

struct CompletionRun {
    final_snapshot: CampaignSnapshotId,
    planning_view: CampaignViewId,
    planner_step: PlannerStepId,
    accepted_second_first: bool,
}

fn run_shuffled_completion(
    mode: CampaignMode,
    reverse_delivery: bool,
) -> Result<CompletionRun, Box<dyn Error>> {
    let fixture = GateFixture::new(
        "shuffled-completion",
        mode,
        tree_search_explorer()?,
        &BTreeMap::new(),
    )?;
    let campaign = "shuffled-completion";
    let head = fixture.create_funded_running(campaign, &BTreeMap::new(), 16)?;
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1)?);
    let request = request_for_source(
        &fixture,
        &domain,
        ChoiceValue::Boolean(false),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))?,
        BranchRequestCause::Operator(command_id(campaign, "request")),
        "shuffled-completion",
        BranchBudget::new(2, 2)?,
    )?;
    let requested = discover_and_submit(&fixture, campaign, head.snapshot_id(), &request)?;

    let first_proposal = proposal(
        &fixture,
        &fixture.repository,
        campaign,
        &request,
        ChoiceValue::Boolean(false),
        1,
    )?;
    let first_issued =
        fixture
            .repository
            .issue_proposal(campaign, requested.new_snapshot, &first_proposal)?;
    let (first_selection, first_path, first_attempt) =
        branch_attempt(&fixture.repository, &request, &first_proposal)?;
    let first_admitted = fixture.repository.admit_proposal(
        campaign,
        first_issued.new_snapshot,
        first_issued.proposal,
        &first_selection,
        &first_path,
        &first_attempt,
    )?;
    let first_admission_replay = fixture.repository.admit_proposal(
        campaign,
        first_issued.new_snapshot,
        first_issued.proposal,
        &first_selection,
        &first_path,
        &first_attempt,
    )?;
    assert!(first_admission_replay.replayed);
    assert_eq!(first_admission_replay.admission, first_admitted.admission);
    assert_eq!(first_admission_replay.attempt, first_admitted.attempt);

    let second_proposal = proposal(
        &fixture,
        &fixture.repository,
        campaign,
        &request,
        ChoiceValue::Boolean(true),
        2,
    )?;
    let second_issued = fixture.repository.issue_proposal(
        campaign,
        first_admitted.new_snapshot,
        &second_proposal,
    )?;
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&fixture.repository, &request, &second_proposal)?;
    let second_admitted = fixture.repository.admit_proposal(
        campaign,
        second_issued.new_snapshot,
        second_issued.proposal,
        &second_selection,
        &second_path,
        &second_attempt,
    )?;

    let first_observation = observation(
        &fixture,
        &first_admitted,
        &first_path,
        request.opportunity(),
        "shuffled-first",
    )?;
    let second_observation = observation(
        &fixture,
        &second_admitted,
        &second_path,
        request.opportunity(),
        "shuffled-second",
    )?;

    let (first_result, accepted_second_first) = if reverse_delivery {
        match fixture.repository.publish_observation(
            campaign,
            second_admitted.new_snapshot,
            &second_observation,
        ) {
            Ok(second_first) if mode == CampaignMode::Streaming => {
                let first = fixture.repository.publish_observation(
                    campaign,
                    second_first.new_snapshot,
                    &first_observation,
                )?;
                (first, true)
            }
            Err(CampaignRepositoryError::Integrity {
                reason: "strict-completion-order-gap",
            }) if mode == CampaignMode::Strict => {
                assert_eq!(
                    fixture.repository.head(campaign)?.snapshot_id(),
                    second_admitted.new_snapshot
                );
                let first = fixture.repository.publish_observation(
                    campaign,
                    second_admitted.new_snapshot,
                    &first_observation,
                )?;
                fixture.repository.publish_observation(
                    campaign,
                    first.new_snapshot,
                    &second_observation,
                )?;
                (first, false)
            }
            result => {
                return Err(format!("unexpected reverse completion result: {result:?}").into());
            }
        }
    } else {
        let first = fixture.repository.publish_observation(
            campaign,
            second_admitted.new_snapshot,
            &first_observation,
        )?;
        fixture.repository.publish_observation(
            campaign,
            first.new_snapshot,
            &second_observation,
        )?;
        (first, false)
    };

    let first_replay = fixture.repository.publish_observation(
        campaign,
        first_result.prior_snapshot,
        &first_observation,
    )?;
    assert!(first_replay.replayed);
    assert_eq!(first_replay.new_snapshot, first_result.new_snapshot);
    assert_eq!(first_replay.observation, first_result.observation);

    let settled = fixture.repository.head(campaign)?;
    let final_snapshot = settled.snapshot_id();
    let planning_view = settled.snapshot().planning_view().id()?;
    let mut driver = planner_driver(&fixture)?;
    let CampaignPlannerStepOutcome::Advanced {
        result,
        disposition: PlannerDisposition::NoWork,
    } = driver.step(campaign)?
    else {
        return Err("completed frontier did not settle with a no-work planner step".into());
    };

    Ok(CompletionRun {
        final_snapshot,
        planning_view,
        planner_step: result.step,
        accepted_second_first,
    })
}

#[test]
fn shuffled_completion_preserves_strict_steps_and_streaming_acceptance()
-> Result<(), Box<dyn Error>> {
    let strict_ordered = run_shuffled_completion(CampaignMode::Strict, false)?;
    let strict_reversed = run_shuffled_completion(CampaignMode::Strict, true)?;
    assert!(!strict_reversed.accepted_second_first);
    assert_eq!(
        strict_reversed.final_snapshot,
        strict_ordered.final_snapshot
    );
    assert_eq!(strict_reversed.planning_view, strict_ordered.planning_view);
    assert_eq!(strict_reversed.planner_step, strict_ordered.planner_step);

    let streaming_reversed = run_shuffled_completion(CampaignMode::Streaming, true)?;
    assert!(streaming_reversed.accepted_second_first);

    Ok(())
}

#[test]
fn progressive_source_waits_widens_exhausts_and_recovers_after_restart()
-> Result<(), Box<dyn Error>> {
    let generator = CandidateGeneratorSpec::new(
        PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 3,
            feedback_interval: 1,
        },
    )?;
    let generator_id = generator.id()?;
    let generators = BTreeMap::from([(generator_id, generator)]);
    let fixture = GateFixture::new(
        "progressive-frontier",
        CampaignMode::Strict,
        tree_search_explorer()?,
        &generators,
    )?;
    let campaign = "progressive-frontier";
    let head = fixture.create_funded_running(campaign, &generators, 64)?;
    let domain = integer_domain(8)?;
    let request = generated_integer_request(&fixture, &domain, generator_id, "progressive", 9)?;
    let requested = discover_and_submit(&fixture, campaign, head.snapshot_id(), &request)?;
    assert_eq!(
        requested.summary.validated_cardinality(),
        BranchAcceptanceCount::Exact(9)
    );

    let values = [0, 4, 8, 2, 6, 1, 3, 5, 7];
    let mut current = requested.new_snapshot;
    let mut observations = Vec::new();
    for (index, value) in values.iter().take(3).enumerate() {
        let (admitted, path) = issue_and_admit(
            &fixture,
            &fixture.repository,
            campaign,
            &request,
            current,
            ChoiceValue::Integer(IntegerValue::Unsigned(*value)),
            index as u64 + 1,
        )?;
        current = admitted.new_snapshot;
        observations.push(observation(
            &fixture,
            &admitted,
            &path,
            request.opportunity(),
            &format!("progressive-{index}"),
        )?);
    }

    let request_id = request.id()?;
    let expansion =
        fixture
            .repository
            .project_finite_expansion(current, request.branch_point(), None, 16)?;
    assert_eq!(
        fixture
            .repository
            .load_expansion_state(expansion)?
            .continuations()
            .get(&request_id),
        Some(&ContinuationState::WaitingForFeedback(FeedbackWait::new(
            0, 1
        )?))
    );
    let waiting_restart = CampaignRepository::with_component_authorities(
        fixture.blobs.clone(),
        fixture.refs.clone(),
        fixture.planner_authority.clone(),
        fixture.debugger_authority.clone(),
    )?;
    let rebuilt_wait =
        waiting_restart.project_finite_expansion(current, request.branch_point(), None, 16)?;
    assert_eq!(
        waiting_restart
            .load_expansion_state(rebuilt_wait)?
            .continuations()
            .get(&request_id),
        Some(&ContinuationState::WaitingForFeedback(FeedbackWait::new(
            0, 1
        )?))
    );

    let mut credited = 0_usize;
    for (index, value) in values.iter().enumerate().skip(3) {
        let required_visits = index - 2;
        while credited < required_visits {
            let observed = fixture.repository.publish_observation(
                campaign,
                current,
                &observations[credited],
            )?;
            current = observed.new_snapshot;
            credited += 1;
        }

        let ready = fixture.repository.project_finite_expansion(
            current,
            request.branch_point(),
            None,
            16,
        )?;
        assert_eq!(
            fixture
                .repository
                .load_expansion_state(ready)?
                .continuations()
                .get(&request_id),
            Some(&ContinuationState::Ready)
        );

        let restarted_ready = (index == 3)
            .then(|| {
                CampaignRepository::with_component_authorities(
                    fixture.blobs.clone(),
                    fixture.refs.clone(),
                    fixture.planner_authority.clone(),
                    fixture.debugger_authority.clone(),
                )
            })
            .transpose()?;
        let generation_owner = restarted_ready.as_ref().unwrap_or(&fixture.repository);
        if index == 3 {
            let cold_ready = generation_owner.project_finite_expansion(
                current,
                request.branch_point(),
                None,
                16,
            )?;
            assert_eq!(
                generation_owner
                    .load_expansion_state(cold_ready)?
                    .continuations()
                    .get(&request_id),
                Some(&ContinuationState::Ready)
            );
        }

        let (admitted, path) = issue_and_admit(
            &fixture,
            generation_owner,
            campaign,
            &request,
            current,
            ChoiceValue::Integer(IntegerValue::Unsigned(*value)),
            index as u64 + 1,
        )?;
        current = admitted.new_snapshot;
        observations.push(observation(
            &fixture,
            &admitted,
            &path,
            request.opportunity(),
            &format!("progressive-{index}"),
        )?);

        let state = fixture.repository.project_finite_expansion(
            current,
            request.branch_point(),
            None,
            16,
        )?;
        let state = fixture.repository.load_expansion_state(state)?;
        if index + 1 == values.len() {
            assert_eq!(
                state.continuations().get(&request_id),
                Some(&ContinuationState::Exhausted)
            );
        } else {
            assert!(matches!(
                state.continuations().get(&request_id),
                Some(ContinuationState::WaitingForFeedback(_))
            ));
        }
    }

    let restarted = CampaignRepository::with_component_authorities(
        fixture.blobs.clone(),
        fixture.refs.clone(),
        fixture.planner_authority.clone(),
        fixture.debugger_authority.clone(),
    )?;
    let rebuilt = restarted.project_finite_expansion(current, request.branch_point(), None, 16)?;
    assert_eq!(
        restarted
            .load_expansion_state(rebuilt)?
            .continuations()
            .get(&request_id),
        Some(&ContinuationState::Exhausted)
    );

    Ok(())
}
