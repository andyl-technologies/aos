//! Verifies strict campaign planner replay through the public coordinator API.
//!
//! The fixture rebuilds the planner driver from authenticated repository state
//! before every step. Two independent stores receive the same canonical facts
//! with different worker-delivery order, and every accepted planner step must
//! retain the same identity and body.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::sync::Arc;

use crucible_campaign::{
    Attempt, AttemptId, AttemptStart, BooleanDomain, BranchBudget, BranchPath, BranchPathSegment,
    BranchRequest, BranchRequestCause, BudgetGrant, CampaignCodecError, CampaignCommandId,
    CampaignControlAction, CampaignHash, CampaignLineage, CampaignMode, CampaignPlannerDriver,
    CampaignPlannerDriverConfigError, CampaignPlannerStepOutcome, CampaignPolicy,
    CampaignRepository, CampaignRepositoryError, CampaignSeed, CampaignSnapshotId, CandidateSource,
    CanonicalFrontierPlanner, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
    ChoiceOpportunity, ChoiceSource, ChoiceValue, ControlRequest, CoverageProjection,
    DebuggerAuthorityKey, ExactRational, ExplorerPolicy, FairnessPolicy, MeasurementSet,
    Observation, PlannerAuthorityKey, PlannerDisposition, PlannerExecutionSupervisor,
    PlannerRequest, PlannerStepId, PlanningBudget, ProgressiveWideningPolicy, PropertyVerdictSet,
    Proposal, PuctPolicy, PurePlannerEngine, RetentionPolicy, SelectableDeclaration, Selection,
    SelectionOrigin, StopCondition, StopOutcome, SupervisedPlannerExecution,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

const CAMPAIGN: &str = "strict-planner-replay";

struct ReplayFixture {
    repository: CampaignRepository,
    blobs: Arc<MemoryBlobBackend>,
    refs: Arc<MemoryRefBackend>,
    lineage: CampaignLineage,
    policy: CampaignPolicy,
    planner_authority: PlannerAuthorityKey,
    debugger_authority: DebuggerAuthorityKey,
}

impl ReplayFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let blobs = Arc::new(MemoryBlobBackend::new(
            "strict-campaign-planner-replay",
            64 * 1024 * 1024,
        ));
        let refs = Arc::new(MemoryRefBackend::new());
        let planner_authority = PlannerAuthorityKey::from_bytes([0x91; 32])?;
        let debugger_authority = DebuggerAuthorityKey::from_bytes([0x92; 32])?;
        let repository = CampaignRepository::with_component_authorities(
            blobs.clone(),
            refs.clone(),
            planner_authority.clone(),
            debugger_authority.clone(),
        )?;

        let scenario = crucible_campaign::ScenarioDefId::from_hash(hash("scenario"));
        let genesis = crucible_campaign::ConfigurationId::from_hash(hash("genesis"));
        let scenario_content = repository.publish_scenario_artifact(
            scenario,
            1,
            b"strict planner replay scenario".to_vec(),
        )?;
        let genesis_content = repository.publish_configuration_artifact(
            scenario,
            scenario_content,
            genesis,
            1,
            b"strict planner replay genesis".to_vec(),
        )?;
        let lineage = CampaignLineage::new(
            scenario,
            scenario_content,
            genesis,
            genesis_content,
            "crucible-campaign-replay-gate",
            "qemu-campaign-replay-gate",
            BTreeMap::from([(String::from("control"), 1)]),
            1,
            1,
        )?;
        let policy = CampaignPolicy::new(
            scenario,
            CampaignSeed::from_bytes([0x93; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(ProgressiveWideningPolicy::new(
                    ExactRational::new(1, 1)?,
                    ExactRational::new(1, 2)?,
                    1,
                    16,
                    1,
                )?),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
            BTreeMap::new(),
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

    fn create_funded_running(&self) -> Result<CampaignSnapshotId, CampaignRepositoryError> {
        let created =
            self.repository
                .create(CAMPAIGN, &self.lineage, &self.policy, &BTreeMap::new())?;
        let funded = self.repository.apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: command_id("fund"),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(BudgetGrant::new(16, 16)?),
            },
        )?;
        let resumed = self.repository.apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: command_id("resume"),
                expected_snapshot: funded.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )?;
        Ok(resumed.new_snapshot)
    }

    fn restarted_repository(&self) -> Result<CampaignRepository, CampaignRepositoryError> {
        CampaignRepository::with_component_authorities(
            self.blobs.clone(),
            self.refs.clone(),
            self.planner_authority.clone(),
            self.debugger_authority.clone(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AcceptedPlannerStep {
    id: PlannerStepId,
    prior_snapshot: CampaignSnapshotId,
    new_snapshot: CampaignSnapshotId,
    body: Vec<u8>,
    invocation: crucible_campaign::PlannerInvocationId,
    request_digest: CampaignHash,
    input_view: crucible_campaign::CampaignViewId,
    next_state: crucible_campaign::PlannerStateId,
    disposition: PlannerDisposition,
}

struct StrictReplayRun {
    steps: Vec<AcceptedPlannerStep>,
    final_snapshot: CampaignSnapshotId,
    rejected_completion_gap: bool,
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

#[test]
fn strict_campaign_planner_reproduces_every_accepted_step() -> Result<(), Box<dyn Error>> {
    let ordered = run_strict_replay(false, false)?;
    let reordered = run_strict_replay(true, false)?;

    assert!(!ordered.rejected_completion_gap);
    assert!(reordered.rejected_completion_gap);
    assert_eq!(ordered.steps.len(), 3);
    assert_eq!(reordered.steps, ordered.steps);
    assert_eq!(reordered.final_snapshot, ordered.final_snapshot);

    let changed_input = run_strict_replay(false, true)?;
    assert_ne!(changed_input.steps, ordered.steps);

    Ok(())
}

fn run_strict_replay(
    reverse_completion_delivery: bool,
    change_authenticated_request: bool,
) -> Result<StrictReplayRun, Box<dyn Error>> {
    let fixture = ReplayFixture::new()?;
    assert_wrong_planner_authority_is_rejected(&fixture)?;
    let running = fixture.create_funded_running()?;
    let request = publish_branch_request(&fixture, running, change_authenticated_request)?;

    let mut steps = Vec::new();

    let (first_step, first_disposition) = advance_restarted_planner(&fixture)?;
    let first_proposal = only_issued_proposal(&fixture.repository, &first_disposition)?;
    let (first_attempt, first_path) =
        planner_attempt(&fixture.repository, &request, &first_proposal)?;
    steps.push(first_step);

    let (second_step, second_disposition) = advance_restarted_planner(&fixture)?;
    let second_proposal = only_issued_proposal(&fixture.repository, &second_disposition)?;
    assert_ne!(second_proposal.value(), first_proposal.value());
    let (second_attempt, second_path) =
        planner_attempt(&fixture.repository, &request, &second_proposal)?;
    let second_step_snapshot = second_step.new_snapshot;
    steps.push(second_step);

    let first_observation = observation(
        &fixture,
        first_attempt,
        &first_path,
        request.opportunity(),
        "first",
    )?;
    let second_observation = observation(
        &fixture,
        second_attempt,
        &second_path,
        request.opportunity(),
        "second",
    )?;
    let rejected_completion_gap = publish_completions(
        &fixture,
        &first_observation,
        &second_observation,
        second_step_snapshot,
        reverse_completion_delivery,
    )?;

    let (settled_step, disposition) = advance_restarted_planner(&fixture)?;
    assert_eq!(disposition, PlannerDisposition::NoWork);
    steps.push(settled_step);

    Ok(StrictReplayRun {
        steps,
        final_snapshot: fixture.repository.head(CAMPAIGN)?.snapshot_id(),
        rejected_completion_gap,
    })
}

fn publish_branch_request(
    fixture: &ReplayFixture,
    expected_snapshot: CampaignSnapshotId,
    change_authenticated_request: bool,
) -> Result<BranchRequest, Box<dyn Error>> {
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1)?);
    fixture.repository.publish_choice_domain(&domain)?;
    let declaration = SelectableDeclaration::new(
        "gate.campaign-replay.choice",
        ChoiceSource::Workload {
            producer: String::from("campaign-replay-gate"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new())?,
        BTreeSet::new(),
        true,
    )?;
    fixture.repository.publish_selectable(&declaration)?;
    let coordinate_label = if change_authenticated_request {
        "changed-coordinate"
    } else {
        "canonical-coordinate"
    };
    let opportunity = ChoiceOpportunity::new(
        fixture.lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: hash("scheduler-coordinate"),
            producer: hash(coordinate_label),
        },
        "strict-planner-choice",
        None,
    )?;
    fixture
        .repository
        .publish_choice_opportunity(&opportunity)?;
    let request = BranchRequest::new(
        opportunity.branch_point_id(fixture.lineage.genesis()),
        fixture.lineage.genesis_content(),
        opportunity.id()?,
        domain.id()?,
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))?,
        BranchRequestCause::Operator(command_id("request")),
        BranchBudget::new(2, 2)?,
        StopCondition::NextChoice,
    )?;
    let discovered = fixture.repository.discover_operator_choice_opportunity(
        CAMPAIGN,
        expected_snapshot,
        request.parent(),
        request.opportunity(),
    )?;
    fixture.repository.submit_operator_branch_request(
        CAMPAIGN,
        discovered.new_snapshot,
        &request,
    )?;
    Ok(request)
}

fn advance_restarted_planner(
    fixture: &ReplayFixture,
) -> Result<(AcceptedPlannerStep, PlannerDisposition), Box<dyn Error>> {
    let repository = Arc::new(fixture.restarted_repository()?);
    let basis = repository.publish_canonical_frontier_planner_basis()?;
    let (engine, artifact, initial_state) = basis.into_parts();
    let client = crucible_campaign::PlannerClient::new(
        crucible_campaign::AuthorizedPlannerService::new(
            CanonicalFrontierPlanner,
            DirectPlannerSupervisor,
            fixture.planner_authority.clone(),
        ),
        fixture.planner_authority.clone(),
    );
    let mut driver = CampaignPlannerDriver::new(
        repository.clone(),
        client,
        engine,
        artifact,
        initial_state,
        16,
        PlanningBudget::new(1, 1, 64, 64 * 1024, 10_000)?,
    )?
    .require_tree_search_policy();
    let CampaignPlannerStepOutcome::Advanced {
        result,
        disposition,
    } = driver.step(CAMPAIGN)?
    else {
        return Err("strict planner did not advance".into());
    };
    let step = repository.load_planner_step_at(result.new_snapshot, result.step)?;
    let accepted = AcceptedPlannerStep {
        id: result.step,
        prior_snapshot: result.prior_snapshot,
        new_snapshot: result.new_snapshot,
        body: step.canonical_bytes(),
        invocation: step.invocation(),
        request_digest: step.request_digest(),
        input_view: step.input_view(),
        next_state: step.next_state(),
        disposition: step.disposition().clone(),
    };
    assert_eq!(accepted.disposition, disposition);
    Ok((accepted, disposition))
}

fn only_issued_proposal(
    repository: &CampaignRepository,
    disposition: &PlannerDisposition,
) -> Result<Proposal, Box<dyn Error>> {
    let PlannerDisposition::Issue {
        issued_proposals, ..
    } = disposition
    else {
        return Err("strict planner did not issue a proposal".into());
    };
    let [proposal] = issued_proposals.as_slice() else {
        return Err("strict planner did not issue exactly one proposal".into());
    };
    Ok(repository.load_proposal(*proposal)?)
}

fn planner_attempt(
    repository: &CampaignRepository,
    request: &BranchRequest,
    proposal: &Proposal,
) -> Result<(AttemptId, BranchPath), Box<dyn Error>> {
    let opportunity = repository.load_choice_opportunity(request.opportunity())?;
    let domain = repository.load_choice_domain(request.domain())?;
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        request.branch_point(),
    )?;
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        return Err("planner proposal lost its campaign branch edge".into());
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
    Ok((attempt.id()?, path))
}

fn observation(
    fixture: &ReplayFixture,
    attempt: AttemptId,
    path: &BranchPath,
    opportunity: crucible_campaign::ChoiceOpportunityId,
    label: &str,
) -> Result<Observation, Box<dyn Error>> {
    let child = crucible_campaign::ConfigurationId::from_hash(hash(&format!("child-{label}")));
    let child_content = fixture.repository.publish_configuration_artifact(
        fixture.lineage.scenario(),
        fixture.lineage.scenario_content(),
        child,
        1,
        format!("strict planner child {label}").into_bytes(),
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
        attempt,
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

fn publish_completions(
    fixture: &ReplayFixture,
    first: &Observation,
    second: &Observation,
    expected_snapshot: CampaignSnapshotId,
    reverse_delivery: bool,
) -> Result<bool, Box<dyn Error>> {
    let rejected_gap = if reverse_delivery {
        assert!(matches!(
            fixture
                .repository
                .publish_observation(CAMPAIGN, expected_snapshot, second),
            Err(CampaignRepositoryError::Integrity {
                reason: "strict-completion-order-gap"
            })
        ));
        assert_eq!(
            fixture.repository.head(CAMPAIGN)?.snapshot_id(),
            expected_snapshot
        );
        true
    } else {
        false
    };
    let first_result =
        fixture
            .repository
            .publish_observation(CAMPAIGN, expected_snapshot, first)?;
    fixture
        .repository
        .publish_observation(CAMPAIGN, first_result.new_snapshot, second)?;
    Ok(rejected_gap)
}

fn assert_wrong_planner_authority_is_rejected(
    fixture: &ReplayFixture,
) -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(fixture.restarted_repository()?);
    let basis = repository.publish_canonical_frontier_planner_basis()?;
    let (engine, artifact, initial_state) = basis.into_parts();
    let wrong_authority = PlannerAuthorityKey::from_bytes([0xa1; 32])?;
    let client = crucible_campaign::PlannerClient::new(
        crucible_campaign::AuthorizedPlannerService::new(
            CanonicalFrontierPlanner,
            DirectPlannerSupervisor,
            wrong_authority.clone(),
        ),
        wrong_authority,
    );
    let result = CampaignPlannerDriver::new(
        repository,
        client,
        engine,
        artifact,
        initial_state,
        16,
        PlanningBudget::new(1, 1, 64, 64 * 1024, 10_000)?,
    );
    assert!(matches!(
        result,
        Err(CampaignPlannerDriverConfigError::AuthorityMismatch)
    ));
    Ok(())
}

fn command_id(action: &str) -> CampaignCommandId {
    CampaignCommandId::from_hash(hash(&format!("command-{action}")))
}

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("gate.campaign-replay", label.as_bytes())
}
