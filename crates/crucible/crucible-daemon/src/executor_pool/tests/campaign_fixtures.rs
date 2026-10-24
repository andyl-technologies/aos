//! Campaign policies and scenarios shared by executor-pool conformance cases.

use super::*;

pub(super) fn campaign_attempt_fixture(
    repository: &CampaignRepository,
    name: &str,
) -> (
    CampaignLineage,
    CampaignPolicy,
    BranchRequest,
    crucible_campaign::AttemptAdmissionResult,
    ObservationCandidate,
) {
    let scenario_form = minimal_campaign_scenario();
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("rational"),
        ExactRational::new(1, 2).expect("rational"),
        1,
        100,
        1,
    )
    .expect("widening");

    campaign_attempt_fixture_with_policy(
        repository,
        name,
        scenario_form,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        InterventionLearningPolicy::Exclude,
        BranchBudget::new(2, 2).expect("branch budget"),
    )
}

pub(super) fn campaign_attempt_fixture_with_policy(
    repository: &CampaignRepository,
    name: &str,
    scenario_form: ScenarioDefForm,
    explorer: ExplorerPolicy,
    objectives: BTreeMap<String, Objective>,
    intervention_learning: InterventionLearningPolicy,
    branch_budget: BranchBudget,
) -> (
    CampaignLineage,
    CampaignPolicy,
    BranchRequest,
    crucible_campaign::AttemptAdmissionResult,
    ObservationCandidate,
) {
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario_form).expect("scenario artifact");
    let scenario = scenario_artifact.scenario();
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario,
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("scenario artifact");
    let genesis_configuration = Configuration::genesis(scenario_form.scenario_def());
    let genesis_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &genesis_configuration.schedule)
            .expect("genesis configuration artifact");
    let genesis = genesis_artifact.configuration();
    let genesis_content = repository
        .publish_configuration_artifact(
            scenario,
            scenario_content,
            genesis,
            genesis_artifact.payload_schema(),
            genesis_artifact.payload().to_vec(),
        )
        .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-v1",
        "qemu-build-v1",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_artifact.payload_schema(),
        1,
    )
    .expect("lineage");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            explorer,
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            objectives,
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("policy");
    let policy = match intervention_learning {
        InterventionLearningPolicy::Exclude => policy,
        InterventionLearningPolicy::IncludeInGuidance => policy
            .with_intervention_learning_policy(intervention_learning)
            .expect("intervention-guided fixture policy"),
    };
    let created = repository
        .create(name, &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    repository
        .apply_control(
            name,
            &crucible_campaign::ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.executor-flight.budget.v1",
                    name.as_bytes(),
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    crucible_campaign::BudgetGrant::new(2, 2).expect("campaign allowance"),
                ),
            },
        )
        .expect("fund campaign");
    let created = repository.head(name).expect("funded head");

    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.executor-flight",
        ChoiceSource::Workload {
            producer: String::from("executor-flight"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from([String::from("executor-flight")]))
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
        scenario,
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("crucible.test.executor-flight.scheduler.v1", b"s"),
            producer: CampaignHash::derive("crucible.test.executor-flight.producer.v1", b"p"),
        },
        "executor-flight",
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let discovered = repository
        .discover_operator_choice_opportunity(
            name,
            created.snapshot_id(),
            genesis_content,
            opportunity.id().expect("opportunity id"),
        )
        .expect("discover opportunity");
    let request = BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(genesis),
            genesis_content,
            opportunity.id().expect("opportunity id"),
            domain.id().expect("domain id"),
        ),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.executor-flight.branch.v1",
            b"branch",
        ))),
        branch_budget,
        StopCondition::NextChoice,
    )
    .expect("branch request");
    let requested = repository
        .submit_operator_branch_request(name, discovered.new_snapshot, &request)
        .expect("submit branch request");
    let request_head = repository.head(name).expect("request head");
    let proposal = Proposal::new(
        request.branch_point(),
        request.id().expect("request id"),
        request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        None,
        1,
        request_head
            .snapshot()
            .planning_view()
            .id()
            .expect("planning view"),
    )
    .expect("proposal");
    let proposed = repository
        .issue_proposal(name, requested.new_snapshot, &proposal)
        .expect("issue proposal");
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        request.branch_point(),
    )
    .expect("selection");
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign branch selection")
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(request.branch_point(), edge)])
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
    let admitted = repository
        .admit_proposal(
            name,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit proposal");

    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "crucible.test.executor-flight.child.v1",
        name.as_bytes(),
    ));
    let child_artifact =
        ConfigurationArtifact::new(scenario, scenario_content, child, 1, b"child".to_vec())
            .expect("child artifact");
    let measurements = MeasurementSet::from_evaluation(
        CampaignHash::derive(
            "crucible.test.measurement-definitions.v1",
            b"executor flight",
        ),
        1,
        CampaignHash::derive(
            "crucible.test.measurement-evaluation.v1",
            b"executor flight",
        ),
        b"executor flight".to_vec(),
        BTreeSet::new(),
    )
    .expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        admitted.attempt,
        Observation::outcome(
            child,
            child_artifact.id().expect("child artifact id"),
            path.id().expect("path id"),
            StopOutcome::Reached(StopCondition::NextChoice),
            measurements.id().expect("measurement id"),
            properties.id().expect("properties id"),
            coverage.id().expect("coverage id"),
        ),
        BTreeSet::from([opportunity.id().expect("opportunity id")]),
    )
    .expect("observation");
    let candidate = ObservationCandidate::new(
        child_artifact,
        measurements,
        properties,
        coverage,
        vec![
            crucible_campaign::ChoiceDiscovery::new(declaration, domain, opportunity)
                .expect("choice discovery"),
        ],
        observation,
    )
    .expect("observation candidate");
    (lineage, policy, request, admitted, candidate)
}

pub(super) fn minimal_campaign_scenario() -> ScenarioDefForm {
    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty world");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(9),
    )
    .expect("minimal scenario")
}

pub(super) fn beam_objective_scenario() -> ScenarioDefForm {
    let base = crucible_engine::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let node = base
        .world()
        .vm_nodes()
        .first()
        .expect("happy-path VM")
        .id
        .clone();
    let measurements = MeasurementDefinitions::new(
        base.world(),
        base.plan(),
        base.properties(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("beam-window").expect("measurement ID"),
            begin: BoundarySelector::ScenarioGenesis,
            end: BoundarySelector::SchedulerQuiescence,
            timeout: None,
            cohort: CohortPolicy::All(vec![node]),
            metrics: vec![MetricDefinition {
                id: MetricId::parse("scheduler-events").expect("metric ID"),
                value_type: MetricValueType::UnsignedInteger,
                unit: UnitId::parse("events").expect("unit ID"),
                source: MetricSource::SchedulerEventCount,
                aggregation: Aggregation::Count,
            }],
        }],
    )
    .expect("Beam measurement definitions");

    ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        base.world(),
        base.plan(),
        base.properties(),
        &measurements,
        base.seed(),
        base.app_random_draw_cap(),
    )
    .expect("Beam objective scenario")
}
