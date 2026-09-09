//! Statistical campaign policy and estimator regressions.

use super::*;
use crate::repository::projection::weighted_categorical_draw;
use std::sync::Arc;

#[derive(Clone, Copy)]
struct StatisticalPlannerSupervisor;

impl crate::PlannerExecutionSupervisor<CanonicalFrontierPlanner> for StatisticalPlannerSupervisor {
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        engine: &mut CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<crate::SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let measured_fuel = request.invocation().scan_page().input_objects() + 1;
        Ok(crate::SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

type StatisticalPlannerService =
    crate::AuthorizedPlannerService<CanonicalFrontierPlanner, StatisticalPlannerSupervisor>;

fn statistical_planner_driver(
    repository: Arc<CampaignRepository>,
    authority: PlannerAuthorityKey,
) -> crate::CampaignPlannerDriver<StatisticalPlannerService> {
    let basis = repository
        .publish_canonical_frontier_planner_basis()
        .expect("publish statistical planner basis");
    let (engine, artifact, initial_state) = basis.into_parts();
    let planner = crate::PlannerClient::new(
        crate::AuthorizedPlannerService::new(
            CanonicalFrontierPlanner,
            StatisticalPlannerSupervisor,
            authority.clone(),
        ),
        authority,
    );
    crate::CampaignPlannerDriver::new(
        repository,
        planner,
        engine,
        artifact,
        initial_state,
        16,
        PlanningBudget::new(1, 1, 16, 8_192, 100).expect("statistical planner budget"),
    )
    .expect("statistical planner driver")
    .require_exhaustive_policy()
}

fn drive_statistical_request(
    driver: &mut crate::CampaignPlannerDriver<StatisticalPlannerService>,
    repository: &CampaignRepository,
    campaign: &str,
) -> (PlannerStepResult, BranchRequest) {
    let outcome = driver.step(campaign).expect("issue statistical request");
    let crate::CampaignPlannerStepOutcome::Advanced {
        result,
        disposition:
            PlannerDisposition::Issue {
                issued_branch_requests,
                issued_proposals,
                ..
            },
    } = outcome
    else {
        panic!("statistical request issue: {outcome:?}")
    };
    assert_eq!(issued_branch_requests.len(), 1);
    assert!(issued_proposals.is_empty());

    let request = repository
        .read_branch_request(issued_branch_requests[0].content_id())
        .expect("load statistical request");
    (result, request)
}

fn drive_statistical_proposal(
    driver: &mut crate::CampaignPlannerDriver<StatisticalPlannerService>,
    repository: &CampaignRepository,
    campaign: &str,
) -> (PlannerStepResult, Proposal) {
    let outcome = driver.step(campaign).expect("admit statistical proposal");
    let crate::CampaignPlannerStepOutcome::Advanced {
        result,
        disposition:
            PlannerDisposition::Issue {
                issued_branch_requests,
                issued_proposals,
                ..
            },
    } = outcome
    else {
        panic!("statistical proposal admission: {outcome:?}")
    };
    assert!(issued_branch_requests.is_empty());
    assert_eq!(issued_proposals.len(), 1);

    let proposal = repository
        .load_proposal(issued_proposals[0])
        .expect("load statistical proposal");
    (result, proposal)
}

fn model(label: &str) -> ProbabilityModelId {
    ProbabilityModelId::from_hash(CampaignHash::derive(
        "test.statistical-model",
        label.as_bytes(),
    ))
}

fn content_id(kind: ObjectKind, schema_version: u32, label: &str) -> ContentId {
    ContentId::for_bytes(kind, schema_version, label.as_bytes())
}

fn distribution(
    target_false: u64,
    target_true: u64,
    proposal_false: u64,
    proposal_true: u64,
) -> crate::StatisticalDistribution {
    crate::StatisticalDistribution::new(
        BTreeMap::from([
            (ChoiceValue::Boolean(false), target_false),
            (ChoiceValue::Boolean(true), target_true),
        ]),
        BTreeMap::from([
            (ChoiceValue::Boolean(false), proposal_false),
            (ChoiceValue::Boolean(true), proposal_true),
        ]),
    )
    .expect("statistical distribution")
}

fn one_draw_design(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
) -> crate::StatisticalSamplingDesign {
    let model = model("one-draw");
    let distribution = distribution(1, 3, 3, 1);
    let template = modeled_branch_request(
        repository,
        lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "one-draw",
        model,
        distribution.target_masses().clone(),
    );
    let opportunity = repository
        .load_choice_opportunity(template.opportunity())
        .expect("one-draw opportunity");
    crate::StatisticalSamplingDesign::new(
        BTreeMap::from([(model, distribution)]),
        BTreeMap::from([(
            0,
            crate::StatisticalDrawPlan::new(None, &opportunity, model, StopCondition::NextChoice)
                .expect("one-draw plan"),
        )]),
        BTreeSet::from([0]),
    )
    .expect("one-draw design")
}

fn statistical_policy(
    base: &CampaignPolicy,
    design: crate::StatisticalSamplingDesign,
    retention: RetentionPolicy,
) -> CampaignPolicy {
    statistical_policy_with_seed(base, base.campaign_seed(), design, retention)
}

fn statistical_policy_with_seed(
    base: &CampaignPolicy,
    campaign_seed: CampaignSeed,
    design: crate::StatisticalSamplingDesign,
    retention: RetentionPolicy,
) -> CampaignPolicy {
    CampaignPolicy::new(
        base.scenario(),
        campaign_seed,
        CampaignMode::Statistical,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 16,
        },
        base.choice_policies().clone(),
        base.objectives().clone(),
        base.guidance().clone(),
        base.stop_conditions().clone(),
        base.fairness(),
        retention,
        base.admits_scenario_defaults(),
    )
    .expect("statistical policy")
    .with_statistical_sampling_design(design)
    .expect("statistical design")
}

fn statistical_attempt(
    repository: &CampaignRepository,
    request: &BranchRequest,
    proposal: &Proposal,
    ancestors: &[crate::BranchPathSegment],
) -> (BranchPath, Attempt) {
    let opportunity = repository
        .load_choice_opportunity(request.opportunity())
        .expect("statistical opportunity");
    let domain = repository
        .load_choice_domain(request.domain())
        .expect("statistical domain");
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        request.branch_point(),
    )
    .expect("statistical selection");
    let crate::SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign branch selection")
    };
    let mut segments = ancestors.to_vec();
    segments.push(crate::BranchPathSegment::new(request.branch_point(), edge));
    let path = BranchPath::new(segments).expect("statistical path");
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: request.parent(),
            selection: selection.id().expect("statistical selection ID"),
        },
        path.id().expect("statistical path ID"),
        request.stop().clone(),
    )
    .expect("statistical attempt");
    (path, attempt)
}

// crucible-lint: allow rust-allow -- the test helper keeps the full transition basis explicit.
#[allow(clippy::too_many_arguments)]
fn publish_observation_for_attempt(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    campaign: &str,
    snapshot: CampaignSnapshotId,
    request: &BranchRequest,
    path: &BranchPath,
    attempt: &Attempt,
    label: &str,
) -> (ObservationResult, ConfigurationArtifactId, ConfigurationId) {
    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "test.statistical-child",
        label.as_bytes(),
    ));
    let child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            label.as_bytes().to_vec(),
        )
        .expect("publish statistical child");
    let measurements = repository
        .publish_measurement_set(&MeasurementSet::new(BTreeMap::new()).expect("measurements"))
        .expect("publish measurements");
    let properties = repository
        .publish_property_verdict_set(
            &PropertyVerdictSet::new(BTreeMap::new()).expect("properties"),
        )
        .expect("publish properties");
    let coverage = repository
        .publish_coverage_projection(
            &CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage"),
        )
        .expect("publish coverage");
    let observation = Observation::new(
        attempt.id().expect("statistical attempt ID"),
        child,
        child_content,
        path.id().expect("statistical path ID"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
        BTreeSet::from([request.opportunity()]),
    )
    .expect("statistical observation");
    let result = repository
        .publish_observation(campaign, snapshot, &observation)
        .expect("publish statistical observation");
    (result, child_content, child)
}

#[test]
fn statistical_policy_identity_is_immutable_for_live_and_cold_activation() {
    let (repository, lineage, base) = fixture();
    let design = one_draw_design(&repository, &lineage);
    let current = statistical_policy(&base, design.clone(), base.retention());
    let changed = statistical_policy(&base, design, RetentionPolicy::new(true, 2, true, true));
    assert_ne!(
        current.id().expect("current policy ID"),
        changed.id().expect("changed policy ID")
    );
    let published_current = repository
        .publish_policy(&current)
        .expect("publish current statistical policy");
    assert_eq!(
        published_current,
        current
            .id()
            .expect("published current policy ID")
            .content_id()
    );

    let genesis = repository
        .create(
            "statistical-policy-freeze",
            &lineage,
            &current,
            &BTreeMap::new(),
        )
        .expect("create statistical campaign");
    let changed_id = CampaignPolicyId::from_content_id(
        repository
            .publish_policy(&changed)
            .expect("publish changed policy"),
    )
    .expect("changed policy ID");
    let activate = command(
        "change-statistical-policy",
        genesis.snapshot_id(),
        CampaignControlAction::ActivatePolicy(changed_id),
    );
    assert!(matches!(
        repository.apply_control("statistical-policy-freeze", &activate),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical-policy-identity-is-immutable"
        })
    ));
    assert!(matches!(
        repository.derive_campaign(
            "statistical-policy-freeze",
            genesis.snapshot_id(),
            "statistical-policy-freeze-derived",
            Some(&changed),
        ),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "derived policy is incompatible with the source campaign"
        })
    ));

    let parent = repository
        .read_snapshot(genesis.content_id())
        .expect("statistical parent");
    let control = CampaignFact::ControlRequested(activate.clone());
    let control_content = repository.put_fact(&control).expect("put forged control");
    let mut accounting = repository
        .merkle
        .insert(
            parent.snapshot.roots().accounting,
            map_key_hash("accounting.command", activate.command.as_hash()),
            control_content,
        )
        .expect("forged command accounting");
    let activation = CampaignFact::PolicyActivated(
        PolicyActivation::new(current.id().expect("current policy ID"), changed_id)
            .expect("forged activation"),
    );
    let activation_content = repository
        .put_fact(&activation)
        .expect("put forged activation");
    accounting = repository
        .insert_fact(accounting, &activation, activation_content)
        .expect("forged activation accounting");
    let mut roots = parent.snapshot.roots();
    roots.accounting = accounting.content_id();
    let forged = CampaignSnapshot::successor(
        genesis.snapshot_id(),
        parent.snapshot.lineage(),
        changed_id,
        roots,
        CampaignFactId::from_content_id(control_content).expect("control fact ID"),
    )
    .expect("forged statistical policy successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged statistical successor");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical-policy-identity-is-immutable"
        })
    ));
}

#[test]
fn statistical_design_requires_static_exhaustive_policy_and_legacy_reports_fail_closed() {
    let (repository, lineage, base) = fixture();
    let design = one_draw_design(&repository, &lineage);
    for explorer in [
        ExplorerPolicy::Beam {
            width: 2,
            novelty_reserve: 1,
        },
        ExplorerPolicy::TreeSearch {
            puct: PuctPolicy::new(1_000_000, 1, 0),
            widening: None,
        },
    ] {
        let adaptive = CampaignPolicy::new(
            base.scenario(),
            base.campaign_seed(),
            CampaignMode::Statistical,
            explorer,
            base.choice_policies().clone(),
            base.objectives().clone(),
            base.guidance().clone(),
            base.stop_conditions().clone(),
            base.fairness(),
            base.retention(),
            base.admits_scenario_defaults(),
        )
        .expect("adaptive statistical policy without a sampling design");
        assert!(matches!(
            adaptive.with_statistical_sampling_design(design.clone()),
            Err(CampaignCodecError::InvalidValue {
                reason: "statistical sampling design requires static exhaustive policy"
            })
        ));
    }

    let legacy = CampaignPolicy::new(
        base.scenario(),
        base.campaign_seed(),
        CampaignMode::Statistical,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 16,
        },
        base.choice_policies().clone(),
        base.objectives().clone(),
        base.guidance().clone(),
        base.stop_conditions().clone(),
        base.fairness(),
        base.retention(),
        base.admits_scenario_defaults(),
    )
    .expect("legacy statistical policy");
    assert!(legacy.statistical_sampling_design().is_none());
    let genesis = repository
        .create(
            "legacy-statistical-report",
            &lineage,
            &legacy,
            &BTreeMap::new(),
        )
        .expect("create legacy statistical campaign");
    assert!(matches!(
        repository
            .project_statistical_estimate("legacy-statistical-report", genesis.snapshot_id(),),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical-report-policy-lacks-design"
        })
    ));
}

#[test]
fn two_edge_statistical_flight_reports_the_full_unequal_probability_product() {
    let (repository, lineage, base, _, planner_authority, _) = authorized_fixture();
    let root_model = model("two-edge-root");
    let leaf_model = model("two-edge-leaf");
    let root_distribution = distribution(1, 3, 3, 1);
    let leaf_distribution = distribution(2, 5, 5, 2);
    let root_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "statistical-bootstrap",
        root_model,
        root_distribution.target_masses().clone(),
    );
    let leaf_genesis_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "statistical-leaf",
        leaf_model,
        leaf_distribution.target_masses().clone(),
    );
    let root_opportunity = repository
        .load_choice_opportunity(root_template.opportunity())
        .expect("root opportunity");
    let leaf_opportunity = repository
        .load_choice_opportunity(leaf_genesis_template.opportunity())
        .expect("leaf opportunity");
    let design = crate::StatisticalSamplingDesign::new(
        BTreeMap::from([
            (root_model, root_distribution.clone()),
            (leaf_model, leaf_distribution.clone()),
        ]),
        BTreeMap::from([
            (
                0,
                crate::StatisticalDrawPlan::new(
                    None,
                    &root_opportunity,
                    root_model,
                    StopCondition::NextChoice,
                )
                .expect("root draw plan"),
            ),
            (
                1,
                crate::StatisticalDrawPlan::new(
                    Some(0),
                    &leaf_opportunity,
                    leaf_model,
                    StopCondition::NextChoice,
                )
                .expect("leaf draw plan"),
            ),
        ]),
        BTreeSet::from([1]),
    )
    .expect("two-edge design");
    let policy = statistical_policy(&base, design, base.retention());
    let campaign = "statistical-two-edge";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create funded statistical campaign");
    let discovered_root = repository
        .discover_choice_opportunity(
            campaign,
            genesis.snapshot_id(),
            lineage.genesis_content(),
            root_template.opportunity(),
        )
        .expect("discover root opportunity");
    repository
        .apply_control(
            campaign,
            &command(
                "resume-statistical-two-edge",
                discovered_root.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume statistical campaign");

    let repository = Arc::new(repository);
    let mut driver = statistical_planner_driver(Arc::clone(&repository), planner_authority);

    let root_request_outcome = driver
        .step(campaign)
        .expect("issue root statistical request");
    let crate::CampaignPlannerStepOutcome::Advanced {
        result: _root_requested,
        disposition:
            PlannerDisposition::Issue {
                issued_branch_requests,
                issued_proposals,
                ..
            },
    } = root_request_outcome
    else {
        panic!("root statistical request issue: {root_request_outcome:?}")
    };
    assert_eq!(issued_branch_requests.len(), 1);
    assert!(issued_proposals.is_empty());
    let root_request = repository
        .read_branch_request(issued_branch_requests[0].content_id())
        .expect("load root statistical request");

    let crate::CampaignPlannerStepOutcome::Advanced {
        result: root_admitted,
        disposition:
            PlannerDisposition::Issue {
                issued_branch_requests,
                issued_proposals,
                ..
            },
    } = driver.step(campaign).expect("admit root statistical draw")
    else {
        panic!("root statistical draw admission")
    };
    assert!(issued_branch_requests.is_empty());
    assert_eq!(issued_proposals.len(), 1);
    let root_proposal = repository
        .load_proposal(issued_proposals[0])
        .expect("load root statistical proposal");
    let (root_path, root_attempt) =
        statistical_attempt(repository.as_ref(), &root_request, &root_proposal, &[]);
    let (root_observed, root_child_content, root_child) = publish_observation_for_attempt(
        repository.as_ref(),
        &lineage,
        campaign,
        root_admitted.new_snapshot,
        &root_request,
        &root_path,
        &root_attempt,
        "two-edge-root-child",
    );

    let leaf_template = modeled_branch_request(
        repository.as_ref(),
        &lineage,
        root_child_content,
        root_child,
        "statistical-leaf",
        leaf_model,
        leaf_distribution.target_masses().clone(),
    );
    assert_eq!(
        leaf_template.opportunity(),
        leaf_opportunity.id().expect("leaf opportunity ID")
    );
    let _discovered = repository
        .discover_choice_opportunity(
            campaign,
            root_observed.new_snapshot,
            root_child_content,
            leaf_template.opportunity(),
        )
        .expect("discover leaf opportunity");

    let crate::CampaignPlannerStepOutcome::Advanced {
        result: _leaf_requested,
        disposition:
            PlannerDisposition::Issue {
                issued_branch_requests,
                issued_proposals,
                ..
            },
    } = driver
        .step(campaign)
        .expect("issue leaf statistical request")
    else {
        panic!("leaf statistical request issue")
    };
    assert_eq!(issued_branch_requests.len(), 1);
    assert!(issued_proposals.is_empty());
    let leaf_request = repository
        .read_branch_request(issued_branch_requests[0].content_id())
        .expect("load leaf statistical request");

    let crate::CampaignPlannerStepOutcome::Advanced {
        result: leaf_admitted,
        disposition:
            PlannerDisposition::Issue {
                issued_branch_requests,
                issued_proposals,
                ..
            },
    } = driver.step(campaign).expect("admit leaf statistical draw")
    else {
        panic!("leaf statistical draw admission")
    };
    assert!(issued_branch_requests.is_empty());
    assert_eq!(issued_proposals.len(), 1);
    let leaf_proposal = repository
        .load_proposal(issued_proposals[0])
        .expect("load leaf statistical proposal");
    let root_segments = root_path.segments().expect("root path segments");
    let (leaf_path, leaf_attempt) = statistical_attempt(
        repository.as_ref(),
        &leaf_request,
        &leaf_proposal,
        root_segments,
    );
    let (leaf_observed, _, _) = publish_observation_for_attempt(
        repository.as_ref(),
        &lineage,
        campaign,
        leaf_admitted.new_snapshot,
        &leaf_request,
        &leaf_path,
        &leaf_attempt,
        "two-edge-leaf-child",
    );

    let report = repository
        .project_statistical_estimate(campaign, leaf_observed.new_snapshot)
        .expect("project statistical report");
    assert_eq!(report.endpoints().len(), 1);
    let endpoint = &report.endpoints()[0];
    let root_evidence = root_proposal.statistical_evidence().expect("root evidence");
    let leaf_evidence = leaf_proposal.statistical_evidence().expect("leaf evidence");
    let expected_target = crate::StatisticalRational::new(
        u128::from(root_evidence.target_mass()),
        u128::from(root_evidence.target_total()),
    )
    .expect("root target probability")
    .checked_multiply(
        crate::StatisticalRational::new(
            u128::from(leaf_evidence.target_mass()),
            u128::from(leaf_evidence.target_total()),
        )
        .expect("leaf target probability"),
    )
    .expect("target product");
    let expected_proposal = crate::StatisticalRational::new(
        u128::from(root_evidence.proposal_mass()),
        u128::from(root_evidence.proposal_total()),
    )
    .expect("root proposal probability")
    .checked_multiply(
        crate::StatisticalRational::new(
            u128::from(leaf_evidence.proposal_mass()),
            u128::from(leaf_evidence.proposal_total()),
        )
        .expect("leaf proposal probability"),
    )
    .expect("proposal product");
    assert_eq!(endpoint.target_probability(), expected_target);
    assert_eq!(endpoint.proposal_probability(), expected_proposal);
    assert_eq!(
        endpoint.importance_weight(),
        expected_target
            .checked_divide(expected_proposal)
            .expect("full importance weight")
    );
    assert_eq!(
        report.diagnostics().effective_sample_size(),
        crate::StatisticalRational::new(1, 1).expect("unit ESS")
    );
    assert_eq!(
        report.diagnostics().concentration(),
        crate::StatisticalRational::new(1, 1).expect("unit concentration")
    );
}

#[test]
fn statistical_driver_issues_coordinates_before_branch_point_order() {
    let (repository, lineage, base, _, planner_authority, _) = authorized_fixture();
    let first_model = model("coordinate-order-first");
    let second_model = model("coordinate-order-second");
    let first_distribution = distribution(1, 1, 1, 1);
    let second_distribution = distribution(1, 1, 1, 1);
    let first_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "coordinate-order-first",
        first_model,
        first_distribution.target_masses().clone(),
    );
    let second_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "coordinate-order-second",
        second_model,
        second_distribution.target_masses().clone(),
    );
    let (coordinate_zero, coordinate_zero_model, coordinate_one, coordinate_one_model) =
        if first_template.branch_point() > second_template.branch_point() {
            (first_template, first_model, second_template, second_model)
        } else {
            (second_template, second_model, first_template, first_model)
        };
    assert!(coordinate_zero.branch_point() > coordinate_one.branch_point());

    let coordinate_zero_opportunity = repository
        .load_choice_opportunity(coordinate_zero.opportunity())
        .expect("coordinate-zero opportunity");
    let coordinate_one_opportunity = repository
        .load_choice_opportunity(coordinate_one.opportunity())
        .expect("coordinate-one opportunity");
    let design = crate::StatisticalSamplingDesign::new(
        BTreeMap::from([
            (coordinate_zero_model, first_distribution),
            (coordinate_one_model, second_distribution),
        ]),
        BTreeMap::from([
            (
                0,
                crate::StatisticalDrawPlan::new(
                    None,
                    &coordinate_zero_opportunity,
                    coordinate_zero_model,
                    StopCondition::NextChoice,
                )
                .expect("coordinate-zero draw"),
            ),
            (
                1,
                crate::StatisticalDrawPlan::new(
                    None,
                    &coordinate_one_opportunity,
                    coordinate_one_model,
                    StopCondition::NextChoice,
                )
                .expect("coordinate-one draw"),
            ),
        ]),
        BTreeSet::from([0, 1]),
    )
    .expect("opposite-order design");
    let policy = statistical_policy(&base, design, base.retention());
    let campaign = "statistical-coordinate-order";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create coordinate-order campaign");
    let first_discovery = repository
        .discover_choice_opportunity(
            campaign,
            genesis.snapshot_id(),
            lineage.genesis_content(),
            coordinate_zero.opportunity(),
        )
        .expect("discover coordinate-zero opportunity");
    let second_discovery = repository
        .discover_choice_opportunity(
            campaign,
            first_discovery.new_snapshot,
            lineage.genesis_content(),
            coordinate_one.opportunity(),
        )
        .expect("discover coordinate-one opportunity");
    repository
        .apply_control(
            campaign,
            &command(
                "resume-statistical-coordinate-order",
                second_discovery.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume coordinate-order campaign");

    let repository = Arc::new(repository);
    let mut driver = statistical_planner_driver(Arc::clone(&repository), planner_authority);
    let (_, first_request) = drive_statistical_request(&mut driver, repository.as_ref(), campaign);
    let CandidateSource::StatisticalFinite(first_source) = first_request.source() else {
        panic!("coordinate-zero statistical source")
    };
    assert_eq!(first_source.coordinate(), 0);
    drive_statistical_proposal(&mut driver, repository.as_ref(), campaign);

    let (_, second_request) = drive_statistical_request(&mut driver, repository.as_ref(), campaign);
    let CandidateSource::StatisticalFinite(second_source) = second_request.source() else {
        panic!("coordinate-one statistical source")
    };
    assert_eq!(second_source.coordinate(), 1);
    assert!(first_request.branch_point() > second_request.branch_point());
    drive_statistical_proposal(&mut driver, repository.as_ref(), campaign);
}

#[test]
fn duplicate_draws_reuse_one_observation_without_losing_sampling_multiplicity() {
    let (repository, lineage, base, _, planner_authority, _) = authorized_fixture();
    let draw_model = model("duplicate-draw");
    let draw_distribution = distribution(1, 3, 1, 1);
    let template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "duplicate-draw",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let opportunity = repository
        .load_choice_opportunity(template.opportunity())
        .expect("duplicate-draw opportunity");
    let design = crate::StatisticalSamplingDesign::new(
        BTreeMap::from([(draw_model, draw_distribution)]),
        BTreeMap::from([
            (
                0,
                crate::StatisticalDrawPlan::new(
                    None,
                    &opportunity,
                    draw_model,
                    StopCondition::NextChoice,
                )
                .expect("first duplicate draw"),
            ),
            (
                1,
                crate::StatisticalDrawPlan::new(
                    None,
                    &opportunity,
                    draw_model,
                    StopCondition::NextChoice,
                )
                .expect("second duplicate draw"),
            ),
        ]),
        BTreeSet::from([0, 1]),
    )
    .expect("duplicate-draw design");

    // Select a deterministic policy seed whose two fixed coordinates draw the
    // same value. This makes semantic-attempt deduplication part of the fixture.
    let policy = (0_u16..=u16::MAX)
        .find_map(|nonce| {
            let mut seed = [0_u8; 32];
            seed[..2].copy_from_slice(&nonce.to_be_bytes());
            let policy = statistical_policy_with_seed(
                &base,
                CampaignSeed::from_bytes(seed),
                design.clone(),
                base.retention(),
            );
            let digest = policy.id().ok()?.content_id().digest();
            let first = weighted_categorical_draw(digest, 0, 2).ok()?;
            let second = weighted_categorical_draw(digest, 1, 2).ok()?;
            (first == second).then_some(policy)
        })
        .expect("a duplicate fixed draw in the bounded seed space");
    let campaign = "statistical-duplicate-draw";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create duplicate-draw campaign");
    let discovered = repository
        .discover_choice_opportunity(
            campaign,
            genesis.snapshot_id(),
            lineage.genesis_content(),
            template.opportunity(),
        )
        .expect("discover duplicate-draw opportunity");
    repository
        .apply_control(
            campaign,
            &command(
                "resume-statistical-duplicate-draw",
                discovered.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume duplicate-draw campaign");

    let repository = Arc::new(repository);
    let mut driver = statistical_planner_driver(Arc::clone(&repository), planner_authority);
    let ready = repository
        .head(campaign)
        .expect("ready duplicate-draw head");
    assert!(matches!(
        repository.project_statistical_estimate(campaign, ready.snapshot_id()),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical-report-draw-request-is-missing"
        })
    ));

    let planner_basis = repository
        .publish_canonical_frontier_planner_basis()
        .expect("publish forged-basis planner support");
    let (engine, artifact, state) = planner_basis.into_parts();
    let invocation = repository
        .prepare_planner_invocation(
            campaign,
            ready.snapshot_id(),
            &engine,
            &artifact,
            &state,
            None,
            16,
            PlanningBudget::new(1, 1, 16, 8_192, 100).expect("forged-basis planner budget"),
        )
        .expect("prepare forged-basis invocation");
    let valid_request = repository
        .build_planner_request(
            ready.snapshot_id(),
            invocation.id().expect("forged-basis invocation ID"),
        )
        .expect("build valid statistical planner request");
    let valid_basis = valid_request
        .statistical_request_basis()
        .expect("valid statistical request basis");
    let forged_basis = crate::StatisticalRequestBasis::new(
        valid_basis.coordinate() + 1,
        valid_basis.parent(),
        valid_basis.configuration(),
    );
    let forged_request = PlannerRequest::new_with_statistical_request_basis(
        valid_request.expected_snapshot(),
        valid_request.invocation().clone(),
        valid_request.engine().clone(),
        valid_request.policy_artifact().clone(),
        valid_request.policy().clone(),
        valid_request.planner_state().clone(),
        *valid_request.input_view(),
        Some(forged_basis),
        valid_request.input_bundle().clone(),
    )
    .expect("structurally valid forged statistical basis");
    assert!(matches!(
        repository.validate_planner_request_inputs(&forged_request),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-request-statistical-basis-mismatch"
        })
    ));

    let (first_requested, first_request) =
        drive_statistical_request(&mut driver, repository.as_ref(), campaign);
    assert!(matches!(
        repository.project_statistical_estimate(campaign, first_requested.new_snapshot),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical-report-draw-proposal-is-missing"
        })
    ));
    let (first_admitted, first_proposal) =
        drive_statistical_proposal(&mut driver, repository.as_ref(), campaign);
    assert!(matches!(
        repository.project_statistical_estimate(campaign, first_admitted.new_snapshot),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical-report-draw-observation-is-missing"
        })
    ));
    let (first_path, first_attempt) =
        statistical_attempt(repository.as_ref(), &first_request, &first_proposal, &[]);
    let (first_observed, _, _) = publish_observation_for_attempt(
        repository.as_ref(),
        &lineage,
        campaign,
        first_admitted.new_snapshot,
        &first_request,
        &first_path,
        &first_attempt,
        "duplicate-draw-child",
    );

    let changed_design = crate::StatisticalSamplingDesign::new(
        design.distributions().clone(),
        design.draws().clone(),
        BTreeSet::from([0]),
    )
    .expect("changed endpoint subset");
    let changed_policy = statistical_policy_with_seed(
        &base,
        policy.campaign_seed(),
        changed_design,
        base.retention(),
    );
    let changed_policy_id = CampaignPolicyId::from_content_id(
        repository
            .publish_policy(&changed_policy)
            .expect("publish changed endpoint policy"),
    )
    .expect("changed endpoint policy ID");
    assert!(matches!(
        repository.apply_control(
            campaign,
            &command(
                "change-statistical-endpoints-after-observation",
                first_observed.new_snapshot,
                CampaignControlAction::ActivatePolicy(changed_policy_id),
            ),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical-policy-identity-is-immutable"
        })
    ));

    let (_, second_request) = drive_statistical_request(&mut driver, repository.as_ref(), campaign);
    let (second_admitted, second_proposal) =
        drive_statistical_proposal(&mut driver, repository.as_ref(), campaign);
    assert_ne!(
        first_request.id().expect("first request ID"),
        second_request.id().expect("second request ID")
    );
    assert_ne!(
        first_proposal.id().expect("first proposal ID"),
        second_proposal.id().expect("second proposal ID")
    );
    assert_eq!(first_proposal.value(), second_proposal.value());

    let head = repository.head(campaign).expect("duplicate-draw head");
    let loaded = repository
        .read_snapshot(head.content_id())
        .expect("duplicate-draw snapshot");
    let admission_for = |proposal: &Proposal| {
        let content = repository
            .merkle
            .get(
                loaded.snapshot.roots().accounting,
                map_key_content(
                    "accounting.proposal-admission",
                    proposal.id().expect("proposal ID").content_id(),
                ),
            )
            .expect("proposal-admission lookup")
            .expect("proposal admission");
        repository
            .read_attempt_admission(content)
            .expect("read proposal admission")
    };
    let first_admission = admission_for(&first_proposal);
    let second_admission = admission_for(&second_proposal);
    assert_eq!(first_admission.attempt(), second_admission.attempt());
    assert!(matches!(
        first_admission.role(),
        AttemptAdmissionRole::ExecutionBasis {
            cause: BranchRequestCause::Planner(_),
            ..
        }
    ));
    assert!(matches!(
        second_admission.role(),
        AttemptAdmissionRole::AdditionalCause { proposal }
            if proposal == second_proposal.id().expect("second proposal ID")
    ));

    let canonical_observation = repository
        .read_observation(first_observed.observation.content_id())
        .expect("canonical duplicate observation");
    let replay = repository
        .publish_observation(
            campaign,
            second_admitted.new_snapshot,
            &canonical_observation,
        )
        .expect("replay canonical duplicate observation");
    assert!(replay.replayed);

    let report_head = repository.head(campaign).expect("duplicate report head");
    let report = repository
        .project_statistical_estimate(campaign, report_head.snapshot_id())
        .expect("project duplicate-draw report");
    assert_eq!(report.endpoints().len(), 2);
    assert_eq!(report.endpoints()[0].coordinate(), 0);
    assert_eq!(report.endpoints()[1].coordinate(), 1);
    assert_eq!(
        report.endpoints()[0].observation(),
        report.endpoints()[1].observation()
    );
    assert_eq!(
        report.endpoints()[0].attempt(),
        report.endpoints()[1].attempt()
    );
    assert_ne!(
        report.endpoints()[0].proposal(),
        report.endpoints()[1].proposal()
    );
    assert_eq!(
        report.diagnostics().effective_sample_size(),
        crate::StatisticalRational::new(2, 1).expect("two draw multiplicity")
    );

    let AttemptAdmissionRole::ExecutionBasis {
        admission_ordinal, ..
    } = first_admission.role()
    else {
        panic!("first draw execution basis")
    };
    let operator_cause = BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
        CampaignHash::derive("test.statistical-intervention", b"duplicate-draw"),
    ));
    let operator_request = BranchRequest::new(
        first_request.branch_point(),
        first_request.parent(),
        first_request.opportunity(),
        first_request.domain(),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("operator candidate source"),
        operator_cause,
        BranchBudget::new(2, 2).expect("operator branch budget"),
        first_request.stop().clone(),
    )
    .expect("operator request for identical attempt");
    repository
        .put_branch_request(&operator_request)
        .expect("put operator request");
    let operator_proposal = Proposal::new_for_request(
        operator_request.branch_point(),
        operator_request.id().expect("operator request ID"),
        operator_request.domain(),
        first_proposal.value().clone(),
        policy.id().expect("statistical policy ID"),
        None,
        1,
        first_proposal.guidance_basis(),
        &operator_request,
    )
    .expect("operator proposal for identical attempt");
    repository
        .put_proposal(&operator_proposal)
        .expect("put operator proposal");
    let intervention_basis = AttemptAdmission::new(
        first_admission.attempt(),
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(operator_proposal.id().expect("operator proposal ID")),
            cause: operator_cause,
            admission_ordinal,
        },
    );
    let intervention_content = repository
        .put_attempt_admission(&intervention_basis)
        .expect("put intervention basis");
    let accounting = repository
        .merkle
        .insert(
            loaded.snapshot.roots().accounting,
            map_key_content(
                "accounting.attempt-execution-basis",
                first_admission.attempt().content_id(),
            ),
            intervention_content,
        )
        .expect("replace execution basis with intervention");
    let mut forged_roots = loaded.snapshot.roots();
    forged_roots.accounting = accounting.content_id();
    let forged_snapshot = CampaignSnapshot::successor(
        head.snapshot_id(),
        loaded.snapshot.lineage(),
        loaded.snapshot.active_policy(),
        forged_roots,
        loaded.snapshot.transition().expect("head transition"),
    )
    .expect("forged intervention snapshot");
    let forged_loaded = LoadedSnapshot {
        envelope: loaded.envelope,
        snapshot: forged_snapshot,
    };
    let intervention_result =
        repository.validate_statistical_attempt_basis(&forged_loaded, first_admission.attempt());
    assert!(
        matches!(
            intervention_result,
            Err(CampaignRepositoryError::Integrity {
                reason: "statistical-attempt-execution-basis-is-intervention"
            })
        ),
        "unexpected intervention result: {intervention_result:?}"
    );
}

#[test]
fn ordinary_and_self_normalized_event_estimates_keep_distinct_denominators() {
    let observation_in =
        ObservationId::from_content_id(content_id(ObjectKind::Observation, 1, "event-in"))
            .expect("event-in observation ID");
    let observation_out =
        ObservationId::from_content_id(content_id(ObjectKind::Observation, 1, "event-out"))
            .expect("event-out observation ID");
    let endpoint = |coordinate, observation, weight| {
        crate::StatisticalEndpointEstimate::new(
            coordinate,
            ProposalId::from_content_id(content_id(
                ObjectKind::CampaignFact,
                1,
                &format!("proposal-{coordinate}"),
            ))
            .expect("proposal ID"),
            AttemptId::from_content_id(content_id(
                ObjectKind::CampaignFact,
                1,
                &format!("attempt-{coordinate}"),
            ))
            .expect("attempt ID"),
            observation,
            BranchPathId::from_content_id(content_id(
                ObjectKind::CampaignFact,
                2,
                &format!("path-{coordinate}"),
            ))
            .expect("path ID"),
            weight,
            crate::StatisticalRational::new(1, 1).expect("proposal probability"),
            weight,
        )
    };
    let report = crate::StatisticalEstimateReport::new(
        CampaignSnapshotId::from_content_id(content_id(
            ObjectKind::CampaignSnapshot,
            2,
            "snapshot",
        ))
        .expect("snapshot ID"),
        CampaignPolicyId::from_content_id(content_id(ObjectKind::Policy, 3, "policy"))
            .expect("policy ID"),
        vec![
            endpoint(
                0,
                observation_in,
                crate::StatisticalRational::new(2, 1).expect("weight two"),
            ),
            endpoint(
                1,
                observation_out,
                crate::StatisticalRational::new(1, 1).expect("weight one"),
            ),
        ],
        crate::StatisticalWeightDiagnostics::new(
            crate::StatisticalRational::new(2, 3).expect("concentration"),
            crate::StatisticalRational::new(9, 5).expect("ESS"),
        ),
    );
    let event = BTreeSet::from([observation_in]);

    assert_eq!(
        report.estimate_event(&event).expect("ordinary estimate"),
        crate::StatisticalRational::new(1, 1).expect("ordinary expected")
    );
    assert_eq!(
        report
            .estimate_event_self_normalized(&event)
            .expect("self-normalized estimate"),
        crate::StatisticalRational::new(2, 3).expect("self-normalized expected")
    );
}
