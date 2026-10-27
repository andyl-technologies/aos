//! Checked archive replay for positive statistical planner bases.

use super::*;
use crate::repository::tests::transfer::inspection_io::assert_checked_mirror_archive;

fn assert_canonical_planner_input(request: &PlannerRequest) {
    let canonical = crate::codec::encode(request);
    let decoded: PlannerRequest =
        crate::codec::decode(&canonical).expect("decode canonical retained planner request");
    assert_eq!(&decoded, request);

    // Minimal statistical requests can retain their complete basis by value and
    // therefore need no separate input-bundle objects. Any present object must
    // still decode to the exact content identity named by the canonical bundle.
    for id in request.input_bundle().object_ids() {
        let object = request
            .input_bundle()
            .object(id)
            .expect("decode retained planner bundle object")
            .expect("retained planner bundle object is embedded");
        assert_eq!(object.content_id(), id);
    }
}

fn retained_request(
    repository: &CampaignRepository,
    result: &PlannerStepResult,
) -> (ContentId, PlannerRequest) {
    let step = repository
        .load_planner_step_at(result.new_snapshot, result.step)
        .expect("load retained statistical planner step");
    let request = repository
        .load_planner_request(step.request())
        .expect("load retained statistical planner request");
    (step.request().content_id(), request)
}

#[test]
fn checked_mirror_replays_positive_finite_statistical_request_basis() {
    const CAMPAIGN: &str = "checked-finite-statistical-archive";

    let (repository, lineage, base, _, planner_authority, _) = authorized_fixture();
    let design = one_draw_design(&repository, &lineage);
    let opportunity = design
        .draw(0)
        .expect("one-draw statistical plan")
        .opportunity();
    let policy = statistical_policy(&base, design, base.retention());
    let genesis = repository
        .create_funded(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create finite statistical campaign");
    let discovered = repository
        .discover_choice_opportunity(
            CAMPAIGN,
            genesis.snapshot_id(),
            lineage.genesis_content(),
            opportunity,
        )
        .expect("discover finite statistical opportunity");
    repository
        .apply_control(
            CAMPAIGN,
            &command(
                "resume-checked-finite-statistical-archive",
                discovered.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume finite statistical campaign");

    let repository = Arc::new(repository);
    let mut driver = statistical_planner_driver(Arc::clone(&repository), planner_authority);
    let (issued, request) = drive_statistical_request(&mut driver, &repository, CAMPAIGN);
    let CandidateSource::StatisticalFinite(source) = request.source() else {
        panic!("finite statistical request source: {:?}", request.source())
    };
    assert_eq!(source.coordinate(), 0);

    let (request_content, retained) = retained_request(&repository, &issued);
    let basis = retained
        .statistical_request_basis()
        .expect("finite statistical request basis");
    assert_eq!(basis.coordinate(), source.coordinate());
    assert_eq!(basis.parent(), request.parent());
    assert_eq!(basis.parent(), lineage.genesis_content());
    assert_eq!(basis.configuration(), lineage.genesis());
    assert!(retained.smc_request_basis().is_none());
    assert_canonical_planner_input(&retained);

    assert_checked_mirror_archive(&repository, issued.new_snapshot, request_content);
}

#[test]
fn checked_mirror_replays_positive_smc_request_basis() {
    const CAMPAIGN: &str = "checked-smc-statistical-archive";

    let (repository, lineage, base, _, planner_authority, _) = authorized_fixture();
    let draw_model = model("checked-smc-archive");
    let draw_distribution = distribution(1, 3, 3, 1);
    let initial_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "checked-smc-initial",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let transition_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "checked-smc-transition",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let initial_opportunity = repository
        .load_choice_opportunity(initial_template.opportunity())
        .expect("load initial SMC opportunity");
    let transition_opportunity = repository
        .load_choice_opportunity(transition_template.opportunity())
        .expect("load transition SMC opportunity");
    let initial = crate::StatisticalSamplingDesign::new(
        BTreeMap::from([(draw_model, draw_distribution.clone())]),
        BTreeMap::from([(
            0,
            crate::StatisticalDrawPlan::new(
                None,
                &initial_opportunity,
                draw_model,
                StopCondition::NextChoice,
            )
            .expect("initial SMC draw"),
        )]),
        BTreeSet::from([0]),
    )
    .expect("one-particle initial SMC design");
    let selector = crate::SmcOpportunitySelector::new(
        transition_opportunity.declaration_semantics(),
        transition_opportunity.domain_semantics(),
        "checked-smc-transition",
        draw_model,
        StopCondition::NextChoice,
    )
    .expect("one-stage SMC selector");
    let sequential = crate::SequentialMonteCarloDesign::new(
        1,
        BTreeMap::from([(draw_model, draw_distribution)]),
        BTreeMap::from([(1, crate::SmcStagePlan::new(0, selector))]),
        crate::SmcResamplingPolicy::new(
            crate::SmcResamplingAlgorithm::SystematicV1,
            crate::ExactRational::new(1, 2).expect("SMC ESS threshold"),
        )
        .expect("SMC resampling policy"),
    )
    .expect("one-particle one-stage SMC design");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            base.scenario(),
            CampaignSeed::from_bytes([0x43; 32]),
            CampaignMode::Statistical,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 16,
            },
        ),
        CampaignPolicy::rules(
            base.choice_policies().clone(),
            base.objectives().clone(),
            base.guidance().clone(),
            base.stop_conditions().clone(),
            base.fairness(),
            base.retention(),
            base.admits_scenario_defaults(),
        ),
    )
    .expect("statistical SMC policy")
    .with_sequential_monte_carlo_design(initial, sequential)
    .expect("attach one-stage SMC design");

    let genesis = repository
        .create_funded(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create SMC campaign");
    let discovered = repository
        .discover_choice_opportunity(
            CAMPAIGN,
            genesis.snapshot_id(),
            lineage.genesis_content(),
            initial_template.opportunity(),
        )
        .expect("discover initial SMC opportunity");
    repository
        .apply_control(
            CAMPAIGN,
            &command(
                "resume-checked-smc-statistical-archive",
                discovered.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume SMC campaign");

    let repository = Arc::new(repository);
    let mut driver = statistical_planner_driver(Arc::clone(&repository), planner_authority);
    let (_, initial_request) = drive_statistical_request(&mut driver, &repository, CAMPAIGN);
    let (admitted, initial_proposal) =
        drive_statistical_proposal(&mut driver, &repository, CAMPAIGN);
    let (path, attempt) =
        statistical_attempt(&repository, &initial_request, &initial_proposal, &[]);
    let (_, child_content, child_configuration) = publish_observation_for_attempt_with(
        &repository,
        &lineage,
        CAMPAIGN,
        admitted.new_snapshot,
        &path,
        &attempt,
        "checked-smc-initial-child",
        StopOutcome::Reached(StopCondition::NextChoice),
        BTreeSet::from([transition_template.opportunity()]),
    );

    let (issued, request) = drive_statistical_request(&mut driver, &repository, CAMPAIGN);
    let CandidateSource::StatisticalSmc(source) = request.source() else {
        panic!("SMC request source: {:?}", request.source())
    };
    assert_eq!((source.stage(), source.slot()), (1, 0));

    let (request_content, retained) = retained_request(&repository, &issued);
    assert!(retained.statistical_request_basis().is_none());
    let basis = retained.smc_request_basis().expect("SMC request basis");
    assert_eq!(basis.generation(), source.generation());
    assert_eq!(basis.particle().generation(), source.stage());
    assert_eq!(basis.particle().slot(), source.slot());
    assert_eq!(basis.particle().id(), source.input_particle());
    assert_eq!(basis.parent(), request.parent());
    assert_eq!(basis.parent(), child_content);
    assert_eq!(basis.configuration(), child_configuration);
    assert_eq!(
        basis.opportunity().id().expect("SMC basis opportunity ID"),
        request.opportunity()
    );
    assert_eq!(
        basis.domain().id().expect("SMC basis domain ID"),
        request.domain()
    );
    assert_canonical_planner_input(&retained);

    assert_checked_mirror_archive(&repository, issued.new_snapshot, request_content);
}
