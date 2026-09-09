//! Sequential Monte Carlo repository restart regressions.

use super::*;

fn smc_policy(
    base: &CampaignPolicy,
    initial: crate::StatisticalSamplingDesign,
    selector_opportunity: &ChoiceOpportunity,
    model: ProbabilityModelId,
    distribution: crate::StatisticalDistribution,
) -> CampaignPolicy {
    smc_policy_with_resampling(
        base,
        initial,
        selector_opportunity,
        model,
        distribution,
        CampaignSeed::from_bytes([0x53; 32]),
        crate::ExactRational::new(1, 2).expect("SMC ESS threshold"),
    )
}

// crucible-lint: allow rust-allow -- the fixture keeps every policy axis explicit at each call site.
#[allow(clippy::too_many_arguments)]
fn smc_policy_with_resampling(
    base: &CampaignPolicy,
    initial: crate::StatisticalSamplingDesign,
    selector_opportunity: &ChoiceOpportunity,
    model: ProbabilityModelId,
    distribution: crate::StatisticalDistribution,
    campaign_seed: CampaignSeed,
    effective_sample_size_threshold: crate::ExactRational,
) -> CampaignPolicy {
    let selector = crate::SmcOpportunitySelector::new(
        selector_opportunity.declaration_semantics(),
        selector_opportunity.domain_semantics(),
        "smc-next-stage",
        model,
        StopCondition::NextChoice,
    )
    .expect("SMC selector");
    let resampling = crate::SmcResamplingPolicy::new(
        crate::SmcResamplingAlgorithm::SystematicV1,
        effective_sample_size_threshold,
    )
    .expect("SMC resampling policy");
    let sequential = crate::SequentialMonteCarloDesign::new(
        2,
        BTreeMap::from([(model, distribution)]),
        BTreeMap::from([
            (1, crate::SmcStagePlan::new(0, selector.clone())),
            (2, crate::SmcStagePlan::new(1, selector)),
        ]),
        resampling,
    )
    .expect("SMC design");
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
        base.retention(),
        base.admits_scenario_defaults(),
    )
    .expect("statistical policy")
    .with_sequential_monte_carlo_design(initial, sequential)
    .expect("SMC policy")
}

struct StartedSmcCampaign {
    repository: Arc<CampaignRepository>,
    lineage: CampaignLineage,
    planner_authority: PlannerAuthorityKey,
    debugger_authority: DebuggerAuthorityKey,
    driver: crate::CampaignPlannerDriver<StatisticalPlannerService>,
    transition_opportunity: ChoiceOpportunityId,
    head: CampaignSnapshotId,
    paths_by_parent: BTreeMap<ConfigurationArtifactId, BranchPath>,
}

fn start_smc_campaign(campaign: &str, initial_stops: [StopOutcome; 2]) -> StartedSmcCampaign {
    let (repository, lineage, base, _, planner_authority, debugger_authority) =
        authorized_fixture();
    let draw_model = model("smc-initial");
    let draw_distribution = distribution(1, 3, 3, 1);
    let first_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "smc-initial-a",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let second_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "smc-initial-b",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let transition_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "smc-next-stage",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let first_opportunity = repository
        .load_choice_opportunity(first_template.opportunity())
        .expect("first initial opportunity");
    let second_opportunity = repository
        .load_choice_opportunity(second_template.opportunity())
        .expect("second initial opportunity");
    let transition_opportunity = repository
        .load_choice_opportunity(transition_template.opportunity())
        .expect("SMC transition opportunity");
    let initial = crate::StatisticalSamplingDesign::new(
        BTreeMap::from([(draw_model, draw_distribution.clone())]),
        BTreeMap::from([
            (
                0,
                crate::StatisticalDrawPlan::new(
                    None,
                    &first_opportunity,
                    draw_model,
                    StopCondition::NextChoice,
                )
                .expect("first initial draw"),
            ),
            (
                1,
                crate::StatisticalDrawPlan::new(
                    None,
                    &second_opportunity,
                    draw_model,
                    StopCondition::NextChoice,
                )
                .expect("second initial draw"),
            ),
        ]),
        BTreeSet::from([0, 1]),
    )
    .expect("initial SMC flight");
    let policy = smc_policy(
        &base,
        initial,
        &transition_opportunity,
        draw_model,
        draw_distribution,
    );
    launch_smc_campaign(
        repository,
        lineage,
        planner_authority,
        debugger_authority,
        campaign,
        policy,
        [first_template, second_template],
        transition_template,
        initial_stops,
    )
}

// crucible-lint: allow rust-allow -- the launch fixture exposes each independent repository and policy input.
#[allow(clippy::too_many_arguments)]
fn launch_smc_campaign(
    repository: CampaignRepository,
    lineage: CampaignLineage,
    planner_authority: PlannerAuthorityKey,
    debugger_authority: DebuggerAuthorityKey,
    campaign: &str,
    policy: CampaignPolicy,
    initial_templates: [BranchRequest; 2],
    transition_template: BranchRequest,
    initial_stops: [StopOutcome; 2],
) -> StartedSmcCampaign {
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create SMC campaign");
    let first_discovery = repository
        .discover_choice_opportunity(
            campaign,
            genesis.snapshot_id(),
            lineage.genesis_content(),
            initial_templates[0].opportunity(),
        )
        .expect("discover first initial opportunity");
    let second_discovery = repository
        .discover_choice_opportunity(
            campaign,
            first_discovery.new_snapshot,
            lineage.genesis_content(),
            initial_templates[1].opportunity(),
        )
        .expect("discover second initial opportunity");
    repository
        .apply_control(
            campaign,
            &command(
                "resume-statistical-smc",
                second_discovery.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume SMC campaign");

    let repository = Arc::new(repository);
    let mut driver = statistical_planner_driver(Arc::clone(&repository), planner_authority.clone());
    let mut head = repository
        .head(campaign)
        .expect("resumed SMC head")
        .snapshot_id();
    let mut paths_by_parent = BTreeMap::new();
    for (coordinate, stop) in initial_stops.into_iter().enumerate() {
        let (_, request) = drive_statistical_request(&mut driver, &repository, campaign);
        let CandidateSource::StatisticalFinite(source) = request.source() else {
            panic!("initial SMC request source: {:?}", request.source())
        };
        assert_eq!(source.coordinate(), coordinate as u64);

        let (admitted, proposal) = drive_statistical_proposal(&mut driver, &repository, campaign);
        let (path, attempt) = statistical_attempt(&repository, &request, &proposal, &[]);
        let (observed, child_content, _) = publish_observation_for_attempt_with(
            &repository,
            &lineage,
            campaign,
            admitted.new_snapshot,
            &path,
            &attempt,
            &format!("smc-initial-child-{coordinate}"),
            stop,
            BTreeSet::from([transition_template.opportunity()]),
        );
        paths_by_parent.insert(child_content, path);
        head = observed.new_snapshot;
    }

    StartedSmcCampaign {
        repository,
        lineage,
        planner_authority,
        debugger_authority,
        driver,
        transition_opportunity: transition_template.opportunity(),
        head,
        paths_by_parent,
    }
}

fn forced_duplicate_resampling_policy(
    base: &CampaignPolicy,
    initial: &crate::StatisticalSamplingDesign,
    transition_opportunity: &ChoiceOpportunity,
    model: ProbabilityModelId,
    distribution: &crate::StatisticalDistribution,
) -> (CampaignPolicy, crate::StatisticalGeneration, [u128; 2]) {
    (0_u16..=u16::MAX)
        .find_map(|nonce| {
            let mut seed_bytes = [0_u8; 32];
            seed_bytes[..2].copy_from_slice(&nonce.to_be_bytes());
            let campaign_seed = CampaignSeed::from_bytes(seed_bytes);
            let policy = smc_policy_with_resampling(
                base,
                initial.clone(),
                transition_opportunity,
                model,
                distribution.clone(),
                campaign_seed,
                crate::ExactRational::new(1, 1).ok()?,
            );
            let policy_id = policy.id().ok()?;
            let digest = policy_id.content_id().digest();
            let draws = [
                weighted_categorical_draw(digest, 0, 2).ok()?,
                weighted_categorical_draw(digest, 1, 2).ok()?,
            ];
            if draws[0] == draws[1]
                || smc_weighted_categorical_draw(digest, 1, 0, 2).ok()?
                    != smc_weighted_categorical_draw(digest, 1, 1, 2).ok()?
            {
                return None;
            }

            let endpoints = draws
                .iter()
                .enumerate()
                .map(|(coordinate, draw)| {
                    let (target, weight) = if *draw == 0 {
                        (
                            crate::StatisticalRational::new(1, 101).ok()?,
                            crate::StatisticalRational::new(2, 101).ok()?,
                        )
                    } else {
                        (
                            crate::StatisticalRational::new(100, 101).ok()?,
                            crate::StatisticalRational::new(200, 101).ok()?,
                        )
                    };
                    Some(crate::StatisticalEndpointEstimate::new(
                        coordinate as u64,
                        ProposalId::from_content_id(content_id(
                            ObjectKind::CampaignFact,
                            2,
                            &format!("forced-proposal-{coordinate}"),
                        ))
                        .ok()?,
                        AttemptId::from_content_id(content_id(
                            ObjectKind::CampaignFact,
                            3,
                            &format!("forced-attempt-{coordinate}"),
                        ))
                        .ok()?,
                        ObservationId::from_content_id(content_id(
                            ObjectKind::Observation,
                            8,
                            &format!("forced-observation-{coordinate}"),
                        ))
                        .ok()?,
                        BranchPathId::from_content_id(content_id(
                            ObjectKind::CampaignFact,
                            2,
                            &format!("forced-path-{coordinate}"),
                        ))
                        .ok()?,
                        target,
                        crate::StatisticalRational::new(1, 2).ok()?,
                        weight,
                    ))
                })
                .collect::<Option<Vec<_>>>()?;
            let report = crate::StatisticalEstimateReport::new(
                CampaignSnapshotId::from_content_id(content_id(
                    ObjectKind::CampaignSnapshot,
                    3,
                    "forced-resampling-snapshot",
                ))
                .ok()?,
                policy_id,
                endpoints,
                crate::StatisticalWeightDiagnostics::new(
                    crate::StatisticalRational::new(100, 101).ok()?,
                    crate::StatisticalRational::new(10_201, 10_001).ok()?,
                ),
            );
            let generation = crate::StatisticalGeneration::from_initial_report(
                policy_id,
                campaign_seed,
                policy.sequential_monte_carlo_design()?,
                &report,
            )
            .ok()?;
            let high_coordinate = draws.iter().position(|draw| *draw == 1)? as u64;
            (generation.resampled()
                && generation
                    .slots()
                    .iter()
                    .all(|particle| particle.source_coordinate() == high_coordinate))
            .then_some((policy, generation, draws))
        })
        .expect("a forced duplicate resampling seed in the bounded search space")
}

struct ForcedResamplingFixture {
    policy: CampaignPolicy,
    initial_templates: [BranchRequest; 2],
    transition_template: BranchRequest,
    expected_generation: crate::StatisticalGeneration,
    draws: [u128; 2],
}

fn forced_resampling_fixture(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    base: &CampaignPolicy,
) -> ForcedResamplingFixture {
    let draw_model = model("forced-resampling");
    let draw_distribution = distribution(1, 100, 1, 1);
    let first_template = modeled_branch_request(
        repository,
        lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "forced-resampling-first",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let second_template = modeled_branch_request(
        repository,
        lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "forced-resampling-second",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let transition_template = modeled_branch_request(
        repository,
        lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "smc-next-stage",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let first_opportunity = repository
        .load_choice_opportunity(first_template.opportunity())
        .expect("first forced-resampling opportunity");
    let second_opportunity = repository
        .load_choice_opportunity(second_template.opportunity())
        .expect("second forced-resampling opportunity");
    let transition_opportunity = repository
        .load_choice_opportunity(transition_template.opportunity())
        .expect("forced-resampling transition opportunity");
    let initial = crate::StatisticalSamplingDesign::new(
        BTreeMap::from([(draw_model, draw_distribution.clone())]),
        BTreeMap::from([
            (
                0,
                crate::StatisticalDrawPlan::new(
                    None,
                    &first_opportunity,
                    draw_model,
                    StopCondition::NextChoice,
                )
                .expect("first forced-resampling draw"),
            ),
            (
                1,
                crate::StatisticalDrawPlan::new(
                    None,
                    &second_opportunity,
                    draw_model,
                    StopCondition::NextChoice,
                )
                .expect("second forced-resampling draw"),
            ),
        ]),
        BTreeSet::from([0, 1]),
    )
    .expect("forced-resampling initial design");
    let (policy, expected_generation, draws) = forced_duplicate_resampling_policy(
        base,
        &initial,
        &transition_opportunity,
        draw_model,
        &draw_distribution,
    );
    ForcedResamplingFixture {
        policy,
        initial_templates: [first_template, second_template],
        transition_template,
        expected_generation,
        draws,
    }
}

fn execute_smc_transition(
    fixture: &mut StartedSmcCampaign,
    campaign: &str,
    stage: u32,
    slot: u32,
) -> ObservationId {
    let (_, request) =
        drive_statistical_request(&mut fixture.driver, &fixture.repository, campaign);
    let CandidateSource::StatisticalSmc(source) = request.source() else {
        panic!("SMC transition request source: {:?}", request.source())
    };
    assert_eq!((source.stage(), source.slot()), (stage, slot));

    let (admitted, proposal) =
        drive_statistical_proposal(&mut fixture.driver, &fixture.repository, campaign);
    assert!(proposal.statistical_evidence().is_some());
    let source_path = fixture
        .paths_by_parent
        .get(&request.parent())
        .expect("SMC transition source path");
    let ancestors = source_path.segments().expect("scoped SMC source path");
    let (path, attempt) = statistical_attempt(&fixture.repository, &request, &proposal, ancestors);
    let label = format!("smc-stage-{stage}-slot-{slot}");
    let (observed, child_content, _) = publish_observation_for_attempt_with(
        &fixture.repository,
        &fixture.lineage,
        campaign,
        admitted.new_snapshot,
        &path,
        &attempt,
        &label,
        StopOutcome::Reached(StopCondition::NextChoice),
        BTreeSet::from([fixture.transition_opportunity]),
    );
    fixture.paths_by_parent.insert(child_content, path);
    fixture.head = observed.new_snapshot;
    observed.observation
}

#[test]
fn two_stage_smc_executes_and_replays_the_same_estimate_after_restart() {
    let campaign = "statistical-smc-cold-restart";
    let reached = StopOutcome::Reached(StopCondition::NextChoice);
    let mut fixture = start_smc_campaign(campaign, [reached.clone(), reached]);

    assert!(matches!(
        fixture
            .repository
            .project_statistical_estimate(campaign, fixture.head),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical report refuses incomplete SMC policy"
        })
    ));
    let generation = fixture
        .repository
        .project_initial_smc_generation(campaign, fixture.head)
        .expect("project initial SMC generation");
    assert_eq!(generation.completed_stage(), 0);
    assert_eq!(generation.next_stage(), 1);
    assert_eq!(generation.slots().len(), 2);

    for slot in 0..2 {
        execute_smc_transition(&mut fixture, campaign, 1, slot);
    }
    let final_observations = (0..2)
        .map(|slot| execute_smc_transition(&mut fixture, campaign, 2, slot))
        .collect::<Vec<_>>();
    let report = fixture
        .repository
        .project_sequential_monte_carlo_estimate(campaign, fixture.head)
        .expect("project complete SMC estimate");
    assert_eq!(report.snapshot(), fixture.head);
    assert_eq!(report.generations().len(), 2);
    assert_eq!(report.generations()[0], generation);
    assert_eq!(report.generations()[1].completed_stage(), 1);
    assert_eq!(report.generations()[1].next_stage(), 2);
    assert_eq!(report.final_particles().len(), 2);
    assert_eq!(
        report
            .final_particles()
            .iter()
            .map(crate::StatisticalParticleOutcome::observation)
            .collect::<Vec<_>>(),
        final_observations
    );

    let selected_event = BTreeSet::from([final_observations[0]]);
    let selected_weight = report.final_particles()[0].estimator_weight();
    let all_weight = selected_weight
        .checked_add(report.final_particles()[1].estimator_weight())
        .expect("sum final SMC weights");
    let expected_ordinary = report
        .normalization_product()
        .checked_multiply(
            selected_weight
                .checked_divide(crate::StatisticalRational::new(2, 1).expect("particle count"))
                .expect("mean selected SMC weight"),
        )
        .expect("ordinary SMC estimate");
    assert_eq!(
        report
            .estimate_event(&selected_event)
            .expect("ordinary event estimate"),
        expected_ordinary
    );
    assert_eq!(
        report
            .estimate_event_self_normalized(&selected_event)
            .expect("self-normalized event estimate"),
        selected_weight
            .checked_divide(all_weight)
            .expect("self-normalized SMC estimate")
    );

    let restarted = CampaignRepository::with_component_authorities(
        fixture.repository.blobs.clone(),
        fixture.repository.refs.clone(),
        fixture.planner_authority,
        fixture.debugger_authority,
    )
    .expect("restart SMC repository");
    restarted
        .validate_complete_head(fixture.head.content_id())
        .expect("cold validate SMC head");
    let restarted_generation = restarted
        .project_initial_smc_generation(campaign, fixture.head)
        .expect("recompute initial SMC generation after restart");
    assert_eq!(restarted_generation, generation);
    assert_eq!(restarted_generation.id(), generation.id());
    assert_eq!(
        restarted
            .project_sequential_monte_carlo_estimate(campaign, fixture.head)
            .expect("replay complete SMC estimate after restart"),
        report
    );
}

#[test]
fn terminal_initial_particle_cannot_seed_a_nonfinal_stage_even_with_a_matching_choice() {
    let campaign = "statistical-smc-terminal-source";
    let reached = StopOutcome::Reached(StopCondition::NextChoice);
    let mut fixture = start_smc_campaign(campaign, [StopOutcome::TerminalSuccess, reached]);

    assert!(matches!(
        fixture.driver.step(campaign),
        Err(crate::CampaignPlannerDriverError::Repository(
            CampaignRepositoryError::Integrity {
                reason: "SMC initial transition did not reach its declared stop"
            }
        ))
    ));
}

#[test]
fn forced_resampling_executes_duplicate_ancestry_and_replays_after_restart() {
    let (repository, lineage, base, _, planner_authority, debugger_authority) =
        authorized_fixture();
    let forced = forced_resampling_fixture(&repository, &lineage, &base);
    let campaign = "statistical-smc-forced-resampling";
    let reached = StopOutcome::Reached(StopCondition::NextChoice);
    let mut fixture = launch_smc_campaign(
        repository,
        lineage,
        planner_authority,
        debugger_authority,
        campaign,
        forced.policy,
        forced.initial_templates,
        forced.transition_template,
        [reached.clone(), reached],
    );
    let initial_generation = fixture
        .repository
        .project_initial_smc_generation(campaign, fixture.head)
        .expect("project forced initial generation");
    assert!(initial_generation.resampled());
    assert_eq!(
        initial_generation.normalization_factor(),
        crate::StatisticalRational::one()
    );
    assert_eq!(
        initial_generation.slots()[0].parent(),
        initial_generation.slots()[1].parent()
    );
    assert!(
        initial_generation
            .slots()
            .iter()
            .all(|particle| particle.resampling_multiplicity() == 2)
    );

    let (_, first_request) =
        drive_statistical_request(&mut fixture.driver, &fixture.repository, campaign);
    let (first_admitted, first_proposal) =
        drive_statistical_proposal(&mut fixture.driver, &fixture.repository, campaign);
    let first_source_path = fixture
        .paths_by_parent
        .get(&first_request.parent())
        .expect("first resampled source path");
    let (first_path, first_attempt) = statistical_attempt(
        &fixture.repository,
        &first_request,
        &first_proposal,
        first_source_path
            .segments()
            .expect("first scoped resampled source path"),
    );
    let (first_observed, stage_one_child, _) = publish_observation_for_attempt_with(
        &fixture.repository,
        &fixture.lineage,
        campaign,
        first_admitted.new_snapshot,
        &first_path,
        &first_attempt,
        "forced-resampling-stage-one-child",
        StopOutcome::Reached(StopCondition::NextChoice),
        BTreeSet::from([fixture.transition_opportunity]),
    );
    fixture
        .paths_by_parent
        .insert(stage_one_child, first_path.clone());

    let (_, second_request) =
        drive_statistical_request(&mut fixture.driver, &fixture.repository, campaign);
    let (second_admitted, second_proposal) =
        drive_statistical_proposal(&mut fixture.driver, &fixture.repository, campaign);
    assert_eq!(first_request.parent(), second_request.parent());
    assert_eq!(first_proposal.value(), second_proposal.value());
    assert_ne!(
        first_proposal.id().expect("first stage-one proposal ID"),
        second_proposal.id().expect("second stage-one proposal ID")
    );
    let second_source_path = fixture
        .paths_by_parent
        .get(&second_request.parent())
        .expect("second resampled source path");
    let (second_path, second_attempt) = statistical_attempt(
        &fixture.repository,
        &second_request,
        &second_proposal,
        second_source_path
            .segments()
            .expect("second scoped resampled source path"),
    );
    assert_eq!(second_path, first_path);
    assert_eq!(
        second_attempt.id().expect("second stage-one attempt ID"),
        first_attempt.id().expect("first stage-one attempt ID")
    );
    let canonical_observation = fixture
        .repository
        .read_observation(first_observed.observation.content_id())
        .expect("load canonical stage-one observation");
    let replayed = fixture
        .repository
        .publish_observation(
            campaign,
            second_admitted.new_snapshot,
            &canonical_observation,
        )
        .expect("reuse canonical stage-one observation");
    assert!(replayed.replayed);
    fixture.head = replayed.new_snapshot;

    let final_observations = (0..2)
        .map(|slot| execute_smc_transition(&mut fixture, campaign, 2, slot))
        .collect::<Vec<_>>();
    let report = fixture
        .repository
        .project_sequential_monte_carlo_estimate(campaign, fixture.head)
        .expect("project forced-resampling SMC estimate");
    let stage_one_weight = match first_proposal.value() {
        ChoiceValue::Boolean(false) => {
            crate::StatisticalRational::new(2, 101).expect("false stage-one weight")
        }
        ChoiceValue::Boolean(true) => {
            crate::StatisticalRational::new(200, 101).expect("true stage-one weight")
        }
        value => panic!("unexpected stage-one SMC value: {value:?}"),
    };
    assert_eq!(report.normalization_product(), stage_one_weight);
    assert_eq!(report.generations().len(), 2);
    assert_eq!(report.generations()[0], initial_generation);
    assert!(report.generations()[1].resampled());
    assert_eq!(
        report.generations()[1].normalization_factor(),
        stage_one_weight
    );
    assert_eq!(
        report.generations()[1].slots()[0].observation(),
        report.generations()[1].slots()[1].observation()
    );
    assert_eq!(
        report.generations()[1].slots()[0].attempt(),
        report.generations()[1].slots()[1].attempt()
    );
    assert_ne!(
        report.generations()[1].slots()[0].parent(),
        report.generations()[1].slots()[1].parent()
    );
    assert_eq!(report.final_particles().len(), 2);
    assert_eq!(
        report
            .final_particles()
            .iter()
            .map(crate::StatisticalParticleOutcome::observation)
            .collect::<Vec<_>>(),
        final_observations
    );

    let restarted = CampaignRepository::with_component_authorities(
        fixture.repository.blobs.clone(),
        fixture.repository.refs.clone(),
        fixture.planner_authority,
        fixture.debugger_authority,
    )
    .expect("restart forced-resampling repository");
    restarted
        .validate_complete_head(fixture.head.content_id())
        .expect("cold validate forced-resampling head");
    assert_eq!(
        restarted
            .project_sequential_monte_carlo_estimate(campaign, fixture.head)
            .expect("replay forced-resampling estimate"),
        report
    );
}

#[test]
fn terminal_initial_endpoint_is_rejected_even_when_resampling_would_drop_it() {
    let (repository, lineage, base, _, planner_authority, debugger_authority) =
        authorized_fixture();
    let forced = forced_resampling_fixture(&repository, &lineage, &base);
    let dropped_coordinate = forced
        .draws
        .iter()
        .position(|draw| *draw == 0)
        .expect("low-weight coordinate");
    assert!(
        forced
            .expected_generation
            .slots()
            .iter()
            .all(|particle| particle.source_coordinate() != dropped_coordinate as u64)
    );
    let mut stops = [
        StopOutcome::Reached(StopCondition::NextChoice),
        StopOutcome::Reached(StopCondition::NextChoice),
    ];
    stops[dropped_coordinate] = StopOutcome::TerminalSuccess;
    let campaign = "statistical-smc-dropped-terminal";
    let fixture = launch_smc_campaign(
        repository,
        lineage,
        planner_authority,
        debugger_authority,
        campaign,
        forced.policy,
        forced.initial_templates,
        forced.transition_template,
        stops,
    );

    assert!(matches!(
        fixture
            .repository
            .project_initial_smc_generation(campaign, fixture.head),
        Err(CampaignRepositoryError::Integrity {
            reason: "SMC initial transition did not reach its declared stop"
        })
    ));
}

#[test]
fn planner_request_validation_rejects_forged_smc_generation_stage_and_slot() {
    let campaign = "statistical-smc-forged-basis";
    let reached = StopOutcome::Reached(StopCondition::NextChoice);
    let mut fixture = start_smc_campaign(campaign, [reached.clone(), reached]);
    let (issued, _) = drive_statistical_request(&mut fixture.driver, &fixture.repository, campaign);
    let step = fixture
        .repository
        .load_planner_step_at(issued.new_snapshot, issued.step)
        .expect("load valid SMC request step");
    let valid = fixture
        .repository
        .load_planner_request(step.request())
        .expect("load valid retained SMC planner request");
    let basis = valid.smc_request_basis().expect("valid SMC request basis");

    let mut wrong_stage_bytes = crate::codec::encode(basis.particle());
    wrong_stage_bytes[..4].copy_from_slice(&2_u32.to_be_bytes());
    let wrong_stage_particle: crate::StatisticalParticleSlot =
        crate::codec::decode(&wrong_stage_bytes).expect("structurally valid wrong-stage particle");
    let mut wrong_slot_bytes = crate::codec::encode(basis.particle());
    wrong_slot_bytes[4..8].copy_from_slice(&1_u32.to_be_bytes());
    let wrong_slot_particle: crate::StatisticalParticleSlot =
        crate::codec::decode(&wrong_slot_bytes).expect("structurally valid wrong-slot particle");
    let forged_generation = crate::StatisticalGenerationId::from_hash(CampaignHash::derive(
        "test.SMC-forgery",
        b"wrong generation",
    ));
    let forged_bases = [
        crate::SmcRequestBasis::new(
            forged_generation,
            basis.particle().clone(),
            basis.parent(),
            basis.configuration(),
            basis.opportunity().clone(),
            basis.domain().clone(),
        )
        .expect("wrong-generation SMC basis"),
        crate::SmcRequestBasis::new(
            basis.generation(),
            wrong_stage_particle,
            basis.parent(),
            basis.configuration(),
            basis.opportunity().clone(),
            basis.domain().clone(),
        )
        .expect("wrong-stage SMC basis"),
        crate::SmcRequestBasis::new(
            basis.generation(),
            wrong_slot_particle,
            basis.parent(),
            basis.configuration(),
            basis.opportunity().clone(),
            basis.domain().clone(),
        )
        .expect("wrong-slot SMC basis"),
    ];
    for forged_basis in forged_bases {
        let forged = PlannerRequest::new_with_smc_request_basis(
            valid.expected_snapshot(),
            valid.invocation().clone(),
            valid.engine().clone(),
            valid.policy_artifact().clone(),
            valid.policy().clone(),
            valid.planner_state().clone(),
            *valid.input_view(),
            Some(forged_basis),
            valid.input_bundle().clone(),
        )
        .expect("structurally valid forged SMC planner request");
        assert!(matches!(
            fixture.repository.validate_planner_request_inputs(&forged),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-request-SMC-basis-mismatch"
            })
        ));
    }
}

#[test]
fn smc_issues_each_request_before_its_proposal_and_waits_for_all_stage_observations() {
    let campaign = "statistical-smc-stage-barriers";
    let reached = StopOutcome::Reached(StopCondition::NextChoice);
    let mut fixture = start_smc_campaign(campaign, [reached.clone(), reached]);
    let basis_at = |snapshot_id: CampaignSnapshotId| {
        let snapshot = fixture
            .repository
            .read_snapshot(snapshot_id.content_id())
            .expect("load SMC barrier snapshot");
        let policy = fixture
            .repository
            .read_policy(snapshot.snapshot.active_policy().content_id())
            .expect("load SMC barrier policy");
        fixture
            .repository
            .smc_request_basis(&snapshot, &policy)
            .expect("resolve SMC barrier basis")
    };
    let first_basis = basis_at(fixture.head).expect("first stage-one request basis");
    assert_eq!(
        (
            first_basis.particle().generation(),
            first_basis.particle().slot()
        ),
        (1, 0)
    );

    let (first_requested, first_request) =
        drive_statistical_request(&mut fixture.driver, &fixture.repository, campaign);
    assert!(basis_at(first_requested.new_snapshot).is_none());
    let (first_admitted, first_proposal) =
        drive_statistical_proposal(&mut fixture.driver, &fixture.repository, campaign);
    let second_basis = basis_at(first_admitted.new_snapshot).expect("second stage-one basis");
    assert_eq!(
        (
            second_basis.particle().generation(),
            second_basis.particle().slot()
        ),
        (1, 1)
    );

    let (second_requested, second_request) =
        drive_statistical_request(&mut fixture.driver, &fixture.repository, campaign);
    assert!(basis_at(second_requested.new_snapshot).is_none());
    let (second_admitted, second_proposal) =
        drive_statistical_proposal(&mut fixture.driver, &fixture.repository, campaign);
    assert!(basis_at(second_admitted.new_snapshot).is_none());
    let stage_one_admitted = fixture
        .repository
        .read_snapshot(second_admitted.new_snapshot.content_id())
        .expect("load fully admitted stage-one snapshot");
    assert!(
        fixture
            .repository
            .merkle
            .get(
                stage_one_admitted.snapshot.roots().exploration,
                smc_transition_request_key(2, 0),
            )
            .expect("stage-two request lookup")
            .is_none()
    );

    let first_source_path = fixture
        .paths_by_parent
        .get(&first_request.parent())
        .expect("first stage-one source path");
    let (first_path, first_attempt) = statistical_attempt(
        &fixture.repository,
        &first_request,
        &first_proposal,
        first_source_path
            .segments()
            .expect("first scoped stage-one path"),
    );
    let (first_observed, _, _) = publish_observation_for_attempt_with(
        &fixture.repository,
        &fixture.lineage,
        campaign,
        second_admitted.new_snapshot,
        &first_path,
        &first_attempt,
        "SMC-barrier-first-child",
        StopOutcome::Reached(StopCondition::NextChoice),
        BTreeSet::from([fixture.transition_opportunity]),
    );
    assert!(basis_at(first_observed.new_snapshot).is_none());

    let second_source_path = fixture
        .paths_by_parent
        .get(&second_request.parent())
        .expect("second stage-one source path");
    let (second_path, second_attempt) = statistical_attempt(
        &fixture.repository,
        &second_request,
        &second_proposal,
        second_source_path
            .segments()
            .expect("second scoped stage-one path"),
    );
    let (second_observed, _, _) = publish_observation_for_attempt_with(
        &fixture.repository,
        &fixture.lineage,
        campaign,
        first_observed.new_snapshot,
        &second_path,
        &second_attempt,
        "SMC-barrier-second-child",
        StopOutcome::Reached(StopCondition::NextChoice),
        BTreeSet::from([fixture.transition_opportunity]),
    );
    let stage_two = basis_at(second_observed.new_snapshot).expect("stage-two request basis");
    assert_eq!(
        (
            stage_two.particle().generation(),
            stage_two.particle().slot()
        ),
        (2, 0)
    );
}

#[test]
fn finite_statistical_version_seven_engine_issues_the_next_draw_after_cold_restart() {
    let (repository, lineage, base, _, planner_authority, debugger_authority) =
        authorized_fixture();
    let draw_model = model("finite-v7-restart");
    let draw_distribution = distribution(1, 3, 3, 1);
    let first_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "finite-v7-first",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let second_template = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "finite-v7-second",
        draw_model,
        draw_distribution.target_masses().clone(),
    );
    let first_opportunity = repository
        .load_choice_opportunity(first_template.opportunity())
        .expect("first finite-v7 opportunity");
    let second_opportunity = repository
        .load_choice_opportunity(second_template.opportunity())
        .expect("second finite-v7 opportunity");
    let design = crate::StatisticalSamplingDesign::new(
        BTreeMap::from([(draw_model, draw_distribution)]),
        BTreeMap::from([
            (
                0,
                crate::StatisticalDrawPlan::new(
                    None,
                    &first_opportunity,
                    draw_model,
                    StopCondition::NextChoice,
                )
                .expect("first finite-v7 draw"),
            ),
            (
                1,
                crate::StatisticalDrawPlan::new(
                    None,
                    &second_opportunity,
                    draw_model,
                    StopCondition::NextChoice,
                )
                .expect("second finite-v7 draw"),
            ),
        ]),
        BTreeSet::from([0, 1]),
    )
    .expect("finite-v7 design");
    let policy = statistical_policy(&base, design, base.retention());
    let campaign = "finite-statistical-v7-cold-restart";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create finite-v7 campaign");
    let first_discovery = repository
        .discover_choice_opportunity(
            campaign,
            genesis.snapshot_id(),
            lineage.genesis_content(),
            first_template.opportunity(),
        )
        .expect("discover first finite-v7 opportunity");
    let second_discovery = repository
        .discover_choice_opportunity(
            campaign,
            first_discovery.new_snapshot,
            lineage.genesis_content(),
            second_template.opportunity(),
        )
        .expect("discover second finite-v7 opportunity");
    repository
        .apply_control(
            campaign,
            &command(
                "resume-finite-v7",
                second_discovery.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume finite-v7 campaign");

    let engine = PlannerEngine::new(
        "crucible-canonical-frontier",
        7,
        1,
        BTreeSet::from([
            crate::CANONICAL_FRONTIER_OFFERS_CAPABILITY.to_owned(),
            crate::CANONICAL_FRONTIER_BUDGET_CAPABILITY.to_owned(),
            crate::CANONICAL_FRONTIER_REQUEST_BUDGET_CAPABILITY.to_owned(),
        ]),
    )
    .expect("version-seven canonical frontier engine");
    assert_eq!(
        CanonicalFrontierPlanner::descriptor()
            .expect("current canonical frontier descriptor")
            .implementation_version(),
        8
    );
    let dependency_bytes = b"crucible-canonical-frontier-planner.v7".to_vec();
    let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
    repository
        .blobs
        .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
        .expect("publish finite-v7 dependency");
    let artifact = PolicyArtifact::new(
        engine.id().expect("version-seven engine ID"),
        1,
        dependency,
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("version-seven policy artifact");
    let initial_state = CanonicalFrontierPlanner::initial_state_for_engine(&engine)
        .expect("version-seven planner state");
    let repository = Arc::new(repository);
    let mut driver = statistical_planner_driver_with_basis(
        Arc::clone(&repository),
        planner_authority.clone(),
        engine.clone(),
        artifact.clone(),
        initial_state.clone(),
    );
    let (_, first_request) = drive_statistical_request(&mut driver, &repository, campaign);
    let (first_admitted, first_proposal) =
        drive_statistical_proposal(&mut driver, &repository, campaign);
    let (first_path, first_attempt) =
        statistical_attempt(&repository, &first_request, &first_proposal, &[]);
    let (first_observed, _, _) = publish_observation_for_attempt(
        &repository,
        &lineage,
        campaign,
        first_admitted.new_snapshot,
        &first_request,
        &first_path,
        &first_attempt,
        "finite-v7-first-child",
    );
    drop(driver);

    let restarted = Arc::new(
        CampaignRepository::with_component_authorities(
            repository.blobs.clone(),
            repository.refs.clone(),
            planner_authority.clone(),
            debugger_authority,
        )
        .expect("restart finite-v7 repository"),
    );
    restarted
        .validate_complete_head(first_observed.new_snapshot.content_id())
        .expect("cold validate finite-v7 head");
    let mut restarted_driver = statistical_planner_driver_with_basis(
        Arc::clone(&restarted),
        planner_authority,
        engine,
        artifact,
        initial_state,
    );
    let (issued, second_request) =
        drive_statistical_request(&mut restarted_driver, &restarted, campaign);
    let CandidateSource::StatisticalFinite(source) = second_request.source() else {
        panic!(
            "second finite-v7 request source: {:?}",
            second_request.source()
        )
    };
    assert_eq!(source.coordinate(), 1);
    let step = restarted
        .load_planner_step_at(issued.new_snapshot, issued.step)
        .expect("load post-restart finite-v7 planner step");
    let retained = restarted
        .load_planner_request(step.request())
        .expect("load post-restart finite-v7 planner request");
    assert_eq!(retained.engine().implementation_version(), 7);
    assert_eq!(
        u32::from_be_bytes(
            retained.canonical_bytes()[..4]
                .try_into()
                .expect("planner request schema bytes")
        ),
        2
    );
}
