//! Sequential Monte Carlo repository restart regressions.

use super::*;

fn smc_policy(
    base: &CampaignPolicy,
    initial: crate::StatisticalSamplingDesign,
    selector_opportunity: &ChoiceOpportunity,
    model: ProbabilityModelId,
    distribution: crate::StatisticalDistribution,
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
        crate::ExactRational::new(1, 1).expect("SMC ESS threshold"),
    )
    .expect("SMC resampling policy");
    let sequential = crate::SequentialMonteCarloDesign::new(
        2,
        BTreeMap::from([(model, distribution)]),
        BTreeMap::from([(1, crate::SmcStagePlan::new(0, selector))]),
        resampling,
    )
    .expect("SMC design");
    CampaignPolicy::new(
        base.scenario(),
        CampaignSeed::from_bytes([0x53; 32]),
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

#[test]
fn initial_generation_is_owner_recomputed_across_cold_restart() {
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
    let first_opportunity = repository
        .load_choice_opportunity(first_template.opportunity())
        .expect("first initial opportunity");
    let second_opportunity = repository
        .load_choice_opportunity(second_template.opportunity())
        .expect("second initial opportunity");
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
        &first_opportunity,
        draw_model,
        draw_distribution,
    );
    let campaign = "statistical-smc-cold-restart";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create SMC campaign");
    let first_discovery = repository
        .discover_choice_opportunity(
            campaign,
            genesis.snapshot_id(),
            lineage.genesis_content(),
            first_template.opportunity(),
        )
        .expect("discover first initial opportunity");
    let second_discovery = repository
        .discover_choice_opportunity(
            campaign,
            first_discovery.new_snapshot,
            lineage.genesis_content(),
            second_template.opportunity(),
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
    let (_, first_request) = drive_statistical_request(&mut driver, &repository, campaign);
    let (first_admitted, first_proposal) =
        drive_statistical_proposal(&mut driver, &repository, campaign);
    let (first_path, first_attempt) =
        statistical_attempt(&repository, &first_request, &first_proposal, &[]);
    publish_observation_for_attempt(
        &repository,
        &lineage,
        campaign,
        first_admitted.new_snapshot,
        &first_request,
        &first_path,
        &first_attempt,
        "smc-first-child",
    );

    let (_, second_request) = drive_statistical_request(&mut driver, &repository, campaign);
    let (second_admitted, second_proposal) =
        drive_statistical_proposal(&mut driver, &repository, campaign);
    let (second_path, second_attempt) =
        statistical_attempt(&repository, &second_request, &second_proposal, &[]);
    let (second_observed, _, _) = publish_observation_for_attempt(
        &repository,
        &lineage,
        campaign,
        second_admitted.new_snapshot,
        &second_request,
        &second_path,
        &second_attempt,
        "smc-second-child",
    );

    assert!(matches!(
        repository.project_statistical_estimate(campaign, second_observed.new_snapshot),
        Err(CampaignRepositoryError::Integrity {
            reason: "statistical report refuses incomplete SMC policy"
        })
    ));
    let generation = repository
        .project_initial_smc_generation(campaign, second_observed.new_snapshot)
        .expect("project initial SMC generation");
    assert_eq!(generation.completed_stage(), 0);
    assert_eq!(generation.next_stage(), 1);
    assert_eq!(generation.slots().len(), 2);

    let restarted = CampaignRepository::with_component_authorities(
        repository.blobs.clone(),
        repository.refs.clone(),
        planner_authority,
        debugger_authority,
    )
    .expect("restart SMC repository");
    restarted
        .validate_complete_head(second_observed.new_snapshot.content_id())
        .expect("cold validate SMC head");
    let restarted_generation = restarted
        .project_initial_smc_generation(campaign, second_observed.new_snapshot)
        .expect("recompute initial SMC generation after restart");
    assert_eq!(restarted_generation, generation);
    assert_eq!(restarted_generation.id(), generation.id());
}
