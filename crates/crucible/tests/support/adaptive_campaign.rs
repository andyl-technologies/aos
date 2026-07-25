//! Integrated deterministic-UCB campaign fixture and assertions.

use super::*;

pub(super) fn run_integrated_adaptive_campaign_gate() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("adaptive-campaign")?;
    let scenario_form = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::default(),
    )?;
    let scenario = scenario_form.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let decisions = (0..3).map(guidance_decision).collect::<Vec<_>>();
    let children = decisions
        .iter()
        .cloned()
        .map(|decision| try_step(&root, decision))
        .collect::<Result<Vec<_>, _>>()?;
    let baked = bake_with_search_frontier_choices(&world, decisions)?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let failure_oracle = SearchFailureOracle::none().with_failure(
        children[2].id(),
        ContentHash::from_canonical_material("crucible.test.adaptive.failure", "branch"),
    );
    let reduction_policy = FrontierReductionPolicy::none();
    let config = AdaptiveCampaignConfig::new(
        AdaptiveStrategyConfig::enabled(
            Seed::from_u64(0xada9),
            vec![
                AdaptiveStrategyArm::BreadthFirst,
                AdaptiveStrategyArm::CoverageGuided,
                AdaptiveStrategyArm::Priority,
            ],
            2,
        ),
        GuidanceSearchConfig::default(),
    );
    let mut guidance = GuidanceSearchState::default();
    for (index, child) in children.iter().enumerate() {
        guidance.record_event_log_observation(child, &guidance_event_log(index as u64));
    }
    let mut repeated_graph = graph.clone();
    let mut repeated_guidance = guidance.clone();

    let run = graph.search_adaptive_campaign(
        &scenario_form,
        &root,
        SearchBudget::new(3),
        reduction_policy.clone(),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &failure_oracle,
        &config,
        &mut guidance,
    )?;
    let repeated = repeated_graph.search_adaptive_campaign(
        &scenario_form,
        &root,
        SearchBudget::new(3),
        reduction_policy,
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &failure_oracle,
        &config,
        &mut repeated_guidance,
    )?;

    assert_eq!(run, repeated);
    assert_eq!(run.selections.len(), 3);
    assert_eq!(run.selections[0].arm, AdaptiveStrategyArm::BreadthFirst);
    assert_eq!(run.selections[2].arm, AdaptiveStrategyArm::BreadthFirst);
    assert_eq!(run.expansions[0].search.frontier_report.explored.len(), 3);
    assert!(run
        .credits
        .windows(2)
        .all(|pair| pair[0].configuration <= pair[1].configuration));
    assert!(run
        .credits
        .iter()
        .any(|credit| credit.reward.confirmed_failure));
    assert!(run.discovered_failures.iter().all(|failure| {
        failure.reproduction_artifact().artifact.scenario_form() == &scenario_form
            && failure.reproduction_artifact().artifact.schedule() == &children[2].schedule
    }));
    assert_ne!(run.campaign_identity, config.strategy.campaign_identity());

    Ok(())
}
