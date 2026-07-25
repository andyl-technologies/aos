//! Gates guided/adaptive exploration prerequisites for coverage-guided fuzzing.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;

use crucible::{
    AdaptiveStrategyArm, AdaptiveStrategyConfig, AdaptiveStrategyCredit, AdaptiveStrategyReward,
    AppRandomBranchConfig, AppRandomDecision, AppRandomDrawSite, AssertionProximityGuidanceSignal,
    Checkpoint, CheckpointKind, Configuration, ContentHash, CoverageGuidanceSignal, Decision,
    EngineError, FrontierReductionPolicy, GuidanceScore, GuidanceSignal, GuidanceSignalComposition,
    GuidanceSignalInput, GuidanceSignalKind, GuidanceSignalWeight, Icount, IrqVector, NodeId,
    NodeTemplate, NoveltyRarityGuidanceSignal, PartialOrderReductionPolicy, PreemptionBranchConfig,
    PreemptionKind, ReadyPoint, RngStreamId, ScenarioDef, SearchBudget, Seed, TemporalGraph,
    VcpuId, WhiteBoxPolicy, World, WorldNode, app_random_branch_decisions, bake,
    lint_guidance_determinism_source, preemption_branch_decisions, reduce,
    run_adaptive_strategy_selection, step, try_step,
};

#[test]
fn gate_guidance_signals_are_fixed_point_readers_only() {
    let coverage = ContentHash::from_canonical_material("crucible.test.guidance.coverage", "new");
    let input = GuidanceSignalInput {
        coverage_fingerprint: coverage,
        rarity_count: 3,
        assertion_proximity_distance: Some(4),
    };
    let coverage_signal = CoverageGuidanceSignal;
    let novelty_signal = NoveltyRarityGuidanceSignal;
    let proximity_signal = AssertionProximityGuidanceSignal;
    let composition = GuidanceSignalComposition::new(vec![
        GuidanceSignalWeight {
            signal: GuidanceSignalKind::AssertionProximity,
            weight_micros: 250_000,
        },
        GuidanceSignalWeight {
            signal: GuidanceSignalKind::Coverage,
            weight_micros: 500_000,
        },
        GuidanceSignalWeight {
            signal: GuidanceSignalKind::NoveltyRarity,
            weight_micros: 250_000,
        },
    ]);
    let checkpoint = Checkpoint::new(
        ContentHash::from_canonical_material("crucible.test.guidance.checkpoint", "id"),
        ContentHash::from_canonical_material("crucible.test.guidance.checkpoint", "configuration"),
        CheckpointKind::Thin,
    );
    let scored_checkpoint = checkpoint.clone().with_coverage_fingerprint(coverage);

    assert_eq!(coverage_signal.kind(), GuidanceSignalKind::Coverage);
    assert_eq!(novelty_signal.kind(), GuidanceSignalKind::NoveltyRarity);
    assert_eq!(
        proximity_signal.kind(),
        GuidanceSignalKind::AssertionProximity
    );
    assert!(coverage_signal.score(input).micros > GuidanceScore::default().micros);
    assert_eq!(novelty_signal.score(input).micros, 250_000);
    assert_eq!(proximity_signal.score(input).micros, 200_000);
    assert_eq!(
        GuidanceSignalComposition::coverage_only().score(input),
        coverage_signal.score(input)
    );
    assert_eq!(
        coverage_signal.search_order_key(input),
        (0, input.coverage_fingerprint)
    );
    assert_eq!(
        coverage_signal.search_order_key(GuidanceSignalInput::default()),
        (1, ContentHash::default())
    );
    assert_eq!(
        composition.weights()[0].signal,
        GuidanceSignalKind::Coverage
    );
    assert!(composition.score(input).micros > 0);
    assert_eq!(checkpoint.id, scored_checkpoint.id);
}

#[test]
fn gate_adaptive_strategy_selection_is_deterministic_and_fair() {
    let config = AdaptiveStrategyConfig::enabled(
        Seed::from_u64(0xada9),
        vec![
            AdaptiveStrategyArm::CoverageGuided,
            AdaptiveStrategyArm::BreadthFirst,
        ],
        2,
    );
    let graph = BTreeSet::from([
        ContentHash::from_canonical_material("crucible.test.adaptive.graph", "a"),
        ContentHash::from_canonical_material("crucible.test.adaptive.graph", "b"),
    ]);
    let coverage_credit = AdaptiveStrategyCredit {
        arm: AdaptiveStrategyArm::CoverageGuided,
        configuration: *graph.iter().next().expect("fixture graph has nodes"),
        reward: AdaptiveStrategyReward {
            new_coverage: 10,
            novelty_gain: 20,
            assertion_proximity_progress: 30,
            confirmed_failure: true,
        },
    };
    let bfs_credit = AdaptiveStrategyCredit {
        arm: AdaptiveStrategyArm::BreadthFirst,
        configuration: *graph.iter().last().expect("fixture graph has nodes"),
        reward: AdaptiveStrategyReward {
            new_coverage: 1,
            novelty_gain: 0,
            assertion_proximity_progress: 0,
            confirmed_failure: false,
        },
    };
    let credits = vec![bfs_credit, coverage_credit];
    let reversed_credits = vec![coverage_credit, bfs_credit];
    let first = run_adaptive_strategy_selection(&config, &graph, &credits, SearchBudget::new(4));
    let second =
        run_adaptive_strategy_selection(&config, &graph, &reversed_credits, SearchBudget::new(4));
    let disabled = run_adaptive_strategy_selection(
        &AdaptiveStrategyConfig::disabled(config.seed),
        &graph,
        &credits,
        SearchBudget::new(4),
    );
    let changed_identity = AdaptiveStrategyConfig::enabled(
        Seed::from_u64(0xada9),
        vec![AdaptiveStrategyArm::CoverageGuided],
        0,
    )
    .campaign_identity();

    assert_eq!(first, second);
    assert_eq!(first.selections[0].arm, AdaptiveStrategyArm::BreadthFirst);
    assert_eq!(first.selections[2].arm, AdaptiveStrategyArm::BreadthFirst);
    assert!(
        first
            .selections
            .iter()
            .any(|selection| selection.arm == AdaptiveStrategyArm::CoverageGuided)
    );
    assert!(
        disabled
            .selections
            .iter()
            .all(|selection| selection.arm == AdaptiveStrategyArm::BreadthFirst)
    );
    assert_ne!(first.campaign_identity, changed_identity);
    assert_ne!(first.graph_fingerprint, ContentHash::default());
}

#[test]
fn gate_guidance_determinism_lint_rejects_float_scores() {
    let clean = lint_guidance_determinism_source("let score: u64 = reward_micros;");
    let dirty = lint_guidance_determinism_source("let score: f64 = reward as f64;");

    assert!(clean.is_clean());
    assert!(!dirty.is_clean());
    assert_eq!(dirty.forbidden_hits, vec!["f64".to_string()]);
}

#[test]
fn gate_preemption_branching_records_oracle_validated_children() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("preemption-branching")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let config = PreemptionBranchConfig {
        node: node("guest-a"),
        deadline: Icount { retired: 2 },
        horizon: Icount { retired: 4 },
        step: 1,
        switch_from_vcpu: VcpuId { index: 0 },
        switch_to_vcpu: VcpuId { index: 0 },
        target_vcpu: VcpuId { index: 0 },
        irq: IrqVector { vector: 32 },
    };
    let decisions = preemption_branch_decisions(&config);
    let run = graph.branch_preemptions(&root, &config, FrontierReductionPolicy::none())?;

    assert_eq!(decisions.len(), 6);
    assert_eq!(run.decisions, decisions);
    assert_eq!(run.report.explored.len(), 6);
    assert_eq!(run.materialized.len(), run.report.explored.len());
    assert!(run.report.covered.is_empty());
    for child in &run.report.explored {
        assert!(matches!(child.decision, Decision::Preemption(_)));
        assert_eq!(child.configuration.id(), child.configuration.content_hash());
        assert!(reduce(&child.configuration.def, &child.configuration.schedule).is_ok());
    }
    assert!(run.decisions.iter().any(|decision| matches!(
        decision,
        Decision::Preemption(crucible::PreemptionDecision {
            kind: PreemptionKind::VcpuSwitch { .. },
            ..
        })
    )));
    assert!(run.decisions.iter().any(|decision| matches!(
        decision,
        Decision::Preemption(crucible::PreemptionDecision {
            kind: PreemptionKind::InterruptAt { .. },
            ..
        })
    )));
    assert_eq!(
        run.materialized
            .iter()
            .map(|checkpoint| checkpoint.id)
            .collect::<BTreeSet<_>>(),
        run.report
            .explored
            .iter()
            .map(|child| child.configuration.id())
            .collect::<BTreeSet<_>>()
    );

    Ok(())
}

#[test]
fn gate_preemption_branching_reduces_commuting_single_vcpu_preemptions()
-> Result<(), Box<dyn Error>> {
    let world = two_single_vcpu_node_world("preemption-por")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let config_a = single_vcpu_preemption_config("guest-a");
    let config_b = single_vcpu_preemption_config("guest-b");
    let decision_a = preemption_branch_decisions(&config_a)
        .into_iter()
        .next()
        .ok_or("guest-a should produce a preemption branch")?;
    let decision_b = preemption_branch_decisions(&config_b)
        .into_iter()
        .next()
        .ok_or("guest-b should produce a preemption branch")?;
    let (frontier_decision, branch_decision, branch_config) =
        if decision_a.reduction_order_key() > decision_b.reduction_order_key() {
            (decision_a, decision_b, config_b)
        } else {
            (decision_b, decision_a, config_a)
        };
    let frontier = step(&root, frontier_decision.clone());
    graph.record_step(&root, frontier_decision.clone())?;
    let policy = FrontierReductionPolicy::none().with_partial_order(
        PartialOrderReductionPolicy::new()
            .with_independent_pair(&frontier_decision, &branch_decision),
    );
    let run = graph.branch_preemptions(&frontier, &branch_config, policy)?;

    assert_eq!(run.decisions.len(), 2);
    assert_eq!(run.report.covered.len(), 1);
    assert_eq!(run.report.covered[0].decision, branch_decision);
    assert_eq!(
        run.report.covered[0].reason,
        crucible::FrontierReductionReason::PartialOrder
    );
    assert_eq!(run.report.explored.len(), 1);
    assert_eq!(run.materialized.len(), 2);
    let materialized = run
        .materialized
        .iter()
        .map(|checkpoint| checkpoint.id)
        .collect::<BTreeSet<_>>();
    assert!(materialized.contains(&run.report.covered[0].representative));
    assert!(materialized.contains(&run.report.explored[0].configuration.id()));
    assert!(
        run.materialized
            .iter()
            .all(|checkpoint| checkpoint.kind == CheckpointKind::Fat)
    );
    assert!(run.materialized.iter().all(|checkpoint| {
        graph
            .checkpoint_configuration(checkpoint.id)
            .is_some_and(|configuration| graph.replay(configuration).is_ok())
    }));

    Ok(())
}

#[test]
fn gate_app_random_branching_is_optional_and_bounded() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("app-random-branching")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let base_config = AppRandomBranchConfig {
        draw_sites: Vec::new(),
        samples: 3,
        seed: Seed::from_u64(0xa11),
    };
    let unchanged = graph.branch_app_random(&root, &base_config)?;
    let before_count = graph.checkpoint_node_count();
    let mut branch_config = base_config.clone();
    branch_config.draw_sites = vec![AppRandomDrawSite {
        node: node("guest-a"),
        stream: RngStreamId::for_node("guest-a/app-random"),
        request_id: 7,
        width: 8,
    }];
    let decisions = app_random_branch_decisions(&branch_config);
    let branched = graph.branch_app_random(&root, &branch_config)?;

    assert!(unchanged.decisions.is_empty());
    assert!(unchanged.report.explored.is_empty());
    assert_eq!(
        before_count,
        graph.checkpoint_node_count() - branched.report.explored.len()
    );
    assert_eq!(branched.decisions, decisions);
    assert_eq!(branched.report.explored.len(), 3);
    for decision in &branched.decisions {
        assert!(matches!(
            decision,
            Decision::AppRandom(AppRandomDecision { width: 8, .. })
        ));
    }
    for child in &branched.report.explored {
        assert!(matches!(child.decision, Decision::AppRandom(_)));
        assert!(reduce(&child.configuration.def, &child.configuration.schedule).is_ok());
    }

    let capped = Configuration::genesis(
        ScenarioDef::from_canonical_material_with_seed_and_app_random_draw_cap(
            "crucible.test.app-random-cap",
            &scenario.id().to_hex(),
            Seed::from_u64(1),
            0,
        ),
    );
    let capped_decision = app_random_branch_decisions(&branch_config)
        .into_iter()
        .next()
        .ok_or("expected app-random decision")?;
    assert!(try_step(&capped, capped_decision).is_err());

    Ok(())
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![single_vcpu_world_node("guest-a", label)])
}

fn two_single_vcpu_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![
        single_vcpu_world_node("guest-a", label),
        single_vcpu_world_node("guest-b", label),
    ])
}

fn single_vcpu_world_node(name: &str, label: &str) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-guided-adaptive={label}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 100 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn single_vcpu_preemption_config(name: &str) -> PreemptionBranchConfig {
    PreemptionBranchConfig {
        node: node(name),
        deadline: Icount { retired: 2 },
        horizon: Icount { retired: 2 },
        step: 1,
        switch_from_vcpu: VcpuId { index: 0 },
        switch_to_vcpu: VcpuId { index: 0 },
        target_vcpu: VcpuId { index: 0 },
        irq: IrqVector { vector: 32 },
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}
