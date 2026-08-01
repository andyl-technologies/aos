//! Gates self-contained finding reproduction artifacts for advanced exploration.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;

use crucible::{
    ChoiceTag, Configuration, ContentHash, CoverageGuidedCorpusConfig, CoverageGuidedFuzzConfig,
    Decision, EngineError, EventLogCoverageFeedback, FamilySpace, FaultDensity, FaultDensityRange,
    FindingDiscoveryPath, FindingReproductionArtifact, FindingReproductionArtifactError,
    GenesisCheckpoint, Icount, MarkerId, MaterializationPolicy, MaterializationTrigger,
    MemoryDagStore, NodeTemplate, ObservableEvent, OverrideDecision, Plan, Properties, ReadyPoint,
    ScenarioDefForm, ScenarioFamily, SchedulingPoint, SearchBudget, SearchFailureOracle,
    SearchFrontierChoices, SearchStrategy, Seed, SeedSpace, TemporalGraph, TopologyShape,
    TopologySizeRange, WhiteBoxPolicy, World, WorldNode, bake, try_step,
};

#[test]
fn gate_findings_emit_same_artifact_for_interactive_and_search_paths() -> Result<(), Box<dyn Error>>
{
    let world = single_node_world("finding-artifact")?;
    let scenario = scenario_form(&world)?;
    let root = Configuration::genesis(scenario.scenario_def());
    let decision = override_decision("finding/path", "branch");
    let branch = try_step(&root, decision.clone())?;
    let baked = bake_with_search_frontier_choices(&world, vec![decision.clone()])?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&root.def, baked)?;
    let fork = graph.fork(&root, vec![decision.clone()])?;
    let fingerprint = finding_fingerprint("same-configuration");
    let interactive = fork.reproduction_artifact(&scenario, fingerprint)?;
    let failure_oracle = SearchFailureOracle::none().with_failure(branch.id(), fingerprint);
    let search_run = graph.search_with_strategy_and_failure_oracle(
        &scenario,
        &root,
        SearchStrategy::BreadthFirst,
        SearchBudget::new(1),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &failure_oracle,
    )?;
    let search_failure = search_run
        .discovered_failures
        .first()
        .ok_or("expected state-space search failure")?;
    let search = search_failure.reproduction_artifact();

    assert_eq!(fork.branch, branch);
    assert_eq!(search_run.discovered_failures.len(), 1);
    assert_eq!(search_failure.configuration, branch.id());
    assert_eq!(
        interactive.discovery_path,
        FindingDiscoveryPath::InteractiveFork
    );
    assert_eq!(
        search.discovery_path,
        FindingDiscoveryPath::StateSpaceSearch
    );
    assert_eq!(interactive.finding_fingerprint, fingerprint);
    assert_eq!(search.finding_fingerprint, fingerprint);
    assert_eq!(interactive.configuration, branch.id());
    assert_eq!(search.configuration, branch.id());
    assert_eq!(interactive.artifact.id(), search.artifact.id());
    assert_eq!(interactive.artifact.scenario_form(), &scenario);
    assert_eq!(interactive.artifact.schedule(), &branch.schedule);
    assert_eq!(interactive.replay, search.replay);
    assert_eq!(
        interactive.replay.state,
        crucible::reduce(&branch.def, &branch.schedule)?.id
    );

    let wrong_scenario = scenario_form(&single_node_world("wrong-scenario")?)?;
    assert!(matches!(
        FindingReproductionArtifact::capture(
            FindingDiscoveryPath::InteractiveFork,
            fingerprint,
            &wrong_scenario,
            &branch,
        ),
        Err(EngineError::ReproductionScenarioMismatch { .. })
    ));

    Ok(())
}

#[test]
fn gate_fuzz_and_retained_corpus_artifacts_replay_without_campaign() -> Result<(), Box<dyn Error>> {
    let family = fuzz_family()?;
    let fuzz = family.fuzz_coverage_guided(
        CoverageGuidedFuzzConfig::new(Seed::from_u64(0xf17a), 2),
        &[coverage_feedback("guest-a", 0x9000, "fuzz")],
    )?;
    let fuzz_finding =
        fuzz.iterations[0].reproduction_artifact(finding_fingerprint("fuzz-finding"))?;
    let store = MemoryDagStore::new();
    let stored_key = fuzz_finding.store_artifact(&store)?;
    let loaded_fuzz = FindingReproductionArtifact::load_from_store(
        FindingDiscoveryPath::CoverageGuidedFuzzing,
        fuzz_finding.finding_fingerprint,
        &store,
        stored_key,
    )?;

    assert_eq!(
        fuzz_finding.discovery_path,
        FindingDiscoveryPath::CoverageGuidedFuzzing
    );
    assert_eq!(loaded_fuzz.artifact.id(), fuzz_finding.artifact.id());
    assert_eq!(loaded_fuzz.replay, fuzz_finding.replay);
    assert_eq!(
        loaded_fuzz.artifact.replay()?.state,
        fuzz_finding.replay.state
    );

    let corpus_store = MemoryDagStore::new();
    let corpus = family.fuzz_coverage_guided_corpus(
        &corpus_store,
        CoverageGuidedFuzzConfig::new(Seed::from_u64(0xc041), 25),
        CoverageGuidedCorpusConfig::new(Seed::from_u64(0xc042)),
        &[coverage_feedback("guest-a", 0xa000, "corpus")],
    )?;
    let retained = corpus
        .corpus
        .entries()
        .values()
        .find(|entry| entry.parent.is_some())
        .ok_or("expected at least one fuzz-retained corpus entry")?;
    let retained_finding = retained.reproduction_artifact(&corpus_store)?;

    assert_eq!(
        retained_finding.discovery_path,
        FindingDiscoveryPath::RetainedCorpusEntry
    );
    assert_eq!(retained_finding.artifact.id(), retained.artifact);
    assert_eq!(retained_finding.replay.state, retained.replayed_state);
    assert_eq!(
        retained_finding.finding_fingerprint,
        retained.coverage_fingerprint
    );
    assert_ne!(retained.descriptor_key, retained.store_key);

    let mut corrupt_retained = *retained;
    corrupt_retained.artifact = finding_fingerprint("wrong-retained-artifact");
    assert!(matches!(
        corrupt_retained.reproduction_artifact(&corpus_store),
        Err(
            FindingReproductionArtifactError::RetainedCorpusEntryMismatch {
                field: "artifact",
                ..
            }
        )
    ));

    Ok(())
}

fn scenario_form(world: &World) -> Result<ScenarioDefForm, EngineError> {
    ScenarioDefForm::from_components(world, &Plan::empty(), &Properties::empty(), Seed::default())
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: crucible::NodeId {
            name: "guest-a".to_owned(),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-reproduction-artifact={label}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 100 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
}

fn bake_with_search_frontier_choices(
    world: &World,
    decisions: Vec<Decision>,
) -> Result<GenesisCheckpoint, EngineError> {
    let mut baked = bake(world)?;
    let state = baked.checkpoint.state.as_ref().ok_or(
        EngineError::CheckpointMaterializedStateIncomplete {
            checkpoint: baked.checkpoint.id,
            reason: "missing-test-genesis-state",
        },
    )?;
    let mut scheduler = state.scheduler.clone();
    scheduler.search_frontier = SearchFrontierChoices::from_decisions(decisions);
    baked.checkpoint.state = Some(
        crucible::MaterializedState::from_components_with_event_log_segments(
            state.vm_snapshots.clone(),
            state.device_overlays.clone(),
            scheduler,
            state.decision_rng.clone(),
            state.event_log,
            state.event_log_segments.clone(),
        ),
    );
    Ok(baked)
}

fn fuzz_family() -> Result<ScenarioFamily, EngineError> {
    let density_one = FaultDensity::from_millionths(1)?;
    let space = FamilySpace::new(
        SeedSpace::explicit(vec![Seed::from_u64(0x11)])?,
        FaultDensityRange::new(FaultDensity::ZERO, density_one)?,
        TopologySizeRange::new(2, 2)?,
        vec![TopologyShape::Ring],
    )?;
    Ok(ScenarioFamily::new(
        space,
        NodeTemplate::fixed_icount(Icount { retired: 50 }),
    ))
}

fn override_decision(point: &str, choice: &str) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: point.to_owned(),
        },
        choice: ChoiceTag {
            name: choice.to_owned(),
        },
    })
}

fn finding_fingerprint(label: &str) -> ContentHash {
    ContentHash::from_canonical_material("crucible.test.finding-artifact", label)
}

fn coverage_feedback(
    node_name: &str,
    guest_pc: u64,
    marker_name: &str,
) -> EventLogCoverageFeedback {
    let node = crucible::NodeId {
        name: node_name.to_owned(),
    };
    let log = vec![
        crucible::test_support::condition_observation_entry_for_test(
            0,
            &ObservableEvent::coverage_block(icount(10), node.clone(), guest_pc, 0x20),
        ),
        crucible::test_support::condition_observation_entry_for_test(
            1,
            &ObservableEvent::coverage_marker(icount(11), node, marker(marker_name)),
        ),
    ];
    EventLogCoverageFeedback::from_event_log(&log)
}

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
