//! Gates the advanced-feature unifying temporal-graph view.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;

use crucible::{
    AssertionDef, AssertionId, AssertionQuantifierKind, AssertionRunVerdict, BlackBoxHostOracle,
    Checkpoint, CheckpointKind, ChoiceTag, Configuration, ContentHash, CoverageGuidedFuzzConfig,
    Decision, EngineError, EventLogCoverageFeedback, EventLogCoverageFeedbackConsumer, FamilySpace,
    FaultDensity, FaultDensityRange, FindingDiscoveryPath, FindingReproductionArtifact,
    GenesisCheckpoint, Icount, MarkerId, MaterializationPolicy, MaterializationTrigger,
    MemoryDagStore, MinimizationConfig, NodeTemplate, ObservableEvent, OfflineAssertionChecker,
    OverrideDecision, Plan, Predicate, Properties, Property, ReadyPoint, RecordedAssertionLog,
    ScenarioDefForm, ScenarioFamily, SchedulingPoint, SearchBudget, SearchFailureOracle,
    SearchFrontierChoices, SearchStrategy, Seed, TemporalGraph, TopologyShape, TopologySizeRange,
    UnifiedGraphOperationEvidence, UnifiedGraphOperationKind, UnifiedGraphOperationReport,
    VirtualTime, WhiteBoxPolicy, World, WorldNode, bake, reduce, try_step,
};

#[test]
fn gate_unifying_view_validates_every_advanced_operation_on_one_graph() -> Result<(), Box<dyn Error>>
{
    let world = single_node_world("unifying-view")?;
    let scenario = scenario_form(&world)?;
    let root = Configuration::genesis(scenario.scenario_def());
    let noise = override_decision("noise", "left");
    let critical = override_decision("critical", "fail");
    let baked =
        bake_with_search_frontier_choices(&scenario, vec![noise.clone(), critical.clone()])?;
    let mut graph = TemporalGraph::new(finding_fingerprint("unifying-graph"))
        .with_baked_genesis(&root.def, baked)?;
    let graph_id = graph.id;

    let resume_runtime = graph.resume(&root)?;
    let resume_report =
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Resume {
            configuration: root.clone(),
            runtime: resume_runtime.clone(),
        })?;
    assert_eq!(resume_runtime.runtime.id, resume_report.runtime_state);
    assert_unified_report(
        &resume_report,
        graph_id,
        UnifiedGraphOperationKind::Resume,
        &root,
    )?;

    let fork = graph.fork(&root, vec![noise.clone(), critical.clone()])?;
    let fork_report =
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Fork(fork.clone()))?;
    assert_eq!(fork.base.configuration, root.id());
    assert_unified_report(
        &fork_report,
        graph_id,
        UnifiedGraphOperationKind::Fork,
        &fork.branch,
    )?;

    let store = MemoryDagStore::new();
    let save = graph.save(&store, &fork.branch)?;
    let save_report = graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Save {
        configuration: fork.branch.clone(),
        save: save.clone(),
    })?;
    assert_eq!(save.configuration, save_report.configuration);
    assert_eq!(save.checkpoint, save_report.checkpoint);
    assert_unified_report(
        &save_report,
        graph_id,
        UnifiedGraphOperationKind::Save,
        &fork.branch,
    )?;

    let replay = graph.replay(&fork.branch)?;
    let replay_report =
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Replay {
            configuration: fork.branch.clone(),
            replay: replay.clone(),
        })?;
    assert_eq!(replay, replay_report.replay_oracle);
    assert_unified_report(
        &replay_report,
        graph_id,
        UnifiedGraphOperationKind::Replay,
        &fork.branch,
    )?;

    let critical_branch = try_step(&root, critical.clone())?;
    let search_fingerprint = finding_fingerprint("search-critical");
    let failure_oracle =
        SearchFailureOracle::none().with_failure(critical_branch.id(), search_fingerprint);
    let search_graph = graph.clone();
    let search = graph.search_with_strategy_and_failure_oracle(
        &scenario,
        &root,
        SearchStrategy::BreadthFirst,
        SearchBudget::new(1),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &failure_oracle,
    )?;
    let search_failure = search
        .discovered_failures
        .first()
        .ok_or("expected search to report the critical branch")?;
    let search_report =
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::StateSpaceSearch {
            graph: search_graph,
            scenario: scenario.clone(),
            root: root.clone(),
            strategy: SearchStrategy::BreadthFirst,
            budget: SearchBudget::new(1),
            materialization_policy: MaterializationPolicy::thin_only(),
            trigger: MaterializationTrigger::Cold,
            failure_oracle: failure_oracle.clone(),
            run: search.clone(),
            failure: search_failure.clone(),
        })?;
    assert_eq!(search_failure.configuration, critical_branch.id());
    assert_eq!(
        search_failure.reproduction_artifact().discovery_path,
        FindingDiscoveryPath::StateSpaceSearch
    );
    assert_unified_report(
        &search_report,
        graph_id,
        UnifiedGraphOperationKind::StateSpaceSearch,
        &critical_branch,
    )?;

    let reproduction = search_failure.reproduction_artifact();
    let reproduction_config = configuration_from_finding(reproduction);
    let reproduction_report = graph.validate_unified_operation(
        &UnifiedGraphOperationEvidence::ReproductionArtifact(reproduction.clone()),
    )?;
    assert_eq!(
        reproduction.configuration,
        reproduction_report.configuration
    );
    assert_eq!(reproduction.replay.state, reproduction_report.reduced_state);
    assert_unified_report(
        &reproduction_report,
        graph_id,
        UnifiedGraphOperationKind::ReproductionArtifact,
        &reproduction_config,
    )?;

    let family = fuzz_family()?;
    let fuzz_feedback = vec![coverage_feedback("guest-a", 0x7100, "unifying")];
    let fuzz = family.fuzz_coverage_guided(
        CoverageGuidedFuzzConfig::new(Seed::from_u64(0x5160), 1),
        &fuzz_feedback,
    )?;
    let fuzz_iteration = fuzz
        .iterations
        .first()
        .ok_or("expected one coverage-guided fuzz iteration")?;
    graph.cache_baked_genesis(
        &fuzz_iteration.configuration.def,
        bake_for_scenario_form(fuzz_iteration.scenario.form())?,
    )?;
    let fuzz_report = graph.validate_unified_operation(
        &UnifiedGraphOperationEvidence::CoverageGuidedFuzzing {
            family: family.clone(),
            run: fuzz.clone(),
            feedback_fingerprints: coverage_feedback_fingerprints(&fuzz_feedback),
            iteration: fuzz_iteration.clone(),
        },
    )?;
    assert_eq!(fuzz_iteration.configuration_id(), fuzz_report.configuration);
    assert_unified_report(
        &fuzz_report,
        graph_id,
        UnifiedGraphOperationKind::CoverageGuidedFuzzing,
        &fuzz_iteration.configuration,
    )?;

    let minimization_target = failure_fingerprint_for_schedule(&scenario, &fork.branch.schedule)?
        .ok_or("fork branch should violate the assertion")?;
    let original_finding = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::InteractiveFork,
        minimization_target,
        &scenario,
        &fork.branch,
    )?;
    let minimized = original_finding.minimize(
        MinimizationConfig::new(Seed::from_u64(0x5161)),
        |candidate| minimization_oracle(original_finding.finding_fingerprint, candidate),
    )?;
    let minimized_config = configuration_from_finding(&minimized.minimized);
    let minimization_report = graph.validate_unified_operation(
        &UnifiedGraphOperationEvidence::Minimization(minimized.clone()),
    )?;
    assert_eq!(
        minimized.minimized.replay.state,
        minimization_report.reduced_state
    );
    assert_eq!(minimized_config.schedule.len(), 1);
    assert_unified_report(
        &minimization_report,
        graph_id,
        UnifiedGraphOperationKind::Minimization,
        &minimized_config,
    )?;

    let operations = [
        resume_report,
        fork_report,
        save_report,
        replay_report,
        search_report,
        reproduction_report,
        fuzz_report,
        minimization_report,
    ];
    assert_eq!(
        operations
            .iter()
            .map(|report| report.operation)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            UnifiedGraphOperationKind::Resume,
            UnifiedGraphOperationKind::Fork,
            UnifiedGraphOperationKind::Save,
            UnifiedGraphOperationKind::Replay,
            UnifiedGraphOperationKind::StateSpaceSearch,
            UnifiedGraphOperationKind::CoverageGuidedFuzzing,
            UnifiedGraphOperationKind::ReproductionArtifact,
            UnifiedGraphOperationKind::Minimization,
        ])
    );
    assert!(operations.iter().all(|report| report.graph == graph_id));

    Ok(())
}

#[test]
fn gate_unifying_view_rejects_mismatched_operation_evidence() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("mismatched-evidence")?;
    let scenario = scenario_form(&world)?;
    let root = Configuration::genesis(scenario.scenario_def());
    let noise = override_decision("noise", "left");
    let critical = override_decision("critical", "fail");
    let baked =
        bake_with_search_frontier_choices(&scenario, vec![noise.clone(), critical.clone()])?;
    let mut graph = TemporalGraph::new(finding_fingerprint("mismatched-graph"))
        .with_baked_genesis(&root.def, baked)?;
    let resume_runtime = graph.resume(&root)?;
    let branch = try_step(&root, critical.clone())?;

    let mismatched = UnifiedGraphOperationEvidence::Resume {
        configuration: branch,
        runtime: resume_runtime,
    };

    assert!(matches!(
        graph.validate_unified_operation(&mismatched),
        Err(EngineError::RuntimeConfigurationMismatch { .. })
    ));

    let mut forged_runtime = graph.resume(&root)?;
    forged_runtime.runtime.id = finding_fingerprint("forged-runtime-state");
    let forged_resume = UnifiedGraphOperationEvidence::Resume {
        configuration: root.clone(),
        runtime: forged_runtime,
    };
    assert!(matches!(
        graph.validate_unified_operation(&forged_resume),
        Err(EngineError::ReplayTargetMismatch { .. })
    ));

    let fork = graph.fork(&root, vec![noise.clone(), critical.clone()])?;
    let critical_branch = try_step(&root, critical)?;
    let mut forged_fork = fork.clone();
    forged_fork.base = graph.resume(&critical_branch)?;
    assert!(matches!(
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Fork(forged_fork)),
        Err(EngineError::ReplayTargetMismatch { .. })
    ));

    let store = MemoryDagStore::new();
    let save = graph.save(&store, &fork.branch)?;
    let mut forged_save = save.clone();
    forged_save.store_keys.checkpoint_nodes.insert(
        finding_fingerprint("forged-checkpoint-node"),
        finding_fingerprint("forged-store-key"),
    );
    assert!(matches!(
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Save {
            configuration: fork.branch.clone(),
            save: forged_save,
        }),
        Err(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "save",
            reason: "save-store-keys",
        })
    ));

    let mut forged_replay = graph.replay(&fork.branch)?;
    forged_replay.thin_checkpoint = root.id();
    assert!(matches!(
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Replay {
            configuration: fork.branch.clone(),
            replay: forged_replay,
        }),
        Err(EngineError::ReplayTargetMismatch { .. })
    ));

    let search_fingerprint = finding_fingerprint("search-critical-forged");
    let failure_oracle =
        SearchFailureOracle::none().with_failure(critical_branch.id(), search_fingerprint);
    let search_graph = graph.clone();
    let search = graph.search_with_strategy_and_failure_oracle(
        &scenario,
        &root,
        SearchStrategy::BreadthFirst,
        SearchBudget::new(1),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &failure_oracle,
    )?;
    let forged_search_fingerprint = finding_fingerprint("forged-search-failure");
    let forged_search_artifact = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        forged_search_fingerprint,
        &scenario,
        &fork.branch,
    )?;
    let forged_search_failure = crucible::SearchDiscoveredFailure {
        configuration: fork.branch.id(),
        fingerprint: forged_search_fingerprint,
        reproduction_artifact: forged_search_artifact,
    };
    assert!(matches!(
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::StateSpaceSearch {
            graph: search_graph,
            scenario: scenario.clone(),
            root: root.clone(),
            strategy: SearchStrategy::BreadthFirst,
            budget: SearchBudget::new(1),
            materialization_policy: MaterializationPolicy::thin_only(),
            trigger: MaterializationTrigger::Cold,
            failure_oracle: failure_oracle.clone(),
            run: search,
            failure: forged_search_failure,
        }),
        Err(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "state-space-search",
            reason: "search-failure-output",
        })
    ));

    let family = fuzz_family()?;
    let fuzz_feedback = vec![coverage_feedback("guest-a", 0x7200, "forged")];
    let fuzz = family.fuzz_coverage_guided(
        CoverageGuidedFuzzConfig::new(Seed::from_u64(0x6162), 1),
        &fuzz_feedback,
    )?;
    let mut forged_fuzz_iteration = fuzz
        .iterations
        .first()
        .ok_or("expected one coverage-guided fuzz iteration")?
        .clone();
    forged_fuzz_iteration.energy = forged_fuzz_iteration.energy.saturating_add(1);
    assert!(matches!(
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::CoverageGuidedFuzzing {
            family,
            run: fuzz,
            feedback_fingerprints: coverage_feedback_fingerprints(&fuzz_feedback),
            iteration: forged_fuzz_iteration,
        }),
        Err(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "coverage-guided-fuzzing",
            reason: "iteration-output",
        })
    ));

    let minimization_target = failure_fingerprint_for_schedule(&scenario, &fork.branch.schedule)?
        .ok_or("fork branch should violate the assertion")?;
    let original_finding = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::InteractiveFork,
        minimization_target,
        &scenario,
        &fork.branch,
    )?;
    let mut forged_minimization = original_finding.minimize(
        MinimizationConfig::new(Seed::from_u64(0x5162)),
        |candidate| minimization_oracle(original_finding.finding_fingerprint, candidate),
    )?;
    forged_minimization.minimized = forged_minimization.original.clone();
    assert!(matches!(
        graph.validate_unified_operation(&UnifiedGraphOperationEvidence::Minimization(
            forged_minimization
        )),
        Err(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "minimization",
            reason: "minimized-candidate",
        })
    ));

    Ok(())
}

fn assert_unified_report(
    report: &UnifiedGraphOperationReport,
    graph: ContentHash,
    operation: UnifiedGraphOperationKind,
    configuration: &Configuration,
) -> Result<(), EngineError> {
    let reduced = reduce(&configuration.def, &configuration.schedule)?;
    assert_eq!(report.operation, operation);
    assert_eq!(report.graph, graph);
    assert_eq!(report.configuration, configuration.id());
    assert_eq!(report.schedule, configuration.schedule.content_hash());
    assert_eq!(report.checkpoint, configuration.id());
    assert_eq!(report.reduced_state, reduced.id);
    assert_eq!(report.runtime_state, reduced.id);
    assert_eq!(report.single_vm_fingerprint.hash, reduced.id);
    assert_eq!(report.replay_oracle.configuration, configuration.id());
    assert_eq!(report.replay_oracle.fat_checkpoint, configuration.id());
    assert_eq!(report.replay_oracle.thin_checkpoint, configuration.id());
    Ok(())
}

fn configuration_from_finding(finding: &FindingReproductionArtifact) -> Configuration {
    Configuration {
        def: finding.artifact.scenario_def(),
        schedule: finding.artifact.schedule().clone(),
    }
}

fn minimization_oracle(
    target: ContentHash,
    candidate: &FindingReproductionArtifact,
) -> Result<Option<ContentHash>, EngineError> {
    let _ = candidate.artifact.replay()?;
    let fingerprint = failure_fingerprint_for_schedule(
        candidate.artifact.scenario_form(),
        candidate.artifact.schedule(),
    )?;
    Ok((fingerprint == Some(target)).then_some(target))
}

fn failure_fingerprint_for_schedule(
    scenario: &ScenarioDefForm,
    schedule: &crucible::Schedule,
) -> Result<Option<ContentHash>, EngineError> {
    let retained = retained_event_log(schedule)?;
    let mut oracle = BlackBoxHostOracle;
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(scenario.world())
        .check_run_with_oracle(scenario.properties(), &retained, &mut oracle)
        .map_err(|source| EngineError::ScenarioSerialization {
            reason: format!("unifying minimization assertion fold failed: {source}"),
        })?;
    let fingerprint = report
        .violations()
        .iter()
        .find(|violation| {
            violation.assertion == assertion_id("no-forbidden-marker")
                && violation.quantifier == AssertionQuantifierKind::Always
        })
        .map(assertion_fold_failure_fingerprint);
    assert!(
        matches!(report.verdict(), AssertionRunVerdict::Failed { .. }) == fingerprint.is_some()
    );
    Ok(fingerprint)
}

fn retained_event_log(schedule: &crucible::Schedule) -> Result<RecordedAssertionLog, EngineError> {
    let mut entries = schedule
        .decisions()
        .iter()
        .enumerate()
        .map(|(sequence, decision)| {
            crucible::test_support::condition_payload_entry_for_test(
                sequence as u64,
                time(sequence as u64),
                crucible::SchedulerEventLogPayload::Decision(decision.clone()),
            )
        })
        .collect::<Vec<_>>();
    let mut sequence = entries.len() as u64;
    if schedule_emits_forbidden_marker(schedule) {
        entries.push(
            crucible::test_support::condition_observation_entry_for_test(
                sequence,
                &ObservableEvent::guest_marker(
                    icount(7),
                    crucible::NodeId {
                        name: "guest-a".to_owned(),
                    },
                    marker("forbidden"),
                ),
            ),
        );
        sequence += 1;
    }
    entries.push(crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(7),
        crucible::SchedulerEvaluationBoundaryKind::Quantum,
    ));
    RecordedAssertionLog::from_segments(vec![entries]).map_err(|source| {
        EngineError::ScenarioSerialization {
            reason: format!("unifying minimization retained log failed: {source}"),
        }
    })
}

fn schedule_emits_forbidden_marker(schedule: &crucible::Schedule) -> bool {
    schedule.decisions().iter().any(|decision| {
        matches!(
            decision,
            Decision::Override(override_decision)
                if override_decision.point.key == "critical"
                    && override_decision.choice.name == "fail"
        )
    })
}

fn assertion_fold_failure_fingerprint(violation: &crucible::HostAssertionViolation) -> ContentHash {
    let icount = violation
        .at_icount
        .map(|value| value.retired.to_string())
        .unwrap_or_else(|| "none".to_owned());
    let node = violation
        .node
        .as_ref()
        .map(|value| value.name.as_str())
        .unwrap_or("none");
    ContentHash::from_canonical_material(
        "crucible.test.unifying-view.assertion-fold.v1",
        &format!(
            "assertion={}\nmessage={}\nquantifier={:?}\nicount={icount}\nvirtual_time={}\nnode={node}\ndetail={}",
            violation.assertion.name,
            violation.message,
            violation.quantifier,
            violation.at_virtual_time.ticks,
            violation.detail
        ),
    )
}

fn scenario_form(world: &World) -> Result<ScenarioDefForm, EngineError> {
    ScenarioDefForm::from_components(
        world,
        &Plan::empty(),
        &Properties::from_assertions_for_world(
            world,
            vec![AssertionDef {
                id: assertion_id("no-forbidden-marker"),
                message: "forbidden marker must stay absent".to_owned(),
                property: Property::Always {
                    predicate: Predicate::not(Predicate::guest_marker(marker("forbidden"))),
                },
            }],
        )?,
        Seed::default(),
    )
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: crucible::NodeId {
            name: "guest-a".to_owned(),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-unifying-view={label}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 100 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
}

fn bake_with_search_frontier_choices(
    scenario: &ScenarioDefForm,
    decisions: Vec<Decision>,
) -> Result<GenesisCheckpoint, EngineError> {
    let mut baked = bake_for_scenario_form(scenario)?;
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

fn bake_for_scenario_form(scenario: &ScenarioDefForm) -> Result<GenesisCheckpoint, EngineError> {
    let baked = bake(scenario.world())?;
    let genesis = Configuration::genesis(scenario.scenario_def());
    let checkpoint = Checkpoint::from_recorded_configuration(
        &genesis,
        None,
        VirtualTime::default(),
        baked.checkpoint.node_icounts,
        CheckpointKind::Fat,
        baked.checkpoint.node_blobs,
    )?;
    Ok(GenesisCheckpoint { checkpoint })
}

fn fuzz_family() -> Result<ScenarioFamily, EngineError> {
    let density_one = FaultDensity::from_millionths(1)?;
    let space = FamilySpace::new(
        crucible::SeedSpace::explicit(vec![Seed::from_u64(0x11)])?,
        FaultDensityRange::new(FaultDensity::ZERO, density_one)?,
        TopologySizeRange::new(2, 2)?,
        vec![TopologyShape::Ring],
    )?;
    Ok(ScenarioFamily::new(
        space,
        NodeTemplate::fixed_icount(Icount { retired: 50 }),
    ))
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

fn coverage_feedback_fingerprints(feedback: &[EventLogCoverageFeedback]) -> Vec<ContentHash> {
    feedback
        .iter()
        .map(|entry| entry.fingerprint_for(EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing))
        .collect()
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
    ContentHash::from_canonical_material("crucible.test.unifying-view", label)
}

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
