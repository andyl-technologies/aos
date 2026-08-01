//! Gates canonical debug time travel as restore-plus-replay.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::error::Error;

use crucible::{
    Checkpoint, CheckpointKind, ChoiceTag, Configuration, ContentHash, DebugAttachRequest,
    DebugCheckpointCadenceRequest, DebugCheckpointStride, DebugCoordinate, DebugGotoRequest,
    DebugPerNodeTimeTravelRequest, DebugReverseContinueRequest, DebugReverseStepGrain,
    DebugReverseStepRequest, DebugWholeWorldTarget, DebugWholeWorldTimeTravelRequest, Decision,
    EngineError, Icount, NodeBlobRef, NodeId, NodeLifecycle, NodeTemplate, ObservableEvent,
    OverrideDecision, Predicate, ReadyPoint, SavevmCompletenessHedge, SchedulingPoint,
    TemporalGraph, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode, bake,
    instantiate, try_step,
};

#[test]
fn debug_goto_uses_nearest_checkpoint_then_replay_to_exact_coordinate() -> Result<(), Box<dyn Error>>
{
    let world = single_node_world("debug-goto")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(&root, override_decision("debug/goto", "first"))?;
    let second = try_step(&first, override_decision("debug/goto", "second"))?;
    let third = try_step(&second, override_decision("debug/goto", "third"))?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let cached_first = graph.materialize_checkpoint(&first)?;
    graph.record_thin_checkpoint(&second)?;
    graph.record_thin_checkpoint(&third)?;
    let attach = graph.debug_attach(&attach_request(&third)?)?;

    let by_time = graph.debug_goto(
        &attach,
        &DebugGotoRequest::new(
            third.clone(),
            DebugCoordinate::virtual_time(VirtualTime { ticks: 2 }),
        ),
    )?;

    assert_eq!(by_time.target_configuration, second.id());
    assert_eq!(by_time.restore_configuration, first.id());
    assert_eq!(by_time.restore_checkpoint, cached_first.id);
    assert_eq!(by_time.replay_suffix_decisions, 1);
    assert!(by_time.proves_replay_oracle());
    assert!(by_time.used_restore_then_replay());

    let by_icount = graph.debug_goto(
        &attach,
        &DebugGotoRequest::new(
            third.clone(),
            DebugCoordinate::node_icount(node_id("guest-a"), Icount { retired: 102 }),
        ),
    )?;

    assert_eq!(by_icount.target_configuration, second.id());
    assert!(by_icount.proves_replay_oracle());

    Ok(())
}

#[test]
fn debug_goto_coordinate_resolution_stays_on_current_ancestry() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-goto-ancestry")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let left_first = try_step(&root, override_decision("debug/branch", "left-first"))?;
    let left_second = try_step(
        &left_first,
        override_decision("debug/branch", "left-second"),
    )?;
    let right_first = try_step(&root, override_decision("debug/branch", "right-first"))?;
    let right_second = try_step(
        &right_first,
        override_decision("debug/branch", "right-second"),
    )?;
    let (current, sibling) = if left_second.id() < right_second.id() {
        (left_second.clone(), right_second.clone())
    } else {
        (right_second.clone(), left_second.clone())
    };

    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    graph.record_thin_checkpoint(&left_second)?;
    graph.record_thin_checkpoint(&right_second)?;
    let attach = graph.debug_attach(&attach_request(&current)?)?;

    let by_time = graph.debug_goto(
        &attach,
        &DebugGotoRequest::new(
            current.clone(),
            DebugCoordinate::virtual_time(VirtualTime { ticks: 2 }),
        ),
    )?;

    assert_eq!(by_time.target_configuration, current.id());
    assert_ne!(by_time.target_configuration, sibling.id());

    let by_icount = graph.debug_goto(
        &attach,
        &DebugGotoRequest::new(
            current.clone(),
            DebugCoordinate::node_icount(node_id("guest-a"), Icount { retired: 102 }),
        ),
    )?;

    assert_eq!(by_icount.target_configuration, current.id());
    assert_ne!(by_icount.target_configuration, sibling.id());

    Ok(())
}

#[test]
fn debug_reverse_step_and_continue_are_realized_by_goto() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-reverse")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(&root, override_decision("debug/reverse", "first"))?;
    let second = try_step(&first, override_decision("debug/reverse", "second"))?;
    let third = try_step(&second, override_decision("debug/reverse", "third"))?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    graph.materialize_checkpoint(&first)?;
    graph.record_thin_checkpoint(&second)?;
    graph.record_thin_checkpoint(&third)?;
    let attach = graph.debug_attach(&attach_request(&third)?)?;

    let reverse_instruction = graph.debug_reverse_step(
        &attach,
        &DebugReverseStepRequest::new(
            third.clone(),
            DebugReverseStepGrain::Instruction,
            Vec::new(),
        ),
    )?;

    assert_eq!(reverse_instruction.target_configuration, second.id());
    assert_eq!(reverse_instruction.target_event_sequence, None);
    assert!(reverse_instruction.realized_by_goto());

    let quantum_log = vec![
        crucible::test_support::condition_boundary_entry_for_test(
            0,
            VirtualTime { ticks: 1 },
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        ),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            VirtualTime { ticks: 2 },
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ];
    let reverse_quantum = graph.debug_reverse_step(
        &attach,
        &DebugReverseStepRequest::new(third.clone(), DebugReverseStepGrain::Quantum, quantum_log)
            .with_event_coordinate(0, first.clone())
            .with_event_coordinate(1, second.clone())
            .with_current_event_sequence(3),
    )?;

    assert_eq!(reverse_quantum.target_event_sequence, Some(1));
    assert_eq!(reverse_quantum.target_configuration, second.id());
    assert!(reverse_quantum.realized_by_goto());

    let condition_log = vec![
        crucible::test_support::condition_observation_entry_for_test(
            0,
            &ObservableEvent::node_state(
                VirtualTime { ticks: 1 },
                node_id("guest-a"),
                NodeLifecycle::Started,
            ),
        ),
        crucible::test_support::condition_observation_entry_for_test(
            1,
            &ObservableEvent::node_state(
                VirtualTime { ticks: 2 },
                node_id("guest-a"),
                NodeLifecycle::Started,
            ),
        ),
        crucible::test_support::condition_boundary_entry_for_test(
            2,
            VirtualTime { ticks: 3 },
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ];
    let reverse_continue = graph.debug_reverse_continue(
        &attach,
        &DebugReverseContinueRequest::new(
            third.clone(),
            Predicate::node_state(node_id("guest-a"), NodeLifecycle::Started),
            condition_log.clone(),
        )
        .with_event_coordinate(0, first.clone())
        .with_event_coordinate(1, second.clone())
        .with_current_event_sequence(3),
    )?;
    let matched = reverse_continue
        .matched
        .as_ref()
        .expect("latest matching condition coordinate should be found");

    assert_eq!(matched.event_sequence, 1);
    assert_eq!(matched.target_configuration, second.id());
    assert!(reverse_continue.realized_by_goto());

    let inclusive_reverse_continue = graph.debug_reverse_continue(
        &attach,
        &DebugReverseContinueRequest::new(
            third,
            Predicate::node_state(node_id("guest-a"), NodeLifecycle::Started),
            condition_log,
        )
        .with_event_coordinate(0, first)
        .with_event_coordinate(1, second.clone())
        .with_current_event_sequence(1),
    )?;
    let inclusive_matched = inclusive_reverse_continue
        .matched
        .as_ref()
        .expect("current event sequence is an inclusive reverse-continue candidate");

    assert_eq!(inclusive_matched.event_sequence, 1);
    assert_eq!(inclusive_matched.target_configuration, second.id());

    Ok(())
}

#[test]
fn debug_goto_replay_oracle_mismatch_carries_bisection_coordinate() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-goto-bisect")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let parent = try_step(&root, override_decision("debug/bisect", "parent"))?;
    let target = try_step(&parent, override_decision("debug/bisect", "target"))?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    graph.materialize_checkpoint(&parent)?;
    let corrupt = corrupt_checkpoint(&parent, &target)?;
    graph.cache_snapshot(&target, corrupt.clone())?;
    let attach = graph.debug_attach(&attach_request(&parent)?)?;

    let error = graph
        .debug_goto(
            &attach,
            &DebugGotoRequest::at_configuration(parent.clone(), target.clone()),
        )
        .expect_err("corrupt exact target snapshot must fail debug goto");

    let EngineError::DebugGotoReplayOracleMismatch {
        bisection,
        checkpoint,
        expected,
        actual,
    } = error
    else {
        panic!("debug goto should localize replay-oracle mismatch");
    };

    assert_eq!(checkpoint, corrupt.id);
    assert_ne!(expected, actual);
    assert_eq!(bisection.current_configuration, parent.id());
    assert_eq!(bisection.target_configuration, target.id());
    assert_eq!(bisection.restore_configuration, target.id());
    assert_eq!(bisection.first_different_schedule_prefix_len, 2);
    assert_eq!(bisection.last_matching_schedule_prefix_len, Some(1));

    Ok(())
}

#[test]
fn debug_per_node_and_whole_world_time_travel_land_coherently() -> Result<(), Box<dyn Error>> {
    let world = two_node_world("debug-scoped")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(&root, override_decision("debug/scoped", "first"))?;
    let second = try_step(&first, override_decision("debug/scoped", "second"))?;
    let third = try_step(&second, override_decision("debug/scoped", "third"))?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    graph.record_thin_checkpoint(&first)?;
    graph.record_thin_checkpoint(&second)?;
    graph.record_thin_checkpoint(&third)?;
    let attach = graph.debug_attach(&attach_request(&third)?)?;
    let attach_second = graph.debug_attach(&attach_request(&second)?)?;

    let forward_per_node = graph.debug_per_node_time_travel(
        &attach_second,
        &DebugPerNodeTimeTravelRequest::new(
            second.clone(),
            node_id("guest-a"),
            Icount { retired: 103 },
        ),
    )?;

    assert_eq!(forward_per_node.target_configuration, third.id());
    assert_eq!(
        forward_per_node.current_node_icount,
        Icount { retired: 102 }
    );
    assert_eq!(forward_per_node.landed_node_icount, Icount { retired: 103 });
    assert_eq!(
        forward_per_node.final_node_icounts.get(&node_id("guest-b")),
        attach_second
            .runtime
            .runtime
            .node_icounts
            .get(&node_id("guest-b"))
    );
    assert_eq!(forward_per_node.node_goto.materialized_nodes.len(), 1);
    assert!(
        forward_per_node
            .node_goto
            .materialized_nodes
            .contains(&node_id("guest-a"))
    );
    assert!(forward_per_node.realized_by_goto());
    assert!(forward_per_node.lands_node_coherently());
    assert!(forward_per_node.leaves_other_nodes_unreinstantiated());

    let per_node = graph.debug_per_node_time_travel(
        &attach,
        &DebugPerNodeTimeTravelRequest::new(
            third.clone(),
            node_id("guest-a"),
            Icount { retired: 102 },
        ),
    )?;

    assert_eq!(per_node.target_configuration, second.id());
    assert_eq!(per_node.current_node_icount, Icount { retired: 103 });
    assert_eq!(per_node.landed_node_icount, Icount { retired: 102 });
    assert_eq!(
        per_node.final_node_icounts.get(&node_id("guest-a")),
        Some(&Icount { retired: 102 })
    );
    assert_eq!(
        per_node.final_node_icounts.get(&node_id("guest-b")),
        attach.runtime.runtime.node_icounts.get(&node_id("guest-b"))
    );
    assert!(per_node.realized_by_goto());
    assert!(per_node.lands_node_coherently());
    assert!(per_node.leaves_other_nodes_unreinstantiated());

    let unknown_node = graph
        .debug_per_node_time_travel(
            &attach,
            &DebugPerNodeTimeTravelRequest::new(
                third.clone(),
                node_id("missing"),
                Icount { retired: 1 },
            ),
        )
        .unwrap_err();
    assert!(matches!(
        unknown_node,
        EngineError::DebugTimeTravelUnknownNode { .. }
    ));

    let whole_prefix = graph.debug_whole_world_time_travel(
        &attach,
        &DebugWholeWorldTimeTravelRequest::new(third.clone(), DebugWholeWorldTarget::prefix_len(2)),
    )?;

    assert_eq!(whole_prefix.target_configuration, second.id());
    assert_eq!(
        whole_prefix.landed_node_icounts.get(&node_id("guest-a")),
        Some(&Icount { retired: 102 })
    );
    assert_eq!(
        whole_prefix.landed_node_icounts.get(&node_id("guest-b")),
        Some(&Icount { retired: 202 })
    );
    assert!(whole_prefix.realized_by_goto());
    assert!(whole_prefix.is_fork_without_divergence());
    assert!(whole_prefix.lands_all_nodes_coherently());

    let whole_event = graph.debug_whole_world_time_travel(
        &attach,
        &DebugWholeWorldTimeTravelRequest::new(
            third.clone(),
            DebugWholeWorldTarget::event_sequence(7),
        )
        .with_event_coordinate(7, first.clone()),
    )?;

    assert_eq!(whole_event.target_configuration, first.id());
    assert!(whole_event.realized_by_goto());
    assert!(whole_event.lands_all_nodes_coherently());

    Ok(())
}

#[test]
fn debug_checkpoint_stride_is_performance_only_and_defaults_to_thin_replay()
-> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-stride")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(&root, override_decision("debug/stride", "first"))?;
    let second = try_step(&first, override_decision("debug/stride", "second"))?;
    let third = try_step(&second, override_decision("debug/stride", "third"))?;
    let fourth = try_step(&third, override_decision("debug/stride", "fourth"))?;
    let stride = DebugCheckpointStride::new(2).ok_or("stride must be non-zero")?;

    let mut thin_graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let thin_report = thin_graph.debug_apply_checkpoint_cadence(
        &DebugCheckpointCadenceRequest::thin_replay_until_full_s3(fourth.clone(), stride),
    )?;
    let thin_runtime = instantiate(&thin_graph, &fourth)?;

    assert_eq!(
        thin_report.candidate_configurations,
        vec![second.id(), fourth.id()]
    );
    assert!(thin_report.defaults_to_thin_replay_until_full_s3());
    assert!(thin_report.is_performance_only_cache_decision());
    assert!(thin_report.fat_checkpoints.is_empty());
    assert_eq!(thin_report.thin_checkpoints.len(), 2);
    assert_eq!(thin_graph.cached_snapshot_count(), 0);
    assert_eq!(thin_runtime.configuration, fourth.id());

    let mut verified_graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let fat_report = verified_graph.debug_apply_checkpoint_cadence(
        &DebugCheckpointCadenceRequest::with_hedge(
            fourth.clone(),
            stride,
            SavevmCompletenessHedge::verified(),
        ),
    )?;
    let exact_runtime = instantiate(&verified_graph, &fourth)?;
    verified_graph.evict_fat_checkpoint_to_thin(&second)?;
    verified_graph.evict_fat_checkpoint_to_thin(&fourth)?;
    let replay_runtime = instantiate(&verified_graph, &fourth)?;

    assert_eq!(fat_report.fat_checkpoints, vec![second.id(), fourth.id()]);
    assert!(fat_report.thin_checkpoints.is_empty());
    assert!(fat_report.is_performance_only_cache_decision());
    assert_eq!(exact_runtime.id, replay_runtime.id);
    assert_eq!(exact_runtime.configuration, replay_runtime.configuration);
    assert_eq!(exact_runtime.node_icounts, replay_runtime.node_icounts);

    let mut eviction_graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    eviction_graph.debug_apply_checkpoint_cadence(&DebugCheckpointCadenceRequest::with_hedge(
        fourth.clone(),
        stride,
        SavevmCompletenessHedge::verified(),
    ))?;
    let before_eviction = instantiate(&eviction_graph, &fourth)?;
    let eviction_report = eviction_graph.debug_apply_checkpoint_cadence(
        &DebugCheckpointCadenceRequest::thin_replay_until_full_s3(fourth.clone(), stride),
    )?;
    let after_eviction = instantiate(&eviction_graph, &fourth)?;

    assert_eq!(eviction_report.cached_snapshots_before, 2);
    assert_eq!(eviction_report.cached_snapshots_after, 0);
    assert!(eviction_report.defaults_to_thin_replay_until_full_s3());
    assert!(eviction_report.is_performance_only_cache_decision());
    assert_eq!(before_eviction.id, after_eviction.id);
    assert_eq!(before_eviction.configuration, after_eviction.configuration);
    assert_eq!(before_eviction.node_icounts, after_eviction.node_icounts);

    Ok(())
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("guest-a"),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-debug-time-travel={label}"),
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

fn two_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![
        WorldNode {
            id: node_id("guest-a"),
            arch: VmArchitecture::X86_64,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: format!("crucible-debug-time-travel={label}-a"),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 100 },
            },
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        },
        WorldNode {
            id: node_id("guest-b"),
            arch: VmArchitecture::X86_64,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: format!("crucible-debug-time-travel={label}-b"),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 200 },
            },
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        },
    ])
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
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

fn attach_request(configuration: &Configuration) -> Result<DebugAttachRequest, EngineError> {
    DebugAttachRequest::new(
        configuration.clone(),
        node_id("guest-a"),
        "unix:/tmp/crucible-qemu-gdbstub.sock,server=on,wait=off",
        "127.0.0.1:9000",
    )
}

fn corrupt_checkpoint(
    parent: &Configuration,
    target: &Configuration,
) -> Result<Checkpoint, EngineError> {
    Checkpoint::from_recorded_configuration(
        target,
        Some(parent),
        VirtualTime { ticks: 2 },
        BTreeMap::from([(node_id("guest-a"), Icount { retired: 9_999 })]),
        CheckpointKind::Fat,
        BTreeMap::from([(
            node_id("guest-a"),
            NodeBlobRef::baked(ContentHash::from_canonical_material(
                "crucible.test.debug-time-travel.corrupt-snapshot",
                "wrong-loadvm-payload",
            )),
        )]),
    )
}
