//! Implements `gate:content-address` over the execution-model identity spine.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use crucible::{
    AppRandomDecision, Checkpoint, CheckpointKind, CheckpointMeta, Configuration, ContentHash,
    CowDeltaKind, CowDeltaRef, Decision, DecisionRngState, DeliveryOrderDecision, DeviceId,
    DeviceOverlayDelta, DeviceRngState, EngineError, EventKey, EventLogOffset, FaultDecision,
    FaultId, FaultState, Icount, MaterializedState, NodeBlobRef, NodeId, PendingFrame, RngDecision,
    RngStreamId, RngStreamPosition, ScenarioDef, Schedule, SchedulerState, State, TemporalGraph,
    TimerId, TimerRegistry, TimerState, VirtualTime, VmSnapshotRef, World, bake, reduce, step,
};

#[test]
fn gate_content_address_keeps_fixed_vectors_stable() {
    let scenario = scenario("scenario=alpha\nnodes=a,b\nseed=42");
    let schedule = fixed_schedule();
    let configuration = Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let state = assert_twice_reduce_canonical_digest(|| reduce(&scenario, &schedule));

    assert_eq!(
        fixed_vectors(&scenario, &schedule, &configuration, &state),
        expected_vectors([
            (
                "scenario",
                "ca5ef63d14b2039d0a0d6e4fa94820f2ffb2ab4f7c89fabd4e5658b53051b77a"
            ),
            (
                "schedule",
                "26714bc8d41b4e9e29443ba658b71de1c0edf4a87879cde0661029b1043a2cde"
            ),
            (
                "configuration",
                "5bdb16ae8ac9702c711e3d340e61b8ed60c6e2462d0928da377a19fba6f8521c",
            ),
            (
                "state",
                "90db4fac84b59501c7804fd618508b312754c4bf7d4e768dd92328e2d860ab65"
            ),
            (
                "world-component",
                "d1614627d7442f5fcd7757db23250ab820f3d9648373811bd4cf4ee853ddc4a5",
            ),
            (
                "snapshot-blob",
                "285760e51578adf57b28481e664232064eb12f7eba7d4b2fba8da197463d8321",
            ),
            (
                "event-log-segment",
                "8d356acd5b719e0a42fb04fd03464e52ebe2eec33bd0c6d0647407b1a1229a41",
            ),
        ])
    );
}

#[test]
fn gate_content_address_hashes_equal_content_to_equal_ids() {
    let first_scenario = scenario("scenario=equal\nnodes=a,b\nseed=7");
    let second_scenario = scenario("scenario=equal\nnodes=a,b\nseed=7");
    let first_schedule = fixed_schedule();
    let second_schedule = fixed_schedule();
    let first_configuration = Configuration {
        def: first_scenario.clone(),
        schedule: first_schedule.clone(),
    };
    let second_configuration = Configuration {
        def: second_scenario.clone(),
        schedule: second_schedule.clone(),
    };

    assert_eq!(first_scenario.id, second_scenario.id);
    assert_eq!(
        first_schedule.content_hash(),
        second_schedule.content_hash()
    );
    assert_eq!(
        first_configuration.content_hash(),
        second_configuration.content_hash()
    );
    assert_eq!(
        assert_twice_reduce_canonical_digest(|| reduce(&first_scenario, &first_schedule)),
        assert_twice_reduce_canonical_digest(|| reduce(&second_scenario, &second_schedule))
    );
}

#[test]
fn gate_content_address_changes_on_single_byte_mutations() {
    assert_ne!(
        ScenarioDef::from_canonical_material("crucible.test.content-address.scenario", "seed=1").id,
        ScenarioDef::from_canonical_material("crucible.test.content-address.scenario", "seed=2").id
    );
    assert_ne!(
        ContentHash::from_canonical_material("crucible.test.content-address.snapshot", "page=A"),
        ContentHash::from_canonical_material("crucible.test.content-address.snapshot", "page=B")
    );
    assert_ne!(
        ContentHash::from_canonical_material("crucible.test.content-address.log", "event=deliver"),
        ContentHash::from_canonical_material("crucible.test.content-address.log", "event=delives")
    );

    let scenario = scenario("scenario=mutation\nnodes=a,b\nseed=11");
    let base = Configuration::genesis(scenario.clone());
    let first = step(
        &base,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId {
                name: String::from("node-a/fault"),
            },
            value: 1,
        }),
    );
    let changed = step(
        &base,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId {
                name: String::from("node-a/fault"),
            },
            value: 2,
        }),
    );

    assert_ne!(
        first.schedule.content_hash(),
        changed.schedule.content_hash()
    );
    assert_ne!(first.content_hash(), changed.content_hash());
    assert_ne!(
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &first.schedule)),
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &changed.schedule))
    );
}

#[test]
fn gate_content_address_is_sensitive_to_schedule_order() {
    let scenario = scenario("scenario=order\nnodes=a,b\nseed=13");
    let draw = Decision::RngDraw(RngDecision {
        stream: RngStreamId {
            name: String::from("scheduler/order"),
        },
        value: 9,
    });
    let delivery = Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 3 },
        order: vec![EventKey { sequence: 1 }],
    });
    let first = Schedule::empty()
        .appended(draw.clone())
        .appended(delivery.clone());
    let second = Schedule::empty().appended(delivery).appended(draw);

    assert_ne!(first.content_hash(), second.content_hash());
    assert_ne!(
        Configuration {
            def: scenario.clone(),
            schedule: first.clone(),
        }
        .content_hash(),
        Configuration {
            def: scenario.clone(),
            schedule: second.clone(),
        }
        .content_hash()
    );
    assert_ne!(
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &first)),
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &second))
    );
}

#[test]
fn gate_content_address_excludes_materialization_cache_from_identity() {
    let scenario = scenario("scenario=cache\nnodes=a\nseed=17");
    let configuration = step(
        &Configuration::genesis(scenario.clone()),
        Decision::FaultFires(FaultDecision {
            at: VirtualTime { ticks: 5 },
            fault: FaultId {
                name: String::from("disk-delay"),
            },
            fired: true,
        }),
    );
    let id = configuration.content_hash();
    let thin = Checkpoint::new(id, id, CheckpointKind::Thin);
    let fat = Checkpoint::new(id, id, CheckpointKind::Fat);

    assert_eq!(thin.id, fat.id);
    assert_eq!(thin.configuration, fat.configuration);
    assert_ne!(thin.kind, fat.kind);
    assert_eq!(configuration.content_hash(), id);
    assert_eq!(
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &configuration.schedule)),
        assert_twice_reduce_canonical_digest(|| reduce(&scenario, &configuration.schedule))
    );
}

#[test]
fn gate_content_address_checkpoint_identity_matches_configuration_id() {
    for seed in 0..64 {
        let scenario = scenario(&format!("scenario=checkpoint\nseed={seed}\n"));
        let parent = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(seed, 2),
        };
        let configuration = step(&parent, generated_decision(seed, 99));
        let schedule_delta = match configuration.schedule.suffix_from(parent.schedule.len()) {
            Ok(schedule) => schedule,
            Err(error) => panic!("generated parent must be a prefix: {error}"),
        };
        let node = NodeId {
            name: format!("node-{seed}"),
        };
        let node_icounts = BTreeMap::from([(
            node.clone(),
            Icount {
                retired: seed * 17 + 3,
            },
        )]);
        let node_blobs = BTreeMap::from([(
            node,
            NodeBlobRef::baked(ContentHash::from_canonical_material(
                "crucible.test.content-address.checkpoint-blob",
                &format!("seed={seed}"),
            )),
        )]);
        let checkpoint = Checkpoint::from_recorded_configuration(
            &configuration,
            Some(&parent),
            VirtualTime { ticks: seed * 23 },
            node_icounts.clone(),
            CheckpointKind::Thin,
            node_blobs,
        )
        .unwrap_or_else(|error| panic!("valid parent edge should build checkpoint: {error}"));
        let materialized =
            checkpoint
                .clone()
                .with_materialized_state(Some(MaterializedState::from_content_hash(
                    ContentHash::from_canonical_material(
                        "crucible.test.content-address.materialized-state",
                        &format!("seed={seed}"),
                    ),
                )));
        let covered =
            materialized
                .clone()
                .with_coverage_fingerprint(ContentHash::from_canonical_material(
                    "crucible.test.content-address.coverage",
                    &format!("seed={seed}"),
                ));
        let annotated = covered
            .clone()
            .with_metadata(CheckpointMeta::from_labels(BTreeMap::from([(
                String::from("owner"),
                format!("case-{seed}"),
            )])));

        assert_eq!(checkpoint.id, configuration.id());
        assert_eq!(checkpoint.configuration, configuration.id());
        assert_eq!(checkpoint.scenario_ref, scenario.id);
        assert_eq!(checkpoint.parent, Some(parent.id()));
        assert_eq!(checkpoint.schedule_delta, schedule_delta);
        assert_eq!(checkpoint.virtual_time, VirtualTime { ticks: seed * 23 });
        assert_eq!(checkpoint.node_icounts, node_icounts);
        assert_eq!(materialized.id, checkpoint.id);
        assert_eq!(covered.id, checkpoint.id);
        assert_eq!(annotated.id, checkpoint.id);
        assert_eq!(annotated.configuration, configuration.id());
    }
}

#[test]
fn gate_content_address_materialized_state_hashes_loadvm_components() {
    let node = NodeId {
        name: String::from("node-a"),
    };
    let peer = NodeId {
        name: String::from("node-b"),
    };
    let device = DeviceId {
        name: String::from("disk-a"),
    };
    let timer = TimerId {
        name: String::from("heal-after"),
    };
    let fault = FaultId {
        name: String::from("partition-a-b"),
    };
    let stream = RngStreamId {
        name: String::from("device/disk-a"),
    };
    let parent_blob =
        ContentHash::from_canonical_material("crucible.test.materialized-state", "parent-blob");
    let delta_blob =
        ContentHash::from_canonical_material("crucible.test.materialized-state", "delta-blob");
    let resolved_blob =
        ContentHash::from_canonical_material("crucible.test.materialized-state", "resolved-blob");
    let payload =
        ContentHash::from_canonical_material("crucible.test.materialized-state", "frame-payload");
    let event_log = EventLogOffset::new(
        ContentHash::from_canonical_material(
            "crucible.test.materialized-state",
            "event-log-prefix",
        ),
        128,
        9,
    );
    let snapshots = BTreeMap::from([(
        node.clone(),
        VmSnapshotRef::new(
            NodeBlobRef::cow_delta(parent_blob, delta_blob, resolved_blob),
            Icount { retired: 4096 },
        ),
    )]);
    let device_rng = DeviceRngState {
        streams: BTreeMap::from([(stream.clone(), RngStreamPosition::new(7))]),
    };
    let overlays = BTreeMap::from([(
        device,
        DeviceOverlayDelta::new(parent_blob, delta_blob, resolved_blob, device_rng),
    )]);
    let scheduler = SchedulerState {
        horizons: BTreeMap::from([(node.clone(), VirtualTime { ticks: 44 })]),
        pending_frames: BTreeMap::from([(
            peer.clone(),
            vec![PendingFrame {
                source: node.clone(),
                sequence: 3,
                delivery_icount: Icount { retired: 8192 },
                payload,
            }],
        )]),
        timers: TimerRegistry {
            timers: BTreeMap::from([(
                timer,
                TimerState {
                    owner: peer,
                    armed_at: VirtualTime { ticks: 12 },
                    fire_at: VirtualTime { ticks: 99 },
                    fire_icount: Icount { retired: 16384 },
                },
            )]),
        },
        active_faults: BTreeMap::from([(
            fault,
            FaultState {
                active_since: VirtualTime { ticks: 15 },
                heal_at: Some(VirtualTime { ticks: 120 }),
            },
        )]),
    };
    let decision_rng = DecisionRngState {
        positions: BTreeMap::from([(stream, RngStreamPosition::new(11))]),
    };
    let state = MaterializedState::from_components(
        snapshots.clone(),
        overlays.clone(),
        scheduler.clone(),
        decision_rng.clone(),
        event_log,
    );
    let same = MaterializedState::from_components(
        snapshots.clone(),
        overlays.clone(),
        scheduler.clone(),
        decision_rng.clone(),
        event_log,
    );
    let mut changed_snapshots = snapshots;
    changed_snapshots
        .get_mut(&node)
        .unwrap_or_else(|| panic!("snapshot fixture should contain node"))
        .icount = Icount { retired: 4097 };
    let changed = MaterializedState::from_components(
        changed_snapshots,
        overlays,
        scheduler,
        decision_rng,
        event_log,
    );

    assert_eq!(state.id, same.id);
    assert_ne!(state.id, changed.id);
    assert_eq!(state.vm_snapshots[&node].blob.content_hash(), resolved_blob);
    assert_eq!(state.event_log, event_log);
}

#[test]
fn gate_content_address_cow_sharing_dedups_identical_fork_deltas() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "cow-sharing-root",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}")),
        )
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    let first = step(&genesis, generated_decision(377, 0));
    let second = step(&genesis, generated_decision(377, 1));
    let shared_vm_delta =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.vm", "dirty-page=7");
    let shared_overlay_delta =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.overlay", "sector=22");
    let shared_log_prefix =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.log", "shared-prefix");
    let shared_log_segment =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.log", "events=boot-ready");
    let first_checkpoint = cow_fork_checkpoint(
        &first,
        &genesis,
        shared_vm_delta,
        shared_overlay_delta,
        shared_log_prefix,
        shared_log_segment,
    );
    let second_checkpoint = cow_fork_checkpoint(
        &second,
        &genesis,
        shared_vm_delta,
        shared_overlay_delta,
        shared_log_prefix,
        shared_log_segment,
    );
    let first_refs: BTreeSet<_> = first_checkpoint.cow_delta_refs().into_iter().collect();
    let second_refs: BTreeSet<_> = second_checkpoint.cow_delta_refs().into_iter().collect();

    assert!(first_refs.contains(&CowDeltaRef::new(CowDeltaKind::VmMemory, shared_vm_delta)));
    assert!(first_refs.contains(&CowDeltaRef::new(
        CowDeltaKind::DeviceOverlay,
        shared_overlay_delta
    )));
    assert!(first_refs.contains(&CowDeltaRef::new(
        CowDeltaKind::EventLogSegment,
        shared_log_segment
    )));
    assert_eq!(first_refs.len(), 4);
    assert_eq!(second_refs.len(), 4);
    assert_eq!(
        graph.marginal_fork_cow_delta_objects(&first_checkpoint),
        first_refs.len()
    );

    graph
        .cache_snapshot(&first, first_checkpoint)
        .unwrap_or_else(|error| panic!("first fork should cache: {error}"));

    assert_eq!(graph.marginal_fork_cow_delta_objects(&second_checkpoint), 1);

    graph
        .cache_snapshot(&second, second_checkpoint)
        .unwrap_or_else(|error| panic!("second fork should cache: {error}"));
    let stats = graph.cow_sharing_stats();

    assert_eq!(stats.unique_objects, 5);
    assert_eq!(stats.logical_references, 10);
    assert_eq!(stats.deduped_references(), 5);
}

#[test]
fn gate_content_address_checkpoint_rejects_malformed_parent_edges() {
    let scenario_def = scenario("scenario=checkpoint-parent\nseed=89\n");
    let parent = Configuration {
        def: scenario_def.clone(),
        schedule: generated_schedule(89, 2),
    };
    let configuration = step(&parent, generated_decision(89, 99));
    let sibling_parent = Configuration {
        def: scenario_def.clone(),
        schedule: generated_schedule(89, 1).appended(generated_decision(90, 44)),
    };
    let other_scenario_parent = Configuration::genesis(scenario("scenario=other\nseed=89\n"));

    assert!(
        Checkpoint::from_recorded_configuration(
            &configuration,
            Some(&parent),
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Thin,
            BTreeMap::new(),
        )
        .is_ok()
    );
    assert_checkpoint_topology_reason(
        Checkpoint::from_recorded_configuration(
            &configuration,
            None,
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Thin,
            BTreeMap::new(),
        ),
        "descendant-missing-parent",
    );
    assert_checkpoint_topology_reason(
        Checkpoint::from_recorded_configuration(
            &Configuration::genesis(scenario_def.clone()),
            Some(&parent),
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Thin,
            BTreeMap::new(),
        ),
        "genesis-has-parent",
    );
    assert_checkpoint_topology_reason(
        Checkpoint::from_recorded_configuration(
            &configuration,
            Some(&sibling_parent),
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Thin,
            BTreeMap::new(),
        ),
        "parent-not-schedule-prefix",
    );
    assert_checkpoint_topology_reason(
        Checkpoint::from_recorded_configuration(
            &configuration,
            Some(&other_scenario_parent),
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Thin,
            BTreeMap::new(),
        ),
        "parent-scenario-mismatch",
    );
}

#[test]
fn gate_content_address_rejects_corrupt_checkpoint_cache_topology() {
    let scenario_def = scenario("scenario=checkpoint-cache\nseed=144\n");
    let configuration = Configuration {
        def: scenario_def,
        schedule: generated_schedule(144, 3),
    };
    let valid = recorded_fat_checkpoint(&configuration);
    let mut wrong_scenario = valid.clone();
    wrong_scenario.scenario_ref = scenario("scenario=other-cache\nseed=144\n").id;
    let mut wrong_parent = valid.clone();
    wrong_parent.parent = None;
    let mut wrong_delta = valid.clone();
    wrong_delta.schedule_delta = Schedule::empty();

    assert_cache_topology_reason(&configuration, wrong_scenario, "scenario-ref-mismatch");
    assert_cache_topology_reason(&configuration, wrong_parent, "parent-mismatch");
    assert_cache_topology_reason(&configuration, wrong_delta, "schedule-delta-mismatch");
}

#[test]
fn gate_content_address_temporal_graph_records_step_closure_and_parent_chain() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "temporal-graph-root",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}"));
    let root_checkpoint = baked.checkpoint.clone();
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&scenario, baked)
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    let first_decision = generated_decision(233, 0);
    let first_config = step(&genesis, first_decision.clone());
    let first_checkpoint = graph
        .record_step(&genesis, first_decision.clone())
        .unwrap_or_else(|error| panic!("first step should record: {error}"));
    let duplicate_first = graph
        .record_step(&genesis, first_decision)
        .unwrap_or_else(|error| panic!("duplicate first step should dedup: {error}"));
    let second_decision = generated_decision(233, 1);
    let second_config = step(&first_config, second_decision.clone());
    let second_checkpoint = graph
        .record_step(&first_config, second_decision)
        .unwrap_or_else(|error| panic!("second step should record: {error}"));
    let chain = graph
        .checkpoint_parent_chain(second_checkpoint.id)
        .unwrap_or_else(|error| panic!("parent chain should resolve: {error}"));
    let mut reconstructed = Schedule::empty();

    assert_eq!(first_checkpoint.id, first_config.id());
    assert_eq!(duplicate_first.id, first_checkpoint.id);
    assert_eq!(second_checkpoint.id, second_config.id());
    assert_eq!(graph.checkpoint_node_count(), 3);
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0], root_checkpoint);
    assert_eq!(chain[0].kind, CheckpointKind::Fat);
    assert!(chain[0].parent.is_none());
    assert_eq!(chain[1].parent, Some(chain[0].id));
    assert_eq!(chain[2].parent, Some(chain[1].id));

    for checkpoint in &chain {
        reconstructed = append_schedule(&reconstructed, &checkpoint.schedule_delta);
        let prefix_configuration = Configuration {
            def: scenario.clone(),
            schedule: reconstructed.clone(),
        };
        assert_eq!(checkpoint.id, prefix_configuration.id());
        assert_eq!(checkpoint.configuration, prefix_configuration.id());
    }
    assert_eq!(reconstructed, second_config.schedule);
}

#[test]
fn gate_content_address_temporal_graph_frontier_records_checkpoint_dag_children() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "temporal-graph-frontier",
    ));
    let scenario = world.scenario_def();
    let frontier = Configuration::genesis(scenario.clone());
    let baked = bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}"));
    let root_checkpoint = baked.checkpoint.clone();
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&scenario, baked)
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    let duplicate = generated_decision(244, 0);
    let distinct = generated_decision(244, 1);
    let first = graph
        .enumerate_frontier(
            &frontier,
            vec![duplicate.clone(), duplicate, distinct.clone()],
        )
        .unwrap_or_else(|error| panic!("frontier should record children: {error}"));
    let second = graph
        .enumerate_frontier(&frontier, vec![generated_decision(244, 0), distinct])
        .unwrap_or_else(|error| panic!("frontier should reuse recorded children: {error}"));

    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|child| !child.already_recorded));
    assert_eq!(second.len(), 2);
    assert!(second.iter().all(|child| child.already_recorded));
    assert_eq!(graph.checkpoint_node_count(), 3);

    for child in &first {
        let chain = graph
            .checkpoint_parent_chain(child.configuration.id())
            .unwrap_or_else(|error| panic!("frontier child chain should resolve: {error}"));
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0], root_checkpoint);
        assert_eq!(chain[1].id, child.configuration.id());
        assert_eq!(chain[1].parent, Some(root_checkpoint.id));
    }
}

#[test]
fn gate_content_address_temporal_graph_requires_baked_genesis_root() {
    let scenario = scenario("temporal-graph-missing-root");
    let genesis = Configuration::genesis(scenario.clone());
    let mut graph = TemporalGraph::empty();

    let error = graph
        .record_step(&genesis, generated_decision(250, 0))
        .unwrap_err();

    assert!(matches!(
        error,
        EngineError::MissingBakedGenesis { scenario: missing } if missing == scenario.id
    ));
    assert_eq!(graph.checkpoint_node_count(), 0);
    assert_eq!(graph.recorded_configuration_count(), 0);

    let error = graph
        .enumerate_frontier(&genesis, vec![generated_decision(250, 1)])
        .unwrap_err();

    assert!(matches!(
        error,
        EngineError::MissingBakedGenesis { scenario: missing } if missing == scenario.id
    ));
    assert_eq!(graph.checkpoint_node_count(), 0);
    assert_eq!(graph.recorded_configuration_count(), 0);
}

#[test]
fn gate_content_address_collision_corpus_has_unique_ids() {
    let mut seen = BTreeSet::new();

    for index in 0..512_u64 {
        let material = format!(
            "kind=corpus\nindex={index}\nnode=node-{}\nseed={}\n",
            index % 17,
            index.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        );
        let id =
            ContentHash::from_canonical_material("crucible.test.content-address.corpus", &material);
        assert!(
            seen.insert(id),
            "duplicate content id for corpus index {index}"
        );
    }
}

fn assert_twice_reduce_canonical_digest<T, E, F>(mut reduce: F) -> T
where
    T: Debug + PartialEq,
    E: Debug,
    F: FnMut() -> Result<T, E>,
{
    let first = match reduce() {
        Ok(value) => value,
        Err(error) => panic!("first reduction failed: {error:?}"),
    };
    let second = match reduce() {
        Ok(value) => value,
        Err(error) => panic!("second reduction failed: {error:?}"),
    };
    assert_eq!(first, second);
    first
}

fn assert_checkpoint_topology_reason(
    result: Result<Checkpoint, EngineError>,
    expected_reason: &'static str,
) {
    match result {
        Ok(_) => panic!("malformed checkpoint edge should fail"),
        Err(EngineError::CheckpointTopologyMismatch { reason, .. }) => {
            assert_eq!(reason, expected_reason);
        }
        Err(error) => panic!("wrong checkpoint error: {error:?}"),
    }
}

fn assert_cache_topology_reason(
    configuration: &Configuration,
    checkpoint: Checkpoint,
    expected_reason: &'static str,
) {
    match TemporalGraph::empty().with_cached_snapshot(configuration, checkpoint) {
        Ok(_) => panic!("corrupt checkpoint topology should fail cache validation"),
        Err(EngineError::CheckpointTopologyMismatch { reason, .. }) => {
            assert_eq!(reason, expected_reason);
        }
        Err(error) => panic!("wrong cache validation error: {error:?}"),
    }
}

fn scenario(material: &str) -> ScenarioDef {
    ScenarioDef::from_canonical_material("crucible.test.content-address.scenario", material)
}

fn fixed_schedule() -> Schedule {
    Schedule::empty()
        .appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: vec![EventKey { sequence: 2 }, EventKey { sequence: 3 }],
        }))
        .appended(Decision::FaultFires(FaultDecision {
            at: VirtualTime { ticks: 4 },
            fault: FaultId {
                name: String::from("link-a-b/drop"),
            },
            fired: true,
        }))
        .appended(Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId {
                name: String::from("guest/request"),
            },
            request_id: 12,
            width: 32,
            value: 0xabcd_1234,
        }))
}

fn generated_schedule(seed: u64, decisions: u64) -> Schedule {
    let mut schedule = Schedule::empty();
    for index in 0..decisions {
        schedule = schedule.appended(generated_decision(seed, index));
    }
    schedule
}

fn generated_decision(seed: u64, index: u64) -> Decision {
    match (seed + index) % 3 {
        0 => Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime {
                ticks: seed + index,
            },
            order: vec![EventKey { sequence: index }],
        }),
        1 => Decision::FaultFires(FaultDecision {
            at: VirtualTime {
                ticks: seed + index,
            },
            fault: FaultId {
                name: format!("fault-{seed}-{index}"),
            },
            fired: index % 2 == 0,
        }),
        _ => Decision::RngDraw(RngDecision {
            stream: RngStreamId {
                name: format!("stream-{seed}"),
            },
            value: seed ^ index,
        }),
    }
}

fn cow_fork_checkpoint(
    configuration: &Configuration,
    parent: &Configuration,
    vm_delta: ContentHash,
    overlay_delta: ContentHash,
    log_prefix: ContentHash,
    log_segment: ContentHash,
) -> Checkpoint {
    let node = NodeId {
        name: String::from("node-a"),
    };
    let device = DeviceId {
        name: String::from("disk-a"),
    };
    let parent_vm =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.vm", "parent-ready");
    let resolved_vm =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.vm", "resolved-dirty");
    let parent_overlay =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.overlay", "base");
    let resolved_overlay =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.overlay", "resolved");
    let icount = Icount { retired: 33 };
    let node_blobs = BTreeMap::from([(
        node.clone(),
        NodeBlobRef::cow_delta(parent_vm, vm_delta, resolved_vm),
    )]);
    let node_icounts = BTreeMap::from([(node.clone(), icount)]);
    let state = MaterializedState::from_components(
        BTreeMap::from([(
            node,
            VmSnapshotRef::new(
                NodeBlobRef::cow_delta(parent_vm, vm_delta, resolved_vm),
                icount,
            ),
        )]),
        BTreeMap::from([(
            device,
            DeviceOverlayDelta::new(
                parent_overlay,
                overlay_delta,
                resolved_overlay,
                DeviceRngState::empty(),
            ),
        )]),
        SchedulerState::empty(),
        DecisionRngState::empty(),
        EventLogOffset::with_appended_segment(log_prefix, 96, 3, log_segment),
    );

    Checkpoint::from_recorded_configuration(
        configuration,
        Some(parent),
        VirtualTime::default(),
        node_icounts,
        CheckpointKind::Fat,
        node_blobs,
    )
    .unwrap_or_else(|error| panic!("CoW fork checkpoint should be recorded-shaped: {error}"))
    .with_materialized_state(Some(state))
}

fn recorded_fat_checkpoint(configuration: &Configuration) -> Checkpoint {
    let parent = if configuration.is_genesis() {
        None
    } else {
        let schedule = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))
            .unwrap_or_else(|error| panic!("test schedule prefix should build: {error}"));
        Some(Configuration {
            def: configuration.def.clone(),
            schedule,
        })
    };
    Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("test checkpoint should be recorded-shaped: {error}"))
}

fn append_schedule(prefix: &Schedule, delta: &Schedule) -> Schedule {
    let mut schedule = prefix.clone();
    for decision in delta.decisions() {
        schedule = schedule.appended(decision.clone());
    }
    schedule
}

fn fixed_vectors(
    scenario: &ScenarioDef,
    schedule: &Schedule,
    configuration: &Configuration,
    state: &State,
) -> [(&'static str, String); 7] {
    [
        ("scenario", hash_hex(scenario.id)),
        ("schedule", hash_hex(schedule.content_hash())),
        ("configuration", hash_hex(configuration.content_hash())),
        ("state", hash_hex(state.id)),
        (
            "world-component",
            hash_hex(ContentHash::from_canonical_material(
                "crucible.test.content-address.world",
                "nodes=[node-a,node-b]\nlinks=[a-b]\n",
            )),
        ),
        (
            "snapshot-blob",
            hash_hex(ContentHash::from_canonical_material(
                "crucible.test.content-address.snapshot",
                "vm=node-a\npage=0000\nbytes=0011223344556677\n",
            )),
        ),
        (
            "event-log-segment",
            hash_hex(ContentHash::from_canonical_material(
                "crucible.test.content-address.log",
                "0 delivery node-a->node-b icount=5\n1 fault link-drop fired=true\n",
            )),
        ),
    ]
}

fn expected_vectors(vectors: [(&'static str, &'static str); 7]) -> [(&'static str, String); 7] {
    vectors.map(|(name, hash)| (name, hash.to_owned()))
}

fn hash_hex(hash: ContentHash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(hash.bytes.len() * 2);
    for byte in hash.bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
