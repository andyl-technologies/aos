//! Implements `gate:content-address` over the execution-model identity spine.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible::{
    AppRandomDecision, Checkpoint, CheckpointKind, CheckpointMeta, Configuration, ContentHash,
    CowDeltaKind, CowDeltaRef, DagStore, DagStoreError, DagStoreReproductionArtifact, Decision,
    DecisionRngState, DeliveryOrderDecision, DeviceId, DeviceOverlayDelta, DeviceRngState,
    EffectOutcomeDecision, EngineError, EventKey, EventLogOffset, EventSequenceState, FaultId,
    FaultState, FrontierReductionPolicy, FrontierReductionReason, Icount, IrqVector, LocalDagStore,
    MaterializationPolicy, MaterializationTrigger, MaterializedState, MemoryDagStore,
    NetworkLinkRuntimeCursor, NodeBlobRef, NodeId, PartialOrderReductionPolicy, PendingFrame,
    PreemptionDecision, PreemptionKind, RngDecision, RngStreamId, RngStreamPosition, ScenarioDef,
    Schedule, SchedulerNodeId, SchedulerState, SchedulingNodeKind, SearchFrontierChoices, State,
    SymmetryClassId, SymmetryReductionClasses, TemporalGraph, TemporalGraphGcRoots,
    TemporalGraphStoreError, TimerId, TimerRegistry, TimerState, VcpuId, VirtualTime,
    VmSnapshotRef, World, bake, instantiate, reduce, step,
};

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

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
                "10999eb4e514503faa0ed63c2d63906ea2ab683c54679e151e50d2f3ea9f1f1f"
            ),
            (
                "schedule",
                "c2b68e7b541ae33c09353c9ea1c1d6279528210f38a58b691660656e4b184892"
            ),
            (
                "configuration",
                "fb8a2f5a06ec7ab97784f947fe77a7376c18856e9b9b9e7798a8e5dbf88a5040",
            ),
            (
                "state",
                "15012a0bf6d785b9ef33c4cfb437164c83e0aa213b4cc8263bd1a09248c702cf"
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

    assert_eq!(first_scenario.id(), second_scenario.id());
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
        ScenarioDef::from_canonical_material("crucible.test.content-address.scenario", "seed=1")
            .id(),
        ScenarioDef::from_canonical_material("crucible.test.content-address.scenario", "seed=2")
            .id()
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
            stream: RngStreamId::for_node("node-a/fault"),
            value: 1,
        }),
    );
    let changed = step(
        &base,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_node("node-a/fault"),
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
        stream: RngStreamId::from_name("scheduler/order"),
        value: 9,
    });
    let delivery = Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 3 },
        order: vec![event_key(3, 1)],
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
        Decision::EffectOutcome(EffectOutcomeDecision {
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
        assert_eq!(checkpoint.scenario_ref, scenario.id());
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
    let network_link = DeviceId {
        name: String::from("link-a-to-b"),
    };
    let timer = TimerId {
        name: String::from("heal-after"),
    };
    let fault = FaultId {
        name: String::from("partition-a-b"),
    };
    let stream = RngStreamId::from_name("device/disk-a");
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
        network_link_cursors: BTreeMap::from([(
            network_link.clone(),
            NetworkLinkRuntimeCursor {
                current_icount: 17,
                next_sequence: 2,
                rng_position: 11,
                inflight: Vec::new(),
            },
        )]),
        event_sequences: EventSequenceState::empty(),
        topology_epoch: 0,
        effective_topology_edges: Vec::new(),
        pending_topology_changes: Vec::new(),
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
        active_fault_tags: BTreeMap::new(),
        active_fault_table: crucible::ActiveFaultTable::default(),
        pending_device_decisions: Vec::new(),
        search_frontier: SearchFrontierChoices::empty(),
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
    let mut changed_scheduler = scheduler.clone();
    changed_scheduler
        .network_link_cursors
        .get_mut(&network_link)
        .unwrap_or_else(|| panic!("scheduler fixture should contain network link"))
        .rng_position = 12;
    let changed_network_cursor = MaterializedState::from_components(
        snapshots.clone(),
        overlays.clone(),
        changed_scheduler,
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
    assert_ne!(state.id, changed_network_cursor.id);
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
fn gate_content_address_dag_store_put_get_exists_dedups_equal_bytes() {
    let store = MemoryDagStore::new();
    let bytes = b"checkpoint-node\nparent=genesis\ndelta=decision-0\n";
    let first = store
        .put(bytes)
        .unwrap_or_else(|error| panic!("first store put should succeed: {error}"));
    let second = store
        .put(bytes)
        .unwrap_or_else(|error| panic!("second identical store put should succeed: {error}"));
    let changed = store
        .put(b"checkpoint-node\nparent=genesis\ndelta=decision-1\n")
        .unwrap_or_else(|error| panic!("changed store put should succeed: {error}"));
    let missing = ContentHash::from_bytes(b"missing-object");

    assert_eq!(first, second);
    assert_ne!(first, changed);
    assert_eq!(
        first.to_hex(),
        "ccd5518b5e42662190b09ab692a0d86827cea51e1c2e782cabe9474e575a0ee3"
    );
    assert_eq!(
        store
            .get(&first)
            .unwrap_or_else(|error| panic!("stored object should be readable: {error}")),
        bytes
    );
    assert!(
        store
            .exists(&first)
            .unwrap_or_else(|error| panic!("stored object lookup should succeed: {error}"))
    );
    assert!(
        !store
            .exists(&missing)
            .unwrap_or_else(|error| panic!("missing object lookup should succeed: {error}"))
    );
    assert!(
        store
            .delete(&changed)
            .unwrap_or_else(|error| panic!("stored object delete should succeed: {error}"))
    );
    assert!(
        !store
            .exists(&changed)
            .unwrap_or_else(|error| panic!("deleted object lookup should succeed: {error}"))
    );
    assert!(
        !store
            .delete(&changed)
            .unwrap_or_else(|error| panic!("repeated delete should be idempotent: {error}"))
    );
    assert!(matches!(
        store.get(&missing),
        Err(DagStoreError::NotFound { key }) if key == missing
    ));
    assert_eq!(
        store
            .object_count()
            .unwrap_or_else(|error| panic!("memory store count should be readable: {error}")),
        1
    );
}

#[test]
fn gate_content_address_local_dag_store_uses_two_level_layout() {
    let root = unique_temp_dir("local-dag-store");
    let store = LocalDagStore::new(root.clone());
    let bytes = b"vm-delta\npage=7\nbytes=dirty\n";
    let key = store
        .put(bytes)
        .unwrap_or_else(|error| panic!("local store put should succeed: {error}"));
    let path = store.object_path(&key);
    let hex = key.to_hex();

    assert_eq!(path, root.join(&hex[0..2]).join(&hex));
    assert_eq!(
        fs::read(&path).unwrap_or_else(|error| panic!("object file should be readable: {error}")),
        bytes
    );
    assert_eq!(
        store
            .get(&key)
            .unwrap_or_else(|error| panic!("local object should be readable: {error}")),
        bytes
    );
    assert!(
        store
            .exists(&key)
            .unwrap_or_else(|error| panic!("local object lookup should succeed: {error}"))
    );

    let repeated = store
        .put(bytes)
        .unwrap_or_else(|error| panic!("repeated local put should dedup: {error}"));
    let fanout_entries = fs::read_dir(root.join(&hex[0..2]))
        .unwrap_or_else(|error| panic!("fanout directory should be readable: {error}"))
        .count();

    assert_eq!(repeated, key);
    assert_eq!(fanout_entries, 1);
    assert!(
        store
            .delete(&key)
            .unwrap_or_else(|error| panic!("local object delete should succeed: {error}"))
    );
    assert!(
        !store
            .exists(&key)
            .unwrap_or_else(|error| panic!("deleted local object lookup should succeed: {error}"))
    );
    assert!(
        !store
            .delete(&key)
            .unwrap_or_else(|error| panic!("repeated local delete should be idempotent: {error}"))
    );

    fs::remove_dir_all(&root)
        .unwrap_or_else(|error| panic!("temporary DAG store root should remove: {error}"));
}

#[test]
fn gate_content_address_local_dag_store_repairs_corrupt_object_path() {
    let root = unique_temp_dir("local-dag-store-corrupt");
    let store = LocalDagStore::new(root.clone());
    let bytes = b"vm-delta\npage=9\nbytes=repaired\n";
    let key = ContentHash::from_bytes(bytes);
    let path = store.object_path(&key);
    let parent = path
        .parent()
        .unwrap_or_else(|| panic!("object path should have a fanout parent"));

    fs::create_dir_all(parent)
        .unwrap_or_else(|error| panic!("fanout directory should be creatable: {error}"));
    fs::write(&path, b"corrupt-object")
        .unwrap_or_else(|error| panic!("corrupt object fixture should be writable: {error}"));

    assert!(matches!(
        store.get(&key),
        Err(DagStoreError::ContentMismatch { expected, .. }) if expected == key
    ));
    assert!(matches!(
        store.exists(&key),
        Err(DagStoreError::ContentMismatch { expected, .. }) if expected == key
    ));

    let repaired = store
        .put(bytes)
        .unwrap_or_else(|error| panic!("put should repair corrupt content-address path: {error}"));

    assert_eq!(repaired, key);
    assert_eq!(
        fs::read(&path).unwrap_or_else(|error| panic!("repaired object should read: {error}")),
        bytes
    );
    assert!(
        store
            .exists(&key)
            .unwrap_or_else(|error| panic!("repaired object lookup should succeed: {error}"))
    );

    fs::remove_dir_all(&root)
        .unwrap_or_else(|error| panic!("temporary DAG store root should remove: {error}"));
}

#[test]
fn gate_content_address_reproduction_artifact_is_store_key_closure() {
    let store = MemoryDagStore::new();
    let scenario_key = store
        .put(b"scenario-def\nnodes=a,b\nseed=42\n")
        .unwrap_or_else(|error| panic!("scenario bytes should store: {error}"));
    let genesis_key = store
        .put(b"genesis-snapshot\nnode=a\nnode=b\n")
        .unwrap_or_else(|error| panic!("genesis bytes should store: {error}"));
    let first_delta = store
        .put(b"schedule-delta\ndecision=deliver-a-b\n")
        .unwrap_or_else(|error| panic!("first delta should store: {error}"));
    let second_delta = store
        .put(b"schedule-delta\ndecision=deliver-a-b\n")
        .unwrap_or_else(|error| panic!("duplicate delta should dedup: {error}"));
    let artifact = DagStoreReproductionArtifact::new(
        scenario_key,
        genesis_key,
        vec![first_delta, second_delta],
    );

    assert_eq!(first_delta, second_delta);
    assert_eq!(
        artifact.store_keys(),
        BTreeSet::from([scenario_key, genesis_key, first_delta])
    );
    for key in artifact.store_keys() {
        assert!(
            store
                .exists(&key)
                .unwrap_or_else(|error| panic!("artifact key lookup should succeed: {error}"))
        );
    }
}

#[test]
fn gate_content_address_temporal_graph_persists_checkpoint_closure_in_dag_store() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "dag-store-persist-root",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let first = step(&genesis, generated_decision(610, 0));
    let vm_delta =
        ContentHash::from_canonical_material("crucible.test.dag-store-persist.vm", "dirty-page=11");
    let overlay_delta =
        ContentHash::from_canonical_material("crucible.test.dag-store-persist.overlay", "sector=7");
    let log_prefix =
        ContentHash::from_canonical_material("crucible.test.dag-store-persist.log", "prefix");
    let log_segment_bytes = b"crucible.test.dag-store-persist.log.segment";
    let log_segment = ContentHash::from_bytes(log_segment_bytes);
    let fat_checkpoint = cow_fork_checkpoint(
        &first,
        &genesis,
        vm_delta,
        overlay_delta,
        log_prefix,
        log_segment,
    );
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}")),
        )
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    graph
        .cache_snapshot(&first, fat_checkpoint)
        .unwrap_or_else(|error| panic!("fat checkpoint should cache: {error}"));
    let store = MemoryDagStore::new();
    store
        .put(log_segment_bytes)
        .unwrap_or_else(|error| panic!("event-log segment bytes should store: {error}"));

    let first_keys = graph
        .persist_checkpoint_closure(&store, &first)
        .unwrap_or_else(|error| panic!("checkpoint closure should persist: {error}"));
    let second_keys = graph
        .persist_checkpoint_closure(&store, &first)
        .unwrap_or_else(|error| panic!("checkpoint closure should dedup on replay: {error}"));
    let schedule_ref = CowDeltaRef::new(CowDeltaKind::ScheduleDelta, first.schedule.content_hash());
    let vm_ref = CowDeltaRef::new(CowDeltaKind::VmMemory, vm_delta);
    let overlay_ref = CowDeltaRef::new(CowDeltaKind::DeviceOverlay, overlay_delta);
    let log_ref = CowDeltaRef::new(CowDeltaKind::EventLogSegment, log_segment);

    assert_eq!(first_keys, second_keys);
    assert_eq!(first_keys.checkpoint_nodes.len(), 2);
    assert_eq!(first_keys.cached_snapshots.len(), 1);
    assert_eq!(first_keys.reproduction_artifact.schedule_deltas.len(), 1);
    assert!(first_keys.checkpoint_nodes.contains_key(&genesis.id()));
    assert!(first_keys.checkpoint_nodes.contains_key(&first.id()));
    assert!(first_keys.cached_snapshots.contains_key(&first.id()));
    assert!(first_keys.cow_deltas.contains_key(&schedule_ref));
    assert!(first_keys.cow_deltas.contains_key(&vm_ref));
    assert!(first_keys.cow_deltas.contains_key(&overlay_ref));
    assert!(first_keys.cow_deltas.contains_key(&log_ref));
    assert_eq!(first_keys.cow_deltas.len(), 4);
    assert_eq!(
        first_keys.reproduction_artifact.schedule_deltas[0],
        first_keys.cow_deltas[&schedule_ref]
    );
    assert_eq!(
        store
            .object_count()
            .unwrap_or_else(|error| panic!("memory store count should be readable: {error}")),
        first_keys.store_keys().len()
    );
    for key in first_keys.store_keys() {
        assert!(
            store
                .exists(&key)
                .unwrap_or_else(|error| panic!("persisted graph key should exist: {error}"))
        );
    }
}

#[test]
fn gate_content_address_gc_refcounts_abandoned_branch_unique_objects() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "gc-refcount-root",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let left = step(&genesis, generated_decision(620, 0));
    let right = step(&genesis, generated_decision(621, 0));
    let shared_vm_delta =
        ContentHash::from_canonical_material("crucible.test.gc-refcount.vm", "shared-dirty-page");
    let left_overlay_delta =
        ContentHash::from_canonical_material("crucible.test.gc-refcount.overlay", "left-sector");
    let right_overlay_delta =
        ContentHash::from_canonical_material("crucible.test.gc-refcount.overlay", "right-sector");
    let log_prefix =
        ContentHash::from_canonical_material("crucible.test.gc-refcount.log", "shared-prefix");
    let left_log_segment_bytes = b"crucible.test.gc-refcount.log.left-segment";
    let right_log_segment_bytes = b"crucible.test.gc-refcount.log.right-segment";
    let left_log_segment = ContentHash::from_bytes(left_log_segment_bytes);
    let right_log_segment = ContentHash::from_bytes(right_log_segment_bytes);
    let left_checkpoint = cow_fork_checkpoint(
        &left,
        &genesis,
        shared_vm_delta,
        left_overlay_delta,
        log_prefix,
        left_log_segment,
    );
    let right_checkpoint = cow_fork_checkpoint(
        &right,
        &genesis,
        shared_vm_delta,
        right_overlay_delta,
        log_prefix,
        right_log_segment,
    );
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}")),
        )
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    graph
        .cache_snapshot(&left, left_checkpoint)
        .unwrap_or_else(|error| panic!("left fork should cache: {error}"));
    graph
        .cache_snapshot(&right, right_checkpoint)
        .unwrap_or_else(|error| panic!("right fork should cache: {error}"));
    let shared_vm_ref = CowDeltaRef::new(CowDeltaKind::VmMemory, shared_vm_delta);
    let left_overlay_ref = CowDeltaRef::new(CowDeltaKind::DeviceOverlay, left_overlay_delta);
    let left_log_ref = CowDeltaRef::new(CowDeltaKind::EventLogSegment, left_log_segment);
    let left_schedule_ref =
        CowDeltaRef::new(CowDeltaKind::ScheduleDelta, left.schedule.content_hash());
    let right_overlay_ref = CowDeltaRef::new(CowDeltaKind::DeviceOverlay, right_overlay_delta);
    let both_roots = TemporalGraphGcRoots::new()
        .with_live_tip(left.id())
        .with_live_tip(right.id());
    let store = MemoryDagStore::new();
    store
        .put(left_log_segment_bytes)
        .unwrap_or_else(|error| panic!("left event-log segment bytes should store: {error}"));
    store
        .put(right_log_segment_bytes)
        .unwrap_or_else(|error| panic!("right event-log segment bytes should store: {error}"));
    let left_keys = graph
        .persist_checkpoint_closure(&store, &left)
        .unwrap_or_else(|error| panic!("left branch should persist before GC: {error}"));
    let right_keys = graph
        .persist_checkpoint_closure(&store, &right)
        .unwrap_or_else(|error| panic!("right branch should persist before GC: {error}"));
    let shared_vm_store_key = left_keys.cow_deltas[&shared_vm_ref];
    let left_overlay_store_key = left_keys.cow_deltas[&left_overlay_ref];
    let left_log_store_key = left_keys.cow_deltas[&left_log_ref];
    let left_schedule_store_key = left_keys.cow_deltas[&left_schedule_ref];
    let left_checkpoint_store_key = left_keys.checkpoint_nodes[&left.id()];
    let left_cache_store_key = left_keys.cached_snapshots[&left.id()];

    let counts = graph
        .reference_counts(&both_roots)
        .unwrap_or_else(|error| panic!("reference counts should compute: {error}"));

    assert_eq!(counts.cow_deltas[&shared_vm_ref], 2);
    assert_eq!(counts.checkpoint_nodes[&right.id()], 1);
    assert_eq!(counts.cow_deltas[&left_overlay_ref], 1);
    assert_eq!(counts.cow_deltas[&left_log_ref], 1);
    assert_eq!(shared_vm_store_key, right_keys.cow_deltas[&shared_vm_ref]);
    assert!(
        store
            .exists(&left_overlay_store_key)
            .unwrap_or_else(|error| panic!("left overlay store key should exist: {error}"))
    );

    let report = graph
        .garbage_collect_store(
            &store,
            &TemporalGraphGcRoots::new().with_live_tip(right.id()),
        )
        .unwrap_or_else(|error| {
            panic!("store-backed GC should collect abandoned left branch: {error}")
        });

    assert!(report.collected_checkpoints.contains(&left.id()));
    assert!(report.collected_cached_snapshots.contains(&left.id()));
    assert!(report.collected_configurations.contains(&left.id()));
    assert!(report.collectible_cow_deltas.contains(&left_overlay_ref));
    assert!(report.collectible_cow_deltas.contains(&left_log_ref));
    assert!(!report.collectible_cow_deltas.contains(&shared_vm_ref));
    assert!(
        report
            .live_reference_counts
            .cow_deltas
            .contains_key(&right_overlay_ref)
    );
    assert!(report.deleted_store_keys.contains(&left_overlay_store_key));
    assert!(report.deleted_store_keys.contains(&left_log_store_key));
    assert!(report.deleted_store_keys.contains(&left_schedule_store_key));
    assert!(
        report
            .deleted_store_keys
            .contains(&left_checkpoint_store_key)
    );
    assert!(report.deleted_store_keys.contains(&left_cache_store_key));
    assert!(report.missing_store_keys.is_empty());
    assert!(
        !store
            .exists(&left_overlay_store_key)
            .unwrap_or_else(|error| panic!(
                "left overlay store key lookup should succeed: {error}"
            ))
    );
    assert!(
        !store
            .exists(&left_log_store_key)
            .unwrap_or_else(|error| panic!("left log store key lookup should succeed: {error}"))
    );
    assert!(
        store
            .exists(&shared_vm_store_key)
            .unwrap_or_else(|error| panic!("shared VM store key should remain: {error}"))
    );
    assert!(graph.checkpoint_node(left.id()).is_none());
    assert!(graph.cached_snapshot(&left).is_none());
    assert!(graph.checkpoint_node(right.id()).is_some());
    assert!(graph.cached_snapshot(&right).is_some());
}

#[test]
fn gate_content_address_gc_mark_sweep_roots_live_tips_pins_and_genesis() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "gc-mark-sweep-root",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let first_decision = generated_decision(720, 0);
    let first = step(&genesis, first_decision.clone());
    let second_decision = generated_decision(720, 1);
    let second = step(&first, second_decision.clone());
    let abandoned_decision = generated_decision(721, 0);
    let abandoned = step(&genesis, abandoned_decision.clone());
    let first_delta_ref = CowDeltaRef::new(
        CowDeltaKind::ScheduleDelta,
        Schedule::empty()
            .appended(first_decision.clone())
            .content_hash(),
    );
    let second_delta_ref = CowDeltaRef::new(
        CowDeltaKind::ScheduleDelta,
        Schedule::empty()
            .appended(second_decision.clone())
            .content_hash(),
    );
    let abandoned_delta_ref = CowDeltaRef::new(
        CowDeltaKind::ScheduleDelta,
        Schedule::empty()
            .appended(abandoned_decision.clone())
            .content_hash(),
    );
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}")),
        )
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    graph
        .record_step(&genesis, first_decision)
        .unwrap_or_else(|error| panic!("first step should record: {error}"));
    graph
        .record_step(&first, second_decision)
        .unwrap_or_else(|error| panic!("second step should record: {error}"));
    graph
        .record_step(&genesis, abandoned_decision)
        .unwrap_or_else(|error| panic!("abandoned sibling should record: {error}"));
    let mut roots = TemporalGraphGcRoots::new()
        .with_live_tip(second.id())
        .with_pinned_checkpoint(second.id());
    roots.live_tips.insert(abandoned.id(), 0);

    let report = graph
        .garbage_collect(&roots)
        .unwrap_or_else(|error| panic!("GC should retain pinned branch: {error}"));
    let chain = graph
        .checkpoint_parent_chain(second.id())
        .unwrap_or_else(|error| panic!("pinned checkpoint chain should remain: {error}"));
    let runtime = instantiate(&graph, &second)
        .unwrap_or_else(|error| panic!("pinned checkpoint should remain realizable: {error}"));

    assert!(report.live_checkpoints.contains(&genesis.id()));
    assert!(report.live_checkpoints.contains(&first.id()));
    assert!(report.live_checkpoints.contains(&second.id()));
    assert!(report.collected_checkpoints.contains(&abandoned.id()));
    assert!(report.collectible_cow_deltas.contains(&abandoned_delta_ref));
    assert_eq!(
        report.live_reference_counts.checkpoint_nodes[&second.id()],
        2
    );
    assert!(
        report
            .live_reference_counts
            .cow_deltas
            .contains_key(&first_delta_ref)
    );
    assert!(
        report
            .live_reference_counts
            .cow_deltas
            .contains_key(&second_delta_ref)
    );
    assert_eq!(chain.len(), 3);
    assert_eq!(runtime.configuration, second.id());
    assert!(graph.checkpoint_node(abandoned.id()).is_none());
}

#[test]
fn gate_content_address_gc_missing_root_errors_without_deleting_store_objects() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "gc-missing-root",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let first = step(&genesis, generated_decision(725, 0));
    let missing = ContentHash::from_canonical_material(
        "crucible.test.content-address.gc",
        "missing-live-root",
    );
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}")),
        )
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    graph
        .record_thin_checkpoint(&first)
        .unwrap_or_else(|error| panic!("thin checkpoint should record: {error}"));
    let store = MemoryDagStore::new();
    graph
        .persist_checkpoint_closure(&store, &first)
        .unwrap_or_else(|error| panic!("recorded branch should persist before GC: {error}"));
    let before_objects = store
        .object_count()
        .unwrap_or_else(|error| panic!("store count should be readable before GC: {error}"));
    let before_checkpoints = graph.checkpoint_node_count();

    let error = graph
        .garbage_collect_store(&store, &TemporalGraphGcRoots::new().with_live_tip(missing))
        .unwrap_err();

    match error {
        TemporalGraphStoreError::Engine { source, .. } => match source.as_ref() {
            EngineError::CheckpointNotRecorded { checkpoint } => assert_eq!(*checkpoint, missing),
            other => panic!("unexpected engine error: {other}"),
        },
        other => panic!("unexpected temporal graph store error: {other}"),
    }
    assert_eq!(graph.checkpoint_node_count(), before_checkpoints);
    assert_eq!(
        store.object_count().unwrap_or_else(|error| panic!(
            "store count should be readable after failed GC: {error}"
        )),
        before_objects
    );
    assert!(graph.checkpoint_node(first.id()).is_some());
}

#[test]
fn gate_content_address_gc_collects_cache_not_identity() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "gc-cache-not-identity-root",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let first = step(&genesis, generated_decision(730, 0));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}")),
        )
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    graph
        .cache_snapshot(&first, recorded_fat_checkpoint(&first))
        .unwrap_or_else(|error| panic!("fat checkpoint should cache: {error}"));
    let store = MemoryDagStore::new();
    let keys = graph
        .persist_checkpoint_closure(&store, &first)
        .unwrap_or_else(|error| panic!("fat checkpoint should persist before cache GC: {error}"));
    let cache_store_key = keys.cached_snapshots[&first.id()];
    let thin_store_key = keys.checkpoint_nodes[&first.id()];

    let report = graph
        .collect_cached_snapshot_store(&store, &first)
        .unwrap_or_else(|error| panic!("fat snapshot cache should collect from store: {error}"))
        .unwrap_or_else(|| panic!("collecting existing fat snapshot should report deleted keys"));
    let runtime = instantiate(&graph, &first)
        .unwrap_or_else(|error| panic!("thin checkpoint should replay after cache GC: {error}"));
    let thin = graph
        .checkpoint_node(first.id())
        .unwrap_or_else(|| panic!("thin checkpoint should remain after cache GC"));

    assert!(report.collected_cached_snapshots.contains(&first.id()));
    assert!(report.deleted_store_keys.contains(&cache_store_key));
    assert!(
        !store
            .exists(&cache_store_key)
            .unwrap_or_else(|error| panic!("cache store key lookup should succeed: {error}"))
    );
    assert!(
        store
            .exists(&thin_store_key)
            .unwrap_or_else(|error| panic!("thin checkpoint key should remain: {error}"))
    );
    assert_eq!(thin.kind, CheckpointKind::Thin);
    assert_eq!(graph.cached_snapshot_count(), 0);
    assert!(graph.cached_snapshot(&first).is_none());
    assert!(matches!(
        graph.checkpoint_node(first.id()),
        Some(checkpoint) if checkpoint.kind == CheckpointKind::Thin
    ));
    assert_eq!(runtime.configuration, first.id());
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
    wrong_scenario.scenario_ref = scenario("scenario=other-cache\nseed=144\n").id();
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
fn gate_content_address_temporal_graph_symmetry_reduction_covers_relabelled_frontier() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "temporal-graph-symmetry-reduction",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}"));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&scenario, baked)
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    let replica_a = node_id("replica-a");
    let replica_b = node_id("replica-b");
    let symmetry_classes = SymmetryReductionClasses::new()
        .with_node_class(replica_a.clone(), symmetry_class("replicas"))
        .with_node_class(replica_b.clone(), symmetry_class("replicas"));
    let base = node_blob("symmetry/base");
    let dirty = node_blob("symmetry/dirty");
    let coverage = ContentHash::from_canonical_material(
        "crucible.test.content-address.coverage",
        "symmetry-class",
    );
    let left_decision = preemption_decision("replica-a", 11);
    let right_decision = preemption_decision("replica-b", 11);
    let left_config = step(&genesis, left_decision.clone());
    let right_config = step(&genesis, right_decision.clone());
    let left_checkpoint = fat_checkpoint_with_coverage(
        &left_config,
        &genesis,
        coverage,
        BTreeMap::from([
            (replica_a.clone(), dirty.clone()),
            (replica_b.clone(), base.clone()),
        ]),
    );
    let right_checkpoint = fat_checkpoint_with_coverage(
        &right_config,
        &genesis,
        coverage,
        BTreeMap::from([(replica_a, base), (replica_b, dirty)]),
    );

    graph
        .cache_snapshot(&left_config, left_checkpoint)
        .unwrap_or_else(|error| panic!("left symmetric checkpoint should cache: {error}"));
    graph
        .cache_snapshot(&right_config, right_checkpoint)
        .unwrap_or_else(|error| panic!("right symmetric checkpoint should cache: {error}"));
    let recorded_before = graph.checkpoint_node_count();

    let left_key = graph
        .symmetry_reduction_key(&left_config, &symmetry_classes)
        .unwrap_or_else(|| panic!("left checkpoint should have a symmetry key"));
    let right_key = graph
        .symmetry_reduction_key(&right_config, &symmetry_classes)
        .unwrap_or_else(|| panic!("right checkpoint should have a symmetry key"));
    let report = graph
        .enumerate_frontier_reduced(
            &genesis,
            vec![left_decision, right_decision],
            FrontierReductionPolicy::none().with_symmetry_classes(symmetry_classes),
        )
        .unwrap_or_else(|error| panic!("reduced frontier should enumerate: {error}"));

    assert_ne!(left_config.id(), right_config.id());
    assert_eq!(left_key, right_key);
    assert_eq!(report.explored.len(), 1);
    assert_eq!(report.covered.len(), 1);
    assert_eq!(report.covered[0].reason, FrontierReductionReason::Symmetry);
    assert_eq!(
        report.covered[0].representative,
        report.explored[0].configuration.id()
    );
    assert_eq!(report.covered[0].reduction_key, left_key.fingerprint);
    assert_eq!(graph.checkpoint_node_count(), recorded_before);
}

#[test]
fn gate_content_address_temporal_graph_symmetry_reduction_explores_without_proof() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "temporal-graph-symmetry-conservative",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}"));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&scenario, baked)
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    let left_decision = preemption_decision("replica-a", 17);
    let right_decision = preemption_decision("replica-b", 17);

    let report = graph
        .enumerate_frontier_reduced(
            &genesis,
            vec![left_decision, right_decision],
            FrontierReductionPolicy::none(),
        )
        .unwrap_or_else(|error| panic!("reduced frontier should enumerate: {error}"));

    assert_eq!(report.explored.len(), 2);
    assert!(report.covered.is_empty());
    assert!(report.explored.iter().all(|child| {
        graph
            .symmetry_reduction_key(&child.configuration, &SymmetryReductionClasses::new())
            .is_none()
    }));
}

#[test]
fn gate_content_address_temporal_graph_symmetry_reduction_explores_when_state_differs() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "temporal-graph-symmetry-state-differs",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}"));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&scenario, baked)
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    let replica_a = node_id("replica-a");
    let replica_b = node_id("replica-b");
    let symmetry_classes = SymmetryReductionClasses::new()
        .with_node_class(replica_a.clone(), symmetry_class("replicas"))
        .with_node_class(replica_b.clone(), symmetry_class("replicas"));
    let base = node_blob("symmetry/state/base");
    let dirty = node_blob("symmetry/state/dirty");
    let coverage = ContentHash::from_canonical_material(
        "crucible.test.content-address.coverage",
        "symmetry-state-differs",
    );
    let left_decision = preemption_decision("replica-a", 41);
    let right_decision = preemption_decision("replica-b", 41);
    let left_config = step(&genesis, left_decision.clone());
    let right_config = step(&genesis, right_decision.clone());
    let left_checkpoint = fat_checkpoint_with_coverage_and_event_log(
        &left_config,
        &genesis,
        coverage,
        BTreeMap::from([
            (replica_a.clone(), dirty.clone()),
            (replica_b.clone(), base.clone()),
        ]),
        EventLogOffset::with_appended_segment(
            ContentHash::from_canonical_material("crucible.test.event-log", "prefix"),
            8,
            1,
            ContentHash::from_canonical_material("crucible.test.event-log", "left"),
        ),
    );
    let right_checkpoint = fat_checkpoint_with_coverage_and_event_log(
        &right_config,
        &genesis,
        coverage,
        BTreeMap::from([(replica_a, base), (replica_b, dirty)]),
        EventLogOffset::with_appended_segment(
            ContentHash::from_canonical_material("crucible.test.event-log", "prefix"),
            8,
            1,
            ContentHash::from_canonical_material("crucible.test.event-log", "right"),
        ),
    );

    graph
        .cache_snapshot(&left_config, left_checkpoint)
        .unwrap_or_else(|error| panic!("left checkpoint should cache: {error}"));
    graph
        .cache_snapshot(&right_config, right_checkpoint)
        .unwrap_or_else(|error| panic!("right checkpoint should cache: {error}"));

    let left_key = graph
        .symmetry_reduction_key(&left_config, &symmetry_classes)
        .unwrap_or_else(|| panic!("left checkpoint should have a symmetry key"));
    let right_key = graph
        .symmetry_reduction_key(&right_config, &symmetry_classes)
        .unwrap_or_else(|| panic!("right checkpoint should have a symmetry key"));
    let report = graph
        .enumerate_frontier_reduced(
            &genesis,
            vec![left_decision, right_decision],
            FrontierReductionPolicy::none().with_symmetry_classes(symmetry_classes),
        )
        .unwrap_or_else(|error| panic!("reduced frontier should enumerate: {error}"));

    assert_ne!(left_key, right_key);
    assert_eq!(report.explored.len(), 2);
    assert!(report.covered.is_empty());
}

#[test]
fn gate_content_address_temporal_graph_partial_order_reduction_skips_noncanonical_interleaving() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "temporal-graph-partial-order-reduction",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}"));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&scenario, baked)
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    let left = preemption_decision("node-a", 21);
    let right = preemption_decision("node-b", 21);
    let (first, second) = if left.reduction_order_key() < right.reduction_order_key() {
        (right, left)
    } else {
        (left, right)
    };
    let frontier = step(&genesis, first.clone());
    let covered = step(&frontier, second.clone());
    let canonical_frontier = step(&genesis, second.clone());
    let representative = Configuration {
        def: scenario,
        schedule: Schedule::empty()
            .appended(second.clone())
            .appended(first.clone()),
    };
    let partial_order = PartialOrderReductionPolicy::new().with_independent_pair(&first, &second);

    assert!(first.is_independent_from(&second, &partial_order));
    graph
        .record_step(&genesis, second.clone())
        .unwrap_or_else(|error| panic!("canonical frontier should record: {error}"));
    graph
        .record_step(&canonical_frontier, first.clone())
        .unwrap_or_else(|error| panic!("canonical representative should record: {error}"));
    graph
        .record_step(&genesis, first)
        .unwrap_or_else(|error| panic!("frontier should record: {error}"));
    assert!(graph.contains_configuration(&representative));

    let report = graph
        .enumerate_frontier_reduced(
            &frontier,
            vec![second],
            FrontierReductionPolicy::none().with_partial_order(partial_order),
        )
        .unwrap_or_else(|error| panic!("reduced frontier should enumerate: {error}"));

    assert!(report.explored.is_empty());
    assert_eq!(report.covered.len(), 1);
    assert_eq!(
        report.covered[0].reason,
        FrontierReductionReason::PartialOrder
    );
    assert_eq!(report.covered[0].configuration.id(), covered.id());
    assert_eq!(report.covered[0].representative, representative.id());
    assert!(!graph.contains_configuration(&covered));
    assert!(graph.checkpoint_node(covered.id()).is_none());
}

#[test]
fn gate_content_address_temporal_graph_partial_order_reduction_records_missing_representative() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "temporal-graph-partial-order-missing-representative",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario);
    let baked = bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}"));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&genesis.def, baked)
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    let left = preemption_decision("node-a", 51);
    let right = preemption_decision("node-b", 51);
    let (first, second) = if left.reduction_order_key() < right.reduction_order_key() {
        (right, left)
    } else {
        (left, right)
    };
    let frontier = step(&genesis, first.clone());
    let covered = step(&frontier, second.clone());
    let representative = Configuration {
        def: genesis.def.clone(),
        schedule: Schedule::empty()
            .appended(second.clone())
            .appended(first.clone()),
    };
    let partial_order = PartialOrderReductionPolicy::new().with_independent_pair(&first, &second);

    graph
        .record_step(&genesis, first)
        .unwrap_or_else(|error| panic!("frontier should record: {error}"));
    assert!(!graph.contains_configuration(&representative));

    let report = graph
        .enumerate_frontier_reduced(
            &frontier,
            vec![second],
            FrontierReductionPolicy::none().with_partial_order(partial_order),
        )
        .unwrap_or_else(|error| panic!("reduced frontier should enumerate: {error}"));

    assert!(report.explored.is_empty());
    assert_eq!(report.covered.len(), 1);
    assert_eq!(
        report.covered[0].reason,
        FrontierReductionReason::PartialOrder
    );
    assert_eq!(report.covered[0].configuration.id(), covered.id());
    assert_eq!(report.covered[0].representative, representative.id());
    assert!(graph.contains_configuration(&representative));
    assert!(!graph.contains_configuration(&covered));
}

#[test]
fn gate_content_address_temporal_graph_partial_order_reduction_explores_when_dependent() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "temporal-graph-partial-order-dependent",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}"));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&scenario, baked)
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));
    let first = preemption_decision("node-a", 31);
    let frontier = step(&genesis, first.clone());
    let same_node = preemption_decision("node-a", 32);
    let unknown = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("global"),
        value: 9,
    });
    let same_stream_a = app_random_decision("node-a", "shared", 1);
    let same_stream_b = app_random_decision("node-b", "shared", 2);
    let different_stream_b = app_random_decision("node-b", "other", 2);
    let dependent_proofs = PartialOrderReductionPolicy::new()
        .with_independent_pair(&first, &same_node)
        .with_independent_pair(&first, &unknown);
    let same_stream_proof =
        PartialOrderReductionPolicy::new().with_independent_pair(&same_stream_a, &same_stream_b);
    let different_stream_proof = PartialOrderReductionPolicy::new()
        .with_independent_pair(&same_stream_a, &different_stream_b);

    assert!(!same_node.is_independent_from(&first, &dependent_proofs));
    assert!(!unknown.is_independent_from(&first, &dependent_proofs));
    assert!(!same_stream_a.is_independent_from(&same_stream_b, &same_stream_proof));
    assert!(same_stream_a.is_independent_from(&different_stream_b, &different_stream_proof));
    graph
        .record_step(&genesis, first)
        .unwrap_or_else(|error| panic!("frontier should record: {error}"));

    let report = graph
        .enumerate_frontier_reduced(
            &frontier,
            vec![same_node.clone(), unknown.clone()],
            FrontierReductionPolicy::none().with_partial_order(dependent_proofs),
        )
        .unwrap_or_else(|error| panic!("reduced frontier should enumerate: {error}"));

    assert_eq!(report.explored.len(), 2);
    assert!(report.covered.is_empty());
    assert!(graph.contains_configuration(&step(&frontier, same_node)));
    assert!(graph.contains_configuration(&step(&frontier, unknown)));
}

#[test]
fn gate_content_address_temporal_graph_user_operations_share_single_dag() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.content-address.world",
        "temporal-graph-user-operations",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let store = MemoryDagStore::new();
    let saved = step(&genesis, generated_decision(810, 0));
    let fork_decision = generated_decision(811, 0);
    let forked = step(&genesis, fork_decision.clone());
    let search_extra = generated_decision(814, 0);
    let search_only = generated_decision(812, 0);
    let mut baked =
        bake(&world).unwrap_or_else(|error| panic!("bake should produce genesis: {error}"));
    baked.checkpoint = checkpoint_with_search_frontier_choices(
        baked.checkpoint,
        vec![search_extra, search_only.clone()],
    );
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&scenario, baked)
        .unwrap_or_else(|error| panic!("baked genesis should seed temporal graph: {error}"));

    let save = graph
        .save(&store, &saved)
        .unwrap_or_else(|error| panic!("save operation should persist graph closure: {error}"));
    assert_eq!(save.configuration, saved.id());
    assert_eq!(save.checkpoint, saved.id());
    assert_eq!(save.checkpoint_kind, CheckpointKind::Fat);
    assert!(save.store_keys.checkpoint_nodes.contains_key(&saved.id()));
    assert!(save.store_keys.cached_snapshots.contains_key(&saved.id()));
    for key in save.store_keys.store_keys() {
        assert!(
            store
                .exists(&key)
                .unwrap_or_else(|error| panic!("store key should be queryable: {error}")),
            "saved store key should exist: {}",
            key.to_hex()
        );
    }

    let resumed = graph
        .resume(&saved)
        .unwrap_or_else(|error| panic!("resume operation should instantiate saved tip: {error}"));
    assert_eq!(resumed.configuration, saved.id());
    assert_eq!(resumed.checkpoint, saved.id());
    assert_eq!(resumed.runtime.configuration, saved.id());

    let fork = graph
        .fork(&genesis, vec![fork_decision])
        .unwrap_or_else(|error| panic!("fork operation should record branch: {error}"));
    assert_eq!(fork.base.configuration, genesis.id());
    assert_eq!(fork.base.runtime.configuration, genesis.id());
    assert_eq!(fork.branch.id(), forked.id());
    assert_eq!(fork.branch_checkpoint.id, forked.id());
    assert_eq!(fork.branch_checkpoint.kind, CheckpointKind::Thin);

    let replay = graph.replay(&saved).unwrap_or_else(|error| {
        panic!("replay operation should validate saved checkpoint: {error}")
    });
    assert_eq!(replay.configuration, saved.id());
    assert_eq!(replay.fat_checkpoint, saved.id());
    assert_eq!(replay.thin_checkpoint, saved.id());

    let search = graph
        .search(
            &genesis,
            FrontierReductionPolicy::none(),
            MaterializationPolicy::thin_only(),
            MaterializationTrigger::Cold,
        )
        .unwrap_or_else(|error| panic!("search operation should expand frontier: {error}"));
    assert_eq!(search.frontier, genesis.id());
    assert_eq!(search.frontier_report.explored.len(), 2);
    assert!(search.frontier_report.covered.is_empty());
    assert_eq!(search.materialized.len(), 2);
    let explored_ids = search
        .frontier_report
        .explored
        .iter()
        .map(|child| child.configuration.id())
        .collect::<BTreeSet<_>>();
    let materialized_ids = search
        .materialized
        .iter()
        .map(|checkpoint| checkpoint.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(materialized_ids, explored_ids);
    for checkpoint_id in explored_ids {
        assert!(graph.checkpoint_node(checkpoint_id).is_some());
    }
    assert!(graph.contains_configuration(&saved));
    assert!(graph.contains_configuration(&forked));
    assert_eq!(
        graph.checkpoint_node(saved.id()).map(|node| node.id),
        Some(saved.id())
    );
    assert_eq!(
        graph.checkpoint_node(forked.id()).map(|node| node.id),
        Some(forked.id())
    );
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
        EngineError::MissingBakedGenesis { scenario: missing } if missing == scenario.id()
    ));
    assert_eq!(graph.checkpoint_node_count(), 0);
    assert_eq!(graph.recorded_configuration_count(), 0);

    let error = graph
        .enumerate_frontier(&genesis, vec![generated_decision(250, 1)])
        .unwrap_err();

    assert!(matches!(
        error,
        EngineError::MissingBakedGenesis { scenario: missing } if missing == scenario.id()
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

fn unique_temp_dir(label: &str) -> PathBuf {
    let index = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("crucible-{label}-{}-{index}", std::process::id()));
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("temporary DAG store root should be clearable: {error}"),
    }
    root
}

fn checkpoint_with_search_frontier_choices(
    mut checkpoint: Checkpoint,
    decisions: Vec<Decision>,
) -> Checkpoint {
    let state = checkpoint
        .state
        .as_ref()
        .expect("test checkpoint must be materialized");
    let mut scheduler = state.scheduler.clone();
    scheduler.search_frontier = SearchFrontierChoices::from_decisions(decisions);
    checkpoint.state = Some(MaterializedState::from_components_with_event_log_segments(
        state.vm_snapshots.clone(),
        state.device_overlays.clone(),
        scheduler,
        state.decision_rng.clone(),
        state.event_log,
        state.event_log_segments.clone(),
    ));
    checkpoint
}

fn scenario(material: &str) -> ScenarioDef {
    ScenarioDef::from_canonical_material("crucible.test.content-address.scenario", material)
}

fn event_key(virtual_time: u64, sequence: u64) -> EventKey {
    EventKey::new(
        VirtualTime {
            ticks: virtual_time,
        },
        scheduler_node("consumer"),
        scheduler_node("producer"),
        sequence,
    )
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

fn fixed_schedule() -> Schedule {
    Schedule::empty()
        .appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: vec![event_key(1, 2), event_key(1, 3)],
        }))
        .appended(Decision::EffectOutcome(EffectOutcomeDecision {
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
            stream: RngStreamId::for_node("guest/request"),
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
            order: vec![event_key(seed + index, index)],
        }),
        1 => Decision::EffectOutcome(EffectOutcomeDecision {
            at: VirtualTime {
                ticks: seed + index,
            },
            fault: FaultId {
                name: format!("fault-{seed}-{index}"),
            },
            fired: index.is_multiple_of(2),
        }),
        _ => Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name(format!("stream-{seed}")),
            value: seed ^ index,
        }),
    }
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn symmetry_class(name: &str) -> SymmetryClassId {
    SymmetryClassId {
        name: String::from(name),
    }
}

fn node_blob(material: &str) -> NodeBlobRef {
    NodeBlobRef::baked(ContentHash::from_canonical_material(
        "crucible.test.content-address.node-blob",
        material,
    ))
}

fn preemption_decision(node: &str, retired: u64) -> Decision {
    Decision::Preemption(PreemptionDecision {
        node: node_id(node),
        at: Icount { retired },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    })
}

fn app_random_decision(node: &str, stream: &str, value: u64) -> Decision {
    Decision::AppRandom(AppRandomDecision {
        node: node_id(node),
        stream: RngStreamId::for_node(stream),
        request_id: value,
        width: 64,
        value,
    })
}

fn fat_checkpoint_with_coverage(
    configuration: &Configuration,
    parent: &Configuration,
    coverage: ContentHash,
    node_blobs: BTreeMap<NodeId, NodeBlobRef>,
) -> Checkpoint {
    fat_checkpoint_with_coverage_and_event_log(
        configuration,
        parent,
        coverage,
        node_blobs,
        EventLogOffset::default(),
    )
}

fn fat_checkpoint_with_coverage_and_event_log(
    configuration: &Configuration,
    parent: &Configuration,
    coverage: ContentHash,
    node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    event_log: EventLogOffset,
) -> Checkpoint {
    let node_icounts = node_blobs
        .keys()
        .cloned()
        .map(|node| (node, Icount { retired: 99 }))
        .collect::<BTreeMap<_, _>>();
    let state = MaterializedState::from_components(
        materialized_snapshots_for_blobs(&node_blobs, &node_icounts),
        BTreeMap::new(),
        SchedulerState::empty(),
        DecisionRngState::empty(),
        event_log,
    );
    Checkpoint::from_recorded_configuration(
        configuration,
        Some(parent),
        VirtualTime::default(),
        node_icounts,
        CheckpointKind::Fat,
        node_blobs,
    )
    .unwrap_or_else(|error| panic!("fat checkpoint should be constructible: {error}"))
    .with_materialized_state(Some(state))
    .with_coverage_fingerprint(coverage)
}

fn materialized_snapshots_for_blobs(
    node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
    node_icounts: &BTreeMap<NodeId, Icount>,
) -> BTreeMap<NodeId, VmSnapshotRef> {
    node_blobs
        .iter()
        .map(|(node, blob)| {
            (
                node.clone(),
                VmSnapshotRef::new(
                    blob.clone(),
                    node_icounts.get(node).copied().unwrap_or_default(),
                ),
            )
        })
        .collect()
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
        ("scenario", hash_hex(scenario.id())),
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
