//! Implements the phase6 savevm-completeness hedge gate.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::error::Error;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, DagStore, Decision, DecisionRngState,
    DeviceId, DeviceOverlayDelta, DeviceRngState, EventLogOffset, Icount, MaterializationPolicy,
    MaterializationTrigger, MaterializedState, MemoryDagStore, NodeId, NodeTemplate, ReadyPoint,
    RngDecision, RngStreamId, SavevmCompletenessHedge, SchedulerState, TemporalGraph, VirtualTime,
    World, WorldNode, bake, instantiate, step,
};

#[test]
fn gate_savevm_completeness_keeps_unreliable_snapshots_thin() -> Result<(), Box<dyn Error>> {
    let world = savevm_world();
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let target = savevm_target(&genesis);
    let device = savevm_device();
    let snapshot = fat_checkpoint_with_device_overlay(&target, device.clone())?;
    let baked = bake(&world)?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked.clone())?;
    let mut direct_graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let unreliable = SavevmCompletenessHedge::with_unreliable_devices([device.clone()]);

    let directly_hedged = direct_graph.materialize_checkpoint_with_savevm_hedge(
        &target,
        &SavevmCompletenessHedge::with_unreliable_devices([device.clone()]),
    )?;
    let direct_replay_runtime = instantiate(&direct_graph, &target)?;

    assert_eq!(directly_hedged.kind, CheckpointKind::Thin);
    assert!(directly_hedged.state.is_none());
    assert!(direct_graph.cached_snapshot(&target).is_none());
    assert_eq!(direct_replay_runtime.configuration, target.id());

    let cached = graph.cache_snapshot_with_savevm_hedge(
        &target,
        snapshot.clone(),
        &SavevmCompletenessHedge::verified(),
    )?;
    assert_eq!(cached.kind, CheckpointKind::Fat);
    assert_eq!(graph.cached_snapshot(&target), Some(&cached));

    let thin = graph.cache_snapshot_with_savevm_hedge(&target, snapshot, &unreliable)?;
    let replay_runtime = instantiate(&graph, &target)?;

    assert!(unreliable.unreliable_devices().contains(&device));
    assert!(!unreliable.fat_snapshot_default());
    assert_eq!(thin.kind, CheckpointKind::Thin);
    assert!(thin.state.is_none());
    assert!(graph.cached_snapshot(&target).is_none());
    assert_eq!(
        graph
            .checkpoint_node(target.id())
            .map(|checkpoint| checkpoint.kind),
        Some(CheckpointKind::Thin)
    );
    assert_eq!(replay_runtime.configuration, target.id());

    Ok(())
}

#[test]
fn gate_savevm_completeness_global_fallback_evicts_to_thin_replay() -> Result<(), Box<dyn Error>> {
    let world = savevm_world();
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let target = savevm_target(&genesis);
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;

    let fat = graph.materialize_checkpoint(&target)?;
    let exact_runtime = instantiate(&graph, &target)?;
    let thin = graph.materialize_hot_checkpoint_with_savevm_hedge(
        &target,
        MaterializationPolicy::with_budget(8),
        MaterializationTrigger::InteractiveTarget,
        &SavevmCompletenessHedge::thin_replay_until_full_s3(),
    )?;
    let replay_runtime = instantiate(&graph, &target)?;

    assert_eq!(fat.kind, CheckpointKind::Fat);
    assert_eq!(thin.id, fat.id);
    assert_eq!(thin.kind, CheckpointKind::Thin);
    assert!(thin.state.is_none());
    assert!(graph.cached_snapshot(&target).is_none());
    assert_eq!(exact_runtime, replay_runtime);

    Ok(())
}

#[test]
fn gate_savevm_completeness_save_persists_fat_checkpoint_keyed_by_configuration()
-> Result<(), Box<dyn Error>> {
    let world = savevm_world();
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let target = savevm_target(&genesis);
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let store = MemoryDagStore::new();

    let save = graph.save(&store, &target)?;
    let cached = graph
        .cached_snapshot(&target)
        .ok_or("save should retain a fat snapshot cache entry")?;
    let thin = graph
        .checkpoint_node(target.id())
        .ok_or("save should retain the thin source-of-truth checkpoint")?;

    assert_eq!(save.configuration, target.id());
    assert_eq!(save.checkpoint, target.id());
    assert_eq!(save.checkpoint_kind, CheckpointKind::Fat);
    assert_eq!(cached.id, target.id());
    assert_eq!(cached.kind, CheckpointKind::Fat);
    assert_eq!(thin.id, target.id());
    assert_eq!(thin.kind, CheckpointKind::Thin);
    assert!(thin.state.is_none());
    assert!(save.store_keys.checkpoint_nodes.contains_key(&target.id()));
    assert!(save.store_keys.cached_snapshots.contains_key(&target.id()));
    for key in save.store_keys.store_keys() {
        assert!(
            store.exists(&key)?,
            "save should persist every content-addressed closure object"
        );
    }

    Ok(())
}

fn savevm_world() -> World {
    World::from_nodes(vec![WorldNode {
        id: savevm_node(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 700 },
        },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("single savevm node should be a valid world")
}

fn savevm_node() -> NodeId {
    NodeId {
        name: String::from("savevm-a"),
    }
}

fn savevm_device() -> DeviceId {
    DeviceId {
        name: String::from("block0"),
    }
}

fn savevm_target(genesis: &Configuration) -> Configuration {
    step(
        &step(genesis, rng_decision("savevm/seed-a", 41)),
        rng_decision("savevm/seed-b", 42),
    )
}

fn rng_decision(stream: &str, value: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name(stream),
        value,
    })
}

fn fat_checkpoint_with_device_overlay(
    configuration: &Configuration,
    device: DeviceId,
) -> Result<Checkpoint, crucible::EngineError> {
    let parent = parent_configuration(configuration)?;
    let mut checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )?;
    checkpoint.state = Some(MaterializedState::from_components(
        BTreeMap::new(),
        BTreeMap::from([(device.clone(), device_overlay(&device.name))]),
        SchedulerState::empty(),
        DecisionRngState::empty(),
        EventLogOffset::default(),
    ));
    Ok(checkpoint)
}

fn parent_configuration(
    configuration: &Configuration,
) -> Result<Option<Configuration>, crucible::EngineError> {
    if configuration.is_genesis() {
        return Ok(None);
    }
    let schedule = configuration
        .schedule
        .prefix(configuration.schedule.len().saturating_sub(1))
        .map_err(crucible::EngineError::SchedulePrefix)?;
    Ok(Some(Configuration {
        def: configuration.def.clone(),
        schedule,
    }))
}

fn device_overlay(label: &str) -> DeviceOverlayDelta {
    let parent =
        ContentHash::from_canonical_material("crucible.test.savevm.device-overlay.parent", label);
    let delta =
        ContentHash::from_canonical_material("crucible.test.savevm.device-overlay.delta", label);
    let resolved =
        ContentHash::from_canonical_material("crucible.test.savevm.device-overlay.resolved", label);
    DeviceOverlayDelta::new(parent, delta, resolved, DeviceRngState::empty())
}
