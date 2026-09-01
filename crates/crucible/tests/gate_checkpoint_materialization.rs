//! Gates exact fat-checkpoint persistence and advisory thin caching.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- integration-test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;

use crucible::{
    CheckpointKind, Configuration, DagStore, Decision, Icount, MemoryDagStore, NodeId,
    NodeTemplate, ReadyPoint, RngDecision, RngStreamId, TemporalGraph, World, WorldNode, bake,
    step,
};

#[test]
fn gate_checkpoint_materialization_persists_exact_fat_checkpoint_by_configuration()
-> Result<(), Box<dyn Error>> {
    let world = checkpoint_world();
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let target = step(
        &step(&genesis, rng_decision("checkpoint/seed-a", 41)),
        rng_decision("checkpoint/seed-b", 42),
    );
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let store = MemoryDagStore::new();

    let save = graph.save(&store, &target)?;
    let cached = graph
        .cached_snapshot(&target)
        .ok_or("save should retain an exact fat snapshot cache entry")?;
    let thin = graph
        .checkpoint_node(target.id())
        .ok_or("save should retain the thin reconstruction checkpoint")?;

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
        assert!(store.exists(&key)?);
    }
    Ok(())
}

fn checkpoint_world() -> World {
    World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: String::from("checkpoint-a"),
        },
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
    .expect("single checkpoint node should be a valid world")
}

fn rng_decision(stream: &str, value: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name(stream),
        value,
    })
}
