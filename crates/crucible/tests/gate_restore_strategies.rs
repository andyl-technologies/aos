//! Implements the phase6 restore-strategies gate over temporal-graph checkpoints.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::error::Error;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, Decision, EngineError, Icount,
    NodeBlobRef, NodeId, NodeTemplate, ReadyPoint, RngDecision, RngStreamId, TemporalGraph,
    VirtualTime, World, WorldNode, bake, instantiate, step,
};
use crucible_harness::divergence::{
    DecisionTraceEntry, DivergenceMemoryRegion, DivergenceRegister, DivergenceSide,
    DivergenceStateDump,
};
use crucible_harness::fingerprint::{
    FingerprintSample, FingerprintSampleTrigger, FingerprintStream,
};
use crucible_harness::replay_oracle::{
    ReplayOracleCheckpointKind, ReplayOracleDivergenceInputs, ReplayOracleMaterializedCase,
    ReplayOracleSamplingConfig, ReplayOracleSearchBisectionError,
    ReplayOracleSearchDivergenceMaterialization, ReplayOracleSearchMaterialization,
    check_sampled_search_replay_oracle_with_bisection,
};

const RESTORE_DIVERGENCE_ICOUNT: u64 = 17;

#[test]
fn gate_restore_strategies_converge_on_thin_source_of_truth() -> Result<(), Box<dyn Error>> {
    let world = restore_world();
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake(&world)?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let target = restore_target(&genesis);

    let thin_checkpoint = graph.record_thin_checkpoint(&target)?;
    let replay_from_seed = graph.resume(&target)?;

    assert_eq!(thin_checkpoint.kind, CheckpointKind::Thin);
    assert!(graph.cached_snapshot(&target).is_none());
    assert_eq!(replay_from_seed.configuration, target.id());
    assert_eq!(replay_from_seed.runtime.configuration, target.id());

    let snapshot = graph.materialize_checkpoint(&target)?;
    let replay_check = graph.replay(&target)?;
    let snapshot_restore = instantiate(&graph, &target)?;

    assert_eq!(snapshot.kind, CheckpointKind::Fat);
    assert_eq!(
        graph
            .checkpoint_node(target.id())
            .map(|checkpoint| checkpoint.kind),
        Some(CheckpointKind::Thin),
        "the fat snapshot cache must not replace the thin source-of-truth DAG node"
    );
    assert_eq!(replay_check.configuration, target.id());
    assert_eq!(replay_check.fat_checkpoint, snapshot.id);
    assert_eq!(replay_check.thin_checkpoint, snapshot.id);
    assert_eq!(
        snapshot_restore.configuration,
        replay_from_seed.runtime.configuration
    );
    assert_eq!(snapshot_restore.id, replay_from_seed.runtime.id);
    assert_eq!(
        snapshot_restore.node_blobs,
        replay_from_seed.runtime.node_blobs
    );
    assert_eq!(
        snapshot_restore.scheduler,
        replay_from_seed.runtime.scheduler
    );
    assert_eq!(
        snapshot_restore.event_log,
        replay_from_seed.runtime.event_log
    );

    Ok(())
}

#[test]
fn gate_restore_strategies_reject_corrupt_snapshot_restore_and_evict_cache()
-> Result<(), Box<dyn Error>> {
    let world = restore_world();
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let parent = step(
        &step(&genesis, rng_decision("restore/corrupt-a", 31)),
        rng_decision("restore/corrupt-b", 32),
    );
    let target = step(&parent, rng_decision("restore/corrupt-c", 33));
    let baked = bake(&world)?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let corrupt = corrupt_loadable_checkpoint(&restore_node(), &parent, &target)?;

    graph.cache_snapshot(&target, corrupt.clone())?;
    assert!(graph.cached_snapshot(&target).is_some());

    let restore_error = match instantiate(&graph, &target) {
        Ok(_) => panic!("snapshot restore should validate before loading corrupt cache"),
        Err(error) => error,
    };
    let EngineError::ReplayOracleMismatch {
        checkpoint: restore_checkpoint,
        expected: restore_expected,
        actual: restore_actual,
    } = restore_error
    else {
        panic!("snapshot restore should surface replay-oracle divergence");
    };

    assert_eq!(restore_checkpoint, corrupt.id);
    assert_ne!(restore_expected, restore_actual);
    assert!(
        graph.cached_snapshot(&target).is_some(),
        "immutable snapshot restore validation reports divergence without mutating the cache"
    );
    assert_restore_mismatch_localizes(restore_checkpoint, restore_expected, restore_actual)?;

    let error = match graph.replay_oracle_admit_cached_snapshot(&target) {
        Ok(_) => panic!("corrupt snapshot restore should fail the replay oracle"),
        Err(error) => error,
    };
    let EngineError::ReplayOracleMismatch {
        checkpoint,
        expected,
        actual,
    } = error
    else {
        panic!("corrupt snapshot restore should surface replay-oracle divergence");
    };

    assert_eq!(checkpoint, corrupt.id);
    assert_ne!(
        expected, actual,
        "fat and thin materialized-state identities must expose the divergence"
    );
    assert!(
        graph.cached_snapshot(&target).is_none(),
        "corrupt cached snapshot should be evicted back to thin replay"
    );
    assert_eq!(
        graph
            .checkpoint_node(target.id())
            .map(|checkpoint| checkpoint.kind),
        Some(CheckpointKind::Thin)
    );

    Ok(())
}

fn restore_world() -> World {
    World::from_nodes(vec![WorldNode {
        id: restore_node(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 512 },
        },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("single restore node should be a valid world")
}

fn restore_node() -> NodeId {
    NodeId {
        name: String::from("restore-a"),
    }
}

fn restore_target(genesis: &Configuration) -> Configuration {
    step(
        &step(
            &step(genesis, rng_decision("restore/seed-a", 11)),
            rng_decision("restore/seed-b", 12),
        ),
        rng_decision("restore/seed-c", 13),
    )
}

fn assert_restore_mismatch_localizes(
    checkpoint: ContentHash,
    expected: ContentHash,
    actual: ContentHash,
) -> Result<(), Box<dyn Error>> {
    let checkpoint_id = checkpoint.to_hex();
    let case = ReplayOracleMaterializedCase {
        checkpoint_id: checkpoint_id.clone(),
        kind: ReplayOracleCheckpointKind::Fat,
        fat_checkpoint_hash: checkpoint.bytes.to_vec(),
        thin_checkpoint_hash: checkpoint.bytes.to_vec(),
        fat_configuration_hash: b"restore-target".to_vec(),
        thin_configuration_hash: b"restore-target".to_vec(),
        fat_ancestor_hash: b"restore-parent".to_vec(),
        thin_ancestor_hash: b"restore-parent".to_vec(),
        fat_schedule_delta_hash: b"restore-delta".to_vec(),
        thin_schedule_delta_hash: b"restore-delta".to_vec(),
        fat_hash: actual.bytes.to_vec(),
        thin_hash: expected.bytes.to_vec(),
    };
    let (fat_stream, thin_stream) = restore_divergence_streams();
    let fat_decisions = restore_fat_decisions();
    let thin_decisions = restore_thin_decisions();
    let materializations = [ReplayOracleSearchDivergenceMaterialization::new(
        ReplayOracleSearchMaterialization::new(0, case),
        ReplayOracleDivergenceInputs {
            fat_stream: &fat_stream,
            thin_stream: &thin_stream,
            fat_decisions: &fat_decisions,
            thin_decisions: &thin_decisions,
        },
    )];
    let config = ReplayOracleSamplingConfig::new(1, 1, "restore-strategy-localization")?;
    let error = match check_sampled_search_replay_oracle_with_bisection(
        &materializations,
        &config,
        |_, icount| icount < RESTORE_DIVERGENCE_ICOUNT,
        |_, side, icount| restore_state_dump(side, icount),
    ) {
        Ok(_) => panic!("restore mismatch should require divergence localization"),
        Err(error) => error,
    };
    let ReplayOracleSearchBisectionError::Mismatch { localized } = error else {
        panic!("restore mismatch should localize instead of returning an unlocalized error");
    };

    assert_eq!(localized.mismatch.checkpoint_id, checkpoint_id);
    assert_eq!(localized.bisection.sequence, 0);
    assert_eq!(localized.bisection.checkpoint_id, checkpoint_id);
    assert_eq!(
        localized.divergence.first_different_icount,
        RESTORE_DIVERGENCE_ICOUNT
    );
    let Some(decision) = localized.divergence.first_different_decision else {
        panic!("restore mismatch must localize the first differing decision");
    };
    assert_eq!(decision.index, 2);

    Ok(())
}

fn restore_divergence_streams() -> (FingerprintStream, FingerprintStream) {
    (
        FingerprintStream {
            definition_digest: vec![0x55],
            samples: vec![
                restore_sample(0, 10, b"restore-same-at-10"),
                restore_sample(1, 20, b"restore-fat-at-20"),
                restore_sample(2, 30, b"restore-fat-at-30"),
            ],
            final_fingerprint: b"restore-fat-final".to_vec(),
        },
        FingerprintStream {
            definition_digest: vec![0x55],
            samples: vec![
                restore_sample(0, 10, b"restore-same-at-10"),
                restore_sample(1, 20, b"restore-thin-at-20"),
                restore_sample(2, 30, b"restore-thin-at-30"),
            ],
            final_fingerprint: b"restore-thin-final".to_vec(),
        },
    )
}

fn restore_fat_decisions() -> Vec<DecisionTraceEntry> {
    vec![
        restore_decision(0, 4, "rng restore/order value=31", b"rng:31"),
        restore_decision(1, 10, "deliver restore frame seq=1", b"deliver:1"),
        restore_decision(
            2,
            RESTORE_DIVERGENCE_ICOUNT,
            "snapshot payload accepted wrong device state",
            b"restore:snapshot-wrong",
        ),
    ]
}

fn restore_thin_decisions() -> Vec<DecisionTraceEntry> {
    vec![
        restore_decision(0, 4, "rng restore/order value=31", b"rng:31"),
        restore_decision(1, 10, "deliver restore frame seq=1", b"deliver:1"),
        restore_decision(
            2,
            RESTORE_DIVERGENCE_ICOUNT,
            "thin replay reconstructs device state",
            b"restore:thin-correct",
        ),
    ]
}

fn restore_decision(
    index: usize,
    icount: u64,
    summary: &str,
    canonical_bytes: &[u8],
) -> DecisionTraceEntry {
    DecisionTraceEntry {
        index,
        node: Some(String::from("restore-a")),
        icount: Some(icount),
        summary: summary.to_owned(),
        canonical_bytes: canonical_bytes.to_vec(),
    }
}

fn restore_state_dump(side: DivergenceSide, icount: u64) -> DivergenceStateDump {
    let diverged = icount >= RESTORE_DIVERGENCE_ICOUNT && side == DivergenceSide::Right;
    let pc = if diverged {
        RESTORE_DIVERGENCE_ICOUNT + 1
    } else {
        icount
    };
    let page_byte = if diverged { 0x7e } else { 0x44 };
    let event_suffix = if diverged {
        "thin replay reconstructs device state"
    } else {
        "snapshot payload accepted wrong device state"
    };

    DivergenceStateDump {
        icount,
        registers: vec![
            DivergenceRegister {
                name: String::from("pc"),
                bytes: pc.to_le_bytes().to_vec(),
            },
            DivergenceRegister {
                name: String::from("r0"),
                bytes: 31_u64.to_le_bytes().to_vec(),
            },
        ],
        memory_regions: vec![DivergenceMemoryRegion {
            name: String::from("restore-page"),
            start: 0x2000,
            bytes: vec![page_byte, 0x55, 0x66, 0x77],
        }],
        last_canonical_events: vec![
            String::from("rng restore/order value=31"),
            String::from("deliver restore frame seq=1"),
            String::from(event_suffix),
        ],
    }
}

fn restore_sample(seq: u64, icount: u64, rolling_fingerprint: &[u8]) -> FingerprintSample {
    FingerprintSample {
        seq,
        node: String::from("restore-a"),
        icount,
        trigger: FingerprintSampleTrigger::Periodic,
        rolling_fingerprint: rolling_fingerprint.to_vec(),
    }
}

fn rng_decision(stream: &str, value: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name(stream),
        value,
    })
}

fn corrupt_loadable_checkpoint(
    node: &NodeId,
    parent: &Configuration,
    target: &Configuration,
) -> Result<Checkpoint, EngineError> {
    Checkpoint::from_recorded_configuration(
        target,
        Some(parent),
        VirtualTime::default(),
        BTreeMap::from([(node.clone(), Icount { retired: 9_999 })]),
        CheckpointKind::Fat,
        BTreeMap::from([(
            node.clone(),
            NodeBlobRef::baked(ContentHash::from_canonical_material(
                "crucible.test.restore-strategies.corrupt-snapshot",
                "wrong-loadvm-payload",
            )),
        )]),
    )
}
