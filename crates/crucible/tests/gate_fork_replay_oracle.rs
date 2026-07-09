//! Implements the phase6 fork replay-oracle gate over temporal-graph forks.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::error::Error;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, Decision, EngineError, Icount,
    NodeBlobRef, NodeId, NodeTemplate, ReadyPoint, RngDecision, RngStreamId, TemporalGraph,
    VirtualTime, WhiteBoxPolicy, World, WorldNode, bake, instantiate, step,
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

const FORK_DIVERGENCE_ICOUNT: u64 = 23;

#[test]
fn gate_fork_replay_oracle_validates_base_and_materialized_branch() -> Result<(), Box<dyn Error>> {
    let world = fork_world();
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake(&world)?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let base = step(&genesis, rng_decision("fork/base", 41));
    let base_checkpoint = graph.materialize_checkpoint(&base)?;
    let fork_decision = rng_decision("fork/branch", 42);
    let expected_branch = step(&base, fork_decision.clone());

    let fork = graph.fork(&base, [fork_decision])?;

    assert_eq!(base_checkpoint.kind, CheckpointKind::Fat);
    assert_eq!(fork.base.configuration, base.id());
    assert_eq!(fork.base.runtime, instantiate(&graph, &base)?);
    assert_eq!(fork.branch, expected_branch);
    assert_eq!(fork.branch_checkpoint.kind, CheckpointKind::Thin);
    assert_eq!(fork.branch_checkpoint.parent, Some(base.id()));
    assert_eq!(fork.branch_checkpoint.state, None);
    assert!(graph.cached_snapshot(&fork.branch).is_none());

    let branch_checkpoint = graph.materialize_checkpoint(&fork.branch)?;
    let replay_check = graph.replay(&fork.branch)?;
    let branch_restore = instantiate(&graph, &fork.branch)?;
    let branch_replay = graph.resume(&fork.branch)?;

    assert_eq!(branch_checkpoint.kind, CheckpointKind::Fat);
    assert_eq!(
        graph
            .checkpoint_node(fork.branch.id())
            .map(|checkpoint| checkpoint.kind),
        Some(CheckpointKind::Thin),
        "fork materialization must keep the thin branch as the source-of-truth DAG node"
    );
    assert_eq!(replay_check.configuration, fork.branch.id());
    assert_eq!(replay_check.fat_checkpoint, branch_checkpoint.id);
    assert_eq!(replay_check.thin_checkpoint, branch_checkpoint.id);
    assert_eq!(branch_restore, branch_replay.runtime);

    Ok(())
}

#[test]
fn gate_fork_replay_oracle_rejects_corrupt_base_before_branching() -> Result<(), Box<dyn Error>> {
    let world = fork_world();
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let base = step(&genesis, rng_decision("fork/corrupt-base", 51));
    let fork_decision = rng_decision("fork/corrupt-base-branch", 52);
    let branch = step(&base, fork_decision.clone());
    let baked = bake(&world)?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let corrupt_base = corrupt_loadable_checkpoint(&fork_node(), &genesis, &base)?;

    graph.cache_snapshot(&base, corrupt_base.clone())?;

    let fork_error = match graph.fork(&base, [fork_decision]) {
        Ok(_) => panic!("fork should validate a cached base before recording a branch"),
        Err(error) => error,
    };
    let EngineError::ReplayOracleMismatch {
        checkpoint,
        expected,
        actual,
    } = fork_error
    else {
        panic!("fork should surface the base replay-oracle mismatch");
    };

    assert_eq!(checkpoint, corrupt_base.id);
    assert_ne!(expected, actual);
    assert!(
        graph.checkpoint_node(branch.id()).is_none(),
        "a base replay-oracle failure must not record the fork branch"
    );
    assert!(
        graph.cached_snapshot(&base).is_some(),
        "immutable fork validation reports the corrupt base without mutating the cache"
    );

    Ok(())
}

#[test]
fn gate_fork_replay_oracle_rejects_corrupt_branch_cache_and_localizes() -> Result<(), Box<dyn Error>>
{
    let world = fork_world();
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let base = step(&genesis, rng_decision("fork/corrupt-branch-base", 61));
    let baked = bake(&world)?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let fork = graph.fork(&base, [rng_decision("fork/corrupt-branch", 62)])?;
    let corrupt_branch = corrupt_loadable_checkpoint(&fork_node(), &base, &fork.branch)?;

    graph.cache_snapshot(&fork.branch, corrupt_branch.clone())?;

    let restore_error = match instantiate(&graph, &fork.branch) {
        Ok(_) => panic!("fork branch restore should validate before loading corrupt cache"),
        Err(error) => error,
    };
    let EngineError::ReplayOracleMismatch {
        checkpoint: restore_checkpoint,
        expected: restore_expected,
        actual: restore_actual,
    } = restore_error
    else {
        panic!("fork branch restore should surface replay-oracle divergence");
    };
    assert_eq!(restore_checkpoint, corrupt_branch.id);
    assert_ne!(restore_expected, restore_actual);
    assert_fork_mismatch_localizes(restore_checkpoint, restore_expected, restore_actual)?;

    let eviction_error = match graph.replay_oracle_admit_cached_snapshot(&fork.branch) {
        Ok(_) => panic!("corrupt fork branch cache should fail the replay oracle"),
        Err(error) => error,
    };
    let EngineError::ReplayOracleMismatch {
        checkpoint,
        expected,
        actual,
    } = eviction_error
    else {
        panic!("corrupt fork branch cache should surface replay-oracle divergence");
    };

    assert_eq!(checkpoint, corrupt_branch.id);
    assert_ne!(expected, actual);
    assert!(
        graph.cached_snapshot(&fork.branch).is_none(),
        "corrupt fork branch cache should be evicted back to thin replay"
    );
    assert_eq!(
        graph
            .checkpoint_node(fork.branch.id())
            .map(|checkpoint| checkpoint.kind),
        Some(CheckpointKind::Thin)
    );
    let thin_after_eviction = instantiate(&graph, &fork.branch)?;
    assert_eq!(
        thin_after_eviction.configuration,
        fork.branch.id(),
        "thin replay after cache eviction should realize the fork branch"
    );

    Ok(())
}

fn fork_world() -> World {
    World::from_nodes(vec![WorldNode {
        id: fork_node(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 700 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("single fork node should be a valid world")
}

fn fork_node() -> NodeId {
    NodeId {
        name: String::from("fork-a"),
    }
}

fn assert_fork_mismatch_localizes(
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
        fat_configuration_hash: b"fork-branch".to_vec(),
        thin_configuration_hash: b"fork-branch".to_vec(),
        fat_ancestor_hash: b"fork-base".to_vec(),
        thin_ancestor_hash: b"fork-base".to_vec(),
        fat_schedule_delta_hash: b"fork-delta".to_vec(),
        thin_schedule_delta_hash: b"fork-delta".to_vec(),
        fat_hash: actual.bytes.to_vec(),
        thin_hash: expected.bytes.to_vec(),
    };
    let (fat_stream, thin_stream) = fork_divergence_streams();
    let fat_decisions = fork_fat_decisions();
    let thin_decisions = fork_thin_decisions();
    let materializations = [ReplayOracleSearchDivergenceMaterialization::new(
        ReplayOracleSearchMaterialization::new(0, case),
        ReplayOracleDivergenceInputs {
            fat_stream: &fat_stream,
            thin_stream: &thin_stream,
            fat_decisions: &fat_decisions,
            thin_decisions: &thin_decisions,
        },
    )];
    let config = ReplayOracleSamplingConfig::new(1, 1, "fork-replay-oracle-localization")?;
    let error = match check_sampled_search_replay_oracle_with_bisection(
        &materializations,
        &config,
        |_, icount| icount < FORK_DIVERGENCE_ICOUNT,
        |_, side, icount| fork_state_dump(side, icount),
    ) {
        Ok(_) => panic!("fork mismatch should require divergence localization"),
        Err(error) => error,
    };
    let ReplayOracleSearchBisectionError::Mismatch { localized } = error else {
        panic!("fork mismatch should localize instead of returning an unlocalized error");
    };

    assert_eq!(localized.mismatch.checkpoint_id, checkpoint_id);
    assert_eq!(localized.bisection.sequence, 0);
    assert_eq!(localized.bisection.checkpoint_id, checkpoint_id);
    assert_eq!(
        localized.divergence.first_different_icount,
        FORK_DIVERGENCE_ICOUNT
    );
    let Some(decision) = localized.divergence.first_different_decision else {
        panic!("fork mismatch must localize the first differing decision");
    };
    assert_eq!(decision.index, 2);

    Ok(())
}

fn fork_divergence_streams() -> (FingerprintStream, FingerprintStream) {
    (
        FingerprintStream {
            definition_digest: vec![0x66],
            samples: vec![
                fork_sample(0, 8, b"fork-same-at-8"),
                fork_sample(1, 24, b"fork-fat-at-24"),
                fork_sample(2, 40, b"fork-fat-at-40"),
            ],
            final_fingerprint: b"fork-fat-final".to_vec(),
        },
        FingerprintStream {
            definition_digest: vec![0x66],
            samples: vec![
                fork_sample(0, 8, b"fork-same-at-8"),
                fork_sample(1, 24, b"fork-thin-at-24"),
                fork_sample(2, 40, b"fork-thin-at-40"),
            ],
            final_fingerprint: b"fork-thin-final".to_vec(),
        },
    )
}

fn fork_fat_decisions() -> Vec<DecisionTraceEntry> {
    vec![
        fork_decision_trace(0, 3, "instantiate fork base snapshot", b"fork:base"),
        fork_decision_trace(1, 11, "append fork branch decision", b"fork:branch"),
        fork_decision_trace(
            2,
            FORK_DIVERGENCE_ICOUNT,
            "fork cache accepted wrong branch state",
            b"fork:cache-wrong",
        ),
    ]
}

fn fork_thin_decisions() -> Vec<DecisionTraceEntry> {
    vec![
        fork_decision_trace(0, 3, "instantiate fork base snapshot", b"fork:base"),
        fork_decision_trace(1, 11, "append fork branch decision", b"fork:branch"),
        fork_decision_trace(
            2,
            FORK_DIVERGENCE_ICOUNT,
            "thin replay reconstructs fork branch state",
            b"fork:thin-correct",
        ),
    ]
}

fn fork_decision_trace(
    index: usize,
    icount: u64,
    summary: &str,
    canonical_bytes: &[u8],
) -> DecisionTraceEntry {
    DecisionTraceEntry {
        index,
        node: Some(String::from("fork-a")),
        icount: Some(icount),
        summary: summary.to_owned(),
        canonical_bytes: canonical_bytes.to_vec(),
    }
}

fn fork_state_dump(side: DivergenceSide, icount: u64) -> DivergenceStateDump {
    let diverged = icount >= FORK_DIVERGENCE_ICOUNT && side == DivergenceSide::Right;
    let pc = if diverged {
        FORK_DIVERGENCE_ICOUNT + 1
    } else {
        icount
    };
    let page_byte = if diverged { 0x9c } else { 0x21 };
    let event_suffix = if diverged {
        "thin replay reconstructs fork branch state"
    } else {
        "fork cache accepted wrong branch state"
    };

    DivergenceStateDump {
        icount,
        registers: vec![
            DivergenceRegister {
                name: String::from("pc"),
                bytes: pc.to_le_bytes().to_vec(),
            },
            DivergenceRegister {
                name: String::from("r1"),
                bytes: 42_u64.to_le_bytes().to_vec(),
            },
        ],
        memory_regions: vec![DivergenceMemoryRegion {
            name: String::from("fork-page"),
            start: 0x3000,
            bytes: vec![page_byte, 0x10, 0x20, 0x30],
        }],
        last_canonical_events: vec![
            String::from("instantiate fork base snapshot"),
            String::from("append fork branch decision"),
            String::from(event_suffix),
        ],
    }
}

fn fork_sample(seq: u64, icount: u64, rolling_fingerprint: &[u8]) -> FingerprintSample {
    FingerprintSample {
        seq,
        node: String::from("fork-a"),
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
        BTreeMap::from([(node.clone(), Icount { retired: 12_345 })]),
        CheckpointKind::Fat,
        BTreeMap::from([(
            node.clone(),
            NodeBlobRef::baked(ContentHash::from_canonical_material(
                "crucible.test.fork-replay-oracle.corrupt-snapshot",
                "wrong-fork-cache-payload",
            )),
        )]),
    )
}
