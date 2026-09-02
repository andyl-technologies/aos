//! Implements `gate:replay-oracle` over the in-process reduction model.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

use crucible::{
    AppRandomDecision, AssertionDef, AssertionId, AssertionQuantifierKind,
    AssertionViolationArtifactReplay, AssertionViolationReplayError, Checkpoint, CheckpointKind,
    Configuration, ContentHash, Decision, DeliveryOrderDecision, EngineError,
    EventDiagnosticPayload, EventKey, EventLevel, FramePredicate, FrontierReductionPolicy,
    GenesisCheckpoint, Icount, MaterializationPolicy, MaterializationTrigger, MaterializedState,
    MemoryDagStore, NodeBlobRef, NodeId, NodeTemplate, ObservableEvent, OfflineAssertionChecker,
    Plan, Predicate, Properties, Property, ReadyPoint, RecordedAssertionLog, ReproductionArtifact,
    RngDecision, RngStreamId, ScenarioDef, ScenarioDefForm, Schedule,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, SchedulerEventLogPayload,
    SchedulerNodeId, SchedulerState, SchedulingNodeKind, SearchFrontierChoices,
    SearchReplayOracleSamplingConfig, Seed, State, TemporalGraph, VirtualTime, WhiteBoxPolicy,
    World, WorldNode, bake, check_assertion_violation_reproduction, compare_event_log_determinism,
    instantiate, reduce, step,
};
use crucible_harness::replay_oracle::{
    ReplayOracleArtifactRun, ReplayOracleBuildIdentity, ReplayOracleCheckpointKind,
    ReplayOracleMaterializedCase, ReplayOracleMismatch, ReplayOracleReproductionArtifact,
    ReplayOracleRoundTripError, ReplayOracleSamplingConfig, ReplayOracleSearchMaterialization,
    ReplayOracleSearchSamplingError, check_materialized_replay_oracle,
    check_replay_oracle_reproduction_artifact_round_trip, check_sampled_search_replay_oracle,
};

struct SimDouble;

#[derive(Clone, Debug)]
struct MaterializedCheckpoint {
    checkpoint_id: String,
    checkpoint: Checkpoint,
    configuration: Configuration,
    ancestor: Configuration,
    schedule_delta: Schedule,
    state: State,
    observational_entries: Vec<String>,
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::enum_variant_names)]
enum ReproductionArtifactErrorCoverage {
    BuildIdentityMismatch,
    FingerprintMismatch,
    OracleCaseMismatch,
}

impl SimDouble {
    fn materialize_fat_checkpoint(
        &self,
        checkpoint_id: String,
        ancestor: &Configuration,
        configuration: &Configuration,
    ) -> Result<MaterializedCheckpoint, Box<dyn Error>> {
        let schedule_delta = schedule_delta(&ancestor.schedule, &configuration.schedule)?;
        let state =
            assert_twice_reduce_canonical_digest(&configuration.def, &configuration.schedule)?;
        let node_blobs = materialized_node_blobs(ancestor.content_hash(), &schedule_delta, &state);
        let checkpoint = Checkpoint::with_node_blobs(
            test_double_checkpoint_hash(
                &checkpoint_id,
                configuration,
                ancestor.content_hash(),
                &schedule_delta,
                &state,
            ),
            configuration.content_hash(),
            CheckpointKind::Fat,
            node_blobs,
        );

        Ok(MaterializedCheckpoint {
            checkpoint_id,
            checkpoint,
            configuration: configuration.clone(),
            ancestor: ancestor.clone(),
            schedule_delta,
            state,
            observational_entries: vec![String::from("host-observation:materialized")],
        })
    }

    fn replay_case(
        &self,
        checkpoint: &MaterializedCheckpoint,
    ) -> Result<ReplayOracleMaterializedCase, Box<dyn Error>> {
        self.replay_case_with_delta(checkpoint, &checkpoint.schedule_delta)
    }

    fn replay_case_with_delta(
        &self,
        checkpoint: &MaterializedCheckpoint,
        thin_delta: &Schedule,
    ) -> Result<ReplayOracleMaterializedCase, Box<dyn Error>> {
        let thin_schedule = replay_schedule(&checkpoint.ancestor.schedule, thin_delta);
        let thin_configuration = Configuration {
            def: checkpoint.configuration.def.clone(),
            schedule: thin_schedule,
        };
        let thin_state = reduce(&thin_configuration.def, &thin_configuration.schedule)?;
        let fat_blob_hash = checkpoint
            .checkpoint
            .node_blob(&oracle_node_id())
            .map(NodeBlobRef::content_hash)
            .ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidData,
                    "materialized checkpoint missing oracle node blob",
                )
            })?;
        let thin_blob_hash =
            materialized_node_blobs(checkpoint.ancestor.content_hash(), thin_delta, &thin_state)
                .get(&oracle_node_id())
                .map(NodeBlobRef::content_hash)
                .ok_or_else(|| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        "thin replay missing oracle node blob",
                    )
                })?;
        let thin_checkpoint_hash = test_double_checkpoint_hash(
            &checkpoint.checkpoint_id,
            &thin_configuration,
            checkpoint.ancestor.content_hash(),
            thin_delta,
            &thin_state,
        );

        Ok(ReplayOracleMaterializedCase {
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            kind: checkpoint_kind(checkpoint.checkpoint.kind),
            fat_checkpoint_hash: hash_bytes(checkpoint.checkpoint.id),
            thin_checkpoint_hash: hash_bytes(thin_checkpoint_hash),
            fat_configuration_hash: hash_bytes(checkpoint.checkpoint.configuration),
            thin_configuration_hash: hash_bytes(thin_configuration.content_hash()),
            fat_ancestor_hash: hash_bytes(checkpoint.ancestor.content_hash()),
            thin_ancestor_hash: hash_bytes(checkpoint.ancestor.content_hash()),
            fat_schedule_delta_hash: hash_bytes(checkpoint.schedule_delta.content_hash()),
            thin_schedule_delta_hash: hash_bytes(thin_delta.content_hash()),
            fat_hash: hash_bytes(fat_blob_hash),
            thin_hash: hash_bytes(thin_blob_hash),
        })
    }
}

#[test]
fn gate_replay_oracle_fixed_checkpoint_corpus_matches_thin_reduction() -> Result<(), Box<dyn Error>>
{
    let corpus = assert_replay_oracle_fixed_checkpoint_corpus()?;

    check_materialized_replay_oracle(&corpus)?;
    assert_replay_oracle_excludes_observational_entries(&corpus)?;

    Ok(())
}

#[test]
fn gate_replay_oracle_rejects_corrupt_materialized_checkpoint() -> Result<(), Box<dyn Error>> {
    let corpus = assert_replay_oracle_fixed_checkpoint_corpus()?;
    let configuration_mismatch =
        assert_replay_oracle_rejects_corrupt_configuration_metadata(&corpus)?;
    let delta_mismatch = assert_replay_oracle_rejects_corrupt_schedule_delta_metadata(&corpus)?;
    let body_mismatch = assert_replay_oracle_reports_first_mismatch(&corpus)?;

    assert_eq!(configuration_mismatch.checkpoint_id, "cp-1");
    assert_eq!(delta_mismatch.checkpoint_id, "cp-2");
    assert_eq!(body_mismatch.checkpoint_id, "cp-1");

    Ok(())
}

#[test]
fn gate_replay_oracle_materialized_state_loadvm_branch_captures_resume_components()
-> Result<(), Box<dyn Error>> {
    let node = oracle_node_id();
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 321 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake(&world)?;
    let state =
        baked.checkpoint.state.as_ref().ok_or_else(|| {
            IoError::new(ErrorKind::InvalidData, "baked checkpoint missing state")
        })?;
    let snapshot = state.vm_snapshots.get(&node).ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            "baked state missing VM snapshot ref",
        )
    })?;
    let graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked.clone())?;
    let runtime = instantiate(&graph, &genesis)?;

    assert_eq!(snapshot.icount, Icount { retired: 321 });
    assert_eq!(
        Some(&snapshot.blob),
        graph
            .genesis_snapshot(&scenario)
            .and_then(|genesis| genesis.checkpoint.node_blob(&node))
    );
    assert!(state.device_overlays.is_empty());
    assert_eq!(state.scheduler, SchedulerState::empty());
    assert!(state.decision_rng.positions.is_empty());
    assert_eq!(runtime.configuration, genesis.id());

    Ok(())
}

#[test]
fn gate_replay_oracle_saved_descendant_fat_checkpoint_carries_vm_snapshot_refs()
-> Result<(), Box<dyn Error>> {
    let node = oracle_node_id();
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 987 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake(&world)?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let target = step(
        &genesis,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("save/descendant"),
            value: 42,
        }),
    );
    let checkpoint = graph.save_checkpoint(&target)?;
    let state = checkpoint.state.as_ref().ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            "saved descendant checkpoint missing state",
        )
    })?;
    let snapshot = state.vm_snapshots.get(&node).ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            "saved descendant missing VM snapshot",
        )
    })?;
    let loaded = instantiate(&graph, &target)?;
    let baked_blob = graph
        .genesis_snapshot(&scenario)
        .and_then(|genesis| genesis.checkpoint.node_blob(&node))
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "baked node blob missing"))?;

    assert_eq!(snapshot.icount, Icount { retired: 988 });
    assert_ne!(snapshot.blob.content_hash(), baked_blob.content_hash());
    assert!(matches!(snapshot.blob, NodeBlobRef::CowDelta { .. }));
    assert_eq!(checkpoint.node_blobs.len(), 1);
    assert_eq!(checkpoint.node_icounts[&node], Icount { retired: 988 });
    assert_eq!(loaded.configuration, target.id());

    Ok(())
}

#[test]
fn gate_replay_oracle_temporal_graph_user_operations_share_instantiate_path()
-> Result<(), Box<dyn Error>> {
    let node = oracle_node_id();
    let world = World::from_nodes(vec![WorldNode {
        id: node,
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 111 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked =
        baked_with_search_frontier_choices(&world, vec![rng_decision("operation/search", 9)])?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let store = MemoryDagStore::new();
    let saved = step(&genesis, rng_decision("operation/save", 7));
    let save = graph.save(&store, &saved)?;

    assert_eq!(save.configuration, saved.id());
    assert_eq!(save.checkpoint, saved.id());
    assert_eq!(save.checkpoint_kind, CheckpointKind::Fat);

    let resumed = graph.resume(&saved)?;
    let direct = instantiate(&graph, &saved)?;
    assert_eq!(resumed.runtime, direct);

    let replay = graph.replay(&saved)?;
    assert_eq!(replay.configuration, saved.id());
    assert_eq!(replay.fat_checkpoint, saved.id());
    assert_eq!(replay.thin_checkpoint, saved.id());

    let fork = graph.fork(&genesis, vec![rng_decision("operation/fork", 8)])?;
    let thin_replay_error = graph
        .replay(&fork.branch)
        .expect_err("thin-only fork should not replay as a stored fat checkpoint");
    assert!(matches!(
        thin_replay_error,
        EngineError::CheckpointNotRecorded { checkpoint } if checkpoint == fork.branch.id()
    ));
    let fork_runtime = graph.resume(&fork.branch)?;
    let fork_direct = instantiate(&graph, &fork.branch)?;
    assert_eq!(fork.branch_checkpoint.kind, CheckpointKind::Thin);
    assert_eq!(fork.base.runtime, instantiate(&graph, &genesis)?);
    assert_eq!(fork_runtime.runtime, fork_direct);

    let search = graph.search(
        &genesis,
        FrontierReductionPolicy::none(),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
    )?;
    assert_eq!(search.frontier_report.explored.len(), 1);
    assert_eq!(search.materialized.len(), 1);
    assert_eq!(search.materialized[0].kind, CheckpointKind::Thin);
    let searched = search.frontier_report.explored[0].configuration.clone();
    let search_runtime = graph.resume(&searched)?;
    let search_direct = instantiate(&graph, &searched)?;
    assert_eq!(search_runtime.runtime, search_direct);

    Ok(())
}

#[test]
fn gate_replay_oracle_loadvm_rejects_incomplete_materialized_state() -> Result<(), Box<dyn Error>> {
    let node = oracle_node_id();
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 654 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let scenario = world.scenario_def();
    let baked = bake(&world)?;
    let mut missing_state = baked.checkpoint.clone();
    missing_state.state = None;
    let missing_error = match TemporalGraph::empty().with_baked_genesis(
        &scenario,
        GenesisCheckpoint {
            checkpoint: missing_state,
        },
    ) {
        Ok(_) => panic!("missing materialized state should be rejected"),
        Err(error) => error,
    };
    let mut missing_snapshot = baked.checkpoint.clone();
    let state = missing_snapshot
        .state
        .as_ref()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "baked checkpoint missing state"))?;
    let mut snapshots = state.vm_snapshots.clone();
    snapshots.remove(&node);
    missing_snapshot.state = Some(MaterializedState::from_components(
        snapshots,
        state.device_overlays.clone(),
        state.scheduler.clone(),
        state.decision_rng.clone(),
        state.event_log,
    ));
    let snapshot_error = match TemporalGraph::empty().with_baked_genesis(
        &scenario,
        GenesisCheckpoint {
            checkpoint: missing_snapshot,
        },
    ) {
        Ok(_) => panic!("missing VM snapshot should be rejected"),
        Err(error) => error,
    };
    let mut extra_snapshot = baked.checkpoint.clone();
    let state = extra_snapshot
        .state
        .as_ref()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "baked checkpoint missing state"))?;
    let mut snapshots = state.vm_snapshots.clone();
    snapshots.insert(
        NodeId {
            name: String::from("extra-node"),
        },
        snapshots
            .get(&node)
            .cloned()
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "fixture missing snapshot"))?,
    );
    extra_snapshot.state = Some(MaterializedState::from_components(
        snapshots,
        state.device_overlays.clone(),
        state.scheduler.clone(),
        state.decision_rng.clone(),
        state.event_log,
    ));
    let extra_error = match TemporalGraph::empty().with_baked_genesis(
        &scenario,
        GenesisCheckpoint {
            checkpoint: extra_snapshot,
        },
    ) {
        Ok(_) => panic!("extra VM snapshot should be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        missing_error,
        EngineError::CheckpointMaterializedStateIncomplete {
            reason: "missing-state",
            ..
        }
    ));
    assert!(matches!(
        snapshot_error,
        EngineError::CheckpointMaterializedStateIncomplete {
            reason: "missing-vm-snapshot",
            ..
        }
    ));
    assert!(matches!(
        extra_error,
        EngineError::CheckpointMaterializedStateIncomplete {
            reason: "extra-vm-snapshot",
            ..
        }
    ));

    Ok(())
}

#[test]
fn gate_replay_oracle_samples_materialized_checkpoints_during_search() -> Result<(), Box<dyn Error>>
{
    let corpus = assert_replay_oracle_fixed_checkpoint_corpus()?;
    let report = assert_replay_oracle_in_search_sampling(&corpus)?;

    assert_eq!(report.considered, corpus.len());
    assert_eq!(report.sampled, corpus.len());
    assert_eq!(report.skipped, 0);
    assert_eq!(report.sampled_checkpoints.len(), corpus.len());

    Ok(())
}

#[test]
fn gate_replay_oracle_samples_temporal_graph_search_fat_materializations()
-> Result<(), Box<dyn Error>> {
    let node = oracle_node_id();
    let world = World::from_nodes(vec![WorldNode {
        id: node,
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 222 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = baked_with_search_frontier_choices(
        &world,
        vec![
            rng_decision("search-oracle/a", 1),
            rng_decision("search-oracle/b", 2),
            rng_decision("search-oracle/c", 3),
        ],
    )?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let config = SearchReplayOracleSamplingConfig::new(1, 1, "gate-replay-oracle-graph-search")?;
    let search = graph.search_with_replay_oracle_sampling(
        &genesis,
        FrontierReductionPolicy::none(),
        MaterializationPolicy::with_budget(3),
        MaterializationTrigger::RepeatedForkSource,
        &config,
    )?;
    let report = search.replay_oracle_sampling.as_ref().ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            "search replay-oracle sampling report missing",
        )
    })?;

    assert_eq!(search.frontier_report.explored.len(), 3);
    assert_eq!(search.materialized.len(), 3);
    assert!(
        search
            .materialized
            .iter()
            .all(|checkpoint| checkpoint.kind == CheckpointKind::Fat)
    );
    assert_eq!(report.considered, search.materialized.len());
    assert_eq!(report.sampled, search.materialized.len());
    assert_eq!(report.skipped, 0);
    assert_eq!(report.sampled_checkpoints.len(), search.materialized.len());
    assert_eq!(
        report.sampled_checkpoints,
        search
            .materialized
            .iter()
            .map(|checkpoint| checkpoint.id)
            .collect::<Vec<_>>()
    );

    Ok(())
}

#[test]
fn gate_replay_oracle_search_sampling_rate_can_skip_materializations() -> Result<(), Box<dyn Error>>
{
    let node = oracle_node_id();
    let world = World::from_nodes(vec![WorldNode {
        id: node,
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 222 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = baked_with_search_frontier_choices(
        &world,
        vec![
            rng_decision("search-oracle/skip-a", 1),
            rng_decision("search-oracle/skip-b", 2),
            rng_decision("search-oracle/skip-c", 3),
        ],
    )?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let config =
        SearchReplayOracleSamplingConfig::new(1, u64::MAX, "gate-replay-oracle-graph-search-skip")?;
    let search = graph.search_with_replay_oracle_sampling(
        &genesis,
        FrontierReductionPolicy::none(),
        MaterializationPolicy::with_budget(3),
        MaterializationTrigger::RepeatedForkSource,
        &config,
    )?;
    let report = search.replay_oracle_sampling.as_ref().ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            "search replay-oracle sampling report missing",
        )
    })?;

    assert_eq!(search.materialized.len(), 3);
    assert_eq!(report.considered, search.materialized.len());
    assert_eq!(report.sampled, 0);
    assert_eq!(report.skipped, search.materialized.len());
    assert!(report.sampled_checkpoints.is_empty());

    Ok(())
}

#[test]
fn gate_replay_oracle_search_sampling_mismatch_requests_bisection() -> Result<(), Box<dyn Error>> {
    let node = oracle_node_id();
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 222 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let decision = rng_decision("search-oracle/corrupt", 4);
    let baked = baked_with_search_frontier_choices(&world, vec![decision.clone()])?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let child = step(&genesis, decision.clone());
    let corrupt_checkpoint = Checkpoint::from_recorded_configuration(
        &child,
        Some(&genesis),
        VirtualTime::default(),
        std::collections::BTreeMap::from([(
            node.clone(),
            Icount {
                retired: 222 + child.schedule.len() as u64,
            },
        )]),
        CheckpointKind::Fat,
        std::collections::BTreeMap::from([(
            node,
            NodeBlobRef::baked(ContentHash::from_canonical_material(
                "crucible.test.replay-oracle.search-corrupt-cache",
                "wrong-fat-vm-blob",
            )),
        )]),
    )?;
    graph.cache_snapshot(&child, corrupt_checkpoint)?;
    let config = SearchReplayOracleSamplingConfig::new(1, 1, "gate-replay-oracle-graph-search")?;

    let error = match graph.search_with_replay_oracle_sampling(
        &genesis,
        FrontierReductionPolicy::none(),
        MaterializationPolicy::with_budget(1),
        MaterializationTrigger::RepeatedForkSource,
        &config,
    ) {
        Ok(_) => panic!("sampled corrupt search materialization should fail with bisection"),
        Err(error) => error,
    };
    let EngineError::SearchReplayOracleMismatch {
        bisection,
        checkpoint,
        expected,
        actual,
    } = error
    else {
        panic!("sampled corrupt search materialization should request bisection");
    };

    assert_eq!(bisection.sequence, 0);
    assert_eq!(bisection.checkpoint, checkpoint);
    assert_eq!(
        bisection.reason,
        "sampled fat checkpoint differs from thin reconstruction"
    );
    assert_ne!(expected, actual);

    Ok(())
}

#[test]
fn gate_replay_oracle_sampled_mismatch_requests_bisection() -> Result<(), Box<dyn Error>> {
    let corpus = assert_replay_oracle_fixed_checkpoint_corpus()?;
    let error = assert_replay_oracle_mismatch_bisects(&corpus)?;

    let ReplayOracleSearchSamplingError::Mismatch {
        mismatch,
        bisection,
    } = error
    else {
        panic!("sampled mismatch should require bisection");
    };

    assert_eq!(mismatch.checkpoint_id, "cp-1");
    assert_eq!(bisection.checkpoint_id, "cp-1");
    assert_eq!(bisection.sequence, 1);

    Ok(())
}

#[test]
fn gate_replay_oracle_reproduction_artifact_round_trips() -> Result<(), Box<dyn Error>> {
    assert_reproduction_artifact_roundtrip_coverage()
}

fn assert_reproduction_artifact_roundtrip_coverage() -> Result<(), Box<dyn Error>> {
    let artifact = representative_replay_oracle_reproduction_artifact()?;
    let report = check_replay_oracle_reproduction_artifact_round_trip(
        &artifact,
        &simdouble_replay_build_identity(),
        replay_reproduction_artifact,
    )?;

    assert_eq!(report.seed, 0x0010_0027);
    assert_eq!(report.expected.fingerprint, report.reproduced.fingerprint);
    assert_eq!(report.expected.oracle_case, report.reproduced.oracle_case);

    Ok(())
}

#[test]
fn gate_replay_oracle_covers_assertion_regrade_and_violation_reproduction()
-> Result<(), Box<dyn Error>> {
    let world = assertion_replay_world()?;
    let properties = assertion_replay_properties(&world)?;
    let amended_properties = assertion_replay_amended_properties(&world)?;
    let artifact =
        assertion_replay_artifact(&world, &properties, AssertionReplayPayload::Forbidden)?;
    let passing_artifact =
        assertion_replay_artifact(&world, &properties, AssertionReplayPayload::Allowed)?;
    let recorded_log = assertion_replay_recorded_log_from_artifact(&artifact)?;
    let passing_log = assertion_replay_recorded_log_from_artifact(&passing_artifact)?;
    let retained_corpus = vec![recorded_log.clone(), passing_log];
    let checker = OfflineAssertionChecker::new();

    let first = regrade_assertion_corpus(&checker, &properties, &retained_corpus)?;
    let second = regrade_assertion_corpus(&checker, &properties, &retained_corpus)?;
    assert_eq!(
        first, second,
        "gate:replay-oracle must idempotently re-grade a retained assertion corpus"
    );
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].violations().len(), 1);
    assert_eq!(first[1].violations().len(), 0);

    let amended_first = regrade_assertion_corpus(&checker, &amended_properties, &retained_corpus)?;
    let amended_second = regrade_assertion_corpus(&checker, &amended_properties, &retained_corpus)?;
    assert_eq!(
        amended_first, amended_second,
        "gate:replay-oracle must idempotently re-grade retained runs after assertion suites grow"
    );
    assert_eq!(amended_first[0].violations().len(), 2);
    assert_eq!(amended_first[1].violations().len(), 0);

    let replayed_log = assertion_replay_recorded_log_from_artifact(&artifact)?;
    assert_eq!(
        recorded_log.entries(),
        replayed_log.entries(),
        "artifact-bound assertion replay must emit a bit-identical retained log"
    );
    let replayed = AssertionViolationArtifactReplay::from_artifact(&artifact, replayed_log)?;
    let report = check_assertion_violation_reproduction(&artifact, &recorded_log, &replayed)?;
    assert_eq!(
        report.expected, report.reproduced,
        "artifact-bound replay must reproduce the same assertion violation"
    );
    let violation = &report.reproduced.violations()[0];
    assert_eq!(
        violation.assertion,
        assertion_id("replay-no-forbidden-frame")
    );
    assert_eq!(violation.quantifier, AssertionQuantifierKind::Always);
    assert_eq!(violation.reproduction_artifact, artifact.id());

    let drifted_artifact =
        assertion_replay_artifact(&world, &properties, AssertionReplayPayload::Allowed)?;
    let drifted_log = assertion_replay_recorded_log_from_artifact(&drifted_artifact)?;
    assert_ne!(
        recorded_log.entries(),
        drifted_log.entries(),
        "assertion replay log must be derived from the artifact schedule, not a cloned fixture"
    );
    let drifted_replay =
        AssertionViolationArtifactReplay::from_artifact(&drifted_artifact, drifted_log)?;
    let drift_error =
        check_assertion_violation_reproduction(&artifact, &recorded_log, &drifted_replay)
            .expect_err("schedule drift must not satisfy bit-identical assertion reproduction");
    assert!(matches!(
        drift_error,
        AssertionViolationReplayError::ReplayArtifactMismatch { .. }
    ));

    Ok(())
}

#[test]
fn gate_replay_oracle_reproduction_artifact_rejects_build_identity_drift()
-> Result<(), Box<dyn Error>> {
    let mut artifact = representative_replay_oracle_reproduction_artifact()?;
    artifact.build_identity.backend_build_id = String::from("wrong-build");

    let error = match check_replay_oracle_reproduction_artifact_round_trip(
        &artifact,
        &simdouble_replay_build_identity(),
        replay_reproduction_artifact,
    ) {
        Ok(_) => panic!("build identity drift should fail artifact replay"),
        Err(error) => error,
    };

    assert_reproduction_artifact_error_variant_coverage(
        error,
        ReproductionArtifactErrorCoverage::BuildIdentityMismatch,
    );

    Ok(())
}

#[test]
fn gate_replay_oracle_reproduction_artifact_detects_schedule_drift() -> Result<(), Box<dyn Error>> {
    let mut artifact = representative_replay_oracle_reproduction_artifact()?;
    artifact.schedule = artifact.schedule.appended(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("artifact/drift"),
        value: 0xdead_beef,
    }));

    let error = match check_replay_oracle_reproduction_artifact_round_trip(
        &artifact,
        &simdouble_replay_build_identity(),
        replay_reproduction_artifact,
    ) {
        Ok(_) => panic!("schedule drift should change the reproduced fingerprint"),
        Err(error) => error,
    };

    assert_reproduction_artifact_error_variant_coverage(
        error,
        ReproductionArtifactErrorCoverage::FingerprintMismatch,
    );

    Ok(())
}

#[test]
fn gate_replay_oracle_reproduction_artifact_detects_seed_drift() -> Result<(), Box<dyn Error>> {
    let mut artifact = representative_replay_oracle_reproduction_artifact()?;
    artifact.seed = 0x0010_0028;

    let error = match check_replay_oracle_reproduction_artifact_round_trip(
        &artifact,
        &simdouble_replay_build_identity(),
        replay_reproduction_artifact,
    ) {
        Ok(_) => panic!("seed drift should change the reproduced fingerprint"),
        Err(error) => error,
    };

    assert_reproduction_artifact_error_variant_coverage(
        error,
        ReproductionArtifactErrorCoverage::FingerprintMismatch,
    );

    Ok(())
}

#[test]
fn gate_replay_oracle_reproduction_artifact_detects_scenario_drift() -> Result<(), Box<dyn Error>> {
    let mut artifact = representative_replay_oracle_reproduction_artifact()?;
    artifact.scenario = ScenarioDef::from_canonical_material(
        "crucible.test.replay-oracle.artifact",
        "nodes=artifact-a,artifact-b,artifact-c\nseed=mutated",
    );

    let error = match check_replay_oracle_reproduction_artifact_round_trip(
        &artifact,
        &simdouble_replay_build_identity(),
        replay_reproduction_artifact,
    ) {
        Ok(_) => panic!("scenario drift should change the reproduced fingerprint"),
        Err(error) => error,
    };

    assert_reproduction_artifact_error_variant_coverage(
        error,
        ReproductionArtifactErrorCoverage::FingerprintMismatch,
    );

    Ok(())
}

#[test]
fn gate_replay_oracle_reproduction_artifact_detects_oracle_case_drift() -> Result<(), Box<dyn Error>>
{
    let artifact = representative_replay_oracle_reproduction_artifact()?;
    let error = match check_replay_oracle_reproduction_artifact_round_trip(
        &artifact,
        &simdouble_replay_build_identity(),
        |artifact| {
            let mut run = replay_reproduction_artifact(artifact)?;
            run.oracle_case.checkpoint_id = String::from("artifact-cp-replayed");
            Ok::<_, Box<dyn Error>>(run)
        },
    ) {
        Ok(_) => panic!("oracle case drift should fail artifact replay"),
        Err(error) => error,
    };

    assert_reproduction_artifact_error_variant_coverage(
        error,
        ReproductionArtifactErrorCoverage::OracleCaseMismatch,
    );

    Ok(())
}

fn assert_reproduction_artifact_error_variant_coverage(
    error: ReplayOracleRoundTripError,
    expected: ReproductionArtifactErrorCoverage,
) {
    match expected {
        ReproductionArtifactErrorCoverage::BuildIdentityMismatch => {
            assert!(matches!(
                error,
                ReplayOracleRoundTripError::BuildIdentityMismatch { .. }
            ));
        }
        ReproductionArtifactErrorCoverage::FingerprintMismatch => {
            assert!(matches!(
                error,
                ReplayOracleRoundTripError::FingerprintMismatch { .. }
            ));
        }
        ReproductionArtifactErrorCoverage::OracleCaseMismatch => {
            assert!(matches!(
                error,
                ReplayOracleRoundTripError::OracleCaseMismatch { .. }
            ));
        }
    }
}

fn assert_replay_oracle_fixed_checkpoint_corpus()
-> Result<Vec<ReplayOracleMaterializedCase>, Box<dyn Error>> {
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.replay-oracle", "nodes=a,b\nseed=42");
    let genesis = Configuration::genesis(scenario.clone());
    let first = step(
        &genesis,
        Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 5 },
            order: vec![event_key(5, 1), event_key(5, 2)],
        }),
    );
    let second = step(
        &first,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_link("link-a-b/drop"),
            value: 1,
        }),
    );
    let third = step(
        &second,
        Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId::for_node("whitebox/request"),
            request_id: 9,
            width: 32,
            value: 0xabcd,
        }),
    );

    let double = SimDouble;
    let checkpoints = [genesis, first, second, third];
    let mut cases = Vec::new();

    for (index, configuration) in checkpoints.iter().enumerate() {
        let ancestor = if index == 0 {
            configuration
        } else {
            &checkpoints[index - 1]
        };
        let materialized =
            double.materialize_fat_checkpoint(format!("cp-{index}"), ancestor, configuration)?;
        assert!(matches!(
            materialized.checkpoint.node_blob(&oracle_node_id()),
            Some(NodeBlobRef::CowDelta { resolved, .. }) if *resolved == materialized.state.id
        ));
        cases.push(double.replay_case(&materialized)?);
    }

    Ok(cases)
}

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn assertion_replay_world() -> Result<World, EngineError> {
    World::from_nodes(Vec::new())
}

fn assertion_replay_properties(world: &World) -> Result<Properties, EngineError> {
    Properties::from_assertions_for_world(
        world,
        vec![AssertionDef {
            id: assertion_id("replay-no-forbidden-frame"),
            message: String::from("forbidden frame stays absent"),
            property: Property::Always {
                predicate: Predicate::not(Predicate::network_match(
                    None,
                    FramePredicate::contains(b"forbidden".to_vec()),
                )),
            },
        }],
    )
}

fn assertion_replay_amended_properties(world: &World) -> Result<Properties, EngineError> {
    Properties::from_assertions_for_world(
        world,
        vec![
            AssertionDef {
                id: assertion_id("replay-no-forbidden-frame"),
                message: String::from("forbidden frame stays absent"),
                property: Property::Always {
                    predicate: Predicate::not(Predicate::network_match(
                        None,
                        FramePredicate::contains(b"forbidden".to_vec()),
                    )),
                },
            },
            AssertionDef {
                id: assertion_id("replay-eventually-allowed-frame"),
                message: String::from("allowed frame is eventually retained"),
                property: Property::Sometimes {
                    predicate: Predicate::network_match(
                        None,
                        FramePredicate::contains(b"allowed".to_vec()),
                    ),
                },
            },
        ],
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AssertionReplayPayload {
    Forbidden,
    Allowed,
}

impl AssertionReplayPayload {
    fn schedule_value(self) -> u64 {
        match self {
            Self::Forbidden => 0xa510_0016,
            Self::Allowed => 0xa510_0017,
        }
    }

    fn frame(self) -> Vec<u8> {
        match self {
            Self::Forbidden => b"forbidden".to_vec(),
            Self::Allowed => b"allowed".to_vec(),
        }
    }
}

fn assertion_replay_schedule(payload: AssertionReplayPayload) -> Schedule {
    Schedule::empty().appended(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("assertion/replay-oracle"),
        value: payload.schedule_value(),
    }))
}

fn assertion_replay_payload_from_schedule(
    schedule: &Schedule,
) -> Result<AssertionReplayPayload, Box<dyn Error>> {
    let [Decision::RngDraw(draw)] = schedule.decisions() else {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "assertion replay artifact schedule must contain one rng draw",
        )));
    };
    if draw.stream != RngStreamId::from_name("assertion/replay-oracle") {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "assertion replay artifact schedule uses the wrong stream",
        )));
    }
    match draw.value {
        0xa510_0016 => Ok(AssertionReplayPayload::Forbidden),
        0xa510_0017 => Ok(AssertionReplayPayload::Allowed),
        _ => Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "assertion replay artifact schedule uses an unknown payload value",
        ))),
    }
}

fn assertion_replay_event_log_from_artifact(
    artifact: &ReproductionArtifact,
) -> Result<Vec<SchedulerEventLogEntry>, Box<dyn Error>> {
    let _ = artifact.replay()?;
    let payload = assertion_replay_payload_from_schedule(artifact.schedule())?;
    let decision = artifact
        .schedule()
        .decisions()
        .first()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "missing replay decision"))?
        .clone();
    let observed =
        ObservableEvent::network_delivered(VirtualTime { ticks: 9 }, None, payload.frame());
    Ok(vec![
        crucible::test_support::condition_payload_entry_for_test(
            0,
            VirtualTime { ticks: 0 },
            SchedulerEventLogPayload::Decision(decision),
        ),
        crucible::test_support::condition_observation_entry_for_test(1, &observed),
        crucible::test_support::condition_boundary_entry_for_test(
            2,
            VirtualTime { ticks: 9 },
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ])
}

fn assertion_replay_recorded_log_from_artifact(
    artifact: &ReproductionArtifact,
) -> Result<RecordedAssertionLog, Box<dyn Error>> {
    let event_log = assertion_replay_event_log_from_artifact(artifact)?;
    Ok(RecordedAssertionLog::from_segments(vec![
        event_log[..2].to_vec(),
        event_log[2..].to_vec(),
    ])?)
}

fn assertion_replay_artifact(
    world: &World,
    properties: &Properties,
    payload: AssertionReplayPayload,
) -> Result<ReproductionArtifact, EngineError> {
    let scenario =
        ScenarioDefForm::from_components(world, &Plan::empty(), properties, Seed::from_u64(0x16))?;
    ReproductionArtifact::capture(&scenario, &assertion_replay_schedule(payload))
}

fn regrade_assertion_corpus(
    checker: &OfflineAssertionChecker,
    properties: &Properties,
    corpus: &[RecordedAssertionLog],
) -> Result<Vec<crucible::HostAssertionReport>, Box<dyn Error>> {
    corpus
        .iter()
        .map(|recorded_log| Ok(checker.check_run(properties, recorded_log.entries())?))
        .collect()
}

fn representative_replay_oracle_reproduction_artifact()
-> Result<ReplayOracleReproductionArtifact<ScenarioDef, Schedule>, Box<dyn Error>> {
    let seed = 0x0010_0027;
    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.replay-oracle.artifact",
        &format!("nodes=artifact-a,artifact-b\nseed={seed}"),
    );
    let schedule = Schedule::empty()
        .appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 3 },
            order: vec![event_key(3, 10), event_key(3, 11)],
        }))
        .appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_link("artifact/link-drop"),
            value: 1,
        }))
        .appended(Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("artifact-a"),
            },
            stream: RngStreamId::for_node("artifact/request"),
            request_id: 27,
            width: 64,
            value: 0xfeed_0010_0027,
        }));
    let configuration = Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let genesis = Configuration::genesis(scenario.clone());
    let double = SimDouble;
    let materialized =
        double.materialize_fat_checkpoint(String::from("artifact-cp"), &genesis, &configuration)?;

    Ok(ReplayOracleReproductionArtifact {
        seed,
        scenario,
        schedule,
        build_identity: simdouble_replay_build_identity(),
        expected: ReplayOracleArtifactRun {
            fingerprint: replay_oracle_artifact_fingerprint(
                seed,
                &configuration.def,
                &configuration.schedule,
            )?,
            oracle_case: double.replay_case(&materialized)?,
        },
    })
}

fn replay_reproduction_artifact(
    artifact: &ReplayOracleReproductionArtifact<ScenarioDef, Schedule>,
) -> Result<ReplayOracleArtifactRun, Box<dyn Error>> {
    let genesis = Configuration::genesis(artifact.scenario.clone());
    let configuration = Configuration {
        def: artifact.scenario.clone(),
        schedule: artifact.schedule.clone(),
    };
    let double = SimDouble;
    let materialized =
        double.materialize_fat_checkpoint(String::from("artifact-cp"), &genesis, &configuration)?;

    Ok(ReplayOracleArtifactRun {
        fingerprint: replay_oracle_artifact_fingerprint(
            artifact.seed,
            &artifact.scenario,
            &artifact.schedule,
        )?,
        oracle_case: double.replay_case(&materialized)?,
    })
}

fn simdouble_replay_build_identity() -> ReplayOracleBuildIdentity {
    ReplayOracleBuildIdentity {
        crucible_version: env!("CARGO_PKG_VERSION").to_string(),
        harness_abi: String::from("crucible-replay-oracle-artifact-v1"),
        backend: String::from("SimDouble"),
        backend_build_id: String::from("crucible-model-test-double-v1"),
        qemu_patch_series_hash: String::from(
            "crucible-hash:9aa30c89f10ee512ab3ec9fb12f9b22a95d6d2859f7b1e9581678a113d0fbcf3",
        ),
        shmem_abi_version: crucible_shmem::ABI_VERSION.to_string(),
        guest_host_protocol_version: crucible_protocol::CONTROL_PROTOCOL_VERSION.to_string(),
        rpc_abi_version: String::from("5.1.0"),
        rpc_abi_build: String::from("crucible-rpc-abi-v5"),
        plugin_abi: String::from("simdouble-mock-plugin-abi"),
    }
}

fn replay_oracle_artifact_fingerprint(
    seed: u64,
    scenario: &ScenarioDef,
    schedule: &Schedule,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let state = reduce(scenario, schedule)?;
    let material = format!(
        "seed={seed}\nscenario={}\nschedule={}\nstate={}\n",
        hash_hex(scenario.id()),
        hash_hex(schedule.content_hash()),
        hash_hex(state.id)
    );
    Ok(hash_bytes(ContentHash::from_canonical_material(
        "crucible.test.replay-oracle.artifact-fingerprint",
        &material,
    )))
}

fn assert_replay_oracle_in_search_sampling(
    corpus: &[ReplayOracleMaterializedCase],
) -> Result<crucible_harness::replay_oracle::ReplayOracleSearchSamplingReport, Box<dyn Error>> {
    let config = ReplayOracleSamplingConfig::new(1, 1, "gate-replay-oracle-search")?;
    let materializations = search_materializations(corpus);
    let report = check_sampled_search_replay_oracle(&materializations, &config)?;
    Ok(report)
}

fn assert_replay_oracle_mismatch_bisects(
    corpus: &[ReplayOracleMaterializedCase],
) -> Result<ReplayOracleSearchSamplingError, Box<dyn Error>> {
    let mut corrupted = corpus.to_vec();
    if let Some(case) = corrupted.get_mut(1) {
        case.fat_hash = hash_bytes(ContentHash::from_canonical_material(
            "crucible.test.replay-oracle.search-corrupt",
            "cp-1",
        ));
    }
    let config = ReplayOracleSamplingConfig::new(1, 1, "gate-replay-oracle-search")?;
    let materializations = search_materializations(&corrupted);

    match check_sampled_search_replay_oracle(&materializations, &config) {
        Ok(_) => panic!("sampled corrupt materialization should fail the replay oracle"),
        Err(error) => Ok(error),
    }
}

fn search_materializations(
    corpus: &[ReplayOracleMaterializedCase],
) -> Vec<ReplayOracleSearchMaterialization> {
    corpus
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, case)| ReplayOracleSearchMaterialization::new(index as u64, case))
        .collect()
}

fn assert_replay_oracle_excludes_observational_entries(
    _corpus: &[ReplayOracleMaterializedCase],
) -> Result<(), Box<dyn Error>> {
    let double = SimDouble;
    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.replay-oracle",
        "nodes=observation\nseed=7",
    );
    let genesis = Configuration::genesis(scenario.clone());
    let checkpoint = Configuration {
        def: scenario,
        schedule: Schedule::empty().appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("observation/control"),
            value: 11,
        })),
    };
    let materialized =
        double.materialize_fat_checkpoint(String::from("cp-observation"), &genesis, &checkpoint)?;
    let mut with_extra_observation = materialized.clone();
    with_extra_observation
        .observational_entries
        .push(String::from("host-observation:ignored"));

    assert_ne!(
        materialized.observational_entries,
        with_extra_observation.observational_entries
    );
    assert_eq!(
        double.replay_case(&materialized)?,
        double.replay_case(&with_extra_observation)?
    );
    let expected_log = vec![
        crucible::test_support::condition_payload_entry_for_test(
            0,
            VirtualTime { ticks: 0 },
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("observation/control"),
                value: 11,
            })),
        ),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            VirtualTime { ticks: 1 },
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ];
    let reproduced_log = vec![
        crucible::test_support::condition_payload_entry_for_test(
            0,
            VirtualTime { ticks: 0 },
            SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
                "host-observation:ignored",
                EventLevel::Debug,
                std::collections::BTreeMap::new(),
            )),
        ),
        crucible::test_support::condition_payload_entry_for_test(
            1,
            VirtualTime { ticks: 0 },
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("observation/control"),
                value: 11,
            })),
        ),
        crucible::test_support::condition_boundary_entry_for_test(
            2,
            VirtualTime { ticks: 1 },
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ];
    let comparison = compare_event_log_determinism(&expected_log, &reproduced_log);

    assert!(comparison.passes());
    assert_eq!(
        comparison.expected().canonical_bytes(),
        comparison.reproduced().canonical_bytes()
    );
    Ok(())
}

fn assert_replay_oracle_rejects_corrupt_configuration_metadata(
    corpus: &[ReplayOracleMaterializedCase],
) -> Result<ReplayOracleMismatch, Box<dyn Error>> {
    let mut corrupted = corpus.to_vec();
    if let Some(case) = corrupted.get_mut(1) {
        case.fat_configuration_hash = hash_bytes(ContentHash::from_canonical_material(
            "crucible.test.replay-oracle.corrupt-config",
            "cp-1",
        ));
    }

    match check_materialized_replay_oracle(&corrupted) {
        Ok(()) => panic!("corrupt materialized configuration hash should fail the replay oracle"),
        Err(mismatch) => Ok(mismatch),
    }
}

fn assert_replay_oracle_rejects_corrupt_schedule_delta_metadata(
    corpus: &[ReplayOracleMaterializedCase],
) -> Result<ReplayOracleMismatch, Box<dyn Error>> {
    let mut corrupted = corpus.to_vec();
    if let Some(case) = corrupted.get_mut(2) {
        case.fat_schedule_delta_hash = hash_bytes(ContentHash::from_canonical_material(
            "crucible.test.replay-oracle.corrupt-delta",
            "cp-2",
        ));
    }

    match check_materialized_replay_oracle(&corrupted) {
        Ok(()) => panic!("corrupt materialized schedule delta should fail the replay oracle"),
        Err(mismatch) => Ok(mismatch),
    }
}

fn assert_replay_oracle_reports_first_mismatch(
    corpus: &[ReplayOracleMaterializedCase],
) -> Result<ReplayOracleMismatch, Box<dyn Error>> {
    let mut corrupted = corpus.to_vec();
    if let Some(case) = corrupted.get_mut(1) {
        case.fat_hash = hash_bytes(ContentHash::from_canonical_material(
            "crucible.test.replay-oracle.corrupt-fat",
            "cp-1",
        ));
    }

    match check_materialized_replay_oracle(&corrupted) {
        Ok(()) => panic!("corrupt materialized checkpoint should fail the replay oracle"),
        Err(mismatch) => Ok(mismatch),
    }
}

fn assert_twice_reduce_canonical_digest(
    scenario: &ScenarioDef,
    schedule: &Schedule,
) -> Result<State, Box<dyn Error>> {
    let first = reduce(scenario, schedule)?;
    let second = reduce(scenario, schedule)?;
    assert_eq!(first, second);
    Ok(first)
}

fn schedule_delta(ancestor: &Schedule, schedule: &Schedule) -> Result<Schedule, Box<dyn Error>> {
    let prefix = schedule.prefix(ancestor.len())?;
    assert_eq!(prefix, *ancestor);

    let mut delta = Schedule::empty();
    for decision in &schedule.decisions()[ancestor.len()..] {
        delta = delta.appended(decision.clone());
    }
    Ok(delta)
}

fn replay_schedule(ancestor: &Schedule, delta: &Schedule) -> Schedule {
    let mut schedule = ancestor.clone();
    for decision in delta.decisions() {
        schedule = schedule.appended(decision.clone());
    }
    schedule
}

fn rng_decision(stream: &str, value: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name(stream),
        value,
    })
}

fn baked_with_search_frontier_choices(
    world: &World,
    decisions: Vec<Decision>,
) -> Result<GenesisCheckpoint, Box<dyn Error>> {
    let mut baked = bake(world)?;
    baked.checkpoint = checkpoint_with_search_frontier_choices(baked.checkpoint, decisions);
    Ok(baked)
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

fn materialized_node_blobs(
    ancestor_hash: ContentHash,
    schedule_delta: &Schedule,
    state: &State,
) -> std::collections::BTreeMap<NodeId, NodeBlobRef> {
    let delta_hash = ContentHash::from_canonical_material(
        "crucible.test.replay-oracle.node-blob.delta",
        &format!(
            "ancestor={}\ndelta={}",
            hash_hex(ancestor_hash),
            hash_hex(schedule_delta.content_hash())
        ),
    );
    std::collections::BTreeMap::from([(
        oracle_node_id(),
        NodeBlobRef::cow_delta(ancestor_hash, delta_hash, state.id),
    )])
}

fn oracle_node_id() -> NodeId {
    NodeId {
        name: String::from("oracle"),
    }
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

fn test_double_checkpoint_hash(
    checkpoint_id: &str,
    configuration: &Configuration,
    ancestor_hash: ContentHash,
    schedule_delta: &Schedule,
    state: &State,
) -> ContentHash {
    let material = format!(
        "checkpoint_id={checkpoint_id}\nkind=fat\nconfiguration={}\nancestor={}\ndelta={}\nstate={}\n",
        hash_hex(configuration.content_hash()),
        hash_hex(ancestor_hash),
        hash_hex(schedule_delta.content_hash()),
        hash_hex(state.id)
    );
    ContentHash::from_canonical_material("crucible.test.replay-oracle.fat-checkpoint", &material)
}

fn checkpoint_kind(kind: CheckpointKind) -> ReplayOracleCheckpointKind {
    match kind {
        CheckpointKind::Fat => ReplayOracleCheckpointKind::Fat,
        CheckpointKind::Thin => ReplayOracleCheckpointKind::Thin,
    }
}

fn hash_bytes(hash: ContentHash) -> Vec<u8> {
    hash.bytes.to_vec()
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

#[test]
fn gate_replay_oracle_is_sensitive_to_schedule_order() -> Result<(), Box<dyn Error>> {
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.replay-oracle", "nodes=a,b\nseed=99");
    let draw = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("scheduler/order"),
        value: 1,
    });
    let delivery = Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 1 },
        order: vec![event_key(1, 7)],
    });
    let first_order = Schedule::empty()
        .appended(draw.clone())
        .appended(delivery.clone());
    let second_order = Schedule::empty().appended(delivery).appended(draw);
    let genesis = Configuration::genesis(scenario.clone());
    let first_configuration = Configuration {
        def: scenario.clone(),
        schedule: first_order.clone(),
    };
    let double = SimDouble;
    let materialized = double.materialize_fat_checkpoint(
        String::from("cp-order"),
        &genesis,
        &first_configuration,
    )?;
    let wrong_order_case = double.replay_case_with_delta(&materialized, &second_order)?;

    assert_ne!(
        reduce(&scenario, &first_order)?,
        reduce(&scenario, &second_order)?
    );
    let mismatch = match check_materialized_replay_oracle(&[wrong_order_case]) {
        Ok(()) => panic!("wrong-order thin reconstruction should fail the replay oracle"),
        Err(mismatch) => mismatch,
    };

    assert_eq!(mismatch.checkpoint_id, "cp-order");

    Ok(())
}
