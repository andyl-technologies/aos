//! Checks the execution-model side of `gate:single-vm-fingerprint`.

#![forbid(unsafe_code)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, DecisionRecorder, ExecutionFingerprint,
    FaultId, GenesisCheckpoint, NodeId, RngStreamId, RuntimeState, ScenarioDef, TemporalGraph,
    VirtualTime, instantiate,
};

#[test]
fn gate_single_vm_fingerprint_same_configuration_twice_validates_start_resume_fork_and_snapshot_completeness()
 {
    let scenario = generated_scenario(0x1700);
    let genesis = Configuration::genesis(scenario.clone());
    let target = representative_configuration(scenario.clone(), 8);
    let run_to_prefix = representative_configuration(scenario.clone(), 4);
    let fork_prefix = configuration_prefix(&target, run_to_prefix.schedule.len());

    assert_eq!(fork_prefix, run_to_prefix);

    let start = validate_same_configuration_twice(
        SameConfigurationProbe::Start,
        &genesis,
        graph_with_baked_genesis(&scenario),
        graph_with_baked_genesis(&scenario),
    );
    let resume = validate_same_configuration_twice(
        SameConfigurationProbe::Resume,
        &target,
        graph_with_exact_snapshot_only(&scenario, &target),
        graph_with_ancestor_snapshot_only(&scenario, &fork_prefix),
    );
    let fork = validate_same_configuration_twice(
        SameConfigurationProbe::Fork,
        &fork_prefix,
        graph_with_exact_snapshot_only(&scenario, &run_to_prefix),
        graph_with_baked_genesis(&scenario),
    );
    let saved_checkpoint_graph =
        graph_with_saved_checkpoint_exact_only(&scenario, &target, &fork_prefix);
    let snapshot_completeness = validate_same_configuration_twice(
        SameConfigurationProbe::SnapshotCompleteness,
        &target,
        saved_checkpoint_graph,
        graph_with_ancestor_snapshot_only(&scenario, &fork_prefix),
    );

    assert_eq!(start.configuration, genesis.id());
    assert_eq!(resume.configuration, target.id());
    assert_eq!(fork.configuration, fork_prefix.id());
    assert_eq!(snapshot_completeness.configuration, target.id());
    assert_eq!(resume.fingerprint, snapshot_completeness.fingerprint);
    assert_ne!(start.fingerprint, resume.fingerprint);
    assert_ne!(fork.fingerprint, resume.fingerprint);
}

#[test]
fn gate_single_vm_fingerprint_rejects_different_configuration_fingerprints() {
    let scenario = generated_scenario(0x1701);
    let shorter = representative_configuration(scenario.clone(), 3);
    let longer = representative_configuration(scenario.clone(), 4);
    let shorter_realization = instantiate_for_probe(&graph_with_baked_genesis(&scenario), &shorter);
    let longer_realization = instantiate_for_probe(&graph_with_baked_genesis(&scenario), &longer);

    assert_ne!(shorter.id(), longer.id());
    assert_ne!(
        shorter_realization.fingerprint,
        longer_realization.fingerprint
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SameConfigurationProbe {
    Start,
    Resume,
    Fork,
    SnapshotCompleteness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SameConfigurationFingerprintWitness {
    probe: SameConfigurationProbe,
    configuration: ContentHash,
    fingerprint: ExecutionFingerprint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RealizedConfiguration {
    runtime: RuntimeState,
    fingerprint: ExecutionFingerprint,
}

fn validate_same_configuration_twice(
    probe: SameConfigurationProbe,
    configuration: &Configuration,
    first_graph: TemporalGraph,
    second_graph: TemporalGraph,
) -> SameConfigurationFingerprintWitness {
    let first = instantiate_for_probe(&first_graph, configuration);
    let second = instantiate_for_probe(&second_graph, configuration);

    assert_eq!(first.runtime.configuration, configuration.id());
    assert_eq!(second.runtime.configuration, configuration.id());
    assert_eq!(first.runtime, second.runtime);
    assert_eq!(first.fingerprint, second.fingerprint);

    SameConfigurationFingerprintWitness {
        probe,
        configuration: configuration.id(),
        fingerprint: first.fingerprint,
    }
}

fn instantiate_for_probe(
    graph: &TemporalGraph,
    configuration: &Configuration,
) -> RealizedConfiguration {
    let runtime = match instantiate(graph, configuration) {
        Ok(runtime) => runtime,
        Err(error) => panic!("same-configuration fingerprint probe should instantiate: {error}"),
    };
    let fingerprint = ExecutionFingerprint { hash: runtime.id };

    RealizedConfiguration {
        runtime,
        fingerprint,
    }
}

fn graph_with_baked_genesis(scenario: &ScenarioDef) -> TemporalGraph {
    match TemporalGraph::empty().with_baked_genesis(scenario, genesis_checkpoint(scenario)) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    }
}

fn graph_with_exact_snapshot_only(
    scenario: &ScenarioDef,
    configuration: &Configuration,
) -> TemporalGraph {
    let graph = match TemporalGraph::empty()
        .with_cached_snapshot(configuration, fat_checkpoint_for(configuration))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid exact snapshot should register: {error}"),
    };
    assert!(graph.genesis_snapshot(scenario).is_none());
    graph
}

fn graph_with_ancestor_snapshot_only(
    scenario: &ScenarioDef,
    ancestor: &Configuration,
) -> TemporalGraph {
    graph_with_exact_snapshot_only(scenario, ancestor)
}

fn graph_with_saved_checkpoint_exact_only(
    scenario: &ScenarioDef,
    configuration: &Configuration,
    ancestor: &Configuration,
) -> TemporalGraph {
    let mut source_graph = graph_with_ancestor_snapshot_only(scenario, ancestor);
    let checkpoint = match source_graph.save_checkpoint(configuration) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("same-configuration probe should save checkpoint: {error}"),
    };
    let replay_check = match source_graph.replay_checkpoint(configuration, &checkpoint) {
        Ok(check) => check,
        Err(error) => panic!("saved checkpoint should match thin replay: {error}"),
    };
    assert_eq!(replay_check.fat_checkpoint, replay_check.thin_checkpoint);
    assert_eq!(replay_check.configuration, configuration.id());

    let graph = match TemporalGraph::empty().with_cached_snapshot(configuration, checkpoint) {
        Ok(graph) => graph,
        Err(error) => panic!("saved exact checkpoint should register: {error}"),
    };
    assert!(graph.genesis_snapshot(scenario).is_none());
    graph
}

fn representative_configuration(scenario: ScenarioDef, decisions: u64) -> Configuration {
    let mut recorder = DecisionRecorder::new(Configuration::genesis(scenario), 0x0010_0017);
    for index in 0..decisions {
        record_representative_decision(&mut recorder, index);
    }
    recorder.into_configuration()
}

fn configuration_prefix(configuration: &Configuration, prefix_len: usize) -> Configuration {
    let schedule = match configuration.schedule.prefix(prefix_len) {
        Ok(schedule) => schedule,
        Err(error) => panic!("valid representative prefix should construct: {error}"),
    };
    Configuration {
        def: configuration.def.clone(),
        schedule,
    }
}

fn record_representative_decision(recorder: &mut DecisionRecorder, index: u64) {
    match index % 3 {
        0 => {
            let _value = recorder.draw_u64(stream(&format!("node-a/faults/{index}")));
        }
        1 => {
            let _fired = recorder.decide_fault(
                VirtualTime { ticks: index + 1 },
                FaultId {
                    name: format!("link-a-b/drop-{index}"),
                },
                stream("node-b/faults"),
                u64::MAX / 2,
            );
        }
        _ => match recorder.serve_app_random(node("node-a"), stream("node-a/app-random"), 16) {
            Ok(_value) => {}
            Err(error) => panic!("representative app-random decision should record: {error}"),
        },
    }
}

fn genesis_checkpoint(scenario: &ScenarioDef) -> GenesisCheckpoint {
    let genesis = Configuration::genesis(scenario.clone());
    GenesisCheckpoint {
        checkpoint: Checkpoint::new(
            ContentHash::from_canonical_material(
                "crucible.gate.single-vm-fingerprint.genesis",
                &format!("{:?}", genesis.id().bytes),
            ),
            genesis.id(),
            CheckpointKind::Fat,
        ),
    }
}

fn fat_checkpoint_for(configuration: &Configuration) -> Checkpoint {
    Checkpoint::new(
        ContentHash::from_canonical_material(
            "crucible.gate.single-vm-fingerprint.snapshot",
            &format!("{:?}", configuration.id().bytes),
        ),
        configuration.id(),
        CheckpointKind::Fat,
    )
}

fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material(
        "crucible.gate.single-vm-fingerprint.scenario",
        &format!("seed={seed}"),
    )
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn stream(name: &str) -> RngStreamId {
    RngStreamId {
        name: String::from(name),
    }
}
