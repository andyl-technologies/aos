//! Checks the execution-model side of `gate:single-vm-fingerprint`.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, DecisionRecorder, ExecutionFingerprint,
    FaultId, FaultRateBasisPoints, GenesisCheckpoint, NodeId, RngStreamId, RuntimeState,
    ScenarioDef, Seed, TemporalGraph, VirtualTime, instantiate,
};
use crucible_harness::adversarial::{
    HostAdversaryProfile, canonical_host_adversary_matrix, run_profiled_tasks,
};

#[test]
fn gate_single_vm_fingerprint_model_determinism_survives_adversarial_host_profiles() {
    let scenario = generated_scenario(0x1800);
    let fixtures = same_configuration_fixtures(&scenario);
    let profiles = canonical_host_adversary_matrix();
    let Some((baseline_profile, candidate_profiles)) = profiles.split_first() else {
        panic!("adversarial host matrix must contain a baseline profile");
    };
    let baseline =
        run_model_determinism_under_host_profile(&scenario, &fixtures, *baseline_profile);

    for profile in candidate_profiles {
        let candidate = run_model_determinism_under_host_profile(&scenario, &fixtures, *profile);
        assert_eq!(candidate, baseline, "profile {:?} diverged", profile.name);
    }
}

#[test]
fn gate_single_vm_fingerprint_same_configuration_twice_validates_start_resume_fork_and_snapshot_completeness()
 {
    let scenario = generated_scenario(0x1700);
    let witnesses = same_configuration_fixtures(&scenario)
        .iter()
        .map(|fixture| validate_same_configuration_fixture(&scenario, fixture))
        .collect::<Vec<_>>();

    let start = witness(&witnesses, SameConfigurationProbe::Start);
    let resume = witness(&witnesses, SameConfigurationProbe::Resume);
    let fork = witness(&witnesses, SameConfigurationProbe::Fork);
    let snapshot_completeness = witness(&witnesses, SameConfigurationProbe::SnapshotCompleteness);

    assert_eq!(
        start.configuration,
        Configuration::genesis(scenario.clone()).id()
    );
    assert_eq!(
        resume.configuration,
        representative_configuration(scenario.clone(), 8).id()
    );
    assert_eq!(
        fork.configuration,
        representative_configuration(scenario.clone(), 4).id()
    );
    assert_eq!(snapshot_completeness.configuration, resume.configuration);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct SameConfigurationFixture {
    probe: SameConfigurationProbe,
    configuration: Configuration,
    first_path: InstantiatePath,
    second_path: InstantiatePath,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InstantiatePath {
    BakedGenesis,
    ExactSnapshot,
    AncestorReplay { ancestor: Configuration },
    SavedCheckpoint { ancestor: Configuration },
}

fn run_model_determinism_under_host_profile(
    scenario: &ScenarioDef,
    fixtures: &[SameConfigurationFixture],
    profile: HostAdversaryProfile,
) -> Vec<SameConfigurationFingerprintWitness> {
    let mut results = match run_profiled_tasks(profile, fixtures.len(), |task| {
        let fixture = &fixtures[task.index];
        validate_same_configuration_fixture(scenario, fixture)
    }) {
        Ok(results) => results,
        Err(error) => panic!(
            "model adversarial host profile {} should execute: {error}",
            profile.name
        ),
    };
    results.sort_by_key(|witness| (witness.probe, witness.configuration.bytes));
    results
}

fn same_configuration_fixtures(scenario: &ScenarioDef) -> Vec<SameConfigurationFixture> {
    let genesis = Configuration::genesis(scenario.clone());
    let target = representative_configuration(scenario.clone(), 8);
    let run_to_prefix = representative_configuration(scenario.clone(), 4);
    let fork_prefix = configuration_prefix(&target, run_to_prefix.schedule.len());

    assert_eq!(fork_prefix, run_to_prefix);

    vec![
        SameConfigurationFixture {
            probe: SameConfigurationProbe::Start,
            configuration: genesis,
            first_path: InstantiatePath::BakedGenesis,
            second_path: InstantiatePath::BakedGenesis,
        },
        SameConfigurationFixture {
            probe: SameConfigurationProbe::Resume,
            configuration: target.clone(),
            first_path: InstantiatePath::ExactSnapshot,
            second_path: InstantiatePath::AncestorReplay {
                ancestor: fork_prefix.clone(),
            },
        },
        SameConfigurationFixture {
            probe: SameConfigurationProbe::Fork,
            configuration: fork_prefix.clone(),
            first_path: InstantiatePath::ExactSnapshot,
            second_path: InstantiatePath::BakedGenesis,
        },
        SameConfigurationFixture {
            probe: SameConfigurationProbe::SnapshotCompleteness,
            configuration: target,
            first_path: InstantiatePath::SavedCheckpoint {
                ancestor: fork_prefix.clone(),
            },
            second_path: InstantiatePath::AncestorReplay {
                ancestor: fork_prefix,
            },
        },
    ]
}

fn validate_same_configuration_fixture(
    scenario: &ScenarioDef,
    fixture: &SameConfigurationFixture,
) -> SameConfigurationFingerprintWitness {
    validate_same_configuration_twice(
        fixture.probe,
        &fixture.configuration,
        graph_for_path(scenario, &fixture.configuration, &fixture.first_path),
        graph_for_path(scenario, &fixture.configuration, &fixture.second_path),
    )
}

fn graph_for_path(
    scenario: &ScenarioDef,
    configuration: &Configuration,
    path: &InstantiatePath,
) -> TemporalGraph {
    match path {
        InstantiatePath::BakedGenesis => graph_with_baked_genesis(scenario),
        InstantiatePath::ExactSnapshot => graph_with_exact_snapshot_only(scenario, configuration),
        InstantiatePath::AncestorReplay { ancestor } => {
            graph_with_ancestor_snapshot_only(scenario, ancestor)
        }
        InstantiatePath::SavedCheckpoint { ancestor } => {
            graph_with_saved_checkpoint_exact_only(scenario, configuration, ancestor)
        }
    }
}

fn witness(
    witnesses: &[SameConfigurationFingerprintWitness],
    probe: SameConfigurationProbe,
) -> &SameConfigurationFingerprintWitness {
    match witnesses.iter().find(|witness| witness.probe == probe) {
        Some(witness) => witness,
        None => panic!("same-configuration probe witness should be present"),
    }
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
    let mut recorder = DecisionRecorder::new(Configuration::genesis(scenario));
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
            let _fired = recorder.decide_fault_basis_points(
                VirtualTime { ticks: index + 1 },
                FaultId {
                    name: format!("link-a-b/drop-{index}"),
                },
                stream("node-b/faults"),
                FaultRateBasisPoints::from_basis_points(5_000).expect("test rate should be valid"),
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
    let checkpoint = Checkpoint::from_recorded_configuration(
        &genesis,
        None,
        VirtualTime::default(),
        std::collections::BTreeMap::new(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("genesis checkpoint should be recorded-shaped: {error}"));
    GenesisCheckpoint { checkpoint }
}

fn fat_checkpoint_for(configuration: &Configuration) -> Checkpoint {
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
        std::collections::BTreeMap::new(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("fat checkpoint should be recorded-shaped: {error}"))
}

fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.gate.single-vm-fingerprint.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn stream(name: &str) -> RngStreamId {
    RngStreamId::from_name(name)
}
