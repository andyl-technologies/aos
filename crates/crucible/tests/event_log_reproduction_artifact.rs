//! Checks the T-OBS-10 event-log reproduction-artifact contract.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, DagStore, Decision, EngineError,
    EventDiagnosticPayload, EventLevel, EventLog, MaterializedState, MemoryDagStore, Plan,
    Properties, ReproductionArtifact, ReproductionReplay, RngDecision, RngStreamId,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, SchedulerEventLogPayload, Seed,
    TemporalGraph, VirtualTime, World, bake, event_log_causal_projection, step,
};

fn world(_tag: &str) -> World {
    World::from_nodes(Vec::new()).expect("empty reproduction-artifact world should build")
}

fn reproduction_scenario(world: &World) -> Result<crucible::ScenarioDefForm, EngineError> {
    crucible::ScenarioDefForm::from_components(
        world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(0x0010_0030),
    )
}

fn replay_decision(value: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("event-log/reproduction-artifact"),
        value,
    })
}

fn decision_entry(sequence: u64, ticks: u64, value: u64) -> SchedulerEventLogEntry {
    decision_payload_entry(sequence, ticks, replay_decision(value))
}

fn decision_payload_entry(sequence: u64, ticks: u64, decision: Decision) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        VirtualTime { ticks },
        SchedulerEventLogPayload::Decision(decision),
    )
}

fn boundary_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        VirtualTime { ticks },
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn artifact_decision(artifact: &ReproductionArtifact) -> Decision {
    artifact
        .schedule()
        .decisions()
        .first()
        .expect("test artifact should carry one replay decision")
        .clone()
}

fn recorded_log_from_artifact(artifact: &ReproductionArtifact) -> Vec<SchedulerEventLogEntry> {
    vec![
        decision_payload_entry(0, 0, artifact_decision(artifact)),
        boundary_entry(1, 9),
    ]
}

fn replay_log_from_artifact(
    artifact: &ReproductionArtifact,
    _replay: &ReproductionReplay,
) -> Result<Vec<SchedulerEventLogEntry>, EngineError> {
    Ok(vec![
        diagnostic_entry(0, 0, "host-observation"),
        decision_payload_entry(1, 0, artifact_decision(artifact)),
        boundary_entry(2, 9),
    ])
}

fn corrupted_replay_log_from_artifact(
    _artifact: &ReproductionArtifact,
    _replay: &ReproductionReplay,
) -> Result<Vec<SchedulerEventLogEntry>, EngineError> {
    Ok(vec![decision_entry(0, 0, 24), boundary_entry(1, 9)])
}

fn diagnostic_entry(sequence: u64, ticks: u64, name: &str) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        VirtualTime { ticks },
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            name,
            EventLevel::Debug,
            BTreeMap::new(),
        )),
    )
}

#[test]
fn reproduction_artifact_replay_reconstructs_byte_identical_causal_log_from_metadata() {
    let world = world("causal-log-metadata");
    let scenario = reproduction_scenario(&world).expect("scenario form should build");
    let schedule = crucible::Schedule::empty().appended(replay_decision(17));
    let artifact = ReproductionArtifact::capture(&scenario, &schedule)
        .expect("reproduction artifact should reduce");
    let original_log = recorded_log_from_artifact(&artifact);
    let mut stored_log = EventLog::new();
    let append = stored_log
        .append_entries(original_log.clone())
        .expect("original event log should append");
    let segment = append
        .segment_hash
        .expect("non-empty event log append should have a segment key");
    let debug_artifact = artifact.event_log_debug_artifact_with_segments(
        append.offset,
        &original_log,
        Some(segment),
    );

    let replay = artifact
        .verify_event_log_replay_with(&debug_artifact, replay_log_from_artifact)
        .expect("artifact replay should produce an event-log comparison");

    assert_eq!(debug_artifact.reproduction_artifact, artifact.id());
    assert_eq!(debug_artifact.fork_point, append.offset);
    assert_eq!(debug_artifact.shared_store_segments, vec![segment]);
    assert_eq!(
        debug_artifact.causal_subsequence,
        event_log_causal_projection(&original_log).content_hash()
    );
    assert!(replay.passes());
    assert_eq!(replay.reduction.artifact, artifact.id());
    assert_eq!(
        replay.expected_causal_subsequence,
        replay.reproduced_causal_subsequence
    );
}

#[test]
fn reproduction_artifact_replay_rejects_causal_log_drift_without_original_full_log() {
    let world = world("causal-log-drift");
    let scenario = reproduction_scenario(&world).expect("scenario form should build");
    let schedule = crucible::Schedule::empty().appended(replay_decision(23));
    let artifact = ReproductionArtifact::capture(&scenario, &schedule)
        .expect("reproduction artifact should reduce");
    let original_log = recorded_log_from_artifact(&artifact);
    let debug_artifact =
        artifact.event_log_debug_artifact(crucible::EventLogOffset::default(), &original_log);

    let replay = artifact
        .verify_event_log_replay_with(&debug_artifact, corrupted_replay_log_from_artifact)
        .expect("artifact replay should produce a mismatch report");

    assert!(!replay.passes());
    assert_ne!(
        replay.expected_causal_subsequence,
        replay.reproduced_causal_subsequence
    );
    assert_eq!(
        replay.expected_causal_events,
        replay.reproduced_causal_events
    );
}

#[test]
fn dag_reproduction_artifact_references_shared_event_log_segments_by_content_key() {
    let world = world("shared-store-segment");
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let child = step(&genesis, replay_decision(31));
    let shared = Arc::new(MemoryDagStore::new());
    let store: Arc<dyn DagStore> = shared.clone();
    let mut log = EventLog::with_segment_store(store);
    let first = log
        .append_entries(vec![boundary_entry(0, 11)])
        .expect("first event-log segment should append into shared store");
    let first_segment = first
        .segment_hash
        .expect("first event-log append should have a segment key");
    let second = log
        .append_entries(vec![boundary_entry(first.offset.events, 12)])
        .expect("second event-log segment should append into shared store");
    let second_segment = second
        .segment_hash
        .expect("second event-log append should have a segment key");
    let base_checkpoint = Checkpoint::from_recorded_configuration(
        &child,
        Some(&genesis),
        VirtualTime { ticks: 11 },
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("fat checkpoint should be recorded-shaped");
    let base_state = base_checkpoint
        .state
        .clone()
        .expect("fat checkpoint should carry materialized state");
    let state = MaterializedState::from_components_with_event_log_segments(
        base_state.vm_snapshots,
        base_state.device_overlays,
        base_state.scheduler,
        base_state.decision_rng,
        second.offset,
        [first_segment, second_segment],
    );
    let checkpoint = base_checkpoint.with_materialized_state(Some(state));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&scenario, bake(&world).expect("baked genesis should build"))
        .expect("baked genesis should seed graph");
    graph
        .cache_snapshot(&child, checkpoint)
        .expect("fat checkpoint should cache");

    let keys = graph
        .persist_checkpoint_closure(shared.as_ref(), &child)
        .expect("checkpoint closure should persist with event-log segment refs");

    let expected_segments = BTreeSet::from([first_segment, second_segment]);
    assert_eq!(
        keys.reproduction_artifact
            .event_log_segments
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        expected_segments
    );
    assert!(
        keys.reproduction_artifact
            .store_keys()
            .is_superset(&expected_segments)
    );
    assert_eq!(
        shared
            .get(&first_segment)
            .expect("shared store should retain first raw event-log segment bytes"),
        first.segment_bytes
    );
    assert_eq!(
        shared
            .get(&second_segment)
            .expect("shared store should retain second raw event-log segment bytes"),
        second.segment_bytes
    );
}
