//! Checks the T-OBS-6 causal-subsequence determinism comparison.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    AppRandomDecision, Checkpoint, CheckpointKind, Configuration, ContentHash, Decision,
    EngineError, EventAttributeValue, EventDiagnosticPayload, EventLevel, EventLog, EventSource,
    Icount, MaterializedState, NodeId, RngDecision, RngStreamId, SchedulerEvaluationBoundaryKind,
    SchedulerEventLogEntry, SchedulerEventLogPayload, TemporalGraph, VirtualTime, World, bake,
    compare_event_log_determinism, event_log_causal_projection, step,
};

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn rng_entry(sequence: u64, ticks: u64, stream: &str, value: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name(stream),
            value,
        })),
    )
}

fn app_random_entry(
    sequence: u64,
    ticks: u64,
    node_name: &str,
    stream: &str,
    value: u64,
) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Decision(Decision::AppRandom(AppRandomDecision {
            node: node(node_name),
            stream: RngStreamId::from_name(stream),
            request_id: 1,
            width: 32,
            value,
        })),
    )
}

fn boundary_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn diagnostic_entry(
    sequence: u64,
    ticks: u64,
    name: &str,
    level: EventLevel,
    details: BTreeMap<String, EventAttributeValue>,
) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(name, level, details)),
    )
}

#[test]
fn causal_projection_renumbers_past_observational_interleaving() {
    let expected = vec![
        rng_entry(0, 1, "causal-projection-a", 11),
        rng_entry(1, 2, "causal-projection-b", 17),
    ];
    let reproduced = vec![
        diagnostic_entry(0, 0, "executor.poll", EventLevel::Debug, BTreeMap::new()),
        rng_entry(1, 1, "causal-projection-a", 11),
        diagnostic_entry(2, 1, "executor.poll", EventLevel::Trace, BTreeMap::new()),
        rng_entry(3, 2, "causal-projection-b", 17),
    ];

    let comparison = compare_event_log_determinism(&expected, &reproduced);

    assert_ne!(expected, reproduced);
    assert!(comparison.passes());
    assert_eq!(
        comparison.expected().canonical_bytes(),
        comparison.reproduced().canonical_bytes()
    );
    assert_eq!(
        comparison
            .expected()
            .entries()
            .iter()
            .map(|entry| entry.raw_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(
        comparison
            .reproduced()
            .entries()
            .iter()
            .map(|entry| entry.raw_index)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
    assert_eq!(
        comparison
            .reproduced()
            .entries()
            .iter()
            .map(|entry| entry.entry.sequence())
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
}

#[test]
fn causal_projection_bytes_differ_on_first_causal_payload_change() {
    let expected = vec![
        rng_entry(0, 1, "causal-projection-diff", 11),
        boundary_entry(1, 2),
    ];
    let reproduced = vec![
        rng_entry(0, 1, "causal-projection-diff", 12),
        boundary_entry(1, 2),
    ];

    let comparison = compare_event_log_determinism(&expected, &reproduced);
    let mismatch = comparison
        .mismatch()
        .expect("different causal payload should produce a mismatch");

    assert!(!comparison.passes());
    assert_ne!(
        comparison.expected().canonical_bytes(),
        comparison.reproduced().canonical_bytes()
    );
    assert_ne!(
        comparison.expected().content_hash(),
        comparison.reproduced().content_hash()
    );
    assert_eq!(mismatch.causal_index, 0);
    assert_eq!(mismatch.expected_raw_index, Some(0));
    assert_eq!(mismatch.reproduced_raw_index, Some(0));
}

#[test]
fn causal_mismatch_reports_first_differing_entry_coordinate() {
    let expected = vec![
        diagnostic_entry(0, 8, "before", EventLevel::Debug, BTreeMap::new()),
        app_random_entry(1, 9, "guest-a", "node-local-random", 31),
        boundary_entry(2, 10),
    ];
    let reproduced = vec![
        diagnostic_entry(0, 8, "before", EventLevel::Trace, BTreeMap::new()),
        app_random_entry(1, 9, "guest-a", "node-local-random", 32),
        boundary_entry(2, 10),
    ];

    let comparison = compare_event_log_determinism(&expected, &reproduced);
    let mismatch = comparison
        .mismatch()
        .expect("node-local causal payload change should produce a mismatch");
    let expected_location = mismatch
        .expected_location
        .as_ref()
        .expect("expected side should carry a causal divergence point");
    let reproduced_location = mismatch
        .reproduced_location
        .as_ref()
        .expect("reproduced side should carry a causal divergence point");

    assert!(!comparison.passes());
    assert_eq!(mismatch.causal_index, 0);
    assert_eq!(expected_location.raw_index, 1);
    assert_eq!(expected_location.at.node.as_ref(), Some(&node("guest-a")));
    assert_eq!(expected_location.at.icount, icount(9));
    assert_eq!(
        &expected_location.source,
        &EventSource::Guest {
            node: node("guest-a")
        }
    );
    assert_eq!(expected_location.kind.as_str(), "app_random");
    assert_eq!(mismatch.first_location(), Some(expected_location));
    assert_eq!(reproduced_location.raw_index, 1);
    assert_eq!(&reproduced_location.at, &expected_location.at);
    assert_eq!(&reproduced_location.source, &expected_location.source);
    assert_eq!(&reproduced_location.kind, &expected_location.kind);
}

#[test]
fn observational_verbosity_changes_do_not_change_causal_projection() {
    let mut quiet_details = BTreeMap::new();
    quiet_details.insert(String::from("polls"), EventAttributeValue::U64(1));
    let mut verbose_details = BTreeMap::new();
    verbose_details.insert(String::from("polls"), EventAttributeValue::U64(999));
    verbose_details.insert(
        String::from("worker"),
        EventAttributeValue::String(String::from("maximal")),
    );
    let quiet = vec![
        rng_entry(0, 4, "observational-verbosity", 21),
        diagnostic_entry(1, 4, "executor.poll", EventLevel::Info, quiet_details),
        boundary_entry(2, 5),
    ];
    let verbose = vec![
        diagnostic_entry(0, 4, "executor.poll", EventLevel::Trace, verbose_details),
        rng_entry(1, 4, "observational-verbosity", 21),
        boundary_entry(2, 5),
        diagnostic_entry(3, 5, "tracing.bridge", EventLevel::Error, BTreeMap::new()),
    ];

    let quiet_projection = event_log_causal_projection(&quiet);
    let verbose_projection = event_log_causal_projection(&verbose);

    assert_eq!(quiet_projection.len(), 2);
    assert_eq!(verbose_projection.len(), 2);
    assert_eq!(
        quiet_projection.canonical_bytes(),
        verbose_projection.canonical_bytes()
    );
    assert!(compare_event_log_determinism(&quiet, &verbose).passes());
}

#[test]
fn replay_oracle_rejects_fat_checkpoint_with_inconsistent_event_log_offset() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.event-log-determinism",
        "replay-oracle-offset",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let child = step(
        &genesis,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("event-log-offset"),
            value: 31,
        }),
    );
    let mut log = EventLog::new();
    let append = log
        .append_entries(vec![boundary_entry(0, 7)])
        .expect("event-log append should produce an offset");
    let mut checkpoint = Checkpoint::from_recorded_configuration(
        &child,
        Some(&genesis),
        time(7),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("fat checkpoint should build");
    let state = checkpoint
        .state
        .clone()
        .expect("fat checkpoint should carry materialized state");
    let state = MaterializedState::from_components(
        state.vm_snapshots,
        state.device_overlays,
        state.scheduler,
        state.decision_rng,
        append.offset,
    );
    checkpoint = checkpoint.with_materialized_state(Some(state));
    let graph = TemporalGraph::empty()
        .with_baked_genesis(&scenario, bake(&world).expect("baked genesis should build"))
        .expect("baked genesis should seed graph");

    let error = graph
        .replay_checkpoint(&child, &checkpoint)
        .expect_err("replay oracle should reject inconsistent event-log offset");

    match error {
        EngineError::ReplayOracleMismatch {
            checkpoint,
            expected,
            actual,
        } => {
            assert_eq!(checkpoint, child.id());
            assert_ne!(expected, actual);
        }
        other => panic!("unexpected replay-oracle error: {other:?}"),
    }
}
