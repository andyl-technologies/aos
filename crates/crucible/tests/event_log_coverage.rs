//! Checks T-OBS-9 coverage projection and fingerprinting from the unified event log.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, Decision, EventDiagnosticPayload,
    EventLevel, EventLogCoverageObservation, EventSource, Icount, MarkerId, MaterializationPolicy,
    MaterializationTrigger, MemoryDagStore, NodeId, ObservableEvent, RngDecision, RngStreamId,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, SchedulerEventLogPayload,
    TemporalGraph, VirtualTime, World, bake, compare_event_log_determinism,
    coverage_fingerprint_from_event_log, event_log_coverage_projection, step,
};

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn observation_entry(sequence: u64, event: &ObservableEvent) -> SchedulerEventLogEntry {
    crucible::test_support::condition_observation_entry_for_test(sequence, event)
}

fn rng_entry(sequence: u64, ticks: u64, value: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("coverage-projection"),
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

fn diagnostic_entry(sequence: u64, ticks: u64, name: &str) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            name,
            EventLevel::Debug,
            std::collections::BTreeMap::new(),
        )),
    )
}

#[test]
fn coverage_projection_reads_basic_blocks_and_named_markers_from_one_log() {
    let block = ObservableEvent::coverage_block(icount(11), node("guest-a"), 0x4000, 0x20);
    let named = ObservableEvent::coverage_marker(icount(12), node("guest-a"), marker("joined"));
    let duplicate_block =
        ObservableEvent::coverage_block(icount(13), node("guest-a"), 0x4000, 0x20);
    let log = vec![
        observation_entry(0, &block),
        diagnostic_entry(1, 11, "scheduler.poll"),
        observation_entry(2, &named),
        observation_entry(3, &duplicate_block),
    ];

    let projection = event_log_coverage_projection(&log);
    let deduped_projection = event_log_coverage_projection(&[
        observation_entry(0, &block),
        observation_entry(1, &named),
    ]);

    assert_eq!(projection.len(), 3);
    assert_eq!(projection.entries()[0].raw_index, 0);
    assert_eq!(
        projection.entries()[0].at.node.as_ref(),
        Some(&node("guest-a"))
    );
    assert_eq!(projection.entries()[0].at.icount, icount(11));
    assert_eq!(&projection.entries()[0].source, &EventSource::Engine);
    assert_eq!(
        &projection.entries()[0].observation,
        &EventLogCoverageObservation::BasicBlock {
            node: node("guest-a"),
            guest_pc: 0x4000,
            block_len: 0x20
        }
    );
    assert_eq!(projection.entries()[1].raw_index, 2);
    assert_eq!(
        projection.entries()[1].at.node.as_ref(),
        Some(&node("guest-a"))
    );
    assert_eq!(projection.entries()[1].at.icount, icount(12));
    assert_eq!(
        &projection.entries()[1].source,
        &EventSource::Guest {
            node: node("guest-a")
        }
    );
    assert_eq!(
        &projection.entries()[1].observation,
        &EventLogCoverageObservation::Named {
            node: node("guest-a"),
            marker: marker("joined")
        }
    );
    assert_ne!(projection.content_hash(), ContentHash::default());
    assert_eq!(projection.content_hash(), deduped_projection.content_hash());
    assert_eq!(
        coverage_fingerprint_from_event_log(&log),
        projection.content_hash()
    );
}

#[test]
fn coverage_entries_project_as_observational_coverage_payloads() {
    let block = ObservableEvent::coverage_block(icount(21), node("guest-b"), 0x5000, 0x30);
    let named = ObservableEvent::coverage_marker(icount(22), node("guest-b"), marker("ready"));
    let block_entry = observation_entry(0, &block);
    let named_entry = observation_entry(1, &named);

    assert_eq!(block_entry.event_payload().kind(), "coverage");
    assert_eq!(
        block_entry.event_payload().string("kind"),
        Some("basic_block")
    );
    assert_eq!(block_entry.event_payload().u64("guest_pc"), Some(0x5000));
    assert_eq!(block_entry.event_payload().u64("block_len"), Some(0x30));
    assert_eq!(
        block_entry.event_payload().string("block"),
        Some("0x5000+0x30")
    );
    assert_eq!(block_entry.class(), crucible::EventClass::Observational);

    assert_eq!(named_entry.event_payload().kind(), "coverage");
    assert_eq!(named_entry.event_payload().string("kind"), Some("named"));
    assert_eq!(named_entry.event_payload().string("id"), Some("ready"));
    assert_eq!(
        named_entry.event_payload().icount("retired_icount"),
        Some(icount(22))
    );
    assert_eq!(named_entry.class(), crucible::EventClass::Observational);
}

#[test]
fn coverage_fingerprint_is_checkpoint_feedback_from_log_projection() {
    let block = ObservableEvent::coverage_block(icount(31), node("guest-c"), 0x6000, 0x10);
    let named = ObservableEvent::coverage_marker(icount(32), node("guest-c"), marker("phase-2"));
    let log = vec![observation_entry(0, &block), observation_entry(1, &named)];
    let fingerprint = coverage_fingerprint_from_event_log(&log);
    let checkpoint = Checkpoint::new(
        ContentHash::from_canonical_material("crucible.test.coverage-checkpoint", "id"),
        ContentHash::from_canonical_material("crucible.test.coverage-checkpoint", "config"),
        CheckpointKind::Thin,
    );
    let checkpoint_id = checkpoint.id;
    let checkpoint = checkpoint.with_coverage_fingerprint(fingerprint);

    assert_ne!(fingerprint, ContentHash::default());
    assert_eq!(checkpoint.id, checkpoint_id);
    assert_eq!(checkpoint.coverage_fingerprint, fingerprint);
    assert_eq!(
        coverage_fingerprint_from_event_log(&[]),
        ContentHash::default()
    );
}

#[test]
fn graph_cache_snapshot_stamps_checkpoint_coverage_from_event_log_projection() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.event-log-coverage.world",
        "graph-cache-stamping",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario);
    let child = step(
        &genesis,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("graph-cache-stamping"),
            value: 99,
        }),
    );
    let coverage_log = vec![
        observation_entry(
            0,
            &ObservableEvent::coverage_block(icount(41), node("guest-e"), 0x8000, 0x20),
        ),
        observation_entry(
            1,
            &ObservableEvent::coverage_marker(icount(42), node("guest-e"), marker("steady")),
        ),
    ];
    let checkpoint = Checkpoint::from_recorded_configuration(
        &child,
        Some(&genesis),
        time(42),
        std::collections::BTreeMap::new(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    )
    .expect("fat checkpoint should build");
    let fingerprint = coverage_fingerprint_from_event_log(&coverage_log);
    let baked = bake(&world).expect("baked genesis should build");
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&genesis.def, baked)
        .expect("baked genesis should seed graph");

    graph
        .cache_snapshot_with_event_log_coverage(&child, checkpoint, &coverage_log)
        .expect("coverage-stamped snapshot should cache");
    assert_eq!(
        graph
            .checkpoint_node(child.id())
            .map(|checkpoint| checkpoint.coverage_fingerprint),
        Some(fingerprint)
    );
    let materialized = graph
        .materialize_hot_checkpoint(
            &child,
            MaterializationPolicy::thin_only(),
            MaterializationTrigger::Cold,
        )
        .expect("cached snapshot should be returned before thin materialization");

    assert_eq!(materialized.coverage_fingerprint, fingerprint);
    assert_eq!(
        graph
            .cached_snapshot(&child)
            .map(|checkpoint| checkpoint.coverage_fingerprint),
        Some(fingerprint)
    );
    let thin = graph
        .evict_fat_checkpoint_to_thin(&child)
        .expect("evicting the fat cache should leave a thin checkpoint node");
    assert_eq!(thin.coverage_fingerprint, fingerprint);
    assert_eq!(thin.kind, CheckpointKind::Thin);
}

#[test]
fn delayed_checkpoint_closure_preserves_cached_coverage_fingerprint() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.event-log-coverage.world",
        "delayed-closure-stamping",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario);
    let child = step(
        &genesis,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("delayed-closure-stamping"),
            value: 101,
        }),
    );
    let coverage_log = vec![observation_entry(
        0,
        &ObservableEvent::coverage_marker(icount(52), node("guest-f"), marker("late")),
    )];
    let checkpoint = Checkpoint::from_recorded_configuration(
        &child,
        Some(&genesis),
        time(52),
        std::collections::BTreeMap::new(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    )
    .expect("fat checkpoint should build");
    let fingerprint = coverage_fingerprint_from_event_log(&coverage_log);
    let mut graph = TemporalGraph::empty();

    graph
        .cache_snapshot_with_event_log_coverage(&child, checkpoint, &coverage_log)
        .expect("coverage-stamped snapshot should cache before baked genesis");
    assert!(graph.checkpoint_node(child.id()).is_none());

    let baked = bake(&world).expect("baked genesis should build");
    graph
        .cache_baked_genesis(&genesis.def, baked)
        .expect("baked genesis should be accepted after cache insertion");
    graph
        .persist_checkpoint_closure(&MemoryDagStore::new(), &child)
        .expect("persisting closure should record a thin checkpoint node");
    assert_eq!(
        graph
            .checkpoint_node(child.id())
            .map(|checkpoint| checkpoint.coverage_fingerprint),
        Some(fingerprint)
    );

    let thin = graph
        .evict_fat_checkpoint_to_thin(&child)
        .expect("eviction should leave the stamped thin checkpoint node");
    assert_eq!(thin.coverage_fingerprint, fingerprint);
}

#[test]
fn coverage_projection_is_excluded_from_causal_determinism_comparison() {
    let expected = vec![
        rng_entry(0, 1, 7),
        observation_entry(
            1,
            &ObservableEvent::coverage_block(icount(2), node("guest-d"), 0x7000, 0x20),
        ),
        boundary_entry(2, 3),
    ];
    let reproduced = vec![
        rng_entry(0, 1, 7),
        observation_entry(
            1,
            &ObservableEvent::coverage_marker(icount(2), node("guest-d"), marker("alternate")),
        ),
        boundary_entry(2, 3),
    ];
    let comparison = compare_event_log_determinism(&expected, &reproduced);

    assert!(comparison.passes());
    assert_ne!(
        coverage_fingerprint_from_event_log(&expected),
        coverage_fingerprint_from_event_log(&reproduced)
    );
}
