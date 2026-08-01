//! Checks T-OBS-14 assertion-proximity event-log projection.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, AssertionQuantifierKind, Checkpoint, CheckpointKind, Configuration,
    ContentHash, Decision, EventClass, EventLog, Icount, MaterializationPolicy,
    MaterializationTrigger, MemPlace, MemoryCmp, MemoryWidth, NodeId, NodeTemplate,
    ObservableEvent, OfflineAssertionChecker, Predicate, Properties, Property, ReadyPoint,
    ResolvedMemPlace, RngDecision, RngStreamId, SchedulerEvaluationBoundaryKind,
    SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerLivenessScenario, Shift, SimInstant,
    SingleScheduler, TemporalGraph, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
    assertion_proximity_fingerprint_from_event_log, bake, compare_event_log_determinism,
    event_log_assertion_proximity_projection, event_log_causal_projection, step,
};

#[test]
fn assertion_proximity_entries_are_observational_and_projected() {
    let entry = proximity_entry(0, 2, "counter-reaches-ten", 3);

    assert_eq!(entry.class(), EventClass::Observational);
    assert_eq!(entry.event_payload().kind(), "assertion_proximity");
    assert_eq!(
        entry.event_payload().string("id"),
        Some("counter-reaches-ten")
    );
    assert_eq!(
        entry.event_payload().string("quantifier"),
        Some("sometimes")
    );
    assert_eq!(entry.event_payload().u128("distance"), Some(3));
    assert_eq!(entry.event_payload().u64("distance"), None);
    assert!(entry.class_matches_catalog());
    assert!(entry.has_valid_content_hash());

    let projection = event_log_assertion_proximity_projection(std::slice::from_ref(&entry));
    assert_eq!(projection.len(), 1);
    assert_eq!(
        projection.entries()[0].assertion.name,
        "counter-reaches-ten"
    );
    assert_eq!(projection.entries()[0].distance, 3);
    assert_ne!(projection.content_hash(), ContentHash::default());

    let append = EventLog::new()
        .append_entries(vec![entry])
        .expect("assertion_proximity entry should append");
    assert_eq!(append.offset.events, 1);
    assert!(
        append
            .segment_text
            .contains("entry.payload.kind=assertion_proximity")
    );
    assert!(append.segment_text.contains("entry.class=observational"));
}

#[test]
fn assertion_proximity_is_excluded_from_causal_determinism() {
    let without_proximity = vec![rng_entry(0, 1), boundary_entry(1, 3)];
    let with_proximity = vec![
        rng_entry(0, 1),
        proximity_entry(1, 2, "counter-reaches-ten", 3),
        boundary_entry(2, 3),
    ];

    assert_eq!(
        event_log_causal_projection(&without_proximity).canonical_bytes(),
        event_log_causal_projection(&with_proximity).canonical_bytes()
    );
    assert!(compare_event_log_determinism(&without_proximity, &with_proximity).passes());
}

#[test]
fn assertion_proximity_fingerprint_uses_minimum_distance_per_assertion() {
    let worse = vec![proximity_entry(0, 1, "counter-reaches-ten", 7)];
    let better = vec![proximity_entry(0, 2, "counter-reaches-ten", 3)];
    let same_minimum_later = vec![proximity_entry(0, 99, "counter-reaches-ten", 3)];
    let combined = vec![
        proximity_entry(0, 1, "counter-reaches-ten", 7),
        proximity_entry(1, 2, "counter-reaches-ten", 3),
    ];

    assert_ne!(
        assertion_proximity_fingerprint_from_event_log(&worse),
        assertion_proximity_fingerprint_from_event_log(&better)
    );
    assert_eq!(
        assertion_proximity_fingerprint_from_event_log(&combined),
        assertion_proximity_fingerprint_from_event_log(&better)
    );
    assert_eq!(
        assertion_proximity_fingerprint_from_event_log(&same_minimum_later),
        assertion_proximity_fingerprint_from_event_log(&better)
    );
    assert_eq!(
        assertion_proximity_fingerprint_from_event_log(&[]),
        ContentHash::default()
    );
}

#[test]
fn assertion_proximity_minimums_are_bucketed_by_quantifier_and_node() {
    let sometimes = proximity_entry(0, 1, "shared", 3);
    let eventually_worse =
        proximity_entry_with(1, 2, "shared", AssertionQuantifierKind::Eventually, 9, None);
    let eventually_better =
        proximity_entry_with(2, 3, "shared", AssertionQuantifierKind::Eventually, 2, None);
    let node_a = proximity_entry_with(
        3,
        4,
        "shared",
        AssertionQuantifierKind::Sometimes,
        1,
        Some(node("guest-a")),
    );
    let node_b = proximity_entry_with(
        4,
        5,
        "shared",
        AssertionQuantifierKind::Sometimes,
        4,
        Some(node("guest-b")),
    );

    assert_eq!(
        assertion_proximity_fingerprint_from_event_log(&[
            sometimes.clone(),
            eventually_worse,
            eventually_better.clone(),
        ]),
        assertion_proximity_fingerprint_from_event_log(&[
            sometimes.clone(),
            eventually_better.clone(),
        ])
    );
    assert_ne!(
        assertion_proximity_fingerprint_from_event_log(std::slice::from_ref(&sometimes)),
        assertion_proximity_fingerprint_from_event_log(&[sometimes.clone(), eventually_better])
    );
    assert_ne!(
        assertion_proximity_fingerprint_from_event_log(std::slice::from_ref(&node_a)),
        assertion_proximity_fingerprint_from_event_log(&[node_a.clone(), node_b])
    );
    assert_ne!(
        assertion_proximity_fingerprint_from_event_log(std::slice::from_ref(&sometimes)),
        assertion_proximity_fingerprint_from_event_log(&[sometimes, node_a])
    );
}

#[test]
fn assertion_proximity_distance_serializes_losslessly_above_u64_max() {
    let wide_distance = u128::from(u64::MAX) + 1;
    let entry = proximity_entry(0, 1, "wide-distance", wide_distance);

    assert_eq!(entry.event_payload().u128("distance"), Some(wide_distance));
    assert_eq!(entry.event_payload().u64("distance"), None);
    let projection = event_log_assertion_proximity_projection(std::slice::from_ref(&entry));
    assert_eq!(projection.entries()[0].distance, wide_distance);

    let append = EventLog::new()
        .append_entries(vec![entry])
        .expect("wide assertion_proximity entry should append");
    assert!(
        append
            .segment_text
            .contains("event_payload.attribute.distance.value.type=u128")
    );
    assert!(append.segment_text.contains(&format!(
        "event_payload.attribute.distance.value.value={wide_distance}"
    )));
}

#[test]
fn assertion_proximity_fingerprint_is_checkpoint_feedback_from_log_projection() {
    let log = vec![
        proximity_entry(0, 1, "counter-reaches-ten", 7),
        proximity_entry(1, 2, "counter-reaches-ten", 3),
    ];
    let fingerprint = assertion_proximity_fingerprint_from_event_log(&log);
    let checkpoint = Checkpoint::new(
        ContentHash::from_canonical_material("crucible.test.proximity-checkpoint", "id"),
        ContentHash::from_canonical_material("crucible.test.proximity-checkpoint", "config"),
        CheckpointKind::Thin,
    );
    let checkpoint_id = checkpoint.id;
    let checkpoint = checkpoint.with_assertion_proximity_from_event_log(&log);

    assert_ne!(fingerprint, ContentHash::default());
    assert_eq!(checkpoint.id, checkpoint_id);
    assert_eq!(checkpoint.assertion_proximity_fingerprint, fingerprint);
    assert_eq!(
        Checkpoint::new(
            ContentHash::from_canonical_material("crucible.test.proximity-empty", "id"),
            ContentHash::from_canonical_material("crucible.test.proximity-empty", "config"),
            CheckpointKind::Thin,
        )
        .with_assertion_proximity_from_event_log(&[])
        .assertion_proximity_fingerprint,
        ContentHash::default()
    );
}

#[test]
fn scheduler_appends_report_proximities_to_unified_event_log() {
    let properties = properties(vec![assertion(
        "counter-reaches-ten",
        Property::Sometimes {
            predicate: memory_predicate(MemoryCmp::Ge, 10),
        },
    )]);
    let source_log = vec![
        memory_sample(0, 1, 2),
        memory_sample(1, 2, 7),
        memory_sample(2, 3, 5),
    ];
    let report = OfflineAssertionChecker::new()
        .check_run(&properties, &source_log)
        .expect("assertion report should compute proximity");
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "assertion-proximity-event-log-append",
        Shift::default(),
        1,
        SimInstant { nanos: 1 },
        Vec::new(),
        Vec::new(),
    ))
    .expect("append-only scheduler should build");

    let append = scheduler
        .append_assertion_proximity_events(&report)
        .expect("scheduler should append assertion proximity events");
    let entries = append.entries;

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].event_payload().kind(), "assertion_proximity");
    assert_eq!(entries[0].class(), EventClass::Observational);
    assert_eq!(
        entries[0].event_payload().string("id"),
        Some("counter-reaches-ten")
    );
    assert_eq!(
        entries[0].event_payload().string("quantifier"),
        Some("sometimes")
    );
    assert_eq!(entries[0].event_payload().u128("distance"), Some(3));
    assert!(
        append
            .segment_text
            .contains("entry.payload.kind=assertion_proximity")
    );
    assert!(
        append
            .segment_text
            .contains("event_payload.attribute.distance.value.type=u128")
    );
    assert_eq!(
        assertion_proximity_fingerprint_from_event_log(&entries),
        event_log_assertion_proximity_projection(&entries).content_hash()
    );
}

#[test]
fn graph_cache_snapshot_stamps_checkpoint_assertion_proximity_from_event_log_projection() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.event-log-assertion-proximity.world",
        "graph-cache-stamping",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario);
    let child = step(
        &genesis,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("proximity-graph-cache-stamping"),
            value: 99,
        }),
    );
    let proximity_log = vec![
        proximity_entry(0, 41, "counter-reaches-ten", 9),
        proximity_entry(1, 42, "counter-reaches-ten", 2),
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
    let fingerprint = assertion_proximity_fingerprint_from_event_log(&proximity_log);
    let baked = bake(&world).expect("baked genesis should build");
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(&genesis.def, baked)
        .expect("baked genesis should seed graph");

    graph
        .cache_snapshot_with_event_log_assertion_proximity(&child, checkpoint, &proximity_log)
        .expect("assertion-proximity-stamped snapshot should cache");
    assert_eq!(
        graph
            .checkpoint_node(child.id())
            .map(|checkpoint| checkpoint.assertion_proximity_fingerprint),
        Some(fingerprint)
    );
    let materialized = graph
        .materialize_hot_checkpoint(
            &child,
            MaterializationPolicy::thin_only(),
            MaterializationTrigger::Cold,
        )
        .expect("cached snapshot should be returned before thin materialization");

    assert_eq!(materialized.assertion_proximity_fingerprint, fingerprint);
    assert_eq!(
        graph
            .cached_snapshot(&child)
            .map(|checkpoint| checkpoint.assertion_proximity_fingerprint),
        Some(fingerprint)
    );
    let thin = graph
        .evict_fat_checkpoint_to_thin(&child)
        .expect("evicting the fat cache should leave a thin checkpoint node");
    assert_eq!(thin.assertion_proximity_fingerprint, fingerprint);
    assert_eq!(thin.kind, CheckpointKind::Thin);
}

fn proximity_entry(
    sequence: u64,
    ticks: u64,
    assertion: &str,
    distance: u128,
) -> SchedulerEventLogEntry {
    proximity_entry_with(
        sequence,
        ticks,
        assertion,
        AssertionQuantifierKind::Sometimes,
        distance,
        None,
    )
}

fn proximity_entry_with(
    sequence: u64,
    ticks: u64,
    assertion: &str,
    quantifier: AssertionQuantifierKind,
    distance: u128,
    node: Option<NodeId>,
) -> SchedulerEventLogEntry {
    let event = ObservableEvent::assertion_proximity(
        time(ticks),
        AssertionId::from_name(assertion),
        quantifier,
        distance,
        node,
    );
    crucible::test_support::condition_observation_entry_for_test(sequence, &event)
}

fn assertion(id: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: format!("{id} proximity"),
        property,
    }
}

fn properties(assertions: Vec<AssertionDef>) -> Properties {
    Properties::from_assertions_for_world(&world(), assertions)
        .expect("assertion proximity properties should validate")
}

fn world() -> World {
    World::from_nodes(vec![WorldNode {
        id: node("guest"),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount { icount: icount(1) },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("assertion proximity world should build")
}

fn memory_predicate(cmp: MemoryCmp, value: u64) -> Predicate {
    Predicate::memory_predicate(
        node("guest"),
        MemPlace::register("rax", MemoryWidth::U64),
        cmp,
        value,
    )
}

fn memory_sample(sequence: u64, ticks: u64, value: u64) -> SchedulerEventLogEntry {
    let event = ObservableEvent::memory_sample(
        time(ticks),
        icount(ticks),
        node("guest"),
        ResolvedMemPlace::register("rax", 8),
        value,
    );
    crucible::test_support::condition_observation_entry_for_test(sequence, &event)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn rng_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("assertion-proximity-causal"),
            value: 41,
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

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}
