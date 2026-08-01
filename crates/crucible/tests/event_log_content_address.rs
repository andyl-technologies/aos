//! Checks the T-OBS-5 event-log content-addressed segment contract.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible::{
    BackendInput, Checkpoint, CheckpointKind, Configuration, ContentHash, CowDeltaKind,
    CowDeltaRef, DagStore, Decision, DecisionRngState, EngineError, EventLog, ExactLocalEvent,
    LogEntry, MaterializedState, MemoryDagStore, NetworkLookahead, NodeCounter, NodeId,
    QuantumLoop, QuantumRequest, RngDecision, RngStreamId, ScheduledEvent, ScheduledEventKey,
    ScheduledEventPayload, SchedulerEvaluationBoundaryKind, SchedulerLivenessScenario,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulerState,
    SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler, TemporalGraph,
    VirtualTime, World, bake, instantiate, step,
};

fn boundary_entry(sequence: u64, ticks: u64) -> LogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        VirtualTime { ticks },
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
    }
}

fn scenario_node(name: &str, counter: u64) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name, SchedulingNodeKind::Vm),
        counter: NodeCounter { ticks: counter },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead: NetworkLookahead::Finite(SimDuration { nanos: 10 }),
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}

fn backend_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            producer.clone(),
            sequence,
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: payload.to_vec(),
        }),
    }
}

fn scheduler_scenario(name: &str) -> SchedulerLivenessScenario {
    let node_a = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let node_b = scheduler_node("node-b", SchedulingNodeKind::Vm);
    SchedulerLivenessScenario::from_canonical_material(
        name,
        Shift::new(0).expect("test shift should be valid"),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node("node-a", 0), scenario_node("node-b", 0)],
        vec![backend_event(3, &node_a, &node_b, 1, b"segment")],
    )
}

#[test]
fn event_log_segments_are_binary_canonical_with_derived_text_view() {
    let mut log = EventLog::new();
    let append = log
        .append_entries(vec![boundary_entry(0, 11)])
        .expect("event-log segment should append");

    assert!(append.segment_bytes.starts_with(b"CRUCIBLE-ELOGSEG"));
    assert_eq!(&append.segment_bytes[16..20], &1_u32.to_le_bytes());
    assert_ne!(append.segment_bytes, append.segment_text.as_bytes());
    assert_eq!(
        append.segment_hash,
        Some(ContentHash::from_bytes(&append.segment_bytes))
    );
    assert_eq!(append.offset.appended_segment, append.segment_hash);
    assert!(
        append
            .segment_text
            .contains("format=crucible.scheduler.event-log.segment-text.v1")
    );
    assert!(
        append
            .segment_text
            .contains("canonical_format=crucible.scheduler.event-log.segment.v1")
    );
    assert!(
        append
            .segment_text
            .contains("entry.payload.kind=evaluation_boundary")
    );
}

#[test]
fn shared_segment_store_deduplicates_identical_segments() {
    let shared = Arc::new(MemoryDagStore::new());
    let store: Arc<dyn DagStore> = shared.clone();
    let mut left = EventLog::with_segment_store(store.clone());
    let mut right = EventLog::with_segment_store(store);

    let left_append = left
        .append_entries(vec![boundary_entry(0, 17)])
        .expect("left segment should append");
    let right_append = right
        .append_entries(vec![boundary_entry(0, 17)])
        .expect("right segment should append");
    let segment_hash = left_append
        .segment_hash
        .expect("non-empty append should produce a segment hash");

    assert_eq!(right_append.segment_hash, Some(segment_hash));
    assert_eq!(
        shared
            .object_count()
            .expect("shared segment store should count objects"),
        1
    );
    assert_eq!(
        shared
            .get(&segment_hash)
            .expect("stored segment bytes should be readable"),
        left_append.segment_bytes
    );
}

#[test]
fn scheduler_writes_event_log_segments_to_shared_store() {
    let shared = Arc::new(MemoryDagStore::new());
    let store: Arc<dyn DagStore> = shared.clone();
    let mut scheduler = SingleScheduler::new_with_event_log_segment_store(
        scheduler_scenario("shared-store"),
        store,
    )
    .expect("scheduler should build with shared segment store");

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("scheduler quantum should append an event-log segment");
    let segment_hash = outcome
        .event_log_segment_hash
        .expect("non-empty quantum should have a segment hash");

    assert_eq!(
        outcome.event_log_offset.appended_segment,
        Some(segment_hash)
    );
    assert_eq!(
        shared
            .get(&segment_hash)
            .expect("scheduler segment should be stored as raw bytes"),
        outcome.event_log_segment_bytes
    );
}

#[test]
fn cloned_event_logs_share_prefixes_and_segment_store_on_fork() {
    let shared = Arc::new(MemoryDagStore::new());
    let store: Arc<dyn DagStore> = shared.clone();
    let mut parent = EventLog::with_segment_store(store);
    parent
        .append_entries(vec![boundary_entry(0, 3)])
        .expect("parent prefix segment should append");
    let fork_offset = parent.offset();

    let mut left = parent.clone();
    let mut right = parent.clone();

    assert_eq!(left.offset(), fork_offset);
    assert_eq!(right.offset(), fork_offset);

    let left_append = left
        .append_entries(vec![boundary_entry(1, 5)])
        .expect("left fork segment should append");
    let right_append = right
        .append_entries(vec![boundary_entry(1, 5)])
        .expect("right fork segment should append");

    assert_eq!(left_append.segment_hash, right_append.segment_hash);
    assert_eq!(left_append.offset.prefix, right_append.offset.prefix);
    assert_ne!(left_append.offset.prefix, fork_offset.prefix);
    assert_eq!(
        shared
            .object_count()
            .expect("forks should share segment objects"),
        2
    );
}

#[test]
fn resumed_event_log_continues_appending_after_stored_offset() {
    let shared = Arc::new(MemoryDagStore::new());
    let store: Arc<dyn DagStore> = shared.clone();
    let mut first_log = EventLog::with_segment_store(store.clone());
    let first = first_log
        .append_entries(vec![boundary_entry(0, 23)])
        .expect("first segment should append");
    let mut resumed = EventLog::from_offset_with_segment_store(first.offset, store);

    let second = resumed
        .append_entries(vec![boundary_entry(first.offset.events, 29)])
        .expect("resumed event log should append after stored offset");

    assert_eq!(second.entries[0].sequence(), first.offset.events);
    assert_eq!(second.offset.events, first.offset.events + 1);
    assert!(second.offset.bytes > first.offset.bytes);
    assert_ne!(second.offset.prefix, first.offset.prefix);
    assert_eq!(
        shared
            .object_count()
            .expect("resumed append should store a second segment"),
        2
    );
}

#[test]
fn temporal_graph_closure_references_stored_event_log_segment_bytes() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.event-log-content-address",
        "temporal-graph",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let child = step(
        &genesis,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("event-log-content-address"),
            value: 99,
        }),
    );
    let shared = Arc::new(MemoryDagStore::new());
    let store: Arc<dyn DagStore> = shared.clone();
    let mut log = EventLog::with_segment_store(store.clone());
    let append = log
        .append_entries(vec![boundary_entry(0, 31)])
        .expect("checkpointed segment should append");
    let segment_hash = append
        .segment_hash
        .expect("checkpointed append should record a segment hash");
    let state = MaterializedState::from_components(
        BTreeMap::new(),
        BTreeMap::new(),
        SchedulerState::empty(),
        DecisionRngState::empty(),
        append.offset,
    );
    let checkpoint = Checkpoint::from_recorded_configuration(
        &child,
        Some(&genesis),
        VirtualTime { ticks: 31 },
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint edge should be valid")
    .with_materialized_state(Some(state.clone()));
    let cow_ref = CowDeltaRef::new(CowDeltaKind::EventLogSegment, segment_hash);
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            bake(&world).expect("baked genesis should build for test world"),
        )
        .expect("baked genesis should seed graph");

    assert_eq!(
        checkpoint
            .state
            .as_ref()
            .map(|state| state.event_log)
            .unwrap_or_default(),
        append.offset
    );
    assert_eq!(state.event_log.prefix, append.offset.prefix);
    assert_eq!(state.event_log.bytes, append.offset.bytes);
    assert_eq!(state.event_log.events, append.offset.events);
    assert_eq!(state.event_log.appended_segment, Some(segment_hash));
    assert_eq!(
        state.cow_delta_refs().into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([cow_ref])
    );
    graph
        .cache_snapshot(&child, checkpoint)
        .expect("fat checkpoint with event-log offset should cache");

    let keys = graph
        .persist_checkpoint_closure(shared.as_ref(), &child)
        .expect("checkpoint closure should persist with stored event-log segment");

    assert_eq!(keys.cow_deltas.get(&cow_ref), Some(&segment_hash));
    assert_eq!(
        shared
            .get(&segment_hash)
            .expect("graph closure should reference stored raw segment bytes"),
        append.segment_bytes
    );
}

#[test]
fn thin_replay_rejects_stale_nonzero_event_log_offset() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.event-log-content-address",
        "stale-offset-replay",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let first = step(
        &genesis,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("stale-offset-first"),
            value: 1,
        }),
    );
    let second = step(
        &first,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("stale-offset-second"),
            value: 2,
        }),
    );
    let mut log = EventLog::new();
    let append = log
        .append_entries(vec![boundary_entry(0, 37)])
        .expect("ancestor checkpoint event-log segment should append");
    let state = MaterializedState::from_components(
        BTreeMap::new(),
        BTreeMap::new(),
        SchedulerState::empty(),
        DecisionRngState::empty(),
        append.offset,
    );
    let checkpoint = Checkpoint::from_recorded_configuration(
        &first,
        Some(&genesis),
        VirtualTime { ticks: 37 },
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("ancestor checkpoint edge should be valid")
    .with_materialized_state(Some(state));
    let mut graph = TemporalGraph::empty();
    graph
        .cache_snapshot(&first, checkpoint)
        .expect("ancestor checkpoint with event-log offset should cache");

    let error = instantiate(&graph, &second)
        .expect_err("thin replay must not carry a stale nonzero event-log offset");

    match error {
        EngineError::EventLogReplayUnsupported {
            start,
            target,
            events,
        } if start == first.id() && target == second.id() && events == append.offset.events => {}
        other => panic!("unexpected stale-offset replay error: {other:?}"),
    }
}
