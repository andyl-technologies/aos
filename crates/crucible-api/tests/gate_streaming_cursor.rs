//! Checks the RFC-0010 T-API-6 streaming cursor contract.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::Duration;

use crucible::test_support::condition_payload_entry_for_test;
use crucible::{
    Checkpoint, CheckpointKind, Configuration, Decision, EventAttributeValue,
    EventDiagnosticPayload, EventLevel, GenesisCheckpoint, QuantumLoop, QuantumOutcome,
    QuantumRequest, RngDecision, RngStreamId, ScenarioDef, SchedulerError, SchedulerEventLogEntry,
    SchedulerEventLogPayload, Seed, TemporalGraph, VirtualTime,
};
use crucible_api::{
    AttachRequest, ControlPlaneEventLog, EventLogCursor, InProcessStreamingSession, SendRequest,
    SessionEventLogHub, SessionId, SessionRef,
};
use crucible_session::test_support::append_event_log_entries_for_test;
use crucible_session::{Engine, SessionActor, SessionCommand, SessionError, SessionRunReport};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[tokio::test(flavor = "current_thread")]
async fn streaming_cursor_replays_then_live_tails_api_events() {
    let fixture = CursorFixture::spawn_loaded(6100).await;
    let session = fixture.session;
    append_event_log_entries_for_test(&fixture.event_log_hub, &event_pair(0, 1));

    let before_state = fixture.live.read().state_kind;
    let before_len = fixture.event_log_hub.current_cursor().next_sequence;

    let mut replay = fixture
        .api
        .watch(AttachRequest::new(session).with_cursor(EventLogCursor::new(0)))
        .unwrap_or_else(|error| panic!("Watch attach from genesis should succeed: {error}"));
    assert_eq!(replay.attached().event_log_len, before_len);
    assert_eq!(replay.attached().state, before_state);
    let snapshot = replay
        .attached()
        .snapshot
        .as_ref()
        .expect("snapshot-on-attach should be advertised and present");
    assert_eq!(snapshot.through, EventLogCursor::new(before_len));
    assert_eq!(snapshot.event_count, before_len);
    assert_eq!(snapshot.causal_event_count, before_len / 2);
    assert_eq!(snapshot.observational_event_count, before_len / 2);
    assert_eq!(snapshot.last_sequence, before_len.checked_sub(1));
    assert!(replay.attached().capabilities.snapshot_on_attach);
    assert_eq!(fixture.live.read().state_kind, before_state);
    assert_eq!(
        fixture.event_log_hub.current_cursor(),
        EventLogCursor::new(before_len),
    );

    let causal = recv_event(&mut replay).await;
    assert_eq!(causal.cursor, EventLogCursor::new(0));
    assert_eq!(causal.next_cursor, EventLogCursor::new(1));
    assert_eq!(causal.event.sequence, 0);
    assert_eq!(causal.event.payload.kind, "crucible.event.rng_draw");
    assert!(!causal.event.observational);

    let observational = recv_event(&mut replay).await;
    assert_eq!(observational.cursor, EventLogCursor::new(1));
    assert_eq!(observational.next_cursor, EventLogCursor::new(2));
    assert_eq!(observational.event.sequence, 1);
    assert_eq!(
        observational.event.payload.kind,
        "crucible.event.diagnostic"
    );
    assert!(observational.event.observational);

    assert!(
        tokio::time::timeout(Duration::from_millis(10), replay.recv_event())
            .await
            .is_err(),
        "replay should be exhausted before the next live entry",
    );

    let mut tail_only = fixture
        .api
        .watch(AttachRequest::new(session).with_cursor(EventLogCursor::new(999)))
        .unwrap_or_else(|error| panic!("Watch attach beyond tail should succeed: {error}"));
    assert_eq!(
        tail_only.event_stream().cursor(),
        EventLogCursor::new(tail_only.attached().event_log_len),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(10), tail_only.recv_event())
            .await
            .is_err(),
        "attach beyond current length should skip historical replay",
    );

    append_event_log_entries_for_test(&fixture.event_log_hub, &event_pair(before_len, 2));

    let live = recv_event(&mut tail_only).await;
    assert_eq!(live.cursor, EventLogCursor::new(before_len));
    assert_eq!(live.event.payload.kind, "crucible.event.rng_draw");
    assert!(!live.event.observational);

    fixture
        .api
        .send(SendRequest::new(session, 1, SessionCommand::Stop))
        .await
        .unwrap_or_else(|error| panic!("Stop should dispatch: {error}"));
    fixture.join_stopped().await;
}

async fn recv_event(stream: &mut crucible_api::WatchStream) -> crucible_api::StreamingEventFrame {
    tokio::time::timeout(Duration::from_millis(100), stream.recv_event())
        .await
        .expect("event stream should produce a frame")
        .expect("event stream should not lag")
        .expect("event stream should remain open")
}

struct CursorFixture {
    session: SessionRef,
    api: InProcessStreamingSession,
    event_log_hub: SessionEventLogHub,
    live: std::sync::Arc<crucible_session::LiveSnapshot>,
    actor_task: JoinHandle<Result<SessionRunReport, SessionError>>,
}

impl CursorFixture {
    async fn spawn_loaded(seed: u64) -> Self {
        let scenario = generated_scenario(seed);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let engine = Engine::new(config, graph, CursorLoop);
        let (sender, receiver) = mpsc::channel::<SessionCommand>(16);
        let actor = SessionActor::new(engine, receiver);
        let live = actor.live_snapshot();
        let event_log_hub = actor.event_log();
        let event_log = ControlPlaneEventLog::new(event_log_hub.clone());
        let reproduction_log = actor.reproduction_log();
        let state_transitions = actor.state_transition_bus();
        let actor_task = tokio::spawn(async move { actor.run().await });
        let session = SessionRef::new(SessionId::new(seed), seed, scenario.seed());
        let api = InProcessStreamingSession::new(
            session,
            sender,
            live.clone(),
            event_log,
            reproduction_log,
            state_transitions,
        );
        Self {
            session,
            api,
            event_log_hub,
            live,
            actor_task,
        }
    }

    async fn join_stopped(self) {
        match self.actor_task.await {
            Ok(Ok(_report)) => {}
            Ok(Err(error)) => panic!("actor should stop cleanly: {error}"),
            Err(error) => panic!("actor task should join cleanly: {error}"),
        }
    }
}

#[derive(Default)]
struct CursorLoop;

impl QuantumLoop for CursorLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime::default(),
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }
}

fn event_pair(first_sequence: u64, quantum: u64) -> Vec<SchedulerEventLogEntry> {
    let frontier = VirtualTime { ticks: quantum };
    let causal = condition_payload_entry_for_test(
        first_sequence,
        frontier,
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name(format!("cursor-{quantum}")),
            value: quantum,
        })),
    );

    let mut details = BTreeMap::new();
    details.insert(String::from("quantum"), EventAttributeValue::U64(quantum));
    let observational = condition_payload_entry_for_test(
        first_sequence.saturating_add(1),
        frontier,
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            format!("cursor-diagnostic-{quantum}"),
            EventLevel::Info,
            details,
        )),
    );
    vec![causal, observational]
}

fn graph_with_baked_genesis(scenario: &ScenarioDef) -> TemporalGraph {
    let genesis = Configuration::genesis(scenario.clone());
    match TemporalGraph::empty().with_baked_genesis(scenario, genesis_checkpoint(&genesis)) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    }
}

fn genesis_checkpoint(configuration: &Configuration) -> GenesisCheckpoint {
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("genesis checkpoint should be recorded-shaped: {error}"));
    GenesisCheckpoint { checkpoint }
}

fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.api.gate-streaming-cursor.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}
