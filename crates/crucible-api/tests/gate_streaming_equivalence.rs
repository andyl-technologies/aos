//! API-side checks for `Control` and `Watch`+`Send` equivalence.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, EventLogOffset, GenesisCheckpoint, QuantumLoop,
    QuantumOutcome, QuantumRequest, ScenarioDef, SchedulerError, Seed, TemporalGraph, VirtualTime,
};
use crucible_api::{
    AttachRequest, CommandRejectionKind, CommandResultStatus, ControlPlaneEventLog, EventLogCursor,
    InProcessStreamingSession, SendRequest, SessionId, SessionRef, StateUpdate,
    StreamingCommandCapability, StreamingEquivalenceError, StreamingStateUpdateFrame,
    validate_control_watch_send_equivalence,
};
use crucible_session::{
    Engine, LiveStateKind, SessionActor, SessionCommand, SessionCommandKind, SessionError,
    SessionRunReport,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[test]
fn control_and_watch_send_advertise_identical_command_capabilities() {
    let report = validate_control_watch_send_equivalence()
        .unwrap_or_else(|error| panic!("streaming surfaces should be equivalent: {error}"));

    assert_eq!(report.command_count, SessionCommandKind::ALL.len());
    assert_eq!(report.control_capabilities, report.send_capabilities);
    for command in SessionCommandKind::ALL {
        assert!(
            report.control_capabilities.contains(command),
            "Control should advertise {command:?}"
        );
        assert!(
            report.send_capabilities.contains(command),
            "Send should advertise {command:?}"
        );
    }

    let start = StreamingCommandCapability {
        command_name: "start",
        command_kind: SessionCommandKind::Start,
    };
    assert!(report.control_capabilities.commands.contains(&start));
}

#[tokio::test(flavor = "current_thread")]
async fn control_stream_and_watch_send_drive_the_same_session_lifecycle() {
    let fixture = StreamingFixture::spawn_loaded(11).await;
    let session = fixture.session;

    let mut control = fixture
        .api
        .control(
            AttachRequest::new(session)
                .with_expected_epoch(session.epoch)
                .with_client_name("control-client"),
        )
        .unwrap_or_else(|error| panic!("Control attach should succeed: {error}"));
    assert_eq!(control.attached().session, session);
    assert_eq!(control.attached().state, LiveStateKind::Loaded);
    assert_eq!(control.event_stream().cursor(), EventLogCursor::default());

    let mut watch = fixture
        .api
        .watch(AttachRequest::new(session).with_client_name("watch-client"))
        .unwrap_or_else(|error| panic!("Watch attach should succeed: {error}"));
    assert_eq!(watch.attached().state, LiveStateKind::Loaded);
    assert_eq!(
        watch.attached().capabilities,
        control.attached().capabilities
    );
    assert_eq!(watch.event_stream().cursor(), EventLogCursor::default());

    let started = control
        .send_command(1, SessionCommand::Start)
        .await
        .unwrap_or_else(|error| panic!("Control Start should dispatch: {error}"));
    assert_eq!(started.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        started.state_update.map(|update| update.state),
        Some(LiveStateKind::Paused)
    );

    let continued = fixture
        .api
        .send(SendRequest::new(session, 2, SessionCommand::Continue))
        .await
        .unwrap_or_else(|error| panic!("Send Continue should dispatch: {error}"));
    assert_eq!(continued.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        continued.state_update.map(|update| update.state),
        Some(LiveStateKind::Running)
    );

    let paused = control
        .send_command(3, SessionCommand::Pause)
        .await
        .unwrap_or_else(|error| panic!("Control Pause should dispatch: {error}"));
    assert_eq!(paused.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        paused.state_update.map(|update| update.state),
        Some(LiveStateKind::Paused)
    );

    let stopped = fixture
        .api
        .send(SendRequest::new(session, 4, SessionCommand::Stop))
        .await
        .unwrap_or_else(|error| panic!("Send Stop should dispatch: {error}"));
    assert_eq!(stopped.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        stopped.state_update.map(|update| update.state),
        Some(LiveStateKind::Stopped)
    );

    fixture.join_stopped().await;
}

#[tokio::test(flavor = "current_thread")]
async fn watch_only_state_updates_are_monotone_and_not_event_log_entries() {
    let fixture = StreamingFixture::spawn_loaded(13).await;
    let session = fixture.session;
    let mut watch = fixture
        .api
        .watch(AttachRequest::new(session).with_client_name("watch-state-client"))
        .unwrap_or_else(|error| panic!("Watch attach should succeed: {error}"));
    assert_eq!(watch.attached().state, LiveStateKind::Loaded);
    let mut tracked_state = watch.attached().state;
    let mut last_sequence = 0;

    let started = fixture
        .api
        .send(SendRequest::new(session, 1, SessionCommand::Start))
        .await
        .unwrap_or_else(|error| panic!("Send Start should dispatch: {error}"));
    tracked_state = apply_send_state_update(tracked_state, started.state_update);
    let started_update = recv_watch_state_update(&mut watch).await;
    assert_eq!(started_update.update.state, tracked_state);
    assert!(started_update.sequence > last_sequence);
    last_sequence = started_update.sequence;
    assert_watch_has_no_event_log_frame(&mut watch).await;

    let continued = fixture
        .api
        .send(SendRequest::new(session, 2, SessionCommand::Continue))
        .await
        .unwrap_or_else(|error| panic!("Send Continue should dispatch: {error}"));
    tracked_state = apply_send_state_update(tracked_state, continued.state_update);
    let continued_update = recv_watch_state_update(&mut watch).await;
    assert_eq!(continued_update.update.state, tracked_state);
    assert!(continued_update.sequence > last_sequence);
    last_sequence = continued_update.sequence;
    assert_watch_has_no_event_log_frame(&mut watch).await;

    let paused = fixture
        .api
        .send(SendRequest::new(session, 3, SessionCommand::Pause))
        .await
        .unwrap_or_else(|error| panic!("Send Pause should dispatch: {error}"));
    tracked_state = apply_send_state_update(tracked_state, paused.state_update);
    let paused_update = recv_watch_state_update(&mut watch).await;
    assert_eq!(paused_update.update.state, tracked_state);
    assert!(paused_update.sequence > last_sequence);
    last_sequence = paused_update.sequence;
    assert_watch_has_no_event_log_frame(&mut watch).await;

    let stopped = fixture
        .api
        .send(SendRequest::new(session, 4, SessionCommand::Stop))
        .await
        .unwrap_or_else(|error| panic!("Send Stop should dispatch: {error}"));
    tracked_state = apply_send_state_update(tracked_state, stopped.state_update);
    let stopped_update = recv_watch_state_update(&mut watch).await;
    assert_eq!(stopped_update.update.state, tracked_state);
    assert!(stopped_update.sequence > last_sequence);
    assert_watch_has_no_event_log_frame(&mut watch).await;

    fixture.join_stopped().await;
}

#[tokio::test(flavor = "current_thread")]
async fn control_and_send_drive_non_basic_command_classes() {
    for command in [
        SessionCommandKind::StepQuantum,
        SessionCommandKind::Inject,
        SessionCommandKind::SetBreakpoint,
        SessionCommandKind::RemoveBreakpoint,
        SessionCommandKind::CreateSavepoint,
        SessionCommandKind::Fork,
        SessionCommandKind::Stop,
    ] {
        let control_response = drive_command_with_control(command).await;
        let send_response = drive_command_with_send(command).await;
        assert_eq!(
            control_response.result.command_kind,
            send_response.result.command_kind,
        );
        let expected = if command == SessionCommandKind::RemoveBreakpoint {
            CommandResultStatus::Rejected {
                reason: CommandRejectionKind::NotFound,
            }
        } else {
            CommandResultStatus::Accepted
        };
        assert_eq!(control_response.result.status, expected);
        assert_eq!(send_response.result.status, expected);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn control_and_send_reject_invalid_lifecycle_commands_equivalently() {
    let fixture = StreamingFixture::spawn_loaded(12).await;
    let session = fixture.session;
    let control = fixture
        .api
        .control(AttachRequest::new(session))
        .unwrap_or_else(|error| panic!("Control attach should succeed: {error}"));

    let control_rejection = control
        .send_command(10, SessionCommand::Continue)
        .await
        .unwrap_or_else(|error| panic!("Control rejection should be typed: {error}"));
    assert_eq!(
        control_rejection.result.status,
        CommandResultStatus::Rejected {
            reason: CommandRejectionKind::InvalidState,
        }
    );
    assert!(control_rejection.state_update.is_none());

    let send_rejection = fixture
        .api
        .send(SendRequest::new(session, 11, SessionCommand::Continue))
        .await
        .unwrap_or_else(|error| panic!("Send rejection should be typed: {error}"));
    assert_eq!(
        send_rejection.result.status,
        control_rejection.result.status
    );
    assert!(send_rejection.state_update.is_none());
    assert_eq!(fixture.live.read().state_kind, LiveStateKind::Loaded);

    let stopped = fixture
        .api
        .send(SendRequest::new(session, 12, SessionCommand::Stop))
        .await
        .unwrap_or_else(|error| panic!("Send Stop should still dispatch: {error}"));
    assert_eq!(
        stopped.state_update.map(|update| update.state),
        Some(LiveStateKind::Stopped)
    );
    fixture.join_stopped().await;
}

#[test]
fn streaming_equivalence_rejects_missing_capabilities() {
    let missing = StreamingEquivalenceError::MissingCommandCapability {
        command: SessionCommandKind::Start,
    };
    assert_eq!(
        missing.to_string(),
        "streaming command capability Start is missing"
    );
}

async fn recv_watch_state_update(
    watch: &mut crucible_api::WatchStream,
) -> StreamingStateUpdateFrame {
    tokio::time::timeout(Duration::from_millis(100), watch.recv_state_update())
        .await
        .unwrap_or_else(|_| panic!("Watch state update should arrive before timeout"))
        .unwrap_or_else(|error| panic!("Watch state update should decode: {error}"))
        .unwrap_or_else(|| panic!("Watch state update stream should remain open"))
}

async fn assert_watch_has_no_event_log_frame(watch: &mut crucible_api::WatchStream) {
    let event = tokio::time::timeout(Duration::from_millis(10), watch.recv_event()).await;
    assert!(
        event.is_err(),
        "StateUpdate delivery must remain distinct from event-log entries",
    );
}

fn apply_send_state_update(current: LiveStateKind, update: Option<StateUpdate>) -> LiveStateKind {
    update.map(|update| update.state).unwrap_or(current)
}

async fn drive_command_with_control(command: SessionCommandKind) -> crucible_api::SendResponse {
    let fixture = StreamingFixture::spawn_loaded(1000 + command_index(command)).await;
    let session = fixture.session;
    let control = fixture
        .api
        .control(AttachRequest::new(session))
        .unwrap_or_else(|error| panic!("Control attach should succeed: {error}"));
    let _started = fixture
        .api
        .send(SendRequest::new(session, 1, SessionCommand::Start))
        .await
        .unwrap_or_else(|error| panic!("Start before {command:?} should dispatch: {error}"));
    let response = control
        .send_command(2, representative_command(command))
        .await
        .unwrap_or_else(|error| panic!("Control {command:?} should dispatch: {error}"));
    stop_or_join(fixture, command).await;
    response
}

async fn drive_command_with_send(command: SessionCommandKind) -> crucible_api::SendResponse {
    let fixture = StreamingFixture::spawn_loaded(2000 + command_index(command)).await;
    let session = fixture.session;
    let _watch = fixture
        .api
        .watch(AttachRequest::new(session))
        .unwrap_or_else(|error| panic!("Watch attach should succeed: {error}"));
    let _started = fixture
        .api
        .send(SendRequest::new(session, 1, SessionCommand::Start))
        .await
        .unwrap_or_else(|error| panic!("Start before {command:?} should dispatch: {error}"));
    let response = fixture
        .api
        .send(SendRequest::new(
            session,
            2,
            representative_command(command),
        ))
        .await
        .unwrap_or_else(|error| panic!("Send {command:?} should dispatch: {error}"));
    stop_or_join(fixture, command).await;
    response
}

async fn stop_or_join(fixture: StreamingFixture, command: SessionCommandKind) {
    if !matches!(
        command,
        SessionCommandKind::Stop | SessionCommandKind::ExhaustBudget
    ) {
        let _stopped = fixture
            .api
            .send(SendRequest::new(fixture.session, 99, SessionCommand::Stop))
            .await
            .unwrap_or_else(|error| panic!("cleanup Stop should dispatch: {error}"));
    }
    fixture.join_stopped().await;
}

fn representative_command(command: SessionCommandKind) -> SessionCommand {
    command
        .representative_command()
        .unwrap_or_else(|| panic!("{command:?} should have a representative payload"))
}

const fn command_index(command: SessionCommandKind) -> u64 {
    match command {
        SessionCommandKind::Start => 1,
        SessionCommandKind::Continue => 2,
        SessionCommandKind::Pause => 3,
        SessionCommandKind::StepQuantum => 4,
        SessionCommandKind::StepEvent => 5,
        SessionCommandKind::StepAssertion => 6,
        SessionCommandKind::StepTimer => 7,
        SessionCommandKind::StepDuration => 8,
        SessionCommandKind::Stop => 9,
        SessionCommandKind::Inject => 10,
        SessionCommandKind::SetBreakpoint => 11,
        SessionCommandKind::RemoveBreakpoint => 12,
        SessionCommandKind::CreateSavepoint => 13,
        SessionCommandKind::Fork => 14,
        SessionCommandKind::Query => 15,
        SessionCommandKind::Snapshot => 16,
        SessionCommandKind::AttachGdb => 17,
        SessionCommandKind::DebugGoto => 18,
        SessionCommandKind::DebugReverseStep => 19,
        SessionCommandKind::DebugReverseContinue => 20,
        SessionCommandKind::DebugForkNonCanonical => 21,
        SessionCommandKind::ExhaustBudget => 22,
    }
}

struct StreamingFixture {
    session: SessionRef,
    api: InProcessStreamingSession,
    live: std::sync::Arc<crucible_session::LiveSnapshot>,
    actor_task: JoinHandle<Result<SessionRunReport, SessionError>>,
}

impl StreamingFixture {
    async fn spawn_loaded(seed: u64) -> Self {
        let scenario = generated_scenario(seed);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let engine = Engine::new(config, graph, StreamingLoop { quanta: 0 });
        let (sender, receiver) = mpsc::channel::<SessionCommand>(16);
        let actor = SessionActor::new(engine, receiver);
        let live = actor.live_snapshot();
        let event_log = ControlPlaneEventLog::new(actor.event_log());
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

struct StreamingLoop {
    quanta: u64,
}

impl QuantumLoop for StreamingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }
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
        std::collections::BTreeMap::new(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("genesis checkpoint should be recorded-shaped: {error}"));
    GenesisCheckpoint { checkpoint }
}

fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.api.gate-streaming-equivalence.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}
