//! Phase-6 exploration lifecycle checks for pause/resume/stop.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ControlOperation, ControlOperationKind, Decision,
    DeliveryOrderDecision, EventKey, GenesisCheckpoint, NodeId, QuantumLoop, QuantumOutcome,
    QuantumRequest, ScenarioDef, SchedulerError, SchedulerNodeId, SchedulingNodeKind, Seed,
    TemporalGraph, VirtualTime, step,
};
use crucible_session::{
    EXPLORATION_LIFECYCLE_RESPONSE_BOUND_QUANTA, Engine, EngineState, EventLogCursor,
    ExplorationLifecycleCommand, ExplorationLifecycleDriver, LiveSnapshot, LiveStateKind, Outcome,
    SessionActor, SessionCommand, SessionError, SessionEventLog, SessionRunReport,
};
use tokio::sync::mpsc;

#[tokio::test(flavor = "current_thread")]
async fn exploration_lifecycle_driver_routes_pause_resume_stop_as_session_commands() {
    let fixture = RunningSessionFixture::start(101).await;
    wait_for_quanta(&fixture.live, 1).await;

    let pause = fixture.pause().await;
    assert_eq!(pause.command, ExplorationLifecycleCommand::Pause);
    assert_eq!(pause.requested_state, LiveStateKind::Running);
    assert_eq!(pause.acknowledged_state, LiveStateKind::Paused);
    assert_bounded_ack(&pause);

    let resume = fixture.resume().await;
    assert_eq!(resume.command, ExplorationLifecycleCommand::Resume);
    assert_eq!(resume.requested_state, LiveStateKind::Paused);
    assert_eq!(resume.acknowledged_state, LiveStateKind::Running);
    assert_bounded_ack(&resume);

    let stop = fixture.stop().await;
    assert_eq!(stop.command, ExplorationLifecycleCommand::Stop);
    assert_eq!(stop.requested_state, LiveStateKind::Running);
    assert_eq!(stop.acknowledged_state, LiveStateKind::Stopped);
    assert_bounded_ack(&stop);

    let observed_control = Arc::clone(&fixture.observed_control);
    let report = fixture.join().await;
    assert!(matches!(
        report.final_snapshot.state,
        EngineState::Stopped {
            outcome: Outcome::Stopped
        }
    ));
    assert!(
        observed_control_operations(&observed_control).is_empty(),
        "pause/resume/stop must not be injected as scheduler-owned control operations"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn pause_resume_continue_matches_uninterrupted_canonical_run() {
    let fixture = RunningSessionFixture::start(202).await;
    wait_for_quanta(&fixture.live, 2).await;

    let first_pause = fixture.pause().await;
    assert_eq!(first_pause.acknowledged_state, LiveStateKind::Paused);
    assert_bounded_ack(&first_pause);
    assert!(
        first_pause.acknowledged_event_log_len >= first_pause.requested_event_log_len,
        "an in-flight quantum may complete before pause is acknowledged, but pause must not regress the log"
    );

    let resume = fixture.resume().await;
    assert_eq!(resume.acknowledged_state, LiveStateKind::Running);
    assert_bounded_ack(&resume);
    assert_eq!(
        resume.requested_event_log_len, resume.acknowledged_event_log_len,
        "resume/continue must not append canonical event-log entries by itself"
    );

    wait_for_quanta(&fixture.live, resume.acknowledged_at_quantum + 3).await;
    let second_pause = fixture.pause().await;
    assert_eq!(second_pause.acknowledged_state, LiveStateKind::Paused);
    assert_bounded_ack(&second_pause);

    let stop = fixture.stop().await;
    assert_eq!(stop.requested_state, LiveStateKind::Paused);
    assert_eq!(stop.acknowledged_state, LiveStateKind::Stopped);
    assert_eq!(stop.acknowledged_at_quantum, stop.requested_at_quantum);
    assert_eq!(
        stop.requested_event_log_len, stop.acknowledged_event_log_len,
        "stop from a pause boundary must not append canonical event-log entries"
    );

    let scenario = fixture.scenario.clone();
    let event_log = fixture.event_log.clone();
    let observed_control = Arc::clone(&fixture.observed_control);
    let report = fixture.join().await;
    let uninterrupted = run_uninterrupted(scenario, report.quanta);
    assert_eq!(
        report.final_snapshot.configuration.schedule,
        uninterrupted.snapshot.configuration.schedule
    );
    assert_eq!(
        report.final_snapshot.event_log_len,
        uninterrupted.snapshot.event_log_len
    );
    assert_eq!(
        event_log.len(),
        u64::try_from(report.final_snapshot.event_log_len)
            .unwrap_or_else(|error| panic!("event-log length should fit u64: {error}"))
    );
    assert_event_log_replay_is_exact(&event_log, &uninterrupted.event_log_entries).await;
    assert!(observed_control_operations(&observed_control).is_empty());
}

fn assert_bounded_ack(ack: &crucible_session::ExplorationLifecycleAcknowledgement) {
    let delta = ack
        .acknowledgement_delta_quanta()
        .unwrap_or_else(|| panic!("acknowledgement quantum should not move backward"));
    assert!(
        delta <= EXPLORATION_LIFECYCLE_RESPONSE_BOUND_QUANTA,
        "acknowledgement delta {delta} exceeded lifecycle bound"
    );
}

struct RunningSessionFixture {
    scenario: ScenarioDef,
    live: Arc<LiveSnapshot>,
    event_log: SessionEventLog,
    driver: ExplorationLifecycleDriver,
    actor_task: tokio::task::JoinHandle<Result<SessionRunReport, SessionError>>,
    observed_control: Arc<Mutex<Vec<ControlOperationKind>>>,
}

impl RunningSessionFixture {
    async fn start(seed: u64) -> Self {
        let scenario = generated_scenario(seed);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let observed_control = Arc::new(Mutex::new(Vec::new()));
        let engine = Engine::new(
            config,
            graph,
            AppendingLoop::new(Arc::clone(&observed_control)),
        );
        let (sender, receiver) = mpsc::channel(8);
        let actor = SessionActor::new(engine, receiver);
        let live = actor.live_snapshot();
        let event_log = actor.event_log();
        let driver = ExplorationLifecycleDriver::new(sender.clone(), Arc::clone(&live));
        let actor_task = tokio::spawn(async move { actor.run().await });

        send_command(&sender, SessionCommand::Start).await;
        send_command(&sender, SessionCommand::Continue).await;
        wait_until_state(&live, LiveStateKind::Running).await;

        Self {
            scenario,
            live,
            event_log,
            driver,
            actor_task,
            observed_control,
        }
    }

    async fn pause(&self) -> crucible_session::ExplorationLifecycleAcknowledgement {
        self.driver
            .pause()
            .await
            .unwrap_or_else(|error| panic!("exploration pause should be acknowledged: {error}"))
    }

    async fn resume(&self) -> crucible_session::ExplorationLifecycleAcknowledgement {
        self.driver
            .resume()
            .await
            .unwrap_or_else(|error| panic!("exploration resume should be acknowledged: {error}"))
    }

    async fn stop(&self) -> crucible_session::ExplorationLifecycleAcknowledgement {
        self.driver
            .stop()
            .await
            .unwrap_or_else(|error| panic!("exploration stop should be acknowledged: {error}"))
    }

    async fn join(self) -> SessionRunReport {
        match self.actor_task.await {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => panic!("session actor should stop cleanly: {error}"),
            Err(error) => panic!("session actor task should join cleanly: {error}"),
        }
    }
}

async fn send_command(sender: &mpsc::Sender<SessionCommand>, command: SessionCommand) {
    if let Err(error) = sender.send(command).await {
        panic!("session command should enqueue: {error}");
    }
}

async fn wait_until_state(live: &LiveSnapshot, state: LiveStateKind) {
    for _ in 0..128 {
        if live.read().state_kind == state {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("session should enter {state:?} within bounded actor yields");
}

async fn wait_for_quanta(live: &LiveSnapshot, quanta: u64) {
    for _ in 0..256 {
        if live.read().quanta_stepped >= quanta {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("session should reach {quanta} quanta within bounded actor yields");
}

async fn assert_event_log_replay_is_exact(
    event_log: &SessionEventLog,
    expected_entries: &[crucible::SchedulerEventLogEntry],
) {
    let mut stream = event_log.subscribe(EventLogCursor::default());
    for (expected_sequence, expected_entry) in expected_entries.iter().enumerate() {
        let frame = stream
            .recv()
            .await
            .unwrap_or_else(|error| panic!("event-log stream should not lag: {error}"))
            .unwrap_or_else(|| panic!("event-log stream should retain stopped run entries"));
        assert_eq!(
            frame.cursor.next_sequence,
            u64::try_from(expected_sequence)
                .unwrap_or_else(|error| panic!("sequence should fit u64: {error}"))
        );
        assert_eq!(frame.entry.sequence(), frame.cursor.next_sequence);
        assert_eq!(
            frame.entry, *expected_entry,
            "paused/resumed event-log entry must match uninterrupted entry {expected_sequence}"
        );
    }
}

struct UninterruptedRun {
    snapshot: crucible_session::EngineSnapshot,
    event_log_entries: Vec<crucible::SchedulerEventLogEntry>,
}

fn run_uninterrupted(scenario: ScenarioDef, quanta: u64) -> UninterruptedRun {
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(
        config,
        graph,
        AppendingLoop::new(Arc::new(Mutex::new(Vec::new()))),
    );
    engine
        .apply_command(SessionCommand::Start)
        .unwrap_or_else(|error| panic!("uninterrupted run should start: {error}"));
    engine
        .apply_command(SessionCommand::Continue)
        .unwrap_or_else(|error| panic!("uninterrupted run should continue: {error}"));
    for _ in 0..quanta {
        engine
            .step_quantum()
            .unwrap_or_else(|error| panic!("uninterrupted quantum should step: {error}"));
    }
    let snapshot = engine.snapshot();
    let event_log_entries = engine.into_quantum_loop().emitted_event_log_entries;
    UninterruptedRun {
        snapshot,
        event_log_entries,
    }
}

struct AppendingLoop {
    quanta: u64,
    event_log_events: u64,
    emitted_event_log_entries: Vec<crucible::SchedulerEventLogEntry>,
    observed_control: Arc<Mutex<Vec<ControlOperationKind>>>,
}

impl AppendingLoop {
    fn new(observed_control: Arc<Mutex<Vec<ControlOperationKind>>>) -> Self {
        Self {
            quanta: 0,
            event_log_events: 0,
            emitted_event_log_entries: Vec::new(),
            observed_control,
        }
    }
}

impl QuantumLoop for AppendingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let decision = generated_decision(self.quanta);
        let configuration = step(&request.configuration, decision.clone());
        record_control_operations(&self.observed_control, &request.control);
        let entry = test_event_log_entry(self.event_log_events, self.quanta);
        let event_log_entries = vec![entry.clone()];
        self.emitted_event_log_entries.push(entry);
        self.event_log_events = self.event_log_events.saturating_add(1);
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: request
                .control
                .into_iter()
                .map(|operation| resolved_control_operation(self.quanta, operation))
                .collect(),
            decisions: vec![decision],
            discovered_choices: Vec::new(),
            event_log_entries,
            event_log_segment_bytes: vec![b'x'],
            event_log_segment_text: String::from("x"),
            event_log_segment_hash: Some(crucible::ContentHash::from_bytes(b"x")),
            event_log_offset: crucible::EventLogOffset::new(
                Default::default(),
                0,
                self.event_log_events,
            ),
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
        "crucible.session.exploration-lifecycle",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}

fn generated_decision(seed: u64) -> Decision {
    let node = scheduler_node("exploration-driver");
    Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: seed },
        order: vec![EventKey::new(
            VirtualTime { ticks: seed },
            node.clone(),
            node,
            seed,
        )],
    })
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::ControlPlane,
    }
}

fn test_event_log_entry(sequence: u64, ticks: u64) -> crucible::SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        VirtualTime { ticks },
        crucible::SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn record_control_operations(
    observed_control: &Arc<Mutex<Vec<ControlOperationKind>>>,
    operations: &[ControlOperation],
) {
    let mut observed = observed_control
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    observed.extend(operations.iter().map(|operation| operation.kind.clone()));
}

fn observed_control_operations(
    observed_control: &Arc<Mutex<Vec<ControlOperationKind>>>,
) -> Vec<ControlOperationKind> {
    observed_control
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn resolved_control_operation(
    sequence: u64,
    operation: ControlOperation,
) -> crucible::ScheduledEvent {
    let node = scheduler_node("control-plane");
    crucible::ScheduledEvent {
        key: crucible::ScheduledEventKey::from_parts(
            VirtualTime { ticks: sequence },
            node.clone(),
            node,
            operation.sequence,
        ),
        payload: crucible::ScheduledEventPayload::Control(operation),
    }
}
