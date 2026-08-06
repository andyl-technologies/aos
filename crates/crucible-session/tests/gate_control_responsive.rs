//! Session-side `gate:control-responsive` latency check.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crucible::{
    BackendEffect, BackendInput, Checkpoint, CheckpointKind, Configuration, ControlOperation,
    ControlOperationKind, Decision, DeliveryOrderDecision, EventClass, EventDiagnosticPayload,
    EventKey, EventLevel, EventSource, GenesisCheckpoint, NodeId, QuantumLoop, QuantumOutcome,
    QuantumRequest, ScenarioDef, ScheduledEvent, ScheduledEventKey, SchedulerError,
    SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerNodeId, SchedulingNodeKind, Seed,
    SimDouble, SimDoubleConfig, SimulationBackend, TemporalGraph, VirtualTime,
    compare_event_log_determinism, step,
};
use crucible_protocol::{CONTROL_PROTOCOL_VERSION, HostMsg, control_encode_host_msg};
use crucible_session::{
    Engine, EngineState, EventLogCursor, LiveQueryKind, LiveQueryResult, LiveStateKind, Outcome,
    PauseReason, SessionActor, SessionCommand,
};
use tokio::sync::mpsc;

const CONTROL_RESPONSIVE_BACKEND: &str = "crucible::SimDouble quantum-loop adapter";
const CONTROL_RESPONSIVE_REQUIRES_REAL_QEMU: bool = false;
const FIDELITY_PROPERTIES_REQUIRING_QEMU: [&str; 3] =
    ["contract-a", "guest-non-mutation", "patch-inertness"];

#[test]
fn gate_control_responsive_declares_in_process_sim_double_backend() {
    assert_eq!(
        CONTROL_RESPONSIVE_BACKEND,
        "crucible::SimDouble quantum-loop adapter"
    );
    const { assert!(!CONTROL_RESPONSIVE_REQUIRES_REAL_QEMU) };
    assert_eq!(
        FIDELITY_PROPERTIES_REQUIRING_QEMU,
        ["contract-a", "guest-non-mutation", "patch-inertness"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn gate_control_responsive_reads_live_snapshot_without_mailbox_roundtrip() {
    let scenario = generated_scenario(31);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let observed_control = Arc::new(Mutex::new(Vec::new()));
    let engine = Engine::new(
        config,
        graph,
        SimDoubleQuantumLoop::new(Arc::clone(&observed_control)),
    );
    let (sender, receiver) = mpsc::channel(8);
    let actor = SessionActor::new(engine, receiver);
    let live = actor.live_snapshot();
    let actor_task = tokio::spawn(async move { actor.run().await });

    send_command(&sender, SessionCommand::Start).await;
    send_command(&sender, SessionCommand::Continue).await;
    wait_until_running(&live).await;

    let mut last = live.read();
    let mut observed_progress = false;
    for _ in 0..128 {
        tokio::task::yield_now().await;
        let current = live.read();
        assert!(current.quanta_stepped >= last.quanta_stepped);
        assert!(current.virtual_time >= last.virtual_time);
        if current.quanta_stepped >= 3 {
            observed_progress = true;
            last = current;
            break;
        }
        last = current;
    }

    assert!(observed_progress);
    assert_eq!(last.state_kind, LiveStateKind::Running);
    assert!(last.event_log_len >= last.quanta_stepped);

    let snapshot_acknowledged =
        acknowledge_operation(&sender, &live, SessionCommand::Snapshot, "snapshot").await;
    assert_eq!(snapshot_acknowledged.state_kind, LiveStateKind::Running);
    let inject_acknowledged =
        acknowledge_operation(&sender, &live, SessionCommand::Inject, "inject").await;
    assert_eq!(inject_acknowledged.state_kind, LiveStateKind::Running);
    assert_eq!(
        live.query(LiveQueryKind::Status),
        LiveQueryResult::Status(inject_acknowledged)
    );
    assert_eq!(
        live.query(LiveQueryKind::State),
        LiveQueryResult::State(crucible_session::LifecycleStateKind::Running)
    );
    assert_eq!(
        live.query(LiveQueryKind::EventLogLength),
        LiveQueryResult::EventLogLength(inject_acknowledged.event_log_len)
    );
    assert_eq!(
        observed_control_operations(&observed_control),
        vec![ControlOperationKind::Snapshot, ControlOperationKind::Inject,]
    );

    let paused = acknowledge_operation(&sender, &live, SessionCommand::Pause, "pause").await;
    assert_eq!(paused.state_kind, LiveStateKind::Paused);
    let fork_acknowledged =
        acknowledge_boundary_operation(&sender, &live, SessionCommand::fork_current(), "fork")
            .await;
    assert_eq!(fork_acknowledged.state_kind, LiveStateKind::Paused);

    send_command(&sender, SessionCommand::Continue).await;
    send_command(&sender, SessionCommand::Stop).await;
    let stop_requested_after = live.read();

    let mut stop_acknowledged = false;
    for _ in 0..128 {
        if actor_task.is_finished() {
            stop_acknowledged = true;
            break;
        }
        tokio::task::yield_now().await;
    }

    if !stop_acknowledged {
        actor_task.abort();
        panic!("stop command should be acknowledged within bounded actor yields");
    }

    let report = match actor_task.await {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => panic!("actor should stop cleanly: {error}"),
        Err(error) => panic!("actor task should join cleanly: {error}"),
    };

    assert!(report.quanta >= last.quanta_stepped);
    assert!(report.quanta >= stop_requested_after.quanta_stepped);
    let quanta_after_stop_request = report
        .quanta
        .saturating_sub(stop_requested_after.quanta_stepped);
    assert!(
        quanta_after_stop_request <= 1,
        "stop command should be acknowledged within one post-request quantum, observed {quanta_after_stop_request}"
    );
    assert_eq!(report.final_snapshot.quanta, report.quanta);
}

#[tokio::test(flavor = "current_thread")]
async fn gate_control_responsive_acknowledges_query_command_within_quantum_bound() {
    let scenario = generated_scenario(39);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let observed_control = Arc::new(Mutex::new(Vec::new()));
    let engine = Engine::new(
        config,
        graph,
        SimDoubleQuantumLoop::new(Arc::clone(&observed_control)),
    );
    let (sender, receiver) = mpsc::channel(8);
    let actor = SessionActor::new(engine, receiver);
    let live = actor.live_snapshot();
    let actor_task = tokio::spawn(async move { actor.run().await });

    send_command(&sender, SessionCommand::Start).await;
    send_command(&sender, SessionCommand::Continue).await;
    wait_until_running(&live).await;

    let query_acknowledged =
        acknowledge_operation(&sender, &live, SessionCommand::query_snapshot(), "query").await;
    assert_eq!(query_acknowledged.state_kind, LiveStateKind::Running);
    assert_eq!(
        observed_control_operations(&observed_control),
        vec![ControlOperationKind::Query]
    );

    send_command(&sender, SessionCommand::Stop).await;
    match actor_task.await {
        Ok(Ok(report)) => {
            assert!(report.quanta >= query_acknowledged.quanta_stepped);
        }
        Ok(Err(error)) => panic!("actor should stop cleanly: {error}"),
        Err(error) => panic!("actor task should join cleanly: {error}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn gate_control_plane_streams_event_log_entries_from_cursor_without_mutation() {
    let scenario = generated_scenario(41);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let observed_control = Arc::new(Mutex::new(Vec::new()));
    let engine = Engine::new(
        config,
        graph,
        SimDoubleQuantumLoop::new(Arc::clone(&observed_control)),
    );
    let (sender, receiver) = mpsc::channel(8);
    let actor = SessionActor::new(engine, receiver);
    let live = actor.live_snapshot();
    let event_log = actor.event_log();
    let mut stream = event_log.subscribe(EventLogCursor::default());
    let mut future_stream = event_log.subscribe(EventLogCursor::new(10_000));
    assert_eq!(future_stream.cursor(), EventLogCursor::default());
    let actor_task = tokio::spawn(async move { actor.run().await });

    send_command(&sender, SessionCommand::Start).await;
    send_command(&sender, SessionCommand::Continue).await;
    wait_until_running(&live).await;
    let future_frame = future_stream
        .recv()
        .await
        .unwrap_or_else(|error| panic!("future cursor stream should not lag: {error}"))
        .unwrap_or_else(|| panic!("future cursor stream should deliver live entries"));
    assert_eq!(future_frame.cursor, EventLogCursor::default());

    acknowledge_operation(&sender, &live, SessionCommand::Inject, "stream-inject").await;
    send_command(&sender, SessionCommand::Pause).await;

    let mut streamed = Vec::new();
    for _ in 0..128 {
        let frame = stream
            .recv()
            .await
            .unwrap_or_else(|error| panic!("event-log stream should not lag: {error}"))
            .unwrap_or_else(|| panic!("event-log stream should stay open while actor runs"));
        streamed.push(frame.entry.clone());
        let has_causal = streamed
            .iter()
            .any(|entry| entry.class() == EventClass::Causal);
        let has_observational = streamed
            .iter()
            .any(|entry| entry.class() == EventClass::Observational);
        let has_command = streamed
            .iter()
            .any(|entry| matches!(entry.source(), EventSource::Command { command_id } if *command_id == 1));
        if has_causal && has_observational && has_command {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert!(
        streamed
            .iter()
            .any(|entry| entry.class() == EventClass::Causal)
    );
    assert!(
        streamed
            .iter()
            .any(|entry| entry.class() == EventClass::Observational)
    );
    assert!(streamed.iter().any(
        |entry| matches!(entry.source(), EventSource::Command { command_id } if *command_id == 1)
    ));
    let comparison = compare_event_log_determinism(&streamed, &streamed);
    assert!(comparison.passes());

    let cursor = EventLogCursor::new(1);
    let mut replay_from_cursor = event_log.subscribe(cursor);
    let first_from_cursor = replay_from_cursor
        .recv()
        .await
        .unwrap_or_else(|error| panic!("cursor stream should not lag: {error}"))
        .unwrap_or_else(|| panic!("cursor stream should return retained entries"));
    assert!(first_from_cursor.entry.sequence() >= cursor.next_sequence);
    assert_eq!(replay_from_cursor.cursor(), first_from_cursor.next_cursor);

    wait_until_paused(&live).await;
    let before_subscribe = live.read();
    let observation_only = event_log.subscribe(EventLogCursor::new(before_subscribe.event_log_len));
    drop(observation_only);
    let after_unsubscribe = live.read();
    assert_eq!(after_unsubscribe, before_subscribe);

    send_command(&sender, SessionCommand::Stop).await;
    match actor_task.await {
        Ok(Ok(report)) => {
            assert!(report.final_snapshot.event_log_len >= streamed.len());
        }
        Ok(Err(error)) => panic!("actor should stop cleanly: {error}"),
        Err(error) => panic!("actor task should join cleanly: {error}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn gate_control_plane_streams_state_transitions_without_mailbox_roundtrip() {
    let scenario = generated_scenario(43);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let observed_control = Arc::new(Mutex::new(Vec::new()));
    let engine = Engine::new(
        config,
        graph,
        SimDoubleQuantumLoop::new(Arc::clone(&observed_control)),
    );
    let (sender, receiver) = mpsc::channel(8);
    let actor = SessionActor::new(engine, receiver);
    let live = actor.live_snapshot();
    let state_transitions = actor.state_transition_bus();
    let mut stream = state_transitions.subscribe();
    let actor_task = tokio::spawn(async move { actor.run().await });

    send_command(&sender, SessionCommand::Start).await;
    let started = receive_state_transition(&mut stream).await;
    assert_eq!(started.sequence, 1);
    assert_eq!(started.from_state, EngineState::Loaded);
    assert_eq!(
        started.to_state,
        EngineState::Paused {
            reason: PauseReason::Instantiated,
        }
    );
    assert_eq!(started.from.state_kind, LiveStateKind::Loaded);
    assert_eq!(started.to.state_kind, LiveStateKind::Paused);

    send_command(&sender, SessionCommand::Continue).await;
    let continued = receive_state_transition(&mut stream).await;
    assert_eq!(continued.sequence, 2);
    assert_eq!(
        continued.from_state,
        EngineState::Paused {
            reason: PauseReason::Instantiated,
        }
    );
    assert_eq!(continued.to_state, EngineState::Running);
    assert_eq!(continued.from.state_kind, LiveStateKind::Paused);
    assert_eq!(continued.to.state_kind, LiveStateKind::Running);
    wait_until_running(&live).await;

    send_command(&sender, SessionCommand::Pause).await;
    let paused = receive_state_transition(&mut stream).await;
    assert_eq!(paused.sequence, 3);
    assert_eq!(paused.from_state, EngineState::Running);
    assert_eq!(
        paused.to_state,
        EngineState::Paused {
            reason: PauseReason::UserRequested,
        }
    );
    assert_eq!(paused.from.state_kind, LiveStateKind::Running);
    assert_eq!(paused.to.state_kind, LiveStateKind::Paused);
    wait_until_paused(&live).await;

    let before_observation = live.read();
    let observation_only = state_transitions.subscribe();
    drop(observation_only);
    assert_eq!(live.read(), before_observation);

    send_command(&sender, SessionCommand::Stop).await;
    let stopped = receive_state_transition(&mut stream).await;
    assert_eq!(stopped.sequence, 4);
    assert_eq!(
        stopped.from_state,
        EngineState::Paused {
            reason: PauseReason::UserRequested,
        }
    );
    assert_eq!(
        stopped.to_state,
        EngineState::Stopped {
            outcome: Outcome::Stopped,
        }
    );
    assert_eq!(stopped.from.state_kind, LiveStateKind::Paused);
    assert_eq!(stopped.to.state_kind, LiveStateKind::Stopped);

    match actor_task.await {
        Ok(Ok(report)) => {
            assert_eq!(
                report.final_snapshot.state,
                EngineState::Stopped {
                    outcome: Outcome::Stopped,
                },
            );
        }
        Ok(Err(error)) => panic!("actor should stop cleanly: {error}"),
        Err(error) => panic!("actor task should join cleanly: {error}"),
    }
}

async fn send_command(sender: &mpsc::Sender<SessionCommand>, command: SessionCommand) {
    if let Err(error) = sender.send(command).await {
        panic!("session command should enqueue: {error}");
    }
}

async fn wait_until_running(live: &crucible_session::LiveSnapshot) {
    for _ in 0..128 {
        if live.read().state_kind == LiveStateKind::Running {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("session should enter Running within bounded actor yields");
}

async fn wait_until_paused(live: &crucible_session::LiveSnapshot) {
    for _ in 0..128 {
        if live.read().state_kind == LiveStateKind::Paused {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("session should enter Paused within bounded actor yields");
}

async fn acknowledge_operation(
    sender: &mpsc::Sender<SessionCommand>,
    live: &crucible_session::LiveSnapshot,
    command: SessionCommand,
    operation: &'static str,
) -> crucible_session::LiveSnapshotView {
    let requested_after = live.read();
    assert_eq!(requested_after.state_kind, LiveStateKind::Running);
    let acknowledgements_before = requested_after.control_acknowledgements;

    send_command(sender, command).await;

    for _ in 0..128 {
        let current = live.read();
        if current.control_acknowledgements > acknowledgements_before {
            let quanta_after_request = current
                .quanta_stepped
                .saturating_sub(requested_after.quanta_stepped);
            assert!(
                quanta_after_request <= 1,
                "{operation} command should be acknowledged within one post-request quantum, observed {quanta_after_request}"
            );
            return current;
        }
        tokio::task::yield_now().await;
    }

    panic!("{operation} command should be acknowledged within bounded actor yields");
}

async fn acknowledge_boundary_operation(
    sender: &mpsc::Sender<SessionCommand>,
    live: &crucible_session::LiveSnapshot,
    command: SessionCommand,
    operation: &'static str,
) -> crucible_session::LiveSnapshotView {
    let requested_after = live.read();
    assert_eq!(requested_after.state_kind, LiveStateKind::Paused);
    let acknowledgements_before = requested_after.control_acknowledgements;

    send_command(sender, command).await;

    for _ in 0..128 {
        let current = live.read();
        if current.control_acknowledgements > acknowledgements_before {
            return current;
        }
        tokio::task::yield_now().await;
    }

    panic!("{operation} boundary command should be acknowledged within bounded actor yields");
}

async fn receive_state_transition(
    stream: &mut crucible_session::SessionStateTransitionStream,
) -> crucible_session::SessionStateTransitionFrame {
    match stream.recv().await {
        Ok(Some(frame)) => frame,
        Ok(None) => panic!("state-transition stream should remain open while actor runs"),
        Err(error) => panic!("state-transition stream should not lag: {error}"),
    }
}

struct SimDoubleQuantumLoop {
    backend: SimDouble,
    quanta: u64,
    event_log_events: u64,
    observed_control: Arc<Mutex<Vec<ControlOperationKind>>>,
}

impl SimDoubleQuantumLoop {
    fn new(observed_control: Arc<Mutex<Vec<ControlOperationKind>>>) -> Self {
        Self {
            backend: ready_sim_double(),
            quanta: 0,
            event_log_events: 0,
            observed_control,
        }
    }
}

impl QuantumLoop for SimDoubleQuantumLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        self.apply_backend_control(&request.control)?;
        let observation =
            SimulationBackend::step_to(&mut self.backend, VirtualTime { ticks: self.quanta })?;
        assert_eq!(observation.reached, VirtualTime { ticks: self.quanta });
        let decision = generated_decision(self.quanta);
        let configuration = step(&request.configuration, decision.clone());
        let control = request.control;
        record_control_operations(&self.observed_control, &control);
        let event_log_entries = self.event_log_entries(&control);
        let mut resolved_events: Vec<_> = control
            .into_iter()
            .map(|operation| resolved_control_operation(self.quanta, operation))
            .collect();
        resolved_events.push(resolved_control_event(self.quanta));
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events,
            decisions: vec![decision],
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

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.apply_backend_control(&control)?;
        record_control_operations(&self.observed_control, &control);
        Ok(self.event_log_entries(&control))
    }
}

impl SimDoubleQuantumLoop {
    fn apply_backend_control(
        &mut self,
        control: &[ControlOperation],
    ) -> Result<(), SchedulerError> {
        for operation in control {
            match &operation.kind {
                ControlOperationKind::Snapshot => {
                    let _snapshot = SimulationBackend::snapshot(&mut self.backend)?;
                }
                ControlOperationKind::Query => {
                    let _fingerprint =
                        SimulationBackend::fingerprint(&mut self.backend, control_node().node)?;
                }
                ControlOperationKind::Inject => {
                    let input = BackendInput {
                        node: control_node().node,
                        payload: b"session-control-inject".to_vec(),
                    };
                    let now = SimulationBackend::now(&self.backend);
                    SimulationBackend::apply(
                        &mut self.backend,
                        &BackendEffect::DeliverInput(input),
                        now,
                    )?;
                }
                ControlOperationKind::Pause
                | ControlOperationKind::Resume
                | ControlOperationKind::Step
                | ControlOperationKind::Fork => {
                    let now = SimulationBackend::now(&self.backend);
                    SimulationBackend::apply(&mut self.backend, &BackendEffect::Noop, now)?;
                }
            }
        }
        Ok(())
    }

    fn event_log_entries(&mut self, control: &[ControlOperation]) -> Vec<SchedulerEventLogEntry> {
        let base = self.event_log_events;
        let mut entries = Vec::new();
        for operation in control {
            if let Some(entry) =
                control_operation_log_entry(base + entries.len() as u64, self.quanta, operation)
            {
                entries.push(entry);
            }
        }
        entries.push(crucible::test_support::condition_payload_entry_for_test(
            base + entries.len() as u64,
            VirtualTime { ticks: self.quanta },
            SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
                "session.event-log.stream",
                EventLevel::Debug,
                BTreeMap::new(),
            )),
        ));
        entries.push(crucible::test_support::condition_boundary_entry_for_test(
            base + entries.len() as u64,
            VirtualTime { ticks: self.quanta },
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        ));
        self.event_log_events = self
            .event_log_events
            .saturating_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));
        entries
    }
}

fn ready_sim_double() -> SimDouble {
    let mut backend = SimDouble::new(SimDoubleConfig::default())
        .unwrap_or_else(|error| panic!("SimDouble test backend should build: {error}"));
    complete_sim_double_setup(&mut backend);
    backend
}

fn complete_sim_double_setup(backend: &mut SimDouble) {
    let hello_ack = control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: backend.shmem_header_snapshot().abi_version,
        slot_index: 0,
        node_count: backend.shmem_layout().node_count,
    });
    if let Err(error) = backend.accept_host_control_frame(&hello_ack) {
        panic!("SimDouble hello acknowledgement should succeed: {error}");
    }

    let setup = control_encode_host_msg(&HostMsg::Setup {
        region_len: backend.shmem_layout().region_size,
    });
    match backend.accept_host_control_frame(&setup) {
        Ok(Some(_setup_ack)) => {}
        Ok(None) => panic!("SimDouble setup should return a setup acknowledgement"),
        Err(error) => panic!("SimDouble setup should succeed: {error}"),
    }
}

fn control_operation_log_entry(
    _sequence: u64,
    _ticks: u64,
    _operation: &ControlOperation,
) -> Option<SchedulerEventLogEntry> {
    None
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

fn resolved_control_operation(sequence: u64, operation: ControlOperation) -> ScheduledEvent {
    let node = control_node();
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime { ticks: sequence },
            node.clone(),
            node,
            operation.sequence,
        ),
        payload: crucible::ScheduledEventPayload::Control(operation),
    }
}

fn resolved_control_event(sequence: u64) -> ScheduledEvent {
    let node = control_node();
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime { ticks: sequence },
            node.clone(),
            node,
            sequence,
        ),
        payload: crucible::ScheduledEventPayload::Control(ControlOperation {
            sequence,
            kind: ControlOperationKind::Query,
        }),
    }
}

fn control_node() -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: String::from("control-plane"),
        },
        kind: SchedulingNodeKind::ControlPlane,
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
        "crucible.session.gate-control-responsive.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}

fn generated_decision(seed: u64) -> Decision {
    let node = control_node();
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
