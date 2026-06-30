//! Session-side `gate:control-responsive` latency check.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ControlFaultAction, ControlFaultDecision,
    ControlOperation, ControlOperationKind, Decision, DeliveryOrderDecision, EventClass,
    EventDiagnosticPayload, EventKey, EventLevel, EventSource, Fault,
    FaultSlowdownFactorBasisPoints, FaultTag, GenesisCheckpoint, NodeFault, NodeId, QuantumLoop,
    QuantumOutcome, QuantumRequest, ScenarioDef, ScheduledEvent, ScheduledEventKey, SchedulerError,
    SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerNodeId, SchedulingNodeKind, Seed,
    TemporalGraph, VirtualTime, compare_event_log_determinism, step,
};
use crucible_session::{Engine, EventLogCursor, LiveStateKind, SessionActor, SessionCommand};
use tokio::sync::mpsc;

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
    let fork_acknowledged =
        acknowledge_operation(&sender, &live, SessionCommand::Fork, "fork").await;
    assert_eq!(fork_acknowledged.state_kind, LiveStateKind::Running);
    let inject_acknowledged =
        acknowledge_operation(&sender, &live, SessionCommand::Inject, "inject").await;
    assert_eq!(inject_acknowledged.state_kind, LiveStateKind::Running);
    let query_acknowledged =
        acknowledge_operation(&sender, &live, SessionCommand::Query, "query").await;
    assert_eq!(query_acknowledged.state_kind, LiveStateKind::Running);
    assert_eq!(
        observed_control_operations(&observed_control),
        vec![
            ControlOperationKind::Snapshot,
            ControlOperationKind::Fork,
            ControlOperationKind::Inject,
            ControlOperationKind::Query,
        ]
    );

    let paused = acknowledge_operation(&sender, &live, SessionCommand::Pause, "pause").await;
    assert_eq!(paused.state_kind, LiveStateKind::Paused);

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
async fn gate_control_responsive_accepts_typed_fault_control_commands() {
    let scenario = generated_scenario(37);
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

    let tag = FaultTag::from_name("slow-db0");
    let fault = Fault::Node(NodeFault::Slow {
        node: NodeId {
            name: String::from("node-a"),
        },
        factor: FaultSlowdownFactorBasisPoints::from_basis_points(20_000)
            .unwrap_or_else(|error| panic!("valid slowdown factor: {error}")),
    });
    let inject_acknowledged = acknowledge_operation(
        &sender,
        &live,
        SessionCommand::InjectFault {
            tag: tag.clone(),
            fault: fault.clone(),
        },
        "inject-fault",
    )
    .await;
    assert_eq!(inject_acknowledged.state_kind, LiveStateKind::Running);
    let heal_acknowledged = acknowledge_operation(
        &sender,
        &live,
        SessionCommand::HealFault { tag: tag.clone() },
        "heal-fault",
    )
    .await;
    assert_eq!(heal_acknowledged.state_kind, LiveStateKind::Running);

    assert_eq!(
        observed_control_operations(&observed_control),
        vec![
            ControlOperationKind::InjectFault {
                tag: tag.clone(),
                fault,
            },
            ControlOperationKind::HealFault { tag },
        ]
    );

    send_command(&sender, SessionCommand::Stop).await;
    let report = match actor_task.await {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => panic!("actor should stop cleanly: {error}"),
        Err(error) => panic!("actor task should join cleanly: {error}"),
    };
    assert!(report.quanta >= heal_acknowledged.quanta_stepped);
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

    let tag = FaultTag::from_name("streamed-control");
    let fault = Fault::Node(NodeFault::Slow {
        node: NodeId {
            name: String::from("node-a"),
        },
        factor: FaultSlowdownFactorBasisPoints::from_basis_points(20_000)
            .unwrap_or_else(|error| panic!("valid slowdown factor: {error}")),
    });
    acknowledge_operation(
        &sender,
        &live,
        SessionCommand::InjectFault {
            tag: tag.clone(),
            fault,
        },
        "stream-inject-fault",
    )
    .await;
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

#[derive(Default)]
struct SimDoubleQuantumLoop {
    quanta: u64,
    event_log_events: u64,
    observed_control: Arc<Mutex<Vec<ControlOperationKind>>>,
}

impl SimDoubleQuantumLoop {
    fn new(observed_control: Arc<Mutex<Vec<ControlOperationKind>>>) -> Self {
        Self {
            quanta: 0,
            event_log_events: 0,
            observed_control,
        }
    }
}

impl QuantumLoop for SimDoubleQuantumLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
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
        })
    }
}

impl SimDoubleQuantumLoop {
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

fn control_operation_log_entry(
    sequence: u64,
    ticks: u64,
    operation: &ControlOperation,
) -> Option<SchedulerEventLogEntry> {
    let action = match &operation.kind {
        ControlOperationKind::InjectFault { tag, fault } => ControlFaultAction::Inject {
            tag: tag.clone(),
            fault: fault.clone(),
        },
        ControlOperationKind::HealFault { tag } => ControlFaultAction::Heal { tag: tag.clone() },
        ControlOperationKind::Pause
        | ControlOperationKind::Resume
        | ControlOperationKind::Step
        | ControlOperationKind::Snapshot
        | ControlOperationKind::Fork
        | ControlOperationKind::Inject
        | ControlOperationKind::Query => return None,
    };
    Some(crucible::test_support::condition_payload_entry_for_test(
        sequence,
        VirtualTime { ticks },
        SchedulerEventLogPayload::Decision(Decision::ControlFault(ControlFaultDecision {
            at: VirtualTime { ticks },
            sequence: operation.sequence,
            action,
        })),
    ))
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
    let node = SchedulerNodeId {
        node: NodeId {
            name: String::from("control-plane"),
        },
        kind: SchedulingNodeKind::ControlPlane,
    };
    node
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
