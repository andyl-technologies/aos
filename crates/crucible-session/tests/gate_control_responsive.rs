//! Session-side `gate:control-responsive` latency check.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ControlOperation, ControlOperationKind, Decision,
    DeliveryOrderDecision, EventKey, GenesisCheckpoint, NodeId, QuantumLoop, QuantumOutcome,
    QuantumRequest, ScenarioDef, ScheduledEvent, ScheduledEventKey, SchedulerError,
    SchedulerNodeId, SchedulingNodeKind, Seed, TemporalGraph, VirtualTime, step,
};
use crucible_session::{Engine, LiveStateKind, SessionActor, SessionCommand};
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

async fn send_command(sender: &mpsc::Sender<SessionCommand>, command: SessionCommand) {
    if let Err(error) = sender.send(command).await {
        panic!("session command should enqueue: {error}");
    }
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
    observed_control: Arc<Mutex<Vec<ControlOperationKind>>>,
}

impl SimDoubleQuantumLoop {
    fn new(observed_control: Arc<Mutex<Vec<ControlOperationKind>>>) -> Self {
        Self {
            quanta: 0,
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
        })
    }
}

fn record_control_operations(
    observed_control: &Arc<Mutex<Vec<ControlOperationKind>>>,
    operations: &[ControlOperation],
) {
    let mut observed = observed_control
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    observed.extend(operations.iter().map(|operation| operation.kind));
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
