//! Session-side `gate:control-responsive` latency check.

#![forbid(unsafe_code)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, ControlOperation, ControlOperationKind,
    Decision, DeliveryOrderDecision, EventKey, GenesisCheckpoint, NodeId, QuantumLoop,
    QuantumOutcome, QuantumRequest, ScenarioDef, ScheduledEvent, ScheduledEventKey, SchedulerError,
    SchedulerNodeId, SchedulingNodeKind, TemporalGraph, VirtualTime, step,
};
use crucible_session::{Engine, LiveStateKind, SessionActor, SessionCommand};
use tokio::sync::mpsc;

#[tokio::test]
async fn gate_control_responsive_reads_live_snapshot_without_mailbox_roundtrip() {
    let scenario = generated_scenario(31);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, AppendingLoop::default());
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
    send_command(&sender, SessionCommand::Stop).await;

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
    assert_eq!(report.final_snapshot.quanta, report.quanta);
}

async fn send_command(sender: &mpsc::Sender<SessionCommand>, command: SessionCommand) {
    if let Err(error) = sender.send(command).await {
        panic!("session command should enqueue: {error}");
    }
}

#[derive(Default)]
struct AppendingLoop {
    quanta: u64,
}

impl QuantumLoop for AppendingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let decision = generated_decision(self.quanta);
        let configuration = step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: vec![resolved_control_event(self.quanta)],
            decisions: vec![decision],
        })
    }
}

fn resolved_control_event(sequence: u64) -> ScheduledEvent {
    let node = SchedulerNodeId {
        node: NodeId {
            name: String::from("control-plane"),
        },
        kind: SchedulingNodeKind::ControlPlane,
    };
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

fn graph_with_baked_genesis(scenario: &ScenarioDef) -> TemporalGraph {
    let genesis = Configuration::genesis(scenario.clone());
    match TemporalGraph::empty().with_baked_genesis(scenario, genesis_checkpoint(&genesis)) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    }
}

fn genesis_checkpoint(configuration: &Configuration) -> GenesisCheckpoint {
    GenesisCheckpoint {
        checkpoint: Checkpoint::new(
            ContentHash::from_canonical_material(
                "crucible.session.gate-control-responsive.baked-genesis",
                &format!("{:?}", configuration.id().bytes),
            ),
            configuration.id(),
            CheckpointKind::Fat,
        ),
    }
}

fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material(
        "crucible.session.gate-control-responsive.scenario",
        &format!("seed={seed}"),
    )
}

fn generated_decision(seed: u64) -> Decision {
    Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: seed },
        order: vec![EventKey { sequence: seed }],
    })
}
