//! Daemon-side `gate:control-responsive` acknowledgement checks.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use crucible::{
    Checkpoint, CheckpointKind, Configuration,
    ControlOperationKind as SchedulerControlOperationKind, Decision, DeliveryOrderDecision,
    EventKey, GenesisCheckpoint, NodeId, QuantumLoop, QuantumOutcome, QuantumRequest, ScenarioDef,
    SchedulerError, SchedulerNodeId, SchedulingNodeKind, Seed, TemporalGraph, VirtualTime, step,
};
use crucible_api::{
    ControlAcknowledgementStatus, ControlOperationAcknowledgement, ControlOperationKind,
    ControlResponsivenessError, ControlSessionState,
};
use crucible_daemon::{
    DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND, DaemonControlResponsiveRoute,
    validate_daemon_control_responsiveness,
};
use crucible_session::{Engine, SessionActor, SessionCommand, SessionError, SessionRunReport};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[tokio::test(flavor = "current_thread")]
async fn gate_control_responsive_daemon_routes_use_api_quantum_bound() {
    let fixture = RunningSimDoubleControlPlane::spawn().await;
    let route = DaemonControlResponsiveRoute::new(fixture.probe.clone());
    let mut acknowledgements = Vec::new();

    for operation in [
        ControlOperationKind::Snapshot,
        ControlOperationKind::Fork,
        ControlOperationKind::Inject,
        ControlOperationKind::Query,
        ControlOperationKind::Pause,
    ] {
        let acknowledgement = route
            .issue_against_running_session(operation)
            .await
            .unwrap_or_else(|error| {
                panic!("daemon route should acknowledge {operation:?}: {error}")
            });
        acknowledgements.push(acknowledgement);
    }
    assert_eq!(
        fixture.observed_control_operations(),
        vec![
            SchedulerControlOperationKind::Snapshot,
            SchedulerControlOperationKind::Fork,
            SchedulerControlOperationKind::Inject,
            SchedulerControlOperationKind::Query,
        ]
    );

    let report = validate_daemon_control_responsiveness(&acknowledgements)
        .unwrap_or_else(|error| panic!("daemon route evidence should satisfy gate: {error}"));

    assert_eq!(DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND, 1);
    assert_eq!(report.bound_quanta, DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND);
    assert_eq!(report.observations, acknowledgements.len());
    assert_eq!(report.required_operations_observed, 5);
    assert!(report.max_acknowledgement_delta_quanta <= 1);

    fixture.stop().await;
}

#[test]
fn gate_control_responsive_daemon_rejects_required_operation_rejection() {
    let acknowledgements = [
        applied_acknowledgement(ControlOperationKind::Snapshot, 10),
        applied_acknowledgement(ControlOperationKind::Fork, 11),
        ControlOperationAcknowledgement::new(
            ControlOperationKind::Inject,
            ControlSessionState::Running,
            12,
            12,
            ControlAcknowledgementStatus::Rejected,
        ),
        applied_acknowledgement(ControlOperationKind::Query, 13),
        applied_acknowledgement(ControlOperationKind::Pause, 14),
    ];

    let error = validate_daemon_control_responsiveness(&acknowledgements)
        .expect_err("daemon validator must reject rejected required operations");
    assert_eq!(
        error,
        ControlResponsivenessError::RequiredOperationRejected {
            operation: ControlOperationKind::Inject,
            status: ControlAcknowledgementStatus::Rejected,
        }
    );
}

fn applied_acknowledgement(
    operation: ControlOperationKind,
    quantum: u64,
) -> ControlOperationAcknowledgement {
    ControlOperationAcknowledgement::new(
        operation,
        ControlSessionState::Running,
        quantum,
        quantum,
        ControlAcknowledgementStatus::Applied,
    )
}

struct RunningSimDoubleControlPlane {
    sender: mpsc::Sender<SessionCommand>,
    actor_task: JoinHandle<Result<SessionRunReport, SessionError>>,
    probe: crucible_api::ControlResponsiveSessionProbe,
    observed_control: Arc<Mutex<Vec<SchedulerControlOperationKind>>>,
}

impl RunningSimDoubleControlPlane {
    async fn spawn() -> Self {
        let scenario = generated_scenario(51);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let observed_control = Arc::new(Mutex::new(Vec::new()));
        let engine = Engine::new(
            config,
            graph,
            SimDoubleQuantumLoop::new(Arc::clone(&observed_control)),
        );
        let (sender, receiver) = mpsc::channel(16);
        let actor = SessionActor::new(engine, receiver);
        let live = actor.live_snapshot();
        let actor_task = tokio::spawn(async move { actor.run().await });

        send_command(&sender, SessionCommand::Start).await;
        send_command(&sender, SessionCommand::Continue).await;

        for _ in 0..128 {
            if live.read().state_kind == crucible_session::LiveStateKind::Running {
                let probe = crucible_api::ControlResponsiveSessionProbe::new(sender.clone(), live);
                return Self {
                    sender,
                    actor_task,
                    probe,
                    observed_control,
                };
            }
            tokio::task::yield_now().await;
        }

        panic!("SimDouble daemon control-plane session should enter Running");
    }

    fn observed_control_operations(&self) -> Vec<SchedulerControlOperationKind> {
        self.observed_control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    async fn stop(self) {
        send_command(&self.sender, SessionCommand::Stop).await;
        match self.actor_task.await {
            Ok(Ok(_report)) => {}
            Ok(Err(error)) => panic!("actor should stop cleanly: {error}"),
            Err(error) => panic!("actor task should join cleanly: {error}"),
        }
    }
}

async fn send_command(sender: &mpsc::Sender<SessionCommand>, command: SessionCommand) {
    if let Err(error) = sender.send(command).await {
        panic!("session command should enqueue: {error}");
    }
}

#[derive(Default)]
struct SimDoubleQuantumLoop {
    quanta: u64,
    observed_control: Arc<Mutex<Vec<SchedulerControlOperationKind>>>,
}

impl SimDoubleQuantumLoop {
    fn new(observed_control: Arc<Mutex<Vec<SchedulerControlOperationKind>>>) -> Self {
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
        self.observed_control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend(request.control.iter().map(|operation| operation.kind));
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
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
        "crucible.daemon.gate-control-responsive.scenario",
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

fn control_node() -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: "control-plane".to_owned(),
        },
        kind: SchedulingNodeKind::ControlPlane,
    }
}
