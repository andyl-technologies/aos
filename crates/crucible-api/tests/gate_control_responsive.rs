//! API-side `gate:control-responsive` acknowledgement checks.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use crucible::{
    Checkpoint, CheckpointKind, Configuration,
    ControlOperationKind as SchedulerControlOperationKind, Decision, DeliveryOrderDecision,
    EventKey, GenesisCheckpoint, QuantumLoop, QuantumOutcome, QuantumRequest, ScenarioDef,
    SchedulerError, Seed, TemporalGraph, VirtualTime, step,
};
use crucible_api::{
    CONTROL_RESPONSIVE_QUANTUM_BOUND, ControlAcknowledgementStatus,
    ControlOperationAcknowledgement, ControlOperationKind, ControlResponsiveSessionProbe,
    ControlResponsivenessError, ControlSessionState, validate_control_responsiveness,
};
use crucible_session::{Engine, SessionActor, SessionCommand, SessionError, SessionRunReport};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[tokio::test(flavor = "current_thread")]
async fn gate_control_responsive_accepts_required_ops_within_quantum_bound() {
    let fixture = RunningSimDoubleControlPlane::spawn().await;
    let acknowledgements = fixture.issue_required_operations().await;
    assert_eq!(
        fixture.observed_control_operations(),
        vec![
            SchedulerControlOperationKind::Snapshot,
            SchedulerControlOperationKind::Fork,
            SchedulerControlOperationKind::Inject,
            SchedulerControlOperationKind::Query,
        ]
    );

    let report =
        validate_control_responsiveness(&acknowledgements, CONTROL_RESPONSIVE_QUANTUM_BOUND)
            .unwrap_or_else(|error| {
                panic!("control acknowledgements should satisfy gate: {error}")
            });

    assert_eq!(report.bound_quanta, 1);
    assert_eq!(report.observations, 5);
    assert_eq!(report.required_operations_observed, 5);
    assert!(report.max_acknowledgement_delta_quanta <= 1);

    fixture.stop().await;
}

#[test]
fn gate_control_responsive_rejects_wall_clock_shaped_or_unbounded_evidence() {
    let slow_pause = [ControlOperationAcknowledgement::new(
        ControlOperationKind::Pause,
        ControlSessionState::Running,
        7,
        9,
        ControlAcknowledgementStatus::Applied,
    )];

    let error = validate_control_responsiveness(&slow_pause, CONTROL_RESPONSIVE_QUANTUM_BOUND)
        .expect_err("two-quantum acknowledgement must fail a one-quantum gate");
    assert_eq!(
        error,
        ControlResponsivenessError::AcknowledgementExceededBound {
            operation: ControlOperationKind::Pause,
            observed_delta_quanta: 2,
            bound_quanta: 1,
        }
    );
}

#[test]
fn gate_control_responsive_requires_running_session_and_all_operation_classes() {
    let paused_query = [ControlOperationAcknowledgement::new(
        ControlOperationKind::Query,
        ControlSessionState::Paused,
        3,
        3,
        ControlAcknowledgementStatus::Applied,
    )];

    let error = validate_control_responsiveness(&paused_query, CONTROL_RESPONSIVE_QUANTUM_BOUND)
        .expect_err("operation issued outside Running must fail the gate");
    assert_eq!(
        error,
        ControlResponsivenessError::OperationNotAgainstRunningSession {
            operation: ControlOperationKind::Query,
            requested_state: ControlSessionState::Paused,
        }
    );

    let missing_query = &applied_acknowledgements()[..4];
    let error = validate_control_responsiveness(missing_query, CONTROL_RESPONSIVE_QUANTUM_BOUND)
        .expect_err("missing query coverage must fail the gate");
    assert_eq!(
        error,
        ControlResponsivenessError::MissingRequiredOperation {
            operation: ControlOperationKind::Query,
        }
    );
}

#[test]
fn gate_control_responsive_requires_required_operations_to_apply() {
    let mut acknowledgements = applied_acknowledgements();
    acknowledgements[2] = ControlOperationAcknowledgement::new(
        ControlOperationKind::Fork,
        ControlSessionState::Running,
        12,
        12,
        ControlAcknowledgementStatus::Rejected,
    );

    let error =
        validate_control_responsiveness(&acknowledgements, CONTROL_RESPONSIVE_QUANTUM_BOUND)
            .expect_err("rejected required operation must fail the gate");
    assert_eq!(
        error,
        ControlResponsivenessError::RequiredOperationRejected {
            operation: ControlOperationKind::Fork,
            status: ControlAcknowledgementStatus::Rejected,
        }
    );
}

fn applied_acknowledgements() -> [ControlOperationAcknowledgement; 5] {
    [
        ControlOperationAcknowledgement::new(
            ControlOperationKind::Snapshot,
            ControlSessionState::Running,
            10,
            10,
            ControlAcknowledgementStatus::Applied,
        ),
        ControlOperationAcknowledgement::new(
            ControlOperationKind::Fork,
            ControlSessionState::Running,
            11,
            11,
            ControlAcknowledgementStatus::Applied,
        ),
        ControlOperationAcknowledgement::new(
            ControlOperationKind::Inject,
            ControlSessionState::Running,
            12,
            12,
            ControlAcknowledgementStatus::Applied,
        ),
        ControlOperationAcknowledgement::new(
            ControlOperationKind::Pause,
            ControlSessionState::Running,
            13,
            14,
            ControlAcknowledgementStatus::Applied,
        ),
        ControlOperationAcknowledgement::new(
            ControlOperationKind::Query,
            ControlSessionState::Running,
            14,
            14,
            ControlAcknowledgementStatus::Applied,
        ),
    ]
}

struct RunningSimDoubleControlPlane {
    sender: mpsc::Sender<SessionCommand>,
    actor_task: JoinHandle<Result<SessionRunReport, SessionError>>,
    probe: ControlResponsiveSessionProbe,
    observed_control: Arc<Mutex<Vec<SchedulerControlOperationKind>>>,
}

impl RunningSimDoubleControlPlane {
    async fn spawn() -> Self {
        let scenario = generated_scenario(41);
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
                let probe = ControlResponsiveSessionProbe::new(sender.clone(), live);
                return Self {
                    sender,
                    actor_task,
                    probe,
                    observed_control,
                };
            }
            tokio::task::yield_now().await;
        }

        panic!("SimDouble control-plane session should enter Running");
    }

    async fn issue_required_operations(&self) -> Vec<ControlOperationAcknowledgement> {
        let mut acknowledgements = Vec::new();
        for operation in [
            ControlOperationKind::Snapshot,
            ControlOperationKind::Fork,
            ControlOperationKind::Inject,
            ControlOperationKind::Query,
            ControlOperationKind::Pause,
        ] {
            let acknowledgement = self
                .probe
                .issue_against_running_session(operation)
                .await
                .unwrap_or_else(|error| panic!("{operation:?} should be acknowledged: {error}"));
            acknowledgements.push(acknowledgement);
        }
        acknowledgements
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
        "crucible.api.gate-control-responsive.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}

fn generated_decision(seed: u64) -> Decision {
    Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: seed },
        order: vec![EventKey { sequence: seed }],
    })
}
