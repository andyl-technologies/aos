//! Daemon-side `gate:control-responsive` acknowledgement checks.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use crucible::{
    BackendEffect, BackendInput, Checkpoint, CheckpointKind, Configuration,
    ControlOperationKind as SchedulerControlOperationKind, Decision, DeliveryOrderDecision,
    EventKey, GenesisCheckpoint, NodeId, QuantumLoop, QuantumOutcome, QuantumRequest, ScenarioDef,
    SchedulerError, SchedulerEventLogEntry, SchedulerNodeId, SchedulingNodeKind, Seed, SimDouble,
    SimDoubleConfig, SimulationBackend, TemporalGraph, VirtualTime, step,
};
use crucible_api::{
    ControlAcknowledgementStatus, ControlOperationAcknowledgement, ControlOperationKind,
    ControlResponsivenessError, ControlSessionState,
};
use crucible_daemon::{
    DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND, DaemonControlResponsiveRoute,
    validate_daemon_control_responsiveness,
};
use crucible_protocol::{CONTROL_PROTOCOL_VERSION, HostMsg, control_encode_host_msg};
use crucible_session::{Engine, SessionActor, SessionCommand, SessionError, SessionRunReport};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const CONTROL_RESPONSIVE_BACKEND: &str = "crucible::SimDouble quantum-loop adapter";
const CONTROL_RESPONSIVE_REQUIRES_REAL_QEMU: bool = false;
const FIDELITY_PROPERTIES_REQUIRING_QEMU: [&str; 3] =
    ["contract-a", "guest-non-mutation", "patch-inertness"];

#[test]
fn gate_control_responsive_daemon_declares_in_process_sim_double_backend() {
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
async fn gate_control_responsive_daemon_routes_use_api_quantum_bound() {
    let fixture = RunningSimDoubleControlPlane::spawn().await;
    let route = DaemonControlResponsiveRoute::new(fixture.probe.clone());
    let mut acknowledgements = Vec::new();

    for operation in [
        ControlOperationKind::Snapshot,
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
            SchedulerControlOperationKind::Inject,
            SchedulerControlOperationKind::Query,
        ]
    );

    let report = validate_daemon_control_responsiveness(&acknowledgements)
        .unwrap_or_else(|error| panic!("daemon route evidence should satisfy gate: {error}"));

    assert_eq!(DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND, 1);
    assert_eq!(report.bound_quanta, DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND);
    assert_eq!(report.observations, acknowledgements.len());
    assert_eq!(report.required_operations_observed, 4);
    assert!(report.max_acknowledgement_delta_quanta <= 1);

    fixture.stop().await;
}

#[test]
fn gate_control_responsive_daemon_rejects_required_operation_rejection() {
    let acknowledgements = [
        applied_acknowledgement(ControlOperationKind::Snapshot, 10),
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

struct SimDoubleQuantumLoop {
    backend: SimDouble,
    quanta: u64,
    observed_control: Arc<Mutex<Vec<SchedulerControlOperationKind>>>,
}

impl SimDoubleQuantumLoop {
    fn new(observed_control: Arc<Mutex<Vec<SchedulerControlOperationKind>>>) -> Self {
        Self {
            backend: ready_sim_double(),
            quanta: 0,
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
        record_control_operations(&self.observed_control, &request.control);
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            event_log_entries: Vec::new(),
            event_log_segment_bytes: vec![b'x'],
            event_log_segment_text: String::from("x"),
            event_log_segment_hash: Some(crucible::ContentHash::from_bytes(b"x")),
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, 0),
            scheduler_quiescence: None,
        })
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<crucible::ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.apply_backend_control(&control)?;
        record_control_operations(&self.observed_control, &control);
        Ok(Vec::new())
    }
}

impl SimDoubleQuantumLoop {
    fn apply_backend_control(
        &mut self,
        control: &[crucible::ControlOperation],
    ) -> Result<(), SchedulerError> {
        for operation in control {
            match &operation.kind {
                SchedulerControlOperationKind::Snapshot => {
                    let _snapshot = SimulationBackend::snapshot(&mut self.backend)?;
                }
                SchedulerControlOperationKind::Query => {
                    let _fingerprint =
                        SimulationBackend::fingerprint(&mut self.backend, control_node().node)?;
                }
                SchedulerControlOperationKind::Inject => {
                    let input = BackendInput {
                        node: control_node().node,
                        payload: b"daemon-control-inject".to_vec(),
                    };
                    let now = SimulationBackend::now(&self.backend);
                    SimulationBackend::apply(
                        &mut self.backend,
                        &BackendEffect::DeliverInput(input),
                        now,
                    )?;
                }
                SchedulerControlOperationKind::Pause
                | SchedulerControlOperationKind::Resume
                | SchedulerControlOperationKind::Step
                | SchedulerControlOperationKind::Fork
                | SchedulerControlOperationKind::InjectFault { .. }
                | SchedulerControlOperationKind::HealFault { .. } => {
                    let now = SimulationBackend::now(&self.backend);
                    SimulationBackend::apply(&mut self.backend, &BackendEffect::Noop, now)?;
                }
            }
        }
        Ok(())
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

fn record_control_operations(
    observed_control: &Arc<Mutex<Vec<SchedulerControlOperationKind>>>,
    control: &[crucible::ControlOperation],
) {
    observed_control
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .extend(control.iter().map(|operation| operation.kind.clone()));
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
