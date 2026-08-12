//! API-side `gate:control-responsive` acknowledgement checks.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crucible::{
    Checkpoint, CheckpointKind, Configuration,
    ControlOperationKind as SchedulerControlOperationKind, Decision, DeliveryOrderDecision,
    EventClass, EventDiagnosticPayload, EventKey, EventLevel, GenesisCheckpoint, NodeId,
    QuantumLoop, QuantumOutcome, QuantumRequest, ScenarioDef, SchedulerError,
    SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerNodeId, SchedulingNodeKind, Seed,
    SimDouble, SimDoubleConfig, SimulationBackend, TemporalGraph, VirtualTime, step,
};
use crucible_api::{
    CONTROL_RESPONSIVE_QUANTUM_BOUND, ControlAcknowledgementStatus,
    ControlOperationAcknowledgement, ControlOperationKind, ControlPlaneEventLog,
    ControlResponsiveSessionProbe, ControlResponsivenessError, ControlSessionState, EventLogCursor,
    validate_control_responsiveness,
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
fn gate_control_responsive_api_declares_in_process_sim_double_backend() {
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
async fn gate_control_responsive_accepts_required_ops_within_quantum_bound() {
    let fixture = RunningSimDoubleControlPlane::spawn().await;
    let acknowledgements = fixture.issue_required_operations().await;
    assert_eq!(
        fixture.observed_control_operations(),
        vec![
            SchedulerControlOperationKind::Snapshot,
            SchedulerControlOperationKind::Query,
        ]
    );

    let report =
        validate_control_responsiveness(&acknowledgements, CONTROL_RESPONSIVE_QUANTUM_BOUND)
            .unwrap_or_else(|error| {
                panic!("control acknowledgements should satisfy gate: {error}")
            });

    assert_eq!(report.bound_quanta, 1);
    assert_eq!(report.observations, 3);
    assert_eq!(report.required_operations_observed, 3);
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

    let missing_query = &applied_acknowledgements()[..2];
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
    acknowledgements[0] = ControlOperationAcknowledgement::new(
        ControlOperationKind::Snapshot,
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
            operation: ControlOperationKind::Snapshot,
            status: ControlAcknowledgementStatus::Rejected,
        }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn gate_control_plane_event_log_stream_api_subscribes_without_mutation() {
    let scenario = generated_scenario(43);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let observed_control = Arc::new(Mutex::new(Vec::new()));
    let engine = Engine::new(
        config,
        graph,
        SimDoubleQuantumLoop::new(Arc::clone(&observed_control)),
    );
    let (sender, receiver) = mpsc::channel(4);
    let actor = SessionActor::new(engine, receiver);
    let live = actor.live_snapshot();
    let before_subscribe = live.read();
    let api_event_log = ControlPlaneEventLog::new(actor.event_log());
    let future_cursor = EventLogCursor::new(before_subscribe.event_log_len.saturating_add(10_000));

    let mut stream = api_event_log.subscribe(future_cursor);
    let after_subscribe = live.read();

    assert_eq!(stream.cursor(), api_event_log.current_cursor());
    assert_eq!(stream.cursor(), EventLogCursor::default());
    assert_eq!(after_subscribe, before_subscribe);

    let actor_task = tokio::spawn(async move { actor.run().await });
    send_command(&sender, SessionCommand::Start).await;
    send_command(&sender, SessionCommand::Continue).await;
    wait_until_running(&live).await;

    let mut saw_causal = false;
    let mut saw_observational = false;
    for _ in 0..128 {
        let frame = stream
            .recv()
            .await
            .unwrap_or_else(|error| panic!("API event-log stream should not lag: {error}"))
            .unwrap_or_else(|| panic!("API event-log stream should stay open while actor runs"));
        saw_causal |= frame.entry.class() == EventClass::Causal;
        saw_observational |= frame.entry.class() == EventClass::Observational;
        if saw_causal && saw_observational {
            break;
        }
    }

    assert!(saw_causal);
    assert!(saw_observational);

    send_command(&sender, SessionCommand::Stop).await;
    match actor_task.await {
        Ok(Ok(_report)) => {}
        Ok(Err(error)) => panic!("actor should stop cleanly: {error}"),
        Err(error) => panic!("actor task should join cleanly: {error}"),
    }
}

fn applied_acknowledgements() -> [ControlOperationAcknowledgement; 3] {
    [
        ControlOperationAcknowledgement::new(
            ControlOperationKind::Snapshot,
            ControlSessionState::Running,
            10,
            10,
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

async fn wait_until_running(live: &crucible_session::LiveSnapshot) {
    for _ in 0..128 {
        if live.read().state_kind == crucible_session::LiveStateKind::Running {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("session should enter Running within bounded actor yields");
}

struct SimDoubleQuantumLoop {
    backend: SimDouble,
    quanta: u64,
    event_log_events: u64,
    observed_control: Arc<Mutex<Vec<SchedulerControlOperationKind>>>,
}

impl SimDoubleQuantumLoop {
    fn new(observed_control: Arc<Mutex<Vec<SchedulerControlOperationKind>>>) -> Self {
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
        record_control_operations(&self.observed_control, &request.control);
        let event_log_entries = self.event_log_entries();
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
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
        control: Vec<crucible::ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.apply_backend_control(&control)?;
        record_control_operations(&self.observed_control, &control);
        Ok(Vec::new())
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
                SchedulerControlOperationKind::Pause
                | SchedulerControlOperationKind::Resume
                | SchedulerControlOperationKind::Step
                | SchedulerControlOperationKind::Fork => {
                    let now = SimulationBackend::now(&self.backend);
                    SimulationBackend::apply(&mut self.backend, &BackendEffect::Noop, now)?;
                }
            }
        }
        Ok(())
    }

    fn event_log_entries(&mut self) -> Vec<SchedulerEventLogEntry> {
        let base = self.event_log_events;
        let entries = vec![
            crucible::test_support::condition_payload_entry_for_test(
                base,
                VirtualTime { ticks: self.quanta },
                SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
                    "api.event-log.stream",
                    EventLevel::Debug,
                    BTreeMap::new(),
                )),
            ),
            crucible::test_support::condition_boundary_entry_for_test(
                base.saturating_add(1),
                VirtualTime { ticks: self.quanta },
                crucible::SchedulerEvaluationBoundaryKind::Quantum,
            ),
        ];
        self.event_log_events = self.event_log_events.saturating_add(2);
        entries
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
