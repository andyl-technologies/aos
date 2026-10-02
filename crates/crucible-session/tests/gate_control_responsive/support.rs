//! Deterministic backend and scenario fixtures for control responsiveness tests.

use super::*;

pub(super) struct SimDoubleQuantumLoop {
    backend: SimDouble,
    quanta: u64,
    event_log_events: u64,
    observed_control: Arc<Mutex<Vec<ControlOperationKind>>>,
}

impl SimDoubleQuantumLoop {
    pub(super) fn new(observed_control: Arc<Mutex<Vec<ControlOperationKind>>>) -> Self {
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
    sequence: u64,
    ticks: u64,
    operation: &ControlOperation,
) -> Option<SchedulerEventLogEntry> {
    let mut event = resolved_control_operation(sequence, operation.clone());
    event.key = ScheduledEventKey::from_parts(
        VirtualTime { ticks },
        control_node(),
        control_node(),
        operation.sequence,
    );
    Some(crucible::test_support::condition_payload_entry_for_test(
        sequence,
        VirtualTime { ticks },
        SchedulerEventLogPayload::ResolvedHappening(event),
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

pub(super) fn observed_control_operations(
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

pub(super) fn graph_with_baked_genesis(scenario: &ScenarioDef) -> TemporalGraph {
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

pub(super) fn generated_scenario(seed: u64) -> ScenarioDef {
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
