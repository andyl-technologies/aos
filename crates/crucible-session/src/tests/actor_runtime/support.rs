//! Shared loop and scenario fixtures for session engine tests.

use super::*;

pub(in crate::tests) struct CaptureBeforeShutdownLoop {
    pub(super) operations: Arc<Mutex<Vec<&'static str>>>,
}

impl QuantumLoop for CaptureBeforeShutdownLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("terminal-order test must not drive a quantum"),
        })
    }

    fn capture_checkpoint(
        &mut self,
        _configuration: &Configuration,
    ) -> Result<Option<ContentHash>, SchedulerError> {
        self.operations
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("terminal-order operation log lock is poisoned"),
            })?
            .push("capture");
        Ok(Some(ContentHash::from_bytes(b"terminal-order-checkpoint")))
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.operations
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("terminal-order operation log lock is poisoned"),
            })?
            .push("shutdown");
        Ok(Vec::new())
    }
}

pub(in crate::tests) struct NonDenseShutdownLoop;

impl QuantumLoop for NonDenseShutdownLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("non-dense shutdown test must not drive a quantum"),
        })
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(vec![test_event_log_entry(1)])
    }
}

pub(in crate::tests) struct BackendCrashLoop;

impl QuantumLoop for BackendCrashLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        Err(BackendError::Rejected {
            message: String::from("backend process exited unexpectedly"),
        }
        .into())
    }
}

#[derive(Default)]
pub(in crate::tests) struct CoverageAppendingLoop {
    event_log: crucible::EventLog,
}

impl QuantumLoop for CoverageAppendingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: 19 },
            advanced_node: Some(SchedulerNodeId {
                node: node_id("vm-a"),
                kind: SchedulingNodeKind::Vm,
            }),
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: self.event_log.offset(),
            scheduler_quiescence: None,
        })
    }

    fn append_backend_observable_events(
        &mut self,
        events: Vec<crucible::ObservableEvent>,
    ) -> Result<crucible::SchedulerEventLogAppend, SchedulerError> {
        self.event_log.append_observable_events(events)
    }

    fn append_backend_observations_at_boundary(
        &mut self,
        events: Vec<crucible::ObservableEvent>,
        at: VirtualTime,
    ) -> Result<crucible::SchedulerEventLogAppend, SchedulerError> {
        self.event_log.append_observations_at_boundary(
            events,
            at,
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        )
    }
}

pub(in crate::tests) struct CoverageBackend {
    now: VirtualTime,
    events: Vec<crucible::ObservableEvent>,
}

impl CoverageBackend {
    fn new(event: crucible::ObservableEvent) -> Self {
        Self {
            now: VirtualTime::default(),
            events: vec![event],
        }
    }
}

impl crucible::SimulationBackend for CoverageBackend {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<crucible::StepObservation, BackendError> {
        self.now = ceiling;
        Ok(crucible::StepObservation::from_advance_outcome(
            ceiling,
            crucible::AdvanceOutcome::ReachedHorizon,
        ))
    }

    fn drain_observable_events(&mut self) -> Result<Vec<crucible::ObservableEvent>, BackendError> {
        Ok(std::mem::take(&mut self.events))
    }

    fn apply(
        &mut self,
        _effect: &crucible::BackendEffect,
        _at: VirtualTime,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn snapshot(&mut self) -> Result<crucible::BackendSnapshot, BackendError> {
        Err(BackendError::Unsupported {
            capability: "coverage test snapshot",
        })
    }

    fn restore(&mut self, _snapshot: &crucible::BackendSnapshot) -> Result<(), BackendError> {
        Err(BackendError::Unsupported {
            capability: "coverage test restore",
        })
    }

    fn now(&self) -> VirtualTime {
        self.now
    }

    fn fingerprint(&mut self, _node: NodeId) -> Result<FingerprintSample, BackendError> {
        Err(BackendError::Unsupported {
            capability: "coverage test fingerprint",
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
}

pub(in crate::tests) struct StubLoop;

impl QuantumLoop for StubLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: 0 },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: Default::default(),
            scheduler_quiescence: None,
        })
    }
}

pub(in crate::tests) struct TerminalVerdictLoop {
    verdict: Option<QuantumTerminalVerdict>,
}

impl TerminalVerdictLoop {
    pub(in crate::tests) fn new(verdict: QuantumTerminalVerdict) -> Self {
        Self {
            verdict: Some(verdict),
        }
    }
}

impl QuantumLoop for TerminalVerdictLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        StubLoop.drive_quantum(request)
    }

    fn take_terminal_verdict(&mut self) -> Option<QuantumTerminalVerdict> {
        self.verdict.take()
    }
}

#[derive(Default)]
pub(in crate::tests) struct CountingLoop {
    quanta: u64,
}

impl QuantumLoop for CountingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: Default::default(),
            scheduler_quiescence: None,
        })
    }
}

pub(in crate::tests) struct RecordingLoop {
    quanta: u64,
    control_batches: Arc<Mutex<Vec<Vec<ControlOperationKind>>>>,
}

impl RecordingLoop {
    pub(in crate::tests) fn new(
        control_batches: Arc<Mutex<Vec<Vec<ControlOperationKind>>>>,
    ) -> Self {
        Self {
            quanta: 0,
            control_batches,
        }
    }
}

impl QuantumLoop for RecordingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        let control_batch = request
            .control
            .iter()
            .map(|control| control.kind.clone())
            .collect::<Vec<_>>();
        match self.control_batches.lock() {
            Ok(mut batches) => batches.push(control_batch),
            Err(poisoned) => poisoned.into_inner().push(control_batch),
        }
        self.quanta = self.quanta.saturating_add(1);
        let decision = generated_decision(self.quanta);
        let configuration = accepted_step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            discovered_choices: Vec::new(),
            event_log_entries: vec![test_event_log_entry(self.quanta - 1)],
            event_log_segment_bytes: vec![b'x'],
            event_log_segment_text: String::from("x"),
            event_log_segment_hash: Some(crucible::ContentHash::from_bytes(b"x")),
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, self.quanta),
            scheduler_quiescence: None,
        })
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let control_batch = control
            .iter()
            .map(|operation| operation.kind.clone())
            .collect::<Vec<_>>();
        match self.control_batches.lock() {
            Ok(mut batches) => batches.push(control_batch),
            Err(poisoned) => poisoned.into_inner().push(control_batch),
        }
        Ok(Vec::new())
    }
}

#[derive(Default)]
pub(in crate::tests) struct ControlSensitiveLoop {
    quanta: u64,
    control_batches: u64,
}

impl ControlSensitiveLoop {
    fn apply_control_batch(&mut self, controls: &[ControlOperation]) {
        if controls.is_empty() {
            return;
        }
        self.control_batches = self.control_batches.saturating_add(1);
        for control in controls {
            match &control.kind {
                ControlOperationKind::Pause
                | ControlOperationKind::Resume
                | ControlOperationKind::Step
                | ControlOperationKind::Snapshot
                | ControlOperationKind::Fork
                | ControlOperationKind::Query => {}
            }
        }
    }

    fn decision_seed(&self) -> u64 {
        self.quanta
            .saturating_add(self.control_batches.saturating_mul(100_000))
    }
}

impl QuantumLoop for ControlSensitiveLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.apply_control_batch(&request.control);
        self.quanta = self.quanta.saturating_add(1);
        let decision = generated_decision(self.decision_seed());
        let configuration = accepted_step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            discovered_choices: Vec::new(),
            event_log_entries: vec![test_event_log_entry(self.quanta - 1)],
            event_log_segment_bytes: vec![b'x'],
            event_log_segment_text: String::from("x"),
            event_log_segment_hash: Some(crucible::ContentHash::from_bytes(b"x")),
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, self.quanta),
            scheduler_quiescence: None,
        })
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.apply_control_batch(&control);
        Ok(Vec::new())
    }
}

pub(in crate::tests) struct ShutdownLoop {
    quanta: u64,
    shutdowns: Arc<AtomicU64>,
}

impl ShutdownLoop {
    pub(in crate::tests) fn new(shutdowns: Arc<AtomicU64>) -> Self {
        Self {
            quanta: 0,
            shutdowns,
        }
    }
}

impl QuantumLoop for ShutdownLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: Default::default(),
            scheduler_quiescence: None,
        })
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
}

#[derive(Default)]
pub(in crate::tests) struct ScriptedStepLoop {
    quanta: u64,
    event_log_entries: u64,
    payloads_by_quantum: std::collections::BTreeMap<u64, Vec<SchedulerEventLogPayload>>,
    scheduler_quiescence: Option<SchedulerQuiescence>,
}

impl ScriptedStepLoop {
    pub(in crate::tests) fn with_payload(quantum: u64, payload: SchedulerEventLogPayload) -> Self {
        Self::with_payloads(quantum, vec![payload])
    }

    pub(in crate::tests) fn with_payloads(
        quantum: u64,
        payloads: Vec<SchedulerEventLogPayload>,
    ) -> Self {
        let mut payloads_by_quantum = std::collections::BTreeMap::new();
        payloads_by_quantum.insert(quantum, payloads);
        Self {
            quanta: 0,
            event_log_entries: 0,
            payloads_by_quantum,
            scheduler_quiescence: None,
        }
    }

    pub(in crate::tests) fn with_quiescence(scheduler_quiescence: SchedulerQuiescence) -> Self {
        Self {
            scheduler_quiescence: Some(scheduler_quiescence),
            ..Self::default()
        }
    }
}

impl QuantumLoop for ScriptedStepLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let at = VirtualTime { ticks: self.quanta };
        let entries = if let Some(payloads) = self.payloads_by_quantum.remove(&self.quanta) {
            payloads
                .into_iter()
                .enumerate()
                .map(|(index, payload)| {
                    crucible::test_support::condition_payload_entry_for_test(
                        self.event_log_entries + usize_to_u64(index),
                        at,
                        payload,
                    )
                })
                .collect::<Vec<_>>()
        } else {
            vec![crucible::test_support::condition_boundary_entry_for_test(
                self.event_log_entries,
                at,
                crucible::SchedulerEvaluationBoundaryKind::Quantum,
            )]
        };
        self.event_log_entries = self
            .event_log_entries
            .saturating_add(usize_to_u64(entries.len()));
        let decision = generated_decision(self.quanta);
        let configuration = accepted_step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: at,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            discovered_choices: Vec::new(),
            event_log_entries: entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::new(
                Default::default(),
                0,
                self.event_log_entries,
            ),
            scheduler_quiescence: self.scheduler_quiescence.clone(),
        })
    }
}

pub(in crate::tests) struct NoEventQuiescenceLoop {
    pub(in crate::tests) quiescence: SchedulerQuiescence,
}

impl QuantumLoop for NoEventQuiescenceLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: 1 },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: Some(self.quiescence.clone()),
        })
    }
}

pub(in crate::tests) struct PriorEventThenNoEventQuiescenceLoop {
    pub(in crate::tests) quanta: u64,
    pub(in crate::tests) quiescence: SchedulerQuiescence,
}

impl QuantumLoop for PriorEventThenNoEventQuiescenceLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let at = VirtualTime { ticks: self.quanta };
        let entries = if self.quanta == 1 {
            vec![crucible::test_support::condition_boundary_entry_for_test(
                0,
                at,
                crucible::SchedulerEvaluationBoundaryKind::Quantum,
            )]
        } else {
            Vec::new()
        };
        let decision = generated_decision(self.quanta);
        let configuration = accepted_step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: at,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            discovered_choices: Vec::new(),
            event_log_entries: entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, 1),
            scheduler_quiescence: Some(self.quiescence.clone()),
        })
    }
}

pub(in crate::tests) struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("session step-mode tests should not evaluate host leaf predicates")
            }
        }
    }
}

#[derive(Default)]
pub(in crate::tests) struct AppendingLoop {
    quanta: u64,
}

pub(in crate::tests) struct InvalidEventLogLoop;

impl QuantumLoop for InvalidEventLogLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: 1 },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, 1),
            scheduler_quiescence: None,
        })
    }
}

#[derive(Default)]
pub(in crate::tests) struct RegressingEventLogLoop {
    quanta: u64,
}

impl QuantumLoop for RegressingEventLogLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let (entries, offset) = if self.quanta == 1 {
            (
                vec![test_event_log_entry(0)],
                crucible::EventLogOffset::new(Default::default(), 0, 1),
            )
        } else {
            (Vec::new(), crucible::EventLogOffset::default())
        };
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: offset,
            scheduler_quiescence: None,
        })
    }
}

impl QuantumLoop for AppendingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let decision = generated_decision(self.quanta);
        let configuration = accepted_step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            discovered_choices: Vec::new(),
            event_log_entries: vec![test_event_log_entry(self.quanta - 1)],
            event_log_segment_bytes: vec![b'x'],
            event_log_segment_text: String::from("x"),
            event_log_segment_hash: Some(crucible::ContentHash::from_bytes(b"x")),
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, self.quanta),
            scheduler_quiescence: None,
        })
    }
}

#[path = "debug_loops.rs"]
mod debug_loops;

pub(in crate::tests) use debug_loops::*;

pub(in crate::tests) fn debug_time_travel_fixture()
-> (Configuration, Configuration, Configuration, TemporalGraph) {
    let world = single_node_debug_world("session-command")
        .unwrap_or_else(|error| panic!("debug world should build: {error}"));
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(
        &root,
        override_decision("session/debug-time-travel", "first"),
    )
    .unwrap_or_else(|error| panic!("first debug step should build: {error}"));
    let second = try_step(
        &first,
        override_decision("session/debug-time-travel", "second"),
    )
    .unwrap_or_else(|error| panic!("second debug step should build: {error}"));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            bake(&world).unwrap_or_else(|error| panic!("debug world should bake: {error}")),
        )
        .unwrap_or_else(|error| panic!("debug graph should have baked genesis: {error}"));
    graph
        .record_thin_checkpoint(&first)
        .unwrap_or_else(|error| panic!("first checkpoint should record: {error}"));
    graph
        .record_thin_checkpoint(&second)
        .unwrap_or_else(|error| panic!("second checkpoint should record: {error}"));
    (root, first, second, graph)
}

pub(in crate::tests) fn single_node_debug_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("guest-a"),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-session-debug={label}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: crucible::Icount { retired: 100 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
}

pub(in crate::tests) fn override_decision(point: &str, choice: &str) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: point.to_owned(),
        },
        choice: ChoiceTag {
            name: choice.to_owned(),
        },
    })
}

pub(in crate::tests) fn gdb_listen(endpoint: &str) -> GdbListen {
    GdbListen::new(endpoint)
        .unwrap_or_else(|error| panic!("test gdb listen should be stable: {error}"))
}

pub(in crate::tests) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

pub(in crate::tests) fn graph_with_baked_genesis(scenario: &ScenarioDef) -> TemporalGraph {
    let genesis = Configuration::genesis(scenario.clone());
    match TemporalGraph::empty().with_baked_genesis(scenario, genesis_checkpoint(&genesis)) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    }
}

pub(in crate::tests) fn genesis_checkpoint(configuration: &Configuration) -> GenesisCheckpoint {
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

pub(in crate::tests) fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.session.test.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}

pub(in crate::tests) fn test_event_log_entry(sequence: u64) -> crucible::SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        VirtualTime {
            ticks: sequence.saturating_add(1),
        },
        crucible::SchedulerEvaluationBoundaryKind::Quantum,
    )
}

pub(in crate::tests) fn resolved_backend_input_payload(seed: u64) -> SchedulerEventLogPayload {
    let node = scheduler_node("node-a");
    SchedulerEventLogPayload::ResolvedHappening(ScheduledEvent {
        key: ScheduledEventKey::new(
            crucible::SharedTimelineKey {
                virtual_time: crucible::SimInstant {
                    nanos: (VirtualTime { ticks: seed }).ticks,
                },
                node: node.clone(),
                sequence: seed,
            },
            node.clone(),
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: node.node,
            payload: vec![1, 2, 3],
        }),
    })
}

pub(in crate::tests) fn assertion_state_change_payload() -> SchedulerEventLogPayload {
    SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionStateChanged {
        name: AssertionId::from_name("session-step-assertion"),
        state: AssertionPhase::Satisfied,
    })
}

pub(in crate::tests) fn trigger_fired_payload(
    sequence: u64,
    event: EventId,
    predicate: Predicate,
) -> SchedulerEventLogPayload {
    let graph = EventGraph::new(vec![Event::once(
        event.clone(),
        Some(predicate),
        Action::Log {
            level: LogLevel::Info,
            message: String::from("session breakpoint trigger fired"),
        },
    )])
    .unwrap_or_else(|error| panic!("trigger-fired event graph should build: {error}"));
    let mut graph_state = EventGraphState::new();
    let mut pass = ConditionEvaluationPass::from_log_prefix(
        crucible::test_support::condition_prefix_at_quantum_boundary_for_test(sequence),
        NoLeaves,
    );
    let firings = pass.evaluate_event_graph(&graph, &mut graph_state);
    let Some(firing) = firings
        .iter()
        .find(|firing| firing.event() == &event)
        .cloned()
    else {
        panic!("trigger-fired event graph should produce the requested firing");
    };
    SchedulerEventLogPayload::TriggerFired(firing)
}

pub(in crate::tests) fn timer_fire_payload(sequence: u64) -> SchedulerEventLogPayload {
    let timer = TimerId {
        name: String::from("session-step-timer"),
    };
    let graph = EventGraph::new(vec![
        Event::once(
            EventId::from_name("session-step-arm-timer"),
            None,
            Action::arm_timer(
                timer.clone(),
                SimDuration::from_nanoseconds(sequence)
                    .unwrap_or_else(|error| panic!("timer duration fits in ticks: {error}")),
            ),
        ),
        Event::once(
            EventId::from_name("session-step-timer"),
            Some(Predicate::timer(timer.clone())),
            Action::Log {
                level: LogLevel::Info,
                message: String::from("session step timer fired"),
            },
        ),
    ])
    .unwrap_or_else(|error| panic!("timer fire event graph should build: {error}"));
    let mut graph_state = EventGraphState::new();
    let mut timer_fires = std::collections::BTreeMap::new();
    timer_fires.insert(timer, VirtualTime { ticks: sequence });
    let mut pass = ConditionEvaluationPass::from_log_prefix(
        crucible::test_support::condition_prefix_at_quantum_boundary_for_test(sequence),
        NoLeaves,
    )
    .with_timer_fires(timer_fires);
    let firings = pass.evaluate_event_graph(&graph, &mut graph_state);
    let Some(firing) = firings
        .iter()
        .find(|firing| condition_summary_is_timer_fire(firing.condition_summary()))
        .cloned()
    else {
        panic!("timer fire event graph should produce a timer predicate firing");
    };
    SchedulerEventLogPayload::TriggerFired(firing)
}

pub(in crate::tests) fn timer_action_payload(sequence: u64) -> SchedulerEventLogPayload {
    SchedulerEventLogPayload::TriggerActionApplied(TriggerActionApplication {
        sequence,
        event: EventId::from_name("session-step-timer"),
        at: VirtualTime { ticks: sequence },
        path: Vec::new(),
        action: Action::cancel_timer(TimerId {
            name: String::from("session-step-timer"),
        }),
    })
}

pub(in crate::tests) fn generated_decision(seed: u64) -> Decision {
    let node = scheduler_node("control-plane");
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

pub(in crate::tests) fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::ControlPlane,
    }
}
#[path = "coverage.rs"]
mod coverage;
