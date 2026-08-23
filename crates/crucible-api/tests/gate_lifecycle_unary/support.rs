//! Shared lifecycle-unary scenario and checkpoint fixtures.

use super::*;

pub(super) fn lifecycle_control_plane()
-> LifecycleControlPlane<NoopLoop, LifecycleLoopFactory<NoopLoop>> {
    LifecycleControlPlane::new(
        "crucible-lifecycle-test-server",
        vec![catalog_entry()],
        |_scenario, _seed| NoopLoop,
    )
    .with_mailbox_capacity(LIFECYCLE_SESSION_MAILBOX_CAPACITY)
}

pub(super) fn catalog_entry() -> ScenarioCatalogEntry {
    ScenarioCatalogEntry::from_canonical_material(
        "api-lifecycle-scenario",
        "Lifecycle unary API scenario",
        "test://api-lifecycle-scenario",
        "crucible.api.gate-lifecycle-unary.scenario",
        "scenario=api-lifecycle",
    )
}

pub(super) struct NoopLoop;

impl QuantumLoop for NoopLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        panic!("lifecycle unary gate keeps sessions paused before any quantum")
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        GdbAttachInfo::new(node, "127.0.0.1:39001", listen).map_err(SchedulerError::from)
    }

    fn reposition_debug_runtime(
        &mut self,
        request: crucible::DebugRuntimeRepositionRequest,
    ) -> Result<crucible::DebugRuntimeRepositionReport, SchedulerError> {
        let endpoint = crucible::DebugGdbEndpoint::new("qemu_gdbstub", "127.0.0.1:39002").map_err(
            |error| SchedulerError::BoundaryViolation {
                message: format!("test reposition endpoint is invalid: {error}"),
            },
        )?;
        Ok(crucible::DebugRuntimeRepositionReport::completed(
            &request, endpoint, 2,
        ))
    }
}

pub(super) struct FailingLoop;

impl QuantumLoop for FailingLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("synthetic backend quantum failure"),
        })
    }
}

pub(super) struct RejectShutdownLoop;

impl QuantumLoop for RejectShutdownLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        panic!("rejected-shutdown gate keeps its session paused")
    }

    fn shutdown(&mut self) -> Result<Vec<crucible::SchedulerEventLogEntry>, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("synthetic unconsumed branch choice"),
        })
    }
}

pub(super) struct RuntimeOnlyReplayLoop {
    frontier: u64,
    step: u64,
}

impl RuntimeOnlyReplayLoop {
    pub(super) const fn new() -> Self {
        Self {
            frontier: 0,
            step: 1,
        }
    }

    pub(super) const fn with_step(step: u64) -> Self {
        Self { frontier: 0, step }
    }
}

impl QuantumLoop for RuntimeOnlyReplayLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.frontier = self.frontier.saturating_add(self.step);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime {
                ticks: self.frontier,
            },
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

pub(super) struct DivergentReplayLoop;

impl QuantumLoop for DivergentReplayLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        let frontier = VirtualTime { ticks: 1 };
        let node = crucible::SchedulerNodeId {
            node: crucible::NodeId {
                name: String::from("unexpected"),
            },
            kind: crucible::SchedulingNodeKind::ControlPlane,
        };
        let decision = Decision::DeliveryOrder(DeliveryOrderDecision {
            at: frontier,
            order: vec![crucible::EventKey::new(frontier, node.clone(), node, 0)],
        });
        let configuration =
            crucible::try_step(&request.configuration, decision.clone()).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!("divergent replay loop could not record decision: {error}"),
                }
            })?;
        Ok(QuantumOutcome {
            configuration,
            frontier,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
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

pub(super) fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.api.gate-lifecycle-unary.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}

pub(super) fn resume_request(seed: u64) -> ResumeSessionRequest {
    let mut scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    if scenario.seed() != Seed::from_u64(seed) {
        scenario = scenario_with_seed(&scenario, Seed::from_u64(seed));
    }
    let scenario_def = scenario.scenario_def();
    let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 1 },
        order: Vec::new(),
    }));
    let configuration = Configuration {
        def: scenario_def,
        schedule: schedule.clone(),
    };
    let checkpoint = checkpoint_for_configuration(&configuration, VirtualTime { ticks: 1 });
    ResumeSessionRequest::new(scenario, schedule, checkpoint, Seed::from_u64(seed))
}

pub(super) fn scenario_with_seed(scenario: &ScenarioDefForm, seed: Seed) -> ScenarioDefForm {
    ScenarioDefForm::from_components_with_app_random_draw_cap(
        scenario.world(),
        scenario.plan(),
        scenario.properties(),
        seed,
        scenario.app_random_draw_cap(),
    )
    .unwrap_or_else(|error| panic!("test scenario should rebuild with seed: {error}"))
}

pub(super) fn checkpoint_for_configuration(
    configuration: &Configuration,
    frontier: VirtualTime,
) -> Checkpoint {
    let parent = if configuration.schedule.is_empty() {
        None
    } else {
        let prefix = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))
            .unwrap_or_else(|error| panic!("test schedule prefix should exist: {error}"));
        Some(Configuration {
            def: configuration.def.clone(),
            schedule: prefix,
        })
    };
    Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        frontier,
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("test checkpoint should record configuration: {error}"))
}
