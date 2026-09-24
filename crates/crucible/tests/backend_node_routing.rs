//! Node-address preservation tests for live backend scheduling.

// crucible-lint: allow panic-shortcut -- focused routing fixtures use panic assertions.
#![allow(clippy::expect_used)]

use crucible::{
    BackendEffect, BackendError, BackendInput, BackendNetworkOutput,
    BackendNetworkOutputInterceptor, BackendNetworkRoute, BackendQuantumLoop, BackendRngEvidence,
    BackendSnapshot, ConcurrentBackendRun, ConcurrentBackendRunOutcome, ConcurrentQuantumLoop,
    ConcurrentSimulationBackend, Configuration, ContentHash, Decision, EventLogOffset,
    ExactLocalEvent, FingerprintSample, Icount, LinkDef, LinkId, LinkLossProbability,
    MIN_LINK_LATENCY, NetworkLinkDirection, NetworkLookahead, NodeCounter, NodeId, NodeTemplate,
    ObservableEvent, Plan, Properties, QuantumLoop, QuantumOutcome, QuantumRequest, ReadyPoint,
    RngStreamId, ScenarioDef, ScenarioDefForm, ScheduledEvent, ScheduledEventKey,
    ScheduledEventPayload, SchedulerError, SchedulerLivenessScenario, SchedulerNodeActivity,
    SchedulerNodeId, SchedulerScenarioNode, Seed, SelectionDecision, Shift, SimDuration,
    SimInstant, SimulationBackend, SingleScheduler, StepObservation, VirtualTime, WhiteBoxPolicy,
    World, WorldNode,
};

fn world_node(name: &str) -> WorldNode {
    WorldNode {
        id: NodeId {
            name: String::from(name),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

struct SelectedNodeLoop {
    selected: SchedulerNodeId,
}

impl QuantumLoop for SelectedNodeLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: 17 },
            advanced_node: Some(self.selected.clone()),
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }
}

#[derive(Default)]
struct NodeRecordingBackend {
    stepped: Vec<NodeId>,
    ceilings: Vec<VirtualTime>,
    applied: Vec<(NodeId, BackendEffect, VirtualTime)>,
    network_outputs: Vec<BackendNetworkOutput>,
    observable_events: Vec<ObservableEvent>,
    rng_evidence: Vec<BackendRngEvidence>,
    shutdown_count: usize,
    concurrent_run_sizes: Vec<usize>,
}

impl SimulationBackend for NodeRecordingBackend {
    fn step_to(&mut self, _ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        Err(BackendError::Unsupported {
            capability: "backend-global step_to",
        })
    }

    fn step_node_to(
        &mut self,
        node: &NodeId,
        ceiling: VirtualTime,
    ) -> Result<StepObservation, BackendError> {
        self.stepped.push(node.clone());
        self.ceilings.push(ceiling);
        Ok(StepObservation::from_advance_outcome(
            ceiling,
            crucible::AdvanceOutcome::ReachedHorizon,
        ))
    }

    fn apply(&mut self, _effect: &BackendEffect, _at: VirtualTime) -> Result<(), BackendError> {
        Ok(())
    }

    fn apply_to_node(
        &mut self,
        node: &NodeId,
        effect: &BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        self.applied.push((node.clone(), effect.clone(), at));
        Ok(())
    }

    fn drain_network_outputs(&mut self) -> Result<Vec<BackendNetworkOutput>, BackendError> {
        Ok(std::mem::take(&mut self.network_outputs))
    }

    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, BackendError> {
        Ok(std::mem::take(&mut self.observable_events))
    }

    fn drain_rng_evidence(&mut self) -> Result<Vec<BackendRngEvidence>, BackendError> {
        Ok(std::mem::take(&mut self.rng_evidence))
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        Err(BackendError::Unsupported {
            capability: "snapshot",
        })
    }

    fn restore(&mut self, _snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        Err(BackendError::Unsupported {
            capability: "restore",
        })
    }

    fn now(&self) -> VirtualTime {
        VirtualTime::default()
    }

    fn fingerprint(&mut self, _node: NodeId) -> Result<FingerprintSample, BackendError> {
        Err(BackendError::Unsupported {
            capability: "fingerprint",
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.shutdown_count += 1;
        Ok(())
    }
}

impl ConcurrentSimulationBackend for NodeRecordingBackend {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        _max_host_workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunOutcome>, BackendError> {
        self.concurrent_run_sizes.push(runs.len());
        let mut pending_outputs = std::mem::take(&mut self.network_outputs);
        let outcomes = runs
            .into_iter()
            .map(|run| {
                let (current, later) = pending_outputs
                    .drain(..)
                    .partition(|output: &BackendNetworkOutput| output.source == run.node);
                pending_outputs = later;
                ConcurrentBackendRunOutcome {
                    node: run.node,
                    step: StepObservation::from_advance_outcome(
                        run.ceiling,
                        crucible::AdvanceOutcome::ReachedHorizon,
                    ),
                    rng_evidence: Vec::new(),
                    network_outputs: current,
                    observations: Vec::new(),
                }
            })
            .collect();
        self.network_outputs = pending_outputs;
        Ok(outcomes)
    }
}

#[derive(Default)]
struct RecordingNetworkInterceptor {
    batches: Vec<(VirtualTime, usize, u8)>,
}

impl BackendNetworkOutputInterceptor<SingleScheduler, NodeRecordingBackend>
    for RecordingNetworkInterceptor
{
    fn intercept_network_outputs(
        &mut self,
        _loop_impl: &mut SingleScheduler,
        _backend: &mut NodeRecordingBackend,
        frontier: VirtualTime,
        _pending_outputs: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<crucible::SchedulerEventLogAppend>, SchedulerError> {
        let output_count = outputs.len();
        let Some(output) = outputs.first_mut() else {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network interceptor received an empty committed batch"),
            });
        };
        let Some(last) = output.payload.last_mut() else {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network interceptor received an empty frame"),
            });
        };
        *last = 0x5a;
        self.batches.push((frontier, output_count, *last));
        Ok(Vec::new())
    }
}

struct SplittingNetworkInterceptor;

impl BackendNetworkOutputInterceptor<SingleScheduler, NodeRecordingBackend>
    for SplittingNetworkInterceptor
{
    fn intercept_network_outputs(
        &mut self,
        _loop_impl: &mut SingleScheduler,
        _backend: &mut NodeRecordingBackend,
        _frontier: VirtualTime,
        _pending_outputs: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<crucible::SchedulerEventLogAppend>, SchedulerError> {
        let mut later = outputs[0].clone();
        later.sequence = 1;
        outputs.push(later);
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct FailingSecondRouteInterceptor {
    calls: usize,
}

impl BackendNetworkOutputInterceptor<SingleScheduler, NodeRecordingBackend>
    for FailingSecondRouteInterceptor
{
    fn intercept_network_outputs(
        &mut self,
        _loop_impl: &mut SingleScheduler,
        _backend: &mut NodeRecordingBackend,
        _frontier: VirtualTime,
        _pending_outputs: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<crucible::SchedulerEventLogAppend>, SchedulerError> {
        self.calls += 1;
        if self.calls == 2 {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("second route failed after the first was intercepted"),
            });
        }
        outputs.clear();
        Ok(Vec::new())
    }
}

#[test]
fn backend_quantum_loop_preserves_the_scheduler_selected_node() {
    let selected = SchedulerNodeId {
        node: NodeId {
            name: String::from("vm-b"),
        },
        kind: crucible::SchedulingNodeKind::Vm,
    };
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.backend-node-routing",
        "scenario=backend-node-routing",
    ));
    let mut adapter = BackendQuantumLoop::new(
        SelectedNodeLoop {
            selected: selected.clone(),
        },
        NodeRecordingBackend::default(),
    );

    adapter
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("node-addressed backend step should succeed: {error}"));

    assert_eq!(adapter.backend().stepped, vec![selected.node]);
}

#[test]
fn backend_quantum_loop_uses_node_counter_instead_of_virtual_frontier() {
    let node = SchedulerNodeId {
        node: NodeId {
            name: String::from("vm-a"),
        },
        kind: crucible::SchedulingNodeKind::Vm,
    };
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "backend-node-counter-ceiling",
        Shift::new(7).unwrap_or_else(|error| panic!("shift should be valid: {error}")),
        4,
        SimInstant { nanos: 1_280 },
        vec![SchedulerScenarioNode {
            id: node.clone(),
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Runnable,
            network_lookahead: NetworkLookahead::Finite(SimDuration { nanos: 1_280 }),
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    );
    let scheduler = SingleScheduler::new(scenario)
        .unwrap_or_else(|error| panic!("scheduler should build: {error}"));
    let configuration = scheduler.configuration().clone();
    let mut adapter = BackendQuantumLoop::new(scheduler, NodeRecordingBackend::default());

    let outcome = adapter
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("node-addressed backend step should succeed: {error}"));

    assert_eq!(outcome.frontier, VirtualTime { ticks: 1_280 });
    assert_eq!(adapter.backend().stepped, vec![node.node]);
    assert_eq!(adapter.backend().ceilings, vec![VirtualTime { ticks: 10 }]);
}

#[test]
fn backend_quantum_loop_delivers_resolved_network_input_at_the_exact_boundary() {
    let source = SchedulerNodeId {
        node: NodeId {
            name: String::from("vm-a"),
        },
        kind: crucible::SchedulingNodeKind::Vm,
    };
    let destination = SchedulerNodeId {
        node: NodeId {
            name: String::from("vm-b"),
        },
        kind: crucible::SchedulingNodeKind::Vm,
    };
    let input = BackendInput {
        node: destination.node.clone(),
        payload: b"guest-frame".to_vec(),
    };
    let event = ScheduledEvent {
        key: ScheduledEventKey::new(
            crucible::SharedTimelineKey {
                virtual_time: crucible::SimInstant {
                    nanos: (VirtualTime { ticks: 17 }).ticks,
                },
                node: destination.clone(),
                sequence: 3,
            },
            source,
        ),
        payload: ScheduledEventPayload::BackendInput(input.clone()),
    };
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.backend-network-delivery",
        "scenario=backend-network-delivery",
    ));

    struct DeliveryLoop {
        selected: SchedulerNodeId,
        event: ScheduledEvent,
    }

    impl QuantumLoop for DeliveryLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime { ticks: 17 },
                advanced_node: Some(self.selected.clone()),
                resolved_events: vec![self.event.clone()],
                decisions: Vec::new(),
                discovered_choices: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: EventLogOffset::default(),
                scheduler_quiescence: None,
            })
        }
    }

    let mut adapter = BackendQuantumLoop::new(
        DeliveryLoop {
            selected: destination.clone(),
            event,
        },
        NodeRecordingBackend::default(),
    );
    adapter
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("resolved frame delivery should succeed: {error}"));

    assert_eq!(
        adapter.backend().applied,
        vec![(
            destination.node,
            BackendEffect::DeliverInput(input),
            VirtualTime { ticks: 17 },
        )]
    );
}

#[test]
fn backend_quantum_loop_routes_guest_output_through_the_world_link() {
    let source = NodeId {
        name: String::from("vm-a"),
    };
    let destination = NodeId {
        name: String::from("vm-b"),
    };
    let world = World::from_nodes_and_links(
        vec![world_node(&source.name), world_node(&destination.name)],
        vec![
            LinkDef::new(source.clone(), destination.clone())
                .unwrap_or_else(|error| panic!("test link should build: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("test World should build: {error}"));
    let form = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(19),
    )
    .unwrap_or_else(|error| panic!("test scenario should build: {error}"));
    let runtime = SchedulerLivenessScenario::from_runnable_world(
        "backend-network-output",
        Shift::new(0).unwrap_or_else(|error| panic!("zero shift should build: {error}")),
        4,
        SimInstant { nanos: 100 },
        0,
        &world,
    )
    .with_scenario_def(form.scenario_def());
    let mut scheduler = SingleScheduler::new(runtime)
        .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
    scheduler
        .attach_world_network_links(&world)
        .unwrap_or_else(|error| panic!("World network should attach: {error}"));
    let configuration = scheduler.configuration().clone();
    let mut payload = vec![0_u8; 60];
    payload[..6].copy_from_slice(&crucible::deterministic_node_mac(&destination));
    let output = BackendNetworkOutput {
        source: source.clone(),
        destination: NodeId {
            name: String::from("net-router"),
        },
        emit_icount: Icount { retired: 1 },
        sequence: 0,
        payload,
        route: None,
        fault_continuation: Default::default(),
    };
    let routes = scheduler
        .resolve_backend_network_routes(&output)
        .unwrap_or_else(|error| panic!("unicast route should resolve: {error}"));
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination, destination);

    let mut invalid_output = output.clone();
    invalid_output.route = Some(BackendNetworkRoute {
        link: LinkId::from_name("not-a-world-link"),
        direction: NetworkLinkDirection::EndpointAToEndpointB,
        destination: destination.clone(),
    });
    assert!(matches!(
        scheduler.resolve_backend_network_routes(&invalid_output),
        Err(SchedulerError::BoundaryViolation { .. })
    ));
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        NodeRecordingBackend {
            network_outputs: vec![output],
            ..NodeRecordingBackend::default()
        },
        RecordingNetworkInterceptor::default(),
    );

    let first = adapter
        .drive_quantum(QuantumRequest {
            configuration: configuration.clone(),
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("first live-network quantum should succeed: {error}"));

    assert!(first.decisions.is_empty());
    let outcome = adapter
        .drive_quantum(QuantumRequest {
            configuration: first.configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| {
            panic!("committed guest output should route through the scheduler: {error}")
        });

    assert_eq!(adapter.backend().stepped.len(), 2);
    assert_eq!(adapter.backend().stepped[0], source);
    assert_eq!(
        adapter.network_output_interceptor().batches,
        vec![(outcome.frontier, 1, 0x5a)]
    );
    assert!(!outcome.decisions.is_empty());
    let link = adapter
        .loop_impl()
        .world_network_link(
            &LinkId::for_endpoints(&source, &destination),
            NetworkLinkDirection::EndpointAToEndpointB,
        )
        .unwrap_or_else(|| panic!("scheduler-owned directed link should remain attached"));
    assert!(link.next_exact_local_event().is_some());
}

#[test]
fn backend_network_route_resolution_expands_and_locks_flood_routes() {
    let source = NodeId {
        name: String::from("vm-a"),
    };
    let destination_b = NodeId {
        name: String::from("vm-b"),
    };
    let destination_c = NodeId {
        name: String::from("vm-c"),
    };
    let world = World::from_nodes_and_links(
        vec![world_node("vm-a"), world_node("vm-b"), world_node("vm-c")],
        vec![
            LinkDef::new(source.clone(), destination_b.clone())
                .unwrap_or_else(|error| panic!("first flood link should build: {error}")),
            LinkDef::new(source.clone(), destination_c.clone())
                .unwrap_or_else(|error| panic!("second flood link should build: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("flood World should build: {error}"));
    let form = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(23),
    )
    .unwrap_or_else(|error| panic!("flood scenario should build: {error}"));
    let runtime = SchedulerLivenessScenario::from_runnable_world(
        "backend-network-flood",
        Shift::new(0).unwrap_or_else(|error| panic!("zero shift should build: {error}")),
        4,
        SimInstant { nanos: 100 },
        0,
        &world,
    )
    .with_scenario_def(form.scenario_def());
    let mut scheduler = SingleScheduler::new(runtime)
        .unwrap_or_else(|error| panic!("flood scheduler should build: {error}"));
    scheduler
        .attach_world_network_links(&world)
        .unwrap_or_else(|error| panic!("flood World network should attach: {error}"));
    let mut payload = vec![0_u8; 60];
    payload[..6].copy_from_slice(&[0xff; 6]);
    let output = BackendNetworkOutput {
        source,
        destination: NodeId {
            name: String::from("net-router"),
        },
        emit_icount: Icount { retired: 1 },
        sequence: 7,
        payload,
        route: None,
        fault_continuation: Default::default(),
    };

    let routes = scheduler
        .resolve_backend_network_routes(&output)
        .unwrap_or_else(|error| panic!("flood routes should resolve: {error}"));
    assert_eq!(routes.len(), 2);
    assert_eq!(
        routes
            .iter()
            .map(|route| route.destination.clone())
            .collect::<Vec<_>>(),
        vec![destination_b.clone(), destination_c]
    );
    let mut forced = output.clone();
    forced.fault_continuation = forced
        .fault_continuation
        .forwarding_mutation(
            ContentHash::from_bytes(b"wrong-port"),
            destination_b.clone(),
        )
        .unwrap_or_else(|| panic!("first forwarding mutation must fit"));
    let forced_routes = scheduler
        .resolve_backend_network_routes(&forced)
        .unwrap_or_else(|error| panic!("forced route should resolve: {error}"));
    assert_eq!(forced_routes.len(), 1);
    assert_eq!(forced_routes[0].destination, destination_b);
    for route in routes {
        let mut locked = output.clone();
        locked.route = Some(route.clone());
        assert_eq!(
            scheduler
                .resolve_backend_network_routes(&locked)
                .unwrap_or_else(|error| panic!("locked flood route should validate: {error}")),
            vec![route]
        );
    }
}

#[test]
fn live_world_network_frontier_replays_selected_loss_before_delivery_mutation() {
    let (default_outcome, default_loop) = network_branch_fixture(None, 0);
    let frontier = default_loop
        .loop_impl()
        .search_frontiers()
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("probabilistic live link should publish a search frontier"));
    let mut selected = Vec::new();
    for choice in frontier.choices.choices() {
        let Some(Decision::Selection(selection)) = choice.decisions().first() else {
            continue;
        };
        selected.push((selection.clone(), choice.decisions().to_vec()));
    }
    assert_eq!(selected.len(), 2);

    let mut delivery_counts = Vec::new();
    for (selection, expected_decisions) in selected {
        let (outcome, loop_impl) = network_branch_fixture(Some(selection), 0);
        assert_eq!(
            outcome.decisions.get(
                outcome
                    .decisions
                    .len()
                    .saturating_sub(expected_decisions.len())..
            ),
            Some(expected_decisions.as_slice())
        );
        let delivery_count = loop_impl
            .loop_impl()
            .world_network_link(
                &LinkId::for_endpoints(
                    &NodeId {
                        name: String::from("vm-a"),
                    },
                    &NodeId {
                        name: String::from("vm-b"),
                    },
                ),
                NetworkLinkDirection::EndpointAToEndpointB,
            )
            .map(crucible_device::NetLink::inflight_len)
            .unwrap_or_else(|| panic!("branch replay should preserve the directed link"));
        delivery_counts.push(delivery_count);
    }
    delivery_counts.sort();
    assert_eq!(delivery_counts, vec![0, 1]);
    assert!(
        default_outcome
            .decisions
            .iter()
            .all(|decision| !matches!(decision, Decision::Override(_)))
    );
}

#[test]
fn live_world_network_preselection_pauses_before_default_and_replays_its_route() {
    let (default_outcome, default_loop) = network_branch_fixture(None, 0);
    let (paused, mut adapter) = network_branch_fixture_with_pause(None, 0, true);
    let choice = adapter
        .live_network_preselection()
        .cloned()
        .unwrap_or_else(|| panic!("probabilistic frame should remain unselected"));
    let opportunity = choice
        .discovery
        .opportunity()
        .id()
        .unwrap_or_else(|error| panic!("reserved opportunity id: {error}"));

    assert_eq!(paused.configuration, choice.parent);
    assert!(paused.discovered_choices.contains(&choice.discovery));
    assert!(!paused.decisions.iter().any(|decision| {
        matches!(decision, Decision::Selection(selection)
            if selection.selection().is_ok_and(|selection| selection.opportunity() == opportunity))
    }));

    let settled = adapter
        .settle_live_network_preselection()
        .unwrap_or_else(|error| panic!("default should settle after discovery: {error}"));
    assert_eq!(settled.configuration, default_outcome.configuration);
    assert_eq!(settled.decisions, default_outcome.decisions);
    assert_eq!(
        settled.discovered_choices,
        default_outcome.discovered_choices
    );
    assert!(adapter.live_network_preselection().is_none());

    let frontier = default_loop
        .loop_impl()
        .search_frontiers()
        .first()
        .unwrap_or_else(|| panic!("default should retain an exact branch frontier"));
    assert_eq!(frontier, &choice.frontier);
    let selected = frontier
        .choices
        .choices()
        .iter()
        .find_map(|alternative| match alternative.decisions().first() {
            Some(Decision::Selection(selection)) => Some(selection.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("live network branch selection"));
    let (branched, replay) = network_branch_fixture_with_pause(Some(selected), 0, true);
    assert!(replay.live_network_preselection().is_none());
    assert!(
        branched
            .discovered_choices
            .iter()
            .any(|discovery| { discovery.opportunity().id().ok() == Some(opportunity) })
    );

    let (_paused, mut handed) = network_branch_fixture_with_pause(None, 0, true);
    handed
        .handoff_live_network_preselection(&choice)
        .unwrap_or_else(|error| panic!("exact parent can hand off its unresolved route: {error}"));
    assert!(
        handed
            .shutdown()
            .unwrap_or_else(|error| panic!("reap without defaulting: {error}"))
            .is_empty(),
        "teardown cannot append a default after the choice observation"
    );
    assert_eq!(handed.backend().shutdown_count, 1);

    let (_paused, mut unhanded) = network_branch_fixture_with_pause(None, 0, true);
    assert!(unhanded.shutdown().is_err());
    assert_eq!(unhanded.backend().shutdown_count, 1);
}

#[test]
fn live_network_preselection_does_not_intercept_a_later_due_frame() {
    let (configuration, mut adapter) = two_frame_network_adapter(None);
    adapter.set_live_network_choice_pause(true);

    let first = adapter
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("first scheduler quantum: {error}"));
    let paused = adapter
        .drive_quantum(QuantumRequest {
            configuration: first.configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("first due frame reaches preselection: {error}"));
    assert!(adapter.live_network_preselection().is_some());
    assert_eq!(adapter.network_output_interceptor().batches.len(), 1);
    assert!(
        paused
            .decisions
            .iter()
            .all(|decision| !matches!(decision, Decision::Selection(_)))
    );

    adapter
        .settle_live_network_preselection()
        .unwrap_or_else(|error| panic!("default settlement admits the remaining frame: {error}"));
    assert_eq!(adapter.network_output_interceptor().batches.len(), 2);
}

#[test]
fn live_network_preselection_two_frame_handoff_replays_the_deferred_suffix() {
    let (configuration, mut source) = two_frame_network_adapter(None);
    source.set_live_network_choice_pause(true);
    let first = source
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("first source quantum: {error}"));
    source
        .drive_quantum(QuantumRequest {
            configuration: first.configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("source preselection quantum: {error}"));
    let choice = source
        .live_network_preselection()
        .cloned()
        .unwrap_or_else(|| {
            panic!("first emitted frame is offered before the second is intercepted")
        });
    let selected = choice
        .frontier
        .choices
        .choices()
        .iter()
        .find_map(|alternative| match alternative.decisions().first() {
            Some(Decision::Selection(selection)) => Some(selection.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("source offered a selected branch"));
    source
        .handoff_live_network_preselection(&choice)
        .unwrap_or_else(|error| panic!("thin replay owns the deferred frame suffix: {error}"));
    assert!(
        source
            .shutdown()
            .unwrap_or_else(|error| panic!("source teardown: {error}"))
            .is_empty()
    );
    assert_eq!(source.network_output_interceptor().batches.len(), 1);

    let (configuration, mut replay) = two_frame_network_adapter(Some(selected.clone()));
    replay.set_live_network_choice_pause(true);
    let first = replay
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("first replay quantum: {error}"));
    let selected_outcome = replay
        .drive_quantum(QuantumRequest {
            configuration: first.configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("selected replay regenerates the second frame: {error}"));
    assert_eq!(replay.network_output_interceptor().batches.len(), 2);
    assert_eq!(
        replay
            .live_network_preselection()
            .map(|choice| choice.output.sequence),
        Some(1)
    );
    assert!(
        selected_outcome
            .decisions
            .contains(&Decision::Selection(selected))
    );
}

#[test]
fn live_network_preselection_reserves_the_first_split_route() {
    let (configuration, scheduler, backend) = network_branch_fixture_components(None, 0);
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
        SplittingNetworkInterceptor,
    );
    adapter.set_live_network_choice_pause(true);

    let first = adapter
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("first scheduler quantum: {error}"));
    let paused = adapter
        .drive_quantum(QuantumRequest {
            configuration: first.configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("split frame must reserve its first route: {error}"));

    let choice = adapter
        .live_network_preselection()
        .unwrap_or_else(|| panic!("split route choice"));
    assert_eq!(paused.configuration, choice.parent);
    assert_eq!(paused.discovered_choices, vec![choice.discovery.clone()]);
    assert!(
        !paused
            .decisions
            .iter()
            .any(|decision| matches!(decision, Decision::Selection(_)))
    );
    let settled = adapter
        .settle_live_network_preselection()
        .unwrap_or_else(|error| panic!("split suffix settles after reservation: {error}"));
    assert_eq!(settled.discovered_choices.len(), 2);
    assert_eq!(
        settled
            .decisions
            .iter()
            .filter(|decision| matches!(decision, Decision::Selection(_)))
            .count(),
        2
    );
}

#[test]
fn live_network_preselection_reserves_the_first_broadcast_route() {
    let (configuration, scheduler, backend) =
        network_branch_fixture_components_with_broadcast(None, 0, true);
    let physical = backend.network_outputs[0].clone();
    let routes = scheduler
        .backend_network_routes(physical.clone())
        .unwrap_or_else(|error| panic!("broadcast routes are canonical: {error}"));
    assert_eq!(
        scheduler
            .backend_network_route_count(&backend.network_outputs[0])
            .unwrap_or_else(|error| panic!("broadcast World routes: {error}")),
        2
    );
    let mut adapter = BackendQuantumLoop::new(scheduler, backend);
    adapter.set_live_network_choice_pause(true);

    let mut configuration = configuration;
    for _ in 0..4 {
        let outcome = adapter
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("broadcast route must reach an exact pause: {error}"));
        if let Some(choice) = adapter.live_network_preselection() {
            assert_eq!(outcome.configuration, choice.parent);
            assert_eq!(outcome.discovered_choices, vec![choice.discovery.clone()]);
            assert_eq!(choice.output.route, routes[0].route);
            assert_eq!(choice.output.source, physical.source);
            assert_eq!(choice.output.sequence, physical.sequence);
            assert_eq!(choice.output.emit_icount, physical.emit_icount);
            assert_eq!(choice.output.payload, physical.payload);
            assert!(
                !outcome
                    .decisions
                    .iter()
                    .any(|decision| matches!(decision, Decision::Selection(_)))
            );
            let settled = adapter
                .settle_live_network_preselection()
                .unwrap_or_else(|error| {
                    panic!("broadcast suffix settles after reservation: {error}")
                });
            assert_eq!(settled.discovered_choices.len(), 2);
            return;
        }
        configuration = outcome.configuration;
    }
    panic!("broadcast choice was never reserved");
}

#[test]
fn choice_free_parallel_boot_poisons_early_and_last_route_choices() {
    for source in ["vm-a", "vm-c"] {
        let (mut configuration, scheduler, mut backend) =
            network_branch_fixture_components_with_broadcast(None, 0, true);
        if source == "vm-c" {
            let output = &mut backend.network_outputs[0];
            output.source = NodeId {
                name: String::from("vm-c"),
            };
            output.payload[..6].copy_from_slice(&crucible::deterministic_node_mac(&NodeId {
                name: String::from("vm-a"),
            }));
        }
        let mut adapter = BackendQuantumLoop::new(scheduler, backend);
        adapter.set_live_network_choice_pause(true);
        adapter.set_choice_free_parallel_boot(true);

        let mut refused = false;
        for _ in 0..8 {
            let before = adapter
                .loop_impl()
                .checkpoint()
                .and_then(|checkpoint| checkpoint.canonical_bytes())
                .expect("checkpoint before parallel batch");
            let request = QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            };
            match adapter.drive_concurrent_quantum(request.clone(), 5) {
                Ok(batch) => {
                    configuration = batch
                        .outcomes
                        .last()
                        .expect("parallel batch outcome")
                        .configuration
                        .clone();
                }
                Err(error) => {
                    assert!(error.to_string().contains("choice-free parallel boot"));
                    let after = adapter
                        .loop_impl()
                        .checkpoint()
                        .and_then(|checkpoint| checkpoint.canonical_bytes())
                        .expect("checkpoint after refused batch");
                    assert_eq!(after, before, "{source} choice must not publish a batch");
                    assert!(adapter.live_network_preselection().is_none());
                    assert!(
                        adapter
                            .drive_concurrent_quantum(request, 5)
                            .expect_err("refused batch poisons continuation")
                            .to_string()
                            .contains("poisoned")
                    );
                    refused = true;
                    break;
                }
            }
        }
        assert!(
            refused,
            "{source} choice must be rejected before publication"
        );
        assert!(
            adapter
                .backend()
                .concurrent_run_sizes
                .iter()
                .any(|size| *size >= 3)
        );
    }
}

#[test]
fn post_marker_pause_keeps_the_first_choice_identical_with_one_or_five_workers() {
    let first_choice = |workers| {
        let (mut configuration, scheduler, backend) =
            network_branch_fixture_components_with_broadcast(None, 0, true);
        let mut adapter = BackendQuantumLoop::new(scheduler, backend);
        adapter.set_live_network_choice_pause(true);

        for _ in 0..8 {
            let batch = adapter
                .drive_concurrent_quantum(
                    QuantumRequest {
                        configuration,
                        control: Vec::new(),
                    },
                    workers,
                )
                .expect("serial reservation after west marker");
            if let Some(choice) = adapter.live_network_preselection() {
                return choice.clone();
            }
            configuration = batch
                .outcomes
                .last()
                .expect("scheduler outcome before first choice")
                .configuration
                .clone();
        }
        panic!("first network choice did not reach its exact reservation");
    };

    assert_eq!(first_choice(1), first_choice(5));
}

fn broadcast_preselection_quantum() -> usize {
    let (mut configuration, scheduler, backend) =
        network_branch_fixture_components_with_broadcast(None, 0, true);
    let mut adapter = BackendQuantumLoop::new(scheduler, backend);
    adapter.set_live_network_choice_pause(true);

    for quantum in 0..4 {
        let outcome = adapter
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("probe broadcast quantum: {error}"));
        if adapter.live_network_preselection().is_some() {
            return quantum;
        }
        configuration = outcome.configuration;
    }
    panic!("broadcast route did not offer a choice");
}

fn broadcast_evidence_run(
    pause: bool,
    choice_quantum: usize,
    queued: &ObservableEvent,
    current: &ObservableEvent,
    rng: &BackendRngEvidence,
) -> (
    QuantumOutcome,
    BackendQuantumLoop<SingleScheduler, NodeRecordingBackend>,
) {
    let (mut configuration, scheduler, mut backend) =
        network_branch_fixture_components_with_broadcast(None, 0, true);
    backend.observable_events.push(queued.clone());
    let mut adapter = BackendQuantumLoop::new(scheduler, backend);
    adapter.set_live_network_choice_pause(pause);

    let mut last = None;
    for quantum in 0..=choice_quantum {
        if quantum == choice_quantum {
            adapter.backend_mut().rng_evidence.push(rng.clone());
            adapter
                .backend_mut()
                .observable_events
                .push(current.clone());
        }
        let outcome = adapter
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("broadcast evidence quantum: {error}"));
        configuration = outcome.configuration.clone();
        last = Some(outcome);
    }
    (
        last.unwrap_or_else(|| panic!("broadcast quantum was executed")),
        adapter,
    )
}

#[test]
fn broadcast_reservation_defers_queued_observations_and_rng_evidence() {
    let choice_quantum = broadcast_preselection_quantum();
    assert!(choice_quantum > 0);
    let source = NodeId {
        name: String::from("vm-a"),
    };
    let queued = ObservableEvent::console_output(
        VirtualTime { ticks: 1_000 },
        source.clone(),
        b"queued".to_vec(),
    );
    let stream = RngStreamId::from_name("app-random/node:4:vm-a/stream:5:route");
    let value = Seed::from_u64(19).fork_stream(&stream).next_u64();
    let rng = BackendRngEvidence {
        node: source.clone(),
        stream,
        request_id: 0,
        width: 64,
        value,
    };
    let current =
        ObservableEvent::console_output(VirtualTime { ticks: 0 }, source, b"current".to_vec());
    let (reservation, mut paused) =
        broadcast_evidence_run(true, choice_quantum, &queued, &current, &rng);
    let choice = paused
        .live_network_preselection()
        .unwrap_or_else(|| panic!("reserved route"));
    assert_eq!(reservation.configuration, choice.parent);
    assert_eq!(
        reservation.discovered_choices,
        vec![choice.discovery.clone()]
    );
    assert!(
        !reservation
            .decisions
            .iter()
            .any(|decision| matches!(decision, Decision::RngDraw(_)))
    );
    assert!(!reservation.event_log_entries.iter().any(|entry| {
        matches!(
            entry.payload(),
            crucible::SchedulerEventLogPayload::Observable(_)
        )
    }));

    let settled = paused
        .settle_live_network_preselection()
        .unwrap_or_else(|error| {
            panic!("route suffix, RNG, and observations settle in causal order: {error}")
        });
    assert_eq!(settled.discovered_choices.len(), 3);
    let rng_position = settled
        .decisions
        .iter()
        .position(
            |decision| matches!(decision, Decision::RngDraw(draw) if draw.stream == rng.stream),
        )
        .unwrap_or_else(|| panic!("RNG evidence is committed after both routes"));
    assert_eq!(rng_position, settled.decisions.len() - 2);
    assert!(settled.event_log_entries.iter().any(|entry| {
        matches!(
            entry.payload(),
            crucible::SchedulerEventLogPayload::Observable(event)
                if event == current.payload()
        )
    }));
    assert!(!settled.event_log_entries.iter().any(|entry| {
        matches!(
            entry.payload(),
            crucible::SchedulerEventLogPayload::Observable(event)
                if event == queued.payload()
        )
    }));

    let (baseline, _uninterrupted) =
        broadcast_evidence_run(false, choice_quantum, &queued, &current, &rng);
    assert_eq!(settled.configuration, baseline.configuration);
    assert_eq!(settled.decisions, baseline.decisions);
    assert_eq!(settled.discovered_choices, baseline.discovered_choices);
}

#[test]
fn broadcast_handoff_accepts_previously_queued_observation() {
    let choice_quantum = broadcast_preselection_quantum();
    let (configuration, scheduler, mut backend) =
        network_branch_fixture_components_with_broadcast(None, 0, true);
    backend
        .observable_events
        .push(ObservableEvent::console_output(
            VirtualTime { ticks: 1_000 },
            NodeId {
                name: String::from("vm-a"),
            },
            b"queued".to_vec(),
        ));
    let mut adapter = BackendQuantumLoop::new(scheduler, backend);
    adapter.set_live_network_choice_pause(true);

    let mut configuration = configuration;
    for _ in 0..=choice_quantum {
        let outcome = adapter
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("broadcast reserves with queued observation: {error}"));
        configuration = outcome.configuration;
    }
    let choice = adapter
        .live_network_preselection()
        .cloned()
        .unwrap_or_else(|| panic!("route choice"));
    adapter
        .handoff_live_network_preselection(&choice)
        .unwrap_or_else(|error| panic!("queued suffix transfers to thin replay: {error}"));
    assert!(
        adapter
            .shutdown()
            .unwrap_or_else(|error| panic!("clean handed-off teardown: {error}"))
            .is_empty()
    );
}

#[test]
fn due_queued_broadcast_reserves_before_default_release() {
    let (configuration, scheduler, mut backend) =
        network_branch_fixture_components_with_broadcast(None, 0, true);
    let mut queued = backend.network_outputs.remove(0);
    queued.emit_icount = Icount { retired: 0 };
    let mut adapter = BackendQuantumLoop::new(scheduler, backend);
    adapter.set_live_network_choice_pause(true);
    adapter.network_transaction_parts_mut().3.push(queued);

    let settlement = adapter
        .settle_pending_network_outputs_at_current_frontier()
        .unwrap_or_else(|error| {
            panic!("due queued broadcast admits the first route only: {error}")
        });
    let reserved = settlement
        .reservation()
        .unwrap_or_else(|| panic!("queued route is reserved"));
    let (prefix_decisions, settled_configuration, _appends) = settlement.clone().into_parts();
    let choice = adapter
        .live_network_preselection()
        .unwrap_or_else(|| panic!("queued choice"));
    assert_eq!(reserved.decisions, prefix_decisions);
    assert_eq!(settled_configuration, Some(reserved.configuration.clone()));
    assert_eq!(reserved.configuration, choice.parent);
    assert_eq!(reserved.configuration, configuration);
    assert_eq!(reserved.discovered_choices, vec![choice.discovery.clone()]);
    assert!(
        !reserved
            .decisions
            .iter()
            .any(|decision| matches!(decision, Decision::Selection(_)))
    );

    let settled = adapter
        .settle_live_network_preselection()
        .unwrap_or_else(|error| panic!("default settlement releases both queued routes: {error}"));
    assert_eq!(settled.discovered_choices.len(), 2);
    assert_eq!(
        settled
            .decisions
            .iter()
            .filter(|decision| matches!(decision, Decision::Selection(_)))
            .count(),
        2
    );
}

#[test]
fn later_route_failure_poisons_the_serial_backend_continuation() {
    let choice_quantum = broadcast_preselection_quantum();
    let (configuration, scheduler, backend) =
        network_branch_fixture_components_with_broadcast(None, 0, true);
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
        FailingSecondRouteInterceptor::default(),
    );
    adapter.set_live_network_choice_pause(true);

    let mut configuration = configuration;
    for _ in 0..choice_quantum {
        let outcome = adapter
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("quantum before broadcast admission: {error}"));
        configuration = outcome.configuration;
    }
    let request = QuantumRequest {
        configuration,
        control: Vec::new(),
    };
    let error = adapter
        .drive_quantum(request.clone())
        .err()
        .unwrap_or_else(|| panic!("second route failure must abort the boundary"));
    assert!(error.to_string().contains("second route failed"));
    assert_eq!(adapter.network_output_interceptor().calls, 2);
    assert!(adapter.live_network_preselection().is_none());
    let subsequent_error = adapter
        .drive_quantum(request)
        .err()
        .unwrap_or_else(|| panic!("partially intercepted boundary must remain poisoned"));
    assert!(subsequent_error.to_string().contains("poisoned"));
}

#[test]
fn live_world_network_branch_identity_uses_the_causal_emission_ordinal() {
    let (_default_outcome, default_loop) = network_branch_fixture(None, 4_096);
    let frontier = default_loop
        .loop_impl()
        .search_frontiers()
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("probabilistic live link should publish a search frontier"));
    let selected = frontier
        .choices
        .choices()
        .iter()
        .find_map(|choice| match choice.decisions().first() {
            Some(Decision::Selection(selection)) => {
                Some((selection.clone(), choice.decisions().to_vec()))
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("loss branch should be available"));

    let (outcome, loop_impl) = network_branch_fixture(Some(selected.0), 8_192);

    assert_eq!(
        loop_impl.loop_impl().pending_branch_effect_choice_count(),
        0
    );
    assert_eq!(
        outcome
            .decisions
            .get(outcome.decisions.len().saturating_sub(selected.1.len())..),
        Some(selected.1.as_slice())
    );
}

fn network_branch_fixture(
    selected: Option<SelectionDecision>,
    ready_counter: u64,
) -> (
    QuantumOutcome,
    BackendQuantumLoop<SingleScheduler, NodeRecordingBackend>,
) {
    network_branch_fixture_with_pause(selected, ready_counter, false)
}

fn network_branch_fixture_with_pause(
    selected: Option<SelectionDecision>,
    ready_counter: u64,
    pause_before_choice: bool,
) -> (
    QuantumOutcome,
    BackendQuantumLoop<SingleScheduler, NodeRecordingBackend>,
) {
    let (configuration, scheduler, backend) =
        network_branch_fixture_components(selected, ready_counter);
    let mut adapter = BackendQuantumLoop::new(scheduler, backend);
    adapter.set_live_network_choice_pause(pause_before_choice);
    let first = adapter
        .drive_quantum(QuantumRequest {
            configuration: configuration.clone(),
            control: Vec::new(),
        })
        .unwrap_or_else(|error| {
            panic!("first live-network branch quantum should execute: {error}")
        });
    assert!(first.decisions.is_empty());
    let outcome = adapter
        .drive_quantum(QuantumRequest {
            configuration: first.configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("committed live network branch should execute: {error}"));
    (outcome, adapter)
}

fn network_branch_fixture_components(
    selected: Option<SelectionDecision>,
    ready_counter: u64,
) -> (Configuration, SingleScheduler, NodeRecordingBackend) {
    network_branch_fixture_components_with_broadcast(selected, ready_counter, false)
}

fn two_frame_network_adapter(
    selected: Option<SelectionDecision>,
) -> (
    Configuration,
    BackendQuantumLoop<SingleScheduler, NodeRecordingBackend, RecordingNetworkInterceptor>,
) {
    let (configuration, scheduler, mut backend) = network_branch_fixture_components(selected, 0);
    let mut later = backend.network_outputs[0].clone();
    later.sequence = 1;
    backend.network_outputs.push(later);
    let adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
        RecordingNetworkInterceptor::default(),
    );
    (configuration, adapter)
}

fn network_branch_fixture_components_with_broadcast(
    selected: Option<SelectionDecision>,
    ready_counter: u64,
    broadcast: bool,
) -> (Configuration, SingleScheduler, NodeRecordingBackend) {
    fn node(name: &str) -> WorldNode {
        WorldNode {
            id: NodeId {
                name: String::from(name),
            },
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }
    }

    let source = NodeId {
        name: String::from("vm-a"),
    };
    let destination = NodeId {
        name: String::from("vm-b"),
    };
    let link = LinkDef::with_transport(
        source.clone(),
        destination.clone(),
        MIN_LINK_LATENCY,
        SimDuration::default(),
        LinkLossProbability::from_millionths(250_000)
            .unwrap_or_else(|error| panic!("loss probability should build: {error}")),
        None,
    )
    .unwrap_or_else(|error| panic!("lossy test link should build: {error}"));
    let mut nodes = vec![node("vm-a"), node("vm-b")];
    let mut links = vec![link];
    if broadcast {
        let other = NodeId {
            name: String::from("vm-c"),
        };
        nodes.push(node("vm-c"));
        links.push(
            LinkDef::with_transport(
                source.clone(),
                other,
                MIN_LINK_LATENCY,
                SimDuration::default(),
                LinkLossProbability::from_millionths(250_000)
                    .unwrap_or_else(|error| panic!("loss probability: {error}")),
                None,
            )
            .unwrap_or_else(|error| panic!("second lossy link: {error}")),
        );
    }
    let world = World::from_nodes_and_links(nodes, links)
        .unwrap_or_else(|error| panic!("lossy test World should build: {error}"));
    let form = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(19),
    )
    .unwrap_or_else(|error| panic!("lossy test scenario should build: {error}"));
    let runtime = SchedulerLivenessScenario::from_runnable_world(
        "backend-network-search",
        Shift::new(0).unwrap_or_else(|error| panic!("zero shift should build: {error}")),
        4,
        SimInstant { nanos: 100 },
        ready_counter,
        &world,
    )
    .with_scenario_def(form.scenario_def());
    let mut scheduler = SingleScheduler::new(runtime)
        .unwrap_or_else(|error| panic!("lossy scheduler should build: {error}"));
    scheduler
        .attach_world_network_links(&world)
        .unwrap_or_else(|error| panic!("lossy World network should attach: {error}"));
    if let Some(choice) = selected {
        scheduler
            .install_branch_network_choices(vec![choice])
            .unwrap_or_else(|error| panic!("network branch should install: {error}"));
    }
    let configuration = scheduler.configuration().clone();
    let mut payload = vec![0_u8; 60];
    let destination_mac = if broadcast {
        [0xff; 6]
    } else {
        crucible::deterministic_node_mac(&destination)
    };
    payload[..6].copy_from_slice(&destination_mac);
    let output = BackendNetworkOutput {
        source,
        destination: NodeId {
            name: String::from("net-router"),
        },
        emit_icount: Icount {
            retired: ready_counter.saturating_add(1),
        },
        sequence: 0,
        payload,
        route: None,
        fault_continuation: Default::default(),
    };
    (
        configuration,
        scheduler,
        NodeRecordingBackend {
            network_outputs: vec![output],
            ..NodeRecordingBackend::default()
        },
    )
}
