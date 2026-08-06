//! Node-address preservation tests for live backend scheduling.

use crucible::{
    BackendEffect, BackendError, BackendInput, BackendNetworkOutput,
    BackendNetworkOutputInterceptor, BackendNetworkRoute, BackendQuantumLoop, BackendSnapshot,
    Configuration, Decision, EventLogOffset, ExactLocalEvent, FingerprintSample, Icount, LinkDef,
    LinkId, LinkLossProbability, MIN_LINK_LATENCY, NetworkLinkDirection, NetworkLookahead,
    NodeCounter, NodeId, NodeTemplate, OverrideDecision, Plan, Properties, QuantumLoop,
    QuantumOutcome, QuantumRequest, ReadyPoint, ScenarioDef, ScenarioDefForm, ScheduledEvent,
    ScheduledEventKey, ScheduledEventPayload, SchedulerError, SchedulerLivenessScenario,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, Seed, Shift, SimDuration,
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
}

impl SimulationBackend for NodeRecordingBackend {
    fn step_to(&mut self, _ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        Err(BackendError::NotImplemented {
            operation: "backend-global step_to",
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

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        Err(BackendError::NotImplemented {
            operation: "snapshot",
        })
    }

    fn restore(&mut self, _snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        Err(BackendError::NotImplemented {
            operation: "restore",
        })
    }

    fn now(&self) -> VirtualTime {
        VirtualTime::default()
    }

    fn fingerprint(&mut self, _node: NodeId) -> Result<FingerprintSample, BackendError> {
        Err(BackendError::NotImplemented {
            operation: "fingerprint",
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        Ok(())
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
        key: ScheduledEventKey::from_parts(
            VirtualTime { ticks: 17 },
            destination.clone(),
            source,
            3,
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
            &LinkId::from_name("vm-a--vm-b"),
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
        vec![destination_b, destination_c]
    );
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
    let (deeffect_outcome, default_loop) = network_branch_fixture(None, 0);
    let frontier = default_loop
        .loop_impl()
        .search_frontiers()
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("probabilistic live link should publish a search frontier"));
    let mut selected = Vec::new();
    for choice in frontier.choices.choices() {
        let Some(Decision::Override(override_decision)) = choice.decisions().first() else {
            continue;
        };
        selected.push((override_decision.clone(), choice.decisions().to_vec()));
    }
    assert_eq!(selected.len(), 2);

    let mut delivery_counts = Vec::new();
    for (override_decision, expected_decisions) in selected {
        let (outcome, loop_impl) = network_branch_fixture(Some(override_decision.clone()), 0);
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
                &LinkId::from_name("vm-a--vm-b"),
                NetworkLinkDirection::EndpointAToEndpointB,
            )
            .map(crucible_device::NetLink::inflight_len)
            .unwrap_or_else(|| panic!("branch replay should preserve the directed link"));
        delivery_counts.push((override_decision.choice.name, delivery_count));
    }
    delivery_counts.sort();
    assert_eq!(
        delivery_counts,
        vec![
            (String::from("loss-fire"), 0),
            (String::from("loss-pass"), 1),
        ]
    );
    assert!(
        deeffect_outcome
            .decisions
            .iter()
            .all(|decision| !matches!(decision, Decision::Override(_)))
    );
}

#[test]
fn live_world_network_branch_identity_uses_the_causal_emission_ordinal() {
    let (_deeffect_outcome, default_loop) = network_branch_fixture(None, 4_096);
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
            Some(Decision::Override(override_decision))
                if override_decision.choice.name == "loss-fire" =>
            {
                Some((override_decision.clone(), choice.decisions().to_vec()))
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
    selected: Option<OverrideDecision>,
    ready_counter: u64,
) -> (
    QuantumOutcome,
    BackendQuantumLoop<SingleScheduler, NodeRecordingBackend>,
) {
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
    let world = World::from_nodes_and_links(vec![node("vm-a"), node("vm-b")], vec![link])
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
    payload[..6].copy_from_slice(&crucible::deterministic_node_mac(&destination));
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
    };
    let mut adapter = BackendQuantumLoop::new(
        scheduler,
        NodeRecordingBackend {
            network_outputs: vec![output],
            ..NodeRecordingBackend::default()
        },
    );
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
