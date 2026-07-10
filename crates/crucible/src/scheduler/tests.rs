//! Scheduler unit tests separated from the production quantum-loop implementation.

use super::*;
use crate::{RngDecision, ScenarioDef, step};

#[test]
fn quantum_loop_trait_is_object_safe() {
    struct StubLoop;

    impl QuantumLoop for StubLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime { ticks: 0 },
                advanced_node: None,
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

    let config = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.scheduler.quantum-loop",
        "scenario=stub",
    ));
    let request = QuantumRequest {
        configuration: config.clone(),
        control: Vec::new(),
    };
    let mut loop_impl = StubLoop;
    let object: &mut dyn QuantumLoop = &mut loop_impl;

    let outcome = object.drive_quantum(request);

    assert_eq!(
        outcome.as_ref().map(|outcome| &outcome.configuration),
        Ok(&config)
    );
}

#[test]
fn backend_quantum_loop_routes_gdbstub_to_wrapped_backend() {
    struct StubLoop;

    impl QuantumLoop for StubLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime { ticks: 0 },
                advanced_node: None,
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
    struct GdbBackend {
        opened: Vec<(NodeId, String)>,
    }

    impl SimulationBackend for GdbBackend {
        fn step_to(
            &mut self,
            _ceiling: VirtualTime,
        ) -> Result<crate::StepObservation, BackendError> {
            Err(BackendError::NotImplemented {
                operation: "step_to",
            })
        }

        fn apply(
            &mut self,
            _effect: &crate::BackendEffect,
            _at: VirtualTime,
        ) -> Result<(), BackendError> {
            Err(BackendError::NotImplemented { operation: "apply" })
        }

        fn snapshot(&mut self) -> Result<crate::BackendSnapshot, BackendError> {
            Err(BackendError::NotImplemented {
                operation: "snapshot",
            })
        }

        fn restore(&mut self, _snapshot: &crate::BackendSnapshot) -> Result<(), BackendError> {
            Err(BackendError::NotImplemented {
                operation: "restore",
            })
        }

        fn now(&self) -> VirtualTime {
            VirtualTime::default()
        }

        fn fingerprint(&mut self, _node: NodeId) -> Result<crate::FingerprintSample, BackendError> {
            Err(BackendError::NotImplemented {
                operation: "fingerprint",
            })
        }

        fn open_gdbstub(
            &mut self,
            node: NodeId,
            listen: GdbListen,
        ) -> Result<GdbAttachInfo, BackendError> {
            self.opened.push((node.clone(), listen.as_str().to_owned()));
            GdbAttachInfo::new(node, "tcp:127.0.0.1:9001", listen)
        }

        fn shutdown(&mut self) -> Result<(), BackendError> {
            Ok(())
        }
    }

    let mut adapter = BackendQuantumLoop::new(StubLoop, GdbBackend::default());
    let info = adapter
        .open_gdbstub(
            NodeId {
                name: String::from("vm-a"),
            },
            GdbListen::new("127.0.0.1:9000")
                .unwrap_or_else(|error| panic!("test listen should be stable: {error}")),
        )
        .unwrap_or_else(|error| panic!("backend adapter should route gdbstub attach: {error}"));

    assert_eq!(info.qemu_endpoint, "tcp:127.0.0.1:9001");
    assert_eq!(
        adapter.backend().opened,
        vec![(
            NodeId {
                name: String::from("vm-a"),
            },
            String::from("127.0.0.1:9000"),
        )]
    );
}

#[test]
fn event_log_append_rejects_class_catalog_mismatch() {
    let mut entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("class-catalog-mismatch"),
            value: 17,
        })),
    );
    entry.class = SchedulerEventLogClass::Observational;

    let error = EventLog::new()
        .append_entries(vec![entry])
        .expect_err("append must reject class/catalog mismatches");

    assert!(matches!(
        error,
        SchedulerError::BoundaryViolation { message }
            if message.contains("class observational does not match catalog class causal")
                && message.contains("payload kind rng_draw")
    ));
}

#[test]
fn event_log_append_rejects_typed_kind_catalog_drift() {
    let mut entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("typed-kind-catalog-drift"),
            value: 23,
        })),
    );
    entry.event_payload = EventPayload::new("diagnostic", entry.event_payload.attributes().clone());

    let error = EventLog::new()
        .append_entries(vec![entry])
        .expect_err("append must reject typed payload kind/catalog drift");

    assert!(matches!(
        error,
        SchedulerError::BoundaryViolation { message }
            if message.contains("class causal does not match catalog class observational")
                && message.contains("payload kind diagnostic")
    ));
}

#[test]
fn event_log_append_rejects_unknown_typed_kind() {
    let mut entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("unknown-typed-kind"),
            value: 31,
        })),
    );
    entry.event_payload = EventPayload::new(
        "unregistered_kind",
        entry.event_payload.attributes().clone(),
    );

    let error = EventLog::new()
        .append_entries(vec![entry])
        .expect_err("append must reject unknown typed payload kinds");

    assert!(matches!(
        error,
        SchedulerError::BoundaryViolation { message }
            if message.contains("payload kind unregistered_kind is not in the event-kind catalog")
    ));
}

#[test]
fn event_log_segment_binary_round_trips_to_same_bytes() {
    let previous_prefix = scheduler_event_log_empty_prefix();
    let entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 9 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("segment-round-trip"),
            value: 41,
        })),
    );
    let entries = vec![entry];
    let segment = scheduler_event_log_segment_material(previous_prefix, &entries);
    let bytes = segment.encode();

    let decoded = decode_scheduler_event_log_segment(&bytes)
        .unwrap_or_else(|error| panic!("segment should decode: {error:?}"));

    assert_eq!(decoded, segment);
    assert_eq!(decoded.encode(), bytes);
    assert_eq!(decoded.text_view(), segment.text_view());
    assert!(decoded.text_view().contains("entry.payload.kind=rng_draw"));
}

#[test]
fn scheduled_event_keys_define_total_order() {
    let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
    let vm_b = scheduler_node("b", SchedulingNodeKind::Vm);
    let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
    let mut keys = [
        event_key(2, &vm_b, &vm_a, 0),
        event_key(1, &vm_b, &disk_a, 1),
        event_key(1, &vm_a, &disk_a, 2),
        event_key(1, &vm_a, &disk_a, 1),
    ];

    keys.sort();

    assert_eq!(
        keys,
        [
            event_key(1, &vm_a, &disk_a, 1),
            event_key(1, &vm_a, &disk_a, 2),
            event_key(1, &vm_b, &disk_a, 1),
            event_key(2, &vm_b, &vm_a, 0),
        ]
    );
}

#[test]
fn scheduled_event_keys_cover_producer_tie_break() {
    let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
    let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
    let network_a = scheduler_node("a", SchedulingNodeKind::Network);
    let mut keys = [
        event_key(1, &vm_a, &network_a, 1),
        event_key(1, &vm_a, &disk_a, 1),
    ];

    keys.sort();

    assert_eq!(
        keys,
        [
            event_key(1, &vm_a, &disk_a, 1),
            event_key(1, &vm_a, &network_a, 1),
        ]
    );
}

#[test]
fn scheduled_events_resolve_by_key_not_arrival_order() {
    let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
    let vm_b = scheduler_node("b", SchedulingNodeKind::Vm);
    let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
    let network_a = scheduler_node("a", SchedulingNodeKind::Network);
    let mut events = vec![
        event(1, &vm_b, &disk_a, 0, b"third"),
        event(2, &vm_a, &disk_a, 0, b"fourth"),
        event(1, &vm_a, &network_a, 1, b"second"),
        event(1, &vm_a, &disk_a, 7, b"first"),
    ];

    let payloads = ordered_scheduled_events(&events)
        .iter()
        .map(|event| match &event.payload {
            ScheduledEventPayload::BackendInput(input) => input.payload.clone(),
            _ => panic!("test event should carry a backend input"),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        payloads,
        [
            b"first".to_vec(),
            b"second".to_vec(),
            b"third".to_vec(),
            b"fourth".to_vec(),
        ]
    );

    events.reverse();

    let reversed_payloads = ordered_scheduled_events(&events)
        .iter()
        .map(|event| match &event.payload {
            ScheduledEventPayload::BackendInput(input) => input.payload.clone(),
            _ => panic!("test event should carry a backend input"),
        })
        .collect::<Vec<_>>();

    assert_eq!(reversed_payloads, payloads);
}

#[test]
fn shared_timeline_projects_vm_and_io_counters_uniformly() {
    let timeline = shared_timeline(2);
    let vm = scheduler_node("a", SchedulingNodeKind::Vm);
    let disk = scheduler_node("a", SchedulingNodeKind::Disk);
    let network = scheduler_node("link-a-b", SchedulingNodeKind::Network);

    let vm_projection = project_counter(
        &timeline,
        vm.clone(),
        NodeCounter::from_icount(Icount { retired: 7 }),
    );
    let disk_projection = project_counter(&timeline, disk.clone(), NodeCounter { ticks: 7 });
    let network_projection = project_counter(&timeline, network.clone(), NodeCounter { ticks: 11 });

    assert_eq!(vm_projection.node, vm);
    assert_eq!(vm_projection.counter, NodeCounter { ticks: 7 });
    assert_eq!(vm_projection.virtual_time, SimInstant { nanos: 28 });
    assert_eq!(disk_projection.node, disk);
    assert_eq!(disk_projection.virtual_time, SimInstant { nanos: 28 });
    assert_eq!(network_projection.node, network);
    assert_eq!(network_projection.virtual_time, SimInstant { nanos: 44 });
}

#[test]
fn shared_timeline_keys_order_by_time_node_and_sequence() {
    let timeline = shared_timeline(1);
    let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
    let vm_b = scheduler_node("b", SchedulingNodeKind::Vm);
    let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
    let arrival_order = vec![
        timeline_key(&timeline, vm_b, 2, 0),
        timeline_key(&timeline, vm_a.clone(), 1, 5),
        timeline_key(&timeline, disk_a, 1, 2),
        timeline_key(&timeline, vm_a, 1, 1),
    ];

    let ordered = ordered_timeline_keys(&arrival_order);

    assert_eq!(
        ordered
            .iter()
            .map(|key| {
                (
                    key.virtual_time.nanos,
                    key.node.node.name.as_str(),
                    key.node.kind,
                    key.sequence,
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (2, "a", SchedulingNodeKind::Vm, 1),
            (2, "a", SchedulingNodeKind::Vm, 5),
            (2, "a", SchedulingNodeKind::Disk, 2),
            (4, "b", SchedulingNodeKind::Vm, 0),
        ]
    );
}

#[test]
fn scheduled_event_keys_consume_shared_timeline_and_refine_by_producer() {
    let timeline = shared_timeline(0);
    let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
    let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
    let network_a = scheduler_node("a", SchedulingNodeKind::Network);
    let mut keys = [
        ScheduledEventKey::new(
            timeline_key(&timeline, vm_a.clone(), 8, 9),
            network_a.clone(),
        ),
        ScheduledEventKey::new(timeline_key(&timeline, vm_a.clone(), 8, 3), disk_a.clone()),
        ScheduledEventKey::new(timeline_key(&timeline, vm_a.clone(), 8, 1), network_a),
    ];

    keys.sort();

    assert_eq!(
        keys.iter()
            .map(|key| (key.producer.kind, key.sequence()))
            .collect::<Vec<_>>(),
        vec![
            (SchedulingNodeKind::Disk, 3),
            (SchedulingNodeKind::Network, 1),
            (SchedulingNodeKind::Network, 9),
        ]
    );
}

#[test]
fn quantum_outcome_carries_step_decisions() {
    let config = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.scheduler.quantum-outcome",
        "scenario=stub",
    ));
    let decision = crate::Decision::RngDraw(crate::RngDecision {
        stream: crate::RngStreamId::from_name("scheduler"),
        value: 7,
    });
    let child = step(&config, decision.clone());
    let outcome = QuantumOutcome {
        configuration: child,
        frontier: VirtualTime { ticks: 1 },
        advanced_node: Some(scheduler_node("node-a", SchedulingNodeKind::Vm)),
        resolved_events: Vec::new(),
        decisions: vec![decision.clone()],
        event_log_entries: Vec::new(),
        event_log_segment_bytes: Vec::new(),
        event_log_segment_text: String::new(),
        event_log_segment_hash: None,
        event_log_offset: EventLogOffset::default(),
        scheduler_quiescence: None,
    };

    assert_eq!(outcome.configuration.schedule.decisions(), &[decision]);
}

#[test]
fn exact_local_deadline_selects_scheduler_horizon_and_ceiling() {
    let horizon = horizon_from_exact_local_event(
        SimInstant { nanos: 100 },
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { nanos: 41 },
        },
        shift(3),
    );

    assert_eq!(
        horizon,
        Ok(SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { nanos: 41 },
                ceiling: Icount { retired: 6 },
            },
            source: SchedulerHorizonSource::ExactLocalTimer,
        })
    );
}

#[test]
fn no_armed_timer_uses_network_horizon() {
    let horizon = horizon_from_exact_local_event(
        SimInstant { nanos: 64 },
        ExactLocalEvent::NoArmedTimer,
        shift(3),
    );

    assert_eq!(
        horizon,
        Ok(SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { nanos: 64 },
                ceiling: Icount { retired: 8 },
            },
            source: SchedulerHorizonSource::NetworkLookahead,
        })
    );
}

#[test]
fn later_exact_deadline_does_not_extend_network_horizon() {
    let horizon = horizon_from_exact_local_event(
        SimInstant { nanos: 50 },
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { nanos: 90 },
        },
        shift(2),
    );

    assert_eq!(
        horizon,
        Ok(SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { nanos: 50 },
                ceiling: Icount { retired: 13 },
            },
            source: SchedulerHorizonSource::NetworkLookahead,
        })
    );
}

#[test]
fn finite_lookahead_is_added_to_current_virtual_time() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { nanos: 20 },
        NetworkLookahead::Finite(SimDuration { nanos: 7 }),
        ExactLocalEvent::NoArmedTimer,
        shift(0),
    );

    assert_eq!(
        horizon,
        Ok(SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { nanos: 27 },
                ceiling: Icount { retired: 27 },
            },
            source: SchedulerHorizonSource::NetworkLookahead,
        })
    );
}

#[test]
fn infinite_network_lookahead_without_local_event_is_unbounded() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { nanos: 20 },
        NetworkLookahead::Infinite,
        ExactLocalEvent::NoArmedTimer,
        shift(0),
    );

    assert_eq!(horizon, Ok(SchedulerHorizon::infinite_network()));
}

#[test]
fn exact_local_event_bounds_infinite_network_lookahead() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { nanos: 20 },
        NetworkLookahead::Infinite,
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { nanos: 23 },
        },
        shift(0),
    );

    assert_eq!(
        horizon,
        Ok(SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { nanos: 23 },
                ceiling: Icount { retired: 23 },
            },
            source: SchedulerHorizonSource::ExactLocalTimer,
        })
    );
}

#[test]
fn exact_deadline_report_maps_to_scheduler_local_event() {
    assert_eq!(
        exact_local_event_from_timer_deadline_ns(Some(124_456)),
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { nanos: 124_456 },
        }
    );
    assert_eq!(
        exact_local_event_from_timer_deadline_ns(None),
        ExactLocalEvent::NoArmedTimer
    );
}

#[test]
fn scheduler_quiescence_detects_all_idle_authoritative_state() {
    let scheduler = test_scheduler(
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );

    let quiescence = scheduler
        .quiescence()
        .unwrap_or_else(|error| panic!("quiescence should compute: {error}"));

    assert!(quiescence.is_quiescent());
    assert_eq!(quiescence.blockers, Vec::new());
}

#[test]
fn scheduler_quiescence_blocks_on_runnable_node_pending_event_and_control() {
    let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("node-b", SchedulingNodeKind::Vm);
    let mut scheduler = test_scheduler(
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![event(7, &consumer, &producer, 3, b"pending")],
    );
    let control = ControlOperation {
        sequence: 11,
        kind: ControlOperationKind::Query,
    };
    scheduler.queue_control(control.clone());

    let quiescence = scheduler
        .quiescence()
        .unwrap_or_else(|error| panic!("quiescence should compute: {error}"));

    assert!(!quiescence.is_quiescent());
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingControl { operation: control })
    );
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingEvent {
                key: event_key(7, &consumer, &producer, 3),
            })
    );
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::RunnableNode { node: consumer })
    );
}

#[test]
fn scheduler_quiescence_blocks_idle_nodes_with_exact_local_wakeups() {
    let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let scheduler = test_scheduler(
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 23 },
            },
        )],
        Vec::new(),
    );

    let quiescence = scheduler
        .quiescence()
        .unwrap_or_else(|error| panic!("quiescence should compute: {error}"));

    assert_eq!(
        quiescence.blockers,
        vec![SchedulerQuiescenceBlocker::PendingExactLocalEvent {
            node,
            event: ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 23 },
            },
        }]
    );
}

#[test]
fn scheduler_quiescence_fast_forwards_idle_exact_wakeup_without_deadlock() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "idle-exact-wakeup",
        shift(0),
        8,
        SimInstant { nanos: 64 },
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 23 },
            },
        )],
        Vec::new(),
    );

    let report = check_scheduler_liveness(scenario)
        .unwrap_or_else(|error| panic!("idle exact wakeup should not deadlock: {error}"));

    assert_eq!(report.terminal, SchedulerTerminal::Quiescent);
    assert_eq!(report.frontier, VirtualTime { ticks: 23 });
    assert_eq!(
        report.advanced_nodes,
        vec![scheduler_node("node-a", SchedulingNodeKind::Vm)]
    );
}

#[test]
fn scheduler_quiescence_idle_exact_wakeup_after_time_limit_stops_at_limit() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "idle-exact-wakeup-after-limit",
        shift(0),
        8,
        SimInstant { nanos: 64 },
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 100 },
            },
        )],
        Vec::new(),
    );

    let report = check_scheduler_liveness(scenario)
        .unwrap_or_else(|error| panic!("idle exact wakeup should respect limit: {error}"));

    assert_eq!(report.terminal, SchedulerTerminal::TimeLimitReached);
    assert_eq!(report.frontier, VirtualTime { ticks: 64 });
    assert_eq!(
        report.advanced_nodes,
        vec![scheduler_node("node-a", SchedulingNodeKind::Vm)]
    );
}

#[test]
fn scheduler_quiescence_fast_forwards_idle_pending_delivery_without_deadlock() {
    let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("node-b", SchedulingNodeKind::Vm);
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "idle-pending-delivery",
        shift(0),
        8,
        SimInstant { nanos: 64 },
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![event(17, &consumer, &producer, 0, b"wake")],
    );

    let report = check_scheduler_liveness(scenario)
        .unwrap_or_else(|error| panic!("idle pending delivery should not deadlock: {error}"));

    assert_eq!(report.terminal, SchedulerTerminal::Quiescent);
    assert_eq!(report.frontier, VirtualTime { ticks: 17 });
    assert_eq!(report.resolved_events, 1);
}

#[test]
fn scheduler_quiescence_blocks_future_io_and_fault_events() {
    let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let disk = scheduler_node("node-a", SchedulingNodeKind::Disk);
    let control_plane = scheduler_node("plan", SchedulingNodeKind::ControlPlane);
    let fault = FaultId {
        name: String::from("planned-fault"),
    };
    let scheduler = test_scheduler(
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![
            io_completion_event(5, &consumer, &disk, 1, b"io"),
            fault_event(9, &consumer, &control_plane, 2, fault),
        ],
    );

    let quiescence = scheduler
        .quiescence()
        .unwrap_or_else(|error| panic!("quiescence should compute: {error}"));

    assert!(!quiescence.is_quiescent());
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingEvent {
                key: event_key(5, &consumer, &disk, 1),
            })
    );
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingEvent {
                key: event_key(9, &consumer, &control_plane, 2),
            })
    );
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingExactLocalEvent {
                node: consumer,
                event: ExactLocalEvent::IoCompletion {
                    virtual_time: SimInstant { nanos: 5 },
                    sub_node: disk,
                },
            })
    );
}

#[test]
fn scheduler_quiescence_ignores_idle_nodes_when_peer_can_advance() {
    let runner = scheduler_node("runner", SchedulingNodeKind::Vm);
    let mut scheduler = test_scheduler(
        vec![
            test_scenario_node(
                "idle",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Finite(SimDuration { nanos: 1 }),
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 100 },
                },
            ),
            test_scenario_node(
                "runner",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Finite(SimDuration { nanos: 4 }),
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    );

    let quiescence = scheduler
        .quiescence()
        .unwrap_or_else(|error| panic!("quiescence should compute: {error}"));
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };
    let outcome = scheduler
        .drive_quantum(request)
        .unwrap_or_else(|error| panic!("runnable peer should advance: {error}"));

    assert_eq!(
        quiescence.blockers,
        vec![
            SchedulerQuiescenceBlocker::PendingExactLocalEvent {
                node: scheduler_node("idle", SchedulingNodeKind::Vm),
                event: ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 100 },
                },
            },
            SchedulerQuiescenceBlocker::RunnableNode {
                node: runner.clone(),
            },
        ]
    );
    assert_eq!(outcome.advanced_node, Some(runner));
}

#[test]
fn search_frontier_choices_from_scheduled_events_captures_probabilistic_fault_branches() {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.scheduler.search-frontier",
        "scenario=probabilistic-fault",
    ));
    let consumer = scheduler_node("vm-a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("control", SchedulingNodeKind::ControlPlane);
    let fault = FaultId {
        name: String::from("packet-loss"),
    };
    let event = probabilistic_fault_event(13, &consumer, &producer, 0, fault.clone());

    let choices = search_frontier_choices_from_scheduled_events(configuration, &[event]);
    let outcomes = choices
        .decisions()
        .iter()
        .map(|decision| match decision {
            Decision::FaultFires(fired) if fired.fault == fault => fired.fired,
            other => panic!("unexpected search frontier decision: {other:?}"),
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(choices.decisions().len(), 2);
    assert!(choices.choices().iter().all(|choice| {
        matches!(
            choice.decisions(),
            [Decision::RngDraw(_), Decision::FaultFires(_)]
        )
    }));
    assert_eq!(outcomes, BTreeSet::from([false, true]));
}

#[test]
fn scheduler_errors_render_all_variants_deterministically() {
    let backend = SchedulerError::from(BackendError::Rejected {
        message: String::from("backend refused"),
    });
    let boundary = SchedulerError::BoundaryViolation {
        message: String::from("bypassed scheduler boundary"),
    };
    let not_implemented = SchedulerError::NotImplemented { operation: "pick" };
    let conversion = SchedulerError::from(TimeConversionError::InvalidShift {
        shift: Shift { bits: 64 },
    });

    assert_eq!(
        not_implemented.to_string(),
        "scheduler operation pick is not implemented yet"
    );
    assert_eq!(
        backend.to_string(),
        "backend failed under scheduler control: backend refused"
    );
    assert_eq!(boundary.to_string(), "bypassed scheduler boundary");
    assert_eq!(
        conversion.to_string(),
        "scheduler virtual-time conversion failed: icount shift 64 cannot be represented as u64"
    );
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_string(),
        },
        kind,
    }
}

fn shared_timeline(bits: u8) -> SharedTimeline {
    match SharedTimeline::new(shift(bits)) {
        Ok(timeline) => timeline,
        Err(error) => panic!("test timeline should be valid: {error}"),
    }
}

fn shift(bits: u8) -> Shift {
    match Shift::new(bits) {
        Ok(shift) => shift,
        Err(error) => panic!("test shift should be valid: {error}"),
    }
}

fn project_counter(
    timeline: &SharedTimeline,
    node: SchedulerNodeId,
    counter: NodeCounter,
) -> NodeTimelineProjection {
    match timeline.project_counter(node, counter) {
        Ok(projection) => projection,
        Err(error) => panic!("test counter should project: {error}"),
    }
}

fn timeline_key(
    timeline: &SharedTimeline,
    node: SchedulerNodeId,
    counter: u64,
    sequence: u64,
) -> SharedTimelineKey {
    match timeline.timeline_key(node, NodeCounter { ticks: counter }, sequence) {
        Ok(key) => key,
        Err(error) => panic!("test timeline key should project: {error}"),
    }
}

fn event_key(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
) -> ScheduledEventKey {
    ScheduledEventKey::from_parts(
        VirtualTime {
            ticks: virtual_time,
        },
        consumer.clone(),
        producer.clone(),
        sequence,
    )
}

fn event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: event_key(virtual_time, consumer, producer, sequence),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: payload.to_vec(),
        }),
    }
}

fn test_scheduler(
    nodes: Vec<SchedulerScenarioNode>,
    pending_events: Vec<ScheduledEvent>,
) -> SingleScheduler {
    SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "test-scheduler-quiescence",
        shift(0),
        16,
        SimInstant { nanos: 64 },
        nodes,
        pending_events,
    ))
    .unwrap_or_else(|error| panic!("test scheduler should build: {error}"))
}

fn test_scenario_node(
    name: &str,
    counter: u64,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name, SchedulingNodeKind::Vm),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead,
        exact_local_event,
    }
}

fn io_completion_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: event_key(virtual_time, consumer, producer, sequence),
        payload: ScheduledEventPayload::IoCompletion(IoCompletion {
            sub_node: producer.clone(),
            target: consumer.node.clone(),
            delivery_icount: Icount {
                retired: virtual_time,
            },
            payload: payload.to_vec(),
        }),
    }
}

fn fault_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    fault: FaultId,
) -> ScheduledEvent {
    ScheduledEvent {
        key: event_key(virtual_time, consumer, producer, sequence),
        payload: ScheduledEventPayload::FaultActivation(fault),
    }
}

fn probabilistic_fault_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    fault: FaultId,
) -> ScheduledEvent {
    ScheduledEvent {
        key: event_key(virtual_time, consumer, producer, sequence),
        payload: ScheduledEventPayload::ProbabilisticFault(SchedulerResolveFaultChoice {
            fault,
            stream: RngStreamId::from_name("test-probabilistic-fault"),
            rate: FaultRateBasisPoints::from_basis_points(5_000)
                .unwrap_or_else(|error| panic!("test rate should be valid: {error}")),
        }),
    }
}

/// Builds a fault-free disk scheduling sub-node targeting VM node `target`,
/// with the given `(request_icount, count)` reads pre-submitted.
fn disk_with_reads(
    target: &str,
    device_name: &str,
    reads: &[(u64, u32)],
) -> crate::device_subnode::DeviceSchedulingSubNode {
    use crucible_device::{BaseImage, BlockDevice, BlockLatency, BlockRequest, IoCore};

    let core = match IoCore::new(0, 1, 16, 16) {
        Ok(core) => core,
        Err(error) => panic!("io core should construct: {error}"),
    };
    let block = BlockDevice::new(
        core,
        BaseImage::new(vec![0x5a; 4096]),
        BlockLatency::default(),
    );
    let mut sub_node = crate::device_subnode::DeviceSchedulingSubNode::new(
        scheduler_node(device_name, SchedulingNodeKind::Disk),
        NodeId {
            name: target.to_string(),
        },
        crate::DeviceId {
            name: device_name.to_string(),
        },
        block,
        crate::Seed::from_u64(0x0d15_c0de),
    );
    for (index, (request_icount, count)) in reads.iter().enumerate() {
        let request_id = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if let Err(error) =
            sub_node.submit(*request_icount, &BlockRequest::read(request_id, 0, *count))
        {
            panic!("disk submit should succeed: {error}");
        }
    }
    sub_node
}

#[test]
fn resolve_device_completions_stamps_each_completion_at_its_exact_icount() {
    // The integration capstone ([SCHED-29], [IO-2]): two sequential disk reads
    // resolved at a single consumer frontier above the head completion are each
    // made visible at their OWN exact delivery icount, in canonical order — not
    // collapsed onto the consumer frontier.
    let mut scheduler = test_scheduler(
        vec![test_scenario_node(
            "a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    scheduler =
        scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(0, 8), (2000, 8)]));

    assert!(
        scheduler.has_undelivered_device_completion(),
        "submitted reads must leave completions in flight"
    );

    let node = scheduler_node("a", SchedulingNodeKind::Vm);
    let (events, _decisions) = match scheduler.resolve_device_completions(&node, 3008) {
        Ok(resolved) => resolved,
        Err(error) => panic!("resolve should succeed: {error}"),
    };
    let stamped: Vec<u64> = events
        .iter()
        .map(|event| event.key.virtual_time().ticks)
        .collect();

    assert_eq!(
        stamped,
        vec![1008, 3008],
        "each completion is stamped at its own exact delivery icount"
    );
    assert!(
        !scheduler.has_undelivered_device_completion(),
        "both completions must be drained after RESOLVE"
    );
}

#[test]
fn refresh_device_horizons_folds_the_inflight_head_into_the_node_horizon() {
    // [IO-3]/[SCHED-10]: the device sub-node's in-flight head delivery icount
    // becomes the owning node's exact I/O-completion horizon term (a horizon
    // TERM, not a deliverable pending event — delivery stays on the RESOLVE
    // path so it is never double-counted). A second refresh is idempotent.
    let mut scheduler = test_scheduler(
        vec![test_scenario_node(
            "a",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    scheduler = scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(0, 8)]));

    scheduler
        .refresh_device_horizons()
        .unwrap_or_else(|error| panic!("refresh should succeed: {error}"));

    // No deliverable event was injected into the pending-event queue.
    assert!(
        !scheduler
            .pending_events
            .iter()
            .any(|event| matches!(event.payload, ScheduledEventPayload::IoCompletion(_))),
        "refresh must not inject a deliverable IoCompletion event"
    );

    // The in-flight head bounds the node's effective exact local event.
    let node_a = scheduler
        .nodes
        .iter()
        .find(|runtime| runtime.id.node.name == "a")
        .unwrap_or_else(|| panic!("node a should exist"));
    let exact = scheduler
        .effective_exact_local_event(node_a)
        .unwrap_or_else(|error| panic!("effective horizon should compute: {error}"));
    assert!(
        matches!(
            exact,
            ExactLocalEvent::IoCompletion { virtual_time, .. } if virtual_time.nanos == 1008
        ),
        "the in-flight head (icount 1008) must bound the node horizon, got {exact:?}"
    );

    // The idle requester is re-activated so it advances to the completion.
    assert!(
        scheduler
            .nodes
            .iter()
            .any(|runtime| runtime.id.node.name == "a"
                && runtime.activity == SchedulerNodeActivity::Runnable),
        "an idle requester that owes a completion must be re-activated"
    );

    // A second refresh recomputes the same single horizon term (idempotent).
    scheduler
        .refresh_device_horizons()
        .unwrap_or_else(|error| panic!("second refresh should succeed: {error}"));
    assert_eq!(
        scheduler.device_horizons.len(),
        1,
        "refresh must be idempotent and record exactly one horizon term"
    );
}

#[test]
fn device_completion_flows_through_live_drive_quantum_at_exact_icount() {
    // ITEM 1 teeth: a device completion submitted to a sub-node is delivered
    // through the LIVE `drive_quantum` (not the building blocks) at EXACTLY its
    // delivery icount ([SCHED-29], [IO-2]). The device horizon caps the
    // requester's advance so it is fast-forwarded to exactly the completion.
    // A time limit comfortably past the completion icount (1008) so the
    // requester can advance to it; budget large enough to reach it.
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "test-device-live-drive",
        shift(0),
        4_096,
        SimInstant { nanos: 4_096 },
        vec![test_scenario_node(
            "a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    let mut scheduler = SingleScheduler::new(scenario)
        .unwrap_or_else(|error| panic!("scheduler should build: {error}"));
    scheduler = scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(0, 8)]));

    // Drive quanta until the run quiesces, recording the icount at which the
    // IoCompletion was resolved through the LIVE loop.
    let mut delivered = None;
    for _ in 0..16 {
        let outcome = scheduler
            .drive_quantum(QuantumRequest {
                configuration: scheduler.configuration().clone(),
                control: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("drive_quantum should succeed: {error}"));
        if let Some(event) = outcome
            .resolved_events
            .iter()
            .find(|event| matches!(event.payload, ScheduledEventPayload::IoCompletion(_)))
        {
            delivered = Some(event.key.virtual_time().ticks);
        }
        if scheduler
            .quiescence()
            .unwrap_or_else(|error| panic!("quiescence should compute: {error}"))
            .is_quiescent()
        {
            break;
        }
    }

    assert_eq!(
        delivered,
        Some(1008),
        "the live loop must deliver the completion at its EXACT delivery icount"
    );
    // Once delivered, nothing remains in flight and the system quiesces.
    assert!(
        !scheduler.has_undelivered_device_completion(),
        "no device completion may remain in flight after delivery"
    );
    assert!(
        scheduler
            .quiescence()
            .unwrap_or_else(|error| panic!("quiescence should compute: {error}"))
            .is_quiescent(),
        "the run must quiesce once the completion has been delivered"
    );
}

#[test]
fn broken_device_delivery_stamp_diverges_proving_gate_falsifiability() {
    // The falsifiability proof for the exact-icount property ([IO-2], [DET-19]).
    // Driving PRODUCTION `resolve_device_completions` at a frontier ABOVE the
    // head completion (the one configuration where exact and frontier provably
    // differ), the exact path stamps each completion at its OWN icount while the
    // freeze-time bug stamps BOTH at the shared consumer frontier — so the
    // resolved-icount vector diverges and a determinism gate would go red.
    let resolve_at_frontier = |broken: bool| -> Vec<u64> {
        let mut scheduler = test_scheduler(
            vec![test_scenario_node(
                "a",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )],
            Vec::new(),
        );
        scheduler =
            scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(0, 8), (2000, 8)]));
        if broken {
            scheduler = scheduler.with_broken_device_delivery_stamp();
        }
        let node = scheduler_node("a", SchedulingNodeKind::Vm);
        let (events, _decisions) = scheduler
            .resolve_device_completions(&node, 3008)
            .unwrap_or_else(|error| panic!("resolve should succeed: {error}"));
        events
            .iter()
            .map(|event| event.key.virtual_time().ticks)
            .collect()
    };

    assert_eq!(
        resolve_at_frontier(false),
        vec![1008, 3008],
        "exact stamps are each completion's own delivery icount"
    );
    assert_eq!(
        resolve_at_frontier(true),
        vec![3008, 3008],
        "the freeze-time bug collapses both onto the consumer frontier"
    );
    assert_ne!(
        resolve_at_frontier(false),
        resolve_at_frontier(true),
        "exact delivery must be distinguishable from frontier delivery"
    );
}
