//! Scheduler unit tests separated from the production quantum-loop implementation.

macro_rules! accepted_step {
    ($configuration:expr, $decision:expr $(,)?) => {
        crate::try_step($configuration, $decision)
            .unwrap_or_else(|error| panic!("test configuration step should be accepted: {error}"))
    };
}

use super::*;
use crate::model::{
    BindingSearchCandidateSemantics, BindingSearchChoice, SearchChoiceId, SearchOverride,
};
use crate::{
    BackendNetworkFaultContinuation, BackendSnapshot, IoEventKind, MockSimulationBackend,
    RngDecision, ScenarioDef, StepObservation,
};

#[path = "tests/concurrent.rs"]
mod concurrent;
#[path = "tests/event_log_contracts.rs"]
mod event_log_contracts;
#[path = "tests/network_checkpoint.rs"]
mod network_checkpoint;
#[path = "tests/ordering.rs"]
mod ordering;
#[path = "tests/production_backend.rs"]
mod production_backend;

#[test]
fn pending_network_boundary_release_settles_before_a_far_quantum() {
    use std::cell::Cell;
    use std::rc::Rc;

    struct FarLoop;

    impl QuantumLoop for FarLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime { ticks: 10_000 },
                advanced_node: None,
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

        fn backend_network_output_time(
            &self,
            _node: &NodeId,
            _at: Icount,
        ) -> Result<VirtualTime, SchedulerError> {
            Ok(VirtualTime { ticks: 0 })
        }
    }

    struct RecordingInterceptor(Rc<Cell<Option<u64>>>);

    impl BackendNetworkOutputInterceptor<FarLoop, MockSimulationBackend> for RecordingInterceptor {
        fn intercept_network_outputs(
            &mut self,
            _loop_impl: &mut FarLoop,
            _backend: &mut MockSimulationBackend,
            frontier: VirtualTime,
            _pending_outputs: &mut Vec<BackendNetworkOutput>,
            outputs: &mut Vec<BackendNetworkOutput>,
        ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
            self.0.set(Some(frontier.ticks));
            outputs.clear();
            Ok(Vec::new())
        }
    }

    let observed = Rc::new(Cell::new(None));
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        FarLoop,
        MockSimulationBackend::default(),
        RecordingInterceptor(Rc::clone(&observed)),
    );
    let opportunity = ContentHash::from_bytes(b"boundary-release");
    let mut output = BackendNetworkOutput {
        source: NodeId {
            name: String::from("source"),
        },
        destination: NodeId {
            name: String::from("destination"),
        },
        emit_icount: Icount { retired: 0 },
        sequence: 1,
        payload: vec![1],
        route: None,
        fault_continuation: BackendNetworkFaultContinuation::default(),
    };
    output
        .fault_continuation
        .cursor_mut()
        .defer_until(10_000, opportunity);
    output
        .fault_continuation
        .cursor_mut()
        .reschedule_queue_until(opportunity, 0)
        .unwrap_or_else(|error| panic!("release pending frame: {error}"));
    adapter.network_transaction_parts_mut().3.push(output);
    assert_eq!(adapter.pending_network_output_count(), 1);

    let settlement = adapter
        .settle_pending_network_outputs_at_current_frontier()
        .unwrap_or_else(|error| panic!("settle boundary frame: {error}"));
    let (decisions, configuration, appends) = settlement.into_parts();
    assert!(decisions.is_empty());
    assert!(configuration.is_none());
    assert!(appends.is_empty());
    assert_eq!(observed.get(), Some(0));
    assert!(adapter.network_transaction_parts_mut().3.is_empty());
    assert_eq!(adapter.pending_network_output_count(), 0);
}

#[test]
fn equal_boundary_custody_releases_settle_in_priority_order() {
    use std::cell::RefCell;
    use std::rc::Rc;

    struct BoundaryLoop;

    impl QuantumLoop for BoundaryLoop {
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
                discovered_choices: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: EventLogOffset::default(),
                scheduler_quiescence: None,
            })
        }

        fn backend_network_output_time(
            &self,
            _node: &NodeId,
            _at: Icount,
        ) -> Result<VirtualTime, SchedulerError> {
            Ok(VirtualTime { ticks: 0 })
        }
    }

    struct SequenceInterceptor(Rc<RefCell<Vec<u64>>>);

    impl BackendNetworkOutputInterceptor<BoundaryLoop, MockSimulationBackend> for SequenceInterceptor {
        fn intercept_network_outputs(
            &mut self,
            _loop_impl: &mut BoundaryLoop,
            _backend: &mut MockSimulationBackend,
            _frontier: VirtualTime,
            _pending_outputs: &mut Vec<BackendNetworkOutput>,
            outputs: &mut Vec<BackendNetworkOutput>,
        ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
            self.0
                .borrow_mut()
                .extend(outputs.iter().map(|output| output.sequence));
            outputs.clear();
            Ok(Vec::new())
        }
    }

    let observed = Rc::new(RefCell::new(Vec::new()));
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        BoundaryLoop,
        MockSimulationBackend::default(),
        SequenceInterceptor(Rc::clone(&observed)),
    );
    for (sequence, priority) in [(1_u64, 3_u8), (2_u64, 0_u8)] {
        let opportunity = ContentHash::from_bytes(&sequence.to_be_bytes());
        let mut output = BackendNetworkOutput {
            source: NodeId {
                name: String::from("source"),
            },
            destination: NodeId {
                name: String::from("destination"),
            },
            emit_icount: Icount { retired: 0 },
            sequence,
            payload: vec![u8::try_from(sequence).unwrap_or(0)],
            route: None,
            fault_continuation: BackendNetworkFaultContinuation::default(),
        };
        output
            .fault_continuation
            .cursor_mut()
            .defer_repeated_effect_until(
                0,
                opportunity,
                crate::model::EffectKind::NetworkCustodyQueue,
                Some(priority),
            );
        adapter.network_transaction_parts_mut().3.push(output);
    }
    adapter
        .network_transaction_parts_mut()
        .3
        .push(BackendNetworkOutput {
            source: NodeId {
                name: String::from("source"),
            },
            destination: NodeId {
                name: String::from("destination"),
            },
            emit_icount: Icount { retired: 0 },
            sequence: 3,
            payload: vec![3],
            route: None,
            fault_continuation: BackendNetworkFaultContinuation::default(),
        });

    adapter
        .settle_pending_network_outputs_at_current_frontier()
        .unwrap_or_else(|error| panic!("settle prioritized custody frames: {error}"));
    assert_eq!(&*observed.borrow(), &[2, 3, 1]);
}

#[test]
fn failed_exact_boundary_network_append_poison_preserves_pending_frame() {
    struct RejectingLoop;

    impl QuantumLoop for RejectingLoop {
        fn drive_quantum(
            &mut self,
            _request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            Err(SchedulerError::BoundaryViolation {
                message: String::from("drive must not follow poison"),
            })
        }

        fn backend_network_output_time(
            &self,
            _node: &NodeId,
            _at: Icount,
        ) -> Result<VirtualTime, SchedulerError> {
            Ok(VirtualTime { ticks: 0 })
        }
    }

    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        RejectingLoop,
        MockSimulationBackend::default(),
        NoopBackendNetworkOutputInterceptor,
    );
    let opportunity = ContentHash::from_bytes(b"failed-boundary-release");
    let mut output = BackendNetworkOutput {
        source: NodeId {
            name: String::from("source"),
        },
        destination: NodeId {
            name: String::from("destination"),
        },
        emit_icount: Icount { retired: 0 },
        sequence: 9,
        payload: vec![9],
        route: None,
        fault_continuation: BackendNetworkFaultContinuation::default(),
    };
    output
        .fault_continuation
        .cursor_mut()
        .defer_until(100, opportunity);
    output
        .fault_continuation
        .cursor_mut()
        .reschedule_queue_until(opportunity, 0)
        .unwrap_or_else(|error| panic!("release failed-append frame: {error}"));
    adapter
        .network_transaction_parts_mut()
        .3
        .push(output.clone());

    assert!(
        adapter
            .settle_pending_network_outputs_at_current_frontier()
            .is_err()
    );
    assert_eq!(adapter.network_transaction_parts_mut().3, &[output]);
    let config = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.scheduler.poisoned-network-settlement",
        "scenario=poisoned-network-settlement",
    ));
    let error = adapter
        .drive_quantum(QuantumRequest {
            configuration: config,
            control: Vec::new(),
        })
        .expect_err("poisoned settlement must reject all later drive attempts");
    assert!(
        error
            .to_string()
            .contains("backend continuation is poisoned")
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
    let timeline = SharedTimeline::new();
    let vm = scheduler_node("a", SchedulingNodeKind::Vm);
    let disk = scheduler_node("a", SchedulingNodeKind::Disk);
    let network = scheduler_node("link-a-b", SchedulingNodeKind::Network);

    let vm_projection = project_counter(
        &timeline,
        vm.clone(),
        NodeCounter::from_tick(SimInstant { ticks: 7 }),
    );
    let disk_projection = project_counter(&timeline, disk.clone(), NodeCounter { ticks: 7 });
    let network_projection = project_counter(&timeline, network.clone(), NodeCounter { ticks: 11 });

    assert_eq!(vm_projection.node, vm);
    assert_eq!(vm_projection.counter, NodeCounter { ticks: 7 });
    assert_eq!(vm_projection.virtual_time, SimInstant { ticks: 7 });
    assert_eq!(disk_projection.node, disk);
    assert_eq!(disk_projection.virtual_time, SimInstant { ticks: 7 });
    assert_eq!(network_projection.node, network);
    assert_eq!(network_projection.virtual_time, SimInstant { ticks: 11 });
}

#[test]
fn shared_timeline_keys_order_by_time_node_and_sequence() {
    let timeline = SharedTimeline::new();
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
                    key.virtual_time.ticks,
                    key.node.node.name.as_str(),
                    key.node.kind,
                    key.sequence,
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (1, "a", SchedulingNodeKind::Vm, 1),
            (1, "a", SchedulingNodeKind::Vm, 5),
            (1, "a", SchedulingNodeKind::Disk, 2),
            (2, "b", SchedulingNodeKind::Vm, 0),
        ]
    );
}

#[test]
fn scheduled_event_keys_consume_shared_timeline_and_refine_by_producer() {
    let timeline = SharedTimeline::new();
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
    let child = accepted_step!(&config, decision.clone());
    let outcome = QuantumOutcome {
        configuration: child,
        frontier: VirtualTime { ticks: 1 },
        advanced_node: Some(scheduler_node("node-a", SchedulingNodeKind::Vm)),
        resolved_events: Vec::new(),
        decisions: vec![decision.clone()],
        discovered_choices: Vec::new(),
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
fn coverage_observation_identity_excludes_event_position() {
    let observation = EventLogCoverageObservation::Named {
        node: NodeId {
            name: String::from("node-a"),
        },
        marker: MarkerId::from_name("covered"),
    };
    let repeated = observation.clone();
    let distinct = EventLogCoverageObservation::Named {
        node: NodeId {
            name: String::from("node-a"),
        },
        marker: MarkerId::from_name("other"),
    };

    assert_eq!(observation.content_hash(), repeated.content_hash());
    assert_ne!(observation.content_hash(), distinct.content_hash());
}

#[test]
fn exact_local_deadline_selects_scheduler_horizon_and_ceiling() {
    let horizon = horizon_from_exact_local_event(
        SimInstant { ticks: 100 },
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks: 41 },
        },
    );

    assert_eq!(
        horizon,
        SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { ticks: 41 },
                ceiling: NodeCounter { ticks: 41 },
            },
            source: SchedulerHorizonSource::ExactLocalTimer,
        }
    );
}

#[test]
fn no_armed_timer_uses_network_horizon() {
    let horizon =
        horizon_from_exact_local_event(SimInstant { ticks: 64 }, ExactLocalEvent::NoArmedTimer);

    assert_eq!(
        horizon,
        SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { ticks: 64 },
                ceiling: NodeCounter { ticks: 64 },
            },
            source: SchedulerHorizonSource::NetworkLookahead,
        }
    );
}

#[test]
fn later_exact_deadline_does_not_extend_network_horizon() {
    let horizon = horizon_from_exact_local_event(
        SimInstant { ticks: 50 },
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks: 90 },
        },
    );

    assert_eq!(
        horizon,
        SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { ticks: 50 },
                ceiling: NodeCounter { ticks: 50 },
            },
            source: SchedulerHorizonSource::NetworkLookahead,
        }
    );
}

#[test]
fn finite_lookahead_is_added_to_current_virtual_time() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { ticks: 20 },
        NetworkLookahead::Finite(SimDuration { ticks: 7 }),
        ExactLocalEvent::NoArmedTimer,
    );

    assert_eq!(
        horizon,
        SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { ticks: 27 },
                ceiling: NodeCounter { ticks: 27 },
            },
            source: SchedulerHorizonSource::NetworkLookahead,
        }
    );
}

#[test]
fn infinite_network_lookahead_without_local_event_is_unbounded() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { ticks: 20 },
        NetworkLookahead::Infinite,
        ExactLocalEvent::NoArmedTimer,
    );

    assert_eq!(horizon, SchedulerHorizon::infinite_network());
}

#[test]
fn exact_local_event_bounds_infinite_network_lookahead() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { ticks: 20 },
        NetworkLookahead::Infinite,
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks: 23 },
        },
    );

    assert_eq!(
        horizon,
        SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { ticks: 23 },
                ceiling: NodeCounter { ticks: 23 },
            },
            source: SchedulerHorizonSource::ExactLocalTimer,
        }
    );
}

#[test]
fn exact_deadline_report_maps_to_scheduler_local_event() {
    assert_eq!(
        exact_local_event_from_timer_deadline_ns(Some(124_456)),
        Ok(ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks: 124_456_000 },
        })
    );
    assert_eq!(
        exact_local_event_from_timer_deadline_ns(None),
        Ok(ExactLocalEvent::NoArmedTimer)
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
                virtual_time: SimInstant { ticks: 23 },
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
                virtual_time: SimInstant { ticks: 23 },
            },
        }]
    );
}

#[test]
fn scheduler_quiescence_fast_forwards_idle_exact_wakeup_without_deadlock() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "idle-exact-wakeup",
        8,
        SimInstant { ticks: 64 },
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { ticks: 23 },
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
        8,
        SimInstant { ticks: 64 },
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { ticks: 100 },
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
        8,
        SimInstant { ticks: 64 },
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
fn scheduler_quiescence_blocks_future_io_events() {
    let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let disk = scheduler_node("node-a", SchedulingNodeKind::Disk);
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
            io_completion_event(9, &consumer, &disk, 2, b"later-io"),
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
                key: event_key(9, &consumer, &disk, 2),
            })
    );
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingExactLocalEvent {
                node: consumer,
                event: ExactLocalEvent::IoCompletion {
                    virtual_time: SimInstant { ticks: 5 },
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
                NetworkLookahead::Finite(SimDuration { ticks: 1 }),
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { ticks: 100 },
                },
            ),
            test_scenario_node(
                "runner",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Finite(SimDuration { ticks: 4 }),
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
                    virtual_time: SimInstant { ticks: 100 },
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
fn scheduler_errors_render_all_variants_deterministically() {
    let backend = SchedulerError::from(BackendError::Rejected {
        message: String::from("backend refused"),
    });
    let boundary = SchedulerError::BoundaryViolation {
        message: String::from("bypassed scheduler boundary"),
    };
    let conversion =
        SchedulerError::from(TimeConversionError::NanosecondOverflow { nanos: u64::MAX });

    assert_eq!(
        backend.to_string(),
        "backend failed under scheduler control: backend refused"
    );
    assert_eq!(boundary.to_string(), "bypassed scheduler boundary");
    assert_eq!(
        conversion.to_string(),
        "scheduler virtual-time conversion failed: 18446744073709551615 nanoseconds exceeds the simulation tick range"
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
    ScheduledEventKey::new(
        SharedTimelineKey {
            virtual_time: SimInstant {
                ticks: virtual_time,
            },
            node: consumer.clone(),
            sequence,
        },
        producer.clone(),
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
        16,
        SimInstant { ticks: 64 },
        nodes,
        pending_events,
    ))
    .unwrap_or_else(|error| panic!("test scheduler should build: {error}"))
}

#[test]
fn attempt_stop_frontier_precedes_branch_and_trigger_horizons() {
    let mut scheduler = test_scheduler(
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    scheduler
        .set_trigger_wakeup(Some(VirtualTime { ticks: 30 }), None)
        .unwrap_or_else(|error| panic!("trigger wakeup should install: {error}"));
    scheduler
        .set_branch_frontier_cap(VirtualTime { ticks: 25 })
        .unwrap_or_else(|error| panic!("branch frontier should install: {error}"));
    scheduler
        .set_attempt_stop_frontier(Some(VirtualTime { ticks: 20 }))
        .unwrap_or_else(|error| panic!("attempt stop should install: {error}"));

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("attempt-capped quantum should run: {error}"));

    assert_eq!(outcome.frontier, VirtualTime { ticks: 20 });
    assert!(!scheduler.reached_time_limit().unwrap_or_else(|error| {
        panic!("scenario terminal state should remain inspectable: {error}")
    }));

    scheduler
        .set_attempt_stop_frontier(None)
        .unwrap_or_else(|error| panic!("attempt stop should clear: {error}"));
    let continued = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("cleared attempt cap should continue: {error}"));
    assert_eq!(continued.frontier, VirtualTime { ticks: 25 });
}

#[test]
fn signal_fault_frontier_preserves_parent_time_and_typed_candidates() {
    let mut scheduler = test_scheduler(Vec::new(), Vec::new());
    let parent = scheduler.configuration().clone();
    let choice = BindingSearchChoice {
        id: SearchChoiceId::from_content_hash(ContentHash::from_bytes(b"binding-choice")),
        candidates_digest: ContentHash::from_bytes(b"binding-candidates"),
        candidate_count: 2,
        candidate_semantics: BindingSearchCandidateSemantics::Outcome,
        selected_index: None,
        overridden: false,
    };

    scheduler
        .record_signal_fault_search_frontiers(
            &parent,
            VirtualTime { ticks: 37 },
            std::slice::from_ref(&choice),
        )
        .unwrap_or_else(|error| panic!("typed fault frontier should record: {error}"));
    let frontier = scheduler
        .search_frontiers()
        .last()
        .unwrap_or_else(|| panic!("typed fault frontier should exist"));
    assert_eq!(frontier.configuration, parent);
    assert_eq!(frontier.at, VirtualTime { ticks: 37 });
    assert_eq!(frontier.choices.choices().len(), 2);
    for (index, branch) in frontier.choices.choices().iter().enumerate() {
        let [Decision::Selection(selection), Decision::Override(decision)] = branch.decisions()
        else {
            panic!("fault search candidate must retain its typed selection and causal override");
        };
        assert!(selection.is_campaign_branch());
        let selection = selection
            .selection()
            .unwrap_or_else(|error| panic!("fault search selection should decode: {error}"));
        assert_eq!(
            selection.value(),
            &crucible_campaign::ChoiceValue::Boolean(index == 1)
        );

        let (id, search_override) = SearchOverride::from_override_decision(decision)
            .unwrap_or_else(|| panic!("fault search candidate override should decode"));
        assert_eq!(id, choice.id);
        assert_eq!(search_override.candidate_index, index as u32);
        assert_eq!(search_override.parent_branch, Some(parent.id()));
    }

    let wrong_parent = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.signal-search-test.v1",
        "wrong-parent",
    ));
    assert!(
        scheduler
            .record_signal_fault_search_frontiers(
                &wrong_parent,
                VirtualTime { ticks: 37 },
                &[choice],
            )
            .is_err()
    );
}

#[test]
fn single_scheduler_checkpoint_round_trips_complete_device_and_event_state() {
    let node = test_scenario_node(
        "a",
        11,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Infinite,
        ExactLocalEvent::NoArmedTimer,
    );
    let consumer = node.id.clone();
    let producer = scheduler_node("peer", SchedulingNodeKind::Vm);
    let pending = event(17, &consumer, &producer, 0, b"pending-input");
    let mut scheduler = test_scheduler(vec![node.clone()], vec![pending.clone()]);
    scheduler = scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(11, 8)]));
    scheduler
        .set_attempt_stop_frontier(Some(VirtualTime { ticks: 23 }))
        .unwrap_or_else(|error| panic!("attempt stop should install: {error}"));
    let retained = ObservableEvent::console_output(
        VirtualTime { ticks: 11 },
        NodeId {
            name: String::from("a"),
        },
        b"checkpoint-prefix".to_vec(),
    );
    let appended = QuantumLoop::append_backend_observable_events(&mut scheduler, vec![retained])
        .unwrap_or_else(|error| panic!("scheduler event should append: {error}"));
    let checkpoint = scheduler
        .checkpoint()
        .unwrap_or_else(|error| panic!("scheduler checkpoint should capture: {error}"));
    assert_eq!(checkpoint.retained_event_log_base_events(), 0);
    assert_eq!(checkpoint.retained_event_log_entries(), appended.entries);
    let bytes = checkpoint
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("scheduler checkpoint should encode: {error}"));
    let decoded = SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)
        .unwrap_or_else(|error| panic!("scheduler checkpoint should decode: {error}"));
    assert_eq!(decoded.retained_event_log_base_events(), 0);
    assert_eq!(decoded.retained_event_log_entries(), appended.entries);

    let mut restored = test_scheduler(vec![node], vec![pending]);
    restored = restored.with_device_sub_node(disk_with_reads("a", "disk-a", &[]));
    decoded
        .restore_into(&mut restored)
        .unwrap_or_else(|error| panic!("scheduler checkpoint should restore: {error}"));

    assert_eq!(restored.attempt_stop_frontier_cap, None);
    assert_eq!(
        restored
            .checkpoint()
            .and_then(|checkpoint| checkpoint.canonical_bytes())
            .unwrap_or_else(|error| panic!("restored scheduler should encode: {error}")),
        bytes
    );
}

#[test]
fn scheduler_checkpoint_restores_absolute_quantum_coordinate() {
    const CHECKPOINT_QUANTA: u64 = 2;
    const STOP_QUANTA: u64 = 4;

    let nodes = ["a", "b", "c", "d"]
        .into_iter()
        .map(|name| {
            test_scenario_node(
                name,
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )
        })
        .collect::<Vec<_>>();
    let mut uninterrupted = test_scheduler(nodes.clone(), Vec::new());
    let mut checkpointed = test_scheduler(nodes.clone(), Vec::new());

    for _ in 0..CHECKPOINT_QUANTA {
        let request = QuantumRequest {
            configuration: checkpointed.configuration().clone(),
            control: Vec::new(),
        };
        checkpointed
            .drive_quantum(request)
            .unwrap_or_else(|error| panic!("checkpoint prefix quantum should drive: {error}"));
    }
    let encoded = checkpointed
        .checkpoint()
        .and_then(|checkpoint| checkpoint.canonical_bytes())
        .unwrap_or_else(|error| panic!("scheduler checkpoint should encode: {error}"));
    let decoded = SingleSchedulerCheckpoint::from_canonical_bytes(&encoded)
        .unwrap_or_else(|error| panic!("scheduler checkpoint should decode: {error}"));
    assert_eq!(decoded.quanta(), CHECKPOINT_QUANTA);

    let mut restored = test_scheduler(nodes, Vec::new());
    decoded
        .restore_into(&mut restored)
        .unwrap_or_else(|error| panic!("scheduler checkpoint should restore: {error}"));
    assert_eq!(restored.quanta(), CHECKPOINT_QUANTA);

    let mut suffix_calls = 0;
    while restored.quanta() < STOP_QUANTA {
        let request = QuantumRequest {
            configuration: restored.configuration().clone(),
            control: Vec::new(),
        };
        restored
            .drive_quantum(request)
            .unwrap_or_else(|error| panic!("restored suffix quantum should drive: {error}"));
        suffix_calls += 1;
    }
    assert_eq!(suffix_calls, STOP_QUANTA - CHECKPOINT_QUANTA);
    assert_eq!(restored.quanta(), STOP_QUANTA);

    for _ in 0..STOP_QUANTA {
        let request = QuantumRequest {
            configuration: uninterrupted.configuration().clone(),
            control: Vec::new(),
        };
        uninterrupted
            .drive_quantum(request)
            .unwrap_or_else(|error| panic!("uninterrupted quantum should drive: {error}"));
    }
    assert_eq!(
        restored
            .checkpoint()
            .and_then(|checkpoint| checkpoint.canonical_bytes())
            .unwrap_or_else(|error| panic!("restored result should encode: {error}")),
        uninterrupted
            .checkpoint()
            .and_then(|checkpoint| checkpoint.canonical_bytes())
            .unwrap_or_else(|error| panic!("uninterrupted result should encode: {error}"))
    );
}

#[test]
fn live_backend_event_log_suffix_is_adopted_atomically() {
    let mut scheduler = test_scheduler(Vec::new(), Vec::new());
    let before = scheduler.event_log().offset();
    let mut backend_log = scheduler.event_log().clone();
    let entry = scheduler_event_log_entry(
        before.events,
        VirtualTime { ticks: 13 },
        SchedulerEventLogPayload::Observable(ObservableEventPayload::ConsoleOutput {
            node: NodeId {
                name: String::from("a"),
            },
            bytes: b"paused-drain".to_vec(),
        }),
    );
    let expected = backend_log
        .append_entries(vec![entry.clone()])
        .unwrap_or_else(|error| panic!("backend suffix should append: {error}"));

    let adopted = scheduler
        .adopt_live_backend_event_log_suffix(&backend_log)
        .unwrap_or_else(|error| panic!("exact backend suffix should be adopted: {error}"));

    assert_eq!(adopted.entries, vec![entry]);
    assert_eq!(adopted.offset, expected.offset);
    assert_eq!(scheduler.event_log().offset(), backend_log.offset());

    let accepted = scheduler.event_log().offset();
    let mut foreign = scheduler.event_log().clone();
    let foreign_entry = scheduler_event_log_entry(
        accepted.events,
        VirtualTime { ticks: 17 },
        SchedulerEventLogPayload::Observable(ObservableEventPayload::ConsoleOutput {
            node: NodeId {
                name: String::from("a"),
            },
            bytes: b"foreign-drain".to_vec(),
        }),
    );
    foreign
        .append_entries(vec![foreign_entry])
        .unwrap_or_else(|error| panic!("foreign suffix should be structurally valid: {error}"));
    foreign.offset.prefix = ContentHash::from_bytes(b"foreign-prefix");

    scheduler
        .adopt_live_backend_event_log_suffix(&foreign)
        .expect_err("foreign final offset must fail closed");
    assert_eq!(scheduler.event_log().offset(), accepted);
}

#[test]
fn network_transition_drop_clears_inflight_and_authenticates_frames() {
    let source = NodeId {
        name: String::from("a"),
    };
    let destination = NodeId {
        name: String::from("b"),
    };
    let mut scheduler = test_scheduler(
        vec![
            test_scenario_node(
                "a",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            ),
            test_scenario_node(
                "b",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    );
    let link_id = scheduler_link_id_for_nodes(&source, &destination);
    let direction = NetworkLinkDirection::EndpointAToEndpointB;
    let mut link = crucible_device::NetLink::new(0, 10, 1, crucible_device::LinkFaults::none())
        .unwrap_or_else(|error| panic!("test link should build: {error}"));
    link.emit(
        &crucible_device::Frame::new(0, 7, vec![1, 2, 3]),
        &crucible_device::FrameDraws::default(),
        crucible_device::PastDeliveryPolicy::FailLoud,
    )
    .unwrap_or_else(|error| panic!("test frame should enter flight: {error}"));
    scheduler.world_network_links.insert(
        (link_id.clone(), direction),
        WorldNetworkLinkRuntime {
            canonical_id: link_id.clone(),
            endpoint_a: source.clone(),
            endpoint_b: destination.clone(),
            direction,
            scheduler_node: scheduler_node("link-a-b", SchedulingNodeKind::Network),
            rng_stream: RngStreamId::for_link(link_id.name.clone()),
            fault_id: crate::DeviceId::from_name("link-a-b"),
            link,
        },
    );
    scheduler
        .world_network_rng_positions
        .insert(link_id.clone(), 19);
    scheduler
        .refresh_device_horizons()
        .unwrap_or_else(|error| panic!("network horizon should refresh: {error}"));
    assert_eq!(
        scheduler.world_network_links[&(link_id.clone(), direction)]
            .link
            .inflight_len(),
        1
    );
    let before_digest = scheduler
        .network_continuation_digest()
        .unwrap_or_else(|error| panic!("network state should encode: {error}"));
    let checkpoint = scheduler.network_checkpoint();
    let checkpoint_bytes = checkpoint
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("network checkpoint should encode: {error}"));
    let checkpoint = SchedulerNetworkCheckpoint::from_canonical_bytes(&checkpoint_bytes)
        .unwrap_or_else(|error| panic!("network checkpoint should decode: {error}"));
    assert_eq!(
        checkpoint
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("decoded checkpoint should encode: {error}")),
        checkpoint_bytes
    );
    let mut trailing = checkpoint_bytes;
    trailing.push(0);
    assert_eq!(
        SchedulerNetworkCheckpoint::from_canonical_bytes(&trailing),
        Err(SchedulerNetworkCheckpointCodecError::Noncanonical)
    );

    let first = scheduler
        .drop_network_inflight_for_route(&source, &destination)
        .unwrap_or_else(|error| panic!("network transition should drop the frame: {error}"));
    let second = scheduler
        .drop_network_inflight_for_route(&source, &destination)
        .unwrap_or_else(|error| panic!("repeated transition should be idempotent: {error}"));

    assert_eq!(first.link, link_id);
    assert_eq!(first.direction, direction);
    assert_eq!(first.frame_count, 1);
    assert_eq!(first.frames.len(), 1);
    assert_eq!(first.frames[0].frame_id, 7);
    assert_eq!(first.frames[0].payload, vec![1, 2, 3]);
    assert_ne!(first.evidence, second.evidence);
    assert_eq!(second.frame_count, 0);
    assert_eq!(
        scheduler.world_network_links[&(first.link, direction)]
            .link
            .inflight_len(),
        0
    );
    assert!(!scheduler.device_horizons.contains_key(&destination));
    assert_ne!(
        before_digest,
        scheduler
            .network_continuation_digest()
            .unwrap_or_else(|error| panic!("dropped network state should encode: {error}"))
    );
    scheduler
        .restore_network_checkpoint(&checkpoint)
        .unwrap_or_else(|error| panic!("network checkpoint should restore: {error}"));
    assert_eq!(
        scheduler
            .network_continuation_digest()
            .unwrap_or_else(|error| panic!("restored network state should encode: {error}")),
        before_digest
    );
    assert_eq!(
        scheduler.world_network_links[&(link_id, direction)]
            .link
            .inflight_len(),
        1
    );
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
            delivery_tick: SimInstant {
                ticks: virtual_time,
            },
            payload: payload.to_vec(),
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

    let core = match IoCore::new(1, 16, 16) {
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
fn resolve_device_completions_keep_non_instruction_aligned_exact_ticks() {
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
        scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(1, 8), (250_001, 8)]));

    assert!(
        scheduler.has_undelivered_device_completion(),
        "submitted reads must leave completions in flight"
    );

    let node = scheduler_node("a", SchedulingNodeKind::Vm);
    let (events, _decisions) = match scheduler.resolve_device_completions(&node, 1_258_001) {
        Ok(resolved) => resolved,
        Err(error) => panic!("resolve should succeed: {error}"),
    };
    let stamped: Vec<u64> = events
        .iter()
        .map(|event| event.key.virtual_time().ticks)
        .collect();

    assert_eq!(
        stamped,
        vec![1_008_001, 1_258_001],
        "each completion is stamped at its own exact delivery tick"
    );
    assert_ne!(stamped[0] % crate::SIM_TICKS_PER_INSTRUCTION, 0);
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
    scheduler = scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(1, 8)]));

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
            ExactLocalEvent::IoCompletion { virtual_time, .. } if virtual_time.ticks == 1_008_001
        ),
        "the in-flight head (icount 1_008_001) must bound the node horizon, got {exact:?}"
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
    // A time limit comfortably past the completion icount (1_008_001) so the
    // requester can advance to it; budget large enough to reach it.
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "test-device-live-drive",
        1_536_000,
        SimInstant { ticks: 1_536_000 },
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
    scheduler = scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(1, 8)]));

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
        Some(1_008_001),
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
fn backend_loop_publishes_resolved_device_completion_as_observation() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "test-device-observation",
        1_536_000,
        SimInstant { ticks: 1_536_000 },
        vec![test_scenario_node(
            "a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    let scheduler = SingleScheduler::new(scenario)
        .unwrap_or_else(|error| panic!("scheduler should build: {error}"))
        .with_device_sub_node(disk_with_reads("a", "disk-a", &[(1, 8)]));
    let mut configuration = scheduler.configuration().clone();
    let mut adapter = BackendQuantumLoop::new(scheduler, MockSimulationBackend::new());

    let mut observed = None;
    for _ in 0..16 {
        let outcome = adapter
            .drive_quantum(QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("backend quantum should succeed: {error}"));
        configuration = outcome.configuration.clone();
        let matching = outcome
            .event_log_entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::Observable(
                        ObservableEventPayload::IoCompletion {
                            node,
                            kind: IoEventKind::Any,
                            ..
                        }
                    ) if node.name == "a"
                )
            })
            .collect::<Vec<_>>();
        if let Some(entry) = matching.first() {
            assert_eq!(
                matching.len(),
                1,
                "one resolved completion must produce exactly one observation"
            );
            observed = Some(entry.at());
            break;
        }
    }

    assert_eq!(
        observed,
        Some(VirtualTime { ticks: 1_008_001 }),
        "the resolved World I/O event must enter the trigger observation stream at its exact time"
    );

    let next = adapter
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("the next backend quantum should succeed: {error}"));
    assert!(
        next.event_log_entries.iter().all(|entry| !matches!(
            entry.payload(),
            SchedulerEventLogPayload::Observable(ObservableEventPayload::IoCompletion {
                node,
                kind: IoEventKind::Any,
                ..
            }) if node.name == "a"
        )),
        "a delivered World I/O completion must not be observed twice"
    );
}

#[test]
fn resolved_device_observation_rejects_a_mismatched_owner() {
    let scheduler = test_scheduler(
        vec![
            test_scenario_node(
                "a",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            ),
            test_scenario_node(
                "b",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    )
    .with_device_sub_node(disk_with_reads("a", "disk-a", &[]));
    let event = io_completion_event(
        8_064,
        &scheduler_node("b", SchedulingNodeKind::Vm),
        &scheduler_node("disk-a", SchedulingNodeKind::Disk),
        0,
        b"completion",
    );

    let error = scheduler
        .resolved_event_observation(&event)
        .expect_err("a completion may only target its sub-node's owning VM");

    assert!(error.to_string().contains("instead of owner `a`"));
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
            scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(1, 8), (250_001, 8)]));
        if broken {
            scheduler = scheduler.with_broken_device_delivery_stamp();
        }
        let node = scheduler_node("a", SchedulingNodeKind::Vm);
        let (events, _decisions) = scheduler
            .resolve_device_completions(&node, 1_258_001)
            .unwrap_or_else(|error| panic!("resolve should succeed: {error}"));
        events
            .iter()
            .map(|event| event.key.virtual_time().ticks)
            .collect()
    };

    assert_eq!(
        resolve_at_frontier(false),
        vec![1_008_001, 1_258_001],
        "exact stamps are each completion's own delivery icount"
    );
    assert_eq!(
        resolve_at_frontier(true),
        vec![1_258_001, 1_258_001],
        "the freeze-time bug collapses both onto the consumer frontier"
    );
    assert_ne!(
        resolve_at_frontier(false),
        resolve_at_frontier(true),
        "exact delivery must be distinguishable from frontier delivery"
    );
}
