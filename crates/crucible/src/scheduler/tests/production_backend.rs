//! Production-backend scheduler binding, observation, and branch-frontier tests.

use super::*;
use crate::{
    AppRandomDecision, BackendEffect, BackendSnapshot, MockSimulationBackend, StepObservation, step,
};

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
fn production_scenario_binding_preserves_the_submitted_configuration_identity() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.scheduler.production-binding",
        "scenario=production-binding",
        Seed::from_u64(42),
    );
    let runtime = SchedulerLivenessScenario::from_canonical_material(
        "runtime scheduler parameters",
        Shift::new(0).unwrap_or_else(|error| panic!("zero shift should be valid: {error}")),
        1,
        SimInstant { nanos: 1 },
        Vec::new(),
        Vec::new(),
    )
    .with_scenario_def(scenario.clone());

    assert_eq!(
        runtime.canonical_configuration(),
        Configuration::genesis(scenario)
    );
}

#[test]
fn admitted_ready_counter_is_the_scheduler_epoch() {
    let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let ready = NodeCounter { ticks: 4_096 };
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "production-ready-counter-origin",
        Shift::new(0).unwrap_or_else(|error| panic!("zero shift should be valid: {error}")),
        4,
        SimInstant { nanos: 64 },
        vec![SchedulerScenarioNode {
            id: node.clone(),
            counter: ready,
            activity: SchedulerNodeActivity::Runnable,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    )
    .with_ready_point_counter(node, ready);
    let scheduler = SingleScheduler::new(scenario)
        .unwrap_or_else(|error| panic!("ready-point scheduler should build: {error}"));

    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 0 });
    assert_eq!(
        scheduler
            .node_time_for_counter(&scheduler.nodes[0], NodeCounter { ticks: 4_103 })
            .unwrap_or_else(|error| panic!("relative node time should project: {error}")),
        SimInstant { nanos: 7 }
    );
}

#[test]
fn backend_quantum_loop_buffers_observations_ahead_of_the_shared_frontier() {
    struct BoundaryLoop {
        event_log: EventLog,
        frontiers: std::vec::IntoIter<VirtualTime>,
    }

    impl QuantumLoop for BoundaryLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            let frontier =
                self.frontiers
                    .next()
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("test boundary loop exhausted"),
                    })?;
            let append = self
                .event_log
                .append_evaluation_boundary(frontier, SchedulerEvaluationBoundaryKind::Quantum)?;
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier,
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
                event_log_entries: append.entries,
                event_log_segment_bytes: append.segment_bytes,
                event_log_segment_text: append.segment_text,
                event_log_segment_hash: append.segment_hash,
                event_log_offset: append.offset,
                scheduler_quiescence: None,
            })
        }

        fn append_backend_observations_at_boundary(
            &mut self,
            events: Vec<ObservableEvent>,
            at: VirtualTime,
        ) -> Result<SchedulerEventLogAppend, SchedulerError> {
            self.event_log.append_observations_at_boundary(
                events,
                at,
                SchedulerEvaluationBoundaryKind::Quantum,
            )
        }
    }

    struct ObservingBackend {
        inner: MockSimulationBackend,
        observations: Vec<ObservableEvent>,
    }

    impl SimulationBackend for ObservingBackend {
        fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
            self.inner.step_to(ceiling)
        }

        fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, BackendError> {
            Ok(std::mem::take(&mut self.observations))
        }

        fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
            self.inner.apply(effect, at)
        }

        fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
            self.inner.snapshot()
        }

        fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
            self.inner.restore(snapshot)
        }

        fn now(&self) -> VirtualTime {
            self.inner.now()
        }

        fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
            self.inner.fingerprint(node)
        }

        fn shutdown(&mut self) -> Result<(), BackendError> {
            self.inner.shutdown()
        }
    }

    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.scheduler.buffered-observation",
        "scenario=buffered-observation",
    );
    let configuration = Configuration::genesis(scenario);
    let observation = ObservableEvent::console_output(
        VirtualTime { ticks: 10 },
        NodeId {
            name: String::from("vm-a"),
        },
        b"committed".to_vec(),
    );
    let mut adapter = BackendQuantumLoop::new(
        BoundaryLoop {
            event_log: EventLog::new(),
            frontiers: vec![VirtualTime { ticks: 5 }, VirtualTime { ticks: 10 }].into_iter(),
        },
        ObservingBackend {
            inner: MockSimulationBackend::new(),
            observations: vec![observation.clone()],
        },
    );

    let first = adapter
        .drive_quantum(QuantumRequest {
            configuration: configuration.clone(),
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("first boundary should buffer the observation: {error}"));
    assert!(
        first
            .event_log_entries
            .iter()
            .all(|entry| entry.at() != observation.at())
    );

    let second = adapter
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("second boundary should commit the observation: {error}"));
    let appended = &second.event_log_entries[1..];
    assert_eq!(appended.len(), 2);
    assert!(matches!(
        appended[0].payload(),
        SchedulerEventLogPayload::Observable(_)
    ));
    assert!(matches!(
        appended[1].payload(),
        SchedulerEventLogPayload::EvaluationBoundary(SchedulerEvaluationBoundaryKind::Quantum)
    ));
    assert_eq!(appended[0].at(), VirtualTime { ticks: 10 });
    assert_eq!(appended[1].at(), VirtualTime { ticks: 10 });
}

#[test]
fn branch_prefix_admission_records_only_explorer_overrides() {
    let mut scheduler = test_scheduler(
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Halted,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    let decision = Decision::Override(crate::OverrideDecision {
        point: crate::SchedulingPoint {
            key: String::from("fuzz/sample"),
        },
        choice: crate::ChoiceTag {
            name: String::from("candidate-7"),
        },
    });

    let (configuration, append) = scheduler
        .append_branch_prefix_overrides(vec![decision.clone()])
        .expect("an explorer override must be admitted");

    assert_eq!(
        configuration.schedule.decisions(),
        std::slice::from_ref(&decision)
    );
    assert_eq!(scheduler.configuration(), &configuration);
    assert!(
        append.entries.iter().any(|entry| {
            entry.payload() == &SchedulerEventLogPayload::Decision(decision.clone())
        })
    );

    let error = scheduler
        .append_branch_prefix_overrides(vec![Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("not-an-override"),
            value: 1,
        })])
        .expect_err("raw RNG choices must use their owning resolution path");
    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
}

#[test]
fn branch_reseed_restarts_the_authoritative_rng_stream() {
    let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("scheduler", SchedulingNodeKind::ControlPlane);
    let event = probabilistic_effect_event(
        11,
        &consumer,
        &producer,
        0,
        FaultId {
            name: String::from("reseeded-loss"),
        },
    );
    let stream = RngStreamId::from_name("test-probabilistic-fault");
    let seed = Seed::from_u64(0x0010_c111);
    let mut expected_stream = seed
        .decision_rng()
        .fork_in_domain(&stream.domain, &stream.name);
    let expected = expected_stream.next_u64();
    let mut scheduler = test_scheduler(Vec::new(), Vec::new());

    scheduler
        .reseed_future_decisions(seed)
        .expect("an idle scheduler should admit a branch re-seed");
    let decisions = scheduler
        .emit_quantum_decisions(
            std::slice::from_ref(&event),
            &[],
            &[],
            SimInstant { nanos: 11 },
        )
        .expect("the re-seeded fault boundary should resolve");
    let actual = decisions.iter().find_map(|decision| match decision {
        Decision::RngDraw(draw) if draw.stream == stream => Some(draw.value),
        _ => None,
    });

    assert_eq!(actual, Some(expected));
    assert_eq!(
        scheduler
            .decision_rng_cursor
            .positions
            .get(&stream)
            .map(|position| position.draws),
        Some(1)
    );
}

#[test]
fn branch_reseed_drives_live_app_random_and_resets_world_network_cursors() {
    fn app_random_decisions(seed: Seed) -> Vec<Decision> {
        let node = NodeId {
            name: String::from("node-a"),
        };
        let stream = RngStreamId::from_name("app-random/node:6:node-a/stream:4:test");
        let mut expected = seed
            .decision_rng()
            .fork_in_domain(&stream.domain, &stream.name);
        let expected_value = expected.next_u64();
        let mut scheduler = test_scheduler(Vec::new(), Vec::new());
        scheduler
            .reseed_future_decisions(seed)
            .expect("an idle scheduler should admit a branch re-seed");
        let (decisions, _configuration, _append) = QuantumLoop::append_backend_causal_decisions(
            &mut scheduler,
            vec![Decision::AppRandom(AppRandomDecision {
                node,
                stream,
                request_id: 0,
                width: 64,
                value: expected_value,
            })],
        )
        .expect("the live app-random value should match the branch seed");
        decisions
    }

    let first_seed = Seed::from_u64(0xa990_0001);
    let second_seed = Seed::from_u64(0xa990_0002);
    let first = app_random_decisions(first_seed);
    let replayed = app_random_decisions(first_seed);
    let second = app_random_decisions(second_seed);
    assert_eq!(first, replayed);
    assert_ne!(first, second);

    let mut scheduler = test_scheduler(Vec::new(), Vec::new());
    let link = LinkId::from_name("node-a--node-b");
    scheduler
        .world_network_rng_positions
        .insert(link.clone(), 19);
    scheduler
        .reseed_future_decisions(second_seed)
        .expect("an idle scheduler should reset World-network cursors");
    assert_eq!(scheduler.world_network_rng_positions.get(&link), Some(&0));
}

#[test]
fn branch_effect_choice_replaces_seeded_resolution_at_matching_point() {
    let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("scheduler", SchedulingNodeKind::ControlPlane);
    let fault = FaultId {
        name: String::from("branch-loss"),
    };
    let event = probabilistic_effect_event(11, &consumer, &producer, 0, fault.clone());
    let stream = RngStreamId::from_name("test-probabilistic-fault");
    let forced = vec![
        Decision::RngDraw(RngDecision {
            stream: stream.clone(),
            value: 0,
        }),
        Decision::EffectOutcome(EffectOutcomeDecision {
            at: VirtualTime { ticks: 11 },
            fault,
            fired: true,
        }),
    ];
    let mut scheduler = test_scheduler(Vec::new(), Vec::new());
    scheduler
        .install_branch_effect_choices(forced.clone())
        .expect("valid branch effect choice must install");
    let mut resolved = resolve_probabilistic_decisions(
        scheduler.configuration().clone(),
        std::slice::from_ref(&event),
    )
    .decisions;

    scheduler
        .apply_branch_effect_choices(&[event], &mut resolved)
        .expect("matching branch choice must replace the seeded resolution");

    assert_eq!(resolved, forced);
    assert_eq!(scheduler.pending_branch_effect_choice_count(), 0);
}

#[test]
fn quantum_captures_pre_choice_runtime_search_frontier() {
    let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("scheduler", SchedulingNodeKind::ControlPlane);
    let event = probabilistic_effect_event(
        1,
        &consumer,
        &producer,
        0,
        FaultId {
            name: String::from("runtime-search-loss"),
        },
    );
    let node = test_scenario_node(
        "node-a",
        0,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Infinite,
        ExactLocalEvent::NoArmedTimer,
    );
    let mut scheduler = test_scheduler(vec![node], vec![event]);
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };

    let outcome = scheduler
        .drive_quantum(request)
        .expect("probabilistic quantum must complete");
    let frontiers = scheduler.search_frontiers();

    assert_eq!(frontiers.len(), 1);
    let frontier = &frontiers[0];
    assert_eq!(frontier.at, VirtualTime { ticks: 1 });
    assert!(matches!(
        frontier.configuration.schedule.decisions(),
        [Decision::DeliveryOrder(_)]
    ));
    assert_eq!(frontier.choices.choices().len(), 2);
    let outcome_prefix = outcome
        .configuration
        .schedule
        .prefix(frontier.configuration.schedule.len())
        .expect("runtime outcome must retain the frontier prefix");
    assert_eq!(outcome_prefix, frontier.configuration.schedule);
    let branches = frontier
        .choices
        .choices()
        .iter()
        .map(|choice| {
            let mut branch = frontier.configuration.clone();
            for decision in choice.decisions() {
                branch = step(&branch, decision.clone());
            }
            branch.id()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(branches.len(), 2);
}
