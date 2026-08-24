//! Production-backend scheduler binding, observation, and branch-frontier tests.

use super::*;
use crate::{
    AppRandomDecision, AppRandomSelectable, BackendEffect, BackendSnapshot, MockSimulationBackend,
    SelectionDecision, StepObservation,
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
fn live_app_random_consumes_an_exact_parent_campaign_selection() {
    let mut scheduler = test_scheduler(Vec::new(), Vec::new());
    let configuration = scheduler.configuration().clone();
    let node = NodeId {
        name: String::from("node-a"),
    };
    let stream = RngStreamId::from_name("app-random/node:6:node-a/stream:6:branch");
    let mut seeded = configuration
        .def
        .seed()
        .decision_rng()
        .fork_in_domain(&stream.domain, &stream.name);
    let raw = seeded.next_u64();
    let selected = raw ^ 1;
    let live = AppRandomDecision {
        node,
        stream: stream.clone(),
        request_id: 9,
        width: 64,
        value: selected,
    };
    let parent = step(
        &configuration,
        Decision::RngDraw(RngDecision { stream, value: raw }),
    );
    let selectable = AppRandomSelectable::from_decision(&configuration.def, &live)
        .expect("live app-random request should reconstruct");
    let selection = selectable
        .branch_selection(&parent, selected)
        .expect("exact parent should admit campaign selection");
    scheduler
        .install_app_random_branch_selections([(parent.id(), SelectionDecision::new(&selection))])
        .expect("campaign selection should install");
    assert!(matches!(
        scheduler.checkpoint(),
        Err(SingleSchedulerCheckpointError::Transient)
    ));

    let (recorded, discoveries, advanced, _append) = QuantumLoop::append_backend_causal_decisions(
        &mut scheduler,
        vec![Decision::AppRandom(live)],
    )
    .expect("live selected value should authenticate");

    assert_eq!(scheduler.pending_branch_effect_choice_count(), 0);
    assert_eq!(advanced.id(), step(&parent, recorded[1].clone()).id());
    assert_eq!(discoveries.len(), 1);
    assert!(matches!(
        recorded.as_slice(),
        [Decision::RngDraw(draw), Decision::Selection(selection)]
            if draw.value == raw && selection.is_campaign_branch()
    ));
}

#[test]
fn lifecycle_activity_requirement_rejects_release_before_scheduler_publication() {
    let node = NodeId {
        name: String::from("node-a"),
    };
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

    assert!(
        scheduler
            .require_vm_node_activity(&node, SchedulerNodeActivity::Runnable)
            .is_err()
    );
    scheduler
        .set_vm_node_activity(&node, SchedulerNodeActivity::Runnable)
        .unwrap_or_else(|error| panic!("scheduler publication should succeed: {error}"));
    scheduler
        .require_vm_node_activity(&node, SchedulerNodeActivity::Runnable)
        .unwrap_or_else(|error| panic!("published scheduler ownership should validate: {error}"));
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
            .backend_observation_time(
                &NodeId {
                    name: String::from("node-a"),
                },
                VirtualTime { ticks: 4_103 },
            )
            .unwrap_or_else(|error| panic!("backend observation should project: {error}")),
        VirtualTime { ticks: 7 }
    );
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
                discovered_choices: Vec::new(),
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
fn shutdown_rejects_causal_decisions_without_a_discovery_handoff() {
    struct ShutdownDecisionBackend {
        inner: MockSimulationBackend,
        decisions: Vec<Decision>,
    }

    impl SimulationBackend for ShutdownDecisionBackend {
        fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
            self.inner.step_to(ceiling)
        }

        fn drain_causal_decisions(&mut self) -> Result<Vec<Decision>, BackendError> {
            Ok(std::mem::take(&mut self.decisions))
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

    let scheduler = test_scheduler(Vec::new(), Vec::new());
    let mut adapter = BackendQuantumLoop::new(
        scheduler,
        ShutdownDecisionBackend {
            inner: MockSimulationBackend::new(),
            decisions: vec![Decision::AppRandom(AppRandomDecision {
                node: NodeId {
                    name: String::from("node-a"),
                },
                stream: RngStreamId::from_name("app-random/node:6:node-a/stream:4:test"),
                request_id: 1,
                width: 8,
                value: 7,
            })],
        },
    );

    let error = adapter
        .shutdown()
        .expect_err("shutdown must not lose typed choice discoveries");
    assert!(
        error
            .to_string()
            .contains("without a quantum discovery handoff")
    );
    assert!(adapter.loop_impl().configuration().schedule.is_empty());
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
fn branch_reseed_drives_live_app_random_and_resets_world_network_cursors() {
    fn app_random_decisions(
        seed: Seed,
    ) -> (Vec<Decision>, Vec<crucible_campaign::ChoiceDiscovery>) {
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
        let (decisions, discovered, _configuration, _append) =
            QuantumLoop::append_backend_causal_decisions(
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
        assert!(matches!(
            decisions.as_slice(),
            [Decision::RngDraw(_), Decision::Selection(_)]
        ));
        assert_eq!(discovered.len(), 1);
        let Decision::Selection(selection) = &decisions[1] else {
            panic!("typed app-random decision should be a selection")
        };
        assert_eq!(
            selection
                .selection()
                .expect("canonical selection")
                .opportunity(),
            discovered[0]
                .opportunity()
                .id()
                .expect("discovered opportunity id")
        );
        (decisions, discovered)
    }

    let first_seed = Seed::from_u64(0xa990_0001);
    let second_seed = Seed::from_u64(0xa990_0002);
    let (first, first_discovered) = app_random_decisions(first_seed);
    let (replayed, replayed_discovered) = app_random_decisions(first_seed);
    let (second, second_discovered) = app_random_decisions(second_seed);
    assert_eq!(first, replayed);
    assert_eq!(first_discovered, replayed_discovered);
    assert_ne!(first, second);
    assert_eq!(first_discovered, second_discovered);

    let mut scheduler = test_scheduler(Vec::new(), Vec::new());
    let link = LinkId::for_endpoints(
        &NodeId {
            name: String::from("node-a"),
        },
        &NodeId {
            name: String::from("node-b"),
        },
    );
    scheduler
        .world_network_rng_positions
        .insert(link.clone(), 19);
    scheduler
        .reseed_future_decisions(second_seed)
        .expect("an idle scheduler should reset World-network cursors");
    assert_eq!(scheduler.world_network_rng_positions.get(&link), Some(&0));
}
