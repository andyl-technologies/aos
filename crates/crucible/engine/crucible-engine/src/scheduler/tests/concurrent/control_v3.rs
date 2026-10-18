//! Explicit control-3 dispatch and strict unclassified Source regressions.

use super::*;

struct UnclassifiedBackend(TestConcurrentBackend);

impl SimulationBackend for UnclassifiedBackend {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        self.0.step_to(ceiling)
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        self.0.apply(effect, at)
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        self.0.snapshot()
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        self.0.restore(snapshot)
    }

    fn now(&self) -> VirtualTime {
        self.0.now()
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<crate::FingerprintSample, BackendError> {
        self.0.fingerprint(node)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.0.shutdown()
    }
}

impl ConcurrentSimulationBackend for UnclassifiedBackend {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        maximum_workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunResult>, BackendError> {
        self.0.execute_concurrent_runs(runs, maximum_workers)
    }
}

fn scheduler() -> SingleScheduler {
    let nodes = ["a", "b"]
        .into_iter()
        .map(|name| {
            test_scenario_node(
                name,
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { ticks: 10 },
                },
            )
        })
        .collect();
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "control-v3-deadline-order",
        64,
        SimInstant { ticks: 64 },
        nodes,
        Vec::new(),
    )
    .with_effective_topology_edges(vec![SchedulerLookaheadEdge::new(
        scheduler_node("b", SchedulingNodeKind::Vm),
        scheduler_node("a", SchedulingNodeKind::Vm),
        SimDuration { ticks: 6 },
    )]);
    SingleScheduler::new(scenario)
        .unwrap_or_else(|error| panic!("deadline/topology fixture: {error}"))
}

#[test]
fn unclassified_backend_refuses_missing_source_before_dispatch() {
    let scheduler = scheduler();
    let configuration = scheduler.configuration().clone();
    let backend = UnclassifiedBackend(TestConcurrentBackend::new(false));
    assert_eq!(
        backend.dispatch_contract(),
        crate::BackendDispatchContract::PhysicalSource
    );
    let mut actor = BackendQuantumLoop::new(scheduler, backend);

    let error = actor
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            },
            2,
        )
        .expect_err("unclassified Source must refuse before dispatch");

    assert!(matches!(
        error,
        SchedulerError::Backend(BackendError::Unsupported {
            capability: "observe_node_io_inventory"
        })
    ));
    assert!(actor.backend().0.run_history.is_empty());
    assert_eq!(actor.loop_impl().configuration(), &configuration);
}

#[test]
fn control_v3_preserves_bounded_deadlines_and_serial_parallel_canonical_order() {
    let scheduler = scheduler();
    let configuration = scheduler.configuration().clone();
    let mut serial = BackendQuantumLoop::new(scheduler.clone(), control_backend());
    let mut parallel = BackendQuantumLoop::new(scheduler, control_backend());
    serial.set_live_network_choice_pause(true);

    serial
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            },
            1,
        )
        .unwrap_or_else(|error| panic!("serial bounded dispatch: {error}"));
    parallel
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            2,
        )
        .unwrap_or_else(|error| panic!("parallel bounded dispatch: {error}"));

    let ceilings = parallel
        .backend()
        .run_history
        .iter()
        .map(|run| (run.node().name.as_str(), run.ceiling().ticks))
        .collect::<Vec<_>>();
    assert_eq!(ceilings, vec![("a", 5), ("b", 5)]);
    assert!(
        parallel.backend().run_history[0]
            .admission
            .semantic_horizon()
            .icount
            .retired
            > 5
    );
    assert_eq!(
        parallel.loop_impl().configuration(),
        serial.loop_impl().configuration()
    );
    assert_eq!(
        parallel.loop_impl().event_log().retained_entries(),
        serial.loop_impl().event_log().retained_entries()
    );
}

fn control_backend() -> TestConcurrentBackend {
    let mut backend = TestConcurrentBackend::new(false);
    backend.control_v3 = true;
    backend
}

#[test]
fn control_v3_refuses_horizon_results_outside_the_exact_published_ceiling() {
    for wrong_tick in [5, 7] {
        let scheduler = scheduler();
        let configuration = scheduler.configuration().clone();
        let mut prepared = scheduler
            .prepare_host_concurrent_quantum_limited(
                QuantumRequest {
                    configuration: configuration.clone(),
                    control: Vec::new(),
                },
                usize::MAX,
            )
            .unwrap_or_else(|error| panic!("bounded preparation: {error}"));
        for run in &mut prepared.runs {
            run.dispatch_contract = crate::BackendDispatchContract::ControlV3;
        }
        let completed = prepared
            .runs
            .iter()
            .map(|run| {
                let ceiling = VirtualTime {
                    ticks: run.plan.target_counter,
                };
                let mut step =
                    StepObservation::from_advance_outcome(ceiling, AdvanceOutcome::ReachedHorizon);
                if run.plan.node.node.name == "a" {
                    step.reached = VirtualTime { ticks: wrong_tick };
                    step.outcome = AdvanceOutcome::Paused {
                        at: Icount {
                            retired: wrong_tick,
                        },
                    };
                }
                ConcurrentBackendRunResult::Completed(ConcurrentBackendRunOutcome {
                    node: run.plan.node.node.clone(),
                    step,
                    rng_evidence: Vec::new(),
                    network_outputs: Vec::new(),
                    observations: Vec::new(),
                })
            })
            .collect();
        let mut actor = BackendQuantumLoop::new(scheduler, control_backend());

        assert!(
            actor
                .complete_prepared_host_run_set(prepared, completed)
                .is_err()
        );
        assert_eq!(actor.loop_impl().configuration(), &configuration);
        assert!(
            actor
                .loop_impl()
                .nodes
                .iter()
                .all(|node| node.counter.ticks == 0)
        );
    }
}

#[test]
fn control_v3_contract_drift_refuses_another_physical_execution() {
    let mut actor = BackendQuantumLoop::new(scheduler(), control_backend());
    let request = QuantumRequest {
        configuration: actor.loop_impl().configuration().clone(),
        control: Vec::new(),
    };
    actor
        .drive_concurrent_quantum(request, 2)
        .unwrap_or_else(|error| panic!("original bounded dispatch: {error}"));
    let run_count = actor.backend().run_history.len();
    let configuration = actor.loop_impl().configuration().clone();
    actor.backend_mut().control_v3 = false;

    let error = actor
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            },
            2,
        )
        .expect_err("changed contract must refuse another physical RUN");

    assert!(error.to_string().contains("dispatch contract changed"));
    assert_eq!(actor.backend().run_history.len(), run_count);
    assert_eq!(actor.loop_impl().configuration(), &configuration);
}

fn input_scheduler(at: u64) -> (SingleScheduler, ScheduledEvent) {
    let consumer = scheduler_node("a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("network", SchedulingNodeKind::Network);
    let input = event(at, &consumer, &producer, 7, b"original-delivery");
    let node = test_scenario_node(
        "a",
        0,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Infinite,
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks: 10 },
        },
    );
    (test_scheduler(vec![node], vec![input.clone()]), input)
}

#[test]
fn control_v3_retains_unresolved_current_time_input_before_execution() {
    let (scheduler, input) = input_scheduler(0);
    let configuration = scheduler.configuration().clone();
    let mut actor = BackendQuantumLoop::new(scheduler, control_backend());

    assert!(
        actor
            .settle_current_fixed_input()
            .expect("select current contract")
            .is_none()
    );
    assert_eq!(actor.loop_impl().pending_events, vec![input.clone()]);
    let error = actor
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            },
            1,
        )
        .expect_err("unresolved current input must refuse RUN");

    assert!(
        matches!(error, SchedulerError::BoundaryViolation { .. }),
        "{error}"
    );
    assert_eq!(actor.loop_impl().pending_events, vec![input]);
    assert_eq!(actor.loop_impl().configuration(), &configuration);
    assert!(actor.backend().run_history.is_empty());
    assert!(actor.backend().inner.state().delivered_inputs.is_empty());
}

#[test]
fn control_v3_future_input_caps_dispatch_and_delivers_original_identity_once() {
    let (scheduler, input) = input_scheduler(5);
    let mut actor = BackendQuantumLoop::new(scheduler, control_backend());
    let mut resolved = Vec::new();

    for _ in 0..2 {
        let outcome = actor
            .drive_concurrent_quantum(
                QuantumRequest {
                    configuration: actor.loop_impl().configuration().clone(),
                    control: Vec::new(),
                },
                1,
            )
            .unwrap_or_else(|error| panic!("input-bounded dispatch: {error}"));
        resolved.extend(
            outcome
                .outcomes
                .into_iter()
                .flat_map(|outcome| outcome.resolved_events),
        );
    }

    assert_eq!(actor.backend().run_history[0].ceiling().ticks, 5);
    assert_eq!(resolved, vec![input.clone()]);
    assert!(actor.loop_impl().pending_events.is_empty());
    let ScheduledEventPayload::BackendInput(delivery) = input.payload else {
        panic!("fixture must carry the original backend delivery");
    };
    assert_eq!(
        actor.backend().inner.state().delivered_inputs,
        vec![delivery]
    );
}

#[test]
fn control_v3_latency_one_cycle_refuses_before_effects_and_retains_inputs() {
    let mut scheduler = scheduler();
    scheduler.effective_topology = SchedulerLookaheadGraph::from_edges(vec![
        SchedulerLookaheadEdge::new(
            scheduler_node("a", SchedulingNodeKind::Vm),
            scheduler_node("b", SchedulingNodeKind::Vm),
            SimDuration { ticks: 1 },
        ),
        SchedulerLookaheadEdge::new(
            scheduler_node("b", SchedulingNodeKind::Vm),
            scheduler_node("a", SchedulingNodeKind::Vm),
            SimDuration { ticks: 1 },
        ),
    ]);
    let input = event(
        5,
        &scheduler_node("a", SchedulingNodeKind::Vm),
        &scheduler_node("network", SchedulingNodeKind::Network),
        9,
        b"retained-on-refusal",
    );
    scheduler.pending_events.push(input.clone());
    let configuration = scheduler.configuration().clone();
    let mut actor = BackendQuantumLoop::new(scheduler, control_backend());

    let error = actor
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            },
            2,
        )
        .expect_err("latency-one cycle has no positive strictly safe tick");

    assert!(
        error
            .to_string()
            .contains("no strictly safe representable RUN"),
        "{error}"
    );
    assert!(actor.backend().run_history.is_empty());
    assert!(actor.backend().inner.state().applied_effects.is_empty());
    assert_eq!(actor.loop_impl().pending_events, vec![input]);
    assert_eq!(actor.loop_impl().configuration(), &configuration);
}

#[test]
fn control_v3_strict_delivery_cap_uses_shared_time_and_rebased_counter_floor() {
    let mut scheduler = scheduler();
    for (node, raw, logical) in [("a", 100, 3), ("b", 200, 3)] {
        let runtime = scheduler
            .nodes
            .iter_mut()
            .find(|runtime| runtime.id.node.name == node)
            .expect("fixture node exists");
        runtime.counter = NodeCounter { ticks: raw };
        runtime.time_mapping = NodeTimeMapping {
            anchor_counter: runtime.counter,
            anchor_time: SimInstant { ticks: logical },
        };
    }
    scheduler.frontier = VirtualTime { ticks: 3 };
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };

    let source = scheduler
        .prepare_host_concurrent_quantum_limited(request.clone(), 2)
        .unwrap_or_else(|error| panic!("unchanged Source preparation: {error}"));
    let control = scheduler
        .prepare_host_concurrent_quantum_for_contract(
            request,
            2,
            crate::BackendDispatchContract::ControlV3,
        )
        .unwrap_or_else(|error| panic!("strict mapped preparation: {error}"));

    assert_eq!(source.runs[0].plan.target_counter, 106);
    assert_eq!(source.runs[0].plan.projected_target_time.ticks, 9);
    assert_eq!(control.runs[0].plan.target_counter, 105);
    assert_eq!(control.runs[0].plan.projected_target_time.ticks, 8);
    assert_eq!(control.run_set.candidates[0].target_time.ticks, 8);
    assert_eq!(control.run_set.candidates[0].max_advance_icount, 105);
    assert_eq!(
        control.runs[0].admission.dispatch_horizon().icount.retired,
        105
    );
}
