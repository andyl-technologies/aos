//! Retained input-boundary fixture and causal peer-delivery regressions.

use super::*;
use crate::BackendEffect;

/// Explicit model of the closed handoff; no native permission is modeled here.
struct InputBoundaryBackend {
    inner: MockSimulationBackend,
    retained: BTreeMap<NodeId, BackendRunInputBoundary>,
    staged: usize,
    fail_stage: Option<usize>,
    fail_after_stage: Option<usize>,
    staged_keys: Vec<ScheduledEventKey>,
    completed: usize,
    completed_nodes: Vec<NodeId>,
    output_node: Option<NodeId>,
    output_tick: u64,
    output_emitted: bool,
    trace: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    chain: bool,
    retained_dispatch: BTreeMap<NodeId, BackendRunDispatchBoundary>,
    chained_admissions: Vec<PreparedRunAdmission>,
}

impl InputBoundaryBackend {
    fn new(fail_stage: Option<usize>) -> Self {
        Self {
            inner: MockSimulationBackend::new(),
            retained: BTreeMap::new(),
            staged: 0,
            fail_stage,
            fail_after_stage: None,
            staged_keys: Vec::new(),
            completed: 0,
            completed_nodes: Vec::new(),
            output_node: None,
            output_tick: 20,
            output_emitted: false,
            trace: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
            chain: false,
            retained_dispatch: BTreeMap::new(),
            chained_admissions: Vec::new(),
        }
    }

    fn continue_wave(
        &mut self,
        run: ConcurrentBackendRun,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        self.chained_admissions.push(run.admission.clone());
        if self.output_node.as_ref() == Some(run.node())
            && !self.output_emitted
            && self.output_tick <= run.ceiling().ticks
        {
            self.output_emitted = true;
            self.inner.step_node_to(
                run.node(),
                VirtualTime {
                    ticks: self.output_tick,
                },
            )?;
            let mut step = StepObservation::from_advance_outcome(
                run.ceiling(),
                crate::AdvanceOutcome::Paused {
                    at: Icount {
                        retired: self.output_tick,
                    },
                },
            );
            step.physical_stop = crate::BackendPhysicalStop::NetworkOutput;
            return Ok(ConcurrentBackendRunResult::Completed(
                ConcurrentBackendRunOutcome {
                    node: run.node().clone(),
                    step,
                    rng_evidence: Vec::new(),
                    observations: Vec::new(),
                    network_outputs: vec![BackendNetworkOutput {
                        source: run.node().clone(),
                        destination: NodeId {
                            name: String::from("z-input"),
                        },
                        emit_icount: Icount {
                            retired: self.output_tick,
                        },
                        sequence: 0,
                        payload: vec![0; 60],
                        route: None,
                        fault_continuation: BackendNetworkFaultContinuation::default(),
                    }],
                },
            ));
        }
        let step = self.inner.step_node_to(run.node(), run.ceiling())?;
        if let Some(reached) = run.admission.input_inventory().next_input()
            && reached.ticks == run.ceiling().ticks
        {
            let boundary = BackendRunInputBoundary {
                admission: run.admission,
                reached,
            };
            self.retained
                .insert(boundary.admission.node().clone(), boundary.clone());
            return Ok(ConcurrentBackendRunResult::InputBoundary(boundary));
        }
        if run.ceiling().ticks < run.admission.semantic_horizon().icount.retired {
            let boundary = BackendRunDispatchBoundary {
                reached: NodeCounter {
                    ticks: run.ceiling().ticks,
                },
                admission: run.admission,
            };
            self.retained_dispatch
                .insert(boundary.admission.node().clone(), boundary.clone());
            return Ok(ConcurrentBackendRunResult::DispatchBoundary(boundary));
        }
        self.completed += 1;
        self.completed_nodes.push(run.node().clone());
        Ok(ConcurrentBackendRunResult::Completed(
            ConcurrentBackendRunOutcome {
                node: run.node().clone(),
                step,
                rng_evidence: Vec::new(),
                network_outputs: Vec::new(),
                observations: Vec::new(),
            },
        ))
    }
}

impl SimulationBackend for InputBoundaryBackend {
    fn io_inventory_authority(&self) -> crate::BackendIoInventoryAuthority {
        crate::BackendIoInventoryAuthority::SchedulerOwnedModel
    }

    fn step_to(&mut self, at: VirtualTime) -> Result<StepObservation, BackendError> {
        self.inner.step_to(at)
    }
    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        self.inner.apply(effect, at)
    }
    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        self.inner.snapshot()
    }
    fn restore(&mut self, state: &BackendSnapshot) -> Result<(), BackendError> {
        self.inner.restore(state)
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

    fn stage_input_boundary_effect(
        &mut self,
        boundary: &BackendRunInputBoundary,
        delivery_key: &ScheduledEventKey,
        effect: &BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        if self.retained.get(boundary.admission.node()) != Some(boundary)
            || at.ticks != boundary.reached.ticks
        {
            return Err(BackendError::Rejected {
                message: String::from("foreign input owner"),
            });
        }
        let BackendEffect::DeliverInput(input) = effect else {
            return Err(BackendError::Rejected {
                message: String::from("non-input effect"),
            });
        };
        if delivery_key.consumer().node != input.node
            || &input.node != boundary.admission.node()
            || self.fail_stage == Some(self.staged + 1)
        {
            return Err(BackendError::Rejected {
                message: String::from("staging refused"),
            });
        }
        self.inner.apply_to_node(&input.node, effect, at)?;
        self.staged += 1;
        self.staged_keys.push(delivery_key.clone());
        self.trace
            .borrow_mut()
            .push(format!("input:{}:{}", input.node.name, at.ticks));
        if self.fail_after_stage == Some(self.staged) {
            return Err(BackendError::Rejected {
                message: String::from("notification refused after modeled input publication"),
            });
        }
        Ok(())
    }

    fn stage_dispatch_boundary_effect(
        &mut self,
        boundary: &BackendRunDispatchBoundary,
        key: &ScheduledEventKey,
        effect: &BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        if self.retained_dispatch.get(boundary.admission.node()) != Some(boundary)
            || at.ticks != boundary.reached.ticks
            || self.fail_stage == Some(self.staged + 1)
        {
            return Err(BackendError::Rejected {
                message: String::from("foreign or refused internal input owner"),
            });
        }
        let BackendEffect::DeliverInput(input) = effect else {
            return Err(BackendError::Rejected {
                message: String::from("non-input effect"),
            });
        };
        if key.consumer().node != input.node || &input.node != boundary.admission.node() {
            return Err(BackendError::Rejected {
                message: String::from("foreign internal input key"),
            });
        }
        self.inner.apply_to_node(&input.node, effect, at)?;
        self.staged += 1;
        self.staged_keys.push(key.clone());
        self.trace
            .borrow_mut()
            .push(format!("input:{}:{}", input.node.name, at.ticks));
        Ok(())
    }
}

impl ConcurrentSimulationBackend for InputBoundaryBackend {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        _workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunResult>, BackendError> {
        runs.into_iter()
            .map(|run| {
                if run
                    .admission
                    .input_inventory()
                    .next_input()
                    .is_none_or(|input| input.ticks > run.ceiling().ticks)
                {
                    if self.chain {
                        return self.continue_wave(run);
                    }
                    if self.output_node.as_ref() == Some(run.node())
                        && !self.output_emitted
                        && self.output_tick <= run.ceiling().ticks
                    {
                        self.output_emitted = true;
                        self.inner.step_node_to(
                            run.node(),
                            VirtualTime {
                                ticks: self.output_tick,
                            },
                        )?;
                        let mut step = StepObservation::from_advance_outcome(
                            run.ceiling(),
                            crate::AdvanceOutcome::Paused {
                                at: Icount {
                                    retired: self.output_tick,
                                },
                            },
                        );
                        step.physical_stop = crate::BackendPhysicalStop::NetworkOutput;
                        return Ok(ConcurrentBackendRunResult::Completed(
                            ConcurrentBackendRunOutcome {
                                node: run.node().clone(),
                                step,
                                rng_evidence: Vec::new(),
                                observations: Vec::new(),
                                network_outputs: vec![BackendNetworkOutput {
                                    source: run.node().clone(),
                                    destination: NodeId {
                                        name: String::from("z-input"),
                                    },
                                    emit_icount: Icount {
                                        retired: self.output_tick,
                                    },
                                    sequence: 0,
                                    payload: vec![0; 60],
                                    route: None,
                                    fault_continuation: BackendNetworkFaultContinuation::default(),
                                }],
                            },
                        ));
                    }
                    if run.ceiling().ticks < run.admission.semantic_horizon().icount.retired {
                        return self.continue_wave(run);
                    }
                    let step = self.inner.step_node_to(run.node(), run.ceiling())?;
                    return Ok(ConcurrentBackendRunResult::Completed(
                        ConcurrentBackendRunOutcome {
                            node: run.node().clone(),
                            step,
                            rng_evidence: Vec::new(),
                            network_outputs: Vec::new(),
                            observations: Vec::new(),
                        },
                    ));
                }
                let reached = run
                    .admission
                    .input_inventory()
                    .next_input()
                    .ok_or_else(|| BackendError::Rejected {
                        message: String::from("fixture needs actual queued input"),
                    })?;
                self.inner.step_node_to(
                    run.node(),
                    VirtualTime {
                        ticks: reached.ticks,
                    },
                )?;
                let boundary = BackendRunInputBoundary {
                    admission: run.admission,
                    reached,
                };
                self.retained
                    .insert(boundary.admission.node().clone(), boundary.clone());
                Ok(ConcurrentBackendRunResult::InputBoundary(boundary))
            })
            .collect()
    }

    fn resume_input_boundary(
        &mut self,
        run: ConcurrentBackendRun,
        boundary: &BackendRunInputBoundary,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        if self.retained.get(boundary.admission.node()) != Some(boundary)
            || self.staged == 0
            || run.admission.control_token() != boundary.admission.control_token()
            || run.admission.context() != boundary.admission.context()
            || run.admission.input_inventory().generation()
                <= boundary.admission.input_inventory().generation()
            || run
                .admission
                .input_inventory()
                .next_input()
                .is_some_and(|input| input <= boundary.reached)
        {
            return Err(BackendError::Rejected {
                message: String::from("stale input readmission"),
            });
        }
        if self.chain {
            self.retained.remove(boundary.admission.node());
            return self.continue_wave(run);
        }
        let step = self.inner.step_node_to(run.node(), run.ceiling())?;
        self.retained.remove(boundary.admission.node());
        self.completed += 1;
        self.completed_nodes.push(run.node().clone());
        Ok(ConcurrentBackendRunResult::Completed(
            ConcurrentBackendRunOutcome {
                node: run.node().clone(),
                step,
                rng_evidence: Vec::new(),
                network_outputs: Vec::new(),
                observations: Vec::new(),
            },
        ))
    }

    fn resume_dispatch_boundary(
        &mut self,
        run: ConcurrentBackendRun,
        boundary: &BackendRunDispatchBoundary,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        if self.retained_dispatch.get(boundary.admission.node()) != Some(boundary)
            || run.admission.context() != boundary.admission.context()
            || run.admission.control_token() != boundary.admission.control_token()
            || run.admission.input_inventory().generation()
                <= boundary.admission.input_inventory().generation()
        {
            return Err(BackendError::Rejected {
                message: String::from("stale internal-stop readmission"),
            });
        }
        self.retained_dispatch.remove(boundary.admission.node());
        self.continue_wave(run)
    }
}

fn input_scheduler(count: u64) -> SingleScheduler {
    let consumer = scheduler_node("a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("network", SchedulingNodeKind::Network);
    test_scheduler(
        vec![runnable("a")],
        (0..count)
            .map(|sequence| event(20, &consumer, &producer, sequence, &[sequence as u8]))
            .collect(),
    )
}

#[test]
fn actual_actor_resolves_reached_input_before_settlement_without_double_staging() {
    for workers in [1, 2] {
        let scheduler = input_scheduler(1);
        let request = QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        };
        let mut actor = BackendQuantumLoop::new(scheduler, InputBoundaryBackend::new(None));

        let outcome = actor
            .drive_concurrent_quantum(request, workers)
            .expect("actor closes due-input stop");

        assert_eq!(outcome.outcomes[0].frontier.ticks, 20);
        assert_eq!(outcome.outcomes[0].resolved_events.len(), 1);
        assert_eq!(actor.backend().staged, 1);
        assert_eq!(actor.backend().inner.state().delivered_inputs.len(), 1);
        assert_eq!(actor.backend().completed, 1);
        assert!(actor.backend().retained.is_empty());
        assert!(actor.loop_impl().pending_events.is_empty());
    }
}

#[test]
fn failed_or_partial_input_staging_retains_owner_without_step_or_floor() {
    for refused in [1, 2] {
        let scheduler = input_scheduler(2);
        let configuration = scheduler.configuration().clone();
        let offset = scheduler.event_log().offset();
        let request = QuantumRequest {
            configuration: configuration.clone(),
            control: Vec::new(),
        };
        let mut actor =
            BackendQuantumLoop::new(scheduler, InputBoundaryBackend::new(Some(refused)));

        assert!(actor.drive_concurrent_quantum(request, 1).is_err());

        assert_eq!(actor.loop_impl().configuration(), &configuration);
        assert_eq!(actor.loop_impl().event_log().offset(), offset);
        assert_eq!(actor.loop_impl().pending_events.len(), 2);
        assert_eq!(actor.backend().completed, 0);
        assert_eq!(actor.backend().staged, refused - 1);
        assert!(!actor.backend().retained.is_empty());
        let progress = actor
            .failed_input_resolution()
            .expect("exact publication cursor is retained");
        assert_eq!(progress.events().len(), 2);
        assert_eq!(progress.applied_keys().len(), refused - 1);
        assert_eq!(
            progress.attempted_key(),
            Some(&progress.events()[refused - 1].key)
        );
        for (key, event) in progress.applied_keys().iter().zip(progress.events()) {
            assert_eq!(key, &event.key);
        }
        let retry = actor
            .drive_concurrent_quantum(
                QuantumRequest {
                    configuration: configuration.clone(),
                    control: Vec::new(),
                },
                2,
            )
            .expect_err("an uncertain prefix is cleanup-only");
        assert!(retry.to_string().contains("continuation is poisoned"));
        assert_eq!(actor.backend().staged, refused - 1);
        assert!(actor.failed_input_resolution().is_some());
    }
}

#[test]
fn equal_payload_events_keep_distinct_keys_after_uncertain_publication() {
    for workers in [1, 2] {
        let mut scheduler = input_scheduler(2);
        for event in &mut scheduler.pending_events {
            let ScheduledEventPayload::BackendInput(input) = &mut event.payload else {
                panic!("fixture contains only actual backend inputs");
            };
            input.payload = vec![7];
        }
        let configuration = scheduler.configuration().clone();
        let keys = scheduler
            .pending_events
            .iter()
            .map(|event| event.key.clone())
            .collect::<Vec<_>>();
        assert_ne!(keys[0], keys[1]);
        let mut backend = InputBoundaryBackend::new(None);
        backend.fail_after_stage = Some(2);
        let mut actor = BackendQuantumLoop::new(scheduler, backend);

        assert!(
            actor
                .drive_concurrent_quantum(
                    QuantumRequest {
                        configuration: configuration.clone(),
                        control: Vec::new(),
                    },
                    workers,
                )
                .is_err()
        );

        let progress = actor
            .failed_input_resolution()
            .expect("retained uncertain key");
        assert_eq!(progress.applied_keys(), &keys[..1]);
        assert_eq!(progress.attempted_key(), Some(&keys[1]));
        assert_eq!(actor.backend().staged_keys, keys);
        assert_eq!(actor.backend().inner.state().delivered_inputs.len(), 2);
        assert_eq!(actor.loop_impl().configuration(), &configuration);
        assert_eq!(actor.backend().completed, 0);

        let retry = actor.drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            workers,
        );
        assert!(
            retry
                .expect_err("uncertain publication is cleanup-only")
                .to_string()
                .contains("continuation is poisoned")
        );
        assert_eq!(actor.backend().staged_keys, keys);
        assert_eq!(actor.backend().inner.state().delivered_inputs.len(), 2);
    }
}

#[test]
fn modeled_io_queue_resolution_cannot_substitute_for_backend_consumption() {
    let consumer = scheduler_node("a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("disk", SchedulingNodeKind::Disk);
    let due = io_completion_event(20, &consumer, &producer, 1, &[9]);
    let scheduler = test_scheduler(vec![runnable("a")], vec![due.clone()]);
    let configuration = scheduler.configuration().clone();
    let mut actor = BackendQuantumLoop::new(scheduler, InputBoundaryBackend::new(None));

    let error = actor
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            },
            1,
        )
        .expect_err("device queue removal is not physical input consumption");

    assert!(
        error
            .to_string()
            .contains("stage_input_boundary_io_completion")
    );
    let progress = actor
        .failed_input_resolution()
        .expect("exact IO attempt retained");
    assert_eq!(progress.events(), std::slice::from_ref(&due));
    assert!(progress.applied_keys().is_empty());
    assert_eq!(progress.attempted_key(), Some(&due.key));
    assert_eq!(actor.loop_impl().configuration(), &configuration);
    assert_eq!(actor.loop_impl().pending_events, vec![due]);
    assert_eq!(actor.backend().completed, 0);
    assert!(!actor.backend().retained.is_empty());
}

#[test]
fn unclassified_backend_refuses_admitted_run_without_advancing() {
    let admission = prepare(&test_scheduler(vec![runnable("a")], Vec::new())).runs[0]
        .admission
        .clone();
    let mut backend = InputBoundaryBackend::new(None);
    assert!(matches!(
        backend.step_node_with_admission(&admission),
        Err(BackendError::Unsupported { .. })
    ));
    assert_eq!(backend.now().ticks, 0);
}

#[derive(Clone)]
struct TraceOutput(std::rc::Rc<std::cell::RefCell<Vec<String>>>);

impl BackendNetworkOutputInterceptor<SingleScheduler, InputBoundaryBackend> for TraceOutput {
    fn intercept_network_outputs(
        &mut self,
        _scheduler: &mut SingleScheduler,
        _backend: &mut InputBoundaryBackend,
        _frontier: VirtualTime,
        _pending: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        for output in outputs.iter() {
            self.0.borrow_mut().push(format!(
                "output:{}:{}",
                output.source.name, output.emit_icount.retired
            ));
        }
        outputs.clear();
        Ok(Vec::new())
    }
}

#[derive(Clone)]
struct TracePeerDelivery(TraceOutput);

impl BackendNetworkOutputInterceptor<SingleScheduler, InputBoundaryBackend> for TracePeerDelivery {
    fn intercept_network_outputs(
        &mut self,
        scheduler: &mut SingleScheduler,
        backend: &mut InputBoundaryBackend,
        frontier: VirtualTime,
        pending: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        // Explicit modeled link delivery, derived from the actual returned TX
        // and the scheduler's source mapping; no native service proof is minted.
        for output in outputs.iter() {
            let emitted =
                scheduler.backend_network_output_time(&output.source, output.emit_icount)?;
            let delivery = emitted
                .ticks
                .checked_add(6)
                .expect("bounded modeled latency");
            let consumer = scheduler_node(&output.destination.name, SchedulingNodeKind::Vm);
            let producer = scheduler_node(&output.source.name, SchedulingNodeKind::Vm);
            scheduler.pending_events.push(event(
                delivery,
                &consumer,
                &producer,
                output.sequence,
                b"peer",
            ));
        }
        self.0
            .intercept_network_outputs(scheduler, backend, frontier, pending, outputs)
    }
}

#[test]
fn later_input_wave_observes_peer_output_between_actual_clipped_dispatches() {
    for workers in [1, 2] {
        assert_peer_delivery_order(workers, false, None);
    }
}

#[test]
fn retained_original_run_observes_canonical_peer_commit_before_next_input_wave() {
    for workers in [1, 2] {
        assert_peer_delivery_order(workers, true, None);
    }
}

#[test]
fn failed_later_wave_retains_original_owner_and_prior_canonical_input_history() {
    for workers in [1, 2] {
        assert_peer_delivery_order(workers, true, Some(2));
    }
}

fn assert_peer_delivery_order(workers: usize, chain: bool, fail_stage: Option<usize>) {
    let input = scheduler_node("z-input", SchedulingNodeKind::Vm);
    let producer = scheduler_node("network", SchedulingNodeKind::Network);
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "two-input-waves-around-peer-output",
        if chain { 64 } else { 16 },
        SimInstant { ticks: 64 },
        vec![
            test_scenario_node(
                "z-input",
                if chain { 0 } else { 29 },
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            ),
            test_scenario_node(
                "a-output",
                if chain { 0 } else { 39 },
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        if chain {
            Vec::new()
        } else {
            vec![
                event(30, &input, &producer, 0, b"first"),
                event(50, &input, &producer, 1, b"last"),
            ]
        },
    )
    .with_effective_topology_edges(vec![SchedulerLookaheadEdge::new(
        scheduler_node("a-output", SchedulingNodeKind::Vm),
        input.clone(),
        SimDuration { ticks: 6 },
    )]);
    let scheduler = SingleScheduler::new(scenario).expect("actual two-node queue fixture");
    let mut backend = InputBoundaryBackend::new(fail_stage);
    backend.chain = chain;
    backend.output_node = Some(NodeId {
        name: String::from("a-output"),
    });
    backend.output_tick = 40;
    backend
        .inner
        .step_node_to(
            &NodeId {
                name: String::from("z-input"),
            },
            VirtualTime {
                ticks: if chain { 0 } else { 29 },
            },
        )
        .expect("model consumer matches its configured ready point");
    backend
        .inner
        .step_node_to(
            &NodeId {
                name: String::from("a-output"),
            },
            VirtualTime {
                ticks: if chain { 0 } else { 39 },
            },
        )
        .expect("model physical node matches the configured ready point");
    let trace = std::rc::Rc::clone(&backend.trace);
    let mut actor = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
        TracePeerDelivery(TraceOutput(std::rc::Rc::clone(&trace))),
    );

    if chain {
        let scheduler = actor.loop_impl();
        let mut prepared = scheduler
            .prepare_host_concurrent_quantum_limited(
                QuantumRequest {
                    configuration: scheduler.configuration().clone(),
                    control: Vec::new(),
                },
                usize::MAX,
            )
            .expect("actual no-input PICK fixes original Run horizon");
        assert_eq!(prepared.runs.len(), 1);
        prepared.next.pending_events.extend([
            event(30, &input, &producer, 0, b"first"),
            event(50, &input, &producer, 1, b"last"),
        ]);
        let run = prepared
            .runs
            .iter()
            .find(|run| run.plan.node == input)
            .expect("actual selected input owner");
        assert_eq!(run.admission.semantic_horizon().icount.retired, 64);
        assert_eq!(run.admission.dispatch_horizon().icount.retired, 6);
        let original = run.admission.clone();
        let runs = prepared
            .runs
            .iter()
            .map(|run| ConcurrentBackendRun {
                admission: run.admission.clone(),
                preemptions: run
                    .preemptions
                    .iter()
                    .map(|application| application.decision.clone())
                    .collect(),
            })
            .collect();
        let completed = actor
            .backend_mut()
            .execute_concurrent_runs(runs, workers)
            .expect("model backend returns real sealed Run results");
        let result = actor.complete_prepared_host_run_set(prepared, completed);
        if fail_stage.is_some() {
            assert!(result.is_err());
            let history = actor
                .failed_input_resolution()
                .expect("later publication retains full Run history");
            assert_eq!(history.boundary().admission.context(), original.context());
            assert_eq!(
                history.boundary().admission.control_token(),
                original.control_token()
            );
            assert_eq!(
                history
                    .events()
                    .iter()
                    .map(|event| event.key.virtual_time().ticks)
                    .collect::<Vec<_>>(),
                [30, 46]
            );
            assert_eq!(
                history
                    .applied_keys()
                    .iter()
                    .map(|key| key.virtual_time().ticks)
                    .collect::<Vec<_>>(),
                [30]
            );
            assert_eq!(
                history
                    .attempted_key()
                    .expect("exact uncertain key")
                    .virtual_time()
                    .ticks,
                46
            );
            assert_eq!(*trace.borrow(), ["input:z-input:30", "output:a-output:40"]);
            assert_eq!(actor.backend().inner.state().delivered_inputs.len(), 1);
            assert_eq!(
                actor
                    .backend()
                    .completed_nodes
                    .iter()
                    .filter(|node| node.name == "z-input")
                    .count(),
                0
            );
            let staged = actor.backend().staged;
            assert!(
                actor
                    .drive_concurrent_quantum(
                        QuantumRequest {
                            configuration: actor.loop_impl().configuration().clone(),
                            control: Vec::new(),
                        },
                        workers
                    )
                    .is_err()
            );
            assert_eq!(actor.backend().staged, staged);
            return;
        }
        result.unwrap_or_else(|error| {
            panic!("one original Run: {error}; trace={:?}", trace.borrow())
        });
    }

    for _ in 0..if chain { 0 } else { 8 } {
        actor
            .drive_concurrent_quantum(
                QuantumRequest {
                    configuration: actor.loop_impl().configuration().clone(),
                    control: Vec::new(),
                },
                workers,
            )
            .unwrap_or_else(|error| {
                panic!("actual capped wave: {error}; trace={:?}", trace.borrow())
            });
        if actor.backend().staged == 3 {
            break;
        }
    }

    let mut expected = vec!["input:z-input:30", "output:a-output:40", "input:z-input:46"];
    if chain {
        expected.push("input:z-input:50");
    }
    assert_eq!(*trace.borrow(), expected);
    let delivered = &actor.backend().inner.state().delivered_inputs;
    assert_eq!(delivered.len(), 3);
    assert_eq!(
        delivered
            .iter()
            .map(|input| input.payload.as_slice())
            .collect::<Vec<_>>(),
        [b"first".as_slice(), b"peer".as_slice(), b"last".as_slice()]
    );
    assert!(actor.backend().retained.is_empty());
    assert!(actor.failed_input_resolution().is_none());
    assert!(actor.backend().retained_dispatch.is_empty());
    if chain {
        let admissions = &actor.backend().chained_admissions;
        assert!(admissions.len() >= 3);
        let input_admissions = admissions
            .iter()
            .filter(|admission| admission.node().name == "z-input")
            .collect::<Vec<_>>();
        let origin = input_admissions[0];
        assert_eq!(origin.semantic_horizon().icount.retired, 64);
        for admission in input_admissions {
            assert_eq!(admission.context(), origin.context());
            assert_eq!(admission.control_token(), origin.control_token());
            assert_eq!(admission.semantic_horizon(), origin.semantic_horizon());
        }
        assert_eq!(
            actor
                .backend()
                .completed_nodes
                .iter()
                .filter(|node| node.name == "z-input")
                .count(),
            1
        );
        assert_eq!(
            actor
                .loop_impl()
                .nodes
                .iter()
                .find(|node| node.id.node.name == "z-input")
                .expect("configured consumer")
                .counter
                .ticks,
            64
        );
    }
}

#[test]
fn later_input_is_staged_only_after_earlier_peer_semantic_publication() {
    for workers in [1, 2] {
        let input = scheduler_node("z-input", SchedulingNodeKind::Vm);
        let producer = scheduler_node("network", SchedulingNodeKind::Network);
        let scenario = SchedulerLivenessScenario::from_canonical_material(
            "canonical-input-after-output",
            16,
            SimInstant { ticks: 30 },
            vec![runnable("z-input"), runnable("a-output")],
            vec![event(30, &input, &producer, 0, b"input")],
        );
        let scheduler = SingleScheduler::new(scenario).expect("actual scenario plans two RUNs");
        let request = QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        };
        let mut backend = InputBoundaryBackend::new(None);
        backend.output_node = Some(NodeId {
            name: String::from("a-output"),
        });
        let trace = std::rc::Rc::clone(&backend.trace);
        let mut actor = BackendQuantumLoop::with_network_output_interceptor(
            scheduler,
            backend,
            TraceOutput(std::rc::Rc::clone(&trace)),
        );

        actor
            .drive_concurrent_quantum(request, workers)
            .expect("exact output and input settle canonically");

        assert_eq!(
            *trace.borrow(),
            [
                String::from("output:a-output:20"),
                String::from("input:z-input:30")
            ]
        );
        assert_eq!(actor.backend().staged, 1);
        assert!(actor.backend().retained.is_empty());
    }
}
