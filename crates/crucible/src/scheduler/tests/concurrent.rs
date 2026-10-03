//! Concurrent scheduler preparation and failure-atomicity tests.

use super::*;
use crate::AdvanceOutcome;
use crate::BackendEffect;

#[path = "concurrent/network_output.rs"]
mod network_output;

#[path = "concurrent/held_stop.rs"]
mod held_stop;

#[path = "concurrent/control_v3.rs"]
mod control_v3;

struct TestConcurrentBackend {
    inner: MockSimulationBackend,
    control_v3: bool,
    fail: bool,
    run_sizes: Vec<usize>,
    run_history: Vec<ConcurrentBackendRun>,
    network_outputs: BTreeMap<NodeId, std::collections::VecDeque<BackendNetworkOutput>>,
    retained_dispatch: BTreeMap<NodeId, BackendRunDispatchBoundary>,
}

impl TestConcurrentBackend {
    fn new(fail: bool) -> Self {
        Self {
            inner: MockSimulationBackend::new(),
            control_v3: false,
            fail,
            run_sizes: Vec::new(),
            run_history: Vec::new(),
            network_outputs: BTreeMap::new(),
            retained_dispatch: BTreeMap::new(),
        }
    }

    fn with_network_output(self, source: &str, emit_tick: u64) -> Self {
        self.with_network_output_to(source, "z-peer", emit_tick)
    }

    fn with_network_output_to(mut self, source: &str, destination: &str, emit_tick: u64) -> Self {
        let node = NodeId {
            name: source.to_owned(),
        };
        let outputs = self.network_outputs.entry(node.clone()).or_default();
        let sequence = outputs.len() as u64;
        let mut payload = vec![0_u8; 60];
        payload[..6].copy_from_slice(&[0xff; 6]);
        payload[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        payload[12..14].copy_from_slice(&[0x08, 0x00]);
        outputs.push_back(BackendNetworkOutput {
            source: node,
            destination: NodeId {
                name: destination.to_owned(),
            },
            emit_icount: Icount { retired: emit_tick },
            sequence,
            payload,
            route: None,
            fault_continuation: BackendNetworkFaultContinuation::default(),
        });
        self
    }
}

impl SimulationBackend for TestConcurrentBackend {
    fn dispatch_contract(&self) -> crate::BackendDispatchContract {
        if self.control_v3 {
            crate::BackendDispatchContract::ControlV3
        } else {
            crate::BackendDispatchContract::PhysicalSource
        }
    }

    fn io_inventory_authority(&self) -> crate::BackendIoInventoryAuthority {
        if self.control_v3 {
            crate::BackendIoInventoryAuthority::PhysicalSource
        } else {
            crate::BackendIoInventoryAuthority::SchedulerOwnedModel
        }
    }

    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        self.inner.step_to(ceiling)
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

    fn stage_dispatch_boundary_effect(
        &mut self,
        boundary: &BackendRunDispatchBoundary,
        key: &ScheduledEventKey,
        effect: &BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        if self.retained_dispatch.get(boundary.admission.node()) != Some(boundary)
            || at.ticks != boundary.reached.ticks
        {
            return Err(BackendError::Rejected {
                message: String::from("modeled dispatch input changed owner"),
            });
        }
        boundary
            .admission
            .validate_input_delivery_coordinate(key, NodeCounter { ticks: at.ticks })?;
        self.inner
            .apply_to_node(boundary.admission.node(), effect, at)
    }
}

impl ConcurrentSimulationBackend for TestConcurrentBackend {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        _max_host_workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunResult>, BackendError> {
        self.run_sizes.push(runs.len());
        self.run_history.extend(runs.iter().cloned());
        if self.fail {
            return Err(BackendError::Rejected {
                message: String::from("injected host worker failure"),
            });
        }
        runs.into_iter()
            .map(|run| {
                let node = run.node().clone();
                let network_outputs = self
                    .network_outputs
                    .get_mut(run.node())
                    .filter(|outputs| {
                        outputs
                            .front()
                            .is_some_and(|output| output.emit_icount.retired <= run.ceiling().ticks)
                    })
                    .and_then(std::collections::VecDeque::pop_front)
                    .into_iter()
                    .collect::<Vec<_>>();
                // A TX stops this RUN at its exact emission coordinate.
                let outcome =
                    network_outputs
                        .first()
                        .map_or(AdvanceOutcome::ReachedHorizon, |output| {
                            AdvanceOutcome::Paused {
                                at: output.emit_icount,
                            }
                        });
                let mut step = StepObservation::from_advance_outcome(run.ceiling(), outcome);
                if !network_outputs.is_empty() {
                    step.physical_stop = crate::BackendPhysicalStop::NetworkOutput;
                }
                if self.control_v3 {
                    self.inner.step_node_to(&node, step.reached)?;
                }
                if !self.control_v3
                    && network_outputs.is_empty()
                    && step.reached.ticks < run.admission.semantic_horizon().icount.retired
                {
                    let boundary = BackendRunDispatchBoundary {
                        reached: NodeCounter {
                            ticks: step.reached.ticks,
                        },
                        admission: run.admission,
                    };
                    self.retained_dispatch.insert(node, boundary.clone());
                    return Ok(ConcurrentBackendRunResult::DispatchBoundary(boundary));
                }
                step.applied_preemptions = run
                    .preemptions
                    .into_iter()
                    .filter(|command| command.at.ticks <= step.reached.ticks)
                    .collect();
                Ok(ConcurrentBackendRunResult::Completed(
                    ConcurrentBackendRunOutcome {
                        node,
                        step,
                        rng_evidence: Vec::new(),
                        network_outputs,
                        observations: Vec::new(),
                    },
                ))
            })
            .collect()
    }

    fn resume_dispatch_boundary(
        &mut self,
        run: ConcurrentBackendRun,
        boundary: &BackendRunDispatchBoundary,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        if self.retained_dispatch.get(run.node()) != Some(boundary)
            || run.admission.context() != boundary.admission.context()
            || run.admission.control_token() != boundary.admission.control_token()
            || run.admission.input_inventory().generation()
                <= boundary.admission.input_inventory().generation()
        {
            return Err(BackendError::Rejected {
                message: String::from("modeled dispatch readmission changed owner"),
            });
        }
        self.retained_dispatch.remove(run.node());
        let mut results = self.execute_concurrent_runs(vec![run], 1)?;
        Ok(results.remove(0))
    }
}

#[test]
fn concurrent_prepare_is_private_until_canonical_commit() {
    let nodes = ["node-a", "node-b"]
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
    let scheduler = test_scheduler(nodes, Vec::new());
    let before_configuration = scheduler.configuration().clone();
    let before_quanta = scheduler.quanta();
    let before_offset = scheduler.event_log().offset();
    let request = QuantumRequest {
        configuration: before_configuration.clone(),
        control: Vec::new(),
    };

    let prepared = scheduler
        .prepare_host_concurrent_quantum_limited(request.clone(), usize::MAX)
        .unwrap_or_else(|error| panic!("concurrent quantum should prepare: {error}"));

    assert_eq!(scheduler.configuration(), &before_configuration);
    assert_eq!(scheduler.quanta(), before_quanta);
    assert_eq!(scheduler.event_log().offset(), before_offset);
    assert_eq!(prepared.run_set.candidates.len(), 2);
    assert_eq!(prepared.runs.len(), 2);
    assert_eq!(prepared.next.event_log().offset(), before_offset);
    assert_eq!(prepared.next.quanta(), before_quanta);

    let mut expected = scheduler.clone();
    let committed = expected
        .drive_concurrent_authoritative_quantum(request)
        .unwrap_or_else(|error| panic!("reference concurrent quantum should drive: {error}"));

    assert_eq!(committed.run_set, prepared.run_set);
    assert_eq!(committed.outcomes.len(), prepared.runs.len());
    assert_eq!(expected.quanta(), before_quanta + 2);
    assert!(expected.event_log().offset().events > before_offset.events);
}

#[test]
fn choice_pause_prepares_only_the_first_canonical_run_before_backend_execution() {
    let nodes = ["node-a", "node-b"]
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
    let scheduler = test_scheduler(nodes, Vec::new());
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };

    let ordinary = scheduler
        .prepare_host_concurrent_quantum_limited(request.clone(), usize::MAX)
        .expect("ordinary same-frontier RUN set");
    let paused = scheduler
        .prepare_host_concurrent_quantum_limited(request, 1)
        .expect("choice-search RUN set");

    assert_eq!(ordinary.run_set.candidates.len(), 2);
    assert_eq!(paused.run_set.candidates, ordinary.run_set.candidates[..1]);
    assert_eq!(paused.runs.len(), 1);
    assert_eq!(scheduler.quanta(), 0);
}

#[test]
fn choice_free_boot_batches_five_peers_then_returns_to_serial_pause() {
    let nodes = [
        "router-a",
        "router-b",
        "router-c",
        "traffic-east",
        "traffic-west",
    ]
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
    let scheduler = test_scheduler(nodes, Vec::new());
    let configuration = scheduler.configuration().clone();
    let mut post_marker =
        BackendQuantumLoop::new(scheduler.clone(), TestConcurrentBackend::new(false));

    let mut serial = BackendQuantumLoop::new(scheduler.clone(), TestConcurrentBackend::new(false));
    serial.set_live_network_choice_pause(true);
    for _ in 0..5 {
        serial
            .drive_concurrent_quantum(
                QuantumRequest {
                    configuration: configuration.clone(),
                    control: Vec::new(),
                },
                5,
            )
            .expect("serial choice pause");
    }

    let mut parallel = BackendQuantumLoop::new(scheduler, TestConcurrentBackend::new(false));
    parallel.set_live_network_choice_pause(true);
    parallel.set_choice_free_parallel_boot(true);
    let boot = parallel
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            },
            5,
        )
        .expect("choice-free boot batch");

    assert_eq!(boot.run_set.candidates.len(), 5);
    assert_eq!(serial.backend().run_sizes, vec![1; 5]);
    assert_eq!(parallel.backend().run_sizes, vec![5]);
    assert_eq!(
        parallel.loop_impl().configuration(),
        serial.loop_impl().configuration()
    );
    assert_eq!(
        parallel.loop_impl().event_log_offset(),
        serial.loop_impl().event_log_offset()
    );
    assert_eq!(
        parallel.loop_impl().event_log().retained_entries(),
        serial.loop_impl().event_log().retained_entries()
    );

    // The owner disables boot batching when it consumes the west marker.
    post_marker.set_live_network_choice_pause(true);
    post_marker.set_choice_free_parallel_boot(true);
    post_marker.set_choice_free_parallel_boot(false);
    post_marker
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            5,
        )
        .expect("post-marker choice pause");
    assert_eq!(post_marker.backend().run_sizes, vec![1; 5]);
}

#[test]
fn concurrent_backend_rejects_zero_workers_before_preparation() {
    let scheduler = test_scheduler(
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    let before_configuration = scheduler.configuration().clone();
    let before_quanta = scheduler.quanta();
    let before_offset = scheduler.event_log().offset();
    let request = QuantumRequest {
        configuration: before_configuration.clone(),
        control: Vec::new(),
    };
    let mut adapter = BackendQuantumLoop::new(scheduler, TestConcurrentBackend::new(true));

    let error = adapter
        .drive_concurrent_quantum(request, 0)
        .expect_err("a concurrent backend must reject a zero host-worker bound");

    assert!(
        error
            .to_string()
            .contains("concurrent backend max_host_workers must be positive")
    );
    assert_eq!(adapter.loop_impl().configuration(), &before_configuration);
    assert_eq!(adapter.loop_impl().quanta(), before_quanta);
    assert_eq!(adapter.loop_impl().event_log().offset(), before_offset);
}

#[test]
fn concurrent_backend_failure_leaves_scheduler_uncommitted() {
    let scheduler = test_scheduler(
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    let before_configuration = scheduler.configuration().clone();
    let before_quanta = scheduler.quanta();
    let before_offset = scheduler.event_log().offset();
    let mut adapter = BackendQuantumLoop::new(scheduler, TestConcurrentBackend::new(true));

    let error = adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: before_configuration.clone(),
                control: Vec::new(),
            },
            1,
        )
        .expect_err("injected host failure must reject the round");

    assert!(error.to_string().contains("injected host worker failure"));
    assert_eq!(adapter.loop_impl().configuration(), &before_configuration);
    assert_eq!(adapter.loop_impl().quanta(), before_quanta);
    assert_eq!(adapter.loop_impl().event_log().offset(), before_offset);

    let retry_error = adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: before_configuration,
                control: Vec::new(),
            },
            1,
        )
        .expect_err("an uncertain live-backend round must poison continuation");
    assert!(retry_error.to_string().contains("continuation is poisoned"));
}

#[test]
fn concurrent_publication_failure_leaves_logical_state_uncommitted_and_poisons() {
    struct InvalidEvidenceBackend(MockSimulationBackend);

    impl SimulationBackend for InvalidEvidenceBackend {
        fn io_inventory_authority(&self) -> crate::BackendIoInventoryAuthority {
            crate::BackendIoInventoryAuthority::SchedulerOwnedModel
        }

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

        fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
            self.0.fingerprint(node)
        }

        fn shutdown(&mut self) -> Result<(), BackendError> {
            self.0.shutdown()
        }
    }

    impl ConcurrentSimulationBackend for InvalidEvidenceBackend {
        fn execute_concurrent_runs(
            &mut self,
            runs: Vec<ConcurrentBackendRun>,
            _max_host_workers: usize,
        ) -> Result<Vec<ConcurrentBackendRunResult>, BackendError> {
            Ok(runs
                .into_iter()
                .map(|run| ConcurrentBackendRunOutcome {
                    node: run.node().clone(),
                    step: StepObservation::from_advance_outcome(
                        run.ceiling(),
                        AdvanceOutcome::ReachedHorizon,
                    ),
                    rng_evidence: vec![BackendRngEvidence {
                        node: run.node().clone(),
                        stream: RngStreamId::from_name("invalid-width"),
                        request_id: 0,
                        width: 65,
                        value: 0,
                    }],
                    network_outputs: Vec::new(),
                    observations: Vec::new(),
                })
                .map(ConcurrentBackendRunResult::Completed)
                .collect())
        }
    }

    let scheduler = test_scheduler(
        vec![test_scenario_node(
            "node-a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };
    let mut adapter = BackendQuantumLoop::new(
        scheduler,
        InvalidEvidenceBackend(MockSimulationBackend::new()),
    );
    let before = adapter
        .loop_impl()
        .checkpoint()
        .and_then(|checkpoint| checkpoint.canonical_bytes())
        .expect("scheduler checkpoint before invalid evidence");

    let error = adapter
        .drive_concurrent_quantum(request.clone(), 1)
        .expect_err("invalid live evidence must fail publication");
    assert!(error.to_string().contains("random"));
    let after = adapter
        .loop_impl()
        .checkpoint()
        .and_then(|checkpoint| checkpoint.canonical_bytes())
        .expect("scheduler checkpoint after invalid evidence");
    assert_eq!(after, before);
    assert_eq!(adapter.committed_frontier(), VirtualTime { ticks: 0 });
    assert_eq!(adapter.pending_network_output_count(), 0);

    let retry = adapter
        .drive_concurrent_quantum(request, 1)
        .expect_err("indeterminate backend publication must poison continuation");
    assert!(retry.to_string().contains("continuation is poisoned"));
}
