//! Concurrent scheduler preparation and failure-atomicity tests.

use super::*;
use crate::AdvanceOutcome;
use crate::BackendEffect;

struct FailingConcurrentBackend(MockSimulationBackend);

impl SimulationBackend for FailingConcurrentBackend {
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

impl ConcurrentSimulationBackend for FailingConcurrentBackend {
    fn execute_concurrent_runs(
        &mut self,
        _runs: Vec<ConcurrentBackendRun>,
        _max_host_workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunOutcome>, BackendError> {
        Err(BackendError::Rejected {
            message: String::from("injected host worker failure"),
        })
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
    let mut scheduler = test_scheduler(nodes, Vec::new());
    let before_configuration = scheduler.configuration().clone();
    let before_quanta = scheduler.quanta();
    let before_offset = scheduler.event_log().offset();
    let request = QuantumRequest {
        configuration: before_configuration.clone(),
        control: Vec::new(),
    };

    let serial_prepared = scheduler
        .prepare_concurrent_quantum(request.clone())
        .unwrap_or_else(|error| panic!("serial concurrent quantum should prepare: {error}"));
    let prepared = scheduler
        .prepare_concurrent_quantum(request.clone())
        .unwrap_or_else(|error| panic!("concurrent quantum should prepare: {error}"));

    assert_eq!(scheduler.configuration(), &before_configuration);
    assert_eq!(scheduler.quanta(), before_quanta);
    assert_eq!(scheduler.event_log().offset(), before_offset);
    assert_eq!(prepared.run_set().candidates.len(), 2);
    assert_eq!(serial_prepared.run_set(), prepared.run_set());
    assert_eq!(serial_prepared.outcomes(), prepared.outcomes());

    let mut expected = scheduler.clone();
    let expected_outcome = expected
        .drive_concurrent_authoritative_quantum(request)
        .unwrap_or_else(|error| panic!("reference concurrent quantum should drive: {error}"));
    let PreparedSchedulerConcurrentQuantum {
        next,
        outcome: committed,
    } = prepared;
    scheduler = next;

    assert_eq!(committed, expected_outcome);
    assert_eq!(scheduler.configuration(), expected.configuration());
    assert_eq!(scheduler.quanta(), expected.quanta());
    assert_eq!(
        scheduler.event_log().offset(),
        expected.event_log().offset()
    );
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
    let mut adapter = BackendQuantumLoop::new(
        scheduler,
        FailingConcurrentBackend(MockSimulationBackend::new()),
    );

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
    let mut adapter = BackendQuantumLoop::new(
        scheduler,
        FailingConcurrentBackend(MockSimulationBackend::new()),
    );

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
        ) -> Result<Vec<ConcurrentBackendRunOutcome>, BackendError> {
            Ok(runs
                .into_iter()
                .map(|run| ConcurrentBackendRunOutcome {
                    node: run.node.clone(),
                    step: StepObservation::from_advance_outcome(
                        run.ceiling,
                        AdvanceOutcome::ReachedHorizon,
                    ),
                    rng_evidence: vec![BackendRngEvidence {
                        node: run.node,
                        stream: RngStreamId::from_name("invalid-width"),
                        request_id: 0,
                        width: 65,
                        value: 0,
                    }],
                    network_outputs: Vec::new(),
                    observations: Vec::new(),
                })
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
