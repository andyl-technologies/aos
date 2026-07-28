//! Host-worker execution gates for T-PERF-29.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::sync::{Arc, Barrier};

use crucible::{
    AdvanceOutcome, BackendEffect, BackendError, BackendSnapshot, FingerprintSample, Icount,
    MockSimulationBackend, NodeId, SchedulerConcurrentRunCandidate, SchedulerConcurrentRunSet,
    SchedulerNodeId, SchedulingNodeKind, SimInstant, SimulationBackend, StepObservation,
    VirtualTime,
};
use crucible_qemu::{
    QemuHostCompletionOrderKey, QemuHostWorkerOutcome, QemuHostWorkerPool, QemuHostWorkerRun,
};

#[derive(Debug)]
struct GatedBackend {
    inner: MockSimulationBackend,
    gate: Option<Arc<Barrier>>,
    pause_once: bool,
}

impl GatedBackend {
    fn new(gate: Option<Arc<Barrier>>) -> Self {
        Self {
            inner: MockSimulationBackend::new(),
            gate,
            pause_once: false,
        }
    }

    fn pausing() -> Self {
        Self {
            inner: MockSimulationBackend::new(),
            gate: None,
            pause_once: true,
        }
    }
}

impl SimulationBackend for GatedBackend {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        if let Some(gate) = &self.gate {
            gate.wait();
        }
        if self.pause_once {
            self.pause_once = false;
            return Ok(StepObservation::from_advance_outcome(
                ceiling,
                AdvanceOutcome::Paused {
                    at: Icount {
                        retired: ceiling.ticks.saturating_sub(1),
                    },
                },
            ));
        }
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
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn run(name: &str, ceiling: u64, order: u64) -> QemuHostWorkerRun {
    QemuHostWorkerRun {
        node: node(name),
        ceiling: VirtualTime { ticks: ceiling },
        completion_order_key: QemuHostCompletionOrderKey {
            ticks: order,
            sequence: 0,
        },
    }
}

fn scheduler_candidate(
    name: &str,
    ceiling: u64,
    target_time: u64,
) -> SchedulerConcurrentRunCandidate {
    SchedulerConcurrentRunCandidate {
        node: SchedulerNodeId {
            node: node(name),
            kind: SchedulingNodeKind::Vm,
        },
        current_time: SimInstant { nanos: 0 },
        target_time: SimInstant { nanos: target_time },
        max_advance_icount: ceiling,
    }
}

fn causal_projection(outcomes: &[QemuHostWorkerOutcome]) -> Vec<(NodeId, VirtualTime)> {
    outcomes
        .iter()
        .map(|outcome| (outcome.node.clone(), outcome.step.reached))
        .collect()
}

/// [PERF-29] — distinct worker threads execute the selected RUN set while the
/// scheduler's completion-order key, not worker return order, controls commit.
#[test]
fn qemu_host_worker_pool_executes_real_concurrent_path_in_canonical_order() {
    let gate = Arc::new(Barrier::new(2));
    let mut pool = QemuHostWorkerPool::new();
    let alpha_gate = Arc::clone(&gate);
    pool.insert_factory(node("alpha"), move || {
        Ok(GatedBackend::new(Some(alpha_gate)))
    })
    .expect("alpha backend");
    pool.insert_factory(node("beta"), move || Ok(GatedBackend::new(Some(gate))))
        .expect("beta backend");

    let run_set = SchedulerConcurrentRunSet {
        max_host_workers: 2,
        candidates: vec![
            scheduler_candidate("alpha", 8, 20),
            scheduler_candidate("beta", 8, 10),
        ],
    };
    let report = pool
        .execute_scheduler_run_set(&run_set)
        .expect("concurrent RUN set");

    assert_eq!(report.realized_parallelism, 2);
    assert_eq!(
        report
            .outcomes
            .iter()
            .map(|outcome| outcome.node.name.as_str())
            .collect::<Vec<_>>(),
        vec!["beta", "alpha"],
        "outcomes must commit in scheduler-key order"
    );
}

/// [PERF-29] — `max_host_workers=1` and `=N` produce identical backend state
/// and canonical outcome projections; the worker count remains diagnostic only.
#[test]
fn qemu_host_worker_count_does_not_change_state_or_canonical_outcomes() {
    let runs = vec![run("alpha", 8, 10), run("beta", 8, 20)];
    let mut serial = QemuHostWorkerPool::new();
    serial
        .insert_factory(node("alpha"), || Ok(GatedBackend::pausing()))
        .expect("serial alpha");
    serial
        .insert_factory(node("beta"), || Ok(GatedBackend::new(None)))
        .expect("serial beta");
    let serial_report = serial.execute(runs.clone(), 1).expect("serial execution");

    let gate = Arc::new(Barrier::new(2));
    let mut parallel = QemuHostWorkerPool::new();
    let alpha_gate = Arc::clone(&gate);
    parallel
        .insert_factory(node("alpha"), move || {
            Ok(GatedBackend::new(Some(alpha_gate)))
        })
        .expect("parallel alpha");
    parallel
        .insert_factory(node("beta"), move || Ok(GatedBackend::new(Some(gate))))
        .expect("parallel beta");
    let parallel_report = parallel.execute(runs, 2).expect("parallel execution");
    let serial_fingerprints = serial.fingerprints().expect("serial fingerprints");
    let parallel_fingerprints = parallel.fingerprints().expect("parallel fingerprints");

    assert_eq!(
        causal_projection(&serial_report.outcomes),
        causal_projection(&parallel_report.outcomes)
    );
    assert_eq!(serial_fingerprints, parallel_fingerprints);
    assert_eq!(serial_report.realized_parallelism, 1);
    assert_eq!(parallel_report.realized_parallelism, 2);
}
