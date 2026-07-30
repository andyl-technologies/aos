//! Live-QEMU acceptance gate for scheduler host-worker parallelism.
//!
//! The gate boots two production [`crate::QemuNode`] backends twice. The first
//! dispatch uses one host worker; the second uses two. Both consume the same
//! scheduler-authored concurrent RUN set, and the gate requires identical state
//! fingerprints, virtual-time outcomes, causal decisions, and observable events.
//! Host overlap is measured inside the production owner-thread path rather than
//! inferred from a cost-model projection.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crucible::{
    BackendError, ContentHash, FingerprintSample, NodeId, SchedulerConcurrentRunCandidate,
    SchedulerConcurrentRunSet, SchedulerNodeId, SchedulingNodeKind, SimInstant,
};
use thiserror::Error;

use crate::{
    QemuHostWorkerOutcome, QemuHostWorkerPool, QemuHostWorkerPoolError, QemuLiveNodeStepGateConfig,
};

use super::node_step_gate::{LiveNodeIdentity, build_live_node};

const HOST_PARALLEL_CEILING: u64 = 3_000_000;
const HOST_PARALLEL_CURRENT: u64 = 1_000_000;
const HOST_PARALLEL_NODES: [&str; 2] = ["host-worker-alpha", "host-worker-beta"];

/// Successful evidence from the real-QEMU host-worker acceptance gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveHostParallelReport {
    /// Peak live backend advances during the one-worker reference run.
    pub serial_realized_parallelism: usize,
    /// Peak live backend advances during the two-worker run.
    pub parallel_realized_parallelism: usize,
    /// Wall time spent advancing the one-worker RUN set.
    pub serial_dispatch_wall: Duration,
    /// Wall time spent advancing the two-worker RUN set.
    pub parallel_dispatch_wall: Duration,
    /// Worker-neutral state/time evidence hash for the reference run.
    pub serial_evidence_hash: ContentHash,
    /// Worker-neutral state/time evidence hash for the parallel run.
    pub parallel_evidence_hash: ContentHash,
    /// Serial and parallel state fingerprints matched exactly.
    pub state_bit_identical: bool,
    /// Serial and parallel virtual-time outcomes matched exactly.
    pub time_bit_identical: bool,
    /// Serial and parallel canonical causal/observable streams matched exactly.
    pub canonical_log_bit_identical: bool,
}

/// Runs the serial-versus-parallel acceptance check on four live QEMU children.
///
/// # Errors
///
/// Returns [`QemuLiveHostParallelGateError`] when a QEMU node cannot be built,
/// a host worker fails, the parallel path does not overlap two backend advances,
/// or serial and parallel state, time, or canonical evidence diverges.
pub fn run_qemu_live_host_parallel_gate(
    config: &QemuLiveNodeStepGateConfig,
) -> Result<QemuLiveHostParallelReport, QemuLiveHostParallelGateError> {
    let serial = run_dispatch(config, "host-parallel-serial", 1)?;
    let parallel = run_dispatch(config, "host-parallel-parallel", HOST_PARALLEL_NODES.len())?;

    let state_bit_identical = serial.fingerprints == parallel.fingerprints;
    let time_bit_identical =
        time_projection(&serial.outcomes) == time_projection(&parallel.outcomes);
    let canonical_log_bit_identical =
        log_projection(&serial.outcomes) == log_projection(&parallel.outcomes);
    if !state_bit_identical || !time_bit_identical || !canonical_log_bit_identical {
        return Err(QemuLiveHostParallelGateError::SerialParallelDiverged {
            state_bit_identical,
            time_bit_identical,
            canonical_log_bit_identical,
        });
    }
    if parallel.realized_parallelism != HOST_PARALLEL_NODES.len() {
        return Err(QemuLiveHostParallelGateError::ParallelismNotRealized {
            expected: HOST_PARALLEL_NODES.len(),
            actual: parallel.realized_parallelism,
        });
    }

    let serial_evidence_hash = evidence_hash(&serial.outcomes, &serial.fingerprints);
    let parallel_evidence_hash = evidence_hash(&parallel.outcomes, &parallel.fingerprints);
    if serial_evidence_hash != parallel_evidence_hash {
        return Err(QemuLiveHostParallelGateError::EvidenceHashDiverged {
            serial: serial_evidence_hash,
            parallel: parallel_evidence_hash,
        });
    }

    Ok(QemuLiveHostParallelReport {
        serial_realized_parallelism: serial.realized_parallelism,
        parallel_realized_parallelism: parallel.realized_parallelism,
        serial_dispatch_wall: serial.wall,
        parallel_dispatch_wall: parallel.wall,
        serial_evidence_hash,
        parallel_evidence_hash,
        state_bit_identical,
        time_bit_identical,
        canonical_log_bit_identical,
    })
}

struct DispatchEvidence {
    realized_parallelism: usize,
    wall: Duration,
    outcomes: Vec<QemuHostWorkerOutcome>,
    fingerprints: BTreeMap<NodeId, FingerprintSample>,
}

fn run_dispatch(
    config: &QemuLiveNodeStepGateConfig,
    subdirectory: &str,
    max_host_workers: usize,
) -> Result<DispatchEvidence, QemuLiveHostParallelGateError> {
    let mut pool = QemuHostWorkerPool::new();
    for &name in &HOST_PARALLEL_NODES {
        let worker_config = config.clone();
        let worker_directory = config.run_directory().join(subdirectory).join(name);
        let worker_node = node(name);
        pool.insert_factory(worker_node, move || {
            build_live_node(
                &worker_config,
                &worker_directory,
                LiveNodeIdentity {
                    node: name,
                    router: "host-worker-router",
                    crash_detector: name,
                },
                None,
            )
            .map_err(|error| BackendError::Rejected {
                message: format!("build live host-worker node {name}: {error}"),
            })
        })?;
    }

    let run_set = SchedulerConcurrentRunSet {
        max_host_workers,
        candidates: HOST_PARALLEL_NODES
            .iter()
            .map(|name| SchedulerConcurrentRunCandidate {
                node: SchedulerNodeId {
                    node: node(name),
                    kind: SchedulingNodeKind::Vm,
                },
                current_time: SimInstant {
                    nanos: HOST_PARALLEL_CURRENT,
                },
                target_time: SimInstant {
                    nanos: HOST_PARALLEL_CEILING,
                },
                max_advance_icount: HOST_PARALLEL_CEILING,
            })
            .collect(),
    };
    let started = diagnostic_wall_clock_start();
    let report = pool.execute_scheduler_run_set(&run_set)?;
    let wall = diagnostic_wall_clock_elapsed(started);
    let fingerprints = pool.fingerprints()?;
    pool.shutdown()?;

    Ok(DispatchEvidence {
        realized_parallelism: report.realized_parallelism,
        wall,
        outcomes: report.outcomes,
        fingerprints,
    })
}

/// Starts a diagnostics-only wall-clock measurement outside canonical state.
// crucible-lint: allow clippy-disallowed-method -- host dispatch timing is emitted only as perf evidence and never enters Crucible state or a content hash.
#[allow(clippy::disallowed_methods)]
fn diagnostic_wall_clock_start() -> Instant {
    Instant::now()
}

/// Measures diagnostics-only host dispatch time outside canonical state.
// crucible-lint: allow clippy-disallowed-method -- host dispatch timing is emitted only as perf evidence and never enters Crucible state or a content hash.
#[allow(clippy::disallowed_methods)]
fn diagnostic_wall_clock_elapsed(started: Instant) -> Duration {
    started.elapsed()
}

fn time_projection(outcomes: &[QemuHostWorkerOutcome]) -> Vec<(&NodeId, u64, u64)> {
    outcomes
        .iter()
        .map(|outcome| {
            (
                &outcome.node,
                outcome.step.requested_ceiling.ticks,
                outcome.step.reached.ticks,
            )
        })
        .collect()
}

fn log_projection(
    outcomes: &[QemuHostWorkerOutcome],
) -> Vec<(&NodeId, &[crucible::Decision], &[crucible::ObservableEvent])> {
    outcomes
        .iter()
        .map(|outcome| {
            (
                &outcome.node,
                outcome.causal_decisions.as_slice(),
                outcome.observable_events.as_slice(),
            )
        })
        .collect()
}

fn evidence_hash(
    outcomes: &[QemuHostWorkerOutcome],
    fingerprints: &BTreeMap<NodeId, FingerprintSample>,
) -> ContentHash {
    let mut material = String::new();
    for outcome in outcomes {
        material.push_str(&outcome.node.name);
        material.push(':');
        material.push_str(&outcome.step.requested_ceiling.ticks.to_string());
        material.push(':');
        material.push_str(&outcome.step.reached.ticks.to_string());
        material.push('\n');
    }
    for (node, sample) in fingerprints {
        material.push_str(&node.name);
        material.push(':');
        material.push_str(&sample.at.ticks.to_string());
        material.push(':');
        material.push_str(&sample.fingerprint.hash.to_hex());
        material.push('\n');
    }
    ContentHash::from_canonical_material("crucible.qemu.host-parallel-evidence.v1", &material)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

/// Failure from the real-QEMU host-worker acceptance gate.
#[derive(Debug, Error)]
pub enum QemuLiveHostParallelGateError {
    /// A worker backend failed to initialize, execute, fingerprint, or shut down.
    #[error("live QEMU host-worker pool failed")]
    WorkerPool {
        /// Underlying worker-pool failure.
        #[from]
        source: QemuHostWorkerPoolError,
    },
    /// The parallel run did not overlap every selected backend.
    #[error("live QEMU worker path realized P={actual}; expected P={expected}")]
    ParallelismNotRealized {
        /// Required peak overlap.
        expected: usize,
        /// Observed peak overlap.
        actual: usize,
    },
    /// Serial and parallel semantic evidence differed.
    #[error(
        "live QEMU serial/parallel divergence: state={state_bit_identical}, time={time_bit_identical}, canonical_log={canonical_log_bit_identical}"
    )]
    SerialParallelDiverged {
        /// Whether state fingerprints matched.
        state_bit_identical: bool,
        /// Whether time outcomes matched.
        time_bit_identical: bool,
        /// Whether canonical causal/observable streams matched.
        canonical_log_bit_identical: bool,
    },
    /// A worker-neutral evidence digest changed with the worker bound.
    #[error("worker-neutral evidence hash diverged: serial={serial:?}, parallel={parallel:?}")]
    EvidenceHashDiverged {
        /// Serial evidence hash.
        serial: ContentHash,
        /// Parallel evidence hash.
        parallel: ContentHash,
    },
}
