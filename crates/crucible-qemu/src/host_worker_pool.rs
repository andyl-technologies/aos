//! QEMU-backed host worker pool for concurrent scheduler RUN sets.
//!
//! Each worker thread constructs and permanently owns one backend. This is
//! load-bearing for live [`crate::QemuNode`] values: mapped shared memory and
//! scheduler authorizers remain thread-affine and never cross a thread
//! boundary. Only scheduler-fixed RUN commands and completed boundary evidence
//! cross the worker channels.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use crucible::{
    BackendError, Decision, FingerprintSample, NodeId, ObservableEvent,
    SchedulerConcurrentRunCandidate, SchedulerConcurrentRunSet, SimulationBackend, StepObservation,
    VirtualTime,
};
use thiserror::Error;

/// Scheduler-computed key used to commit host-worker outcomes canonically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct QemuHostCompletionOrderKey {
    /// Virtual-time component computed before dispatch.
    pub ticks: u64,
    /// Stable scheduler sequence used to break equal-time ties.
    pub sequence: u64,
}

/// One scheduler-authorized QEMU backend RUN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHostWorkerRun {
    /// VM node advanced by this RUN.
    pub node: NodeId,
    /// Node-local ceiling fixed before dispatch.
    pub ceiling: VirtualTime,
    /// Canonical commit key fixed before dispatch.
    pub completion_order_key: QemuHostCompletionOrderKey,
}

impl QemuHostWorkerRun {
    /// Builds one QEMU worker RUN from a scheduler run-set candidate.
    #[must_use]
    pub fn from_scheduler_candidate(
        candidate: &SchedulerConcurrentRunCandidate,
        sequence: u64,
    ) -> Self {
        Self {
            node: candidate.node.node.clone(),
            ceiling: VirtualTime {
                ticks: candidate.max_advance_icount,
            },
            completion_order_key: QemuHostCompletionOrderKey {
                ticks: candidate.target_time.nanos,
                sequence,
            },
        }
    }
}

/// Boundary evidence returned by one completed host worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHostWorkerOutcome {
    /// VM node advanced by the worker.
    pub node: NodeId,
    /// Canonical commit key supplied before dispatch.
    pub completion_order_key: QemuHostCompletionOrderKey,
    /// Backend step observation at the completed boundary.
    pub step: StepObservation,
    /// Causal decisions drained before the backend can run again.
    pub causal_decisions: Vec<Decision>,
    /// Observational events drained after causal decisions.
    pub observable_events: Vec<ObservableEvent>,
}

/// Report for one host-concurrent QEMU RUN set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHostWorkerPoolReport {
    /// Maximum number of workers permitted for this dispatch.
    pub max_host_workers: usize,
    /// Peak number of owner threads simultaneously executing a backend RUN.
    pub realized_parallelism: usize,
    /// Outcomes in scheduler completion-order-key order.
    pub outcomes: Vec<QemuHostWorkerOutcome>,
}

struct WorkerHandle {
    commands: Sender<WorkerCommand>,
    thread: Option<JoinHandle<()>>,
}

enum WorkerCommand {
    Run {
        run: QemuHostWorkerRun,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        result: Sender<Result<QemuHostWorkerOutcome, BackendError>>,
    },
    Fingerprint {
        node: NodeId,
        result: Sender<Result<FingerprintSample, BackendError>>,
    },
    Shutdown {
        result: Sender<Result<(), BackendError>>,
    },
}

/// Owns permanent, thread-affine QEMU backend workers.
///
/// A factory passed to [`Self::insert_factory`] is `Send`, but the backend it
/// constructs need not be: construction happens inside the owner thread and
/// the backend remains there until shutdown. This permits production
/// [`crate::QemuNode`] values to participate without marking raw mappings or
/// authorizer trait objects as `Send`.
#[derive(Default)]
pub struct QemuHostWorkerPool {
    workers: BTreeMap<NodeId, WorkerHandle>,
}

impl fmt::Debug for QemuHostWorkerPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuHostWorkerPool")
            .field("nodes", &self.workers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl QemuHostWorkerPool {
    /// Builds an empty host-worker pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawns one owner thread and constructs its backend inside that thread.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHostWorkerPoolError`] when `node` is already registered,
    /// the owner thread cannot spawn, or the backend factory fails.
    pub fn insert_factory<B, F>(
        &mut self,
        node: NodeId,
        factory: F,
    ) -> Result<(), QemuHostWorkerPoolError>
    where
        B: SimulationBackend + 'static,
        F: FnOnce() -> Result<B, BackendError> + Send + 'static,
    {
        if self.workers.contains_key(&node) {
            return Err(QemuHostWorkerPoolError::DuplicateBackend { node });
        }
        let (commands_tx, commands_rx) = mpsc::channel();
        let (startup_tx, startup_rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name(format!("crucible-qemu-{}", node.name))
            .spawn(move || worker_main(factory, commands_rx, startup_tx))
            .map_err(|error| QemuHostWorkerPoolError::Spawn {
                node: node.clone(),
                message: error.to_string(),
            })?;

        match startup_rx.recv() {
            Ok(Ok(())) => {
                self.workers.insert(
                    node,
                    WorkerHandle {
                        commands: commands_tx,
                        thread: Some(handle),
                    },
                );
                Ok(())
            }
            Ok(Err(source)) => {
                let _ = handle.join();
                Err(QemuHostWorkerPoolError::BackendInitialization { node, source })
            }
            Err(_) => {
                let _ = handle.join();
                Err(QemuHostWorkerPoolError::WorkerDisconnected { node })
            }
        }
    }

    /// Returns the number of independently owned VM backends.
    #[must_use]
    pub fn len(&self) -> usize {
        self.workers.len()
    }

    /// Returns whether the pool owns no VM backends.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }

    /// Dispatches scheduler-authorized RUNs and returns canonical-order outcomes.
    ///
    /// Runs beyond `max_host_workers` execute in bounded batches. The caller
    /// receives evidence only after each batch has completed and the complete
    /// outcome set has been sorted by scheduler-supplied completion keys.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHostWorkerPoolError`] when the worker bound is zero, a node
    /// is duplicated or absent, a worker disconnects, or a backend step/evidence
    /// drain fails.
    pub fn execute(
        &self,
        runs: Vec<QemuHostWorkerRun>,
        max_host_workers: usize,
    ) -> Result<QemuHostWorkerPoolReport, QemuHostWorkerPoolError> {
        if max_host_workers == 0 {
            return Err(QemuHostWorkerPoolError::ZeroWorkers);
        }
        validate_runs(&self.workers, &runs)?;

        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut committed = Vec::with_capacity(runs.len());

        for batch in runs.chunks(max_host_workers) {
            let mut receivers = Vec::with_capacity(batch.len());
            for run in batch {
                let worker = self.workers.get(&run.node).ok_or_else(|| {
                    QemuHostWorkerPoolError::MissingBackend {
                        node: run.node.clone(),
                    }
                })?;
                let (result_tx, result_rx) = mpsc::channel();
                worker
                    .commands
                    .send(WorkerCommand::Run {
                        run: run.clone(),
                        active: Arc::clone(&active),
                        peak: Arc::clone(&peak),
                        result: result_tx,
                    })
                    .map_err(|_| QemuHostWorkerPoolError::WorkerDisconnected {
                        node: run.node.clone(),
                    })?;
                receivers.push((run.node.clone(), result_rx));
            }
            for (node, receiver) in receivers {
                let outcome = receiver
                    .recv()
                    .map_err(|_| QemuHostWorkerPoolError::WorkerDisconnected {
                        node: node.clone(),
                    })?
                    .map_err(|source| QemuHostWorkerPoolError::Backend { node, source })?;
                committed.push(outcome);
            }
        }

        committed.sort_by(|left, right| {
            left.completion_order_key
                .cmp(&right.completion_order_key)
                .then_with(|| left.node.cmp(&right.node))
        });
        Ok(QemuHostWorkerPoolReport {
            max_host_workers,
            realized_parallelism: peak.load(Ordering::SeqCst),
            outcomes: committed,
        })
    }

    /// Executes the RUN candidates selected at one scheduler boundary.
    ///
    /// Candidate enumeration supplies the stable tie-break sequence. Host
    /// completion timing therefore cannot influence the returned order.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHostWorkerPoolError`] when the scheduler set is invalid,
    /// references an unregistered node, a worker disconnects, or backend
    /// execution fails.
    pub fn execute_scheduler_run_set(
        &self,
        run_set: &SchedulerConcurrentRunSet,
    ) -> Result<QemuHostWorkerPoolReport, QemuHostWorkerPoolError> {
        let runs = run_set
            .candidates
            .iter()
            .zip(0_u64..)
            .map(|(candidate, sequence)| {
                QemuHostWorkerRun::from_scheduler_candidate(candidate, sequence)
            })
            .collect();
        self.execute(runs, run_set.max_host_workers)
    }

    /// Samples every registered backend in stable node order.
    ///
    /// Sampling executes on each backend's owner thread. The returned map is
    /// suitable for comparing the state reached by serial and concurrent
    /// dispatch without moving a live [`crate::QemuNode`] between threads.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHostWorkerPoolError`] when an owner thread disconnects or a
    /// backend cannot produce its execution fingerprint.
    pub fn fingerprints(
        &self,
    ) -> Result<BTreeMap<NodeId, FingerprintSample>, QemuHostWorkerPoolError> {
        let mut pending = Vec::with_capacity(self.workers.len());
        for (node, worker) in &self.workers {
            let (result_tx, result_rx) = mpsc::channel();
            worker
                .commands
                .send(WorkerCommand::Fingerprint {
                    node: node.clone(),
                    result: result_tx,
                })
                .map_err(|_| QemuHostWorkerPoolError::WorkerDisconnected { node: node.clone() })?;
            pending.push((node.clone(), result_rx));
        }

        let mut fingerprints = BTreeMap::new();
        for (node, receiver) in pending {
            let sample = receiver
                .recv()
                .map_err(|_| QemuHostWorkerPoolError::WorkerDisconnected { node: node.clone() })?
                .map_err(|source| QemuHostWorkerPoolError::Backend {
                    node: node.clone(),
                    source,
                })?;
            fingerprints.insert(node, sample);
        }
        Ok(fingerprints)
    }

    /// Shuts down every thread-owned backend and joins every worker.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHostWorkerPoolError`] for the first backend shutdown
    /// failure, disconnected worker, or worker panic after attempting all
    /// workers.
    pub fn shutdown(&mut self) -> Result<(), QemuHostWorkerPoolError> {
        let workers = std::mem::take(&mut self.workers);
        let mut pending = Vec::with_capacity(workers.len());
        let mut first_error = None;
        for (node, worker) in workers {
            let (result_tx, result_rx) = mpsc::channel();
            if worker
                .commands
                .send(WorkerCommand::Shutdown { result: result_tx })
                .is_err()
                && first_error.is_none()
            {
                first_error =
                    Some(QemuHostWorkerPoolError::WorkerDisconnected { node: node.clone() });
            }
            pending.push((node, worker.thread, result_rx));
        }
        for (node, handle, result_rx) in pending {
            match result_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(source)) if first_error.is_none() => {
                    first_error = Some(QemuHostWorkerPoolError::Backend {
                        node: node.clone(),
                        source,
                    });
                }
                Err(_) if first_error.is_none() => {
                    first_error =
                        Some(QemuHostWorkerPoolError::WorkerDisconnected { node: node.clone() });
                }
                _ => {}
            }
            if let Some(handle) = handle
                && handle.join().is_err()
                && first_error.is_none()
            {
                first_error = Some(QemuHostWorkerPoolError::WorkerPanicked { node });
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for QemuHostWorkerPool {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn worker_main<B, F>(
    factory: F,
    commands: Receiver<WorkerCommand>,
    startup: Sender<Result<(), BackendError>>,
) where
    B: SimulationBackend + 'static,
    F: FnOnce() -> Result<B, BackendError>,
{
    let mut backend = match factory() {
        Ok(backend) => backend,
        Err(error) => {
            let _ = startup.send(Err(error));
            return;
        }
    };
    if startup.send(Ok(())).is_err() {
        let _ = backend.shutdown();
        return;
    }

    while let Ok(command) = commands.recv() {
        match command {
            WorkerCommand::Run {
                run,
                active,
                peak,
                result,
            } => {
                let concurrent = active.fetch_add(1, Ordering::SeqCst).saturating_add(1);
                peak.fetch_max(concurrent, Ordering::SeqCst);
                let outcome = execute_backend_run(&mut backend, &run);
                active.fetch_sub(1, Ordering::SeqCst);
                let _ = result.send(outcome);
            }
            WorkerCommand::Fingerprint { node, result } => {
                let outcome = backend.fingerprint(node);
                let _ = result.send(outcome);
            }
            WorkerCommand::Shutdown { result } => {
                let outcome = backend.shutdown();
                let _ = result.send(outcome);
                return;
            }
        }
    }
    let _ = backend.shutdown();
}

fn validate_runs(
    workers: &BTreeMap<NodeId, WorkerHandle>,
    runs: &[QemuHostWorkerRun],
) -> Result<(), QemuHostWorkerPoolError> {
    let mut nodes = BTreeSet::new();
    for run in runs {
        if !nodes.insert(run.node.clone()) {
            return Err(QemuHostWorkerPoolError::DuplicateRun {
                node: run.node.clone(),
            });
        }
        if !workers.contains_key(&run.node) {
            return Err(QemuHostWorkerPoolError::MissingBackend {
                node: run.node.clone(),
            });
        }
    }
    Ok(())
}

fn execute_backend_run<B>(
    backend: &mut B,
    run: &QemuHostWorkerRun,
) -> Result<QemuHostWorkerOutcome, BackendError>
where
    B: SimulationBackend,
{
    const MAX_REISSUES: usize = 64;

    let mut causal_decisions = Vec::new();
    let mut observable_events = Vec::new();
    let mut previous_reached = backend.now();
    for reissue in 0..=MAX_REISSUES {
        let step = backend.step_to(run.ceiling)?;
        if step.requested_ceiling != run.ceiling || step.reached > run.ceiling {
            return Err(BackendError::Rejected {
                message: format!(
                    "host worker for {} reached {} for scheduler ceiling {}",
                    run.node.name, step.reached.ticks, run.ceiling.ticks
                ),
            });
        }
        let drained_decisions = backend.drain_causal_decisions()?;
        let drained_events = backend.drain_observable_events()?;
        let made_progress = step.reached > previous_reached;
        let drained_boundary = !drained_decisions.is_empty() || !drained_events.is_empty();
        causal_decisions.extend(drained_decisions);
        observable_events.extend(drained_events);

        if step.reached == run.ceiling {
            return Ok(QemuHostWorkerOutcome {
                node: run.node.clone(),
                completion_order_key: run.completion_order_key,
                step,
                causal_decisions,
                observable_events,
            });
        }
        if reissue == MAX_REISSUES || (!made_progress && !drained_boundary) {
            return Err(BackendError::Rejected {
                message: format!(
                    "host worker for {} stalled at {} below scheduler ceiling {} after {} reissues",
                    run.node.name, step.reached.ticks, run.ceiling.ticks, reissue
                ),
            });
        }
        previous_reached = step.reached;
    }
    Err(BackendError::Rejected {
        message: String::from("QEMU host worker exhausted its bounded reissue loop"),
    })
}

/// Failure while dispatching or joining a QEMU host-worker RUN set.
#[derive(Debug, Error)]
pub enum QemuHostWorkerPoolError {
    /// The caller supplied a zero worker bound.
    #[error("QEMU host worker count must be positive")]
    ZeroWorkers,
    /// Two backends were registered for the same node.
    #[error("QEMU host worker backend for node {node:?} is already registered")]
    DuplicateBackend {
        /// Duplicate node identifier.
        node: NodeId,
    },
    /// A RUN set selected the same node more than once.
    #[error("QEMU host worker RUN set contains duplicate node {node:?}")]
    DuplicateRun {
        /// Duplicate node identifier.
        node: NodeId,
    },
    /// A RUN selected a node with no owned backend.
    #[error("QEMU host worker RUN selected unknown node {node:?}")]
    MissingBackend {
        /// Missing node identifier.
        node: NodeId,
    },
    /// The operating system refused to spawn an owner thread.
    #[error("failed to spawn QEMU host worker for {node:?}: {message}")]
    Spawn {
        /// Node whose owner thread could not start.
        node: NodeId,
        /// Host error detail.
        message: String,
    },
    /// A backend factory failed inside its owner thread.
    #[error("QEMU host worker backend for {node:?} failed to initialize: {source}")]
    BackendInitialization {
        /// Node whose backend failed to initialize.
        node: NodeId,
        /// Backend initialization failure.
        #[source]
        source: BackendError,
    },
    /// An owner thread disconnected from its scheduler channel.
    #[error("QEMU host worker for {node:?} disconnected")]
    WorkerDisconnected {
        /// Disconnected node identifier.
        node: NodeId,
    },
    /// An owner thread panicked.
    #[error("QEMU host worker for {node:?} panicked")]
    WorkerPanicked {
        /// Panicked node identifier.
        node: NodeId,
    },
    /// One backend failed its scheduler-authorized operation.
    #[error("QEMU host worker for {node:?} failed: {source}")]
    Backend {
        /// Node whose backend failed.
        node: NodeId,
        /// Backend failure.
        #[source]
        source: BackendError,
    },
}
