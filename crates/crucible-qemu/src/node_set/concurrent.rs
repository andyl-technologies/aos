//! Bounded host-concurrent execution for the production QEMU node set.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use crucible::{
    BackendEffect, BackendError, ConcurrentBackendRun, ConcurrentBackendRunOutcome,
    ConcurrentSimulationBackend, NodeId, SimulationBackend,
};

use super::QemuNodeSet;

/// Evidence from the most recent production host-concurrent RUN set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHostParallelismEvidence {
    /// Number of scheduler-fixed RUNs dispatched in the round.
    pub requested_runs: usize,
    /// Maximum host workers admitted for the round.
    pub maximum_workers: usize,
    /// Peak workers executing backend RUNs simultaneously.
    pub realized_parallelism: usize,
    /// Scheduler-fixed canonical completion order.
    pub commit_order: Vec<NodeId>,
}

impl ConcurrentSimulationBackend for QemuNodeSet {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        max_host_workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunOutcome>, BackendError> {
        if max_host_workers == 0 {
            return Err(BackendError::Rejected {
                message: String::from("QEMU host worker count must be positive"),
            });
        }

        let mut selected = BTreeSet::new();
        for run in &runs {
            if !selected.insert(run.node.clone()) {
                return Err(BackendError::Rejected {
                    message: format!("QEMU host worker RUN set repeats node `{}`", run.node.name),
                });
            }
            if self.pending_selectable_requests.contains_key(&run.node) {
                return Err(BackendError::Rejected {
                    message: format!(
                        "QEMU node `{}` cannot run with an unresolved selectable request",
                        run.node.name
                    ),
                });
            }
            if !self.nodes.contains_key(&run.node) || self.permanently_closed.contains(&run.node) {
                return Err(BackendError::Rejected {
                    message: format!(
                        "QEMU host worker RUN selected absent node `{}`",
                        run.node.name
                    ),
                });
            }
        }
        self.arm_concurrent_fault_event_staging(&runs)?;

        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut outcomes = Vec::with_capacity(runs.len());
        for batch in runs.chunks(max_host_workers) {
            let mut owned = Vec::with_capacity(batch.len());
            for run in batch {
                let backend =
                    self.nodes
                        .remove(&run.node)
                        .ok_or_else(|| BackendError::Rejected {
                            message: format!(
                                "QEMU host worker lost node `{}` before dispatch",
                                run.node.name
                            ),
                        })?;
                owned.push((run.clone(), backend));
            }

            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let completed = thread::scope(|scope| {
                owned
                    .into_iter()
                    .map(|(run, backend)| {
                        let active = Arc::clone(&active);
                        let peak = Arc::clone(&peak);
                        scope.spawn(move || {
                            let mut one = QemuNodeSet::new();
                            one.nodes.insert(run.node.clone(), backend);
                            let operation = catch_unwind(AssertUnwindSafe(|| {
                                for preemption in &run.preemptions {
                                    let at = one.node_now(&run.node)?;
                                    one.apply_to_node(
                                        &run.node,
                                        &BackendEffect::Preemption(preemption.clone()),
                                        at,
                                    )?;
                                }
                                let concurrent = active.fetch_add(1, Ordering::SeqCst) + 1;
                                peak.fetch_max(concurrent, Ordering::SeqCst);
                                let step = one.step_node_to(&run.node, run.ceiling);
                                active.fetch_sub(1, Ordering::SeqCst);
                                let step = step?;
                                let rng_evidence = one.drain_rng_evidence()?;
                                let network_outputs = one.drain_network_outputs()?;
                                let observations = one.drain_observable_events()?;
                                Ok(ConcurrentBackendRunOutcome {
                                    node: run.node.clone(),
                                    step,
                                    rng_evidence,
                                    network_outputs,
                                    observations,
                                })
                            }));
                            let backend = one.nodes.remove(&run.node);
                            let pending = one.pending_selectable_requests.remove(&run.node);
                            (run.node, backend, pending, operation)
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|handle| handle.join())
                    .collect::<Vec<_>>()
            });

            let mut first_error = None;
            for joined in completed {
                let (node, backend, pending, operation) = match joined {
                    Ok(completed) => completed,
                    Err(_) => {
                        first_error.get_or_insert_with(|| BackendError::Rejected {
                            message: String::from(
                                "QEMU host worker panicked outside its guarded RUN",
                            ),
                        });
                        continue;
                    }
                };
                let Some(backend) = backend else {
                    first_error.get_or_insert_with(|| BackendError::Rejected {
                        message: format!("QEMU host worker lost ownership of node `{}`", node.name),
                    });
                    continue;
                };
                self.nodes.insert(node.clone(), backend);
                if let Some(pending) = pending {
                    self.pending_selectable_requests
                        .insert(node.clone(), pending);
                }
                match operation {
                    Ok(Ok(outcome)) => outcomes.push(outcome),
                    Ok(Err(error)) => {
                        first_error.get_or_insert(error);
                    }
                    Err(_) => {
                        first_error.get_or_insert_with(|| BackendError::Rejected {
                            message: format!("QEMU host worker for `{}` panicked", node.name),
                        });
                    }
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
        }
        if outcomes.len() != selected.len() {
            return Err(BackendError::Rejected {
                message: String::from("QEMU host worker outcome cardinality changed"),
            });
        }
        self.last_host_parallelism = Some(QemuHostParallelismEvidence {
            requested_runs: outcomes.len(),
            maximum_workers: max_host_workers,
            realized_parallelism: peak.load(Ordering::SeqCst),
            commit_order: runs.into_iter().map(|run| run.node).collect(),
        });
        Ok(outcomes)
    }
}
