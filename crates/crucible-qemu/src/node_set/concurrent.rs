//! Bounded host-concurrent execution for the production QEMU node set.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use crucible::{
    BackendEffect, BackendError, ConcurrentBackendRun, ConcurrentBackendRunOutcome,
    ConcurrentSimulationBackend, FingerprintSample, NodeId, SimulationBackend,
};

use super::QemuNodeSet;

fn validate_fingerprint_selection<T>(
    backends: &BTreeMap<NodeId, T>,
    permanently_closed: &[NodeId],
    nodes: &[NodeId],
    maximum_workers: usize,
) -> Result<BTreeSet<NodeId>, BackendError> {
    if maximum_workers == 0 {
        return Err(BackendError::Rejected {
            message: String::from("QEMU fingerprint worker count must be positive"),
        });
    }

    let mut selected = BTreeSet::new();
    let mut repeated = BTreeSet::new();
    for node in nodes {
        if !selected.insert(node.clone()) {
            repeated.insert(node.clone());
        }
    }
    if let Some(node) = repeated.first() {
        return Err(BackendError::Rejected {
            message: format!("QEMU fingerprint request repeats node `{}`", node.name),
        });
    }
    for node in &selected {
        if permanently_closed.contains(node) || !backends.contains_key(node) {
            return Err(BackendError::Rejected {
                message: format!(
                    "QEMU fingerprint request selected absent node `{}`",
                    node.name
                ),
            });
        }
    }

    Ok(selected)
}

fn fingerprint_selected_nodes<T: Send>(
    backends: &mut BTreeMap<NodeId, T>,
    selected: &BTreeSet<NodeId>,
    maximum_workers: usize,
    sample: impl Fn(&mut T, NodeId) -> Result<FingerprintSample, BackendError> + Sync,
) -> Result<BTreeMap<NodeId, FingerprintSample>, BackendError> {
    let mut fingerprints = BTreeMap::new();
    let mut selected_backends = backends
        .iter_mut()
        .filter(|(node, _)| selected.contains(*node))
        .map(|(node, backend)| (node.clone(), backend))
        .collect::<Vec<_>>();

    for batch in selected_backends.chunks_mut(maximum_workers) {
        let completed = thread::scope(|scope| {
            let sampler = &sample;
            batch
                .iter_mut()
                .map(|(node, backend)| {
                    let node = node.clone();
                    scope.spawn(move || sampler(backend, node))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join())
                .collect::<Vec<_>>()
        });

        // Join every worker before reporting the first error in node order.
        // Each backend remains owned by the node set even when sampling fails.
        for ((node, _), result) in batch.iter().zip(completed) {
            let fingerprint = result.map_err(|_| BackendError::Rejected {
                message: format!("QEMU fingerprint worker for `{}` panicked", node.name),
            })??;
            if fingerprint.node != *node {
                return Err(BackendError::Rejected {
                    message: format!(
                        "QEMU fingerprint worker for `{}` returned another node",
                        node.name
                    ),
                });
            }
            fingerprints.insert(node.clone(), fingerprint);
        }
    }

    if fingerprints.len() != selected.len() {
        return Err(BackendError::Rejected {
            message: String::from("QEMU fingerprint result cardinality changed"),
        });
    }

    Ok(fingerprints)
}

impl QemuNodeSet {
    /// Checks that one node can be sampled at the current paused boundary.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or permanently closed.
    pub fn validate_fingerprint_node(&self, node: &NodeId) -> Result<(), BackendError> {
        if self.permanently_closed.contains(node) {
            return Err(BackendError::Rejected {
                message: format!("QEMU node `{}` is permanently failed", node.name),
            });
        }
        if !self.nodes.contains_key(node) {
            return Err(BackendError::Rejected {
                message: format!("QEMU backend set has no node `{}`", node.name),
            });
        }
        Ok(())
    }

    /// Captures every requested node's exact paused-boundary fingerprint.
    ///
    /// Each node keeps its own QEMU process and shared-memory slot. Workers
    /// only overlap independent captures; the returned map and first error
    /// follow canonical node order, independent of host completion order.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] for an invalid worker bound, repeated, absent,
    /// or closed node, or any failed or panicking fingerprint capture.
    pub fn fingerprints_at_boundary(
        &mut self,
        nodes: &[NodeId],
        maximum_workers: usize,
    ) -> Result<BTreeMap<NodeId, FingerprintSample>, BackendError> {
        let selected = validate_fingerprint_selection(
            &self.nodes,
            &self.permanently_closed,
            nodes,
            maximum_workers,
        )?;

        fingerprint_selected_nodes(
            &mut self.nodes,
            &selected,
            maximum_workers,
            |backend, node| backend.fingerprint(node),
        )
    }
}

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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crucible::{ContentHash, ExecutionFingerprint, VirtualTime};

    use super::*;

    fn node(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }

    fn sample(value: &mut u64, node: NodeId) -> FingerprintSample {
        FingerprintSample {
            at: VirtualTime { ticks: *value },
            fingerprint: ExecutionFingerprint {
                hash: ContentHash::from_bytes(node.name.as_bytes()),
            },
            node,
        }
    }

    #[test]
    fn parallel_fingerprints_equal_every_sequential_boundary_sample()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut backends =
            BTreeMap::from([(node("alpha"), 11), (node("beta"), 13), (node("gamma"), 17)]);
        let requested = vec![node("gamma"), node("alpha"), node("beta")];
        let selected = validate_fingerprint_selection(&backends, &[], &requested, 2)?;
        let expected = backends
            .iter_mut()
            .map(|(node, backend)| (node.clone(), sample(backend, node.clone())))
            .collect::<BTreeMap<_, _>>();

        let actual = fingerprint_selected_nodes(&mut backends, &selected, 2, |backend, node| {
            Ok(sample(backend, node))
        })?;

        assert_eq!(actual, expected);
        assert_eq!(actual.len(), requested.len());
        assert_eq!(backends[&node("alpha")], 11);
        Ok(())
    }

    #[test]
    fn invalid_fingerprint_selection_fails_before_sampling() {
        let backends = BTreeMap::from([(node("alpha"), 11)]);

        assert!(matches!(
            validate_fingerprint_selection(&backends, &[], &[node("alpha")], 0),
            Err(BackendError::Rejected { message }) if message.contains("positive")
        ));
        assert!(matches!(
            validate_fingerprint_selection(&backends, &[], &[node("alpha"), node("alpha")], 2),
            Err(BackendError::Rejected { message }) if message.contains("repeats node `alpha`")
        ));
        assert!(matches!(
            validate_fingerprint_selection(&backends, &[], &[node("beta")], 2),
            Err(BackendError::Rejected { message }) if message.contains("absent node `beta`")
        ));
        assert!(matches!(
            validate_fingerprint_selection(&backends, &[], &[node("zeta"), node("beta")], 2),
            Err(BackendError::Rejected { message }) if message.contains("absent node `beta`")
        ));
        assert!(matches!(
            validate_fingerprint_selection(&backends, &[node("alpha")], &[node("alpha")], 2),
            Err(BackendError::Rejected { message }) if message.contains("absent node `alpha`")
        ));
    }

    #[test]
    fn parallel_fingerprint_errors_are_sorted_and_keep_every_backend_owned()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut backends = BTreeMap::from([(node("alpha"), 11), (node("beta"), 13)]);
        let selected = BTreeSet::from([node("alpha"), node("beta")]);
        let sampled = AtomicUsize::new(0);

        let error = fingerprint_selected_nodes(&mut backends, &selected, 2, |_, node| {
            sampled.fetch_add(1, Ordering::SeqCst);
            Err(BackendError::Rejected {
                message: format!("capture failed for `{}`", node.name),
            })
        })
        .err()
        .ok_or("both captures unexpectedly succeeded")?;

        assert!(matches!(
            error,
            BackendError::Rejected { message } if message == "capture failed for `alpha`"
        ));
        assert_eq!(sampled.load(Ordering::SeqCst), 2);
        assert_eq!(
            backends,
            BTreeMap::from([(node("alpha"), 11), (node("beta"), 13)])
        );
        Ok(())
    }

    #[test]
    fn fingerprint_collection_rejects_mismatched_identity_or_missing_result() {
        let mut backends = BTreeMap::from([(node("alpha"), 11)]);
        let selected = BTreeSet::from([node("alpha")]);
        assert!(matches!(
            fingerprint_selected_nodes(&mut backends, &selected, 1, |backend, _| {
                Ok(sample(backend, node("beta")))
            }),
            Err(BackendError::Rejected { message }) if message.contains("returned another node")
        ));

        let missing = BTreeSet::from([node("alpha"), node("beta")]);
        assert!(matches!(
            fingerprint_selected_nodes(&mut backends, &missing, 1, |backend, node| {
                Ok(sample(backend, node))
            }),
            Err(BackendError::Rejected { message }) if message.contains("cardinality changed")
        ));
    }

    #[test]
    fn panicking_fingerprint_worker_keeps_backend_owned() {
        let mut backends = BTreeMap::from([(node("alpha"), 11)]);
        let selected = BTreeSet::from([node("alpha")]);

        let result = fingerprint_selected_nodes(&mut backends, &selected, 1, |_, _| {
            panic!("scripted capture panic")
        });

        assert!(matches!(
            result,
            Err(BackendError::Rejected { message }) if message.contains("worker for `alpha` panicked")
        ));
        assert_eq!(backends[&node("alpha")], 11);
    }

    #[test]
    fn failed_fingerprint_capture_restores_nodes_for_next_sample(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut backends = BTreeMap::from([(node("alpha"), 11), (node("beta"), 13)]);
        let selected = BTreeSet::from([node("alpha"), node("beta")]);
        let first = fingerprint_selected_nodes(&mut backends, &selected, 2, |backend, node| {
            if node.name == "alpha" {
                return Err(BackendError::Rejected {
                    message: String::from("transient alpha sample failure"),
                });
            }
            Ok(sample(backend, node))
        });
        assert!(matches!(
            first,
            Err(BackendError::Rejected { message }) if message == "transient alpha sample failure"
        ));

        let retried = fingerprint_selected_nodes(&mut backends, &selected, 2, |backend, node| {
            Ok(sample(backend, node))
        })?;

        assert_eq!(retried.len(), 2);
        assert_eq!(retried[&node("alpha")].at.ticks, 11);
        assert_eq!(retried[&node("beta")].at.ticks, 13);
        Ok(())
    }
}
