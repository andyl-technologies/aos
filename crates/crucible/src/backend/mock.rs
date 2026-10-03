//! Test-double implementation of the session simulation backend.
//!
//! The module is compiled only for crate tests or when the explicit
//! `test-double` feature is enabled. Default production builds neither compile
//! nor export these types.

use super::*;
use crate::CheckpointKind;
use std::collections::BTreeMap;

/// In-memory backend used for state-machine tests of [`SimulationBackend`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockSimulationBackend {
    state: MockSimulationBackendState,
    snapshots: BTreeMap<ContentHash, MockSimulationBackendState>,
    dispatch_stops: BTreeMap<NodeId, crate::BackendRunDispatchBoundary>,
}

impl MockSimulationBackend {
    /// Builds an empty mock backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the mock state.
    #[must_use]
    pub const fn state(&self) -> &MockSimulationBackendState {
        &self.state
    }

    fn fingerprint_hash(&self, node: &NodeId) -> ContentHash {
        ContentHash::from_canonical_material(
            "crucible.mock-simulation-backend.fingerprint.v1",
            &format!(
                "node={}\nnow={}\ninputs={}\neffects={}\nshutdown={}\n",
                node.name,
                self.state.now.ticks,
                self.state.delivered_inputs.len(),
                self.state.applied_effects.len(),
                self.state.shutdown
            ),
        )
    }

    fn checkpoint(&self) -> Checkpoint {
        let mut checkpoint = Checkpoint::new(
            ContentHash::from_canonical_material(
                "crucible.mock-simulation-backend.checkpoint.v1",
                &format!(
                    "now={}\ninputs={}\neffects={}\nshutdown={}\n",
                    self.state.now.ticks,
                    self.state.delivered_inputs.len(),
                    self.state.applied_effects.len(),
                    self.state.shutdown
                ),
            ),
            self.fingerprint_hash(&NodeId {
                name: String::from("mock"),
            }),
            CheckpointKind::Fat,
        );
        checkpoint.virtual_time = self.state.now;
        checkpoint.node_icounts.insert(
            NodeId {
                name: String::from("mock"),
            },
            Icount {
                retired: self.state.now.ticks,
            },
        );
        checkpoint
    }
}

impl SimulationBackend for MockSimulationBackend {
    fn io_inventory_authority(&self) -> crate::BackendIoInventoryAuthority {
        crate::BackendIoInventoryAuthority::SchedulerOwnedModel
    }

    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        if self.state.shutdown {
            return Err(BackendError::Rejected {
                message: String::from("mock simulation backend is shut down; cannot advance"),
            });
        }
        if ceiling < self.state.now {
            return Err(BackendError::Rejected {
                message: format!(
                    "mock simulation backend cannot advance backwards from {} to {} ticks",
                    self.state.now.ticks, ceiling.ticks
                ),
            });
        }

        self.state.now = ceiling;
        Ok(StepObservation::from_advance_outcome(
            ceiling,
            AdvanceOutcome::ReachedHorizon,
        ))
    }

    fn node_now(&self, node: &NodeId) -> Result<VirtualTime, BackendError> {
        Ok(self.state.node_times.get(node).copied().unwrap_or_default())
    }

    fn step_node_to(
        &mut self,
        node: &NodeId,
        ceiling: VirtualTime,
    ) -> Result<StepObservation, BackendError> {
        self.state.now = self.node_now(node)?;
        let observation = self.step_to(ceiling)?;
        self.state
            .node_times
            .insert(node.clone(), observation.reached);
        Ok(observation)
    }

    fn step_node_with_admission(
        &mut self,
        admission: &crate::PreparedRunAdmission,
    ) -> Result<crate::BackendRunResult, BackendError> {
        let step = self.step_node_to(
            admission.node(),
            VirtualTime {
                ticks: admission.dispatch_horizon().icount.retired,
            },
        )?;
        if step.reached.ticks < admission.semantic_horizon().icount.retired {
            let boundary = crate::BackendRunDispatchBoundary {
                admission: admission.clone(),
                reached: crate::NodeCounter {
                    ticks: step.reached.ticks,
                },
            };
            self.dispatch_stops
                .insert(admission.node().clone(), boundary.clone());
            Ok(crate::BackendRunResult::DispatchBoundary(boundary))
        } else {
            Ok(crate::BackendRunResult::Completed(step))
        }
    }

    fn apply_to_node(
        &mut self,
        node: &NodeId,
        effect: &BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        self.state.now = self.node_now(node)?;
        self.apply(effect, at)
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        if at != self.state.now {
            return Err(BackendError::Rejected {
                message: format!(
                    "mock simulation backend effect at {} does not match scheduler time {}",
                    at.ticks, self.state.now.ticks
                ),
            });
        }

        match effect {
            BackendEffect::Noop => {}
            BackendEffect::DeliverInput(input) => self.state.delivered_inputs.push(input.clone()),
            BackendEffect::Preemption(_) => {}
            BackendEffect::Shutdown => self.state.shutdown = true,
        }
        self.state.applied_effects.push(effect.clone());
        Ok(())
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        if !self.dispatch_stops.is_empty() {
            return Err(BackendError::Rejected {
                message: String::from("model snapshot has an unresolved internal stop"),
            });
        }
        let checkpoint = self.checkpoint();
        self.snapshots.insert(checkpoint.id, self.state.clone());
        Ok(BackendSnapshot::new(checkpoint))
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        if !self.dispatch_stops.is_empty() {
            return Err(BackendError::Rejected {
                message: String::from("model restore has an unresolved internal stop"),
            });
        }
        let Some(state) = self.snapshots.get(&snapshot.checkpoint.id) else {
            return Err(BackendError::Rejected {
                message: String::from("mock simulation backend cannot restore unknown snapshot"),
            });
        };
        self.state = state.clone();
        Ok(())
    }

    fn now(&self) -> VirtualTime {
        self.state.now
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        Ok(FingerprintSample {
            fingerprint: ExecutionFingerprint {
                hash: self.fingerprint_hash(&node),
            },
            node,
            at: self.state.now,
        })
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, BackendError> {
        let _ = node;
        let _ = listen;
        Err(BackendError::Unsupported {
            capability: "open_gdbstub",
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.state.shutdown = true;
        Ok(())
    }

    fn stage_dispatch_boundary_effect(
        &mut self,
        boundary: &crate::BackendRunDispatchBoundary,
        key: &crate::ScheduledEventKey,
        effect: &BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        if self.dispatch_stops.get(boundary.admission.node()) != Some(boundary)
            || at.ticks != boundary.reached.ticks
        {
            return Err(BackendError::Rejected {
                message: String::from("model input changed its retained internal stop"),
            });
        }
        boundary
            .admission
            .validate_input_delivery_coordinate(key, crate::NodeCounter { ticks: at.ticks })?;
        self.apply_to_node(boundary.admission.node(), effect, at)
    }
}

/// State retained by [`MockSimulationBackend`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockSimulationBackendState {
    /// Scheduler-mirrored virtual time.
    pub now: VirtualTime,
    /// Physical counters retained independently for each modeled node.
    pub node_times: BTreeMap<NodeId, VirtualTime>,
    /// Inputs delivered through admitted backend effects.
    pub delivered_inputs: Vec<BackendInput>,
    /// Boundary effects observed by the backend.
    pub applied_effects: Vec<BackendEffect>,
    /// Whether shutdown was requested.
    pub shutdown: bool,
}

impl crate::ConcurrentSimulationBackend for MockSimulationBackend {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<crate::ConcurrentBackendRun>,
        _max_host_workers: usize,
    ) -> Result<Vec<crate::ConcurrentBackendRunResult>, BackendError> {
        runs.into_iter()
            .map(|run| {
                let node = run.node().clone();
                for command in &run.preemptions {
                    self.apply_to_node(
                        &node,
                        &BackendEffect::Preemption(command.clone()),
                        self.node_now(&node)?,
                    )?;
                }
                let mut step = match self.step_node_with_admission(&run.admission)? {
                    crate::BackendRunResult::Completed(step) => step,
                    crate::BackendRunResult::DispatchBoundary(boundary) => {
                        return Ok(crate::ConcurrentBackendRunResult::DispatchBoundary(
                            boundary,
                        ));
                    }
                    _ => {
                        return Err(BackendError::Rejected {
                            message: String::from("model backend cannot retain this physical stop"),
                        });
                    }
                };
                step.applied_preemptions = run.preemptions;
                Ok(crate::ConcurrentBackendRunResult::Completed(
                    crate::ConcurrentBackendRunOutcome {
                        node,
                        step,
                        rng_evidence: self.drain_rng_evidence()?,
                        network_outputs: self.drain_network_outputs()?,
                        observations: self.drain_observable_events()?,
                    },
                ))
            })
            .collect()
    }

    fn resume_dispatch_boundary(
        &mut self,
        run: crate::ConcurrentBackendRun,
        boundary: &crate::BackendRunDispatchBoundary,
    ) -> Result<crate::ConcurrentBackendRunResult, BackendError> {
        if self.dispatch_stops.get(run.node()) != Some(boundary)
            || run.admission.context() != boundary.admission.context()
            || run.admission.control_token() != boundary.admission.control_token()
            || run.admission.input_inventory().generation()
                <= boundary.admission.input_inventory().generation()
            || self.node_now(run.node())?.ticks != boundary.reached.ticks
        {
            return Err(BackendError::Rejected {
                message: String::from("model dispatch continuation changed its retained RUN"),
            });
        }

        self.dispatch_stops.remove(run.node());
        let mut results = self.execute_concurrent_runs(vec![run], 1)?;
        Ok(results.remove(0))
    }
}
