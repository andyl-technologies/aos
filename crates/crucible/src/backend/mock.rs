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
        let checkpoint = self.checkpoint();
        self.snapshots.insert(checkpoint.id, self.state.clone());
        Ok(BackendSnapshot::new(checkpoint))
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
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
}

/// State retained by [`MockSimulationBackend`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockSimulationBackendState {
    /// Scheduler-mirrored virtual time.
    pub now: VirtualTime,
    /// Inputs delivered through admitted backend effects.
    pub delivered_inputs: Vec<BackendInput>,
    /// Boundary effects observed by the backend.
    pub applied_effects: Vec<BackendEffect>,
    /// Whether shutdown was requested.
    pub shutdown: bool,
}
