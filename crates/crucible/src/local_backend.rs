//! Deterministic local backend implementation.

use std::collections::BTreeMap;

use crucible_sim::StableHasher;

use crate::{
    AdvanceOutcome, Backend, BackendEffect, BackendError, BackendInput, BackendSnapshot,
    Checkpoint, CheckpointKind, ContentHash, ExecutionFingerprint, ExecutionHorizon,
    FingerprintSample, Icount, NodeBlobRef, NodeId, SimulationBackend, StepObservation,
    VirtualTime,
};

/// A deterministic in-process backend implementing [`Backend`].
///
/// `SimBackend` models the minimum backend behavior needed by engine tests: it
/// advances an instruction counter, records delivered inputs, produces stable
/// fingerprints, snapshots its small state, restores snapshots captured by the
/// same backend instance, and shuts down deterministically.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimBackend {
    state: SimBackendState,
    snapshots: BTreeMap<ContentHash, SimBackendState>,
}

impl SimBackend {
    /// Builds a backend at instruction count zero with no delivered inputs.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a backend from an explicit state.
    #[must_use]
    pub fn from_state(state: SimBackendState) -> Self {
        Self {
            state,
            snapshots: BTreeMap::new(),
        }
    }

    /// Builds a backend that can restore `checkpoint` as a known snapshot.
    ///
    /// The resulting backend mirrors the checkpoint's highest recorded node
    /// instruction count as its deterministic state. This is intended for
    /// model-backed realization paths that need to replay from an existing
    /// checkpoint without depending on a concrete VM process.
    #[must_use]
    pub fn from_restorable_checkpoint(checkpoint: &Checkpoint) -> Self {
        Self::from_restorable_checkpoints(std::slice::from_ref(checkpoint))
    }

    /// Builds a backend that can restore each checkpoint in `checkpoints`.
    ///
    /// Unknown checkpoints still fail through [`Backend::restore`]. This
    /// constructor only declares the supplied checkpoints as known deterministic
    /// model snapshots.
    #[must_use]
    pub fn from_restorable_checkpoints(checkpoints: &[Checkpoint]) -> Self {
        let mut snapshots = BTreeMap::new();
        for checkpoint in checkpoints {
            snapshots.insert(checkpoint.id, SimBackendState::from_checkpoint(checkpoint));
        }
        let state = checkpoints
            .last()
            .map(SimBackendState::from_checkpoint)
            .unwrap_or_default();
        Self { state, snapshots }
    }

    /// Returns the current deterministic backend state.
    #[must_use]
    pub fn state(&self) -> &SimBackendState {
        &self.state
    }

    /// Consumes the backend and returns the current deterministic state.
    #[must_use]
    pub fn into_state(self) -> SimBackendState {
        self.state
    }

    fn reject_if_shutdown(&self, operation: &'static str) -> Result<(), BackendError> {
        if self.state.shutdown {
            Err(BackendError::Rejected {
                message: format!("sim backend is shut down; cannot {operation}"),
            })
        } else {
            Ok(())
        }
    }
}

impl Backend for SimBackend {
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError> {
        self.reject_if_shutdown("advance")?;
        if horizon.icount < self.state.icount {
            return Err(BackendError::Rejected {
                message: format!(
                    "sim backend cannot advance backwards from {} to {} retired instructions",
                    self.state.icount.retired, horizon.icount.retired
                ),
            });
        }

        self.state.icount = horizon.icount;
        Ok(AdvanceOutcome::ReachedHorizon)
    }

    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
        Ok(ExecutionFingerprint {
            hash: self.state.fingerprint(),
        })
    }

    fn deliver_input(&mut self, input: BackendInput) -> Result<(), BackendError> {
        self.reject_if_shutdown("deliver input")?;
        self.state.delivered_inputs.push(input);
        Ok(())
    }

    fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
        let mut checkpoint = Checkpoint::with_node_blobs(
            self.state.checkpoint_id(),
            self.state.fingerprint(),
            CheckpointKind::Fat,
            self.state.node_blobs(),
        );
        checkpoint.virtual_time = VirtualTime {
            ticks: self.state.icount.retired,
        };
        checkpoint.node_icounts.insert(
            NodeId {
                name: String::from("sim"),
            },
            self.state.icount,
        );
        self.snapshots.insert(checkpoint.id, self.state.clone());
        Ok(checkpoint)
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<(), BackendError> {
        let Some(state) = self.snapshots.get(&checkpoint.id) else {
            return Err(BackendError::Rejected {
                message: String::from("sim backend cannot restore unknown checkpoint"),
            });
        };
        self.state = state.clone();
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.state.shutdown = true;
        Ok(())
    }
}

impl SimulationBackend for SimBackend {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        let outcome = self.advance_to_horizon(ExecutionHorizon {
            icount: Icount {
                retired: ceiling.ticks,
            },
        })?;
        Ok(StepObservation::from_advance_outcome(ceiling, outcome))
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        let now = self.now();
        if at != now {
            return Err(BackendError::Rejected {
                message: format!(
                    "sim backend effect at {} does not match scheduler time {}",
                    at.ticks, now.ticks
                ),
            });
        }
        match effect {
            BackendEffect::Noop => Ok(()),
            BackendEffect::DeliverInput(input) => self.deliver_input(input.clone()),
            BackendEffect::Preemption(_) => Ok(()),
            BackendEffect::Shutdown => Backend::shutdown(self),
        }
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        Backend::snapshot(self).map(BackendSnapshot::new)
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        Backend::restore(self, &snapshot.checkpoint)
    }

    fn now(&self) -> VirtualTime {
        VirtualTime {
            ticks: self.state.icount.retired,
        }
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        Ok(FingerprintSample {
            node,
            at: self.now(),
            fingerprint: Backend::fingerprint(self)?,
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        Backend::shutdown(self)
    }
}

/// The small deterministic state tracked by [`SimBackend`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimBackendState {
    /// The current retired-instruction count.
    pub icount: Icount,
    /// Deterministic inputs delivered to the backend.
    pub delivered_inputs: Vec<BackendInput>,
    /// Whether the backend has been shut down.
    pub shutdown: bool,
}

impl SimBackendState {
    fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        let icount = checkpoint
            .node_icounts
            .values()
            .copied()
            .max()
            .unwrap_or(Icount {
                retired: checkpoint.virtual_time.ticks,
            });
        Self {
            icount,
            delivered_inputs: Vec::new(),
            shutdown: false,
        }
    }

    /// Computes a deterministic fingerprint for this state.
    #[must_use]
    pub fn fingerprint(&self) -> ContentHash {
        let mut hasher = StableHasher::new();
        hasher.write_tag("crucible.sim-backend.state");
        hasher.write_u64(self.icount.retired);
        hasher.write_bool(self.shutdown);
        hasher.write_u64(self.delivered_inputs.len() as u64);
        for input in &self.delivered_inputs {
            hasher.write_tag("input");
            hasher.write_bytes(input.node.name.as_bytes());
            hasher.write_bytes(&input.payload);
        }
        ContentHash {
            bytes: hasher.finish().bytes,
        }
    }

    fn checkpoint_id(&self) -> ContentHash {
        let fingerprint = self.fingerprint();
        let mut hasher = StableHasher::new();
        hasher.write_tag("crucible.sim-backend.checkpoint");
        hasher.write_bytes(&fingerprint.bytes);
        ContentHash {
            bytes: hasher.finish().bytes,
        }
    }

    fn node_blobs(&self) -> BTreeMap<NodeId, NodeBlobRef> {
        let parent = ContentHash::from_canonical_material("crucible.sim-backend.node-blob", "root");
        let resolved = self.fingerprint();
        let delta = ContentHash::from_canonical_material(
            "crucible.sim-backend.node-blob.delta",
            &format!(
                "icount={}\ninputs={}\nshutdown={}",
                self.icount.retired,
                self.delivered_inputs.len(),
                self.shutdown
            ),
        );
        BTreeMap::from([(
            NodeId {
                name: String::from("sim"),
            },
            NodeBlobRef::cow_delta(parent, delta, resolved),
        )])
    }
}
