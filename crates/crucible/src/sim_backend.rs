//! In-process deterministic backend for engine and harness tests.

use std::collections::BTreeMap;

use crucible_sim::StableHasher;

use crate::{
    AdvanceOutcome, Backend, BackendError, BackendInput, Checkpoint, CheckpointKind, ContentHash,
    ExecutionFingerprint, ExecutionHorizon, Icount, NodeBlobRef, NodeId,
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
        let checkpoint = Checkpoint::with_node_blobs(
            self.state.checkpoint_id(),
            self.state.fingerprint(),
            CheckpointKind::Fat,
            self.state.node_blobs(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeId;

    #[test]
    fn sim_backend_advances_and_fingerprints_deterministically() {
        let mut first = SimBackend::new();
        let mut second = SimBackend::new();
        let input = BackendInput {
            node: NodeId {
                name: String::from("node-a"),
            },
            payload: b"hello".to_vec(),
        };

        assert_eq!(first.deliver_input(input.clone()), Ok(()));
        assert_eq!(second.deliver_input(input), Ok(()));
        assert_eq!(
            first.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 25 },
            }),
            Ok(AdvanceOutcome::ReachedHorizon)
        );
        assert_eq!(
            second.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 25 },
            }),
            Ok(AdvanceOutcome::ReachedHorizon)
        );

        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn sim_backend_snapshots_and_restores_small_state() {
        let mut backend = SimBackend::new();
        assert_eq!(
            backend.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 7 },
            }),
            Ok(AdvanceOutcome::ReachedHorizon)
        );
        let checkpoint = match backend.snapshot() {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("snapshot should succeed: {error}"),
        };
        assert!(matches!(
            checkpoint.node_blob(&NodeId {
                name: String::from("sim"),
            }),
            Some(NodeBlobRef::CowDelta { .. })
        ));
        assert_eq!(
            backend.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 9 },
            }),
            Ok(AdvanceOutcome::ReachedHorizon)
        );

        assert_eq!(backend.restore(&checkpoint), Ok(()));

        assert_eq!(backend.state().icount, Icount { retired: 7 });
    }

    #[test]
    fn sim_backend_rejects_backward_advance_and_post_shutdown_mutation() {
        let mut backend = SimBackend::from_state(SimBackendState {
            icount: Icount { retired: 9 },
            delivered_inputs: Vec::new(),
            shutdown: false,
        });

        assert!(matches!(
            backend.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 8 },
            }),
            Err(BackendError::Rejected { .. })
        ));
        assert_eq!(backend.shutdown(), Ok(()));
        assert!(matches!(
            backend.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 10 },
            }),
            Err(BackendError::Rejected { message }) if message == "sim backend is shut down; cannot advance"
        ));
        assert!(matches!(
            backend.deliver_input(BackendInput {
                node: NodeId {
                    name: String::from("node-a"),
                },
                payload: Vec::new(),
            }),
            Err(BackendError::Rejected { .. })
        ));
    }

    #[test]
    fn sim_backend_rejects_unknown_checkpoint_deterministically() {
        let mut backend = SimBackend::new();
        let unknown = Checkpoint::new(
            ContentHash { bytes: [7; 32] },
            ContentHash::default(),
            CheckpointKind::Fat,
        );

        assert!(matches!(
            backend.restore(&unknown),
            Err(BackendError::Rejected { message }) if message == "sim backend cannot restore unknown checkpoint"
        ));
    }
}
