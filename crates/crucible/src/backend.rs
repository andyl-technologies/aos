//! Backend boundary shared by the pure engine and concrete drivers.
//!
//! This module owns the trait and data contracts that backend adapters must
//! implement. Keeping it separate from the execution model prevents QEMU-shaped
//! concepts from leaking into the pure state vocabulary.

use std::collections::BTreeMap;

use crate::{
    Checkpoint, CheckpointKind, ContentHash, Decision, Icount, NodeId, ObservableEvent, VirtualTime,
};
mod error;
pub use error::BackendError;

/// A VM backend boundary declared by the engine.
pub trait Backend {
    /// Advances the backend to `horizon`.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the backend cannot advance to the
    /// requested horizon.
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError>;

    /// Reads the backend's current execution fingerprint.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the fingerprint cannot be read.
    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError>;

    /// Delivers deterministic input to the backend.
    ///
    /// This is a backend delivery surface for already-scheduled model events and
    /// guest-host channel replies. It is not a host-side workload generator and
    /// MUST NOT be used to originate application traffic for a scenario.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the input cannot be delivered.
    fn deliver_input(&mut self, input: BackendInput) -> Result<(), BackendError>;

    /// Captures a backend checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when snapshot capture fails.
    fn snapshot(&mut self) -> Result<Checkpoint, BackendError>;

    /// Restores a backend checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the checkpoint cannot be restored.
    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<(), BackendError>;

    /// Shuts the backend down.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when shutdown fails.
    fn shutdown(&mut self) -> Result<(), BackendError>;
}

/// Pluggable session backend boundary used by the control plane.
///
/// `SimulationBackend` is the L4-facing backend contract from RFC-0010 §20.10.
/// The scheduler remains the only source of timing authority: callers pass a
/// virtual-time ceiling to [`SimulationBackend::step_to`], and implementations
/// report what they observed while advancing toward that ceiling. They do not
/// choose cross-node order, evaluate assertions, or derive their own host-time
/// schedule.
///
/// Backend objects are owned by the session actor that drives them. The trait
/// intentionally does not require [`Send`] because concrete QEMU adapters may
/// wrap thread-affine channel and process-runtime handles.
pub trait SimulationBackend {
    /// Advances backend nodes toward `ceiling`.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when a node, transport, or backend adapter
    /// cannot advance to the requested ceiling.
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError>;

    /// Drains observations produced by the last completed backend step.
    ///
    /// Live adapters use a bounded transport whose consumer is read only after
    /// the step publishes its completion boundary. Backends without an
    /// observational transport return an empty batch. Callers must append every
    /// returned event to the scheduler's unified event log before another step.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the observational transport is corrupt,
    /// exceeds the completed boundary, or cannot be drained completely.
    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, BackendError> {
        Ok(Vec::new())
    }

    /// Drains causal decisions produced by synchronous backend callbacks.
    ///
    /// The authoritative scheduler validates and appends these decisions before
    /// it admits observational events or begins another step. Backends without
    /// a causal callback transport return an empty batch.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the causal transport is corrupt or
    /// cannot be drained completely at the completed boundary.
    fn drain_causal_decisions(&mut self) -> Result<Vec<Decision>, BackendError> {
        Ok(Vec::new())
    }

    /// Applies a backend-level effect at a scheduler boundary.
    ///
    /// `at` is scheduler-supplied virtual time. Implementations may mirror it
    /// for diagnostics, but must not use host wall-clock time to schedule the
    /// effect.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the effect cannot be applied.
    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError>;

    /// Captures the backend-owned node state.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when backend state cannot be captured.
    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError>;

    /// Restores backend-owned node state from `snapshot`.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when `snapshot` is unknown or cannot be
    /// restored by this backend.
    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError>;

    /// Returns the backend's scheduler-mirrored virtual time.
    ///
    /// This value is an observation of the last scheduler-authorized advance,
    /// not an independent time source.
    fn now(&self) -> VirtualTime;

    /// Samples a deterministic execution fingerprint for `node`.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the fingerprint cannot be read.
    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError>;

    /// Opens the optional out-of-band debugger gdbstub channel for `node`.
    ///
    /// This capability is intentionally optional. Backends without a real
    /// mediated gdbstub must return [`BackendError::Unsupported`] rather than
    /// faking a debugger endpoint.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the backend does not support gdbstub
    /// attachment, the requested listener cannot be honored, or the attach
    /// channel cannot be opened.
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

    /// Shuts all backend nodes down.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when shutdown fails.
    fn shutdown(&mut self) -> Result<(), BackendError>;
}

/// A horizon to which a backend should advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionHorizon {
    /// The target instruction count.
    pub icount: Icount,
}

/// The result of advancing a backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdvanceOutcome {
    /// The backend advanced to the requested horizon.
    ReachedHorizon,
    /// The backend paused before reaching the requested horizon.
    Paused {
        /// The instruction count at which the backend paused.
        at: Icount,
    },
}

/// A backend execution fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExecutionFingerprint {
    /// The fingerprint content address.
    pub hash: ContentHash,
}

/// Observation returned by [`SimulationBackend::step_to`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepObservation {
    /// Scheduler-supplied ceiling requested by the control plane.
    pub requested_ceiling: VirtualTime,
    /// Virtual time the backend reached before returning control.
    pub reached: VirtualTime,
    /// Low-level backend advancement result.
    pub outcome: AdvanceOutcome,
}

impl StepObservation {
    /// Builds an observation from a requested ceiling and low-level outcome.
    #[must_use]
    pub const fn from_advance_outcome(ceiling: VirtualTime, outcome: AdvanceOutcome) -> Self {
        let reached = match outcome {
            AdvanceOutcome::ReachedHorizon => ceiling,
            AdvanceOutcome::Paused { at } => VirtualTime { ticks: at.retired },
        };
        Self {
            requested_ceiling: ceiling,
            reached,
            outcome,
        }
    }
}

/// Backend-level effect admitted at a scheduler boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BackendEffect {
    /// No backend mutation is needed for this boundary.
    Noop,
    /// Deliver deterministic input that the scheduler has already admitted.
    DeliverInput(BackendInput),
    /// Shut all backend nodes down as part of a terminal stop.
    Shutdown,
}

/// Content-addressed backend snapshot captured for a fat checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BackendSnapshot {
    /// Backend-owned node-state checkpoint.
    pub checkpoint: Checkpoint,
}

impl BackendSnapshot {
    /// Wraps an existing backend checkpoint.
    #[must_use]
    pub const fn new(checkpoint: Checkpoint) -> Self {
        Self { checkpoint }
    }
}

/// Deterministic execution fingerprint sample for one node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FingerprintSample {
    /// Node whose fingerprint was sampled.
    pub node: NodeId,
    /// Scheduler-mirrored virtual time at which the sample was read.
    pub at: VirtualTime,
    /// Backend execution fingerprint.
    pub fingerprint: ExecutionFingerprint,
}

/// Operator-facing gdb-protocol listen endpoint requested by a debug attach.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GdbListen {
    endpoint: String,
}

impl GdbListen {
    /// Builds a stable debugger listen endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Rejected`] when `endpoint` is empty or contains
    /// newline or NUL bytes.
    pub fn new(endpoint: impl Into<String>) -> Result<Self, BackendError> {
        let endpoint = endpoint.into();
        validate_gdb_endpoint("gdb_listen", &endpoint)?;
        Ok(Self { endpoint })
    }

    /// Returns the endpoint text supplied to the backend.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.endpoint
    }
}

/// Report returned after a backend exposes a mediated gdbstub channel.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GdbAttachInfo {
    /// Node whose gdbstub is exposed.
    pub node: NodeId,
    /// Backend-owned raw gdbstub endpoint.
    pub qemu_endpoint: String,
    /// Operator-facing listener served by Crucible.
    pub operator_listen: GdbListen,
    /// Whether Crucible mediates the raw backend gdbstub.
    pub mediated_by_crucible: bool,
    /// Whether the gdbstub channel is outside scheduler delivery order.
    pub out_of_band: bool,
    /// Whether debugger traffic carries per-quantum timing data.
    pub carries_per_quantum_timing: bool,
    /// Whether debugger traffic carries guest frame data.
    pub carries_frame_data: bool,
}

impl GdbAttachInfo {
    /// Builds a report for a mediated out-of-band gdbstub attach.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Rejected`] when `qemu_endpoint` is not stable
    /// endpoint text.
    pub fn new(
        node: NodeId,
        qemu_endpoint: impl Into<String>,
        operator_listen: GdbListen,
    ) -> Result<Self, BackendError> {
        let qemu_endpoint = qemu_endpoint.into();
        validate_gdb_endpoint("qemu_gdbstub", &qemu_endpoint)?;
        Ok(Self {
            node,
            qemu_endpoint,
            operator_listen,
            mediated_by_crucible: true,
            out_of_band: true,
            carries_per_quantum_timing: false,
            carries_frame_data: false,
        })
    }

    /// Returns whether the channel is a read-only out-of-band debug proxy.
    #[must_use]
    pub const fn is_out_of_band_debug_proxy(&self) -> bool {
        self.mediated_by_crucible
            && self.out_of_band
            && !self.carries_per_quantum_timing
            && !self.carries_frame_data
    }
}

/// Deterministic input delivered to a backend.
///
/// This payload represents backend delivery for model-controlled inputs, not a
/// host-side workload generator. Application workload traffic must originate
/// from guest execution and cross modeled devices as ordinary guest/device I/O.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BackendInput {
    /// The target node.
    pub node: NodeId,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

fn validate_gdb_endpoint(field: &'static str, value: &str) -> Result<(), BackendError> {
    if value.is_empty() || value.chars().any(|ch| matches!(ch, '\n' | '\0')) {
        return Err(BackendError::Rejected {
            message: format!("{field} endpoint is invalid"),
        });
    }
    Ok(())
}

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

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn simulation_backend_trait_is_object_safe_and_scheduler_timed() {
        let mut backend: Box<dyn SimulationBackend> = Box::new(MockSimulationBackend::new());
        let ceiling = VirtualTime { ticks: 11 };

        let observation = match backend.step_to(ceiling) {
            Ok(observation) => observation,
            Err(error) => panic!("mock backend should advance: {error}"),
        };

        assert_eq!(observation.requested_ceiling, ceiling);
        assert_eq!(observation.reached, ceiling);
        assert_eq!(backend.now(), ceiling);

        let input = BackendInput {
            node: NodeId {
                name: String::from("node-a"),
            },
            payload: vec![1, 2, 3],
        };
        if let Err(error) = backend.apply(&BackendEffect::DeliverInput(input), ceiling) {
            panic!("mock backend should apply scheduler-timed input: {error}");
        }
        let sample = match backend.fingerprint(NodeId {
            name: String::from("node-a"),
        }) {
            Ok(sample) => sample,
            Err(error) => panic!("mock backend should fingerprint: {error}"),
        };
        assert_eq!(sample.at, ceiling);

        let snapshot = match backend.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("mock backend should snapshot: {error}"),
        };
        if let Err(error) = backend.step_to(VirtualTime { ticks: 19 }) {
            panic!("mock backend should advance after snapshot: {error}");
        }
        assert_eq!(backend.now(), VirtualTime { ticks: 19 });
        if let Err(error) = backend.restore(&snapshot) {
            panic!("mock backend should restore known snapshot: {error}");
        }
        assert_eq!(backend.now(), ceiling);
    }

    #[test]
    fn mock_simulation_backend_rejects_backend_owned_time_regression() {
        let mut backend = MockSimulationBackend::new();
        if let Err(error) = backend.step_to(VirtualTime { ticks: 7 }) {
            panic!("mock backend should advance: {error}");
        }

        let error = backend
            .step_to(VirtualTime { ticks: 6 })
            .expect_err("backend must not choose backwards time");

        assert!(error.to_string().contains("cannot advance backwards"));
        assert_eq!(backend.now(), VirtualTime { ticks: 7 });
    }

    #[test]
    fn mock_simulation_backend_rejects_gdbstub_capability_with_typed_error() {
        let mut backend = MockSimulationBackend::new();
        let listen = match GdbListen::new("127.0.0.1:9000") {
            Ok(listen) => listen,
            Err(error) => panic!("test listen endpoint should be valid: {error}"),
        };
        let error = backend
            .open_gdbstub(
                NodeId {
                    name: String::from("node-a"),
                },
                listen,
            )
            .expect_err("mock backend must not fake a gdbstub");

        assert_eq!(
            error,
            BackendError::Unsupported {
                capability: "open_gdbstub",
            }
        );
    }
}
