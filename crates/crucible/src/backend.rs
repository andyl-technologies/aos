//! Backend boundary shared by the pure engine and concrete drivers.
//!
//! This module owns the trait and data contracts that backend adapters must
//! implement. Keeping it separate from the execution model prevents QEMU-shaped
//! concepts from leaking into the pure state vocabulary.

use crate::model::{FaultObjectId, FaultPhase};
use crate::{
    Checkpoint, ContentHash, Decision, Icount, NodeId, ObservableEvent, PreemptionDecision,
    VirtualTime,
};
use crucible_protocol::guest_introspection::GuestIntrospectionRecord;
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
    /// Application workload traffic must originate inside modeled guest VMs.
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

    /// Advances one scheduler-selected node toward `ceiling`.
    ///
    /// Single-node backends inherit the default implementation. Multi-node
    /// backends override this method so the scheduler's selected node, rather
    /// than an implicit backend-global node, owns the bounded advance.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when `node` is unknown or cannot advance to
    /// the requested ceiling.
    fn step_node_to(
        &mut self,
        node: &NodeId,
        ceiling: VirtualTime,
    ) -> Result<StepObservation, BackendError> {
        let _ = node;
        self.step_to(ceiling)
    }

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

    /// Drains guest-originated network frames produced by completed steps.
    ///
    /// The scheduler remains the routing and timing authority. Backends report
    /// only the source-local emission coordinate, destination identity, stable
    /// sequence, and payload; they do not select a link or delivery time.
    /// Backends without a guest network transport return an empty batch.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the output transport is corrupt or
    /// cannot be drained completely at the completed boundary.
    fn drain_network_outputs(&mut self) -> Result<Vec<BackendNetworkOutput>, BackendError> {
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

    /// Applies a backend effect to one scheduler-selected node.
    ///
    /// Single-node backends inherit the backend-global implementation.
    /// Multi-node backends override this method to route the effect to `node`.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when `node` is unknown or the effect cannot
    /// be applied at the supplied scheduler boundary.
    fn apply_to_node(
        &mut self,
        node: &NodeId,
        effect: &BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        let _ = node;
        self.apply(effect, at)
    }

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

    /// Returns one node's scheduler-mirrored virtual time.
    ///
    /// Single-node backends inherit [`SimulationBackend::now`].
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when `node` is unknown.
    fn node_now(&self, node: &NodeId) -> Result<VirtualTime, BackendError> {
        let _ = node;
        Ok(self.now())
    }

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

    /// Activates one node's dormant debug guest agent after a non-canonical fork.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when the node is unknown or its fixed
    /// fork-time activation transport is unavailable.
    fn activate_debug_guest(&mut self, node: &NodeId) -> Result<(), BackendError> {
        let _ = node;
        Err(BackendError::Unsupported {
            capability: "activate_debug_guest",
        })
    }

    /// Sends one out-of-band request to a node's debug guest agent.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when guest introspection is unsupported, the
    /// node is unknown, or the bounded request transport rejects the record.
    fn send_guest_introspection(
        &mut self,
        node: &NodeId,
        record: GuestIntrospectionRecord,
    ) -> Result<(), BackendError> {
        let _ = node;
        let _ = record;
        Err(BackendError::Unsupported {
            capability: "send_guest_introspection",
        })
    }

    /// Receives one currently available response from a node's debug guest agent.
    ///
    /// # Errors
    ///
    /// Returns a [`BackendError`] when guest introspection is unsupported, the
    /// node is unknown, or the bounded response transport is malformed.
    fn receive_guest_introspection(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<GuestIntrospectionRecord>, BackendError> {
        let _ = node;
        Err(BackendError::Unsupported {
            capability: "receive_guest_introspection",
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
    /// Scheduler-safe frontier established before returning control.
    ///
    /// This normally equals the backend's physical instruction count. A
    /// backend that parks earlier with a proven exact wake strictly beyond the
    /// requested ceiling may report the requested ceiling here while retaining
    /// the physical park point in [`AdvanceOutcome::Paused`].
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
    /// Apply an explorer-selected preemption during the next bounded RUN.
    Preemption(PreemptionDecision),
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

mod gdb;
mod io;
#[cfg(any(test, feature = "test-double"))]
mod mock;

use gdb::validate_gdb_endpoint;
pub use io::*;
#[cfg(any(test, feature = "test-double"))]
pub use mock::{MockSimulationBackend, MockSimulationBackendState};

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "backend/tests.rs"]
mod tests;
