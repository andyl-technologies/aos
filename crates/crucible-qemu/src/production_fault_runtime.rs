//! Owning production runtime for signal-driven host and QEMU faults.
//!
//! This module keeps the evaluator continuation, canonical adapter ledger,
//! host device state, and live-QEMU transaction routing behind one checkpoint
//! surface. An empty plan has no hidden evaluator and remains a valid inert
//! production configuration.

use std::collections::BTreeMap;
use std::sync::Arc;

use crucible::model::{
    BindingActionKind, BindingEvaluation, BindingSearchChoice, ContentHash, EffectSpecification,
    FaultAdapterManifests, FaultCoordinate, FaultExecutionError, FaultObservation,
    FaultObservationKind, FaultOpportunity, FaultReplayMode, FaultResourceLimitError,
    FaultResourceLimits, FaultRuntimeCheckpoint, FaultSignalPlan, HostFaultActionSink,
    HostFaultActionState, HostFaultAdapterManifests, NodeBootPolicy, NodeEffectSpecification,
    NodeHangScope, NodeLifecycleTransition, NodeStatePolicy, NodeWatchdogPolicy,
    OwnedFaultExecutionRuntime, ReferencedSignalEvent, ResolvedBindingAction, ResolvedEffectTrace,
    ResolvedFaultTarget, SearchChoiceId, SearchOverride, SignalArtifactProvider,
    SignalBoundarySnapshot,
};
use crucible::{BackendError, BackendNetworkOutput, NodeId, SchedulerNetworkCheckpoint};
use crucible_shmem::{
    DequeuedFaultEvent, FaultClockEvidenceV1, FaultEventOutcomeV1, FaultExceptionEvidenceV1,
    FaultInstructionEvidenceV1, FaultRegisterMutationEvidenceV1, FaultTerminalEvidenceV1,
    MemoryMutationEvidenceV1,
};
use sha2::{Digest as _, Sha256};

use crate::checkpoint::bounded_cbor::{BoundedMap, BoundedSet};
use crate::fault_action_sink::CommittedQemuActionEvidence;
use crate::{ProductionFaultActionSink, QemuNodeError, QemuNodeSet};

const MAX_QEMU_CHECKPOINT_NODES: u64 = 16_384;
const MAX_QEMU_CHECKPOINT_ACTIONS: u64 = 1_073_741_824;

type QemuNodeMap<V> = BoundedMap<NodeId, V, MAX_QEMU_CHECKPOINT_NODES>;
type QemuActionMap<V> = BoundedMap<ContentHash, V, MAX_QEMU_CHECKPOINT_ACTIONS>;
type QemuActionSet = BoundedSet<ContentHash, MAX_QEMU_CHECKPOINT_ACTIONS>;
type PendingQemuEventMap = QemuNodeMap<Vec<DequeuedFaultEvent>>;

mod checkpoint_codec;
pub use checkpoint_codec::ProductionFaultRuntimeCheckpointCodecError;
mod fallible_clone;
use fallible_clone::{
    try_clone_action, try_clone_fault_events, try_clone_fault_id,
    try_clone_node_id as try_clone_ledger_node_id, try_clone_string, try_clone_target,
};

/// Complete resumable state for the production fault runtime.
#[derive(Debug)]
pub struct ProductionFaultRuntimeCheckpoint {
    /// Signal evaluator, binding, canonical adapter, replay, and search state.
    runtime: Option<FaultRuntimeCheckpoint>,
    /// Committed host network and storage adapter state.
    host: HostFaultActionState,
    /// Execution fingerprints of the exact QEMU snapshots paired with this state.
    qemu_fingerprints: QemuNodeMap<ContentHash>,
    /// Per-node fault-command continuation paired with the QEMU snapshots.
    qemu_fault_sequences: QemuNodeMap<u64>,
    /// Per-node fault-event continuation paired with the QEMU snapshots.
    qemu_fault_event_sequences: QemuNodeMap<u64>,
    /// Issued QEMU actions needed to authenticate asynchronous occurrence events.
    qemu_issued_actions: QemuActionMap<ResolvedBindingAction>,
    /// Authenticated APPLY results that bind occurrences to exact commands.
    qemu_action_commits: QemuActionMap<CommittedQemuActionEvidence>,
    /// Issued persistent rules that remain installed in QEMU.
    qemu_active_rule_ids: QemuActionSet,
    /// Scheduler-owned network queues, pending outputs, and transition ledger.
    network_state: Option<ProductionNetworkStateCheckpoint>,
    /// Referenced event occurrences retained for device recovery subscriptions.
    emitted_events: Vec<ReferencedSignalEvent>,
    /// Drained QEMU occurrences awaiting a successfully committed boundary.
    pending_qemu_observations: Vec<FaultObservation>,
    /// Raw drained QEMU events retained until validation succeeds atomically.
    pending_qemu_events: PendingQemuEventMap,
    /// Aggregate identity binding every continuation component to the plan.
    identity: ContentHash,
}

/// Complete host/scheduler network continuation paired with QEMU snapshots.
#[derive(Clone, Debug)]
pub struct ProductionNetworkStateCheckpoint {
    identity: ContentHash,
    scheduler: SchedulerNetworkCheckpoint,
    committed_frontier: crucible::VirtualTime,
    pending_outputs: Vec<BackendNetworkOutput>,
    adapter_state: Vec<u8>,
}

impl ProductionNetworkStateCheckpoint {
    /// Creates a network continuation with its independently recomputable identity.
    #[must_use]
    pub fn new(
        identity: ContentHash,
        scheduler: SchedulerNetworkCheckpoint,
        committed_frontier: crucible::VirtualTime,
        pending_outputs: Vec<BackendNetworkOutput>,
        adapter_state: Vec<u8>,
    ) -> Self {
        Self {
            identity,
            scheduler,
            committed_frontier,
            pending_outputs,
            adapter_state,
        }
    }

    /// Returns the expected identity of the complete network continuation.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.identity
    }

    /// Consumes the checkpoint into scheduler, pending-frame, and adapter state.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        SchedulerNetworkCheckpoint,
        crucible::VirtualTime,
        Vec<BackendNetworkOutput>,
        Vec<u8>,
        ContentHash,
    ) {
        (
            self.scheduler,
            self.committed_frontier,
            self.pending_outputs,
            self.adapter_state,
            self.identity,
        )
    }
}

impl ProductionFaultRuntimeCheckpoint {
    /// Returns the aggregate content identity of this continuation.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.identity
    }

    /// Returns the scheduler and adapter continuation paired with this checkpoint.
    #[must_use]
    pub const fn network_state(&self) -> Option<&ProductionNetworkStateCheckpoint> {
        self.network_state.as_ref()
    }

    /// Returns the captured execution fingerprint for one QEMU node.
    #[must_use]
    pub fn qemu_fingerprint(&self, node: &NodeId) -> Option<ContentHash> {
        self.qemu_fingerprints.get(node).copied()
    }

    /// Returns the next fault-command sequence captured for one QEMU node.
    #[must_use]
    pub fn qemu_fault_sequence(&self, node: &NodeId) -> Option<u64> {
        self.qemu_fault_sequences.get(node).copied()
    }

    /// Returns the next required QEMU fault-event sequence for one node.
    #[must_use]
    pub fn qemu_fault_event_sequence(&self, node: &NodeId) -> Option<u64> {
        self.qemu_fault_event_sequences.get(node).copied()
    }
}

/// Failure to admit, execute, checkpoint, or restore the production runtime.
#[derive(Debug, thiserror::Error)]
pub enum ProductionFaultRuntimeError {
    /// A nonempty plan was admitted without its immutable artifact provider.
    #[error("a nonempty signal fault plan requires an artifact provider")]
    MissingArtifactProvider,
    /// Signal evaluation, capability admission, or adapter execution failed.
    #[error(transparent)]
    Execution(#[from] FaultExecutionError),
    /// A live QEMU node could not provide required state or evidence.
    #[error(transparent)]
    Backend(#[from] BackendError),
    /// Restored live QEMU state differs from the paired fault checkpoint.
    #[error(
        "live QEMU black-box fingerprint for `{node}` does not match the fault checkpoint: expected {expected}, observed {observed}"
    )]
    QemuFingerprintMismatch {
        /// First canonical node whose restored state differs.
        node: String,
        /// Checkpoint digest, or `<missing>` when the checkpoint omitted the node.
        expected: String,
        /// Live digest, or `<missing>` when realization omitted the node.
        observed: String,
    },
    /// A QEMU occurrence event has not yet entered the authoritative log.
    #[error("cannot checkpoint while QEMU fault events await boundary admission")]
    PendingQemuFaultEvents,
    /// Explorer choices have not yet crossed into the scheduler frontier log.
    #[error("cannot checkpoint while signal-fault search choices await scheduler admission")]
    PendingSearchChoices,
    /// Authenticated lifecycle work has left the runtime but is not yet resolved.
    #[error(
        "cannot checkpoint or transfer lifecycle work while an owned lifecycle batch is in flight"
    )]
    PendingNodeLifecycleWork,
    /// A scenario-owned production resource reservation failed.
    #[error(transparent)]
    ResourceLimit(#[from] FaultResourceLimitError),
    /// A checkpoint owner could not produce its canonical identity material.
    #[error("cannot encode canonical {component} checkpoint identity material")]
    CheckpointEncoding {
        /// Independently owned continuation that failed canonical encoding.
        component: &'static str,
    },
}

/// One fully authenticated node lifecycle decision awaiting host application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuNodeLifecycleDecision {
    /// Scheduler node whose exact process generation produced the event.
    pub node: NodeId,
    /// Resolved action identity carried by the QEMU event.
    pub action: ContentHash,
    /// Transition requested by the authored node effect.
    pub requested_transition: NodeLifecycleTransition,
    /// Effective terminal transition after retry or fail-closed resolution.
    pub effective_transition: NodeLifecycleTransition,
    /// Closed terminal cause tag from `CRUCLIF1` version 4.
    pub cause: u32,
    /// Exit status required from this child, or `None` for a live transition.
    pub expected_exit_code: Option<i32>,
    /// QEMU-observed instruction coordinate for the terminal decision.
    pub observed_icount: u64,
    /// Measured pre-exit state digest when QEMU could produce one.
    pub pre_exit_hash: Option<ContentHash>,
    /// Authenticated QEMU event evidence digest.
    pub event_evidence: ContentHash,
}

/// Precommit identity of one node action that can publish lifecycle work.
#[derive(Debug, PartialEq, Eq)]
pub struct QemuNodeLifecycleIntent {
    /// Scheduler node whose current QEMU generation owns the action.
    pub node: NodeId,
    /// Canonical resolved-action identity already used by QEMU evidence.
    pub action: ContentHash,
    /// Authored or watchdog-selected lifecycle transition.
    pub requested_transition: NodeLifecycleTransition,
    /// Authenticated terminal-event evidence already pending before this boundary.
    pub event_evidence: Option<ContentHash>,
}

/// Opaque ownership of one authenticated lifecycle publication batch.
///
/// The production runtime retains a matching checkpoint barrier until this
/// value is returned through its acknowledgement method. Dropping the value
/// therefore fails closed: the runtime cannot checkpoint or transfer another
/// batch after losing the sole host-side owner.
pub struct QemuNodeLifecycleWork {
    token: Option<u64>,
    decisions: Vec<QemuNodeLifecycleDecision>,
    boot_requests: Vec<NodeId>,
}

impl QemuNodeLifecycleWork {
    /// Returns the terminal lifecycle decisions in authenticated event order.
    #[must_use]
    pub fn decisions(&self) -> &[QemuNodeLifecycleDecision] {
        &self.decisions
    }

    /// Returns the boot requests in committed action order.
    #[must_use]
    pub fn boot_requests(&self) -> &[NodeId] {
        &self.boot_requests
    }
}

/// Owning signal runtime coupled to host devices and live patched QEMU.
pub struct ProductionFaultRuntime {
    plan_id: ContentHash,
    resource_limits: FaultResourceLimits,
    runtime: Option<OwnedFaultExecutionRuntime>,
    host: HostFaultActionSink,
    restored_network_state: Option<ProductionNetworkStateCheckpoint>,
    emitted_events: Vec<ReferencedSignalEvent>,
    qemu_issued_actions: QemuActionMap<ResolvedBindingAction>,
    qemu_action_commits: QemuActionMap<CommittedQemuActionEvidence>,
    qemu_active_rule_ids: QemuActionSet,
    pending_qemu_observations: Vec<FaultObservation>,
    pending_qemu_events: PendingQemuEventMap,
    pending_node_lifecycle: Vec<QemuNodeLifecycleDecision>,
    pending_node_boot: Vec<NodeId>,
    lifecycle_work_sequence: u64,
    lifecycle_work_in_flight: Option<u64>,
    pending_search_choices: Vec<(FaultCoordinate, Vec<BindingSearchChoice>)>,
}

#[path = "production_fault_runtime/checkpoint.rs"]
mod checkpoint;
#[path = "production_fault_runtime/checkpoint_identity.rs"]
mod checkpoint_identity;
#[path = "production_fault_runtime/construction.rs"]
mod construction;
pub(crate) use construction::validate_qemu_fingerprints;
#[path = "production_fault_runtime/evaluation.rs"]
mod evaluation;
#[cfg(test)]
pub(crate) use evaluation::map_fault_event_drain_error;
use evaluation::runtime_collection_reservation;
#[path = "production_fault_runtime/evidence.rs"]
mod evidence;

use checkpoint_identity::*;
pub(crate) use evidence::*;

#[cfg(test)]
#[path = "production_fault_runtime/lifecycle_tests.rs"]
mod lifecycle_tests;
#[cfg(test)]
#[path = "production_fault_runtime/runtime_tests.rs"]
mod runtime_tests;
#[cfg(test)]
#[path = "production_fault_runtime/test_support.rs"]
pub(crate) mod test_support;
