//! Owning production runtime for signal-driven host and QEMU faults.
//!
//! This module keeps the evaluator continuation, canonical adapter ledger,
//! host device state, and live-QEMU transaction routing behind one checkpoint
//! surface. An empty plan has no hidden evaluator and remains a valid inert
//! production configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible::model::{
    BindingActionKind, BindingEvaluation, BindingSearchChoice, ContentHash, EffectKind,
    EffectSpecification, FaultAdapterManifests, FaultCapabilityId, FaultCapabilityManifest,
    FaultCoordinate, FaultExecutionError, FaultObjectId, FaultObservation, FaultObservationKind,
    FaultOpportunity, FaultReplayMode, FaultResourceLimitError, FaultResourceLimits,
    FaultRuntimeCheckpoint, FaultSignalPlan, HostFaultActionSink, HostFaultActionState,
    NodeBootPolicy, NodeEffectSpecification, NodeHangScope, NodeLifecycleTransition,
    NodeStatePolicy, NodeWatchdogPolicy, OwnedFaultExecutionRuntime, ReferencedSignalEvent,
    ResolvedBindingAction, ResolvedEffectTrace, SearchChoiceId, SearchOverride,
    SignalArtifactProvider, SignalBoundarySnapshot,
};
use crucible::{BackendError, BackendNetworkOutput, NodeId, SchedulerNetworkCheckpoint};
use crucible_shmem::{
    DequeuedFaultEvent, FaultClockEvidenceV1, FaultEventOutcomeV1, FaultExceptionEvidenceV1,
    FaultInstructionEvidenceV1, FaultRegisterMutationEvidenceV1, FaultTerminalEvidenceV1,
    MemoryMutationEvidenceV1,
};
use sha2::{Digest as _, Sha256};

use crate::fault_action_sink::CommittedQemuActionEvidence;
use crate::{ProductionFaultActionSink, QemuNodeSet};

mod checkpoint_codec;
pub use checkpoint_codec::ProductionFaultRuntimeCheckpointCodecError;

/// Complete resumable state for the production fault runtime.
#[derive(Clone, Debug)]
pub struct ProductionFaultRuntimeCheckpoint {
    /// Signal evaluator, binding, canonical adapter, replay, and search state.
    runtime: Option<FaultRuntimeCheckpoint>,
    /// Committed host network and storage adapter state.
    host: HostFaultActionState,
    /// Execution fingerprints of the exact QEMU snapshots paired with this state.
    qemu_fingerprints: BTreeMap<NodeId, ContentHash>,
    /// Per-node fault-command continuation paired with the QEMU snapshots.
    qemu_fault_sequences: BTreeMap<NodeId, u64>,
    /// Per-node fault-event continuation paired with the QEMU snapshots.
    qemu_fault_event_sequences: BTreeMap<NodeId, u64>,
    /// Issued QEMU actions needed to authenticate asynchronous occurrence events.
    qemu_issued_actions: BTreeMap<ContentHash, ResolvedBindingAction>,
    /// Authenticated APPLY results that bind occurrences to exact commands.
    qemu_action_commits: BTreeMap<ContentHash, CommittedQemuActionEvidence>,
    /// Issued persistent rules that remain installed in QEMU.
    qemu_active_rule_ids: BTreeSet<ContentHash>,
    /// Scheduler-owned network queues, pending outputs, and transition ledger.
    network_state: Option<ProductionNetworkStateCheckpoint>,
    /// Referenced event occurrences retained for device recovery subscriptions.
    emitted_events: Vec<ReferencedSignalEvent>,
    /// Drained QEMU occurrences awaiting a successfully committed boundary.
    pending_qemu_observations: Vec<FaultObservation>,
    /// Raw drained QEMU events retained until validation succeeds atomically.
    pending_qemu_events: BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    /// Aggregate identity binding every continuation component to the plan.
    identity: ContentHash,
}

/// Complete host/scheduler network continuation paired with QEMU snapshots.
#[derive(Clone, Debug)]
pub struct ProductionNetworkStateCheckpoint {
    identity: ContentHash,
    scheduler: SchedulerNetworkCheckpoint,
    pending_outputs: Vec<BackendNetworkOutput>,
    adapter_state: Vec<u8>,
}

impl ProductionNetworkStateCheckpoint {
    /// Creates a network continuation with its independently recomputable identity.
    #[must_use]
    pub fn new(
        identity: ContentHash,
        scheduler: SchedulerNetworkCheckpoint,
        pending_outputs: Vec<BackendNetworkOutput>,
        adapter_state: Vec<u8>,
    ) -> Self {
        Self {
            identity,
            scheduler,
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
        Vec<BackendNetworkOutput>,
        Vec<u8>,
        ContentHash,
    ) {
        (
            self.scheduler,
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
    #[error("live QEMU execution fingerprints do not match the fault checkpoint")]
    QemuFingerprintMismatch,
    /// A QEMU occurrence event has not yet entered the authoritative log.
    #[error("cannot checkpoint while QEMU fault events await boundary admission")]
    PendingQemuFaultEvents,
    /// Explorer choices have not yet crossed into the scheduler frontier log.
    #[error("cannot checkpoint while signal-fault search choices await scheduler admission")]
    PendingSearchChoices,
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

/// Owning signal runtime coupled to host devices and live patched QEMU.
#[derive(Clone)]
pub struct ProductionFaultRuntime {
    plan_id: ContentHash,
    resource_limits: FaultResourceLimits,
    runtime: Option<OwnedFaultExecutionRuntime>,
    host: HostFaultActionSink,
    restored_network_state: Option<ProductionNetworkStateCheckpoint>,
    emitted_events: Vec<ReferencedSignalEvent>,
    qemu_issued_actions: BTreeMap<ContentHash, ResolvedBindingAction>,
    qemu_action_commits: BTreeMap<ContentHash, CommittedQemuActionEvidence>,
    qemu_active_rule_ids: BTreeSet<ContentHash>,
    pending_qemu_observations: Vec<FaultObservation>,
    pending_qemu_events: BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    pending_node_lifecycle: Vec<QemuNodeLifecycleDecision>,
    pending_node_boot: BTreeSet<NodeId>,
    pending_search_choices: Vec<(FaultCoordinate, Vec<BindingSearchChoice>)>,
}

#[path = "production_fault_runtime/checkpoint.rs"]
mod checkpoint;
#[path = "production_fault_runtime/checkpoint_identity.rs"]
mod checkpoint_identity;
#[path = "production_fault_runtime/construction.rs"]
mod construction;
#[path = "production_fault_runtime/evaluation.rs"]
mod evaluation;
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
mod test_support;
