//! Node-addressed production QEMU backend set.
//!
//! The authoritative scheduler advances one selected [`NodeId`] per quantum.
//! [`QemuNodeSet`] preserves that address at the backend boundary and routes
//! steps, inputs, preemptions, fingerprints, debugger requests, and shutdown to
//! the corresponding live [`QemuNode`].

use std::collections::BTreeMap;

use crucible::{
    BackendEffect, BackendError, BackendNetworkOutput, BackendSnapshot, Decision,
    FingerprintSample, GdbAttachInfo, GdbListen, Icount, NodeId, ObservableEvent,
    SimulationBackend, StepObservation, VirtualTime,
};
#[cfg(target_os = "linux")]
use crucible::{ContentHash, EventLog};
use crucible_protocol::SelectionReply;
use crucible_protocol::guest_introspection::GuestIntrospectionRecord;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
use crucible_shmem::{
    DequeuedFaultResult, FaultCapabilityRowV1, FaultCommandHeaderV1, MAX_FRAME_DELIVERY_ATTEMPTS,
};

use crate::QemuVmSnapshot;
#[cfg(target_os = "linux")]
use crate::{
    QemuHotForkTemplateIdentity, QemuHotForkTemplatePreparer, QemuLaunchResourceRequirements,
    QemuProcessIdentity,
};
use crate::{QemuNode, QemuNodeError, QemuNodeIdleState};

#[cfg(target_os = "linux")]
#[path = "node_set/block_boundary.rs"]
mod block_boundary;
#[path = "node_set/fault_events.rs"]
mod fault_events;
#[path = "node_set/lifecycle.rs"]
mod lifecycle;

#[cfg(target_os = "linux")]
pub use block_boundary::QemuNodeSetBlockBoundaryCheckpoint;

/// A fully validated, no-fail terminal node-generation map update.
pub struct QemuNodeTerminalReplacementPlan {
    nodes: Vec<NodeId>,
    retired: Vec<(NodeId, QemuNode)>,
}

/// Exact prepared state minted while an authoritative node set still owns QEMU.
///
/// The private fields prevent callers from substituting a configuration,
/// event prefix, resource profile, or source process after preparation.
#[cfg(target_os = "linux")]
#[must_use = "extract the matching prepared source or abort its QEMU transaction"]
pub struct QemuNodeSetPreparedHotForkTemplate {
    node: NodeId,
    source_process: QemuProcessIdentity,
    template_generation: u64,
    identity: QemuHotForkTemplateIdentity,
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for QemuNodeSetPreparedHotForkTemplate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuNodeSetPreparedHotForkTemplate")
            .field("node", &self.node)
            .field("source_process", &self.source_process)
            .field("template_generation", &self.template_generation)
            .field("configuration", &self.identity.configuration())
            .field("event_log_offset", &self.identity.event_log().offset())
            .field("launch_resources", &self.identity.launch_resources())
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl QemuNodeSetPreparedHotForkTemplate {
    /// Returns the exact node whose retained transaction minted this token.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the QMP transaction generation bound during preparation.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns the exact configuration authenticated during preparation.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.identity.configuration()
    }

    /// Returns the unified event prefix authenticated during preparation.
    #[must_use]
    pub const fn event_log(&self) -> &EventLog {
        self.identity.event_log()
    }

    /// Returns the source launch-resource profile bound during preparation.
    #[must_use]
    pub const fn launch_resources(&self) -> QemuLaunchResourceRequirements {
        self.identity.launch_resources()
    }
}

/// Identity-checked operational loan to one retained hot-fork source.
///
/// The loan exposes only the fork and source-side reconciliation operations
/// needed while an authoritative [`QemuNodeSet`] keeps the source process
/// installed. It cannot remove, resume, shut down, or otherwise repurpose the
/// source node. Forking requires the complete prepared state. Reconciliation
/// accepts the same process incarnation and active transaction generation
/// while its branch-private resources are drained in order.
#[cfg(target_os = "linux")]
pub struct QemuNodeSetPreparedHotForkSource<'a> {
    source: &'a mut QemuNode,
    prepared: &'a QemuNodeSetPreparedHotForkTemplate,
}

#[cfg(target_os = "linux")]
impl QemuNodeSetPreparedHotForkSource<'_> {
    /// Returns the exact source process incarnation bound during preparation.
    #[must_use]
    pub const fn process_identity(&self) -> &QemuProcessIdentity {
        &self.prepared.source_process
    }

    /// Returns the exact configuration authenticated during preparation.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.prepared.configuration()
    }

    /// Returns a branch-private clone of the authenticated event-log prefix.
    #[must_use]
    pub fn fork_event_log(&self) -> EventLog {
        self.prepared.event_log().clone()
    }

    /// Returns the source launch-resource profile bound during preparation.
    #[must_use]
    pub const fn launch_resources(&self) -> QemuLaunchResourceRequirements {
        self.prepared.launch_resources()
    }

    /// Stages child-private files and forks this exact prepared source.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuHotForkLaunchError::Rejected`] when the source
    /// process or prepared generation changed before the operation, or when
    /// QEMU rejects the fork before creating a child. Other variants mean a
    /// child exists or may exist and require reconciliation or quarantine.
    pub fn fork_with_files_into<O, F>(
        &mut self,
        process_owner: &mut O,
        contract_for: F,
        destinations: &[crate::QemuHotForkChildFileDestination<'_>],
        maximum_bytes: u64,
    ) -> Result<crate::QemuHotForkChildLaunch<O::Authority>, crate::QemuHotForkLaunchError>
    where
        O: crate::QemuHotForkChildProcessOwner,
        F: for<'a> FnOnce(
            &'a O,
        ) -> Result<
            &'a crate::QemuChildProcessContract,
            crate::QemuNodeChannelError,
        >,
    {
        self.validate_prepared()
            .map_err(|source| crate::QemuHotForkLaunchError::Rejected {
                source: crate::QemuNodeChannelError::new(
                    "authenticate retained hot-fork source",
                    source.to_string(),
                ),
            })?;
        self.source.fork_prepared_hot_fork_template_with_files_into(
            process_owner,
            contract_for,
            destinations,
            maximum_bytes,
        )
    }

    /// Queries the exact parent-owned record for one forked child.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuNodeChannelError`] when source authentication or
    /// the child-status exchange fails.
    pub fn query_child_process(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, crate::QemuNodeChannelError> {
        self.validate_retained_transaction()?;
        self.source.query_hot_fork_child_process(generation)
    }

    /// Releases the exact parent-owned record for one reaped child.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuNodeChannelError`] when source authentication or
    /// the child-status release fails.
    pub fn release_child_process(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, crate::QemuNodeChannelError> {
        self.validate_retained_transaction()?;
        self.source.release_hot_fork_child_process(generation)
    }

    /// Releases the source-owned plugin endpoint stage.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuNodeChannelError`] when source authentication or
    /// the ordered endpoint release fails.
    pub fn release_plugin_endpoints(&mut self) -> Result<(), crate::QemuNodeChannelError> {
        self.validate_retained_transaction()?;
        self.source.release_hot_fork_plugin_endpoints()
    }

    /// Releases the source-owned child-console stage.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuNodeChannelError`] when source authentication or
    /// the ordered console release fails.
    pub fn release_child_console(&mut self) -> Result<(), crate::QemuNodeChannelError> {
        self.validate_retained_transaction()?;
        self.source.release_hot_fork_child_console()
    }

    /// Releases the source-owned child QMP stage.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuNodeChannelError`] when source authentication or
    /// the ordered QMP release fails.
    pub fn release_child_qmp(&mut self) -> Result<(), crate::QemuNodeChannelError> {
        self.validate_retained_transaction()?;
        self.source.release_hot_fork_child_qmp()
    }

    /// Releases the source-owned diagnostics stage with its child consumer.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuNodeChannelError`] when source authentication,
    /// consumer matching, or the ordered diagnostics release fails.
    pub fn release_child_diagnostics(
        &mut self,
        consumer: &mut crate::QemuHotForkChildDiagnosticConsumer,
    ) -> Result<crate::QemuHotForkChildDiagnosticCapture, crate::QemuNodeChannelError> {
        self.validate_retained_transaction()?;
        self.source
            .release_hot_fork_child_diagnostics_with_consumer(consumer)
    }

    /// Releases the source-owned private ring mapping.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuNodeChannelError`] when source authentication or
    /// the ordered ring release fails.
    pub fn release_private_ring(&mut self) -> Result<(), crate::QemuNodeChannelError> {
        self.validate_retained_transaction()?;
        self.source
            .release_hot_fork_private_ring_mapping()
            .map(drop)
    }

    /// Releases the exact child-process contract stage.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuNodeChannelError`] when source authentication or
    /// the ordered contract release fails.
    pub fn release_child_process_contract(
        &mut self,
    ) -> Result<crate::QmpHotForkChildProcessContractState, crate::QemuNodeChannelError> {
        self.validate_retained_transaction()?;
        self.source.release_hot_fork_child_process_contract()
    }

    /// Releases the exact child-file plan stage.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuNodeChannelError`] when source authentication or
    /// the ordered file-plan release fails.
    pub fn release_child_files(
        &mut self,
    ) -> Result<crate::QmpHotForkChildFilesState, crate::QemuNodeChannelError> {
        self.validate_retained_transaction()?;
        self.source.release_hot_fork_child_files()
    }

    fn validate_prepared(&mut self) -> Result<(), crate::QemuNodeChannelError> {
        let current_process = self.source.process_identity().map_err(|source| {
            crate::QemuNodeChannelError::new(
                "authenticate retained hot-fork source process",
                source.to_string(),
            )
        })?;
        let state = self.source.query_hot_fork_template()?;
        validate_prepared_hot_fork_token(self.prepared, &current_process, &state).map_err(
            |source| {
                crate::QemuNodeChannelError::new(
                    "authenticate retained hot-fork source transaction",
                    source.to_string(),
                )
            },
        )
    }

    fn validate_retained_transaction(&mut self) -> Result<(), crate::QemuNodeChannelError> {
        let current_process = self.source.process_identity().map_err(|source| {
            crate::QemuNodeChannelError::new(
                "authenticate retained hot-fork source process",
                source.to_string(),
            )
        })?;
        let state = self.source.query_hot_fork_template()?;
        validate_retained_hot_fork_token(self.prepared, &current_process, &state).map_err(
            |source| {
                crate::QemuNodeChannelError::new(
                    "authenticate retained hot-fork source transaction",
                    source.to_string(),
                )
            },
        )
    }
}

/// One node-qualified guest selectable request retained at a paused boundary.
///
/// The node identity is part of the delivery authority. A request drained from
/// one VM cannot be replayed into another VM even when both guests used the
/// same selectable identifier, sequence, and trap coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuNodeSelectablePendingRequest {
    node: NodeId,
    pending: SelectablePlanPendingRequest,
}

impl QemuNodeSelectablePendingRequest {
    /// Builds a node-qualified request for cross-crate transport tests.
    ///
    /// Production code obtains this token only from
    /// [`QemuNodeSet::drain_pending_selectable_requests`].
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn from_test_parts(node: NodeId, pending: SelectablePlanPendingRequest) -> Self {
        Self { node, pending }
    }

    /// Returns the exact scheduler node that owns the pending request.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the process-neutral guest request and trap coordinate.
    #[must_use]
    pub const fn pending(&self) -> &SelectablePlanPendingRequest {
        &self.pending
    }
}

/// Maximum early-pause reissues for one scheduler-selected node step.
///
/// A backpressured FIFO head can create one exact pause per canonical QEMU RX
/// attempt. Use the public transport hard bound so a valid retained frame can
/// exhaust its own typed retry budget before this adapter reports a generic
/// progress failure.
const MAX_STEP_REISSUES: u32 = MAX_FRAME_DELIVERY_ATTEMPTS;

fn consumed_input_without_retiring(
    observation: &StepObservation,
    previous: VirtualTime,
    inbound_frames_consumed: usize,
) -> bool {
    observation.reached == previous
        && matches!(observation.outcome, crucible::AdvanceOutcome::Paused { .. })
        && inbound_frames_consumed > 0
}

fn stagnant_pause_boundary(
    observation: &StepObservation,
    previous: VirtualTime,
    final_state: Option<QemuNodeIdleState>,
) -> Option<(VirtualTime, Option<Icount>)> {
    (observation.reached == previous
        && matches!(observation.outcome, crucible::AdvanceOutcome::Paused { .. }))
    .then(|| {
        (
            observation.reached,
            final_state.and_then(|state| state.next_deadline),
        )
    })
}

/// A deterministic node-addressed collection of live QEMU backends.
pub struct QemuNodeSet {
    nodes: BTreeMap<NodeId, QemuNode>,
    permanently_closed: Vec<NodeId>,
    fault_event_staging_budget: Option<QemuFaultEventStagingBudget>,
    pending_selectable_requests: BTreeMap<NodeId, SelectablePlanPendingRequest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QemuFaultEventStagingBudget {
    maximum_event_records: usize,
    configured_event_records: usize,
}

impl QemuNodeSet {
    /// Builds an empty node set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            permanently_closed: Vec::new(),
            fault_event_staging_budget: None,
            pending_selectable_requests: BTreeMap::new(),
        }
    }

    /// Inserts a live node under its scheduler identity.
    ///
    /// Returns the prior node when `node` was already present.
    pub fn insert(&mut self, node: NodeId, backend: QemuNode) -> Option<QemuNode> {
        self.permanently_closed.retain(|closed| closed != &node);
        self.nodes.insert(node, backend)
    }

    /// Removes and returns one live node without shutting it down.
    ///
    /// This is used only when a replay lifecycle transfers an oracle-validated
    /// node into the authoritative lifecycle at the same configuration.
    pub fn take(&mut self, node: &NodeId) -> Option<QemuNode> {
        self.nodes.remove(node)
    }

    /// Prepares one installed paused node as a retained hot-fork template.
    ///
    /// The node remains installed in this authoritative set. Callers can thus
    /// prepare a complete world before moving any process authority.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent, permanently failed, or
    /// cannot establish the complete retained-template transaction.
    #[cfg(target_os = "linux")]
    pub fn prepare_retained_hot_fork_template(
        &mut self,
        node: &NodeId,
        configuration: ContentHash,
        event_log: EventLog,
        launch_resources: QemuLaunchResourceRequirements,
        block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
        maximum_ring_image_bytes: usize,
    ) -> Result<QemuNodeSetPreparedHotForkTemplate, BackendError> {
        let source_process = self.process_identity(node)?;
        let prepared = self
            .node_mut(node)?
            .prepare_retained_hot_fork_template(block_snapshot_bindings, maximum_ring_image_bytes)
            .map_err(|error| BackendError::Rejected {
                message: format!("prepare retained hot-fork template: {error}"),
            });
        prepared?;
        let after = self.process_identity(node)?;
        if after != source_process {
            return Err(BackendError::Rejected {
                message: format!(
                    "prepared hot-fork source process for `{}` changed incarnation",
                    node.name
                ),
            });
        }
        let state = self
            .node_mut(node)?
            .query_hot_fork_template()
            .map_err(|error| BackendError::Rejected {
                message: format!("query prepared hot-fork template: {error}"),
            })?;
        if !state.ready() || !state.transaction_active() || state.rollback_complete() {
            return Err(BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` did not retain an exact prepared hot-fork transaction",
                    node.name
                ),
            });
        }
        Ok(QemuNodeSetPreparedHotForkTemplate {
            node: node.clone(),
            source_process,
            template_generation: state.generation(),
            identity: QemuHotForkTemplateIdentity::new_prepared(
                configuration,
                event_log,
                launch_resources,
            ),
        })
    }

    /// Advances rollback for one installed retained hot-fork template.
    ///
    /// A `false` result means QEMU still owns draining rollback work and the
    /// caller must retain the stopped source and call this method again.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or the QMP rollback
    /// exchange fails.
    #[cfg(target_os = "linux")]
    pub fn abort_retained_hot_fork_template(
        &mut self,
        node: &NodeId,
        expected_generation: Option<u64>,
    ) -> Result<bool, BackendError> {
        let backend = self.node_mut(node)?;
        let state = backend
            .query_hot_fork_template()
            .map_err(|error| BackendError::Rejected {
                message: format!("query retained hot-fork rollback state: {error}"),
            })?;
        if let Some(expected) = expected_generation
            && state.generation() != expected
        {
            return Err(BackendError::Rejected {
                message: format!(
                    "retained hot-fork transaction for `{}` changed generation",
                    node.name
                ),
            });
        }
        let host_stages_present = backend.hot_fork_plugin_endpoint_stage().is_some()
            || backend.hot_fork_child_console_stage().is_some()
            || backend.hot_fork_child_qmp_stage().is_some()
            || backend.hot_fork_child_diagnostic_stage().is_some()
            || backend.hot_fork_private_ring_stage().is_some();
        if state.rollback_complete() && !state.transaction_active() {
            return if host_stages_present {
                Err(BackendError::Rejected {
                    message: format!(
                        "QEMU node `{}` rolled back before host-side hot-fork resources were released",
                        node.name
                    ),
                })
            } else {
                Ok(true)
            };
        }
        // Child-private host resources are released in reverse dependency
        // order before the QEMU barriers. Each release retains its stage on
        // error, so a later retry or quarantine still owns every descriptor.
        if backend.hot_fork_plugin_endpoint_stage().is_some() {
            backend
                .release_hot_fork_plugin_endpoints()
                .map_err(|error| BackendError::Rejected {
                    message: format!("release retained hot-fork plugin endpoints: {error}"),
                })?;
        }
        if backend.hot_fork_child_console_stage().is_some() {
            backend
                .release_hot_fork_child_console()
                .map_err(|error| BackendError::Rejected {
                    message: format!("release retained hot-fork child console: {error}"),
                })?;
        }
        if backend.hot_fork_child_qmp_stage().is_some() {
            backend
                .release_hot_fork_child_qmp()
                .map_err(|error| BackendError::Rejected {
                    message: format!("release retained hot-fork child QMP: {error}"),
                })?;
        }
        if backend.hot_fork_child_diagnostic_stage().is_some() {
            let _diagnostics = backend
                .release_hot_fork_child_diagnostics()
                .map_err(|error| BackendError::Rejected {
                    message: format!("release retained hot-fork diagnostics: {error}"),
                })?;
        }
        if backend.hot_fork_private_ring_stage().is_some() {
            let _private_ring =
                backend
                    .release_hot_fork_private_ring_mapping()
                    .map_err(|error| BackendError::Rejected {
                        message: format!("release retained hot-fork private ring: {error}"),
                    })?;
        }
        backend
            .abort_hot_fork_template()
            .map(|state| state.rollback_complete())
            .map_err(|error| BackendError::Rejected {
                message: format!("abort retained hot-fork template: {error}"),
            })
    }

    /// Revalidates an installed source against its opaque preparation token.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node disappeared, changed process or
    /// QMP transaction generation, or no longer reports a complete prepared
    /// transaction.
    #[cfg(target_os = "linux")]
    pub fn validate_retained_hot_fork_template(
        &mut self,
        prepared: &QemuNodeSetPreparedHotForkTemplate,
    ) -> Result<(), BackendError> {
        let current_process = self.process_identity(&prepared.node)?;
        let state = self
            .node_mut(&prepared.node)?
            .query_hot_fork_template()
            .map_err(|error| BackendError::Rejected {
                message: format!("query retained hot-fork template: {error}"),
            })?;
        validate_prepared_hot_fork_token(prepared, &current_process, &state)
    }

    /// Borrows one prepared source through its exact retained-template token.
    ///
    /// The returned capability exposes only fork and source-side child
    /// reconciliation. The node remains installed in this authoritative set
    /// for the complete lifetime of the loan.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the token names a missing node, the source
    /// process incarnation changed, or QEMU no longer owns the exact prepared
    /// transaction generation.
    #[cfg(target_os = "linux")]
    pub fn prepared_hot_fork_source<'a>(
        &'a mut self,
        prepared: &'a QemuNodeSetPreparedHotForkTemplate,
    ) -> Result<QemuNodeSetPreparedHotForkSource<'a>, BackendError> {
        let current_process = self.process_identity(&prepared.node)?;
        let source = self.node_mut(&prepared.node)?;
        let state = source
            .query_hot_fork_template()
            .map_err(|error| BackendError::Rejected {
                message: format!("query retained hot-fork template: {error}"),
            })?;
        validate_prepared_hot_fork_token(prepared, &current_process, &state)?;
        Ok(QemuNodeSetPreparedHotForkSource { source, prepared })
    }

    /// Borrows one source while its authenticated transaction is reconciling.
    ///
    /// Unlike [`Self::prepared_hot_fork_source`], this permits the exact active
    /// transaction to have entered ordered branch-resource release. It still
    /// rejects process reuse, transaction-generation changes, rollback, and
    /// inactive transactions.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the token names a missing node, the source
    /// process incarnation changed, or QEMU no longer owns the token's active
    /// transaction generation.
    #[cfg(target_os = "linux")]
    pub fn retained_hot_fork_source<'a>(
        &'a mut self,
        prepared: &'a QemuNodeSetPreparedHotForkTemplate,
    ) -> Result<QemuNodeSetPreparedHotForkSource<'a>, BackendError> {
        let current_process = self.process_identity(&prepared.node)?;
        let source = self.node_mut(&prepared.node)?;
        let state = source
            .query_hot_fork_template()
            .map_err(|error| BackendError::Rejected {
                message: format!("query retained hot-fork template: {error}"),
            })?;
        validate_retained_hot_fork_token(prepared, &current_process, &state)?;
        Ok(QemuNodeSetPreparedHotForkSource { source, prepared })
    }

    /// Stops and removes one intended-crash runtime.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or its bounded shutdown
    /// ladder cannot reap the QEMU child.
    pub fn stop_intended_crash(&mut self, node: &NodeId) -> Result<(), BackendError> {
        let mut backend = self
            .nodes
            .remove(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU backend set has no live node `{}` to crash", node.name),
            })?;
        SimulationBackend::shutdown(&mut backend)
    }

    /// Returns whether the selected QEMU runtime is currently live.
    #[must_use]
    pub fn contains(&self, node: &NodeId) -> bool {
        self.nodes.contains_key(node)
    }

    /// Releases every reaped node after its enclosing lifecycle has shut down.
    ///
    /// This drops modeled channels and non-owning process-control loans only
    /// after every installed process reports terminal reap. Generation leases
    /// and source-parent reconciliation remain owned by the enclosing
    /// lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] without releasing any node when a process has
    /// not reached terminal reap.
    pub fn release_reaped_nodes(&mut self) -> Result<(), BackendError> {
        if let Some((node, _backend)) = self
            .nodes
            .iter()
            .find(|(_node, backend)| !backend.child_reaped())
        {
            return Err(BackendError::Rejected {
                message: format!(
                    "cannot release modeled node `{}` before terminal reap",
                    node.name
                ),
            });
        }

        self.nodes.clear();
        Ok(())
    }

    /// Drains every node's selectable request at the current paused boundary.
    ///
    /// Results follow canonical [`NodeId`] order. Each node may own at most one
    /// pending request, matching the plugin catalog state machine.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when a node's shared-memory transport is
    /// malformed or reports more than one pending request.
    pub fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, BackendError> {
        for (node, backend) in &mut self.nodes {
            if self.pending_selectable_requests.contains_key(node) {
                continue;
            }
            let pending = backend
                .drain_pending_selectable_requests()
                .map_err(BackendError::from)?;
            if pending.len() > 1 {
                return Err(BackendError::Rejected {
                    message: format!(
                        "QEMU node `{}` reported {} pending selectable requests",
                        node.name,
                        pending.len()
                    ),
                });
            }
            if let Some(pending) = pending.into_iter().next() {
                self.pending_selectable_requests
                    .insert(node.clone(), pending.clone());
            }
        }
        let mut drained = Vec::new();
        drained
            .try_reserve_exact(self.pending_selectable_requests.len())
            .map_err(|_| BackendError::Rejected {
                message: String::from("QEMU selectable request storage is exhausted"),
            })?;
        for (node, pending) in &self.pending_selectable_requests {
            drained.push(QemuNodeSelectablePendingRequest {
                node: node.clone(),
                pending: pending.clone(),
            });
        }
        Ok(drained)
    }

    /// Enqueues a reply for the exact node-qualified pending request.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or permanently closed,
    /// or when its shared-memory transport rejects the request/reply binding.
    pub fn enqueue_selectable_reply(
        &mut self,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), BackendError> {
        let retained = self
            .pending_selectable_requests
            .get(pending.node())
            .ok_or_else(|| BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` has no retained selectable request",
                    pending.node().name
                ),
            })?;
        if retained != pending.pending() {
            return Err(BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` selectable request differs from the retained token",
                    pending.node().name
                ),
            });
        }
        self.node_mut(pending.node())?
            .enqueue_selectable_reply(pending.pending(), reply)
            .map_err(BackendError::from)?;
        self.pending_selectable_requests.remove(pending.node());
        Ok(())
    }

    /// Copies every live node's exact host-mirrored selectable catalog plan.
    #[must_use]
    pub fn selectable_catalog_plans(
        &self,
    ) -> BTreeMap<NodeId, crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan> {
        self.nodes
            .iter()
            .filter_map(|(node, backend)| {
                backend
                    .selectable_catalog_plan()
                    .filter(|plan| !plan.declarations().is_empty())
                    .map(|plan| (node.clone(), plan))
            })
            .collect()
    }

    /// Reports whether one node has no selectable reply awaiting consumption.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent.
    pub fn selectable_reply_is_checkpoint_quiescent(
        &self,
        node: &NodeId,
    ) -> Result<bool, BackendError> {
        Ok(self
            .nodes
            .get(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU backend set has no live node `{}`", node.name),
            })?
            .selectable_reply_is_checkpoint_quiescent())
    }

    /// Returns one node's authoritative live block-device handle.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `node` is absent or has no block device.
    #[cfg(target_os = "linux")]
    pub fn shared_block_device(
        &self,
        node: &NodeId,
    ) -> Result<crate::QemuSharedBlockDevice, BackendError> {
        self.nodes
            .get(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU backend set has no live node `{}`", node.name),
            })?
            .shared_block_device()
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU node `{}` has no live block device", node.name),
            })
    }

    /// Installs the production block-fault coordinator for one live node.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `node` is absent or its host-I/O runtime
    /// does not own an uncoordinated live block device.
    #[cfg(target_os = "linux")]
    pub fn install_block_fault_coordinator(
        &mut self,
        node: &NodeId,
        coordinator: Box<dyn crate::QemuBlockFaultCoordinator>,
    ) -> Result<(), BackendError> {
        self.nodes
            .get_mut(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!(
                    "QEMU backend set has no live node `{}` for block coordination",
                    node.name
                ),
            })?
            .install_block_fault_coordinator(coordinator)
            .map_err(BackendError::from)
    }

    /// Installs the production 9p-fault coordinator for one live node.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `node` is absent or its host-I/O runtime
    /// does not own an uncoordinated live 9p device.
    #[cfg(target_os = "linux")]
    pub fn install_ninep_fault_coordinator(
        &mut self,
        node: &NodeId,
        coordinator: Box<dyn crate::QemuNinepFaultCoordinator>,
    ) -> Result<(), BackendError> {
        self.nodes
            .get_mut(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!(
                    "QEMU backend set has no live node `{}` for 9p coordination",
                    node.name
                ),
            })?
            .install_ninep_fault_coordinator(coordinator)
            .map_err(BackendError::from)
    }

    /// Returns the number of live nodes in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns whether the set has no live nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns the exact QEMU fault capabilities admitted for `node`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `node` is not live in this set.
    pub fn fault_capabilities(
        &self,
        node: &NodeId,
    ) -> Result<&[FaultCapabilityRowV1], BackendError> {
        if self.permanently_closed.contains(node) {
            return Err(BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` is permanently failed and cannot accept faults",
                    node.name
                ),
            });
        }
        self.nodes
            .get(node)
            .map(QemuNode::fault_capabilities)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU backend set has no node `{}`", node.name),
            })
    }

    /// Reports whether one live node's launch manifest admits a guest ready marker.
    #[must_use]
    pub fn admits_ready_marker(
        &self,
        node: &crucible::model::FaultObjectId,
        marker: &crucible::model::FaultObjectId,
    ) -> bool {
        self.nodes
            .iter()
            .find(|(id, _node)| id.name == node.as_str())
            .is_some_and(|(_id, node)| node.ready_markers().contains(marker))
    }

    /// Derives the node capability manifest common to every live QEMU process.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when a capability identifier is invalid. An
    /// empty node set advertises no executable node effects.
    pub fn fault_capability_manifest(
        &self,
    ) -> Result<crucible::model::FaultCapabilityManifest, BackendError> {
        use crucible::model::{FaultCapabilityId, FaultCapabilityManifest, FaultObjectId};
        let mut common = self
            .nodes
            .values()
            .next()
            .map(|node| {
                node.fault_capabilities()
                    .iter()
                    .map(|row| row.command_kind)
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default();
        for node in self.nodes.values().skip(1) {
            let supported = node
                .fault_capabilities()
                .iter()
                .map(|row| row.command_kind)
                .collect::<std::collections::BTreeSet<_>>();
            common.retain(|kind| supported.contains(kind));
        }
        let implementations = crate::fault_implementation::node_effect_implementation_registry()
            .map_err(|error| BackendError::Rejected {
                message: format!("invalid compiled node fault implementation registry: {error}"),
            })?;
        let capabilities = common
            .into_iter()
            .filter_map(crate::fault_implementation::effect_kind_for_command)
            .map(|effect| {
                implementations
                    .require_implemented(effect)
                    .map(|contract| contract.effect.descriptor().capability)
                    .map_err(|error| BackendError::Rejected {
                        message: format!(
                            "live QEMU advertised an unimplemented fault command: {error}"
                        ),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(FaultCapabilityId::parse)
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .map_err(|error| BackendError::Rejected {
                message: error.to_string(),
            })?;
        let backend =
            FaultObjectId::parse("node-qemu").map_err(|error| BackendError::Rejected {
                message: error.to_string(),
            })?;
        Ok(FaultCapabilityManifest {
            backend,
            capabilities,
            bounds: BTreeMap::new(),
        })
    }

    /// Publishes one authenticated QEMU fault command for `node`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or its mapped command
    /// transport rejects the command.
    pub fn enqueue_fault_command(
        &mut self,
        node: &NodeId,
        header: FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<(), BackendError> {
        self.node_mut(node)?
            .enqueue_fault_command(header, payload)
            .map_err(|source| BackendError::Rejected {
                message: source.to_string(),
            })
    }

    /// Removes one completed QEMU fault result for `node`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or its mapped result
    /// transport is corrupt.
    pub fn dequeue_fault_result(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<DequeuedFaultResult>, BackendError> {
        self.node_mut(node)?
            .dequeue_fault_result()
            .map_err(|source| BackendError::Rejected {
                message: source.to_string(),
            })
    }

    /// Drains every authenticated QEMU rule event grouped by scheduler node.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any node transport or sequence is invalid.
    pub(crate) fn visit_fault_event_nodes<E>(
        &mut self,
        mut visit: impl FnMut(&NodeId, &mut QemuNode) -> Result<(), E>,
    ) -> Result<(), E> {
        for (node, backend) in &mut self.nodes {
            visit(node, backend)?;
        }
        Ok(())
    }

    /// Verifies and reaps one child after authenticated terminal lifecycle evidence.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `node` is absent, does not terminate by
    /// the bounded supervision deadline, or returns a status other than the
    /// transition-specific `expected_exit_code`.
    pub fn await_intended_lifecycle_exit(
        &mut self,
        node: &NodeId,
        expected_exit_code: i32,
        action: crucible::ContentHash,
    ) -> Result<i32, BackendError> {
        self.node_mut(node)?
            .await_intended_lifecycle_exit(expected_exit_code, action)
            .map_err(BackendError::from)
    }

    /// Returns the operating-system process identifier for one QEMU node.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `node` is absent or permanently closed.
    pub fn process_id(&self, node: &NodeId) -> Result<u32, BackendError> {
        if self.permanently_closed.contains(node) {
            return Err(BackendError::Rejected {
                message: format!("QEMU node `{}` is permanently closed", node.name),
            });
        }
        self.nodes
            .get(node)
            .map(QemuNode::process_id)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("unknown QEMU node `{}`", node.name),
            })
    }

    /// Returns the complete Linux process identity for one QEMU node.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `node` is absent, permanently closed, or
    /// its `/proc` identity cannot be captured.
    #[cfg(target_os = "linux")]
    pub fn process_identity(&self, node: &NodeId) -> Result<QemuProcessIdentity, BackendError> {
        if self.permanently_closed.contains(node) {
            return Err(BackendError::Rejected {
                message: format!("QEMU node `{}` is permanently closed", node.name),
            });
        }
        self.nodes
            .get(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("unknown QEMU node `{}`", node.name),
            })?
            .process_identity()
            .map_err(BackendError::from)
    }

    /// Reports whether one live node has no device coroutine crossing its boundary.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `node` is unknown or its shared device-I/O
    /// state cannot be inspected consistently.
    pub fn checkpoint_device_io_is_quiescent(
        &mut self,
        node: &NodeId,
    ) -> Result<bool, BackendError> {
        Ok(self.node_mut(node)?.checkpoint_device_io_is_quiescent()?)
    }

    /// Completes one authenticated terminal lifecycle decision over QMP.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when `node` is absent or QEMU cannot
    /// acknowledge the completion command.
    pub fn complete_terminal_lifecycle_exit(
        &mut self,
        node: &NodeId,
        action: crucible::ContentHash,
        evidence: crucible::ContentHash,
        process_generation: u64,
    ) -> Result<(), BackendError> {
        self.node_mut(node)?
            .complete_terminal_lifecycle_exit(action, evidence, process_generation)
            .map_err(BackendError::from)
    }

    /// Applies one admitted QEMU fault command at `node`'s current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or the command fails
    /// capability, coordinate, transport, liveness, or result validation.
    pub fn apply_fault_command_at_current_boundary(
        &mut self,
        node: &NodeId,
        header: FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<DequeuedFaultResult, BackendError> {
        self.node_mut(node)?
            .apply_fault_command_at_current_boundary(header, payload)
            .map_err(BackendError::from)
    }

    pub(crate) fn apply_fault_command_at_current_boundary_with_limits(
        &mut self,
        node: &NodeId,
        header: FaultCommandHeaderV1,
        payload: &[u8],
        result_buffer: Vec<u8>,
        maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuNodeError> {
        self.node_mut_for_fault_command(node)?
            .apply_fault_command_at_current_boundary_with_limits(
                header,
                payload,
                result_buffer,
                maximum_event_records,
            )
    }

    pub(crate) fn apply_fault_preparation_at_current_boundary(
        &mut self,
        node: &NodeId,
        header: FaultCommandHeaderV1,
        payload: &[u8],
        maximum_payload_bytes: usize,
        maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuNodeError> {
        self.node_mut_for_fault_command(node)?
            .apply_fault_preparation_at_current_boundary(
                header,
                payload,
                maximum_payload_bytes,
                maximum_event_records,
            )
    }

    /// Reads one live node's authoritative fault-command coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent, permanently closed,
    /// or its shared-memory hot path cannot be read.
    pub(crate) fn fault_command_coordinate(
        &mut self,
        node: &NodeId,
    ) -> Result<Icount, BackendError> {
        self.node_mut(node)?
            .current_icount()
            .map_err(BackendError::from)
    }

    /// Reserves one strictly increasing fault-command sequence for `node`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or its sequence space
    /// is exhausted.
    pub fn reserve_fault_command_sequence(&mut self, node: &NodeId) -> Result<u64, BackendError> {
        self.node_mut(node)?
            .reserve_fault_command_sequence()
            .map_err(BackendError::from)
    }

    /// Iterates next fault-command sequences without building an intermediate map.
    pub(crate) fn fault_command_sequence_entries(
        &self,
    ) -> impl ExactSizeIterator<Item = (&NodeId, u64)> {
        self.nodes
            .iter()
            .map(|(node, backend)| (node, backend.next_fault_command_sequence()))
    }

    /// Iterates next required fault-event sequences without an intermediate map.
    pub(crate) fn fault_event_sequence_entries(
        &self,
    ) -> impl ExactSizeIterator<Item = (&NodeId, u64)> {
        self.nodes
            .iter()
            .map(|(node, backend)| (node, backend.next_fault_event_sequence()))
    }

    /// Returns one node's next required fault-event sequence.
    pub(crate) fn fault_event_sequence(&self, node: &NodeId) -> Option<u64> {
        self.nodes
            .get(node)
            .map(QemuNode::next_fault_event_sequence)
    }

    /// Atomically restores canonically ordered command and event continuations.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] without mutation when either node membership
    /// differs or any sequence is invalid for its shared-memory ABI.
    pub(crate) fn restore_ordered_fault_sequences(
        &mut self,
        command_sequences: &[(NodeId, u64)],
        event_sequences: &[(NodeId, u64)],
    ) -> Result<(), BackendError> {
        if self
            .nodes
            .keys()
            .ne(command_sequences.iter().map(|(node, _sequence)| node))
            || self
                .nodes
                .keys()
                .ne(event_sequences.iter().map(|(node, _sequence)| node))
        {
            return Err(BackendError::Rejected {
                message: String::from(
                    "QEMU fault-sequence checkpoint node membership differs from live nodes",
                ),
            });
        }
        for (node, sequence) in command_sequences {
            self.nodes
                .get(node)
                .ok_or_else(|| BackendError::Rejected {
                    message: format!("QEMU fault checkpoint names unknown node `{}`", node.name),
                })?
                .validate_fault_command_sequence_restore(*sequence)
                .map_err(BackendError::from)?;
        }
        for (node, sequence) in event_sequences {
            self.nodes
                .get(node)
                .ok_or_else(|| BackendError::Rejected {
                    message: format!("QEMU fault checkpoint names unknown node `{}`", node.name),
                })?
                .validate_fault_event_sequence_restore(*sequence)
                .map_err(BackendError::from)?;
        }

        for (((_node, backend), (_command_node, command)), (_event_node, event)) in self
            .nodes
            .iter_mut()
            .zip(command_sequences)
            .zip(event_sequences)
        {
            backend
                .restore_fault_command_sequence(*command)
                .map_err(BackendError::from)?;
            backend
                .restore_fault_event_sequence(*event)
                .map_err(BackendError::from)?;
        }
        Ok(())
    }

    fn node_mut(&mut self, node: &NodeId) -> Result<&mut QemuNode, BackendError> {
        if self.permanently_closed.contains(node) {
            return Err(BackendError::Rejected {
                message: format!("QEMU node `{}` is permanently failed", node.name),
            });
        }
        self.nodes
            .get_mut(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU backend set has no node `{}`", node.name),
            })
    }

    fn node_mut_for_fault_command(
        &mut self,
        node: &NodeId,
    ) -> Result<&mut QemuNode, QemuNodeError> {
        if self.permanently_closed.contains(node) {
            return Err(QemuNodeError::fault_command(format!(
                "QEMU node `{}` is permanently failed",
                node.name
            )));
        }
        self.nodes
            .get_mut(node)
            .ok_or_else(|| QemuNodeError::fault_command(format!("node {node:?} is absent")))
    }
}

#[cfg(target_os = "linux")]
fn validate_prepared_hot_fork_token(
    prepared: &QemuNodeSetPreparedHotForkTemplate,
    current_process: &QemuProcessIdentity,
    state: &crate::QmpHotForkTemplateState,
) -> Result<(), BackendError> {
    if current_process != &prepared.source_process {
        return Err(BackendError::Rejected {
            message: format!(
                "prepared hot-fork source process for `{}` changed incarnation",
                prepared.node.name
            ),
        });
    }
    if state.generation() != prepared.template_generation
        || !state.ready()
        || !state.transaction_active()
        || state.rollback_complete()
    {
        return Err(BackendError::Rejected {
            message: format!(
                "QEMU node `{}` no longer owns the exact prepared hot-fork transaction",
                prepared.node.name
            ),
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_retained_hot_fork_token(
    prepared: &QemuNodeSetPreparedHotForkTemplate,
    current_process: &QemuProcessIdentity,
    state: &crate::QmpHotForkTemplateState,
) -> Result<(), BackendError> {
    if current_process != &prepared.source_process {
        return Err(BackendError::Rejected {
            message: format!(
                "prepared hot-fork source process for `{}` changed incarnation",
                prepared.node.name
            ),
        });
    }
    if state.generation() != prepared.template_generation
        || !state.transaction_active()
        || state.rollback_complete()
    {
        return Err(BackendError::Rejected {
            message: format!(
                "QEMU node `{}` no longer owns the retained hot-fork transaction",
                prepared.node.name
            ),
        });
    }
    Ok(())
}

impl Default for QemuNodeSet {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulationBackend for QemuNodeSet {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        let node = {
            let mut nodes = self.nodes.keys();
            let node = nodes
                .next()
                .cloned()
                .ok_or_else(|| BackendError::Rejected {
                    message: String::from("QEMU backend set cannot step without a node"),
                })?;
            if nodes.next().is_some() {
                return Err(BackendError::Unsupported {
                    capability: "backend-global step on a multi-node QEMU set",
                });
            }
            node
        };
        self.arm_selected_fault_event_staging(&node)?;
        self.node_mut(&node)?.step_to(ceiling)
    }

    fn step_node_to(
        &mut self,
        node: &NodeId,
        ceiling: VirtualTime,
    ) -> Result<StepObservation, BackendError> {
        self.arm_selected_fault_event_staging(node)?;
        let backend = self.node_mut(node)?;
        let mut previous = SimulationBackend::now(backend);
        let mut last_stagnant_pause = None;
        for reissue in 0..=MAX_STEP_REISSUES {
            let mut observation = backend.step_to(ceiling)?;
            if observation.reached == ceiling {
                return Ok(observation);
            }
            if let crucible::AdvanceOutcome::Paused { .. } = observation.outcome
                && let Some(deadline) = backend
                    .last_step_final_state()
                    .and_then(|state| state.next_deadline)
                && deadline.retired > ceiling.ticks
            {
                observation.reached = ceiling;
                return Ok(observation);
            }
            if matches!(observation.outcome, crucible::AdvanceOutcome::Paused { .. }) {
                // A delivery-capped quantum can stop exactly where an idle
                // timer is also due. Both causes are within the original
                // scheduler horizon, so resume through a fresh quantum.
                // The monotone-progress check below still rejects a plugin
                // that reports the same reachable deadline twice.
                // An inbound frame already staged in the shared-memory ring can
                // likewise cap a running (non-idle) quantum. The hot path drains
                // it before returning; issue a fresh quantum for the remainder.
            }
            if observation.reached <= previous {
                if consumed_input_without_retiring(
                    &observation,
                    previous,
                    backend.last_step_inbound_frames_consumed(),
                ) {
                    // Consuming an input due at the current coordinate is real
                    // boundary progress even though it retires no guest
                    // instruction. Reissue once that complete batch has left
                    // the ring; the bounded loop still rejects a backend that
                    // cannot subsequently move or consume another due batch.
                    last_stagnant_pause = None;
                    continue;
                }
                if let Some(boundary) =
                    stagnant_pause_boundary(&observation, previous, backend.last_step_final_state())
                    && last_stagnant_pause.as_ref() != Some(&boundary)
                {
                    // A fresh timer or control boundary can become visible at
                    // the current coordinate without retiring an instruction.
                    // Reissue it once; only an identical repeated boundary is
                    // a stall. Distinct boundaries remain bounded by the outer
                    // reissue limit.
                    last_stagnant_pause = Some(boundary);
                    continue;
                }
                return Err(BackendError::Rejected {
                    message: format!(
                        "QEMU node `{}` stalled at {} while stepping to {} after {reissue} reissues: effective ceiling {:?}, outcome {:?}, completed state {:?}, consumed inbound {}",
                        node.name,
                        observation.reached.ticks,
                        ceiling.ticks,
                        backend.last_step_ceiling(),
                        observation.outcome,
                        backend.last_step_final_state(),
                        backend.last_step_inbound_frames_consumed(),
                    ),
                });
            }
            previous = observation.reached;
            last_stagnant_pause = None;
        }
        Err(BackendError::Rejected {
            message: format!(
                "QEMU node `{}` did not reach {} within {} reissues",
                node.name, ceiling.ticks, MAX_STEP_REISSUES
            ),
        })
    }

    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, BackendError> {
        let mut events = Vec::new();
        for node in self.nodes.values_mut() {
            events.extend(node.drain_observable_events()?);
        }
        Ok(events)
    }

    fn drain_causal_decisions(&mut self) -> Result<Vec<Decision>, BackendError> {
        let mut decisions = Vec::new();
        for node in self.nodes.values_mut() {
            decisions.extend(node.drain_causal_decisions()?);
        }
        Ok(decisions)
    }

    fn drain_network_outputs(&mut self) -> Result<Vec<BackendNetworkOutput>, BackendError> {
        let mut outputs = Vec::new();
        for node in self.nodes.values_mut() {
            outputs.extend(node.drain_network_outputs()?);
        }
        Ok(outputs)
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        match effect {
            BackendEffect::DeliverInput(input) => self.node_mut(&input.node)?.apply(effect, at),
            BackendEffect::Preemption(preemption) => {
                self.node_mut(&preemption.node)?.apply(effect, at)
            }
            BackendEffect::Shutdown => self.shutdown(),
            BackendEffect::Noop => Ok(()),
        }
    }

    fn apply_to_node(
        &mut self,
        node: &NodeId,
        effect: &BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        self.node_mut(node)?.apply(effect, at)
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        Err(BackendError::Unsupported {
            capability: "QEMU node-set snapshot without realization admission",
        })
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        let _ = snapshot;
        Err(BackendError::Unsupported {
            capability: "QEMU node-set restore without realization admission",
        })
    }

    fn now(&self) -> VirtualTime {
        self.nodes
            .values()
            .map(SimulationBackend::now)
            .min()
            .unwrap_or_default()
    }

    fn node_now(&self, node: &NodeId) -> Result<VirtualTime, BackendError> {
        self.nodes
            .get(node)
            .map(SimulationBackend::now)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU backend set has no node `{}`", node.name),
            })
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        self.node_mut(&node)?.fingerprint(node)
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, BackendError> {
        self.node_mut(&node)?.open_gdbstub(node, listen)
    }

    fn activate_debug_guest(&mut self, node: &NodeId) -> Result<(), BackendError> {
        Ok(self.node_mut(node)?.activate_debug_guest()?)
    }

    fn send_guest_introspection(
        &mut self,
        node: &NodeId,
        record: GuestIntrospectionRecord,
    ) -> Result<(), BackendError> {
        Ok(self.node_mut(node)?.send_guest_introspection(record)?)
    }

    fn receive_guest_introspection(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<GuestIntrospectionRecord>, BackendError> {
        Ok(self.node_mut(node)?.receive_guest_introspection()?)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        let mut first_error = None;
        for (id, node) in &mut self.nodes {
            if self.permanently_closed.contains(id) {
                continue;
            }
            if let Err(error) = SimulationBackend::shutdown(node)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture setup uses panic shortcuts for failure localization.
    #![allow(clippy::expect_used)]

    use crucible::{AdvanceOutcome, Icount};
    use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
    use crucible_protocol::{SelectionReply, SelectionReplyStatus, SelectionRequest};

    use super::*;

    #[test]
    fn current_coordinate_input_consumption_is_reissuable_boundary_progress() {
        let previous = VirtualTime { ticks: 41 };
        let paused = StepObservation::from_advance_outcome(
            VirtualTime { ticks: 100 },
            AdvanceOutcome::Paused {
                at: Icount { retired: 41 },
            },
        );

        assert!(consumed_input_without_retiring(&paused, previous, 1));
        assert!(!consumed_input_without_retiring(&paused, previous, 0));

        let regressed = StepObservation::from_advance_outcome(
            VirtualTime { ticks: 100 },
            AdvanceOutcome::Paused {
                at: Icount { retired: 40 },
            },
        );
        assert!(!consumed_input_without_retiring(&regressed, previous, 1));
    }

    #[test]
    fn fresh_stagnant_pause_is_progress_but_an_identical_repeat_is_not() {
        let previous = VirtualTime { ticks: 41 };
        let paused = StepObservation::from_advance_outcome(
            VirtualTime { ticks: 100 },
            AdvanceOutcome::Paused {
                at: Icount { retired: 41 },
            },
        );
        let first = stagnant_pause_boundary(
            &paused,
            previous,
            Some(QemuNodeIdleState {
                current_icount: Icount { retired: 41 },
                next_deadline: Some(Icount { retired: 60 }),
            }),
        );
        assert_eq!(first, Some((previous, Some(Icount { retired: 60 }))));

        let repeated = stagnant_pause_boundary(
            &paused,
            previous,
            Some(QemuNodeIdleState {
                current_icount: Icount { retired: 41 },
                next_deadline: Some(Icount { retired: 60 }),
            }),
        );
        assert_eq!(repeated, first);

        let advanced_boundary = stagnant_pause_boundary(
            &paused,
            previous,
            Some(QemuNodeIdleState {
                current_icount: Icount { retired: 41 },
                next_deadline: Some(Icount { retired: 61 }),
            }),
        );
        assert_ne!(advanced_boundary, first);

        let regressed = StepObservation::from_advance_outcome(
            VirtualTime { ticks: 100 },
            AdvanceOutcome::Paused {
                at: Icount { retired: 40 },
            },
        );
        assert_eq!(stagnant_pause_boundary(&regressed, previous, None), None);
    }

    #[test]
    fn drained_selectable_request_remains_owned_after_delivery_failure() {
        let node = NodeId {
            name: String::from("node-a"),
        };
        let request = SelectionRequest::new(7, "product.test.selectable", "instance-a", None, 128)
            .expect("selection request");
        let pending = SelectablePlanPendingRequest::new(request, 41, 0, 0x1000);
        let mut nodes = QemuNodeSet::new();
        nodes
            .pending_selectable_requests
            .insert(node.clone(), pending.clone());

        let first = nodes
            .drain_pending_selectable_requests()
            .expect("retained request");
        let second = nodes
            .drain_pending_selectable_requests()
            .expect("retry retained request");
        assert_eq!(first, second);
        assert_eq!(first[0].node(), &node);
        assert_eq!(first[0].pending(), &pending);

        let reply =
            SelectionReply::rejected(7, SelectionReplyStatus::Unavailable, [0; 32], [0; 32])
                .expect("unavailable reply");
        assert!(nodes.enqueue_selectable_reply(&first[0], &reply).is_err());
        assert_eq!(
            nodes
                .drain_pending_selectable_requests()
                .expect("request survives failed delivery"),
            first
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_preparation_token_cannot_authorize_a_new_qmp_transaction() {
        let process = QemuProcessIdentity {
            process_id: 41,
            start_time_ticks: 73,
            executable: std::path::PathBuf::from("qemu-system-test"),
        };
        let token = QemuNodeSetPreparedHotForkTemplate {
            node: NodeId {
                name: String::from("node-a"),
            },
            source_process: process.clone(),
            template_generation: 1,
            identity: QemuHotForkTemplateIdentity::new_prepared(
                ContentHash::from_bytes(b"configuration-a"),
                EventLog::new(),
                QemuLaunchResourceRequirements::from_vm_shape(128, 1, true),
            ),
        };
        let replacement = crate::QmpHotForkTemplateState::one_prepared(
            crate::QmpHotForkRequest::for_test(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2),
        );

        let error = validate_prepared_hot_fork_token(&token, &process, &replacement)
            .expect_err("a token from the prior transaction must be stale");

        assert!(
            error
                .to_string()
                .contains("exact prepared hot-fork transaction")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reconciliation_token_accepts_only_the_same_active_transaction() {
        let process = QemuProcessIdentity {
            process_id: 41,
            start_time_ticks: 73,
            executable: std::path::PathBuf::from("qemu-system-test"),
        };
        let token = QemuNodeSetPreparedHotForkTemplate {
            node: NodeId {
                name: String::from("node-a"),
            },
            source_process: process.clone(),
            template_generation: 1,
            identity: QemuHotForkTemplateIdentity::new_prepared(
                ContentHash::from_bytes(b"configuration-a"),
                EventLog::new(),
                QemuLaunchResourceRequirements::from_vm_shape(128, 1, true),
            ),
        };
        let request =
            crate::QmpHotForkRequest::for_test(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
        let draining = crate::QmpHotForkTemplateState::one_draining_without_resources(request);

        assert!(validate_retained_hot_fork_token(&token, &process, &draining).is_ok());
        assert!(validate_prepared_hot_fork_token(&token, &process, &draining).is_err());

        let reused_process = QemuProcessIdentity {
            start_time_ticks: 74,
            ..process.clone()
        };
        assert!(validate_retained_hot_fork_token(&token, &reused_process, &draining).is_err());

        let next_generation = crate::QmpHotForkTemplateState::one_draining_without_resources(
            crate::QmpHotForkRequest::for_test(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2),
        );
        assert!(validate_retained_hot_fork_token(&token, &process, &next_generation).is_err());

        let rolled_back = crate::QmpHotForkTemplateState::one_aborted(request);
        assert!(validate_retained_hot_fork_token(&token, &process, &rolled_back).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preparation_token_cannot_move_to_a_reused_process_id() {
        let source_process = QemuProcessIdentity {
            process_id: 41,
            start_time_ticks: 73,
            executable: std::path::PathBuf::from("qemu-system-test"),
        };
        let replacement_process = QemuProcessIdentity {
            process_id: 41,
            start_time_ticks: 74,
            executable: std::path::PathBuf::from("qemu-system-test"),
        };
        let token = QemuNodeSetPreparedHotForkTemplate {
            node: NodeId {
                name: String::from("node-a"),
            },
            source_process,
            template_generation: 1,
            identity: QemuHotForkTemplateIdentity::new_prepared(
                ContentHash::from_bytes(b"configuration-a"),
                EventLog::new(),
                QemuLaunchResourceRequirements::from_vm_shape(128, 1, true),
            ),
        };
        let prepared = crate::QmpHotForkTemplateState::one_prepared(
            crate::QmpHotForkRequest::for_test(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1),
        );

        let error = validate_prepared_hot_fork_token(&token, &replacement_process, &prepared)
            .expect_err("PID reuse must not preserve a source token");

        assert!(error.to_string().contains("changed incarnation"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepared_source_loan_rejects_a_stale_transaction_generation() {
        let mut nodes = QemuNodeSet::new();
        let node = NodeId {
            name: String::from("node-a"),
        };
        nodes.insert(
            node.clone(),
            crate::node::tests::node_set_hot_fork_source(false).expect("scripted QEMU source"),
        );
        let mut token = nodes
            .prepare_retained_hot_fork_template(
                &node,
                ContentHash::from_bytes(b"loan-generation"),
                EventLog::new(),
                QemuLaunchResourceRequirements::from_vm_shape(128, 1, true),
                &[],
                64 * 1024 * 1024,
            )
            .expect("prepare source");

        token.template_generation = token.template_generation.saturating_add(1);
        let error = nodes
            .prepared_hot_fork_source(&token)
            .err()
            .unwrap_or_else(|| panic!("stale generation must not mint a source loan"));

        assert!(
            error
                .to_string()
                .contains("exact prepared hot-fork transaction")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepared_source_loan_rejects_a_changed_process_incarnation() {
        let mut nodes = QemuNodeSet::new();
        let node = NodeId {
            name: String::from("node-a"),
        };
        nodes.insert(
            node.clone(),
            crate::node::tests::node_set_hot_fork_source(false).expect("scripted QEMU source"),
        );
        let mut token = nodes
            .prepare_retained_hot_fork_template(
                &node,
                ContentHash::from_bytes(b"loan-incarnation"),
                EventLog::new(),
                QemuLaunchResourceRequirements::from_vm_shape(128, 1, true),
                &[],
                64 * 1024 * 1024,
            )
            .expect("prepare source");

        token.source_process.start_time_ticks =
            token.source_process.start_time_ticks.saturating_add(1);
        let error = nodes
            .prepared_hot_fork_source(&token)
            .err()
            .unwrap_or_else(|| panic!("changed incarnation must not mint a source loan"));

        assert!(error.to_string().contains("changed incarnation"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authoritative_node_set_prepares_and_rolls_back_two_real_source_owners() {
        let mut nodes = QemuNodeSet::new();
        let first = NodeId {
            name: String::from("node-a"),
        };
        let second = NodeId {
            name: String::from("node-b"),
        };
        nodes.insert(
            first.clone(),
            crate::node::tests::node_set_hot_fork_source(false)
                .expect("first scripted QEMU source"),
        );
        nodes.insert(
            second.clone(),
            crate::node::tests::node_set_hot_fork_source(false)
                .expect("second scripted QEMU source"),
        );
        let configuration = ContentHash::from_bytes(b"two-node-source-world");
        let resources = QemuLaunchResourceRequirements::from_vm_shape(128, 1, true);

        let first_token = nodes
            .prepare_retained_hot_fork_template(
                &first,
                configuration,
                EventLog::new(),
                resources,
                &[],
                64 * 1024 * 1024,
            )
            .expect("prepare first source");
        let second_token = nodes
            .prepare_retained_hot_fork_template(
                &second,
                configuration,
                EventLog::new(),
                resources,
                &[],
                64 * 1024 * 1024,
            )
            .expect("prepare second source");

        nodes
            .validate_retained_hot_fork_template(&first_token)
            .expect("first token remains exact");
        nodes
            .validate_retained_hot_fork_template(&second_token)
            .expect("second token remains exact");
        assert!(
            nodes
                .abort_retained_hot_fork_template(
                    &second,
                    Some(second_token.template_generation()),
                )
                .expect("rollback second source")
        );
        assert!(
            nodes
                .abort_retained_hot_fork_template(&first, Some(first_token.template_generation()),)
                .expect("rollback first source")
        );
        for node in [&first, &second] {
            let source = nodes.nodes.get(node).expect("source remains installed");
            assert!(source.hot_fork_private_ring_stage().is_none());
            assert!(source.hot_fork_child_diagnostic_stage().is_none());
            assert!(source.hot_fork_child_qmp_stage().is_none());
            assert!(source.hot_fork_child_console_stage().is_none());
            assert!(source.hot_fork_plugin_endpoint_stage().is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn partial_source_preparation_failure_releases_transferred_host_resources() {
        let mut nodes = QemuNodeSet::new();
        let node = NodeId {
            name: String::from("node-a"),
        };
        nodes.insert(
            node.clone(),
            crate::node::tests::node_set_hot_fork_source(true)
                .expect("scripted failing QEMU source"),
        );

        let error = nodes
            .prepare_retained_hot_fork_template(
                &node,
                ContentHash::from_bytes(b"partial-source-world"),
                EventLog::new(),
                QemuLaunchResourceRequirements::from_vm_shape(128, 1, true),
                &[],
                64 * 1024 * 1024,
            )
            .expect_err("descriptor installation should fail");
        assert!(
            error
                .to_string()
                .contains("prepare retained hot-fork template")
        );

        assert!(
            nodes
                .abort_retained_hot_fork_template(&node, None)
                .expect("rollback partially prepared source")
        );
        let source = nodes.nodes.get(&node).expect("source remains installed");
        assert!(source.hot_fork_private_ring_stage().is_none());
        assert!(source.hot_fork_child_diagnostic_stage().is_none());
        assert!(source.hot_fork_child_qmp_stage().is_none());
        assert!(source.hot_fork_child_console_stage().is_none());
        assert!(source.hot_fork_plugin_endpoint_stage().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn qmp_abort_cannot_hide_retained_host_side_template_resources() {
        let mut nodes = QemuNodeSet::new();
        let node = NodeId {
            name: String::from("node-a"),
        };
        nodes.insert(
            node.clone(),
            crate::node::tests::node_set_hot_fork_source(false).expect("scripted QEMU source"),
        );
        let token = nodes
            .prepare_retained_hot_fork_template(
                &node,
                ContentHash::from_bytes(b"externally-aborted-source"),
                EventLog::new(),
                QemuLaunchResourceRequirements::from_vm_shape(128, 1, true),
                &[],
                64 * 1024 * 1024,
            )
            .expect("prepare source");
        nodes
            .nodes
            .get_mut(&node)
            .expect("source remains installed")
            .abort_hot_fork_template()
            .expect("simulate an external QMP abort");

        let error = nodes
            .abort_retained_hot_fork_template(&node, Some(token.template_generation()))
            .expect_err("host-side stages must prevent a false reusable result");

        assert!(error.to_string().contains("host-side hot-fork resources"));
        let source = nodes.nodes.get(&node).expect("source remains installed");
        assert!(source.hot_fork_private_ring_stage().is_some());
        assert!(source.hot_fork_child_diagnostic_stage().is_some());
        assert!(source.hot_fork_child_qmp_stage().is_some());
        assert!(source.hot_fork_child_console_stage().is_some());
        assert!(source.hot_fork_plugin_endpoint_stage().is_some());
    }
}
