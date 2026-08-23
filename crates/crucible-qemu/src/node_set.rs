//! Node-addressed production QEMU backend set.
//!
//! The authoritative scheduler advances one selected [`NodeId`] per quantum.
//! [`QemuNodeSet`] preserves that address at the backend boundary and routes
//! steps, inputs, preemptions, fingerprints, debugger requests, and shutdown to
//! the corresponding live [`QemuNode`].

use std::collections::{BTreeMap, BTreeSet};

use crucible::{
    BackendEffect, BackendError, BackendNetworkOutput, BackendSnapshot, Decision,
    FingerprintSample, GdbAttachInfo, GdbListen, Icount, NodeId, ObservableEvent,
    SimulationBackend, StepObservation, VirtualTime,
};
use crucible_protocol::guest_introspection::GuestIntrospectionRecord;
use crucible_shmem::{
    DequeuedFaultEvent, DequeuedFaultResult, FaultCapabilityRowV1, FaultCommandHeaderV1,
    MAX_FRAME_DELIVERY_ATTEMPTS,
};

#[cfg(target_os = "linux")]
use crate::QemuProcessIdentity;
use crate::QemuVmSnapshot;
use crate::{QemuNode, QemuNodeError, QemuNodeIdleState};

#[path = "node_set/lifecycle.rs"]
mod lifecycle;

/// A fully validated, no-fail terminal node-generation map update.
pub struct QemuNodeTerminalReplacementPlan {
    nodes: BTreeSet<NodeId>,
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
    permanently_closed: BTreeSet<NodeId>,
}

/// Exact per-node block state captured around one scheduler boundary.
#[cfg(target_os = "linux")]
pub struct QemuNodeSetBlockBoundaryCheckpoint {
    states: BTreeMap<NodeId, Option<crucible_device::block::BlockFaultState>>,
}

impl QemuNodeSet {
    /// Captures every node's block state before a boundary transaction.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if an authoritative device lock is poisoned.
    #[cfg(target_os = "linux")]
    pub fn checkpoint_block_boundary_state(
        &self,
    ) -> Result<QemuNodeSetBlockBoundaryCheckpoint, BackendError> {
        let states = self
            .nodes
            .iter()
            .map(|(id, node)| {
                node.checkpoint_block_boundary_state()
                    .map(|state| (id.clone(), state))
                    .map_err(BackendError::from)
            })
            .collect::<Result<_, _>>()?;
        Ok(QemuNodeSetBlockBoundaryCheckpoint { states })
    }

    /// Restores every node's exact pre-boundary block state.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when node membership changed or any host-I/O
    /// runtime cannot restore its captured state.
    #[cfg(target_os = "linux")]
    pub fn restore_block_boundary_state(
        &mut self,
        checkpoint: QemuNodeSetBlockBoundaryCheckpoint,
    ) -> Result<(), BackendError> {
        if checkpoint.states.len() != self.nodes.len()
            || checkpoint
                .states
                .keys()
                .any(|id| !self.nodes.contains_key(id))
        {
            return Err(BackendError::Rejected {
                message: String::from("block boundary rollback node membership changed"),
            });
        }
        for (id, state) in checkpoint.states {
            self.nodes
                .get_mut(&id)
                .ok_or_else(|| BackendError::Rejected {
                    message: String::from("block rollback node disappeared"),
                })?
                .restore_block_boundary_state(state)
                .map_err(BackendError::from)?;
        }
        Ok(())
    }

    /// Applies one batch of storage boundary actions to every live coordinator.
    ///
    /// Each coordinator filters the batch by its authenticated World target;
    /// unmatched nodes are unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any matching live adapter fails closed.
    #[cfg(target_os = "linux")]
    pub fn apply_block_boundary_actions(
        &mut self,
        coordinate: crucible::model::FaultCoordinate,
        evaluation_sequence: u64,
        actions: &[crucible::model::ResolvedBindingAction],
    ) -> Result<(), BackendError> {
        let rollback = self.checkpoint_block_boundary_state()?;
        for node in self.nodes.values_mut() {
            if let Err(error) =
                node.apply_block_boundary_actions(coordinate, evaluation_sequence, actions)
            {
                self.restore_block_boundary_state(rollback)?;
                return Err(BackendError::from(error));
            }
        }
        Ok(())
    }

    /// Builds an empty node set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            permanently_closed: BTreeSet::new(),
        }
    }

    /// Inserts a live node under its scheduler identity.
    ///
    /// Returns the prior node when `node` was already present.
    pub fn insert(&mut self, node: NodeId, backend: QemuNode) -> Option<QemuNode> {
        self.permanently_closed.remove(&node);
        self.nodes.insert(node, backend)
    }

    /// Removes and returns one live node without shutting it down.
    ///
    /// This is used only when a replay lifecycle transfers an oracle-validated
    /// node into the authoritative lifecycle at the same configuration.
    pub fn take(&mut self, node: &NodeId) -> Option<QemuNode> {
        self.nodes.remove(node)
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
    pub fn drain_fault_events(
        &mut self,
        drained: &mut BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    ) -> Result<(), BackendError> {
        for (node, backend) in &mut self.nodes {
            backend
                .drain_fault_events(drained.entry(node.clone()).or_default())
                .map_err(BackendError::from)?;
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

    /// Reports whether any node has an event awaiting runtime admission.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any event transport is invalid.
    pub fn has_pending_fault_events(&mut self) -> Result<bool, BackendError> {
        for node in self.nodes.values_mut() {
            if node.fault_event_pending().map_err(BackendError::from)? {
                return Ok(true);
            }
        }
        Ok(false)
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

    pub(crate) fn apply_fault_command_at_current_boundary_with_result_buffer(
        &mut self,
        node: &NodeId,
        header: FaultCommandHeaderV1,
        payload: &[u8],
        result_buffer: Vec<u8>,
    ) -> Result<DequeuedFaultResult, BackendError> {
        self.node_mut(node)?
            .apply_fault_command_at_current_boundary_with_result_buffer(
                header,
                payload,
                result_buffer,
            )
            .map_err(BackendError::from)
    }

    pub(crate) fn apply_fault_preparation_at_current_boundary(
        &mut self,
        node: &NodeId,
        header: FaultCommandHeaderV1,
        payload: &[u8],
        maximum_payload_bytes: usize,
    ) -> Result<DequeuedFaultResult, QemuNodeError> {
        self.nodes
            .get_mut(node)
            .ok_or_else(|| QemuNodeError::fault_command(format!("node {node:?} is absent")))?
            .apply_fault_preparation_at_current_boundary(header, payload, maximum_payload_bytes)
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

    /// Iterates live execution fingerprints without building an intermediate map.
    pub(crate) fn execution_fingerprint_entries(
        &mut self,
    ) -> impl ExactSizeIterator<Item = Result<(&NodeId, crucible::ContentHash), BackendError>> {
        self.nodes.iter_mut().map(|(node, backend)| {
            backend
                .execution_fingerprint()
                .map(|fingerprint| (node, fingerprint.hash))
                .map_err(BackendError::from)
        })
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
}

impl Default for QemuNodeSet {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulationBackend for QemuNodeSet {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        let mut nodes = self.nodes.values_mut();
        let node = nodes.next().ok_or_else(|| BackendError::Rejected {
            message: String::from("QEMU backend set cannot step without a node"),
        })?;
        if nodes.next().is_some() {
            return Err(BackendError::Unsupported {
                capability: "backend-global step on a multi-node QEMU set",
            });
        }
        node.step_to(ceiling)
    }

    fn step_node_to(
        &mut self,
        node: &NodeId,
        ceiling: VirtualTime,
    ) -> Result<StepObservation, BackendError> {
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
    use crucible::{AdvanceOutcome, Icount};

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
}
