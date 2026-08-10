//! Node-addressed production QEMU backend set.
//!
//! The authoritative scheduler advances one selected [`NodeId`] per quantum.
//! [`QemuNodeSet`] preserves that address at the backend boundary and routes
//! steps, inputs, preemptions, fingerprints, debugger requests, and shutdown to
//! the corresponding live [`QemuNode`].

use std::collections::BTreeMap;

use crucible::{
    BackendEffect, BackendError, BackendNetworkOutput, BackendSnapshot, Decision,
    FingerprintSample, GdbAttachInfo, GdbListen, NodeId, ObservableEvent, SimulationBackend,
    StepObservation, VirtualTime,
};
use crucible_protocol::guest_introspection::GuestIntrospectionRecord;
use crucible_shmem::{
    DequeuedFaultEvent, DequeuedFaultResult, FaultCapabilityRowV1, FaultCommandHeaderV1,
};

use crate::QemuNode;
use crate::QemuVmSnapshot;

/// Maximum early-pause reissues for one scheduler-selected node step.
const MAX_STEP_REISSUES: u32 = 64;

/// A deterministic node-addressed collection of live QEMU backends.
pub struct QemuNodeSet {
    nodes: BTreeMap<NodeId, QemuNode>,
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
        }
    }

    /// Inserts a live node under its scheduler identity.
    ///
    /// Returns the prior node when `node` was already present.
    pub fn insert(&mut self, node: NodeId, backend: QemuNode) -> Option<QemuNode> {
        self.nodes.insert(node, backend)
    }

    /// Removes and returns one live node without shutting it down.
    ///
    /// This is used only when a replay lifecycle transfers an oracle-validated
    /// node into the authoritative lifecycle at the same configuration.
    pub fn take(&mut self, node: &NodeId) -> Option<QemuNode> {
        self.nodes.remove(node)
    }

    /// Captures one live node's complete exact snapshot at a completed boundary.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or VMState, host-I/O,
    /// or scheduler-facing continuation capture fails.
    pub fn capture_exact_snapshot(
        &mut self,
        node: &NodeId,
        checkpoint: crucible::Checkpoint,
    ) -> Result<QemuVmSnapshot, BackendError> {
        self.node_mut(node)?
            .capture_exact_snapshot(node, checkpoint)
            .map_err(BackendError::from)
    }

    /// Deletes one exact VMState artifact after an uncommitted capture.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or QMP deletion fails.
    pub fn delete_exact_snapshot(
        &mut self,
        node: &NodeId,
        snapshot: &QemuVmSnapshot,
    ) -> Result<(), BackendError> {
        self.node_mut(node)?
            .delete_exact_snapshot(snapshot)
            .map_err(BackendError::from)
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
        self.nodes
            .get(node)
            .map(QemuNode::fault_capabilities)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU backend set has no node `{}`", node.name),
            })
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
        use crucible_shmem::FaultCommandKind;

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
        let capability_for = |kind| match kind {
            FaultCommandKind::NodeLifecycle => Some("qemu.node.lifecycle.v1"),
            FaultCommandKind::NodeHang => Some("qemu.node.hang.v1"),
            FaultCommandKind::CpuService => Some("qemu.cpu.service.v1"),
            FaultCommandKind::CpuVcpuState => Some("qemu.cpu.vcpu-state.v1"),
            FaultCommandKind::CpuRegisterTransform => Some("qemu.register.mutate.v1"),
            FaultCommandKind::CpuInstructionTransform => Some("qemu.cpu.instruction-transform.v1"),
            FaultCommandKind::CpuException => Some("qemu.cpu.exception.v1"),
            FaultCommandKind::InterruptDisposition => Some("qemu.interrupt.control.v1"),
            FaultCommandKind::InterruptStorm => Some("qemu.interrupt.storm.v1"),
            FaultCommandKind::MemoryMutation => Some("qemu.memory.mutate.v1"),
            FaultCommandKind::MemoryAccessTransform => Some("qemu.memory.access-transform.v1"),
            FaultCommandKind::MemoryEccEvent => Some("qemu.memory.ecc-event.v1"),
            FaultCommandKind::MemoryRegionState => Some("qemu.memory.region-state.v1"),
            FaultCommandKind::MemoryService => Some("qemu.memory.service.v1"),
            FaultCommandKind::ClockTransform => Some("qemu.clock.transform.v1"),
            FaultCommandKind::ClockSourceState => Some("qemu.clock.source-state.v1"),
            FaultCommandKind::AcceleratorLifecycle => Some("qemu.accelerator.lifecycle.v1"),
            FaultCommandKind::AcceleratorResultTransform => {
                Some("qemu.accelerator.result-transform.v1")
            }
            FaultCommandKind::AcceleratorMemoryEvent => Some("qemu.accelerator.memory-event.v1"),
            FaultCommandKind::AcceleratorService => Some("qemu.accelerator.service.v1"),
            FaultCommandKind::QueryCapabilities
            | FaultCommandKind::BoundaryProbe
            | FaultCommandKind::QueryTargetManifest => None,
        };
        let capabilities = common
            .into_iter()
            .filter_map(capability_for)
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

    /// Reads the current execution fingerprint of every live node.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any live node cannot supply an
    /// authenticated shared-memory execution fingerprint.
    pub fn execution_fingerprints(
        &mut self,
    ) -> Result<BTreeMap<NodeId, crucible::ContentHash>, BackendError> {
        self.nodes
            .iter_mut()
            .map(|(node, backend)| {
                backend
                    .execution_fingerprint()
                    .map(|fingerprint| (node.clone(), fingerprint.hash))
                    .map_err(BackendError::from)
            })
            .collect()
    }

    /// Returns the next fault-command sequence of every live node.
    #[must_use]
    pub fn fault_command_sequences(&self) -> BTreeMap<NodeId, u64> {
        self.nodes
            .iter()
            .map(|(node, backend)| (node.clone(), backend.next_fault_command_sequence()))
            .collect()
    }

    /// Returns the next required fault-event sequence of every live node.
    #[must_use]
    pub fn fault_event_sequences(&self) -> BTreeMap<NodeId, u64> {
        self.nodes
            .iter()
            .map(|(node, backend)| (node.clone(), backend.next_fault_event_sequence()))
            .collect()
    }

    /// Restores the per-node command continuation paired with VM snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when node membership differs or a sequence is
    /// invalid for the fault-command ABI.
    pub fn restore_fault_command_sequences(
        &mut self,
        sequences: &BTreeMap<NodeId, u64>,
    ) -> Result<(), BackendError> {
        if self.nodes.keys().ne(sequences.keys()) {
            return Err(BackendError::Rejected {
                message: String::from(
                    "QEMU fault-command checkpoint node membership differs from live nodes",
                ),
            });
        }
        for (node, sequence) in sequences {
            self.node_mut(node)?
                .restore_fault_command_sequence(*sequence)
                .map_err(BackendError::from)?;
        }
        Ok(())
    }

    /// Restores per-node event continuation paired with exact VM snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when membership differs or a sequence is zero.
    pub fn restore_fault_event_sequences(
        &mut self,
        sequences: &BTreeMap<NodeId, u64>,
    ) -> Result<(), BackendError> {
        if self.nodes.keys().ne(sequences.keys()) {
            return Err(BackendError::Rejected {
                message: String::from(
                    "QEMU fault-event checkpoint node membership differs from live nodes",
                ),
            });
        }
        for (node, sequence) in sequences {
            self.node_mut(node)?
                .restore_fault_event_sequence(*sequence)
                .map_err(BackendError::from)?;
        }
        Ok(())
    }

    fn node_mut(&mut self, node: &NodeId) -> Result<&mut QemuNode, BackendError> {
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
        for reissue in 0..=MAX_STEP_REISSUES {
            let mut observation = backend.step_to(ceiling)?;
            if observation.reached == ceiling {
                return Ok(observation);
            }
            if let crucible::AdvanceOutcome::Paused { at } = observation.outcome {
                let idle = backend.idle_state().map_err(BackendError::from)?;
                let Some(deadline) = idle.next_deadline else {
                    return Err(BackendError::Rejected {
                        message: format!(
                            "QEMU node `{}` reported a pause at {} without an idle deadline",
                            node.name, at.retired
                        ),
                    });
                };
                if deadline.retired <= ceiling.ticks {
                    return Err(BackendError::Rejected {
                        message: format!(
                            "QEMU node `{}` paused at {} with deadline {} not beyond ceiling {}",
                            node.name, at.retired, deadline.retired, ceiling.ticks
                        ),
                    });
                }
                observation.reached = ceiling;
                return Ok(observation);
            }
            if observation.reached <= previous {
                return Err(BackendError::Rejected {
                    message: format!(
                        "QEMU node `{}` stalled at {} while stepping to {} after {reissue} reissues",
                        node.name, observation.reached.ticks, ceiling.ticks
                    ),
                });
            }
            previous = observation.reached;
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
        for node in self.nodes.values_mut() {
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
