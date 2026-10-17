//! Node-addressed fault capability, command and continuation channels.
//!
//! These methods authenticate live node membership and preserve transport
//! sequencing. Aggregate occurrence staging remains owned by `fault_events`;
//! lifecycle transitions and native process cleanup retain their own owners.

use super::*;

impl QemuNodeSet {
    /// Reads a realized CPU at its current admitted paused SIM boundary.
    ///
    /// # Errors
    /// Refuses absent or closed nodes, running CPUs and stale native generations.
    pub fn paused_cpu(
        &mut self,
        node: &NodeId,
        vcpu: u32,
        generation: Option<u64>,
    ) -> Result<crate::qmp::QmpPausedCpu, BackendError> {
        if self.permanently_closed.contains(node) {
            return Err(BackendError::Rejected {
                message: format!("QEMU node `{}` is permanently closed", node.name),
            });
        }
        self.nodes
            .get_mut(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU backend set has no node `{}`", node.name),
            })?
            .paused_cpu(vcpu, generation)
            .map_err(BackendError::from)
    }

    /// Reserves host-owned metadata before cloning a node's setup manifest.
    ///
    /// # Errors
    ///
    /// Refuses absent or closed nodes and exhausted independently admitted
    /// host service memory. The returned lease must outlive the metadata.
    #[cfg(target_os = "linux")]
    pub fn reserve_fault_manifest_metadata(
        &self,
        node: &NodeId,
        bytes: u64,
    ) -> Result<crate::QemuFaultManifestMetadataLease, BackendError> {
        if self.permanently_closed.contains(node) {
            return Err(BackendError::Rejected {
                message: format!("QEMU node `{}` is permanently closed", node.name),
            });
        }
        self.nodes
            .get(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU backend set has no node `{}`", node.name),
            })?
            .reserve_fault_manifest_metadata(bytes)
            .map_err(|error| BackendError::Rejected {
                message: format!("reserve authenticated fault manifest metadata: {error}"),
            })
    }

    /// Borrows the register manifest authenticated during one node's setup.
    ///
    /// # Errors
    ///
    /// Refuses absent or permanently closed nodes and missing setup manifests.
    /// It neither guesses capabilities nor creates an independent authority.
    pub fn register_capability_manifest(
        &self,
        node: &NodeId,
    ) -> Result<&crucible_shmem::FaultRegisterCapabilityManifestV1, BackendError> {
        if self.permanently_closed.contains(node) {
            return Err(BackendError::Rejected {
                message: format!("QEMU node `{}` is permanently closed", node.name),
            });
        }
        self.nodes
            .get(node)
            .and_then(QemuNode::register_capability_manifest)
            .ok_or_else(|| BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` has no authenticated setup register manifest",
                    node.name,
                ),
            })
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

    /// Reads one live node's logical fault-command tick, including idle advances.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent, permanently closed,
    /// or its shared-memory hot path cannot be read.
    pub(crate) fn fault_command_tick(&mut self, node: &NodeId) -> Result<u64, BackendError> {
        self.node_mut(node)?
            .current_icount()
            .map(|current| current.retired)
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
}
