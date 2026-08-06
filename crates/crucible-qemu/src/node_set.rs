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
use crucible_shmem::{DequeuedFaultResult, FaultCapabilityRowV1, FaultCommandHeaderV1};

use crate::QemuNode;

/// Maximum early-pause reissues for one scheduler-selected node step.
const MAX_STEP_REISSUES: u32 = 64;

/// A deterministic node-addressed collection of live QEMU backends.
pub struct QemuNodeSet {
    nodes: BTreeMap<NodeId, QemuNode>,
}

impl QemuNodeSet {
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
