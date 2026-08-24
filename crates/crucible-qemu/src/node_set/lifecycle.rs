//! Transactional QEMU generation replacement and exact-snapshot operations.

use super::*;
use crate::{QemuNodeLifecycleDecision, QemuNodeLifecycleIntent};
use std::sync::Arc;

impl QemuNodeSet {
    /// Atomically replaces or removes a validated set of node generations.
    ///
    /// A `Some` replacement installs a prepared generation; `None` closes the
    /// node permanently. Validation completes before ownership of the current
    /// map changes, and the subsequent map reconstruction has no fallible step.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when a node appears twice or does not name an
    /// authoritative current generation. The node set is unchanged on error.
    pub fn prepare_terminal_replacements(
        &mut self,
        replacements: Vec<NodeId>,
    ) -> Result<QemuNodeTerminalReplacementPlan, BackendError> {
        for (index, node) in replacements.iter().enumerate() {
            if !self.nodes.contains_key(node) {
                return Err(BackendError::Rejected {
                    message: format!(
                        "terminal replacement has no authoritative node `{}`",
                        node.name
                    ),
                });
            }
            if replacements[..index].contains(node) {
                return Err(BackendError::Rejected {
                    message: format!("terminal replacement repeats node `{}`", node.name),
                });
            }
        }
        let mut retired = Vec::new();
        retired
            .try_reserve_exact(replacements.len())
            .map_err(|_| BackendError::Rejected {
                message: String::from("terminal replacement retirement storage is exhausted"),
            })?;
        self.permanently_closed
            .try_reserve_exact(replacements.len())
            .map_err(|_| BackendError::Rejected {
                message: String::from("terminal closed-node storage is exhausted"),
            })?;
        Ok(QemuNodeTerminalReplacementPlan {
            nodes: replacements,
            retired,
        })
    }

    /// Validates that every retiring QEMU generation has been reaped.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when a node is absent or still owns a live or
    /// unreaped child process.
    pub fn validate_terminal_exits_reaped(&self, nodes: &[NodeId]) -> Result<(), BackendError> {
        for node in nodes {
            let backend = self.nodes.get(node).ok_or_else(|| BackendError::Rejected {
                message: format!("terminal exit has no authoritative node `{}`", node.name),
            })?;
            if !backend.child_reaped() {
                return Err(BackendError::Rejected {
                    message: format!(
                        "terminal replacement for `{}` preceded old-child reap",
                        node.name
                    ),
                });
            }
        }
        Ok(())
    }

    /// Releases one installed restored generation from its native QEMU pause.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or QMP cannot resume
    /// the restored guest.
    pub fn resume_restored_generation(&mut self, node: &NodeId) -> Result<(), BackendError> {
        self.node_mut(node)?
            .boot_powered_off_generation()
            .map_err(BackendError::from)
    }

    /// Boots one prepared power-off process generation.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or QMP cannot resume
    /// the restored guest.
    pub fn boot_powered_off_generation(&mut self, node: &NodeId) -> Result<(), BackendError> {
        self.resume_restored_generation(node)
    }

    /// Contains every node named by one owned lifecycle publication batch.
    ///
    /// Decisions and boot requests remain in their preallocated publication
    /// containers, so containment after visible APPLY does not need to build a
    /// second node list. Every named process is attempted even after an earlier
    /// cleanup error.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any present process cannot be killed and
    /// reaped. All named nodes are removed even when one cleanup reports an
    /// error.
    #[cfg(target_os = "linux")]
    pub fn quarantine_terminal_lifecycle_work(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        boot_requests: &[NodeId],
    ) -> Result<(), BackendError> {
        let mut first_error = None;
        for node in decisions
            .iter()
            .map(|decision| &decision.node)
            .chain(boot_requests)
        {
            if let Some(mut backend) = self.nodes.remove(node)
                && let Err(error) = backend.force_quarantine_and_reap()
                && first_error.is_none()
            {
                first_error = Some(error.to_string());
            }
        }
        first_error.map_or(Ok(()), |message| {
            Err(BackendError::Rejected {
                message: format!("terminal lifecycle quarantine failed: {message}"),
            })
        })
    }

    /// Contains every node named by one precommit lifecycle intent batch.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any present process cannot be killed and
    /// reaped. Every named node is attempted even after one cleanup failure.
    #[cfg(target_os = "linux")]
    pub fn quarantine_terminal_lifecycle_intents(
        &mut self,
        intents: &[QemuNodeLifecycleIntent],
    ) -> Result<(), BackendError> {
        let mut first_error = None;
        for intent in intents {
            if let Some(mut backend) = self.nodes.remove(&intent.node)
                && let Err(error) = backend.force_quarantine_and_reap()
                && first_error.is_none()
            {
                first_error = Some(error.to_string());
            }
        }
        first_error.map_or(Ok(()), |message| {
            Err(BackendError::Rejected {
                message: format!("precommit lifecycle quarantine failed: {message}"),
            })
        })
    }

    /// Commits a previously validated terminal generation update.
    ///
    /// This operation has no fallible step. It returns the retired generations
    /// so the caller can verify that terminal-exit supervision reaped them.
    ///
    /// # Panics
    ///
    /// In debug builds, panics when `replacements` does not name exactly the
    /// nodes validated by `plan`.
    #[must_use]
    pub fn commit_terminal_replacements(
        &mut self,
        mut plan: QemuNodeTerminalReplacementPlan,
        replacements: Vec<Option<QemuNode>>,
    ) -> Vec<(NodeId, QemuNode)> {
        debug_assert_eq!(plan.nodes.len(), replacements.len());
        for (node, replacement) in plan.nodes.into_iter().zip(replacements) {
            match replacement {
                Some(replacement) => {
                    let current = self
                        .nodes
                        .get_mut(&node)
                        .map(|current| std::mem::replace(current, replacement));
                    debug_assert!(current.is_some());
                    self.permanently_closed.retain(|closed| closed != &node);
                    if let Some(current) = current {
                        plan.retired.push((node, current));
                    }
                }
                None => {
                    let current = self.nodes.remove_entry(&node);
                    debug_assert!(current.is_some());
                    if let Some(current) = current {
                        plan.retired.push(current);
                    }
                    self.permanently_closed.push(node);
                }
            }
        }
        plan.retired
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

    /// Captures one live node without resuming its intentionally paused process.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or exact continuation
    /// capture fails.
    pub fn capture_exact_snapshot_paused(
        &mut self,
        node: &NodeId,
        checkpoint: crucible::Checkpoint,
    ) -> Result<QemuVmSnapshot, BackendError> {
        self.node_mut(node)?
            .capture_exact_snapshot_paused(node, checkpoint)
            .map_err(BackendError::from)
    }

    /// Captures one terminal lifecycle transition without resuming QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or its exact VMState and
    /// host-I/O continuation cannot be captured at the completed boundary.
    pub fn capture_terminal_lifecycle_snapshot(
        &mut self,
        node: &NodeId,
        checkpoint: crucible::Checkpoint,
    ) -> Result<QemuVmSnapshot, BackendError> {
        self.capture_terminal_lifecycle_snapshot_shared(node, Arc::new(checkpoint))
    }

    /// Captures a terminal transition while sharing immutable scheduler state.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] under the same conditions as
    /// [`Self::capture_terminal_lifecycle_snapshot`].
    pub fn capture_terminal_lifecycle_snapshot_shared(
        &mut self,
        node: &NodeId,
        checkpoint: Arc<crucible::Checkpoint>,
    ) -> Result<QemuVmSnapshot, BackendError> {
        self.node_mut(node)?
            .capture_terminal_lifecycle_snapshot_shared(node, checkpoint)
            .map_err(BackendError::from)
    }

    /// Prevalidates every node in a terminal snapshot batch.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any node is absent or not at the exact
    /// checkpoint boundary. No node is paused or otherwise mutated.
    pub fn prevalidate_terminal_lifecycle_snapshots<'a>(
        &mut self,
        nodes: impl IntoIterator<Item = &'a NodeId>,
        checkpoint: &crucible::Checkpoint,
    ) -> Result<(), BackendError> {
        for node in nodes {
            self.node_mut(node)?
                .prevalidate_terminal_lifecycle_snapshot(node, checkpoint)
                .map_err(BackendError::from)?;
        }
        Ok(())
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
}
