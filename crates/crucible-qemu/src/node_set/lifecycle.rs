//! Transactional QEMU generation replacement and exact-snapshot operations.

use super::*;

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
        &self,
        replacements: &[NodeId],
    ) -> Result<QemuNodeTerminalReplacementPlan, BackendError> {
        let mut staged = BTreeSet::new();
        for node in replacements {
            if !self.nodes.contains_key(node) {
                return Err(BackendError::Rejected {
                    message: format!(
                        "terminal replacement has no authoritative node `{}`",
                        node.name
                    ),
                });
            }
            if !staged.insert(node.clone()) {
                return Err(BackendError::Rejected {
                    message: format!("terminal replacement repeats node `{}`", node.name),
                });
            }
        }

        Ok(QemuNodeTerminalReplacementPlan { nodes: staged })
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

    /// Boots one prepared power-off process generation.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or QMP cannot resume
    /// the restored guest.
    pub fn boot_powered_off_generation(&mut self, node: &NodeId) -> Result<(), BackendError> {
        self.node_mut(node)?
            .boot_powered_off_generation()
            .map_err(BackendError::from)
    }

    /// Contains and removes a set of indeterminate QEMU generations.
    ///
    /// Each process still present is force-killed and synchronously reaped;
    /// graceful control paths are intentionally not used for an ambiguous
    /// lifecycle transaction. An already removed generation is already
    /// contained and is therefore idempotently accepted.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any present process cannot be killed and
    /// reaped. All named nodes are removed even when one cleanup reports an
    /// error.
    #[cfg(target_os = "linux")]
    pub fn quarantine_terminal_nodes(&mut self, nodes: &[NodeId]) -> Result<(), BackendError> {
        let mut first_error = None;
        for node in nodes {
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
        plan: QemuNodeTerminalReplacementPlan,
        mut replacements: BTreeMap<NodeId, Option<QemuNode>>,
    ) -> Vec<(NodeId, QemuNode)> {
        debug_assert_eq!(plan.nodes, replacements.keys().cloned().collect());
        let current = std::mem::take(&mut self.nodes);
        let mut retired = Vec::with_capacity(replacements.len());
        for (node, backend) in current {
            match replacements.remove(&node) {
                Some(Some(replacement)) => {
                    retired.push((node.clone(), backend));
                    self.permanently_closed.remove(&node);
                    self.nodes.insert(node, replacement);
                }
                Some(None) => {
                    self.permanently_closed.insert(node.clone());
                    self.nodes.insert(node, backend);
                }
                None => {
                    self.nodes.insert(node, backend);
                }
            }
        }
        debug_assert!(replacements.is_empty());
        retired
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

    /// Captures a running node and leaves successful source artifacts paused.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or exact continuation
    /// capture fails. A determinate pre-save failure resumes the running node.
    pub fn capture_exact_snapshot_for_publication(
        &mut self,
        node: &NodeId,
        checkpoint: crucible::Checkpoint,
    ) -> Result<QemuVmSnapshot, BackendError> {
        self.node_mut(node)?
            .capture_exact_snapshot_for_publication(node, checkpoint)
            .map_err(BackendError::from)
    }

    /// Resumes one running node after paused exact-artifact publication.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the node is absent or QMP cannot confirm
    /// the running-state transition.
    pub fn resume_after_exact_snapshot(&mut self, node: &NodeId) -> Result<(), BackendError> {
        self.node_mut(node)?
            .resume_after_exact_snapshot()
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
        self.node_mut(node)?
            .capture_terminal_lifecycle_snapshot(node, checkpoint)
            .map_err(BackendError::from)
    }

    /// Prevalidates every node in a terminal snapshot batch.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any node is absent or not at the exact
    /// checkpoint boundary. No node is paused or otherwise mutated.
    pub fn prevalidate_terminal_lifecycle_snapshots(
        &mut self,
        nodes: &[NodeId],
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
