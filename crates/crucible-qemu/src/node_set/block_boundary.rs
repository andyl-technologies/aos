//! Transactional block-device state around one scheduler boundary.

use super::*;

/// Exact per-node block state captured around one scheduler boundary.
pub struct QemuNodeSetBlockBoundaryCheckpoint {
    states: BTreeMap<NodeId, Option<crucible_device::block::BlockFaultState>>,
}

impl QemuNodeSet {
    /// Captures every node's block state before a boundary transaction.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if an authoritative device lock is poisoned.
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
}
