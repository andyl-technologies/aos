//! Node-addressed disk sealing under retained source process authority.
//!
//! These operations route the exact pause, graph barrier, detached overlay,
//! root seal, and currentness query through the same live node ownership map.

use super::*;

impl QemuNodeSet {
    /// Reads the complete original graph under its prepared template.
    ///
    /// # Errors
    ///
    /// Returns an error when the same live node cannot authenticate the receipt.
    #[cfg(target_os = "linux")]
    pub fn query_hot_fork_source_graph(
        &mut self,
        node: &NodeId,
        expected_qemu_pid: i64,
        expected_template_generation: u64,
    ) -> Result<crate::QmpHotForkSourceGraphReceipt, BackendError> {
        self.node_mut(node)?
            .query_hot_fork_source_graph(expected_qemu_pid, expected_template_generation)
            .map_err(|error| BackendError::Rejected {
                message: format!("query original hot-fork source graph: {error}"),
            })
    }

    /// Pauses a retained source and reads its current writable-root inventory.
    ///
    /// The caller creates detached overlays only after this exact pause and
    /// must keep the same source process through native sealing and PREPARE.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the node cannot stop exactly or QMP cannot
    /// authenticate the current block inventory.
    #[cfg(target_os = "linux")]
    pub fn begin_hot_fork_disk_seal(
        &mut self,
        node: &NodeId,
    ) -> Result<crate::QmpHotForkBlockSealState, BackendError> {
        self.node_mut(node)?
            .pause_for_hot_fork_template()
            .map_err(|error| BackendError::Rejected {
                message: format!("pause hot-fork disk source: {error}"),
            })?;
        self.node_mut(node)?
            .query_hot_fork_block_seal()
            .map_err(|error| BackendError::Rejected {
                message: format!("query current hot-fork disk roots: {error}"),
            })
    }

    /// Opens one caller-owned empty qcow2 file as a detached native node.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the native graph operation fails.
    #[cfg(target_os = "linux")]
    pub fn add_hot_fork_detached_root_overlay(
        &mut self,
        node: &NodeId,
        request: &crate::QmpHotForkBlockSealRequest,
        file_path: &std::path::Path,
    ) -> Result<(), BackendError> {
        self.node_mut(node)?
            .add_hot_fork_detached_root_overlay(request, file_path)
            .map_err(|error| BackendError::Rejected {
                message: format!("add detached hot-fork root overlay: {error}"),
            })
    }

    /// Holds QEMU's native all-block drain and graph-writer barrier.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if QEMU cannot retain the actual barrier.
    #[cfg(target_os = "linux")]
    pub fn hold_hot_fork_disk_seal_barrier(
        &mut self,
        node: &NodeId,
    ) -> Result<crate::QmpHotForkBlockBarrierState, BackendError> {
        self.node_mut(node)?
            .hold_hot_fork_block_barrier()
            .map_err(|error| BackendError::Rejected {
                message: format!("hold hot-fork disk seal barrier: {error}"),
            })
    }

    /// Installs all detached roots and returns the native retained seal.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] on refusal, ambiguity, or mismatched receipt.
    #[cfg(target_os = "linux")]
    pub fn seal_hot_fork_disk_roots(
        &mut self,
        node: &NodeId,
        inventory: &crate::QmpHotForkBlockSealState,
        roots: &[crate::QmpHotForkBlockSealRequest],
    ) -> Result<crate::QmpHotForkBlockSealState, BackendError> {
        self.node_mut(node)?
            .seal_hot_fork_block_roots(inventory, roots)
            .map_err(|error| BackendError::Rejected {
                message: format!("seal current hot-fork disk roots: {error}"),
            })
    }

    /// Rechecks the native seal immediately before PREPARE.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if QMP cannot read a current receipt.
    #[cfg(target_os = "linux")]
    pub fn query_hot_fork_disk_seal(
        &mut self,
        node: &NodeId,
    ) -> Result<crate::QmpHotForkBlockSealState, BackendError> {
        self.node_mut(node)?
            .query_hot_fork_block_seal()
            .map_err(|error| BackendError::Rejected {
                message: format!("recheck current hot-fork disk seal: {error}"),
            })
    }
}
