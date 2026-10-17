//! Live storage-service attachment and scheduler-boundary fault rollback.
//!
//! These node adapters retain the existing host-I/O service as the authority
//! for block diagnostics, fault coordinators, and uncommitted boundary state.

use super::{QemuNode, QemuNodeError};
use crucible::model::{FaultCoordinate, ResolvedBindingAction};

impl QemuNode {
    /// Returns this node's authoritative live block-device handle, when present.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn shared_block_device(&self) -> Option<crate::QemuSharedBlockDevice> {
        self.host_io_runtime.shared_block_device()
    }

    /// Returns accumulated diagnostics for the live block-service path.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn block_io_diagnostics(&self) -> Option<crate::BlockIoDiagnosticsSnapshot> {
        self.host_io_runtime.block_io_diagnostics()
    }

    /// Captures block state for rollback of an uncommitted scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the host-I/O runtime cannot capture the
    /// complete block-fault continuation.
    #[cfg(target_os = "linux")]
    pub fn checkpoint_block_boundary_state(
        &self,
    ) -> Result<Option<crucible_device::block::BlockFaultState>, QemuNodeError> {
        self.host_io_runtime
            .checkpoint_block_boundary_state()
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    /// Restores block state captured before an uncommitted scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the host-I/O runtime cannot restore the
    /// captured topology and state exactly.
    #[cfg(target_os = "linux")]
    pub fn restore_block_boundary_state(
        &mut self,
        state: Option<crucible_device::block::BlockFaultState>,
    ) -> Result<(), QemuNodeError> {
        self.host_io_runtime
            .restore_block_boundary_state(state)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    /// Applies storage-targeted actions through this node's live block adapter.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the coordinator rejects the boundary.
    #[cfg(target_os = "linux")]
    pub fn apply_block_boundary_actions(
        &mut self,
        coordinate: FaultCoordinate,
        evaluation_sequence: u64,
        actions: &[ResolvedBindingAction],
    ) -> Result<(), QemuNodeError> {
        self.host_io_runtime
            .apply_block_boundary_actions(coordinate, evaluation_sequence, actions)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    /// Installs the production signal coordinator for this node's block device.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the host-I/O runtime has no attached block
    /// servicer or already owns a coordinator.
    #[cfg(target_os = "linux")]
    pub fn install_block_fault_coordinator(
        &mut self,
        coordinator: Box<dyn crate::QemuBlockFaultCoordinator>,
    ) -> Result<(), QemuNodeError> {
        self.host_io_runtime
            .install_block_fault_coordinator(coordinator)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    /// Installs the production signal coordinator for this node's 9p device.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the host-I/O runtime has no attached 9p
    /// servicer or already owns a coordinator.
    #[cfg(target_os = "linux")]
    pub fn install_ninep_fault_coordinator(
        &mut self,
        coordinator: Box<dyn crate::QemuNinepFaultCoordinator>,
    ) -> Result<(), QemuNodeError> {
        self.host_io_runtime
            .install_ninep_fault_coordinator(coordinator)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }
}
