//! Managed reset requests through the node's existing QMP connection.

use super::*;

impl QemuNode {
    /// Requests a guest reset under the caller's retained original operation.
    ///
    /// The caller owns the completed-write boundary, native process and all
    /// reset/fingerprint reconciliation. An acknowledged command proves only
    /// QMP acceptance, not physical reset completion or loader seed restoration.
    /// This method neither completes the original guard nor starts another one.
    ///
    /// # Errors
    /// Returns the original QMP error for unavailable channel support, original
    /// supervision refusal, command rejection or uncertain response transport.
    pub fn reset_under_original(
        &mut self,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<crate::qmp::QmpCommandComplete, crate::qmp::QmpError> {
        self.channels
            .qmp_machine_control
            .reset_under_original(original)
    }

    /// Forces and reads a fresh execution fingerprint under the original guard.
    ///
    /// A reset can change RAM without advancing icount. This method always
    /// requests a new capture before consulting the shared sample, so an older
    /// same-icount sample cannot satisfy the reset witness. The caller separately
    /// establishes reset completion and a fresh authenticated idle boundary.
    ///
    /// # Errors
    /// Returns the actual capture, supervision or shared-sample error. Unsupported
    /// runtimes refuse before effects; the original operation remains caller-owned.
    pub fn fresh_execution_fingerprint_under_original(
        &mut self,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<ExecutionFingerprint, QemuNodeError> {
        self.host_io_runtime
            .publish_current_execution_fingerprint_under_original(original)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })?;
        let fingerprint = self
            .channels
            .shmem_hot_path
            .execution_fingerprint()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        original.wait_slice().map_err(|source| {
            QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(
                crate::QemuAsyncDriverRuntimeError::operational_supervision(
                    "fresh execution fingerprint",
                    source,
                ),
            ))
        })?;
        Ok(fingerprint)
    }
}
