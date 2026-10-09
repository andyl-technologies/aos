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
}
