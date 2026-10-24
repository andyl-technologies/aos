//! Addressed stopped-generation verification under the receiving original.

use super::*;

impl QemuNodeSet {
    /// Verifies the retained process and stopped runstate without guest execution.
    ///
    /// # Errors
    /// Refuses closed/absent nodes, generation changes, Source failures, QMP
    /// uncertainty, or the same Transfer original's first refusal.
    pub fn verify_stopped_transfer(
        &mut self,
        node: &NodeId,
        expected: &QemuProcessIdentity,
        original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), crate::QemuStoppedTransferError> {
        if self.permanently_closed.contains(node) {
            return Err(crate::QemuStoppedTransferError::Binding);
        }
        self.nodes
            .get_mut(node)
            .ok_or(crate::QemuStoppedTransferError::Binding)?
            .verify_stopped_transfer(expected, original)
    }
}
