//! Installs a shared test observer on one actual admitted guest node.

use super::*;

impl QemuNodeSet {
    /// Retains an observer beside the exact node's existing worker and channels.
    ///
    /// # Errors
    /// Refuses an absent node, missing original admission, or an existing observer.
    pub fn install_block_completion_observer_for_test(
        &mut self,
        node: &NodeId,
        observer: std::sync::Arc<dyn crate::QemuTestBlockCompletionObserver>,
    ) -> Result<(), BackendError> {
        self.node_mut(node)?
            .install_block_completion_observer_for_test(observer)
            .map_err(BackendError::from)
    }
}
