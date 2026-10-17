//! Test-support retention of authentic guest block completion custody.
//!
//! The observer is attached to the existing admitted block worker and node.
//! It owns its original operation and resource loan, and cannot admit a new
//! process, manufacture a block request, or replace the native QMP owner.

use std::sync::Arc;

use super::ProductionVmLifecycleConfig;

impl ProductionVmLifecycleConfig {
    /// Observes a real admitted block completion without changing guest semantics.
    ///
    /// The existing coordinator authenticates the request before calling the
    /// observer. Pending native observations use that observer's original
    /// Quiescence guard and the node's sole QMP connection.
    #[must_use]
    pub fn with_block_completion_observer_for_test(
        mut self,
        observer: Arc<dyn crucible_qemu::QemuTestBlockCompletionObserver>,
    ) -> Self {
        self.block_completion_observer = Some(observer);
        self
    }
}
