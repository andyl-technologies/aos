//! Read-only stopped World ownership checks before local durable handoff.
//!
//! These checks neither reconstruct a World from a journal nor establish pager
//! settlement. The actual builder's admitted complete continuation and native
//! floor remain prerequisites, retained inside the opaque owner.

use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationClass, HostOperationGuard, HostSupervisionError,
};

/// Preserves the first refused stopped-World ownership or original observation.
#[derive(Debug, thiserror::Error)]
pub enum ProductionStoppedLifecycleError {
    /// The World has already been physically retired.
    #[error("stopped receiving World is closed")]
    Closed,
    /// Current membership or the retained process manifest differs.
    #[error("stopped receiving process ownership differs")]
    Ownership,
    /// The same Transfer original refused.
    #[error("stopped receiving original refused")]
    Original(#[from] HostSupervisionError),
    /// The actual physical process or QMP observation refused.
    #[error("stopped receiving native observation failed")]
    Native(#[from] crucible_qemu_host::QemuStoppedTransferError),
}

impl ProductionVmStoppedLifecycle {
    /// Verifies the same live native generations and paused runstates.
    ///
    /// Uses read-only QMP under the caller's retained Transfer original. No
    /// fresh preparation scope, stop, resume, scheduler, or ownership capability
    /// is issued. Every live node must still match its retained Linux identity.
    ///
    /// # Errors
    /// Refuses closed custody, original cancellation/expiry, changed process
    /// membership, uncertain RAM Source health or a nonpaused native runstate.
    pub fn verify_stopped(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), ProductionStoppedLifecycleError> {
        original.verify_operation_class(HostOperationClass::Transfer)?;
        let lifecycle = self
            .lifecycle
            .as_mut()
            .ok_or(ProductionStoppedLifecycleError::Closed)?;
        if !lifecycle.run_manifest.staged_processes.is_empty() {
            return Err(ProductionStoppedLifecycleError::Ownership);
        }
        let live_nodes = lifecycle
            .node_service_states
            .values()
            .filter(|state| **state != ProductionNodeServiceState::PermanentlyFailed)
            .count();
        if lifecycle.run_manifest.processes.len() != live_nodes
            || lifecycle.inner.backend().len() != live_nodes
        {
            return Err(ProductionStoppedLifecycleError::Ownership);
        }
        for (node, state) in &lifecycle.node_service_states {
            let owned = lifecycle.inner.backend().contains(node);
            let expected = lifecycle.run_manifest.processes.get(&node.name);
            if *state == ProductionNodeServiceState::PermanentlyFailed {
                if owned || expected.is_some() {
                    return Err(ProductionStoppedLifecycleError::Ownership);
                }
                continue;
            }
            let expected = expected.ok_or(ProductionStoppedLifecycleError::Ownership)?;
            if !owned {
                return Err(ProductionStoppedLifecycleError::Ownership);
            }
            lifecycle
                .inner
                .backend_mut()
                .verify_stopped_transfer(node, expected, original)?;
        }
        original.wait_slice()?;
        Ok(())
    }
}
