//! Test-support observation of a genuine admitted guest block completion.
//!
//! The existing block worker can retain an authentic request while the node's
//! sole QMP owner observes native map lifetimes. The observer owns its original
//! resource loan and operation guard; it creates no process, mapping, capacity,
//! paused receipt, or guest completion.

use std::sync::Arc;

use crucible::model::ResolvedFaultTarget;
use crucible_device::block::BlockRequestIdentity;
use crucible_linux_resource::host_supervision::HostOperationGuard;

use crate::{QemuAsyncDriverRuntimeError, QemuNodeChannelError, QmpHotForkBlockBarrierState};

/// Observes actual block dispatch and native borrower inventory in test builds.
///
/// Implementations retain their original Service resource loan through the
/// last worker and node borrower. A completion hold polls the same original
/// operation guard without renewing progress or its deadline. The node driver
/// owns every QMP exchange; the block worker never duplicates that connection.
pub trait QemuTestBlockCompletionObserver: Send + Sync {
    /// Holds a request after genuine coordinator admission and before servicing.
    ///
    /// # Errors
    /// Refuses an expired or canceled original scope, or uncertain fixture custody.
    fn before_completion(
        &self,
        target: &ResolvedFaultTarget,
        request: BlockRequestIdentity,
        guest_icount: u64,
    ) -> Result<(), QemuAsyncDriverRuntimeError>;

    /// Returns the same original scope while a native observation is required.
    fn observation_guard(&self) -> Option<Arc<HostOperationGuard>>;

    /// Observes the actual read-only native inventory on the node driver.
    ///
    /// # Errors
    /// Refuses an expired original scope or a contradictory actual observation.
    fn observe_native(
        &self,
        report: &QmpHotForkBlockBarrierState,
    ) -> Result<(), QemuNodeChannelError>;
}
