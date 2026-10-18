//! Binds current restored capture to the actual admitted administrative attempt.
//!
//! The scope borrows real current owners. It is never constructed from a saved
//! checkpoint, archive reference, row or successful callback. It does not use
//! the original-only collecting capture scope or Host preparation path.

use super::*;
use crate::node_contract::{HostSchedulingSource, NodeRuntime};

/// Borrows genuine current collecting custody for the selected restored codec.
///
/// Its private constructor follows full Window admission. The actual Runtime
/// remains exclusively borrowed by the caller throughout native capture and
/// persistence; neither this scope nor its metadata loans recreate authority.
pub struct RestoredCollectingCaptureScope17<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    graph: &'a crate::node_admission::ConformanceGraph,
    host: &'a HostSchedulingSource,
    world: &'a WorldActivation,
    capture_id: Id,
    slot: usize,
    runtime: *const NodeRuntime,
}

impl<'a> RestoredCollectingCaptureScope17<'a> {
    pub(crate) fn same_graph_data(
        &self,
        graph: &Rc<crate::node_admission::ConformanceGraph>,
    ) -> bool {
        std::ptr::eq(self.graph, graph.as_ref())
    }

    pub(super) fn new(
        window: &'a CompleteOriginalRestorationWindow,
        graph: &'a crate::node_admission::ConformanceGraph,
        host: &'a HostSchedulingSource,
        world: &'a WorldActivation,
        capture_id: Id,
        slot: usize,
        runtime: &NodeRuntime,
    ) -> Result<Self, RuntimeError> {
        let scope = Self {
            window,
            graph,
            host,
            world,
            capture_id,
            slot,
            runtime,
        };
        scope.authenticate_runtime_data(runtime)?;
        Ok(scope)
    }

    /// Borrows the actual opaque collecting plan without ordinary conversion.
    pub fn plan_data(&self) -> &InstalledConformancePlan {
        self.graph.plan()
    }

    /// Borrows the current World, independently of immutable first ancestry.
    pub fn world_data(&self) -> &WorldActivation {
        self.world
    }

    /// Borrows the actual current Host metadata owner without capture delegation.
    pub fn host_data(&self) -> &HostSchedulingSource {
        self.host
    }

    /// Borrows the capture identity retained in the real Window's admitted slot.
    pub fn capture_id_data(&self) -> &Id {
        &self.capture_id
    }

    /// Rechecks current registered members while no native mutable loan is held.
    ///
    /// # Errors
    /// Refuses revoked or foreign plan/Host/Window custody, a changed actual
    /// attempt, unfinished whole observation or missing current activation.
    pub fn authenticate_current_data(&self) -> Result<(), RuntimeError> {
        self.graph
            .authenticate_current_scope()
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
        self.host
            .authenticate_current()
            .map_err(|error| RuntimeError::SchedulerRefused(error.reason))?;
        self.window
            .authenticate_restored_capture_archive_identity_data(
                self.graph.plan(),
                self.world,
                self.slot,
                &self.capture_id,
                self.runtime,
            )
    }

    pub(crate) fn authenticate_runtime_data(
        &self,
        runtime: &NodeRuntime,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(runtime, self.runtime) {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.validate_activation(self.world)?;
        runtime.authenticate_host_scheduling_source(self.host)?;
        self.authenticate_current_data()
    }
}
