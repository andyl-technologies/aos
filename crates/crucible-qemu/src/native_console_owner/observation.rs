//! Per-origin semantic projection and transactional observation transfer.
//!
//! Physical acceptance retains a byte before releasing its ring slot. This
//! module transfers that owned byte into the canonical observation stream only
//! after every origin can be projected through its original semantic owner.

use std::sync::Arc;

use crucible::{NativeConsoleByteOrigin, NativeConsoleMappingLease, NodeCounter, NodeId};

use super::*;

/// Host visibility, independent of native execution and prefix authority.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) enum ConsoleProjection {
    Boot,
    Run(Arc<NativeConsoleMappingLease>),
}

/// Couples a canonical byte with the immutable map of its actual emission RUN.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct RetainedConsoleByte {
    pub(super) origin: NativeConsoleByteOrigin,
    pub(super) projection: ConsoleProjection,
}

impl ConsoleLaunchCustody {
    /// Captures the original semantic RUN map before guest publication begins.
    pub(crate) fn retain_run_projection(
        &self,
        admission: &crucible::PreparedRunAdmission,
    ) -> Result<(), ConsoleOwnerError> {
        let mut owner = self.lock()?;
        let lease = admission.retain_native_console_mapping(owner.logical_generation)?;
        owner.projection = ConsoleProjection::Run(Arc::new(lease));
        Ok(())
    }

    /// Transfers complete projected origins while preserving custody on refusal.
    ///
    /// Boot visibility comes from the same sealed RUN's retained original
    /// ready-point map. No latest counter, poll floor or physical restore ACK
    /// changes either the original emission payload or a retained RUN map.
    pub(crate) fn drain_observations(
        &self,
        node: &NodeId,
        ready_counter: NodeCounter,
    ) -> Result<Vec<crucible::ObservableEvent>, ConsoleOwnerError> {
        let mut owner = self.lock()?;
        let projection = owner.projection.clone();
        owner
            .accepted
            .drain_observations(node, ready_counter, &projection)
    }
}
