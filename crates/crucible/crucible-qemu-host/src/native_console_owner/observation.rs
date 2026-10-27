//! Per-origin semantic projection and transactional observation transfer.
//!
//! Physical acceptance retains a byte before releasing its ring slot. This
//! module transfers that owned byte into the canonical observation stream only
//! after every origin can be projected through its original semantic owner.

use std::sync::Arc;

use crucible_engine::{NativeConsoleByteOrigin, NativeConsoleMappingLease, NodeCounter, NodeId};

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
        admission: &crucible_engine::PreparedRunAdmission,
    ) -> Result<(), ConsoleOwnerError> {
        let mut owner = self.lock()?;
        // One console lifetime never mixes the scheduler and node clocks.
        if owner.standalone_projection {
            return Err(NativeConsoleError::Binding.into());
        }
        let lease = admission.retain_native_console_mapping(owner.logical_generation)?;
        owner.projection = ConsoleProjection::Run(Arc::new(lease));
        Ok(())
    }

    /// Projects later bytes on the node's own clock for a scheduler-free harness.
    ///
    /// Adoption must precede any RUN projection. Bytes accepted before it keep
    /// their boot projection and become visible at genesis.
    pub(crate) fn adopt_standalone_projection(
        &self,
        node: &NodeId,
        ready_counter: NodeCounter,
    ) -> Result<(), ConsoleOwnerError> {
        let mut owner = self.lock()?;
        if owner.standalone_projection || owner.projection != ConsoleProjection::Boot {
            return Err(NativeConsoleError::Binding.into());
        }
        let lease = NativeConsoleMappingLease::standalone(
            node.clone(),
            owner.logical_generation,
            ready_counter,
        );
        owner.projection = ConsoleProjection::Run(Arc::new(lease));
        owner.standalone_projection = true;
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
    ) -> Result<Vec<crucible_engine::ObservableEvent>, ConsoleOwnerError> {
        let mut owner = self.lock()?;
        let projection = owner.projection.clone();
        owner
            .accepted
            .drain_observations(node, ready_counter, &projection)
    }
}
