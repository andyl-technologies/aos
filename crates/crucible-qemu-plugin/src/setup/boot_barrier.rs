//! Boot-barrier access through the setup-owned shared-memory mapping.

use crucible_shmem::{MappedSetupRegionAccessError, ReservedExecutorSlot};
use thiserror::Error;

use crate::{BootBarrierError, BootBarrierRelease, PluginBootBarrier, PluginReadySetupAck};

use super::PluginSetupCompletion;

impl PluginSetupCompletion {
    /// Waits at the initial scheduler ceiling using this mapping's VM slot.
    ///
    /// The mapping remains owned by this completion while the node-slot
    /// reference is borrowed. Two distinct canonical outbound rings are used
    /// only to obtain the shared mapping's typed node view; their contents are
    /// not accessed by the boot barrier.
    ///
    /// # Errors
    ///
    /// Returns [`PluginSetupBootBarrierError`] when the slot or canonical ring
    /// topology cannot be borrowed or the scheduler ceiling wait fails.
    pub fn wait_boot_barrier(
        &mut self,
        setup_ack: PluginReadySetupAck,
        slot_index: u32,
    ) -> Result<BootBarrierRelease, PluginSetupBootBarrierError> {
        let net_slot = u32::try_from(ReservedExecutorSlot::NetRouter.slot())
            .map_err(|_error| PluginSetupBootBarrierError::ExecutorSlotOutOfRange)?;
        let block_slot = u32::try_from(ReservedExecutorSlot::BlockIo.slot())
            .map_err(|_error| PluginSetupBootBarrierError::ExecutorSlotOutOfRange)?;
        let mapped = self
            .mapped_region
            .node_directed_ring_pair_mut(slot_index, slot_index, net_slot, slot_index, block_slot)
            .map_err(|source| PluginSetupBootBarrierError::MappedRegion { source })?;
        PluginBootBarrier::wait(setup_ack, mapped.node_slot)
            .map_err(|source| PluginSetupBootBarrierError::Wait { source })
    }
}

/// An error produced while entering the mapped setup boot barrier.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginSetupBootBarrierError {
    /// The mapped region could not provide the requested VM slot and ring view.
    #[error("setup mapping cannot provide boot-barrier node slot")]
    MappedRegion {
        /// Underlying mapped-region access error.
        source: MappedSetupRegionAccessError,
    },
    /// A reserved executor slot did not fit the shared-memory wire type.
    #[error("reserved executor slot does not fit u32")]
    ExecutorSlotOutOfRange,
    /// The scheduler ceiling wait failed.
    #[error("setup boot barrier failed")]
    Wait {
        /// Underlying boot-barrier failure.
        source: BootBarrierError,
    },
}
