//! Boot-barrier access through the setup-owned shared-memory mapping.

use crucible_qemu_shmem::{MappedSetupRegionAccessError, WholeMappingCustodyError};
use thiserror::Error;

use crate::{BootBarrierError, BootBarrierRelease, PluginBootBarrier, PluginReadySetupAck};

use super::PluginSetupCompletion;

impl PluginSetupCompletion {
    /// Waits at the initial scheduler ceiling using this mapping's VM slot.
    ///
    /// The mapping remains owned by this completion while the node-slot
    /// reference is borrowed through the original owner guard. The boot
    /// barrier observes only this node slot and borrows no ring entries.
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
        let mapping = self
            .mapped_region()
            .map_err(|source| PluginSetupBootBarrierError::MappingCustody { source })?;
        let slot = mapping
            .node_slot(slot_index)
            .map_err(|source| PluginSetupBootBarrierError::MappedRegion { source })?;
        PluginBootBarrier::wait(setup_ack, slot)
            .map_err(|source| PluginSetupBootBarrierError::Wait { source })
    }
}

/// An error produced while entering the mapped setup boot barrier.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginSetupBootBarrierError {
    /// The current original mapping owner refused access before any header read.
    #[error("setup boot-barrier mapping custody failed")]
    MappingCustody {
        /// Underlying process or owner-loan refusal.
        source: WholeMappingCustodyError,
    },
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
