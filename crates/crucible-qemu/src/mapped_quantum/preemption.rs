//! Scheduler-to-plugin preemption mailbox operations.

use crucible_shmem::SchedulerPreemptionCommand;

use super::{QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError};

impl QemuMappedQuantumShmemHotPath {
    /// Publishes one scheduler-commanded preemption to the live plugin.
    ///
    /// The command must be published before the RUN that owns its authorization
    /// ceiling. The plugin acknowledges the returned sequence only after patched
    /// QEMU accepts the exact-icount injection.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] when the configured slot
    /// is absent, the command window is invalid, or a prior command remains
    /// unconsumed.
    pub fn publish_preemption_command(
        &self,
        command: SchedulerPreemptionCommand,
    ) -> Result<u32, QemuMappedQuantumShmemHotPathError> {
        self.region
            .node_slot(self.config.vm_slot)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?
            .publish_preemption_command(command)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::PreemptionMailbox { source })
    }

    /// Returns the latest preemption sequence acknowledged by the live plugin.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] when the configured slot
    /// is absent.
    pub fn consumed_preemption_sequence(&self) -> Result<u32, QemuMappedQuantumShmemHotPathError> {
        self.region
            .node_slot(self.config.vm_slot)
            .map(|slot| slot.consumed_preemption_sequence())
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })
    }
}
