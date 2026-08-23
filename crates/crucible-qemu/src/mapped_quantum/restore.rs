//! Mapped shared-memory state used by exact QEMU restore.

use super::QemuMappedQuantumShmemHotPath;
use crate::QemuNodeChannelError;

impl QemuMappedQuantumShmemHotPath {
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    /// Returns a coherent snapshot of the mapped VM node slot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the configured slot is absent.
    pub(crate) fn node_snapshot(
        &self,
    ) -> Result<crucible_shmem::NodeSlotSnapshot, QemuNodeChannelError> {
        self.region
            .node_slot(self.config.vm_slot)
            .map(|slot| slot.snapshot())
            .map_err(|source| QemuNodeChannelError::new("snapshot node slot", source.to_string()))
    }

    /// Arms the mapped slot for a quiesced VMState restore without waking QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the mapped hot path cannot be
    /// rebound or the restored counter is behind the slot's published counter.
    pub(crate) fn arm_vmstate_restore_ceiling(
        &mut self,
        restored_icount: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.with_hot_path("arm VMState restore ceiling", |hot_path| {
            hot_path
                .arm_vmstate_restore_ceiling(restored_icount)
                .map_err(QemuNodeChannelError::from)
        })
    }

    /// Arms an exact post-VMState logical-time reconstruction boundary.
    ///
    /// The caller must own a natively stopped QEMU process. This publishes the
    /// logical target, advances the request generation, and requests another
    /// plugin pause before QEMU is resumed for the reconstruction callback.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the slot is absent, another restore
    /// request is pending, or the pause wake cannot be published.
    pub(crate) fn arm_logical_time_restore_boundary(
        &mut self,
        target_icount: u64,
    ) -> Result<u32, QemuNodeChannelError> {
        let slot = self
            .region
            .node_slot(self.config.vm_slot)
            .map_err(|source| {
                QemuNodeChannelError::new("arm logical-time restore", source.to_string())
            })?;
        let generation = slot
            .arm_logical_time_restore(target_icount)
            .map_err(|source| {
                QemuNodeChannelError::new("arm logical-time restore", source.to_string())
            })?;
        self.region
            .header()
            .request_pause([slot])
            .map_err(|source| {
                QemuNodeChannelError::new("request logical-time restore pause", source.to_string())
            })?;
        Ok(generation)
    }

    /// Tests whether the plugin acknowledged one exact logical-time restore boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the mapped slot is absent or an
    /// acknowledgement publishes inconsistent logical/raw state.
    pub(crate) fn logical_time_restore_boundary_acknowledged(
        &mut self,
        generation: u32,
        calibration: crate::QemuLogicalTimeCalibration,
    ) -> Result<bool, QemuNodeChannelError> {
        let snapshot = self
            .region
            .node_slot(self.config.vm_slot)
            .map_err(|source| {
                QemuNodeChannelError::new("observe logical-time restore", source.to_string())
            })?
            .snapshot();
        if snapshot.logical_time_restore_ack != generation {
            return Ok(false);
        }
        if snapshot.logical_time_restore_request != generation
            || snapshot.logical_time_restore_target != calibration.logical_icount
            || snapshot.current_icount != calibration.logical_icount
            || snapshot.idle_wake_icount != calibration.logical_icount
            || snapshot.status != crucible_shmem::STATUS_IDLE
            || snapshot.device_io_active != 0
            || snapshot.logical_time_raw_icount != calibration.raw_icount
        {
            return Err(QemuNodeChannelError::new(
                "observe logical-time restore",
                format!("acknowledgement {generation} carried inconsistent boundary: {snapshot:?}"),
            ));
        }
        Ok(true)
    }

    /// Clears the exact post-restore plugin pause while QEMU remains stopped.
    pub(crate) fn clear_logical_time_restore_pause(&mut self) {
        self.region.header().clear_pause();
    }
}
