//! Mapped shared-memory state used by exact QEMU restore.

use super::QemuMappedQuantumShmemHotPath;
use crate::QemuNodeChannelError;

/// Paired plugin generations for one stopped-state logical-time restore.
#[derive(Clone, Copy)]
pub(crate) struct QemuLogicalTimeRestoreBoundary {
    logical_generation: u32,
    control_request: u32,
    fault_command_frontier: u64,
    backing: crucible_shmem::SetupRegionBackingIdentity,
    vm_slot: u32,
}

impl QemuLogicalTimeRestoreBoundary {
    pub(crate) fn from_console_publication(
        publication: crate::native_console_owner::ConsoleRestorePublication,
        backing: crucible_shmem::SetupRegionBackingIdentity,
        vm_slot: u32,
    ) -> Self {
        Self {
            logical_generation: publication.generation(),
            control_request: publication.request(),
            fault_command_frontier: publication.fault_frontier(),
            backing,
            vm_slot,
        }
    }

    pub(crate) const fn logical_generation(self) -> u32 {
        self.logical_generation
    }

    pub(crate) const fn control_request(self) -> u32 {
        self.control_request
    }

    pub(crate) fn validate_console_frontier(
        self,
        backing: crucible_shmem::SetupRegionBackingIdentity,
        frontier: crucible_protocol::native_console::NativeConsoleFrontier,
        paired: crucible_protocol::native_console::NativeConsoleClamp,
        live: crucible_shmem::NodeSlotSnapshot,
        calibration: crate::QemuLogicalTimeCalibration,
    ) -> Result<(), crucible_protocol::native_console::NativeConsoleError> {
        use crucible_protocol::native_console::NativeConsoleError;

        if self.backing != backing
            || frontier.owner.slot != self.vm_slot
            || live.control_boundary_ack != self.control_request.wrapping_add(1)
            || paired.request != self.control_request
            || paired.capture != 0
            || live.control_boundary_capture_request != 0
            || paired.fault_frontier != self.fault_command_frontier
            || live.control_boundary_fault_command_frontier != self.fault_command_frontier
            || live.logical_time_restore_request != self.logical_generation
            || live.logical_time_restore_ack != self.logical_generation
            || live.logical_time_restore_target != calibration.logical_icount
            || live.current_icount != calibration.logical_icount
            || live.idle_wake_icount != calibration.logical_icount
            || live.logical_time_raw_icount != calibration.raw_icount
            || live.publish_gen & 1 != 0
            || live.status != crucible_shmem::STATUS_IDLE
            || live.device_io_active != 0
            || live.advance_publication_sequence != paired.advance
            || live.max_advance_icount != paired.ceiling
            || paired.ceiling < calibration.logical_icount
            || frontier.request != paired.request
            || frontier.accepted_advance != paired.advance
            || frontier.logical_ps != calibration.logical_icount
            || frontier.raw_prefix != calibration.raw_icount
            || paired.last_issued.is_none_or(|body| {
                body.phase != crucible_protocol::native_console::NativeConsolePhase::Restore
                    || body.phase_token != u64::from(self.logical_generation)
                    || body.advance != paired.advance
            })
        {
            return Err(NativeConsoleError::Binding);
        }
        Ok(())
    }

    pub(crate) fn acknowledged(
        self,
        snapshot: crucible_shmem::NodeSlotSnapshot,
        calibration: crate::QemuLogicalTimeCalibration,
    ) -> Result<bool, QemuNodeChannelError> {
        if snapshot.control_boundary_fault_command_frontier != self.fault_command_frontier
            || snapshot.control_boundary_capture_request != 0
        {
            return Err(QemuNodeChannelError::new(
                "observe logical-time restore",
                format!("control boundary changed its bound frontier: {snapshot:?}"),
            ));
        }
        if snapshot.control_boundary_ack == self.control_request {
            return Ok(false);
        }
        if snapshot.control_boundary_ack != self.control_request.wrapping_add(1) {
            return Err(QemuNodeChannelError::new(
                "observe logical-time restore",
                format!("control boundary changed before restore ACK: {snapshot:?}"),
            ));
        }
        if snapshot.logical_time_restore_ack != self.logical_generation {
            return Ok(false);
        }
        if snapshot.logical_time_restore_request != self.logical_generation
            || snapshot.logical_time_restore_target != calibration.logical_icount
            || snapshot.current_icount != calibration.logical_icount
            || snapshot.idle_wake_icount != calibration.logical_icount
            || snapshot.status != crucible_shmem::STATUS_IDLE
            || snapshot.device_io_active != 0
            || snapshot.logical_time_raw_icount != calibration.raw_icount
        {
            return Err(QemuNodeChannelError::new(
                "observe logical-time restore",
                format!(
                    "acknowledgement {} carried inconsistent boundary: {snapshot:?}",
                    self.logical_generation
                ),
            ));
        }
        Ok(true)
    }
}

impl QemuMappedQuantumShmemHotPath {
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
    /// logical target and a paired control request so the subsequent eventfd
    /// wake can reconstruct time in QEMU's stopped main-loop callback.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the slot is absent, a prior control
    /// or restore request is pending, or the pause wake cannot be published.
    pub(crate) fn arm_logical_time_restore_boundary(
        &mut self,
        target_icount: u64,
    ) -> Result<QemuLogicalTimeRestoreBoundary, QemuNodeChannelError> {
        let slot = self
            .region
            .node_slot(self.config.vm_slot)
            .map_err(|source| {
                QemuNodeChannelError::new("arm logical-time restore", source.to_string())
            })?;
        if slot.control_boundary_is_requested() {
            return Err(QemuNodeChannelError::new(
                "arm logical-time restore",
                "another plugin control boundary is still pending",
            ));
        }
        let frontier = self
            .region
            .fault_command_write_index(self.config.vm_slot)
            .map_err(|source| {
                QemuNodeChannelError::new("bind logical-time restore frontier", source.to_string())
            })?;
        let logical_generation =
            slot.arm_logical_time_restore(target_icount)
                .map_err(|source| {
                    QemuNodeChannelError::new("arm logical-time restore", source.to_string())
                })?;
        self.region
            .header()
            .request_pause([slot])
            .map_err(|source| {
                QemuNodeChannelError::new("request logical-time restore pause", source.to_string())
            })?;
        // A stopped QEMU cannot enter a vCPU callback. The eventfd wake only
        // dispatches the plugin's control callback when its slot has an even
        // outstanding request bound to the current fault-command frontier.
        let control_request = slot
            .request_control_boundary(frontier, None)
            .map_err(|source| {
                QemuNodeChannelError::new(
                    "request logical-time restore control boundary",
                    source.to_string(),
                )
            })?;
        Ok(QemuLogicalTimeRestoreBoundary {
            logical_generation,
            control_request,
            fault_command_frontier: frontier,
            backing: self.region.backing_identity(),
            vm_slot: self.config.vm_slot,
        })
    }

    /// Pairs a loaded console continuation before both original restore releases.
    pub(crate) fn arm_console_logical_time_restore_boundary(
        &mut self,
        target_icount: u64,
        saved: &crate::native_console_owner::ConsoleOriginContinuation,
        loaded: crate::qmp::QmpCheckpointRestore,
        expected: crate::qmp::QmpCheckpointIdentity,
    ) -> Result<QemuLogicalTimeRestoreBoundary, QemuNodeChannelError> {
        let custody = self.console_custody.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new("arm console restore", "original console setup is absent")
        })?;
        self.region
            .header()
            .request_pause([self
                .region
                .node_slot(self.config.vm_slot)
                .map_err(|source| {
                    QemuNodeChannelError::new("pause console restore", source.to_string())
                })?])
            .map_err(|source| {
                QemuNodeChannelError::new("pause console restore", source.to_string())
            })?;
        let publication = custody
            .arm_stopped_restore(
                &self.region,
                &self.config.node,
                saved,
                loaded,
                expected,
                target_icount,
            )
            .map_err(|source| {
                QemuNodeChannelError::new("arm console restore", source.to_string())
            })?;
        Ok(QemuLogicalTimeRestoreBoundary {
            logical_generation: publication.generation(),
            control_request: publication.request(),
            fault_command_frontier: publication.fault_frontier(),
            backing: self.region.backing_identity(),
            vm_slot: self.config.vm_slot,
        })
    }

    /// Takes an empty restored prefix only after its exact native restore ACK.
    pub(crate) fn accept_console_logical_time_restore(
        &self,
        boundary: QemuLogicalTimeRestoreBoundary,
        calibration: crate::QemuLogicalTimeCalibration,
    ) -> Result<(), QemuNodeChannelError> {
        if let Some(custody) = &self.console_custody {
            custody
                .accept_restored(&self.region, boundary, calibration)
                .map_err(|source| {
                    QemuNodeChannelError::new("accept console restore", source.to_string())
                })?;
        }
        Ok(())
    }

    /// Tests whether the plugin acknowledged one exact logical-time restore boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the mapped slot is absent or an
    /// acknowledgement publishes inconsistent logical/raw state.
    pub(crate) fn logical_time_restore_boundary_acknowledged(
        &mut self,
        boundary: QemuLogicalTimeRestoreBoundary,
        calibration: crate::QemuLogicalTimeCalibration,
    ) -> Result<bool, QemuNodeChannelError> {
        let snapshot = self
            .region
            .node_slot(self.config.vm_slot)
            .map_err(|source| {
                QemuNodeChannelError::new("observe logical-time restore", source.to_string())
            })?
            .try_snapshot()
            .ok_or_else(|| {
                QemuNodeChannelError::publication_unavailable("observe logical-time restore")
            })?;
        boundary.acknowledged(snapshot, calibration)
    }

    /// Clears the exact post-restore plugin pause while QEMU remains stopped.
    pub(crate) fn clear_logical_time_restore_pause(&mut self) {
        self.region.header().clear_pause();
    }
}
