//! Host-side servicing for live block, 9p, and accelerator device rings.

use super::*;

impl QemuLiveHostIoRuntime {
    /// Services the block-I/O ring at the guest's observed icount, if attached.
    pub(super) fn service_block_io(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let Some(block) = &mut self.block else {
            return Ok(false);
        };
        block.diagnostics.observe_slot(
            snapshot.current_icount,
            snapshot.device_io_active != 0,
            snapshot.idle_wake_icount,
            snapshot.control_boundary_ack,
        );
        if !block.worker.work_in_flight() {
            let pin = block
                .worker
                .pin_next_request_completion()
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new("pin block host work", source.to_string())
                })?;
            if !block.coordinator_required {
                block
                    .worker
                    .dispatch(
                        snapshot.current_icount,
                        crate::QemuDeviceHostWorkDelay::None,
                    )
                    .map_err(|source| {
                        QemuAsyncDriverRuntimeError::new(
                            "dispatch block host work",
                            source.to_string(),
                        )
                    })?;
                if pin.observed.is_none() {
                    return Ok(false);
                }
            } else {
                block
                    .worker
                    .dispatch_coordinated(snapshot.current_icount)
                    .map_err(|source| {
                        QemuAsyncDriverRuntimeError::new(
                            "dispatch coordinated block host work",
                            source.to_string(),
                        )
                    })?;
            }
        }
        let Some(serviced) = block.worker.try_complete().map_err(|source| {
            QemuAsyncDriverRuntimeError::new("complete block host work", source.to_string())
        })?
        else {
            return Ok(false);
        };
        block.diagnostics.record(
            snapshot.current_icount,
            snapshot.device_io_active != 0,
            snapshot.idle_wake_icount,
            snapshot.control_boundary_ack,
            &serviced,
        );
        let made_progress = serviced.processed > 0 || serviced.delivered > 0;
        if made_progress {
            self.write_wake_doorbell()?;
        }
        Ok(made_progress)
    }

    /// Services the 9p ring at the guest's observed coordinate, if attached.
    pub(super) fn service_ninep_io(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let Some(ninep) = &mut self.ninep else {
            return Ok(false);
        };
        if ninep.coordinator_required && ninep.coordinator.is_none() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "service 9p io",
                "branch-private 9p continuation requires a fresh signal coordinator",
            ));
        }
        let serviced = match &mut ninep.coordinator {
            Some(coordinator) => {
                coordinator.service_ninep_io(&mut ninep.servicer, snapshot.current_icount)?
            }
            None => ninep
                .servicer
                .service(snapshot.current_icount)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new("service 9p io", source.to_string())
                })?,
        };
        ninep.diagnostics.record(
            snapshot.current_icount,
            snapshot.device_io_active != 0,
            snapshot.idle_wake_icount,
            &serviced,
        );
        let made_progress = serviced.processed > 0 || serviced.delivered > 0;
        if made_progress {
            self.write_wake_doorbell()?;
        }
        Ok(made_progress)
    }

    /// Services the accelerator ring at the guest's observed coordinate.
    pub(super) fn service_accelerator_io(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let Some(accelerator) = &mut self.accelerator else {
            return Ok(false);
        };
        let serviced = accelerator
            .service(snapshot.current_icount)
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("service accelerator io", source.to_string())
            })?;
        let made_progress = serviced.processed > 0 || serviced.delivered > 0;
        if made_progress {
            self.write_wake_doorbell()?;
        }
        Ok(made_progress)
    }
}
