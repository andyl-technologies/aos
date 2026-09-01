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
        let serviced = match &mut block.coordinator {
            Some(coordinator) => {
                coordinator.service_block_io(&mut block.servicer, snapshot.current_icount)?
            }
            None => block
                .servicer
                .service(snapshot.current_icount)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new("service block io", source.to_string())
                })?,
        };
        block.diagnostics.record(
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

    /// Services the 9p ring at the guest's observed coordinate, if attached.
    pub(super) fn service_ninep_io(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let Some(ninep) = &mut self.ninep else {
            return Ok(false);
        };
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
