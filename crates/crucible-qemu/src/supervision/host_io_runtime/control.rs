//! Tokenized control-boundary publication and pause rollback.

use std::io::Write;

use super::*;

impl QemuLiveHostIoRuntime {
    /// Attaches an output-only QEMU console reader and its boundary spool.
    ///
    /// The stream is drained during every in-flight advance poll so guest
    /// console backpressure cannot prevent QEMU from reaching its scheduler
    /// ceiling. Bytes remain in `spool` until the node emits them at that exact
    /// completed boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveHostIoRuntimeError::DuplicateConsole`] when a console
    /// is already attached.
    pub(crate) fn with_console_observation(
        mut self,
        reader: QemuConsoleObservationReader,
    ) -> Result<Self, QemuLiveHostIoRuntimeError> {
        if self.console.is_some() {
            return Err(QemuLiveHostIoRuntimeError::DuplicateConsole);
        }
        self.console = Some(reader);
        Ok(self)
    }

    /// Drains all currently available console bytes into boundary staging.
    pub(super) fn service_console_output(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let Some(console) = &mut self.console else {
            return Ok(());
        };
        console.drain_available()
    }

    /// Signals QEMU's plugin wake eventfd with the exact eight-byte counter write.
    pub(super) fn write_wake_doorbell(&self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let mut wake = self.wake.as_ref();
        wake.write_all(&1_u64.to_ne_bytes()).map_err(|error| {
            QemuAsyncDriverRuntimeError::new("signal plugin wake", error.to_string())
        })
    }

    /// Publishes a control request and rings QEMU's main-loop eventfd.
    pub(super) fn signal_wake(&self) -> Result<u32, QemuAsyncDriverRuntimeError> {
        let request = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .request_control_boundary()
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "request plugin control boundary",
                    source.to_string(),
                )
            })?;
        self.write_wake_doorbell()?;
        Ok(request)
    }

    /// Aborts a coordinated pause and wakes both plugin wait mechanisms.
    pub(super) fn abort_checkpoint_pause_with_wake(
        &mut self,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.region.header().clear_pause();
        let futex_result = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)
            .and_then(|slot| {
                slot.wake_for_frame_delivery().map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "resume from checkpoint pause",
                        source.to_string(),
                    )
                })
            });
        let doorbell_result = self.signal_wake();
        match (futex_result, doorbell_result) {
            (Ok(_), Ok(_)) => Ok(()),
            (Err(futex), Ok(_)) => Err(futex),
            (Ok(_), Err(doorbell)) => Err(doorbell),
            (Err(futex), Err(doorbell)) => Err(QemuAsyncDriverRuntimeError::new(
                "resume from checkpoint pause",
                format!("futex wake failed: {futex}; doorbell wake failed: {doorbell}"),
            )),
        }
    }

    /// Releases a failed pause transaction while retaining both diagnostics.
    pub(super) fn fail_checkpoint_pause(
        &mut self,
        primary: QemuAsyncDriverRuntimeError,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        match self.abort_checkpoint_pause_with_wake() {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(QemuAsyncDriverRuntimeError::new(
                "rollback failed checkpoint pause",
                format!("primary failure: {primary}; pause release failure: {cleanup}"),
            )),
        }
    }
}
