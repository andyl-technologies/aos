//! Production checkpoint-boundary probes used by executable gates.

use std::time::Duration;

use super::{QemuNode, QemuNodeError};

impl QemuNode {
    /// Probes the real QEMU main-loop device boundary without pausing the VM.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the production host runtime cannot
    /// complete the bounded readiness probe.
    pub(crate) fn probe_checkpoint_device_io_for_gate(
        &mut self,
        timeout: Duration,
    ) -> Result<bool, QemuNodeError> {
        self.host_io_runtime
            .probe_checkpoint_device_io(timeout)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }
}
