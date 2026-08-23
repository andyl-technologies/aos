//! Bounded polling for the dedicated QEMU fault-result transport.

use super::{QemuLiveHostIoRuntime, bounded_poll_attempts};
use crate::QemuAsyncDriverRuntimeError;
use crucible_shmem::{
    BufferedFaultResultPoll, DequeuedFaultResult, dequeue_fault_result_with_buffer,
};
use std::{thread, time::Duration};

impl QemuLiveHostIoRuntime {
    /// Polls the lossless result ring while repeatedly waking QEMU.
    pub(super) fn poll_fault_result(
        &mut self,
        timeout: Duration,
        mut payload_buffer: Vec<u8>,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        if timeout.is_zero() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "await fault result",
                "fault-result timeout is zero",
            ));
        }
        let attempts = bounded_poll_attempts(timeout, self.poll_interval);
        for attempt in 0..attempts {
            self.signal_wake()?;
            let transport = self
                .region
                .fault_result_transport_mut(self.vm_slot)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "map fault-result transport",
                        source.to_string(),
                    )
                })?;
            let result = dequeue_fault_result_with_buffer(
                transport.ring,
                transport.slots,
                transport.arena_header,
                transport.arena,
                transport.arena_region_offset,
                payload_buffer,
            )
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("dequeue fault result", source.to_string())
            })?;
            match result {
                BufferedFaultResultPoll::Pending(buffer) => payload_buffer = buffer,
                BufferedFaultResultPoll::Ready(result) => return Ok(result),
            }
            if attempt + 1 < attempts {
                thread::sleep(self.poll_interval);
            }
        }
        Err(QemuAsyncDriverRuntimeError::new(
            "await fault result",
            format!("no result was published within {timeout:?}"),
        ))
    }
}
