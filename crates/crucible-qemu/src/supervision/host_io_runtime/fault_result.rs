//! Bounded polling for the dedicated QEMU fault-result transport.

use super::{
    QemuLiveHostIoRuntime, bounded_poll_attempts, control_boundary_request_is_acknowledged,
};
use crate::QemuAsyncDriverRuntimeError;
use crucible_shmem::{
    BufferedFaultResultPoll, DequeuedFaultResult, FaultTransportError,
    dequeue_fault_result_with_buffer,
};
use std::{thread, time::Duration};

pub(super) fn admit_fault_preparation_result(
    requested: usize,
    maximum_payload_bytes: usize,
) -> Result<(), QemuAsyncDriverRuntimeError> {
    if requested > maximum_payload_bytes {
        return Err(QemuAsyncDriverRuntimeError::fault_result_storage(
            requested,
            maximum_payload_bytes,
        ));
    }
    Ok(())
}

impl QemuLiveHostIoRuntime {
    /// Waits until the callback that published a result has finished its pump.
    ///
    /// Result and occurrence-event rings are distinct lossless transports. The
    /// plugin publishes results first, then events, and only then release-acks
    /// the control request. Observing the result alone therefore does not prove
    /// that the corresponding event is visible yet. This acquire-side fence
    /// prevents callers from draining an apparently empty event ring in that
    /// publication window.
    fn await_fault_pump_completion(
        &mut self,
        request: u32,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let attempts = bounded_poll_attempts(timeout, self.poll_interval);
        let mut last_ack = None;
        for attempt in 0..attempts {
            self.service_console_output()?;
            let snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(super::map_slot_error)?
                .snapshot();
            last_ack = Some(snapshot.control_boundary_ack);
            if control_boundary_request_is_acknowledged(request, &snapshot) {
                return Ok(());
            }
            if attempt + 1 < attempts {
                if attempt % 16 == 15 {
                    self.write_wake_doorbell()?;
                }
                thread::sleep(self.poll_interval);
            }
        }
        Err(QemuAsyncDriverRuntimeError::new(
            "await fault result publication fence",
            format!(
                "QEMU did not finish fault result/event pump for control token {request} within {timeout:?}; last acknowledgement {}",
                last_ack.map_or_else(|| String::from("none"), |ack| ack.to_string())
            ),
        ))
    }

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
            let request = self.signal_wake()?;
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
                BufferedFaultResultPoll::Ready(result) => {
                    self.await_fault_pump_completion(request, timeout)?;
                    return Ok(result);
                }
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

    /// Polls one PREPARE result and reserves its exact published payload size.
    pub(super) fn poll_fault_preparation_result(
        &mut self,
        timeout: Duration,
        maximum_payload_bytes: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        if timeout.is_zero() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "await fault preparation result",
                "fault-result timeout is zero",
            ));
        }
        let attempts = bounded_poll_attempts(timeout, self.poll_interval);
        let mut payload_buffer = Vec::new();
        for attempt in 0..attempts {
            let request = self.signal_wake()?;
            let transport = self
                .region
                .fault_result_transport_mut(self.vm_slot)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "map fault-result transport",
                        source.to_string(),
                    )
                })?;
            let result = match dequeue_fault_result_with_buffer(
                transport.ring,
                transport.slots,
                transport.arena_header,
                transport.arena,
                transport.arena_region_offset,
                payload_buffer,
            ) {
                Err(FaultTransportError::PayloadBufferTooSmall { requested, .. }) => {
                    admit_fault_preparation_result(requested, maximum_payload_bytes)?;
                    let mut exact = Vec::new();
                    exact.try_reserve_exact(requested).map_err(|_| {
                        QemuAsyncDriverRuntimeError::fault_result_storage(
                            requested,
                            maximum_payload_bytes,
                        )
                    })?;
                    dequeue_fault_result_with_buffer(
                        transport.ring,
                        transport.slots,
                        transport.arena_header,
                        transport.arena,
                        transport.arena_region_offset,
                        exact,
                    )
                }
                other => other,
            }
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("dequeue fault result", source.to_string())
            })?;
            match result {
                BufferedFaultResultPoll::Pending(buffer) => payload_buffer = buffer,
                BufferedFaultResultPoll::Ready(result) => {
                    self.await_fault_pump_completion(request, timeout)?;
                    return Ok(result);
                }
            }
            if attempt + 1 < attempts {
                thread::sleep(self.poll_interval);
            }
        }
        Err(QemuAsyncDriverRuntimeError::new(
            "await fault preparation result",
            format!("no result was published within {timeout:?}"),
        ))
    }
}
