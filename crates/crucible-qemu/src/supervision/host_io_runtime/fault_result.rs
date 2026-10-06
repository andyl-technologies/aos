//! Bounded polling for the dedicated QEMU fault-result transport.

use super::control::PendingControlBoundary;
use super::{QemuLiveHostIoRuntime, control_boundary_request_is_acknowledged};
use crate::QemuAsyncDriverRuntimeError;
use crucible_shmem::{
    BufferedFaultResultPoll, DequeuedFaultResult, FaultTransportError, dequeue_fault_event,
    dequeue_fault_result_with_buffer, fault_event_pending,
};
use std::time::Duration;

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
    pub(super) fn fault_event_ring_indices(
        &mut self,
    ) -> Result<(u64, u64), QemuAsyncDriverRuntimeError> {
        let transport = self
            .region
            .fault_event_transport_mut(self.vm_slot)
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("map fault-event transport", source.to_string())
            })?;
        Ok((transport.ring.read_index(), transport.ring.write_index()))
    }

    pub(super) fn drain_fault_events_for_operation(
        &mut self,
        maximum_event_records: usize,
        deadline: &super::OperationPollBudget,
        timeout: Duration,
        operation: &'static str,
    ) -> Result<usize, QemuAsyncDriverRuntimeError> {
        self.drain_fault_events_with_budget(maximum_event_records, timeout, operation, || {
            Ok(deadline.remaining(operation)?.is_some())
        })
    }

    fn drain_fault_events_with_budget(
        &mut self,
        maximum_event_records: usize,
        timeout: Duration,
        operation: &'static str,
        has_time_remaining: impl Fn() -> Result<bool, QemuAsyncDriverRuntimeError>,
    ) -> Result<usize, QemuAsyncDriverRuntimeError> {
        let mut drained = 0;
        loop {
            let (pending, read_index, write_index, arena_read, arena_write) = {
                let transport = self
                    .region
                    .fault_event_transport_mut(self.vm_slot)
                    .map_err(|source| {
                        QemuAsyncDriverRuntimeError::new(
                            "map fault-event transport",
                            source.to_string(),
                        )
                    })?;
                let pending =
                    fault_event_pending(transport.ring, transport.slots).map_err(|source| {
                        QemuAsyncDriverRuntimeError::new(
                            "inspect fault-event transport",
                            source.to_string(),
                        )
                    })?;
                (
                    pending,
                    transport.ring.read_index(),
                    transport.ring.write_index(),
                    transport.arena_header.read_cursor(),
                    transport.arena_header.write_cursor(),
                )
            };
            if !pending {
                return Ok(drained);
            }
            if !has_time_remaining()? {
                return Err(QemuAsyncDriverRuntimeError::new(
                    operation,
                    format!(
                        "fault-event drain did not quiesce within {timeout:?}: ring read index {read_index}, write index {write_index}, arena read cursor {arena_read}, write cursor {arena_write}, staged events {}, staged sequence range {:?}..={:?}",
                        self.staged_fault_events.len(),
                        self.staged_fault_events
                            .first()
                            .map(|event| event.header.event_sequence),
                        self.staged_fault_events
                            .last()
                            .map(|event| event.header.event_sequence),
                    ),
                ));
            }
            let current = self.staged_fault_events.len();
            if current >= maximum_event_records {
                return Err(QemuAsyncDriverRuntimeError::fault_event_storage(
                    self.fault_event_canonical_current_offset
                        .saturating_add(current),
                    1,
                    self.fault_event_configured_limit,
                ));
            }
            self.staged_fault_events.try_reserve(1).map_err(|_| {
                QemuAsyncDriverRuntimeError::fault_event_storage(
                    self.fault_event_canonical_current_offset
                        .saturating_add(current),
                    1,
                    self.fault_event_configured_limit,
                )
            })?;
            let transport = self
                .region
                .fault_event_transport_mut(self.vm_slot)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "map fault-event transport",
                        source.to_string(),
                    )
                })?;
            let event = dequeue_fault_event(
                transport.ring,
                transport.slots,
                transport.arena_header,
                transport.arena,
                transport.arena_region_offset,
            )
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new("dequeue fault event", source.to_string())
            })?;
            let Some(event) = event else {
                return Ok(drained);
            };
            self.staged_fault_events.push(event);
            drained += 1;
        }
    }

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
        request: PendingControlBoundary,
        timeout: Duration,
        deadline: &super::OperationPollBudget,
        maximum_event_records: usize,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let last_ack = loop {
            self.drain_fault_events_for_operation(
                maximum_event_records,
                deadline,
                timeout,
                "await fault result publication fence",
            )?;
            self.service_console_output()?;
            let snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(super::map_slot_error)?
                .snapshot();
            if control_boundary_request_is_acknowledged(request, &snapshot) {
                deadline.complete("await fault result publication fence")?;
                return Ok(());
            }
            if deadline
                .remaining("await fault result publication fence")?
                .is_none()
            {
                break snapshot.control_boundary_ack;
            }
            self.write_wake_doorbell()?;
            deadline.wait(self.poll_interval, "await fault result publication fence")?;
        };
        Err(QemuAsyncDriverRuntimeError::new(
            "await fault result publication fence",
            format!(
                "QEMU did not finish fault result/event pump for control token {} within {timeout:?}; last acknowledgement {}",
                request.generation, last_ack
            ),
        ))
    }

    /// Polls the lossless result ring while repeatedly waking QEMU.
    pub(super) fn poll_fault_result(
        &mut self,
        timeout: Duration,
        mut payload_buffer: Vec<u8>,
        maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        let deadline = super::OperationPollBudget::begin(
            self.host_operation_supervisor.as_ref(),
            crucible_linux_resource::host_supervision::HostOperationClass::Preparation,
            timeout,
            "await fault result",
        )?;
        loop {
            let request = self.signal_wake(None)?;
            self.drain_fault_events_for_operation(
                maximum_event_records,
                &deadline,
                timeout,
                "await fault result",
            )?;
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
                    self.await_fault_pump_completion(
                        request,
                        timeout,
                        &deadline,
                        maximum_event_records,
                    )?;
                    return Ok(result);
                }
            }
            if deadline.remaining("await fault result")?.is_none() {
                break;
            }
            deadline.wait(self.poll_interval, "await fault result")?;
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
        maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        let deadline = super::OperationPollBudget::begin(
            self.host_operation_supervisor.as_ref(),
            crucible_linux_resource::host_supervision::HostOperationClass::Preparation,
            timeout,
            "await fault preparation result",
        )?;
        let mut payload_buffer = Vec::new();
        loop {
            let request = self.signal_wake(None)?;
            self.drain_fault_events_for_operation(
                maximum_event_records,
                &deadline,
                timeout,
                "await fault preparation result",
            )?;
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
                    self.await_fault_pump_completion(
                        request,
                        timeout,
                        &deadline,
                        maximum_event_records,
                    )?;
                    return Ok(result);
                }
            }
            if deadline
                .remaining("await fault preparation result")?
                .is_none()
            {
                break;
            }
            deadline.wait(self.poll_interval, "await fault preparation result")?;
        }
        Err(QemuAsyncDriverRuntimeError::new(
            "await fault preparation result",
            format!("no result was published within {timeout:?}"),
        ))
    }
}
