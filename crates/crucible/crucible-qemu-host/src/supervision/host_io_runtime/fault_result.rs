//! Bounded polling for the dedicated QEMU fault-result transport.

use super::action_scope::{ControlActionScope, SourceControlAction};
use super::control::PendingControlBoundary;
use super::{QemuLiveHostIoRuntime, control_boundary_request_is_acknowledged, region_missing};
use crate::QemuAsyncDriverRuntimeError;
use crucible_qemu_shmem::{
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
            .as_mut()
            .ok_or_else(region_missing)?
            .fault_event_transport_mut(self.vm_slot)
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::mapped_region_access(
                    "map fault-event transport",
                    source,
                )
            })?;
        Ok((transport.ring.read_index(), transport.ring.write_index()))
    }

    pub(super) fn drain_fault_events_for_operation(
        &mut self,
        maximum_event_records: usize,
        deadline: &super::OperationPollBudget<'_>,
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
                    .as_mut()
                    .ok_or_else(region_missing)?
                    .fault_event_transport_mut(self.vm_slot)
                    .map_err(|source| {
                        QemuAsyncDriverRuntimeError::mapped_region_access(
                            "map fault-event transport",
                            source,
                        )
                    })?;
                let pending =
                    fault_event_pending(transport.ring, transport.slots).map_err(|source| {
                        QemuAsyncDriverRuntimeError::fault_transport(
                            "inspect fault-event transport",
                            source,
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
                .as_mut()
                .ok_or_else(region_missing)?
                .fault_event_transport_mut(self.vm_slot)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::mapped_region_access(
                        "map fault-event transport",
                        source,
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
                QemuAsyncDriverRuntimeError::fault_event("dequeue fault event", source)
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
        deadline: &super::OperationPollBudget<'_>,
        maximum_event_records: usize,
        loan: bool,
        actions: &mut impl ControlActionScope,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let last_ack = loop {
            if loan {
                actions.refresh(self)?;
            }
            self.drain_fault_events_for_operation(
                maximum_event_records,
                deadline,
                timeout,
                "await fault result publication fence",
            )?;
            self.service_console_output()?;
            let snapshot = self
                .region
                .as_ref()
                .ok_or_else(region_missing)?
                .node_slot(self.vm_slot)
                .map_err(super::map_slot_error)?
                .snapshot();
            if control_boundary_request_is_acknowledged(request, &snapshot)
                && (!loan || actions.finish(self)?)
            {
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
        payload_buffer: Vec<u8>,
        maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        self.settle_previous_action()?;
        let deadline = super::OperationPollBudget::begin(
            self.host_operation_supervisor.as_ref(),
            crucible_host_resources::host_supervision::HostOperationClass::Preparation,
            timeout,
            "await fault result",
        )?;
        self.poll_fault_result_with_actions(
            timeout,
            payload_buffer,
            maximum_event_records,
            &deadline,
            &mut SourceControlAction::default(),
        )
    }

    pub(super) fn poll_fault_result_with_actions(
        &mut self,
        timeout: Duration,
        mut payload_buffer: Vec<u8>,
        maximum_event_records: usize,
        deadline: &super::OperationPollBudget<'_>,
        actions: &mut impl ControlActionScope,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        let loan = actions.lend(self, deadline, None)?;
        if deadline.remaining("publish fault action")?.is_none() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "publish fault action",
                "producing operation expired before wake",
            ));
        }
        let request = self.signal_wake(None)?;
        actions.validate(request)?;
        let mut repeat_wake = false;
        loop {
            if loan {
                actions.refresh(self)?;
            }
            // Reuse the immutable request. Republishing after its ACK would
            // mint another token while the same action still owns the frontier.
            if deadline.remaining("continue fault action")?.is_none() {
                break;
            }
            if repeat_wake {
                self.write_wake_doorbell()?;
            }
            repeat_wake = true;
            self.drain_fault_events_for_operation(
                maximum_event_records,
                deadline,
                timeout,
                "await fault result",
            )?;
            let transport = self
                .region
                .as_mut()
                .ok_or_else(region_missing)?
                .fault_result_transport_mut(self.vm_slot)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::mapped_region_access(
                        "map fault-result transport",
                        source,
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
                QemuAsyncDriverRuntimeError::fault_transport("dequeue fault result", source)
            })?;
            match result {
                BufferedFaultResultPoll::Pending(buffer) => payload_buffer = buffer,
                BufferedFaultResultPoll::Ready(result) => {
                    self.await_fault_pump_completion(
                        request,
                        timeout,
                        deadline,
                        maximum_event_records,
                        loan,
                        actions,
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
        self.settle_previous_action()?;
        let deadline = super::OperationPollBudget::begin(
            self.host_operation_supervisor.as_ref(),
            crucible_host_resources::host_supervision::HostOperationClass::Preparation,
            timeout,
            "await fault preparation result",
        )?;
        self.poll_fault_preparation_result_with_actions(
            timeout,
            maximum_payload_bytes,
            maximum_event_records,
            &deadline,
            &mut SourceControlAction::default(),
        )
    }

    pub(super) fn poll_fault_preparation_result_with_actions(
        &mut self,
        timeout: Duration,
        maximum_payload_bytes: usize,
        maximum_event_records: usize,
        deadline: &super::OperationPollBudget<'_>,
        actions: &mut impl ControlActionScope,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        let mut payload_buffer = Vec::new();
        let loan = actions.lend(self, deadline, None)?;
        if deadline.remaining("publish fault action")?.is_none() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "publish fault action",
                "producing operation expired before wake",
            ));
        }
        let request = self.signal_wake(None)?;
        actions.validate(request)?;
        let mut repeat_wake = false;
        loop {
            if loan {
                actions.refresh(self)?;
            }
            // Reuse the immutable request. Republishing after its ACK would
            // mint another token while the same action still owns the frontier.
            if deadline.remaining("continue fault action")?.is_none() {
                break;
            }
            if repeat_wake {
                self.write_wake_doorbell()?;
            }
            repeat_wake = true;
            self.drain_fault_events_for_operation(
                maximum_event_records,
                deadline,
                timeout,
                "await fault preparation result",
            )?;
            let transport = self
                .region
                .as_mut()
                .ok_or_else(region_missing)?
                .fault_result_transport_mut(self.vm_slot)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::mapped_region_access(
                        "map fault-result transport",
                        source,
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
                QemuAsyncDriverRuntimeError::fault_transport("dequeue fault result", source)
            })?;
            match result {
                BufferedFaultResultPoll::Pending(buffer) => payload_buffer = buffer,
                BufferedFaultResultPoll::Ready(result) => {
                    self.await_fault_pump_completion(
                        request,
                        timeout,
                        deadline,
                        maximum_event_records,
                        loan,
                        actions,
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
