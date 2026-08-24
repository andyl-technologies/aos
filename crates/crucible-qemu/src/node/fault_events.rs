//! Lossless QEMU occurrence-event admission and sequence ownership.

use super::*;

impl QemuNode {
    /// Drains and sequence-validates every fault-rule event published so far.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when transport authentication fails or the
    /// per-node event sequence has a gap, duplicate, or overflow.
    pub fn drain_fault_events(
        &mut self,
        events: &mut Vec<DequeuedFaultEvent>,
    ) -> Result<(), QemuNodeError> {
        if let Some(message) = &self.fault_event_terminal_failure {
            return Err(QemuNodeError::fault_command(message.clone()));
        }
        for event in self
            .host_io_runtime
            .take_staged_fault_events()
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })?
        {
            self.accept_fault_event(event, events)?;
        }
        while let Some(event) =
            self.channels
                .shmem_hot_path
                .dequeue_fault_event()
                .map_err(|source| {
                    QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
                })?
        {
            self.accept_fault_event(event, events)?;
        }
        Ok(())
    }

    fn accept_fault_event(
        &mut self,
        event: DequeuedFaultEvent,
        events: &mut Vec<DequeuedFaultEvent>,
    ) -> Result<(), QemuNodeError> {
        let event_sequence = event.header.event_sequence;
        events.push(event);
        if event_sequence != self.next_fault_event_sequence {
            let message = format!(
                "fault event sequence mismatch: expected {}, observed {}",
                self.next_fault_event_sequence, event_sequence
            );
            self.fault_event_terminal_failure = Some(message.clone());
            return Err(QemuNodeError::fault_command(message));
        }
        self.next_fault_event_sequence = match self.next_fault_event_sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                let message = String::from("fault event sequence is exhausted");
                self.fault_event_terminal_failure = Some(message.clone());
                return Err(QemuNodeError::fault_command(message));
            }
        };
        Ok(())
    }

    /// Reports whether a QEMU event still awaits runtime admission.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the event transport is invalid.
    pub fn fault_event_pending(&mut self) -> Result<bool, QemuNodeError> {
        if let Some(message) = &self.fault_event_terminal_failure {
            return Err(QemuNodeError::fault_command(message.clone()));
        }
        if self.host_io_runtime.staged_fault_events_pending() {
            return Ok(true);
        }
        self.channels
            .shmem_hot_path
            .fault_event_pending()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }
}
