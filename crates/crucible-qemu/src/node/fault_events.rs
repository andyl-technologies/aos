//! Lossless QEMU occurrence-event admission and sequence ownership.

use super::*;

impl QemuNode {
    /// Authenticates every pending event without releasing its current owner.
    ///
    /// Events already staged by the host pump remain staged, while events in
    /// shared memory retain their consumer cursor. The returned copies are
    /// therefore precommit evidence only; normal admission later consumes the
    /// same sequence after durable intent publication.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when record storage cannot be admitted,
    /// payload ownership cannot be copied, the transport is invalid, or the
    /// previewed event sequence is not canonical.
    pub(crate) fn preview_fault_events(
        &mut self,
        canonical_current: &mut usize,
        configured_event_records: usize,
    ) -> Result<Vec<DequeuedFaultEvent>, QemuNodeError> {
        if let Some(message) = &self.fault_event_terminal_failure {
            return Err(QemuNodeError::fault_command(message.clone()));
        }
        let staged = self.host_io_runtime.staged_fault_events();
        let published = self
            .channels
            .shmem_hot_path
            .fault_event_count()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        let required =
            staged
                .len()
                .checked_add(published)
                .ok_or(QemuNodeError::FaultEventStorage {
                    current: u64::MAX,
                    requested: u64::MAX,
                    configured: u64::try_from(configured_event_records).unwrap_or(u64::MAX),
                })?;
        admit_fault_event_records(*canonical_current, required, configured_event_records)?;
        let mut preview = Vec::new();
        preview
            .try_reserve_exact(required)
            .map_err(|_| QemuNodeError::FaultEventStorage {
                current: u64::try_from(*canonical_current).unwrap_or(u64::MAX),
                requested: u64::try_from(required).unwrap_or(u64::MAX),
                configured: u64::try_from(configured_event_records).unwrap_or(u64::MAX),
            })?;
        for event in staged {
            let mut payload = Vec::new();
            payload
                .try_reserve_exact(event.payload.len())
                .map_err(|_| {
                    QemuNodeError::fault_command("cannot copy staged fault-event preview payload")
                })?;
            payload.extend_from_slice(&event.payload);
            preview.push(DequeuedFaultEvent {
                header: event.header.clone(),
                payload,
            });
        }
        self.channels
            .shmem_hot_path
            .snapshot_fault_events(&mut preview)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        let mut expected = self.next_fault_event_sequence;
        for event in &preview {
            if event.header.event_sequence != expected {
                return Err(QemuNodeError::fault_command(format!(
                    "fault event preview sequence mismatch: expected {expected}, observed {}",
                    event.header.event_sequence
                )));
            }
            expected = expected.checked_add(1).ok_or_else(|| {
                QemuNodeError::fault_command("fault event preview sequence is exhausted")
            })?;
        }
        *canonical_current =
            canonical_current
                .checked_add(required)
                .ok_or(QemuNodeError::FaultEventStorage {
                    current: u64::MAX,
                    requested: u64::try_from(required).unwrap_or(u64::MAX),
                    configured: u64::try_from(configured_event_records).unwrap_or(u64::MAX),
                })?;
        Ok(preview)
    }

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
        let mut current = events.len();
        self.drain_fault_events_with_budget(
            events,
            &mut current,
            crucible_shmem::HARD_FAULT_EVENT_CAPACITY as usize,
        )
    }

    pub(crate) fn drain_fault_events_with_budget(
        &mut self,
        events: &mut Vec<DequeuedFaultEvent>,
        canonical_current: &mut usize,
        configured_event_records: usize,
    ) -> Result<(), QemuNodeError> {
        if let Some(message) = &self.fault_event_terminal_failure {
            return Err(QemuNodeError::fault_command(message.clone()));
        }
        let staged = self.host_io_runtime.staged_fault_event_count();
        admit_fault_event_records(*canonical_current, staged, configured_event_records)?;
        events
            .try_reserve_exact(staged)
            .map_err(|_| QemuNodeError::FaultEventStorage {
                current: u64::try_from(*canonical_current).unwrap_or(u64::MAX),
                requested: u64::try_from(staged).unwrap_or(u64::MAX),
                configured: u64::try_from(configured_event_records).unwrap_or(u64::MAX),
            })?;
        for event in self
            .host_io_runtime
            .take_staged_fault_events()
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })?
        {
            self.accept_fault_event(event, events)?;
            *canonical_current =
                canonical_current
                    .checked_add(1)
                    .ok_or(QemuNodeError::FaultEventStorage {
                        current: u64::MAX,
                        requested: 1,
                        configured: u64::try_from(configured_event_records).unwrap_or(u64::MAX),
                    })?;
        }
        loop {
            // Reserve the destination slot before consuming the shared-memory
            // owner. Allocation refusal therefore leaves the public event in
            // the ring for a later typed retry instead of losing it.
            admit_fault_event_records(*canonical_current, 1, configured_event_records)?;
            events
                .try_reserve(1)
                .map_err(|_| QemuNodeError::FaultEventStorage {
                    current: u64::try_from(*canonical_current).unwrap_or(u64::MAX),
                    requested: 1,
                    configured: u64::try_from(configured_event_records).unwrap_or(u64::MAX),
                })?;
            let Some(event) =
                self.channels
                    .shmem_hot_path
                    .dequeue_fault_event()
                    .map_err(|source| {
                        QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
                    })?
            else {
                break;
            };
            self.accept_fault_event(event, events)?;
            *canonical_current =
                canonical_current
                    .checked_add(1)
                    .ok_or(QemuNodeError::FaultEventStorage {
                        current: u64::MAX,
                        requested: 1,
                        configured: u64::try_from(configured_event_records).unwrap_or(u64::MAX),
                    })?;
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

fn admit_fault_event_records(
    current: usize,
    requested: usize,
    configured: usize,
) -> Result<(), QemuNodeError> {
    let admitted = current.checked_add(requested);
    if admitted.is_some_and(|total| total <= configured) {
        return Ok(());
    }
    Err(QemuNodeError::FaultEventStorage {
        current: u64::try_from(current).unwrap_or(u64::MAX),
        requested: u64::try_from(requested).unwrap_or(u64::MAX),
        configured: u64::try_from(configured).unwrap_or(u64::MAX),
    })
}
