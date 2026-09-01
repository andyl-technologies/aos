//! Atomic observable-event and evaluation-boundary appends.

use super::*;

impl EventLog {
    /// Appends typed signal-driven fault evidence in evaluation order.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning dense event-log sequences or
    /// appending the canonical segment would overflow scheduler offsets.
    pub fn append_fault_observations(
        &mut self,
        observations: impl IntoIterator<Item = crate::model::FaultObservation>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let mut entries = Vec::new();
        for observation in observations {
            let sequence = self.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                VirtualTime {
                    ticks: observation.coordinate.virtual_nanos,
                },
                SchedulerEventLogPayload::FaultObservation(observation),
            ));
        }
        self.append_entries(entries)
    }

    /// Appends black-box observable condition facts to this event log.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning dense event-log sequences or
    /// appending the event-log segment would overflow scheduler offsets, or when
    /// the resulting checked condition prefix is invalid.
    pub fn append_observable_events(
        &mut self,
        events: impl IntoIterator<Item = ObservableEvent>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let mut entries = Vec::new();
        for event in events {
            let sequence = self.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                event.at(),
                SchedulerEventLogPayload::Observable(event.payload().clone()),
            ));
        }
        self.append_entries(entries)
    }

    /// Atomically appends observations followed by their evaluation boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning dense event-log sequences,
    /// encoding the segment, or validating the resulting checked condition
    /// prefix fails.
    pub fn append_observations_at_boundary(
        &mut self,
        events: impl IntoIterator<Item = ObservableEvent>,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let mut entries = Vec::new();
        for event in events {
            let sequence = self.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                event.at(),
                SchedulerEventLogPayload::Observable(event.payload().clone()),
            ));
        }
        let sequence = self.next_sequence(entries.len())?;
        entries.push(scheduler_event_log_entry(
            sequence,
            at,
            SchedulerEventLogPayload::EvaluationBoundary(kind),
        ));
        self.append_entries(entries)
    }

    /// Appends a deterministic trigger/assertion evaluation boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning the dense event-log sequence or
    /// appending the event-log segment would overflow scheduler offsets, or when
    /// the boundary would make the checked condition prefix invalid.
    pub fn append_evaluation_boundary(
        &mut self,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let sequence = self.next_sequence(0)?;
        self.append_entries(vec![scheduler_event_log_entry(
            sequence,
            at,
            SchedulerEventLogPayload::EvaluationBoundary(kind),
        )])
    }
}
