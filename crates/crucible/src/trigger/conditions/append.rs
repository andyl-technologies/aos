//! Checked extension of an immutable, already validated condition prefix.

use super::*;

impl ConditionEventLogPrefix {
    /// Validates a suffix before committing its entries and derived facts.
    ///
    /// Retained entries were authenticated when this prefix was constructed or
    /// extended and cannot be mutated independently. Only the new suffix needs
    /// hash and observation validation; the previous final time bounds every
    /// retained entry and the last black-box observation preserves ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] for an empty or non-dense suffix,
    /// invalid content hashes or observation stamps, backwards black-box
    /// ordering, entries hidden by the final boundary, or sequence overflow.
    /// Every refusal leaves the retained prefix and its derived facts intact.
    pub(crate) fn append_scheduler_entries(
        &mut self,
        entries: Vec<SchedulerEventLogEntry>,
    ) -> Result<(), ConditionEvaluationError> {
        let Some(last) = entries.last() else {
            return Err(ConditionEvaluationError::EmptyEventLogPrefix);
        };
        let point = EventEvaluationPoint::event_log_entry(last);

        // A backwards boundary must still report the first retained entry it
        // hides, just as validating the complete prefix would. The ordinary
        // nondecreasing append does not revisit the authenticated history.
        if self
            .scheduler_entries
            .last()
            .is_some_and(|previous| previous.at().ticks > point.at().ticks)
            && let Some(entry) = self
                .scheduler_entries
                .iter()
                .find(|entry| entry.at().ticks > point.at().ticks)
        {
            return Err(ConditionEvaluationError::FutureEventLogEntry {
                point: point.at(),
                sequence: entry.sequence(),
                event_at: entry.at(),
            });
        }

        let mut observable_events = Vec::new();
        let mut black_box_observation_kinds = BTreeSet::new();
        let mut ordering_facts = Vec::new();
        let mut previous_black_box_observation = self.last_black_box_observation;
        for (offset, entry) in entries.iter().enumerate() {
            let expected = self
                .scheduler_entries
                .len()
                .checked_add(offset)
                .and_then(|offset| u64::try_from(offset).ok())
                .and_then(|offset| self.base_sequence.checked_add(offset))
                .ok_or(ConditionEvaluationError::NonPrefixEventLogSequence {
                    expected: u64::MAX,
                    actual: entry.sequence(),
                })?;
            if entry.sequence() != expected {
                return Err(ConditionEvaluationError::NonPrefixEventLogSequence {
                    expected,
                    actual: entry.sequence(),
                });
            }
            if !entry.has_valid_content_hash() {
                return Err(ConditionEvaluationError::InvalidEventLogEntryHash {
                    sequence: entry.sequence(),
                });
            }
            if scheduler_entry_black_box_observation_kind(entry).is_some() {
                if let Some((previous_sequence, previous_at)) = previous_black_box_observation
                    && entry.at().ticks < previous_at.ticks
                {
                    return Err(ConditionEvaluationError::OutOfOrderEventLogEntry {
                        previous_sequence,
                        previous_at,
                        sequence: entry.sequence(),
                        event_at: entry.at(),
                    });
                }
                previous_black_box_observation = Some((entry.sequence(), entry.at()));
            }
            if entry.at().ticks > point.at().ticks {
                return Err(ConditionEvaluationError::FutureEventLogEntry {
                    point: point.at(),
                    sequence: entry.sequence(),
                    event_at: entry.at(),
                });
            }
            push_observed_state_facts(
                entry,
                &mut observable_events,
                &mut black_box_observation_kinds,
                &mut ordering_facts,
            )?;
        }
        let events = self
            .scheduler_entries
            .len()
            .checked_add(entries.len())
            .and_then(|length| u64::try_from(length).ok())
            .and_then(|length| self.base_sequence.checked_add(length))
            .ok_or(ConditionEvaluationError::NonPrefixEventLogSequence {
                expected: u64::MAX,
                actual: u64::MAX,
            })?;

        // Everything below is infallible. Apply timer and firing history in
        // entry order so cancellations can remove timers from earlier batches.
        self.point = point;
        self.event_log_offset = EventLogOffset::new(ContentHash::default(), 0, events);
        self.prefix_offsets.clear();
        self.last_black_box_observation = previous_black_box_observation;
        self.observable_events.extend(observable_events);
        self.black_box_observation_kinds
            .extend(black_box_observation_kinds);
        self.ordering_facts.extend(ordering_facts);
        for entry in &entries {
            push_condition_runtime_facts(entry, &mut self.event_firings, &mut self.timer_fires);
        }
        self.scheduler_entries.extend(entries);
        Ok(())
    }

    /// Borrows the single authenticated history also used by checkpoint capture.
    pub(crate) fn scheduler_entries(&self) -> &[SchedulerEventLogEntry] {
        &self.scheduler_entries
    }

    /// Binds the successfully appended prefix to its canonical segment identity.
    pub(crate) fn set_event_log_offset(&mut self, offset: EventLogOffset) {
        self.event_log_offset = offset;
    }
}
