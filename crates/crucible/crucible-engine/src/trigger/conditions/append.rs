//! Checked extension of an immutable, already validated condition prefix.

use super::*;

impl ConditionEventLogPrefix {
    /// Builds an empty prefix whose first appended entry must carry
    /// `base_sequence`.
    ///
    /// Live consumers that observe a log from a resumed offset use this with
    /// [`Self::append_entries`] to keep one prefix current instead of
    /// rebuilding it from their whole history at every evaluation.
    #[must_use]
    pub fn empty_at(base_sequence: u64) -> Self {
        Self::genesis().with_base_sequence(base_sequence)
    }

    /// Extends this prefix with the next dense entries of the same log.
    ///
    /// The suffix is checked exactly as at construction, so extending batch by
    /// batch yields the same prefix as building it from the whole log when
    /// every batch ends at its latest entry, as live appends do.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] for an empty or non-dense suffix,
    /// invalid content hashes or observation stamps, backwards black-box
    /// ordering, or entries hidden by the suffix's final boundary. A refused
    /// suffix leaves this prefix unchanged.
    pub fn append_entries(
        &mut self,
        entries: Vec<SchedulerEventLogEntry>,
    ) -> Result<(), ConditionEvaluationError> {
        self.append_scheduler_entries(entries)
    }

    /// Returns the dense sequence the next appended entry must carry.
    #[must_use]
    pub fn next_sequence(&self) -> u64 {
        u64::try_from(self.scheduler_entries.len())
            .ok()
            .and_then(|length| self.base_sequence.checked_add(length))
            .unwrap_or(u64::MAX)
    }

    /// Returns a copy evaluated at a synthesized boundary after this prefix.
    ///
    /// This is [`Self::from_scheduler_event_log_entries_with_evaluation_boundary`]
    /// applied to an already built prefix: the boundary at `sequence` is
    /// appended to the copy only, and the copy reports the boundary offset.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] when the boundary is not the next
    /// dense entry or precedes a retained entry.
    pub fn with_evaluation_boundary(
        &self,
        sequence: u64,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<Self, ConditionEvaluationError> {
        let mut prefix = self.clone();
        prefix.append_scheduler_entries(vec![SchedulerEventLogEntry::evaluation_boundary(
            sequence, at, kind,
        )])?;
        Ok(prefix.with_event_log_offset(EventLogOffset::new(ContentHash::default(), 0, sequence)))
    }

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
        let first_sequence = u64::try_from(self.scheduler_entries.len())
            .ok()
            .and_then(|length| self.base_sequence.checked_add(length));
        let mut check =
            AppendedEntryCheck::new(first_sequence, point.at(), self.last_black_box_observation);
        for entry in &entries {
            check.check(
                entry,
                &mut observable_events,
                &mut black_box_observation_kinds,
                &mut ordering_facts,
            )?;
        }
        let previous_black_box_observation = check.last_black_box_observation();
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
        if !self.prefix_offsets.is_empty() {
            self.prefix_offsets = std::sync::Arc::default();
        }
        self.last_black_box_observation = previous_black_box_observation;
        // Console matchers fold boundaries as well as bytes, so they read the
        // entries themselves rather than the extracted observations.
        self.console_folds.observe(entries.iter());
        self.point_events.observe(point.at(), &observable_events);
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
    pub(crate) fn scheduler_entries(&self) -> &crate::History<SchedulerEventLogEntry> {
        &self.scheduler_entries
    }

    /// Binds the successfully appended prefix to its canonical segment identity.
    pub(crate) fn set_event_log_offset(&mut self, offset: EventLogOffset) {
        self.event_log_offset = offset;
    }
}

/// Per-entry checks for one appended batch whose final entry is at `point_at`.
///
/// Appends and the streaming offline validator apply exactly these checks in
/// entry order, so both report the same first refusal.
pub(crate) struct AppendedEntryCheck {
    expected: Option<u64>,
    point_at: VirtualTime,
    last_black_box_observation: Option<(u64, VirtualTime)>,
}

impl AppendedEntryCheck {
    /// Starts checking at sequence `expected`; `None` means it overflowed.
    pub(crate) fn new(
        expected: Option<u64>,
        point_at: VirtualTime,
        last_black_box_observation: Option<(u64, VirtualTime)>,
    ) -> Self {
        Self {
            expected,
            point_at,
            last_black_box_observation,
        }
    }

    /// Checks the next entry and collects the facts it contributes.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] for a non-dense sequence, an
    /// invalid content hash, a backwards black-box observation, an entry after
    /// the batch's final time, or an invalid observation.
    pub(crate) fn check(
        &mut self,
        entry: &SchedulerEventLogEntry,
        observable_events: &mut Vec<ObservableEvent>,
        black_box_observation_kinds: &mut BTreeSet<BlackBoxObservationKind>,
        ordering_facts: &mut Vec<ObservedOrderingFact>,
    ) -> Result<(), ConditionEvaluationError> {
        let expected =
            self.expected
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
            if let Some((previous_sequence, previous_at)) = self.last_black_box_observation
                && entry.at().ticks < previous_at.ticks
            {
                return Err(ConditionEvaluationError::OutOfOrderEventLogEntry {
                    previous_sequence,
                    previous_at,
                    sequence: entry.sequence(),
                    event_at: entry.at(),
                });
            }
            self.last_black_box_observation = Some((entry.sequence(), entry.at()));
        }
        if entry.at().ticks > self.point_at.ticks {
            return Err(ConditionEvaluationError::FutureEventLogEntry {
                point: self.point_at,
                sequence: entry.sequence(),
                event_at: entry.at(),
            });
        }
        push_observed_state_facts(
            entry,
            observable_events,
            black_box_observation_kinds,
            ordering_facts,
        )?;
        self.expected = expected.checked_add(1);
        Ok(())
    }

    /// Returns the latest black-box observation accepted so far.
    pub(crate) fn last_black_box_observation(&self) -> Option<(u64, VirtualTime)> {
        self.last_black_box_observation
    }
}
