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
        self.append_entries(AppendEntries::Owned(entries))
    }

    /// Copies a borrowed suffix under its independently retained append account.
    pub(crate) fn append_scheduler_entries_ref(
        &mut self,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), ConditionEvaluationError> {
        self.append_entries(AppendEntries::Borrowed(entries))
    }

    fn append_entries(&mut self, input: AppendEntries<'_>) -> Result<(), ConditionEvaluationError> {
        let entries = input.as_slice();
        let _original = self._decode_custody.enter();
        let custody = owned_prefix::current_custody()?;
        let child = crate::owned_decode::require_current_child_budget()
            .map_err(ConditionEvaluationError::OriginalAdmission)?;
        let _scope = child.enter();
        let staging = crate::owned_decode::require_current_child_budget()
            .map_err(ConditionEvaluationError::OriginalAdmission)?;
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

        // Temporary array and set storage closes at the end of this append.
        // Copied payloads and destination extents stay in the retained child.
        let observable_count = entries
            .iter()
            .filter(|entry| matches!(entry.payload(), SchedulerEventLogPayload::Observable(_)))
            .count();
        let ordering_count = entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::ResolvedHappening(_)
                        | SchedulerEventLogPayload::Decision(Decision::DeliveryOrder(_))
                )
            })
            .count();
        let mut observable_events = staging_vec(&staging, observable_count)?;
        let mut black_box_observation_kinds = BTreeSet::new();
        let mut ordering_facts = staging_vec(&staging, ordering_count)?;
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
            if !entry.has_valid_content_hash()? {
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
                &staging,
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

        // Copied payloads and map keys are provisional until all admission
        // checks succeed. A refused copy releases the entire provisional bank.
        for kind in &black_box_observation_kinds {
            if !self.black_box_observation_kinds.contains(kind) {
                crate::owned_decode::charge_btree_set_entry::<BlackBoxObservationKind>()
                    .map_err(ConditionEvaluationError::OriginalAdmission)?;
            }
        }
        let runtime_updates = prepare_runtime_updates(entries, &staging)?;
        let retained_entries = match &input {
            AppendEntries::Owned(_) => None,
            AppendEntries::Borrowed(entries) => {
                // The provisional element table closes when these moved fields
                // extend the retained history. Only the copied fields stay in
                // the payload account; the table belongs to temporary staging.
                let mut copied = staging_vec(&staging, entries.len())?;
                for entry in *entries {
                    copied.push(
                        crate::scheduler::copy_entry_admitted(entry)
                            .map_err(ConditionEvaluationError::from)?,
                    );
                }
                Some(copied)
            }
        };
        owned_prefix::current_custody()?;

        // Each Vec keeps only its current allocation's account. Reallocation
        // closes the old buffer before replacing that loan; later refusals
        // retain any earlier successful growth without publishing new facts.
        crate::owned_decode::grow_retained_vec(
            &mut self._append_custodies,
            1,
            &mut self._array_custodies[3],
        )
        .map_err(ConditionEvaluationError::OriginalAdmission)?;
        crate::owned_decode::grow_retained_vec(
            &mut self.observable_events,
            observable_events.len(),
            &mut self._array_custodies[0],
        )
        .map_err(ConditionEvaluationError::OriginalAdmission)?;
        crate::owned_decode::grow_retained_vec(
            &mut self.ordering_facts,
            ordering_facts.len(),
            &mut self._array_custodies[1],
        )
        .map_err(ConditionEvaluationError::OriginalAdmission)?;
        crate::owned_decode::grow_retained_vec(
            &mut self.scheduler_entries,
            entries.len(),
            &mut self._array_custodies[2],
        )
        .map_err(ConditionEvaluationError::OriginalAdmission)?;

        self.point = point;
        self.event_log_offset = EventLogOffset::new(ContentHash::default(), 0, events);
        self.prefix_offsets.clear();
        self.last_black_box_observation = previous_black_box_observation;
        self.observable_events.extend(observable_events);
        self.black_box_observation_kinds
            .extend(black_box_observation_kinds);
        self.ordering_facts.extend(ordering_facts);
        for update in runtime_updates {
            match update {
                RuntimeUpdate::Fired(event, at) => {
                    self.event_firings.insert(event, at);
                }
                RuntimeUpdate::Armed(timer, at) => {
                    self.timer_fires.insert(timer, at);
                }
                RuntimeUpdate::Canceled(timer) => {
                    self.timer_fires.remove(timer);
                }
            }
        }
        match input {
            AppendEntries::Owned(entries) => self.scheduler_entries.extend(entries),
            AppendEntries::Borrowed(_) => self
                .scheduler_entries
                .extend(retained_entries.into_iter().flatten()),
        }
        self._append_custodies.push(child.custody());
        self._decode_custody = custody;
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

/// Holds fully admitted map changes until the complete suffix can commit.
enum RuntimeUpdate<'a> {
    Fired(EventId, VirtualTime),
    Armed(TimerId, VirtualTime),
    Canceled(&'a TimerId),
}

fn prepare_runtime_updates<'a>(
    entries: &'a [SchedulerEventLogEntry],
    staging: &crate::owned_decode::DecodeBudget,
) -> Result<Vec<RuntimeUpdate<'a>>, ConditionEvaluationError> {
    let mut updates = staging_vec(staging, entries.len())?;
    for entry in entries {
        let update = match entry.payload() {
            SchedulerEventLogPayload::TriggerFired(firing) => {
                crate::owned_decode::charge_btree_entry::<EventId, VirtualTime>()
                    .map_err(ConditionEvaluationError::OriginalAdmission)?;
                Some(RuntimeUpdate::Fired(
                    owned_prefix::copy(firing.event())?,
                    firing.at(),
                ))
            }
            SchedulerEventLogPayload::TriggerActionApplied(application) => {
                match &application.action {
                    Action::ArmTimer { name, after } => {
                        match application.at.ticks.checked_add(after.ticks) {
                            Some(ticks) => {
                                crate::owned_decode::charge_btree_entry::<TimerId, VirtualTime>()
                                    .map_err(ConditionEvaluationError::OriginalAdmission)?;
                                Some(RuntimeUpdate::Armed(
                                    owned_prefix::copy(name)?,
                                    VirtualTime { ticks },
                                ))
                            }
                            None => None,
                        }
                    }
                    Action::CancelTimer { name } => Some(RuntimeUpdate::Canceled(name)),
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(update) = update {
            updates.push(update);
        }
    }
    Ok(updates)
}

/// Reserves a temporary array under the independent staging account.
fn staging_vec<T>(
    staging: &crate::owned_decode::DecodeBudget,
    count: usize,
) -> Result<Vec<T>, ConditionEvaluationError> {
    let _scope = staging.enter();
    crate::owned_decode::charge_array::<T>(count)
        .map_err(ConditionEvaluationError::OriginalAdmission)?;
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|source| {
        ConditionEvaluationError::OriginalAdmission(crate::owned_decode::DecodeAdmissionError::new(
            source,
        ))
    })?;
    Ok(values)
}

/// Moves already admitted constructor input or borrows an enclosing log's suffix.
enum AppendEntries<'a> {
    Owned(Vec<SchedulerEventLogEntry>),
    Borrowed(&'a [SchedulerEventLogEntry]),
}

impl AppendEntries<'_> {
    fn as_slice(&self) -> &[SchedulerEventLogEntry] {
        match self {
            Self::Owned(entries) => entries,
            Self::Borrowed(entries) => entries,
        }
    }
}
