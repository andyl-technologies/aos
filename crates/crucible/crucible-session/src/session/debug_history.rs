//! The actor's debug history: the furthest canonical run log and its indexes.
//!
//! The subscriber hub follows the session's current position, so a reverse
//! step truncates it. Time travel and breakpoints instead need the furthest
//! canonical run, which survives a reverse step until execution diverges.
//! This module keeps that history without holding the run in memory:
//!
//! - the entries are a [`SegmentedEntryLog`] sharing the hub's store;
//! - each event's configuration coordinate is kept sparsely, one row where the
//!   coordinate changes (a decision or a quantum boundary), not one per event;
//! - the breakpoint condition prefix is extended batch by batch while
//!   breakpoints are armed, instead of rebuilt from the whole log at every
//!   quantum.
//!
//! The condition prefix still retains its own entry and observation history
//! until the bounded condition fold of RFC-0020 CMEAS-15 replaces it. The
//! debugger's engine API takes a complete event-log slice and a per-event
//! coordinate map, so a debugger command that needs them collects the
//! history from its segments for that command only.

use super::session_segmented_log::SegmentedEntryLog;
use super::*;

/// Furthest canonical run history retained for breakpoints and time travel.
#[derive(Debug)]
pub(super) struct SessionDebugHistory {
    entries: SegmentedEntryLog,
    // Each key is the first sequence whose coordinate is the value; the
    // coordinate holds until the next key or the end of `entries`.
    coordinates: BTreeMap<u64, Configuration>,
    // Kept current only while breakpoints are armed.
    condition_prefix: Option<ConditionEventLogPrefix>,
}

impl SessionDebugHistory {
    /// Builds an empty history that seals into `store`.
    pub(super) fn new(store: Arc<dyn DagStore>) -> Self {
        Self {
            entries: SegmentedEntryLog::new(store),
            coordinates: BTreeMap::new(),
            condition_prefix: None,
        }
    }

    /// Returns the number of retained history entries.
    #[cfg(test)]
    pub(super) const fn len(&self) -> u64 {
        self.entries.len()
    }

    /// Collects every history entry for test inspection.
    #[cfg(test)]
    pub(super) fn entries_for_test(&self) -> Vec<SchedulerEventLogEntry> {
        match self.entries.collect_through(u64::MAX) {
            Ok(entries) => entries,
            Err(error) => panic!("debug history must read back: {error}"),
        }
    }

    /// Drops every entry and coordinate at or after sequence `len`.
    pub(super) fn truncate(&mut self, len: u64) -> Result<(), SessionError> {
        self.entries.truncate(len)?;
        self.coordinates.split_off(&len);
        if self
            .condition_prefix
            .as_ref()
            .is_some_and(|prefix| prefix.next_sequence() > len)
        {
            self.condition_prefix = None;
        }
        Ok(())
    }

    /// Appends emitted entries with their configuration coordinates.
    ///
    /// `index` is the coordinate before the first entry and `current` the
    /// configuration after the batch. A decision entry that extends the
    /// coordinate by `current`'s next decision advances it by one; a quantum
    /// boundary moves it to `current`.
    pub(super) fn append(
        &mut self,
        entries: &[SchedulerEventLogEntry],
        index: &Configuration,
        current: &Configuration,
    ) -> Result<(), SessionError> {
        let Some(first) = entries.first() else {
            return Ok(());
        };
        self.entries.append(entries)?;
        self.extend_condition_prefix(entries);

        let mut coordinate = index.clone();
        self.coordinates
            .insert(first.sequence(), coordinate.clone());
        for entry in entries {
            let mut changed = false;
            if let SchedulerEventLogPayload::Decision(decision) = entry.payload()
                && current
                    .schedule
                    .decision_history()
                    .get(coordinate.schedule.len())
                    == Some(decision)
            {
                coordinate = Configuration {
                    def: current.def.clone(),
                    schedule: current
                        .schedule
                        .prefix(coordinate.schedule.len().saturating_add(1))
                        .map_err(EngineError::SchedulePrefix)?,
                };
                changed = true;
            }
            if matches!(
                entry.payload(),
                SchedulerEventLogPayload::EvaluationBoundary(
                    SchedulerEvaluationBoundaryKind::Quantum
                )
            ) {
                coordinate = current.clone();
                changed = true;
            }
            if changed {
                self.coordinates
                    .insert(entry.sequence(), coordinate.clone());
            }
        }
        Ok(())
    }

    /// Returns the configuration coordinate of the event at `sequence`.
    pub(super) fn coordinate(&self, sequence: u64) -> Option<&Configuration> {
        if self.entries.base().is_none_or(|base| sequence < base) || sequence >= self.entries.end()
        {
            return None;
        }
        self.coordinates
            .range(..=sequence)
            .next_back()
            .map(|(_, coordinate)| coordinate)
    }

    /// Expands the sparse coordinates into one row per retained event.
    ///
    /// The debugger's engine requests take this per-event map; it is built
    /// only for the command that needs it.
    pub(super) fn event_coordinates(&self) -> BTreeMap<u64, Configuration> {
        let Some(base) = self.entries.base() else {
            return BTreeMap::new();
        };
        (base..self.entries.end())
            .filter_map(|sequence| {
                self.coordinate(sequence)
                    .map(|coordinate| (sequence, coordinate.clone()))
            })
            .collect()
    }

    /// Collects every history entry before sequence `through`.
    pub(super) fn entries_through(
        &self,
        through: u64,
    ) -> Result<Vec<SchedulerEventLogEntry>, SessionError> {
        Ok(self.entries.collect_through(through)?)
    }

    /// Returns the breakpoint condition prefix over the whole history.
    ///
    /// The prefix is built from the history once when breakpoints become
    /// armed and is extended by [`Self::append`] afterwards. `empty_base` is
    /// the sequence an empty history's first entry will carry. Every console
    /// pattern in `patterns` is declared, which folds the retained console
    /// output once per new pattern.
    pub(super) fn condition_prefix(
        &mut self,
        patterns: &BTreeSet<(NodeId, String)>,
        empty_base: u64,
    ) -> Result<&ConditionEventLogPrefix, SessionError> {
        let prefix = match self.condition_prefix.take() {
            Some(prefix) => prefix,
            None => self.build_condition_prefix(empty_base)?,
        };
        let prefix = self.condition_prefix.insert(prefix);
        for (node, pattern) in patterns {
            prefix
                .declare_console_pattern(node, pattern)
                .map_err(|error| SessionError::BreakpointConditionPrefix {
                    reason: error.to_string(),
                })?;
        }
        Ok(prefix)
    }

    /// Releases the breakpoint condition prefix once no breakpoint is armed.
    pub(super) fn release_condition_prefix(&mut self) {
        self.condition_prefix = None;
    }

    fn build_condition_prefix(
        &self,
        empty_base: u64,
    ) -> Result<ConditionEventLogPrefix, SessionError> {
        let Some(base) = self.entries.base() else {
            return Ok(ConditionEventLogPrefix::empty_at(empty_base));
        };
        let entries = self.entries.collect_through(u64::MAX)?;
        ConditionEventLogPrefix::from_scheduler_event_log_entries_with_base_sequence(entries, base)
            .map_err(|error| SessionError::BreakpointConditionPrefix {
                reason: error.to_string(),
            })
    }

    // Extends a live prefix; a refused or discontinuous batch drops it so the
    // next evaluation rebuilds it and reports any refusal there.
    fn extend_condition_prefix(&mut self, entries: &[SchedulerEventLogEntry]) {
        let Some(prefix) = self.condition_prefix.as_mut() else {
            return;
        };
        let continues = entries
            .first()
            .is_some_and(|first| first.sequence() == prefix.next_sequence());
        if !continues || prefix.append_entries(entries.to_vec()).is_err() {
            self.condition_prefix = None;
        }
    }
}
