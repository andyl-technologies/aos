//! Streaming construction of event-log coverage feedback.
//!
//! [`EventLogCoverageFeedback::from_event_log`] needs the whole log as one
//! slice. Callers that read a retained log one segment at a time use
//! [`EventLogCoverageFold`] instead: it keeps only the coverage entries and
//! their unique observation material, and finishes with the same feedback.

use super::projection_material::{
    event_log_coverage_entry, event_log_coverage_observation_material,
};
use super::*;

/// Incremental builder of [`EventLogCoverageFeedback`] over a streamed log.
///
/// Observing every entry in log order and then finishing yields exactly the
/// feedback [`EventLogCoverageFeedback::from_event_log`] builds from the same
/// entries, while holding only the entries the coverage projection retains.
///
/// # Examples
///
/// ```no_run
/// # fn read_log() -> Vec<crucible::SchedulerEventLogEntry> { Vec::new() }
/// let mut fold = crucible::EventLogCoverageFold::new();
/// for entry in read_log() {
///     fold.observe(&entry);
/// }
/// let feedback = fold.finish();
/// # let _ = feedback.fingerprint();
/// ```
#[derive(Clone, Debug, Default)]
pub struct EventLogCoverageFold {
    entries: Vec<EventLogCoverageProjectionEntry>,
    unique_material: BTreeSet<String>,
    next_index: usize,
}

impl EventLogCoverageFold {
    /// Starts an empty fold.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes the next entry of the log.
    ///
    /// Returns whether the coverage projection retains the entry, so callers
    /// can keep the raw entries that coverage refers to without keeping the
    /// rest of the log.
    pub fn observe(&mut self, entry: &SchedulerEventLogEntry) -> bool {
        let raw_index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        let Some(entry) = event_log_coverage_entry(raw_index, entry) else {
            return false;
        };
        self.unique_material
            .insert(event_log_coverage_observation_material(&entry.observation));
        self.entries.push(entry);
        true
    }

    /// Finishes the fold into coverage feedback for every observed entry.
    #[must_use]
    pub fn finish(self) -> EventLogCoverageFeedback {
        EventLogCoverageFeedback {
            projection: self.into_projection(),
        }
    }

    pub(super) fn into_projection(self) -> EventLogCoverageProjection {
        let content_hash = if self.unique_material.is_empty() {
            ContentHash::default()
        } else {
            ContentHash::from_canonical_material(
                "crucible.scheduler.event-log.coverage-projection.v1",
                &self
                    .unique_material
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
        };
        EventLogCoverageProjection {
            entries: self.entries,
            content_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(sequence: u64, node: &str, guest_pc: u64) -> SchedulerEventLogEntry {
        SchedulerEventLogEntry::observable(
            sequence,
            VirtualTime { ticks: sequence },
            ObservableEventPayload::CoverageBlock {
                execution_icount: Icount { retired: sequence },
                node: NodeId {
                    name: node.to_owned(),
                },
                guest_pc,
                block_len: 4,
            },
        )
    }

    fn diagnostic(sequence: u64) -> SchedulerEventLogEntry {
        SchedulerEventLogEntry::diagnostic(
            sequence,
            VirtualTime { ticks: sequence },
            EventDiagnosticPayload::new(String::from("note"), EventLevel::Info, BTreeMap::new()),
        )
    }

    #[test]
    fn fold_matches_feedback_built_from_the_whole_log() {
        let entries = vec![
            diagnostic(0),
            block(1, "router", 0x1000),
            block(2, "router", 0x1000),
            diagnostic(3),
            block(4, "client", 0x2000),
        ];
        let mut fold = EventLogCoverageFold::new();

        let retained = entries
            .iter()
            .map(|entry| fold.observe(entry))
            .collect::<Vec<_>>();
        let folded = fold.finish();

        assert_eq!(retained, [false, true, true, false, true]);
        assert_eq!(folded, EventLogCoverageFeedback::from_event_log(&entries));
        assert_eq!(
            folded
                .projection()
                .entries()
                .iter()
                .map(|entry| entry.raw_index)
                .collect::<Vec<_>>(),
            [1, 2, 4]
        );
    }

    #[test]
    fn empty_fold_matches_empty_log_feedback() {
        assert_eq!(
            EventLogCoverageFold::new().finish(),
            EventLogCoverageFeedback::from_event_log(&[])
        );
    }
}
