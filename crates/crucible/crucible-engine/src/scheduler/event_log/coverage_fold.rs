//! Streaming construction of event-log coverage feedback.
//!
//! [`EventLogCoverageFeedback::from_event_log`] needs the whole log as one
//! slice. Callers that read a retained log one segment at a time use
//! [`EventLogCoverageFold`] instead: it keeps only the coverage entries and
//! their unique observation material, and finishes with the same feedback.
//!
//! A fold still keeps one entry per coverage hit, because its projection
//! reports stream context. Consumers that need only the distinct coverage and
//! its fingerprint use [`EventLogCoverageSet`], whose size is bounded by the
//! guest's distinct coverage rather than by the length of the run.

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
/// # fn read_log() -> Vec<crucible_engine::SchedulerEventLogEntry> { Vec::new() }
/// let mut fold = crucible_engine::EventLogCoverageFold::new();
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
        EventLogCoverageProjection {
            content_hash: coverage_fingerprint(self.unique_material.iter()),
            entries: self.entries,
        }
    }
}

/// Distinct coverage observations folded from a streamed event log.
///
/// Each distinct observation is kept once, keyed by the canonical material
/// that the coverage fingerprint hashes, together with a count of coverage
/// hits. Observing every entry of a log yields the same
/// [`fingerprint`](Self::fingerprint) and identity set as the
/// [`EventLogCoverageFeedback`] built from those entries.
///
/// # Examples
///
/// ```no_run
/// # fn read_log() -> Vec<crucible_engine::SchedulerEventLogEntry> { Vec::new() }
/// let mut coverage = crucible_engine::EventLogCoverageSet::new();
/// for entry in read_log() {
///     coverage.observe(&entry);
/// }
/// let identities = coverage.identities();
/// # let _ = (identities, coverage.fingerprint());
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventLogCoverageSet {
    // Keyed by canonical observation material, so iteration follows the order
    // in which the fingerprint hashes the distinct observations.
    observations: BTreeMap<String, EventLogCoverageObservation>,
    hits: u64,
}

impl EventLogCoverageSet {
    /// Starts an empty coverage set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes the next entry of a log.
    ///
    /// Returns whether the entry carried a coverage observation, whether or
    /// not that observation was already present.
    pub fn observe(&mut self, entry: &SchedulerEventLogEntry) -> bool {
        let Some(observation) = EventLogCoverageObservation::from_entry(entry) else {
            return false;
        };
        self.hits = self.hits.saturating_add(1);
        self.insert(observation);
        true
    }

    /// Adds one distinct observation without counting a hit.
    ///
    /// Returns whether the observation was not yet present.
    pub fn insert(&mut self, observation: EventLogCoverageObservation) -> bool {
        match self
            .observations
            .entry(event_log_coverage_observation_material(&observation))
        {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(observation);
                true
            }
            std::collections::btree_map::Entry::Occupied(_) => false,
        }
    }

    /// Returns the number of distinct observations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// Returns whether no coverage was observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// Returns the number of coverage entries observed, duplicates included.
    ///
    /// This equals the entry count of the corresponding coverage projection.
    #[must_use]
    pub const fn hits(&self) -> u64 {
        self.hits
    }

    /// Returns the distinct observations in canonical fingerprint order.
    pub fn observations(&self) -> impl ExactSizeIterator<Item = &EventLogCoverageObservation> {
        self.observations.values()
    }

    /// Returns the content identity of every distinct observation.
    #[must_use]
    pub fn identities(&self) -> BTreeSet<ContentHash> {
        self.observations
            .values()
            .map(EventLogCoverageObservation::content_hash)
            .collect()
    }

    /// Returns the deterministic coverage fingerprint.
    ///
    /// It equals [`EventLogCoverageFeedback::fingerprint`] for the same log.
    #[must_use]
    pub fn fingerprint(&self) -> ContentHash {
        coverage_fingerprint(self.observations.keys())
    }
}

/// Hashes sorted unique observation material into the coverage fingerprint.
///
/// Empty coverage has the default hash, so a log without coverage never
/// collides with a log that covered something.
fn coverage_fingerprint<'a>(material: impl ExactSizeIterator<Item = &'a String>) -> ContentHash {
    if material.len() == 0 {
        return ContentHash::default();
    }
    ContentHash::from_canonical_material(
        "crucible.scheduler.event-log.coverage-projection.v1",
        &material.map(String::as_str).collect::<Vec<_>>().join("\n"),
    )
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
    fn coverage_set_matches_feedback_fingerprint_and_identities() {
        let entries = vec![
            diagnostic(0),
            block(1, "router", 0x1000),
            block(2, "router", 0x1000),
            block(3, "client", 0x2000),
            block(4, "router", 0x1000),
        ];
        let feedback = EventLogCoverageFeedback::from_event_log(&entries);
        let mut coverage = EventLogCoverageSet::new();

        let observed = entries
            .iter()
            .map(|entry| coverage.observe(entry))
            .collect::<Vec<_>>();

        assert_eq!(observed, [false, true, true, true, true]);
        assert_eq!(coverage.len(), 2);
        assert_eq!(coverage.hits(), 4);
        assert_eq!(coverage.hits(), feedback.projection().len() as u64);
        assert_eq!(coverage.fingerprint(), feedback.fingerprint());
        assert_eq!(
            coverage.identities(),
            feedback
                .projection()
                .entries()
                .iter()
                .map(|entry| entry.observation.content_hash())
                .collect::<BTreeSet<_>>()
        );

        let mut rebuilt = EventLogCoverageSet::new();
        for observation in coverage.observations() {
            assert!(rebuilt.insert(observation.clone()));
        }
        assert_eq!(rebuilt.fingerprint(), coverage.fingerprint());
        assert_eq!(rebuilt.hits(), 0);
        assert_eq!(
            EventLogCoverageSet::new().fingerprint(),
            EventLogCoverageFeedback::from_event_log(&[]).fingerprint()
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
