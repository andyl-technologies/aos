//! Bounded storage for process-local QEMU execution evidence.
//!
//! The observer keeps its own copy of the attempt's native scheduler entries
//! for finding replay and exact-failure retention. That copy is retained as
//! sealed segments plus an open tail ([`AttemptEventLog`]) under the
//! deployment's `maximum_event_log_bytes`, the same operational bound the
//! modeled driver applies (RFC-0020 CCOMP-25 through CCOMP-28). An executor
//! attempt seals the copy into its own directory, like the driver's log.
//! Sealed segments are shared, so a snapshot copies only the open tail.
//!
//! The resolved-effect trace is retained the same way: the snapshot holds a
//! segmented trace handle whose segments stay in the lifecycle's segment
//! store, so retaining a long trace costs its manifest, not its items.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use crucible_engine::model::ResolvedEffectTrace;
use crucible_engine::{FingerprintSample, SchedulerError, SchedulerEventLogEntry};

use super::{MAX_EXECUTION_FINGERPRINT_SAMPLES, MAX_TERMINAL_FINGERPRINT_SAMPLES};
use crate::DEFAULT_MAXIMUM_EVENT_LOG_BYTES;
use crate::attempt_event_log::{
    AttemptEventLog, AttemptEventLogError, AttemptEventLogVisitError, AttemptLogManifest,
    AttemptLogSegmentRef, AttemptLogSegmentSources, AttemptLogStore, MAX_ATTEMPT_LOG_ENTRY_BYTES,
};

/// Scheduler progress and reproduction evidence from one QEMU attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QemuAttemptExecutionEvidenceSnapshot {
    quanta: u64,
    frontier: crucible_engine::VirtualTime,
    latest_quantum_start_events: Option<u64>,
    semantic_stop_events: Option<u64>,
    event_log: RecordedEventLog,
    execution_fingerprints: Vec<FingerprintSample>,
    terminal_fingerprints: Option<Vec<FingerprintSample>>,
    resolved_effect_trace: Option<ResolvedEffectTrace>,
}

impl QemuAttemptExecutionEvidenceSnapshot {
    #[cfg(test)]
    pub(crate) fn for_replay_capture_test(
        quanta: u64,
        frontier: crucible_engine::VirtualTime,
        event_log_entries: &[SchedulerEventLogEntry],
    ) -> Result<Self, SchedulerError> {
        let mut event_log = RecordedEventLog::default();
        event_log.append(event_log_entries)?;
        Ok(Self {
            quanta,
            frontier,
            event_log,
            terminal_fingerprints: Some(Vec::new()),
            ..Self::default()
        })
    }

    /// Returns the absolute scheduler-quantum coordinate at the latest retained boundary.
    #[must_use]
    pub const fn quanta(&self) -> u64 {
        self.quanta
    }

    /// Returns the last successfully completed scheduler frontier.
    #[must_use]
    pub const fn frontier(&self) -> crucible_engine::VirtualTime {
        self.frontier
    }

    /// Returns the retained event offset before the latest completed quantum.
    #[must_use]
    pub const fn latest_quantum_start_events(&self) -> Option<u64> {
        self.latest_quantum_start_events
    }

    /// Returns the full event count at the modeled stop, before shutdown drain.
    #[must_use]
    pub const fn semantic_stop_events(&self) -> Option<u64> {
        self.semantic_stop_events
    }

    /// Returns the number of scheduler entries retained for the attempt.
    #[must_use]
    pub fn event_log_len(&self) -> u64 {
        self.event_log.len()
    }

    /// Returns the sequence of the first retained scheduler entry.
    ///
    /// A resumed attempt retains only its native suffix, which begins at the
    /// restored checkpoint's event count rather than at zero.
    #[must_use]
    pub fn first_event_sequence(&self) -> Option<u64> {
        self.event_log.first_sequence()
    }

    /// Visits the retained scheduler entries in order.
    ///
    /// Sealed segments are decoded one at a time, so the visit holds at most
    /// one segment's entries in memory.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogVisitError::Log`] when a sealed segment cannot
    /// be read back, or [`AttemptEventLogVisitError::Visit`] with the first
    /// error `visit` returns.
    pub fn try_for_each_event_log_entry<E>(
        &self,
        visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), AttemptEventLogVisitError<E>> {
        self.event_log.try_for_each_from(0, visit)
    }

    /// Seals a complete replay log of `prefix`, the recorded entries, and an
    /// optional host-owned `terminal` entry, and returns its manifest.
    ///
    /// The recorded sealed segments are referenced, not copied. Only the
    /// prefix and the recorded open tail with the terminal entry are encoded
    /// as new segments, written to the recording's own store, so the returned
    /// sources read every segment the manifest names. `prefix` must end where
    /// the recording begins.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when the parts are not dense from
    /// sequence zero, a new segment cannot be encoded or stored, or the
    /// combined log references more segments than one manifest may.
    pub(crate) fn seal_replay_capture_log(
        &self,
        prefix: &[SchedulerEventLogEntry],
        terminal: Option<&SchedulerEventLogEntry>,
    ) -> Result<(AttemptLogManifest, AttemptLogSegmentSources), AttemptEventLogError> {
        let mut store = match &self.event_log.log {
            Some(log) => log.store().clone(),
            None => self.event_log.store.clone().unwrap_or_default(),
        };
        let mut segments = Vec::new();

        // The prefix precedes the recording, so its segments come first.
        if !prefix.is_empty() {
            let mut log = AttemptEventLog::new(store, u64::MAX, 0);
            log.append_all(prefix)?;
            log.seal()?;
            segments.extend_from_slice(log.sealed_segments());
            store = log.into_store();
        }

        let prefix_end = prefix.len() as u64;
        let (tail, tail_start) = match &self.event_log.log {
            Some(log) => {
                if log.first_sequence() != prefix_end {
                    return Err(AttemptEventLogError::NonDense {
                        expected: prefix_end,
                        actual: log.first_sequence(),
                    });
                }
                segments.extend_from_slice(log.sealed_segments());
                let tail = log.tail();
                (tail, log.next_sequence() - tail.len() as u64)
            }
            None => (&[][..], prefix_end),
        };

        // The open tail and the terminal entry close the log as new segments.
        let mut log = AttemptEventLog::new(store, u64::MAX, tail_start);
        log.append_all(tail)?;
        log.append_all(terminal.map(std::slice::from_ref).unwrap_or_default())?;
        log.seal()?;
        segments.extend_from_slice(log.sealed_segments());

        let manifest = AttemptLogManifest::new(segments)?;
        Ok((manifest, log.into_store().into()))
    }

    /// Copies every retained scheduler entry into memory, for assertions.
    #[cfg(test)]
    pub(crate) fn event_log_entries(
        &self,
    ) -> Result<Vec<SchedulerEventLogEntry>, AttemptEventLogError> {
        self.event_log.entries_from(0)
    }

    /// Returns the bounded initial and post-first-quantum diagnostic samples.
    #[must_use]
    pub fn execution_fingerprints(&self) -> &[FingerprintSample] {
        &self.execution_fingerprints
    }

    /// Returns the complete terminal set published after successful teardown.
    #[must_use]
    pub fn terminal_fingerprints(&self) -> Option<&[FingerprintSample]> {
        self.terminal_fingerprints.as_deref()
    }

    /// Returns the segmented resolved-effect trace retained by the live runtime.
    #[must_use]
    pub const fn resolved_effect_trace(&self) -> Option<&ResolvedEffectTrace> {
        self.resolved_effect_trace.as_ref()
    }
}

/// Native scheduler entries recorded for one attempt.
///
/// The segmented log starts at the first recorded entry's sequence, because a
/// resumed attempt records only the suffix after its restored checkpoint. The
/// observer's event offsets count recorded entries from that start.
#[derive(Clone, Debug)]
struct RecordedEventLog {
    maximum_bytes: u64,
    /// Store the log seals into, taken when the first entry is recorded.
    store: Option<AttemptLogStore>,
    log: Option<AttemptEventLog<AttemptLogStore>>,
}

impl Default for RecordedEventLog {
    fn default() -> Self {
        Self::new(DEFAULT_MAXIMUM_EVENT_LOG_BYTES, None)
    }
}

// Two recordings are equal when they retain the same entries. The bound is
// operational and is not part of the evidence (RFC-0020 CCOMP-28).
impl PartialEq for RecordedEventLog {
    fn eq(&self, other: &Self) -> bool {
        self.retained() == other.retained()
    }
}

impl Eq for RecordedEventLog {}

impl RecordedEventLog {
    /// Starts an empty recording that seals into `store`, or into memory.
    const fn new(maximum_bytes: u64, store: Option<AttemptLogStore>) -> Self {
        Self {
            maximum_bytes,
            store,
            log: None,
        }
    }

    /// Returns what the recording retains: its start, sealed segments, and tail.
    fn retained(&self) -> Option<(u64, &[AttemptLogSegmentRef], &[SchedulerEventLogEntry])> {
        self.log
            .as_ref()
            .map(|log| (log.first_sequence(), log.sealed_segments(), log.tail()))
    }

    fn len(&self) -> u64 {
        self.log.as_ref().map_or(0, AttemptEventLog::len)
    }

    fn encoded_bytes(&self) -> u64 {
        self.log.as_ref().map_or(0, AttemptEventLog::total_bytes)
    }

    fn first_sequence(&self) -> Option<u64> {
        self.log.as_ref().map(AttemptEventLog::first_sequence)
    }

    /// Appends every entry, or none of them.
    ///
    /// A refused append leaves the recording unchanged, so the last complete
    /// evidence survives for diagnosis.
    fn append(&mut self, entries: &[SchedulerEventLogEntry]) -> Result<(), SchedulerError> {
        let Some(first) = entries.first() else {
            return Ok(());
        };
        let retained = self.encoded_bytes();
        let appended = match &mut self.log {
            Some(log) => log.append_all(entries),
            None => {
                let store = self.store.clone().unwrap_or_default();
                let mut log = AttemptEventLog::new(store, self.maximum_bytes, first.sequence());
                let appended = log.append_all(entries);
                if appended.is_ok() {
                    self.store = None;
                    self.log = Some(log);
                }
                appended
            }
        };
        appended.map_err(|error| recorded_event_log_error(error, retained))
    }

    /// Visits entries from recorded offset `position` onward.
    fn try_for_each_from<E>(
        &self,
        position: u64,
        visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), AttemptEventLogVisitError<E>> {
        let Some(log) = &self.log else {
            return Ok(());
        };
        log.try_for_each_entry_from(log.first_sequence().saturating_add(position), visit)
    }

    fn entries_from(
        &self,
        position: u64,
    ) -> Result<Vec<SchedulerEventLogEntry>, AttemptEventLogError> {
        let mut entries = Vec::new();
        self.try_for_each_from(position, |entry| {
            entries.push(entry.clone());
            Ok::<(), Infallible>(())
        })
        .map_err(|error| match error {
            AttemptEventLogVisitError::Log(error) => error,
            AttemptEventLogVisitError::Visit(never) => match never {},
        })?;
        Ok(entries)
    }
}

/// Shared read-only evidence for the most recently constructed attempt.
#[derive(Clone, Debug, Default)]
pub struct QemuAttemptExecutionEvidence {
    snapshot: Arc<Mutex<QemuAttemptExecutionEvidenceSnapshot>>,
}

impl QemuAttemptExecutionEvidence {
    /// Reads the most recent successfully recorded attempt progress.
    ///
    /// The copy shares sealed event-log segments with the recorder and copies
    /// only the open tail, bounded fingerprints, and resolved-effect data.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the process-local evidence lock is poisoned.
    pub fn snapshot(&self) -> Result<QemuAttemptExecutionEvidenceSnapshot, SchedulerError> {
        self.snapshot
            .lock()
            .map(|snapshot| snapshot.clone())
            .map_err(|_| evidence_poisoned())
    }

    /// Reads the terminal fingerprint set without copying the event log.
    pub(super) fn terminal_fingerprints(
        &self,
    ) -> Result<Option<Vec<FingerprintSample>>, SchedulerError> {
        self.snapshot
            .lock()
            .map(|snapshot| snapshot.terminal_fingerprints.clone())
            .map_err(|_| evidence_poisoned())
    }

    /// Clears the evidence for a new attempt bounded by `maximum_event_log_bytes`.
    ///
    /// The recorded log seals into `store` when one is given, and into memory
    /// otherwise.
    pub(super) fn reset(
        &self,
        maximum_event_log_bytes: u64,
        store: Option<AttemptLogStore>,
    ) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        *snapshot = QemuAttemptExecutionEvidenceSnapshot {
            event_log: RecordedEventLog::new(maximum_event_log_bytes, store),
            ..QemuAttemptExecutionEvidenceSnapshot::default()
        };
        Ok(())
    }

    pub(super) fn record(
        &self,
        quanta: u64,
        frontier: crucible_engine::VirtualTime,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        let quantum_start_events = snapshot.event_log.len();
        snapshot.event_log.append(entries)?;
        snapshot.quanta = quanta;
        snapshot.frontier = frontier;
        snapshot.latest_quantum_start_events = Some(quantum_start_events);
        Ok(())
    }

    pub(super) fn record_appended_entries(
        &self,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        snapshot.event_log.append(entries)
    }

    pub(super) fn record_preselection_settlement(
        &self,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<usize, SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        let start = snapshot.latest_quantum_start_events.ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: String::from("preselection settlement has no recorded quantum"),
            }
        })?;
        if start > snapshot.event_log.len() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("preselection quantum offset exceeds recorded evidence"),
            });
        }

        // Only the latest quantum's entries are read back; the settlement
        // must repeat them exactly before its suffix extends the log.
        let recorded = snapshot
            .event_log
            .entries_from(start)
            .map_err(recorded_event_log_read_error)?;
        let suffix = entries.strip_prefix(recorded.as_slice()).ok_or_else(|| {
            let (index, field) = first_preselection_evidence_difference(&recorded, entries);
            SchedulerError::BoundaryViolation {
                message: format!(
                    "preselection settlement changed recorded quantum evidence at event {index} ({field}); recorded={} settled={}",
                    recorded.len(),
                    entries.len(),
                ),
            }
        })?;
        snapshot.event_log.append(suffix)?;
        recorded_offset(&snapshot)
    }

    pub(super) fn record_selected_preselection_suffix(
        &self,
        entries: &[SchedulerEventLogEntry],
        selected_prefix_end: usize,
    ) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        let quantum_start = snapshot.latest_quantum_start_events.ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: String::from("selected preselection has no recorded quantum"),
            }
        })?;
        if (selected_prefix_end as u64) < quantum_start
            || snapshot.event_log.len() != selected_prefix_end as u64
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("selected preselection evidence prefix changed"),
            });
        }

        // The scheduler excludes the already-published selected prefix from
        // its returned outcome. Its suffix must begin at the next dense log
        // sequence; otherwise it cannot extend the authenticated prefix.
        validate_contiguous_preselection_entries(selected_prefix_end, entries, "suffix")?;
        snapshot.event_log.append(entries)
    }

    pub(super) fn record_selected_preselection_selection(
        &self,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<usize, SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        if snapshot.latest_quantum_start_events.is_none() || entries.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("selected preselection has no recorded reservation or event"),
            });
        }

        // The wrapped scheduler authenticates the exact offered selection and
        // returns only its newly emitted append, not the preceding quantum.
        let selected_prefix_end = recorded_offset(&snapshot)?;
        validate_contiguous_preselection_entries(selected_prefix_end, entries, "selection")?;
        snapshot.event_log.append(entries)?;
        recorded_offset(&snapshot)
    }

    pub(super) fn record_semantic_stop(&self) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        snapshot.semantic_stop_events = Some(snapshot.event_log.len());
        Ok(())
    }

    /// Records the final drain, trace, and terminal fingerprints.
    ///
    /// The trace is a segmented handle: its length is bounded by the authored
    /// replay counters the fault runtime enforced while recording, not by an
    /// evidence byte ceiling (RFC-0020 section 15).
    pub(super) fn complete(
        &self,
        entries: &[SchedulerEventLogEntry],
        resolved_effect_trace: Option<ResolvedEffectTrace>,
        terminal_fingerprints: Option<Vec<FingerprintSample>>,
    ) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        if terminal_fingerprints
            .as_ref()
            .is_some_and(|samples| samples.len() > MAX_TERMINAL_FINGERPRINT_SAMPLES)
        {
            return Err(evidence_limit(
                "qemu-terminal-fingerprint-count",
                0,
                terminal_fingerprints.as_ref().map_or(0, Vec::len) as u64,
                MAX_TERMINAL_FINGERPRINT_SAMPLES as u64,
            ));
        }

        // The bounded fingerprint payload was validated above and the append
        // is all-or-nothing, so a rejected final drain preserves the last
        // complete evidence snapshot for diagnosis.
        snapshot.event_log.append(entries)?;
        snapshot.resolved_effect_trace = resolved_effect_trace;
        snapshot.terminal_fingerprints = terminal_fingerprints;
        Ok(())
    }

    pub(super) fn record_fingerprints(
        &self,
        samples: Vec<FingerprintSample>,
    ) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        let total = snapshot
            .execution_fingerprints
            .len()
            .checked_add(samples.len())
            .ok_or_else(|| {
                evidence_limit(
                    "qemu-execution-fingerprint-count",
                    snapshot.execution_fingerprints.len() as u64,
                    samples.len() as u64,
                    MAX_EXECUTION_FINGERPRINT_SAMPLES as u64,
                )
            })?;
        if total > MAX_EXECUTION_FINGERPRINT_SAMPLES {
            return Err(evidence_limit(
                "qemu-execution-fingerprint-count",
                snapshot.execution_fingerprints.len() as u64,
                samples.len() as u64,
                MAX_EXECUTION_FINGERPRINT_SAMPLES as u64,
            ));
        }
        snapshot
            .execution_fingerprints
            .try_reserve(samples.len())
            .map_err(|_| evidence_allocation("reserve execution fingerprint evidence"))?;
        snapshot.execution_fingerprints.extend(samples);
        Ok(())
    }
}

fn first_preselection_evidence_difference(
    recorded: &[SchedulerEventLogEntry],
    settled: &[SchedulerEventLogEntry],
) -> (usize, &'static str) {
    for (index, (before, after)) in recorded.iter().zip(settled).enumerate() {
        if before == after {
            continue;
        }

        let field = if before.sequence() != after.sequence() {
            "sequence"
        } else if before.time() != after.time() {
            "time"
        } else if before.source() != after.source() {
            "source"
        } else if before.level() != after.level() {
            "level"
        } else if before.class() != after.class() {
            "class"
        } else if before.event_payload().kind() != after.event_payload().kind() {
            "event-kind"
        } else if before.event_payload().attributes() != after.event_payload().attributes() {
            "event-attributes"
        } else if before.payload() != after.payload() {
            "typed-payload"
        } else if before.content_hash() != after.content_hash() {
            "content-hash"
        } else {
            "entry-metadata"
        };
        return (index, field);
    }

    (settled.len(), "missing-recorded-event")
}

fn validate_contiguous_preselection_entries(
    prefix_end: usize,
    entries: &[SchedulerEventLogEntry],
    phase: &'static str,
) -> Result<(), SchedulerError> {
    for (index, entry) in entries.iter().enumerate() {
        let expected = prefix_end
            .checked_add(index)
            .and_then(|sequence| u64::try_from(sequence).ok());
        if expected != Some(entry.sequence()) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "selected preselection {phase} is not contiguous at event {index}"
                ),
            });
        }
    }
    Ok(())
}

fn recorded_offset(
    snapshot: &QemuAttemptExecutionEvidenceSnapshot,
) -> Result<usize, SchedulerError> {
    usize::try_from(snapshot.event_log.len()).map_err(|_| SchedulerError::BoundaryViolation {
        message: String::from("recorded QEMU execution evidence exceeds host address space"),
    })
}

fn recorded_event_log_error(error: AttemptEventLogError, retained: u64) -> SchedulerError {
    match error {
        AttemptEventLogError::StorageLimit { required, limit } => evidence_limit(
            "qemu-execution-event-bytes",
            retained,
            required.saturating_sub(retained),
            limit,
        ),
        AttemptEventLogError::EntryTooLarge { bytes, .. } => evidence_limit(
            "qemu-execution-event-entry-bytes",
            0,
            bytes as u64,
            MAX_ATTEMPT_LOG_ENTRY_BYTES as u64,
        ),
        AttemptEventLogError::NonDense { expected, actual } => SchedulerError::BoundaryViolation {
            message: format!(
                "recorded QEMU execution evidence expected event {expected}, got {actual}"
            ),
        },
        error => SchedulerError::BoundaryViolation {
            message: format!("retain QEMU execution evidence: {error}"),
        },
    }
}

fn recorded_event_log_read_error(error: AttemptEventLogError) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: format!("read recorded QEMU execution evidence: {error}"),
    }
}

pub(super) fn evidence_limit(
    field: &'static str,
    current: u64,
    requested: u64,
    hard: u64,
) -> SchedulerError {
    SchedulerError::ResourceLimit {
        field,
        current,
        requested,
        configured: hard,
        hard,
    }
}

fn evidence_allocation(operation: &'static str) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: format!("{operation}: allocation failed"),
    }
}

fn evidence_poisoned() -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: String::from("QEMU attempt execution evidence is poisoned"),
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use crucible_engine::{ContentHash, ExecutionFingerprint, NodeId, VirtualTime};

    use super::*;

    #[test]
    fn post_quantum_entries_extend_evidence_without_advancing_frontier() {
        let evidence = QemuAttemptExecutionEvidence::default();
        let frontier = VirtualTime { ticks: 19 };
        let quantum_entry = SchedulerEventLogEntry::execution_budget_exhausted(
            0,
            frontier,
            "quantum-boundary-fixture",
        );
        let reply_entry = SchedulerEventLogEntry::execution_budget_exhausted(
            1,
            frontier,
            "selectable-reply-fixture",
        );

        evidence
            .record(7, frontier, std::slice::from_ref(&quantum_entry))
            .expect("record quantum evidence");
        evidence
            .record_appended_entries(std::slice::from_ref(&reply_entry))
            .expect("record same-boundary reply evidence");

        let snapshot = evidence.snapshot().expect("complete event prefix");
        assert_eq!(snapshot.quanta(), 7);
        assert_eq!(snapshot.frontier(), frontier);
        assert_eq!(
            snapshot.event_log_entries().expect("read evidence"),
            [quantum_entry, reply_entry]
        );
    }

    #[test]
    fn settled_preselection_records_only_its_authenticated_suffix() {
        let evidence = QemuAttemptExecutionEvidence::default();
        let frontier = VirtualTime { ticks: 19 };
        let prefix =
            SchedulerEventLogEntry::execution_budget_exhausted(0, frontier, "preselection-prefix");
        let suffix =
            SchedulerEventLogEntry::execution_budget_exhausted(1, frontier, "preselection-suffix");
        evidence
            .record(7, frontier, std::slice::from_ref(&prefix))
            .expect("record reserved boundary");

        evidence
            .record_preselection_settlement(&[prefix.clone(), suffix.clone()])
            .expect("append settlement suffix");
        let snapshot = evidence.snapshot().expect("settled evidence");
        assert_eq!(
            snapshot.event_log_entries().expect("read evidence"),
            [prefix.clone(), suffix]
        );

        let error = evidence
            .record_preselection_settlement(&[])
            .expect_err("settlement cannot replace reserved evidence");
        assert!(
            error
                .to_string()
                .contains("at event 0 (missing-recorded-event); recorded=2 settled=0")
        );
        assert_eq!(evidence.snapshot().expect("unchanged evidence"), snapshot);
    }

    #[test]
    fn preselection_mismatch_reports_first_field_without_payload_values() {
        let evidence = QemuAttemptExecutionEvidence::default();
        let frontier = VirtualTime { ticks: 19 };
        let recorded = SchedulerEventLogEntry::execution_budget_exhausted(
            0,
            frontier,
            "private-recorded-budget",
        );
        let settled = SchedulerEventLogEntry::execution_budget_exhausted(
            0,
            frontier,
            "private-settled-budget",
        );
        evidence
            .record(1, frontier, &[recorded])
            .expect("record reserved boundary");

        let error = evidence
            .record_preselection_settlement(&[settled])
            .expect_err("changed event attributes must be rejected");
        let message = error.to_string();
        assert!(message.contains("at event 0 (event-attributes); recorded=1 settled=1"));
        assert!(!message.contains("private-recorded-budget"));
        assert!(!message.contains("private-settled-budget"));
    }

    #[test]
    fn selected_preselection_records_only_contiguous_suffix_after_one_or_many_entries() {
        for selected_count in [1, 3] {
            let evidence = QemuAttemptExecutionEvidence::default();
            let frontier = VirtualTime { ticks: 19 };
            let prefix = [
                SchedulerEventLogEntry::execution_budget_exhausted(0, frontier, "first-prefix"),
                SchedulerEventLogEntry::execution_budget_exhausted(1, frontier, "second-prefix"),
            ];
            evidence
                .record(1, frontier, &prefix)
                .expect("record reserved boundary");

            let mut selected = Vec::new();
            for index in 0..selected_count {
                selected.push(SchedulerEventLogEntry::execution_budget_exhausted(
                    (index + prefix.len()) as u64,
                    frontier,
                    "selected-entry",
                ));
            }
            let selected_prefix_end = evidence
                .record_selected_preselection_selection(&selected)
                .expect("append authenticated selection");
            assert_eq!(selected_prefix_end, prefix.len() + selected.len());

            let suffix = [
                SchedulerEventLogEntry::execution_budget_exhausted(
                    selected_prefix_end as u64,
                    frontier,
                    "first-suffix",
                ),
                SchedulerEventLogEntry::execution_budget_exhausted(
                    selected_prefix_end as u64 + 1,
                    frontier,
                    "second-suffix",
                ),
            ];
            evidence
                .record_selected_preselection_suffix(&suffix, selected_prefix_end)
                .expect("append exact selected suffix");

            let entries = evidence
                .snapshot()
                .expect("settled evidence")
                .event_log_entries()
                .expect("read evidence");
            assert_eq!(entries.len(), selected_prefix_end + 2);
            assert_eq!(entries[..prefix.len()], prefix);
            assert_eq!(entries[prefix.len()..selected_prefix_end], selected);
            assert_eq!(entries[selected_prefix_end..], suffix);
        }
    }

    #[test]
    fn selected_preselection_rejects_stale_prefix_or_noncontiguous_suffix() {
        let evidence = QemuAttemptExecutionEvidence::default();
        let frontier = VirtualTime { ticks: 19 };
        let prefix = SchedulerEventLogEntry::execution_budget_exhausted(0, frontier, "prefix");
        assert!(
            evidence
                .record_selected_preselection_selection(std::slice::from_ref(&prefix))
                .is_err()
        );
        evidence
            .record(1, frontier, std::slice::from_ref(&prefix))
            .expect("record reserved boundary");
        assert!(
            evidence
                .record_selected_preselection_selection(&[])
                .is_err()
        );
        let wrong_selection =
            SchedulerEventLogEntry::execution_budget_exhausted(2, frontier, "wrong-selection");
        let error = evidence
            .record_selected_preselection_selection(&[wrong_selection])
            .expect_err("selection append cannot skip an event");
        assert!(
            error
                .to_string()
                .contains("selection is not contiguous at event 0")
        );
        let selected = SchedulerEventLogEntry::execution_budget_exhausted(1, frontier, "selected");
        let selected_prefix_end = evidence
            .record_selected_preselection_selection(std::slice::from_ref(&selected))
            .expect("append authenticated selection");
        let skipped = SchedulerEventLogEntry::execution_budget_exhausted(3, frontier, "skipped");

        let error = evidence
            .record_selected_preselection_suffix(&[skipped], selected_prefix_end)
            .expect_err("gap cannot extend selected prefix");
        assert!(error.to_string().contains("not contiguous at event 0"));
        let error = evidence
            .record_selected_preselection_suffix(&[], selected_prefix_end + 1)
            .expect_err("stale selected prefix cannot be extended");
        assert!(error.to_string().contains("evidence prefix changed"));
        assert_eq!(
            evidence
                .snapshot()
                .expect("unchanged evidence")
                .event_log_entries()
                .expect("read evidence"),
            [prefix, selected]
        );
    }

    #[test]
    fn resumed_suffix_counts_offsets_from_its_first_recorded_sequence() {
        let evidence = QemuAttemptExecutionEvidence::default();
        let frontier = VirtualTime { ticks: 19 };
        let entry = |sequence| {
            SchedulerEventLogEntry::execution_budget_exhausted(sequence, frontier, "resumed-suffix")
        };
        evidence
            .record(4, frontier, &[entry(5), entry(6)])
            .expect("record resumed quantum");

        let settled = evidence
            .record_preselection_settlement(&[entry(5), entry(6), entry(7)])
            .expect("settle resumed quantum");
        assert_eq!(settled, 3);
        let snapshot = evidence.snapshot().expect("resumed evidence");
        assert_eq!(snapshot.first_event_sequence(), Some(5));
        assert_eq!(snapshot.latest_quantum_start_events(), Some(0));
        assert_eq!(
            snapshot.event_log_entries().expect("read evidence"),
            [entry(5), entry(6), entry(7)]
        );

        let error = evidence
            .record_appended_entries(&[entry(9)])
            .expect_err("a gap cannot extend recorded evidence");
        assert!(error.to_string().contains("expected event 8, got 9"));
        assert_eq!(evidence.snapshot().expect("unchanged evidence"), snapshot);
    }

    #[test]
    fn long_recordings_seal_segments_and_settle_across_them() {
        let evidence = QemuAttemptExecutionEvidence::default();
        let frontier = VirtualTime { ticks: 19 };
        // Each entry is large enough that the log seals segments well before
        // the fixture ends.
        let reason = "segment-fixture-".repeat(4096);
        let entries = (0..200)
            .map(|sequence| {
                SchedulerEventLogEntry::execution_budget_exhausted(sequence, frontier, &reason)
            })
            .collect::<Vec<_>>();
        evidence
            .record(1, frontier, &entries[..150])
            .expect("record first quantum");
        let early = evidence.snapshot().expect("early snapshot");
        evidence
            .record(2, frontier, &entries[150..199])
            .expect("record second quantum");

        let settled = evidence
            .record_preselection_settlement(&entries[150..])
            .expect("settle across sealed segments");
        assert_eq!(settled, 200);
        let snapshot = evidence.snapshot().expect("long snapshot");
        let log = snapshot.event_log.log.as_ref().expect("recorded log");
        assert!(!log.sealed_segments().is_empty());
        assert_eq!(
            snapshot.event_log_entries().expect("read evidence"),
            entries
        );
        assert_eq!(
            early.event_log_entries().expect("read early evidence"),
            entries[..150]
        );
    }

    #[test]
    fn replay_capture_log_references_recorded_segments_by_identity() {
        let evidence = QemuAttemptExecutionEvidence::default();
        let frontier = VirtualTime { ticks: 19 };
        let reason = "segment-fixture-".repeat(4096);
        let entries = (0..401)
            .map(|sequence| {
                SchedulerEventLogEntry::execution_budget_exhausted(sequence, frontier, &reason)
            })
            .collect::<Vec<_>>();
        let (prefix, rest) = entries.split_at(10);
        let (recorded, terminal) = rest.split_at(390);

        // A resumed attempt records only what follows its prefix.
        evidence
            .record(1, frontier, recorded)
            .expect("record the resumed attempt");
        let snapshot = evidence.snapshot().expect("snapshot");
        let recorded_segments = snapshot
            .event_log
            .log
            .as_ref()
            .expect("recorded log")
            .sealed_segments()
            .to_vec();
        assert!(recorded_segments.len() > 1, "the fixture spans segments");

        let (manifest, sources) = snapshot
            .seal_replay_capture_log(prefix, terminal.first())
            .expect("seal capture log");
        let read_back = manifest
            .entries(&sources)
            .collect::<Result<Vec<_>, _>>()
            .expect("read capture log");

        assert_eq!(read_back, entries);
        assert_eq!(manifest.entry_count(), 401);
        // The recording's sealed segments are reused, not re-encoded; only the
        // prefix and the closing tail become new segments around them.
        let start = manifest
            .segments()
            .iter()
            .position(|segment| *segment == recorded_segments[0])
            .expect("recorded segments are referenced");
        assert_eq!(start, 1, "the prefix fits in one leading segment");
        assert_eq!(
            manifest.segments()[start..start + recorded_segments.len()],
            recorded_segments[..]
        );
        assert_eq!(
            manifest.segments().len(),
            recorded_segments.len() + 2,
            "one prefix segment and one closing tail segment"
        );

        assert!(matches!(
            snapshot.seal_replay_capture_log(&prefix[..9], None),
            Err(AttemptEventLogError::NonDense { .. })
        ));
    }

    #[test]
    fn recordings_under_a_namespace_seal_into_their_own_directory() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let namespace = crate::AttemptLogNamespace::create(parent.path().join("event-logs"))
            .expect("namespace");
        let evidence = QemuAttemptExecutionEvidence::default();
        let frontier = VirtualTime { ticks: 19 };
        let reason = "segment-fixture-".repeat(4096);
        let entries = (0..200)
            .map(|sequence| {
                SchedulerEventLogEntry::execution_budget_exhausted(sequence, frontier, &reason)
            })
            .collect::<Vec<_>>();
        evidence
            .reset(
                DEFAULT_MAXIMUM_EVENT_LOG_BYTES,
                Some(namespace.create_store().expect("attempt store")),
            )
            .expect("bind the attempt store");

        evidence
            .record(1, frontier, &entries)
            .expect("record the attempt");
        let snapshot = evidence.snapshot().expect("snapshot");
        let log = snapshot.event_log.log.as_ref().expect("recorded log");
        let AttemptLogStore::Directory(store) = log.store() else {
            panic!("namespace recordings seal to disk");
        };
        let directory = store.directory().path().to_path_buf();
        let files = std::fs::read_dir(&directory)
            .expect("list attempt segments")
            .count();

        assert!(!log.sealed_segments().is_empty());
        assert_eq!(files, log.sealed_segments().len());
        assert_eq!(
            snapshot.event_log_entries().expect("read evidence"),
            entries
        );
        evidence
            .reset(DEFAULT_MAXIMUM_EVENT_LOG_BYTES, None)
            .expect("start the next attempt");
        assert!(directory.is_dir(), "the snapshot still reads the directory");
        drop(snapshot);
        assert!(!directory.exists());
    }

    #[test]
    fn event_byte_limit_refusal_preserves_the_complete_snapshot() {
        let retained_entry = SchedulerEventLogEntry::execution_budget_exhausted(
            0,
            VirtualTime { ticks: 19 },
            "retained-evidence-limit-fixture",
        );
        let probe = QemuAttemptExecutionEvidence::default();
        probe
            .record(
                7,
                VirtualTime { ticks: 19 },
                std::slice::from_ref(&retained_entry),
            )
            .expect("measure retained event evidence");
        let retained_bytes = probe
            .snapshot()
            .expect("measured snapshot")
            .event_log
            .encoded_bytes();

        // The bound admits exactly the retained entry, so any further entry
        // exceeds it.
        let evidence = QemuAttemptExecutionEvidence::default();
        evidence
            .reset(retained_bytes, None)
            .expect("bound the attempt");
        evidence
            .record(7, VirtualTime { ticks: 19 }, &[retained_entry])
            .expect("seed retained event evidence");
        let before = evidence.snapshot().expect("snapshot before refusal");
        let entries = [
            SchedulerEventLogEntry::execution_budget_exhausted(
                1,
                VirtualTime { ticks: 20 },
                "evidence-limit-fixture",
            ),
            SchedulerEventLogEntry::execution_budget_exhausted(
                2,
                VirtualTime { ticks: 20 },
                "evidence-limit-fixture",
            ),
        ];

        let error = evidence
            .record(8, VirtualTime { ticks: 20 }, &entries)
            .expect_err("the event byte bound must reject another entry");

        assert!(matches!(
            error,
            SchedulerError::ResourceLimit {
                field: "qemu-execution-event-bytes",
                ..
            }
        ));
        assert_eq!(evidence.snapshot().expect("snapshot after refusal"), before);
    }

    #[test]
    fn completion_retains_the_segmented_effect_trace_handle() {
        let evidence = QemuAttemptExecutionEvidence::default();
        evidence
            .record(3, VirtualTime { ticks: 11 }, &[])
            .expect("seed evidence");
        let item = crucible_engine::model::ResolvedReplayWorkItem {
            coordinate: crucible_engine::model::FaultCoordinate {
                virtual_ticks: 12,
                retired_instructions: None,
            },
            same_coordinate_sequence: 0,
            opportunity: None,
            target: None,
            operation: None,
            direction: None,
            phase: None,
            network_frame_key: None,
            network_producer_direction_key: None,
            derivation_fingerprint: ContentHash::from_bytes(b"retained-trace-fixture"),
            records: Vec::new(),
        };
        let trace = ResolvedEffectTrace::from_items(
            crucible_engine::model::FaultReplayMode::RecomputedCause,
            [item.clone()],
            crucible_engine::model::FaultResourceLimits::default(),
        )
        .expect("trace fixture");

        evidence
            .complete(&[], Some(trace.clone()), Some(Vec::new()))
            .expect("complete evidence");

        let snapshot = evidence.snapshot().expect("completed snapshot");
        let retained = snapshot
            .resolved_effect_trace()
            .expect("the completed snapshot retains the trace");
        assert_eq!(retained, &trace);
        let items = retained
            .items()
            .collect::<Result<Vec<_>, _>>()
            .expect("retained items stay readable");
        assert_eq!(items, vec![item]);
    }

    #[test]
    fn terminal_fingerprint_limit_refusal_preserves_prior_evidence() {
        let evidence = QemuAttemptExecutionEvidence::default();
        evidence
            .record(3, VirtualTime { ticks: 11 }, &[])
            .expect("seed evidence");
        let before = evidence.snapshot().expect("snapshot before refusal");
        let sample = FingerprintSample {
            node: NodeId {
                name: String::from("terminal-limit-fixture"),
            },
            at: VirtualTime { ticks: 11 },
            fingerprint: ExecutionFingerprint {
                hash: ContentHash::from_bytes(b"terminal-limit-fixture"),
            },
        };
        let terminal_fingerprints =
            vec![sample; MAX_TERMINAL_FINGERPRINT_SAMPLES.saturating_add(1)];

        let error = evidence
            .complete(&[], None, Some(terminal_fingerprints))
            .expect_err("the terminal fingerprint ceiling must reject the final evidence");

        assert!(matches!(
            error,
            SchedulerError::ResourceLimit {
                field: "qemu-terminal-fingerprint-count",
                ..
            }
        ));
        assert_eq!(evidence.snapshot().expect("snapshot after refusal"), before);
    }
}
