//! Bounded storage for process-local QEMU execution evidence.

use std::sync::{Arc, Mutex};

use crucible::{FingerprintSample, SchedulerError, SchedulerEventLogEntry};

use super::{
    MAX_EXECUTION_FINGERPRINT_SAMPLES, MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
    MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES, MAX_TERMINAL_FINGERPRINT_SAMPLES,
};

/// Scheduler progress and reproduction evidence from one QEMU attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QemuAttemptExecutionEvidenceSnapshot {
    quanta: u64,
    frontier: crucible::VirtualTime,
    latest_quantum_start_events: Option<u64>,
    semantic_stop_events: Option<u64>,
    event_log_entries: Vec<SchedulerEventLogEntry>,
    event_log_bytes: usize,
    execution_fingerprints: Vec<FingerprintSample>,
    terminal_fingerprints: Option<Vec<FingerprintSample>>,
    resolved_effect_trace: Option<Vec<u8>>,
}

impl QemuAttemptExecutionEvidenceSnapshot {
    #[cfg(test)]
    pub(crate) fn for_replay_capture_test(
        quanta: u64,
        frontier: crucible::VirtualTime,
        event_log_entries: Vec<SchedulerEventLogEntry>,
    ) -> Self {
        let event_log_bytes = event_log_entries
            .iter()
            .map(SchedulerEventLogEntry::canonical_material_len)
            .sum();
        Self {
            quanta,
            frontier,
            event_log_entries,
            event_log_bytes,
            terminal_fingerprints: Some(Vec::new()),
            ..Self::default()
        }
    }

    /// Returns the absolute scheduler-quantum coordinate at the latest retained boundary.
    #[must_use]
    pub const fn quanta(&self) -> u64 {
        self.quanta
    }

    /// Returns the last successfully completed scheduler frontier.
    #[must_use]
    pub const fn frontier(&self) -> crucible::VirtualTime {
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

    /// Returns the exact bounded scheduler event log retained for the attempt.
    #[must_use]
    pub fn event_log_entries(&self) -> &[SchedulerEventLogEntry] {
        &self.event_log_entries
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

    /// Returns the encoded resolved-effect trace retained by the live runtime.
    #[must_use]
    pub fn resolved_effect_trace(&self) -> Option<&[u8]> {
        self.resolved_effect_trace.as_deref()
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
    /// The clone is bounded by the same 64 MiB event-material ceiling used by
    /// the campaign driver, plus bounded fingerprints and resolved-effect data.
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

    pub(super) fn reset(&self) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        *snapshot = QemuAttemptExecutionEvidenceSnapshot::default();
        Ok(())
    }

    pub(super) fn record(
        &self,
        quanta: u64,
        frontier: crucible::VirtualTime,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), SchedulerError> {
        self.record_with_event_limits(
            quanta,
            frontier,
            entries,
            MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES,
            MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
        )
    }

    pub(super) fn record_appended_entries(
        &self,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        append_event_entries(&mut snapshot, entries)
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
        let start = usize::try_from(start).map_err(|_| SchedulerError::BoundaryViolation {
            message: String::from("preselection quantum offset exceeds host address space"),
        })?;
        let recorded = snapshot.event_log_entries.get(start..).ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: String::from("preselection quantum offset exceeds recorded evidence"),
            }
        })?;
        let suffix = entries.strip_prefix(recorded).ok_or_else(|| {
            let (index, field) = first_preselection_evidence_difference(recorded, entries);
            SchedulerError::BoundaryViolation {
                message: format!(
                    "preselection settlement changed recorded quantum evidence at event {index} ({field}); recorded={} settled={}",
                    recorded.len(),
                    entries.len(),
                ),
            }
        })?;
        append_event_entries(&mut snapshot, suffix)?;
        Ok(snapshot.event_log_entries.len())
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
        let quantum_start =
            usize::try_from(quantum_start).map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from(
                    "selected preselection quantum offset exceeds host address space",
                ),
            })?;
        if selected_prefix_end < quantum_start
            || snapshot.event_log_entries.len() != selected_prefix_end
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("selected preselection evidence prefix changed"),
            });
        }

        // The scheduler excludes the already-published selected prefix from
        // its returned outcome. Its suffix must begin at the next dense log
        // sequence; otherwise it cannot extend the authenticated prefix.
        validate_contiguous_preselection_entries(selected_prefix_end, entries, "suffix")?;
        append_event_entries(&mut snapshot, entries)
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
        let selected_prefix_end = snapshot.event_log_entries.len();
        validate_contiguous_preselection_entries(selected_prefix_end, entries, "selection")?;
        append_event_entries(&mut snapshot, entries)?;
        Ok(snapshot.event_log_entries.len())
    }

    pub(super) fn record_semantic_stop(&self) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        snapshot.semantic_stop_events = Some(snapshot.event_log_entries.len() as u64);
        Ok(())
    }

    fn record_with_event_limits(
        &self,
        quanta: u64,
        frontier: crucible::VirtualTime,
        entries: &[SchedulerEventLogEntry],
        event_count_limit: usize,
        event_byte_limit: usize,
    ) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        let quantum_start_events = snapshot.event_log_entries.len() as u64;
        append_event_entries_with_limits(
            &mut snapshot,
            entries,
            event_count_limit,
            event_byte_limit,
        )?;
        snapshot.quanta = quanta;
        snapshot.frontier = frontier;
        snapshot.latest_quantum_start_events = Some(quantum_start_events);
        Ok(())
    }

    pub(super) fn complete(
        &self,
        entries: &[SchedulerEventLogEntry],
        resolved_effect_trace: Option<Vec<u8>>,
        terminal_fingerprints: Option<Vec<FingerprintSample>>,
    ) -> Result<(), SchedulerError> {
        self.complete_with_trace_limit(
            entries,
            resolved_effect_trace,
            terminal_fingerprints,
            MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
        )
    }

    fn complete_with_trace_limit(
        &self,
        entries: &[SchedulerEventLogEntry],
        resolved_effect_trace: Option<Vec<u8>>,
        terminal_fingerprints: Option<Vec<FingerprintSample>>,
        trace_byte_limit: usize,
    ) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        if resolved_effect_trace
            .as_ref()
            .is_some_and(|trace| trace.len() > trace_byte_limit)
        {
            return Err(evidence_limit(
                "qemu-resolved-effect-trace-bytes",
                0,
                resolved_effect_trace.as_ref().map_or(0, Vec::len) as u64,
                trace_byte_limit as u64,
            ));
        }
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

        // Validate and reserve both bounded payloads before mutating the
        // retained attempt. A rejected final drain must preserve the last
        // complete evidence snapshot for diagnosis.
        append_event_entries(&mut snapshot, entries)?;
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

fn append_event_entries(
    snapshot: &mut QemuAttemptExecutionEvidenceSnapshot,
    entries: &[SchedulerEventLogEntry],
) -> Result<(), SchedulerError> {
    append_event_entries_with_limits(
        snapshot,
        entries,
        MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES,
        MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
    )
}

fn append_event_entries_with_limits(
    snapshot: &mut QemuAttemptExecutionEvidenceSnapshot,
    entries: &[SchedulerEventLogEntry],
    event_count_limit: usize,
    event_byte_limit: usize,
) -> Result<(), SchedulerError> {
    let total = snapshot
        .event_log_entries
        .len()
        .checked_add(entries.len())
        .ok_or_else(|| {
            event_limit(
                snapshot,
                entries.len(),
                0,
                event_count_limit,
                event_byte_limit,
            )
        })?;
    if total > event_count_limit {
        return Err(event_limit(
            snapshot,
            entries.len(),
            0,
            event_count_limit,
            event_byte_limit,
        ));
    }
    let added_bytes = entries.iter().try_fold(0usize, |total, entry| {
        total
            .checked_add(entry.canonical_material_len())
            .ok_or_else(|| {
                event_limit(
                    snapshot,
                    entries.len(),
                    usize::MAX,
                    event_count_limit,
                    event_byte_limit,
                )
            })
    })?;
    let total_bytes = snapshot
        .event_log_bytes
        .checked_add(added_bytes)
        .ok_or_else(|| {
            event_limit(
                snapshot,
                entries.len(),
                added_bytes,
                event_count_limit,
                event_byte_limit,
            )
        })?;
    if total_bytes > event_byte_limit {
        return Err(event_limit(
            snapshot,
            entries.len(),
            added_bytes,
            event_count_limit,
            event_byte_limit,
        ));
    }
    snapshot
        .event_log_entries
        .try_reserve(entries.len())
        .map_err(|_| evidence_allocation("reserve scheduler event evidence"))?;
    snapshot.event_log_entries.extend_from_slice(entries);
    snapshot.event_log_bytes = total_bytes;
    Ok(())
}

fn event_limit(
    snapshot: &QemuAttemptExecutionEvidenceSnapshot,
    added_entries: usize,
    added_bytes: usize,
    event_count_limit: usize,
    event_byte_limit: usize,
) -> SchedulerError {
    let count_exceeded = snapshot
        .event_log_entries
        .len()
        .saturating_add(added_entries)
        > event_count_limit;
    if count_exceeded {
        evidence_limit(
            "qemu-execution-event-count",
            snapshot.event_log_entries.len() as u64,
            added_entries as u64,
            event_count_limit as u64,
        )
    } else {
        evidence_limit(
            "qemu-execution-event-bytes",
            snapshot.event_log_bytes as u64,
            added_bytes as u64,
            event_byte_limit as u64,
        )
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
    use crucible::{ContentHash, ExecutionFingerprint, NodeId, VirtualTime};

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
        assert_eq!(snapshot.event_log_entries(), &[quantum_entry, reply_entry]);
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
        assert_eq!(snapshot.event_log_entries(), &[prefix.clone(), suffix]);

        let error = evidence
            .record_preselection_settlement(&[])
            .expect_err("settlement cannot replace reserved evidence");
        assert!(
            error
                .to_string()
                .contains("at event 0 (missing-recorded-event); recorded=2 settled=0")
        );
        assert_eq!(
            evidence
                .snapshot()
                .expect("unchanged evidence")
                .event_log_entries(),
            snapshot.event_log_entries()
        );
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

            let snapshot = evidence.snapshot().expect("settled evidence");
            assert_eq!(snapshot.event_log_entries().len(), selected_prefix_end + 2);
            assert_eq!(snapshot.event_log_entries()[..prefix.len()], prefix);
            assert_eq!(
                snapshot.event_log_entries()[prefix.len()..selected_prefix_end],
                selected
            );
            assert_eq!(snapshot.event_log_entries()[selected_prefix_end..], suffix);
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
                .event_log_entries(),
            &[prefix, selected]
        );
    }

    #[test]
    fn event_byte_limit_refusal_preserves_the_complete_snapshot() {
        let evidence = QemuAttemptExecutionEvidence::default();
        let retained_entry = SchedulerEventLogEntry::execution_budget_exhausted(
            0,
            VirtualTime { ticks: 19 },
            "retained-evidence-limit-fixture",
        );
        evidence
            .record(7, VirtualTime { ticks: 19 }, &[retained_entry])
            .expect("seed retained event evidence");
        let before = evidence.snapshot().expect("snapshot before refusal");
        let entry = SchedulerEventLogEntry::execution_budget_exhausted(
            1,
            VirtualTime { ticks: 20 },
            "evidence-limit-fixture",
        );
        let byte_limit = before
            .event_log_bytes
            .checked_add(entry.canonical_material_len())
            .and_then(|total| total.checked_sub(1))
            .expect("two nonempty canonical event entries");

        let error = evidence
            .record_with_event_limits(
                8,
                VirtualTime { ticks: 20 },
                &[entry],
                MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES,
                byte_limit,
            )
            .expect_err("the event byte ceiling must reject another entry");

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
    fn effect_trace_limit_refusal_preserves_final_events_and_prior_evidence() {
        let evidence = QemuAttemptExecutionEvidence::default();
        evidence
            .record(3, VirtualTime { ticks: 11 }, &[])
            .expect("seed evidence");
        let before = evidence.snapshot().expect("snapshot before refusal");
        let final_entry = SchedulerEventLogEntry::execution_budget_exhausted(
            0,
            VirtualTime { ticks: 12 },
            "final-evidence-limit-fixture",
        );

        let error = evidence
            .complete_with_trace_limit(&[final_entry], Some(vec![0xa5, 0x5a]), None, 1)
            .expect_err("the effect-trace byte ceiling must reject the final evidence");

        assert!(matches!(
            error,
            SchedulerError::ResourceLimit {
                field: "qemu-resolved-effect-trace-bytes",
                ..
            }
        ));
        assert_eq!(evidence.snapshot().expect("snapshot after refusal"), before);
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
            .complete_with_trace_limit(
                &[],
                Some(vec![0xa5]),
                Some(terminal_fingerprints),
                MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
            )
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
