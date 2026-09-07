//! Bounded storage for process-local QEMU execution evidence.

use std::sync::{Arc, Mutex};

use crucible::{FingerprintSample, SchedulerError, SchedulerEventLogEntry};

use super::{
    MAX_EXECUTION_FINGERPRINT_SAMPLES, MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
    MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES,
};

/// Scheduler progress and reproduction evidence from one fresh QEMU attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QemuAttemptExecutionEvidenceSnapshot {
    quanta: u64,
    frontier: crucible::VirtualTime,
    event_log_entries: Vec<SchedulerEventLogEntry>,
    event_log_bytes: usize,
    execution_fingerprints: Vec<FingerprintSample>,
    resolved_effect_trace: Option<Vec<u8>>,
}

impl QemuAttemptExecutionEvidenceSnapshot {
    /// Returns the number of successfully completed lifecycle quanta.
    #[must_use]
    pub const fn quanta(&self) -> u64 {
        self.quanta
    }

    /// Returns the last successfully completed scheduler frontier.
    #[must_use]
    pub const fn frontier(&self) -> crucible::VirtualTime {
        self.frontier
    }

    /// Returns the exact bounded scheduler event log retained for the attempt.
    #[must_use]
    pub fn event_log_entries(&self) -> &[SchedulerEventLogEntry] {
        &self.event_log_entries
    }

    /// Returns the concrete execution fingerprints sampled for the attempt.
    #[must_use]
    pub fn execution_fingerprints(&self) -> &[FingerprintSample] {
        &self.execution_fingerprints
    }

    /// Returns the encoded resolved-effect trace retained by the live runtime.
    #[must_use]
    pub fn resolved_effect_trace(&self) -> Option<&[u8]> {
        self.resolved_effect_trace.as_deref()
    }
}

/// Shared read-only evidence for the most recently constructed fresh attempt.
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

    fn record_with_event_limits(
        &self,
        quanta: u64,
        frontier: crucible::VirtualTime,
        entries: &[SchedulerEventLogEntry],
        event_count_limit: usize,
        event_byte_limit: usize,
    ) -> Result<(), SchedulerError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| evidence_poisoned())?;
        append_event_entries_with_limits(
            &mut snapshot,
            entries,
            event_count_limit,
            event_byte_limit,
        )?;
        snapshot.quanta = quanta;
        snapshot.frontier = frontier;
        Ok(())
    }

    pub(super) fn complete(
        &self,
        entries: &[SchedulerEventLogEntry],
        resolved_effect_trace: Option<Vec<u8>>,
    ) -> Result<(), SchedulerError> {
        self.complete_with_trace_limit(
            entries,
            resolved_effect_trace,
            MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
        )
    }

    fn complete_with_trace_limit(
        &self,
        entries: &[SchedulerEventLogEntry],
        resolved_effect_trace: Option<Vec<u8>>,
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

        // Validate and reserve both bounded payloads before mutating the
        // retained attempt. A rejected final drain must preserve the last
        // complete evidence snapshot for diagnosis.
        append_event_entries(&mut snapshot, entries)?;
        snapshot.resolved_effect_trace = resolved_effect_trace;
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
    use crucible::VirtualTime;

    use super::*;

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
            .complete_with_trace_limit(&[final_entry], Some(vec![0xa5, 0x5a]), 1)
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
}
