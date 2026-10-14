//! Diagnostic summary printed when an attempt exhausts its event-log bound.
//!
//! The entry and byte bounds fail the attempt before any observation is
//! published, so the retained log is otherwise lost. The report attributes
//! the retained canonical bytes to open-set event kinds so the dominant
//! producers are visible; it never influences the failure itself.

use std::collections::BTreeMap;
use std::io::Write as _;

use crucible::SchedulerEventLogEntry;

/// Most event kinds named in one report, largest byte share first.
const REPORTED_KINDS: usize = 12;

#[derive(Default)]
struct KindUsage {
    entries: usize,
    bytes: usize,
    largest: usize,
}

/// Writes one bounded `CRUCIBLE-EVENT-LOG-BUDGET-EXHAUSTED-V1` row to stderr.
pub(crate) fn report_event_log_budget_exhaustion(
    limit: &str,
    retained: &[SchedulerEventLogEntry],
    pending: &[SchedulerEventLogEntry],
) {
    let summary = event_log_budget_summary(limit, retained, pending);
    let _ = writeln!(std::io::stderr().lock(), "{summary}");
}

/// Attributes retained and pending canonical bytes to event kinds.
fn event_log_budget_summary(
    limit: &str,
    retained: &[SchedulerEventLogEntry],
    pending: &[SchedulerEventLogEntry],
) -> String {
    let mut kinds = BTreeMap::<&str, KindUsage>::new();
    let mut retained_bytes = 0_usize;
    let mut pending_bytes = 0_usize;

    for (entry, is_pending) in retained
        .iter()
        .map(|entry| (entry, false))
        .chain(pending.iter().map(|entry| (entry, true)))
    {
        let bytes = entry.canonical_material_len();
        if is_pending {
            pending_bytes = pending_bytes.saturating_add(bytes);
        } else {
            retained_bytes = retained_bytes.saturating_add(bytes);
        }

        let usage = kinds.entry(entry.event_payload().kind()).or_default();
        usage.entries += 1;
        usage.bytes = usage.bytes.saturating_add(bytes);
        usage.largest = usage.largest.max(bytes);
    }

    let mut ranked = kinds.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|(left_kind, left), (right_kind, right)| {
        right.bytes.cmp(&left.bytes).then(left_kind.cmp(right_kind))
    });
    let omitted_kinds = ranked.len().saturating_sub(REPORTED_KINDS);
    let named = ranked
        .iter()
        .take(REPORTED_KINDS)
        .map(|(kind, usage)| {
            format!(
                "{kind}:entries={}/bytes={}/largest={}",
                usage.entries, usage.bytes, usage.largest
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let last_event_ps = pending
        .last()
        .or_else(|| retained.last())
        .map_or(0, |entry| entry.at().ticks);

    format!(
        "CRUCIBLE-EVENT-LOG-BUDGET-EXHAUSTED-V1 limit={limit} retained_entries={} retained_bytes={retained_bytes} pending_entries={} pending_bytes={pending_bytes} last_event_ps={last_event_ps} omitted_kinds={omitted_kinds} kinds=[{named}]",
        retained.len(),
        pending.len(),
    )
}

#[cfg(test)]
#[path = "event_log_budget_report_tests.rs"]
mod tests;
