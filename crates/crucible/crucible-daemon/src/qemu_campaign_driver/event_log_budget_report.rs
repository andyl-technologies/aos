//! Diagnostic summary printed when an attempt exhausts its event-log bound.
//!
//! The storage bound fails the attempt before any observation is published,
//! so the retained log is otherwise lost. The report attributes the retained
//! canonical bytes to open-set event kinds so the dominant producers are
//! visible; it never influences the failure itself.

use std::collections::BTreeMap;
use std::io::Write as _;

use crucible_engine::SchedulerEventLogEntry;

use super::RetainedAttemptLog;

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
    retained: &RetainedAttemptLog,
    pending: &[SchedulerEventLogEntry],
) {
    let mut usage = BudgetUsage::default();
    // The report is diagnostic only: a segment that cannot be read back
    // leaves its entries out of the attribution instead of failing twice.
    let _ = retained.try_for_each_entry(|entry| {
        usage.observe(entry, false);
        Ok(())
    });
    pending.iter().for_each(|entry| usage.observe(entry, true));
    let last = pending.last().or_else(|| retained.last());
    let summary = usage.render(limit, retained.len(), pending.len(), last);
    let _ = writeln!(std::io::stderr().lock(), "{summary}");
}

/// Attributes retained and pending canonical bytes from in-memory entries.
#[cfg(test)]
fn event_log_budget_summary(
    limit: &str,
    retained: &[SchedulerEventLogEntry],
    pending: &[SchedulerEventLogEntry],
) -> String {
    let mut usage = BudgetUsage::default();
    retained
        .iter()
        .for_each(|entry| usage.observe(entry, false));
    pending.iter().for_each(|entry| usage.observe(entry, true));
    let last = pending.last().or_else(|| retained.last());
    usage.render(limit, retained.len(), pending.len(), last)
}

/// Canonical bytes attributed to event kinds, one entry at a time.
#[derive(Default)]
struct BudgetUsage {
    kinds: BTreeMap<String, KindUsage>,
    retained_bytes: usize,
    pending_bytes: usize,
}

impl BudgetUsage {
    fn observe(&mut self, entry: &SchedulerEventLogEntry, is_pending: bool) {
        let bytes = entry.canonical_material_len();
        if is_pending {
            self.pending_bytes = self.pending_bytes.saturating_add(bytes);
        } else {
            self.retained_bytes = self.retained_bytes.saturating_add(bytes);
        }

        let usage = self
            .kinds
            .entry(entry.event_payload().kind().to_owned())
            .or_default();
        usage.entries += 1;
        usage.bytes = usage.bytes.saturating_add(bytes);
        usage.largest = usage.largest.max(bytes);
    }

    fn render(
        self,
        limit: &str,
        retained_entries: usize,
        pending_entries: usize,
        last: Option<&SchedulerEventLogEntry>,
    ) -> String {
        let Self {
            kinds,
            retained_bytes,
            pending_bytes,
        } = self;
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
        let last_event_ps = last.map_or(0, |entry| entry.at().ticks);

        format!(
            "CRUCIBLE-EVENT-LOG-BUDGET-EXHAUSTED-V1 limit={limit} retained_entries={retained_entries} retained_bytes={retained_bytes} pending_entries={pending_entries} pending_bytes={pending_bytes} last_event_ps={last_event_ps} omitted_kinds={omitted_kinds} kinds=[{named}]",
        )
    }
}

#[cfg(test)]
#[path = "event_log_budget_report_tests.rs"]
mod tests;
