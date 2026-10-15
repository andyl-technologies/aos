//! Diagnostic summary printed when modeled driving exhausts its quantum budget.
//!
//! Budget exhaustion fails the attempt before any observation is published,
//! so the retained event log is the only record of how far each guest got.
//! The report names the latest guest semantic markers and console output per
//! node; it never influences the failure itself.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write as _;

use crucible::{ObservableEventPayload, SchedulerEventLogPayload};

use super::RetainedAttemptLog;

/// Most recent semantic markers named for each node.
const RECENT_MARKERS_PER_NODE: usize = 6;

/// Most recent console bytes shown for each node.
const CONSOLE_TAIL_BYTES: usize = 160;

#[derive(Default)]
struct NodeActivity {
    markers: VecDeque<String>,
    marker_count: usize,
    console_tail: Vec<u8>,
}

/// Writes one bounded `CRUCIBLE-QUANTUM-BUDGET-EXHAUSTED-V1` row to stderr.
pub(super) fn report_quantum_budget_exhaustion(
    event_log: &RetainedAttemptLog,
    completed_quanta: u64,
) {
    let mut nodes = BTreeMap::<String, NodeActivity>::new();

    // Diagnostic only: an unreadable segment leaves its entries unreported.
    let _ = event_log.try_for_each_entry(|entry| {
        let SchedulerEventLogPayload::Observable(observable) = entry.payload() else {
            return Ok(());
        };
        match observable {
            ObservableEventPayload::GuestSemanticMarker {
                node,
                marker,
                instance,
                ..
            } => {
                let activity = nodes.entry(node.name.clone()).or_default();
                activity.marker_count += 1;
                if activity.markers.len() == RECENT_MARKERS_PER_NODE {
                    activity.markers.pop_front();
                }
                activity
                    .markers
                    .push_back(format!("{marker}/{instance}@{}", entry.at().ticks));
            }
            ObservableEventPayload::ConsoleOutput { node, bytes } => {
                let tail = &mut nodes.entry(node.name.clone()).or_default().console_tail;
                tail.extend_from_slice(bytes);
                let excess = tail.len().saturating_sub(CONSOLE_TAIL_BYTES);
                tail.drain(..excess);
            }
            _ => {}
        }
        Ok(())
    });

    let summary = nodes
        .iter()
        .map(|(name, activity)| {
            format!(
                "{name}=markers:{}[{}]/console:{:?}",
                activity.marker_count,
                Vec::from(activity.markers.clone()).join(","),
                String::from_utf8_lossy(&activity.console_tail),
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let last_at = event_log.last().map_or(0, |entry| entry.at().ticks);
    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-QUANTUM-BUDGET-EXHAUSTED-V1 quanta={completed_quanta} events={} last_event_ps={last_at} nodes={summary}",
        event_log.len(),
    );
}
