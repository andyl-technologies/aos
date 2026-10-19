//! Diagnostic summary printed when modeled driving exhausts its quantum budget.
//!
//! Budget exhaustion fails the attempt before any observation is published,
//! so the retained event log is the only record of how far each guest got.
//! The report names the latest guest markers, semantic or plain, and the
//! latest console output per node, whether modeled or native. It never
//! influences the failure itself.
//!
//! ```text
//! CRUCIBLE-QUANTUM-BUDGET-EXHAUSTED-V1 quanta=<per-node runs>
//!   budget_charged=<drives charged> budget_maximum=<execution ceiling>
//!   events=<retained entries> last_event_ps=<time>
//!   nodes=<node>=markers:<count>[<recent>,...]/console:"<tail>" ...
//! ```
//!
//! The row is one line; it is wrapped above only for reading. `quanta`
//! counts per-node RUN completions, while the execution budget is charged once
//! per scheduler drive, so the two advance at different rates.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write as _;

use crucible::{ObservableEventPayload, SchedulerEventLogEntry, SchedulerEventLogPayload};

use super::RetainedAttemptLog;

/// Most recent markers named for each node.
const RECENT_MARKERS_PER_NODE: usize = 6;

/// Most recent console bytes shown for each node.
const CONSOLE_TAIL_BYTES: usize = 160;

/// Execution-budget charges at the moment the budget refused another drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct QuantumBudgetCharges {
    /// Drives charged across every lifecycle of this execution.
    pub(super) consumed: u64,
    /// Admitted ceiling on charged drives.
    pub(super) maximum: u64,
}

#[derive(Default)]
struct NodeActivity {
    markers: VecDeque<String>,
    marker_count: usize,
    console_tail: Vec<u8>,
}

impl NodeActivity {
    fn push_marker(&mut self, marker: String) {
        self.marker_count += 1;
        if self.markers.len() == RECENT_MARKERS_PER_NODE {
            self.markers.pop_front();
        }
        self.markers.push_back(marker);
    }

    fn push_console(&mut self, bytes: &[u8]) {
        self.console_tail.extend_from_slice(bytes);
        let excess = self.console_tail.len().saturating_sub(CONSOLE_TAIL_BYTES);
        self.console_tail.drain(..excess);
    }
}

/// Bounded per-node activity folded from the retained log.
#[derive(Default)]
struct NodeActivities {
    nodes: BTreeMap<String, NodeActivity>,
}

impl NodeActivities {
    fn observe(&mut self, entry: &SchedulerEventLogEntry) {
        let SchedulerEventLogPayload::Observable(observable) = entry.payload() else {
            return;
        };
        let at = entry.at().ticks;
        match observable {
            ObservableEventPayload::GuestSemanticMarker {
                node,
                marker,
                instance,
                ..
            } => self
                .node(&node.name)
                .push_marker(format!("{marker}/{instance}@{at}")),
            ObservableEventPayload::GuestMarker { node, marker, .. } => self
                .node(&node.name)
                .push_marker(format!("{}@{at}", marker.name)),
            ObservableEventPayload::ConsoleOutput { node, bytes } => {
                self.node(&node.name).push_console(bytes);
            }
            ObservableEventPayload::NativeConsoleByte { node, origin } => {
                self.node(&node.name)
                    .push_console(std::slice::from_ref(&origin.byte));
            }
            _ => {}
        }
    }

    fn node(&mut self, name: &str) -> &mut NodeActivity {
        self.nodes.entry(name.to_owned()).or_default()
    }

    fn summary(&self) -> String {
        self.nodes
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
            .join(" ")
    }
}

/// Writes one bounded `CRUCIBLE-QUANTUM-BUDGET-EXHAUSTED-V1` row to stderr.
pub(super) fn report_quantum_budget_exhaustion(
    event_log: &RetainedAttemptLog,
    completed_quanta: u64,
    charges: QuantumBudgetCharges,
) {
    let mut activities = NodeActivities::default();

    // Diagnostic only: an unreadable segment leaves its entries unreported.
    let _ = event_log.try_for_each_entry(|entry| {
        activities.observe(entry);
        Ok(())
    });

    let last_at = event_log.last().map_or(0, |entry| entry.at().ticks);
    let row = exhaustion_row(
        completed_quanta,
        charges,
        event_log.len(),
        last_at,
        &activities,
    );
    let _ = writeln!(std::io::stderr().lock(), "{row}");
}

fn exhaustion_row(
    completed_quanta: u64,
    charges: QuantumBudgetCharges,
    events: usize,
    last_at: u64,
    activities: &NodeActivities,
) -> String {
    format!(
        "CRUCIBLE-QUANTUM-BUDGET-EXHAUSTED-V1 quanta={completed_quanta} budget_charged={} budget_maximum={} events={events} last_event_ps={last_at} nodes={}",
        charges.consumed,
        charges.maximum,
        activities.summary(),
    )
}

#[cfg(test)]
mod tests {
    use crucible::test_support::condition_observation_entry_for_test;
    use crucible::{
        ContentHash, Icount, MarkerId, NativeConsoleByteOrigin, NodeId, ObservableEvent,
        VirtualTime,
    };

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn node(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }

    fn native_byte(
        sequence: u64,
        node_name: &str,
        byte: u8,
    ) -> Result<ObservableEvent, crucible::NativeConsoleOriginError> {
        ObservableEvent::native_console_byte(
            VirtualTime {
                ticks: 10 + sequence,
            },
            node(node_name),
            NativeConsoleByteOrigin {
                device: ContentHash { bytes: [7; 32] },
                stream: 1,
                logical_generation: 0,
                node_sequence: sequence,
                stream_sequence: sequence,
                emitted_ps: 10 + sequence,
                raw_prefix: 0,
                vcpu: 0,
                byte,
            },
        )
    }

    #[test]
    fn plain_guest_markers_and_native_console_bytes_are_summarized() -> TestResult {
        let marker = ObservableEvent::guest_marker(
            Icount { retired: 5 },
            node("peer"),
            MarkerId {
                name: String::from("progress"),
            },
        );
        let events = [
            marker,
            native_byte(1, "peer", b'u')?,
            native_byte(2, "peer", b'p')?,
        ];
        let mut activities = NodeActivities::default();
        for (sequence, event) in (0_u64..).zip(&events) {
            activities.observe(&condition_observation_entry_for_test(sequence, event));
        }

        let row = exhaustion_row(
            40,
            QuantumBudgetCharges {
                consumed: 12,
                maximum: 12,
            },
            3,
            12,
            &activities,
        );

        assert_eq!(
            row,
            "CRUCIBLE-QUANTUM-BUDGET-EXHAUSTED-V1 quanta=40 budget_charged=12 budget_maximum=12 \
             events=3 last_event_ps=12 nodes=peer=markers:1[progress@5]/console:\"up\""
        );
        Ok(())
    }

    #[test]
    fn markers_and_console_tails_stay_bounded_per_node() -> TestResult {
        let mut activities = NodeActivities::default();
        let mut sequence = 0_u64;
        for index in 0..(RECENT_MARKERS_PER_NODE + 3) {
            let marker = ObservableEvent::guest_marker(
                Icount { retired: 1 },
                node("guest"),
                MarkerId {
                    name: format!("m{index}"),
                },
            );
            activities.observe(&condition_observation_entry_for_test(sequence, &marker));
            sequence += 1;
        }
        for _ in 0..(CONSOLE_TAIL_BYTES + 40) {
            let byte = native_byte(sequence + 1, "guest", b'x')?;
            activities.observe(&condition_observation_entry_for_test(sequence, &byte));
            sequence += 1;
        }

        let activity = &activities.nodes["guest"];
        assert_eq!(activity.marker_count, RECENT_MARKERS_PER_NODE + 3);
        assert_eq!(activity.markers.len(), RECENT_MARKERS_PER_NODE);
        assert_eq!(activity.markers.front().map(String::as_str), Some("m3@1"));
        assert_eq!(activity.console_tail.len(), CONSOLE_TAIL_BYTES);
        Ok(())
    }
}
