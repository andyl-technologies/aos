//! Bounded diagnostic trace of committed host RUNs.
//!
//! Each host RUN the held publisher commits leaves one record naming the
//! node, the clock it started from, where it physically stopped, how far the
//! backend attested settlement before and after the commit, the physical
//! stop kind, the inputs resolved to the node at its settled endpoint, the
//! frames it emitted, and the wake deadlines the scheduler held for it
//! afterwards. A settled-gap violation or a replay divergence reads these
//! records to show whether a node retired inside a gap it had attested empty,
//! and whether a modeled wake preceded that retirement.
//!
//! The trace is host diagnostics only. It never enters scheduler state, the
//! event log, or any digest, and it keeps at most [`CAPACITY`] records per
//! thread, discarding the oldest.
//!
//! ```text
//! CRUCIBLE-HOST-RUN-V1 node=router-a before=10 reached=12 settled_before=40 settled_through=12 stop=network-output idle_parked=false inputs=0 last_input_ps=none outputs=1 emits=11..11 local_deadline_ps=none vcpu_deadline_ps=60
//! ```

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Write as _;

use super::{ScheduledEvent, SingleScheduler};
use crate::{BackendNetworkOutput, BackendPhysicalStop, StepObservation};

/// Records retained per thread.
pub const CAPACITY: usize = 512;

/// One committed host RUN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRunRecord {
    /// Node the RUN advanced.
    pub node: String,
    /// The node's actual clock when the RUN started.
    pub before: u64,
    /// The node's actual clock where the RUN physically stopped.
    pub reached: u64,
    /// The node's settled clock before the commit.
    pub settled_before: u64,
    /// The tick through which the backend attested settlement for this RUN.
    pub settled_through: u64,
    /// The physical stop the backend reported.
    pub physical_stop: BackendPhysicalStop,
    /// Whether the commit left the node parked idle below its settled clock.
    pub idle_parked: bool,
    /// Inputs resolved to the node at its settled endpoint.
    pub inputs: usize,
    /// Latest virtual time among those inputs, in picoseconds.
    pub last_input_ps: Option<u64>,
    /// Frames the RUN emitted.
    pub outputs: usize,
    /// Earliest and latest emission counters among those frames.
    pub emits: Option<(u64, u64)>,
    /// The node's armed local timer after the commit, in picoseconds.
    pub local_deadline_ps: Option<u64>,
    /// The earliest vCPU wake deadline after the commit, in picoseconds.
    pub vcpu_deadline_ps: Option<u64>,
}

impl HostRunRecord {
    /// Formats the record as one diagnostic row.
    #[must_use]
    pub fn row(&self) -> String {
        let mut row = format!(
            "CRUCIBLE-HOST-RUN-V1 node={} before={} reached={} settled_before={} settled_through={} stop={} idle_parked={} inputs={} last_input_ps={} outputs={}",
            self.node,
            self.before,
            self.reached,
            self.settled_before,
            self.settled_through,
            stop_label(self.physical_stop),
            self.idle_parked,
            self.inputs,
            optional(self.last_input_ps),
            self.outputs,
        );
        match self.emits {
            Some((first, last)) => {
                let _ = write!(row, " emits={first}..{last}");
            }
            None => row.push_str(" emits=none"),
        }
        let _ = write!(
            row,
            " local_deadline_ps={} vcpu_deadline_ps={}",
            optional(self.local_deadline_ps),
            optional(self.vcpu_deadline_ps),
        );
        row
    }
}

fn optional(value: Option<u64>) -> String {
    value.map_or_else(|| String::from("none"), |value| value.to_string())
}

fn stop_label(stop: BackendPhysicalStop) -> String {
    match stop {
        BackendPhysicalStop::Horizon => String::from("horizon"),
        BackendPhysicalStop::UnclassifiedPause => String::from("unclassified-pause"),
        BackendPhysicalStop::Idle => String::from("idle"),
        BackendPhysicalStop::NetworkOutput => String::from("network-output"),
        BackendPhysicalStop::ConsoleOutput { sequence } => format!("console-output:{sequence}"),
        BackendPhysicalStop::GuestSelectable => String::from("guest-selectable"),
        BackendPhysicalStop::CampaignMarker => String::from("campaign-marker"),
    }
}

thread_local! {
    static RECORDS: RefCell<VecDeque<HostRunRecord>> = const { RefCell::new(VecDeque::new()) };
}

/// Retains one committed RUN, discarding the oldest past [`CAPACITY`].
pub(super) fn record(committed: HostRunRecord) {
    RECORDS.with(|records| {
        let mut records = records.borrow_mut();
        if records.len() == CAPACITY {
            records.pop_front();
        }
        records.push_back(committed);
    });
}

/// What a host RUN reported before its commit moved the node.
pub(super) struct HostRunTraceStart {
    index: usize,
    before: u64,
    settled_before: u64,
    settled_through: u64,
    reached: u64,
    physical_stop: BackendPhysicalStop,
    outputs: usize,
    emits: Option<(u64, u64)>,
}

impl HostRunTraceStart {
    /// Captures node `index`'s clocks and the RUN's report before commit.
    pub(super) fn capture(
        scheduler: &SingleScheduler,
        index: usize,
        step: &StepObservation,
        outputs: &[BackendNetworkOutput],
    ) -> Self {
        let node = &scheduler.nodes[index];
        let emits = outputs
            .iter()
            .map(|output| output.emit_icount.retired)
            .fold(None, |range: Option<(u64, u64)>, emit| {
                Some(range.map_or((emit, emit), |(first, last)| {
                    (first.min(emit), last.max(emit))
                }))
            });
        Self {
            index,
            before: node.counter.ticks,
            settled_before: node.settled.ticks,
            settled_through: step.settled_through.ticks,
            reached: step.reached.ticks,
            physical_stop: step.physical_stop,
            outputs: outputs.len(),
            emits,
        }
    }

    /// Records the committed RUN with the inputs `resolved` at its endpoint.
    pub(super) fn record(self, scheduler: &SingleScheduler, resolved: &[ScheduledEvent]) {
        let node = &scheduler.nodes[self.index];
        let inputs = resolved
            .iter()
            .filter(|event| event.key.consumer() == &node.id)
            .map(|event| event.key.virtual_time().ticks)
            .collect::<Vec<_>>();
        record(HostRunRecord {
            node: node.id.node.name.clone(),
            before: self.before,
            reached: self.reached,
            settled_before: self.settled_before,
            settled_through: self.settled_through,
            physical_stop: self.physical_stop,
            idle_parked: node.idle_parked,
            inputs: inputs.len(),
            last_input_ps: inputs.iter().copied().max(),
            outputs: self.outputs,
            emits: self.emits,
            local_deadline_ps: node.exact_local_event.virtual_time().map(|at| at.ticks),
            vcpu_deadline_ps: node
                .vcpu_idle_states
                .iter()
                .filter_map(|state| state.next_deadline)
                .map(|at| at.ticks)
                .min(),
        });
    }
}

/// Returns this thread's latest `limit` records for `node`, oldest first.
#[must_use]
pub fn recent_for_node(node: &str, limit: usize) -> Vec<HostRunRecord> {
    RECORDS.with(|records| {
        let records = records.borrow();
        let mut recent = records
            .iter()
            .rev()
            .filter(|record| record.node == node)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        recent.reverse();
        recent
    })
}

/// Returns this thread's records whose start, stop or settled clocks lie
/// within `half_window` of `center`, oldest first, at most `limit`.
#[must_use]
pub fn records_near(center: u64, half_window: u64, limit: usize) -> Vec<HostRunRecord> {
    RECORDS.with(|records| {
        records
            .borrow()
            .iter()
            .filter(|record| {
                [
                    record.before,
                    record.reached,
                    record.settled_before,
                    record.settled_through,
                ]
                .iter()
                .any(|clock| clock.abs_diff(center) <= half_window)
            })
            .take(limit)
            .cloned()
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(node: &str, before: u64, reached: u64, settled_through: u64) -> HostRunRecord {
        HostRunRecord {
            node: node.to_owned(),
            before,
            reached,
            settled_before: before,
            settled_through,
            physical_stop: BackendPhysicalStop::Idle,
            idle_parked: reached < settled_through,
            inputs: 1,
            last_input_ps: Some(settled_through),
            outputs: 0,
            emits: None,
            local_deadline_ps: None,
            vcpu_deadline_ps: Some(settled_through + 5),
        }
    }

    #[test]
    fn records_select_by_node_and_clock_and_stay_bounded() {
        record(commit("a", 0, 4, 40));
        record(commit("b", 10, 12, 12));
        record(HostRunRecord {
            physical_stop: BackendPhysicalStop::ConsoleOutput { sequence: 3 },
            outputs: 2,
            emits: Some((5, 7)),
            ..commit("a", 4, 7, 7)
        });

        let recent = recent_for_node("a", 8);
        assert_eq!(recent.len(), 2);
        assert_eq!(
            recent[0].row(),
            "CRUCIBLE-HOST-RUN-V1 node=a before=0 reached=4 settled_before=0 settled_through=40 stop=idle idle_parked=true inputs=1 last_input_ps=40 outputs=0 emits=none local_deadline_ps=none vcpu_deadline_ps=45"
        );
        assert!(
            recent[1]
                .row()
                .contains("stop=console-output:3 idle_parked=false inputs=1 last_input_ps=7 outputs=2 emits=5..7")
        );
        assert_eq!(records_near(12, 0, 8)[0].node, "b");

        for before in 0..(CAPACITY as u64 + 8) {
            record(commit("fill", 1_000_000 + before, 1_000_000, 1_000_000));
        }
        let retained = recent_for_node("fill", CAPACITY + 8);
        assert_eq!(retained.len(), CAPACITY);
        assert_eq!(retained[0].before, 1_000_008);
        assert!(recent_for_node("a", 8).is_empty());
    }
}
