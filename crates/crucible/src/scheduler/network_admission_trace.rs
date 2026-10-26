//! Bounded diagnostic trace of live network-frame admissions.
//!
//! Each admitted backend frame leaves one record naming its source, the
//! coordinate the producer emitted it at, the time its admission was logged
//! at, and the publication path that admitted it. A replay divergence reads
//! the records near the divergent time to show whether two runs stamped the
//! same frame differently or admitted it through a different path.
//!
//! The trace is host diagnostics only. It never enters scheduler state, the
//! event log, or any digest, and it keeps at most [`CAPACITY`] records per
//! thread, discarding the oldest.
//!
//! ```text
//! CRUCIBLE-NETWORK-ADMISSION-V1 source=router-a sequence=17 emit_ps=100 stamp_ps=120 path=run-commit
//! ```

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};

use super::SingleScheduler;
use crate::{BackendNetworkOutput, NodeId, SchedulerError, VirtualTime};

/// Records retained per thread.
pub const CAPACITY: usize = 512;

/// One admitted frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkAdmissionRecord {
    /// Producing node.
    pub source: String,
    /// Producer-local frame sequence.
    pub sequence: u64,
    /// Coordinate the producer emitted the frame at, in picoseconds.
    pub emit_ps: u64,
    /// Time the admission was logged at, in picoseconds.
    pub stamp_ps: u64,
    /// Publication path that admitted the frame.
    pub path: &'static str,
}

impl NetworkAdmissionRecord {
    /// Formats the record as one diagnostic row.
    #[must_use]
    pub fn row(&self) -> String {
        format!(
            "CRUCIBLE-NETWORK-ADMISSION-V1 source={} sequence={} emit_ps={} stamp_ps={} path={}",
            self.source, self.sequence, self.emit_ps, self.stamp_ps, self.path
        )
    }
}

thread_local! {
    static RECORDS: RefCell<VecDeque<NetworkAdmissionRecord>> =
        const { RefCell::new(VecDeque::new()) };
    static PATH: Cell<&'static str> = const { Cell::new("unlabeled") };
}

/// Labels admissions on this thread until the guard drops.
#[must_use = "the label applies only while the guard lives"]
pub struct AdmissionPathGuard {
    previous: &'static str,
}

impl Drop for AdmissionPathGuard {
    fn drop(&mut self) {
        PATH.with(|path| path.set(self.previous));
    }
}

/// Labels every admission on this thread with `path` while the guard lives.
pub fn enter_path(path: &'static str) -> AdmissionPathGuard {
    let previous = PATH.with(|current| current.replace(path));
    AdmissionPathGuard { previous }
}

impl SingleScheduler {
    /// Returns the time a batch of live frames is admitted at, and traces
    /// each frame's emission coordinate beside it.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when a frame's emission time cannot be
    /// resolved.
    pub(super) fn traced_network_admission_boundary(
        &self,
        outputs: &[BackendNetworkOutput],
        emission_times: &BTreeMap<(NodeId, u64), VirtualTime>,
    ) -> Result<VirtualTime, SchedulerError> {
        let boundary = self
            .frontier
            .max(self.event_log.condition_prefix().point().at());
        for output in outputs {
            let emitted = self.network_output_emit_time(output, emission_times)?;
            record(
                &output.source.name,
                output.sequence,
                emitted.ticks,
                boundary.ticks,
            );
        }
        Ok(boundary)
    }
}

/// Records one admitted frame under the current path label.
fn record(source: &str, sequence: u64, emit_ps: u64, stamp_ps: u64) {
    let path = PATH.with(Cell::get);
    RECORDS.with(|records| {
        let mut records = records.borrow_mut();
        if records.len() == CAPACITY {
            records.pop_front();
        }
        records.push_back(NetworkAdmissionRecord {
            source: source.to_owned(),
            sequence,
            emit_ps,
            stamp_ps,
            path,
        });
    });
}

/// Returns this thread's records whose emission or stamp lies within
/// `half_window_ps` of `center_ps`, oldest first, at most `limit`.
#[must_use]
pub fn records_near(
    center_ps: u64,
    half_window_ps: u64,
    limit: usize,
) -> Vec<NetworkAdmissionRecord> {
    RECORDS.with(|records| {
        records
            .borrow()
            .iter()
            .filter(|record| {
                record.emit_ps.abs_diff(center_ps) <= half_window_ps
                    || record.stamp_ps.abs_diff(center_ps) <= half_window_ps
            })
            .take(limit)
            .cloned()
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_carry_the_innermost_path_and_stay_bounded() {
        record("outer", 0, 5, 5);
        {
            let _commit = enter_path("run-commit");
            record("a", 1, 10, 12);
            {
                let _custody = enter_path("custody-release");
                record("b", 2, 20, 20);
            }
            record("c", 3, 30, 30);
        }

        let near = records_near(20, 10, 8);
        let paths = near.iter().map(|record| record.path).collect::<Vec<_>>();
        assert_eq!(paths, ["run-commit", "custody-release", "run-commit"]);
        assert_eq!(
            near[0].row(),
            "CRUCIBLE-NETWORK-ADMISSION-V1 source=a sequence=1 emit_ps=10 stamp_ps=12 path=run-commit"
        );
        assert_eq!(records_near(5, 0, 8)[0].path, "unlabeled");

        for sequence in 0..(CAPACITY as u64 + 8) {
            record("fill", sequence, 1_000_000, 1_000_000);
        }
        let retained = records_near(1_000_000, 0, CAPACITY + 8);
        assert_eq!(retained.len(), CAPACITY);
        assert_eq!(retained[0].sequence, 8);
    }
}
