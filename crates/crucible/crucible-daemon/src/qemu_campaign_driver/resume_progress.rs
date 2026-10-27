//! Bounded host progress notices after a restored guest reaches its first markers.
//!
//! An exact-resumed attempt reports, once per VM node, the first scheduler-owned
//! guest marker that node emits after the restore:
//!
//! ```text
//! CRUCIBLE-EXACT-RESUME-PROGRESS-V1 attempt=<id> execution=<id> node=<name> quanta=<n> marker=<name> icount=<tick>
//! ```
//!
//! The notice is per node because the first marker of the whole world need not
//! come from the node whose progress matters. A checkpoint can hold a frame
//! that one node already sent; its peer then observes that frame before the
//! sender reaches its own next marker. A single world-wide notice would be
//! spent on the peer and hide whether the sender ever progressed.

use std::collections::BTreeSet;
use std::io::Write;

use crucible_engine::{
    NodeId, ObservableEventPayload, SchedulerEventLogEntry, SchedulerEventLogPayload,
};

use crate::AttemptExecutionContext;

/// Tracks which nodes already reported their first restored marker.
#[derive(Debug, Default)]
pub(super) struct RestoredMarkerNotices {
    reported: BTreeSet<NodeId>,
}

impl RestoredMarkerNotices {
    /// Emits one notice for each node's first marker in a completed quantum.
    ///
    /// Fresh attempts, and replay toward a selected boundary, report nothing.
    pub(super) fn report(
        &mut self,
        context: &AttemptExecutionContext,
        replaying_selected_boundary: bool,
        entries: &[SchedulerEventLogEntry],
        completed_quanta: u64,
    ) {
        if context.resume_checkpoint().is_none() || replaying_selected_boundary {
            return;
        }
        let Some(basis) = context.runtime_basis() else {
            return;
        };

        let prefix = format!(
            "CRUCIBLE-EXACT-RESUME-PROGRESS-V1 attempt={:?} execution={:?}",
            basis.key().attempt(),
            basis.execution(),
        );
        let notices = self.first_markers(&prefix, entries, completed_quanta);
        if notices.is_empty() {
            return;
        }
        let mut stderr = std::io::stderr().lock();
        for notice in notices {
            let _ = writeln!(stderr, "{notice}");
        }
    }

    /// Returns notices for nodes whose first restored marker is in `entries`.
    fn first_markers(
        &mut self,
        prefix: &str,
        entries: &[SchedulerEventLogEntry],
        completed_quanta: u64,
    ) -> Vec<String> {
        let mut notices = Vec::new();
        for entry in entries {
            let SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
                node,
                marker,
                retired_icount,
            }) = entry.payload()
            else {
                continue;
            };
            if !self.reported.insert(node.clone()) {
                continue;
            }
            notices.push(format!(
                "{prefix} node={} quanta={completed_quanta} marker={} icount={}",
                node.name, marker.name, retired_icount.retired,
            ));
        }
        notices
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crucible_engine::{EventLog, Icount, MarkerId, ObservableEvent};

    use super::*;

    fn markers(
        log: &mut EventLog,
        markers: &[(&str, &str, u64)],
    ) -> Result<Vec<SchedulerEventLogEntry>, Box<dyn Error>> {
        let events = markers.iter().map(|(node, marker, tick)| {
            ObservableEvent::guest_marker(
                Icount { retired: *tick },
                NodeId {
                    name: (*node).into(),
                },
                MarkerId::from_name(*marker),
            )
        });
        Ok(log.append_observable_events(events)?.entries)
    }

    #[test]
    fn a_peer_observing_an_in_flight_frame_does_not_hide_the_senders_progress()
    -> Result<(), Box<dyn Error>> {
        let mut log = EventLog::new();
        let mut notices = RestoredMarkerNotices::default();

        // The peer receives the frame sent before the checkpoint first; the
        // sender's next progress marker arrives in a later quantum.
        let first = markers(
            &mut log,
            &[("choice-peer", "network-observed-selected-fast-q7", 100)],
        )?;
        let second = markers(
            &mut log,
            &[
                ("choice-node", "selected-fast-q7-progress-000001", 900),
                ("choice-peer", "network-observed-again", 950),
                ("choice-node", "selected-fast-q7-progress-000002", 1_900),
            ],
        )?;

        assert_eq!(
            notices.first_markers("P", &first, 7),
            ["P node=choice-peer quanta=7 marker=network-observed-selected-fast-q7 icount=100"]
        );
        assert_eq!(
            notices.first_markers("P", &second, 9),
            ["P node=choice-node quanta=9 marker=selected-fast-q7-progress-000001 icount=900"]
        );
        assert!(notices.first_markers("P", &second, 10).is_empty());
        Ok(())
    }
}
