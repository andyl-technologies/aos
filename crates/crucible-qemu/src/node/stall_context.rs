//! Host-held evidence for a node that stalls at its own coordinate.
//!
//! Several plugin writers publish an idle wake equal to the node's current
//! coordinate: a deferred selectable or campaign-marker VMStop, a console
//! control pause, a network output stop, and a host-requested pause in the
//! idle wait. The slot does not record which writer published it, so a stall
//! error alone cannot name the owner. The host already retains the native
//! stops it released, the last accepted boundary snapshot, staged outputs,
//! and any campaign marker it drained without proving a stop, and the stall
//! error carries them as one row:
//!
//! ```text
//! CRUCIBLE-STALL-CONTEXT-V1 resume_pending=none pending_outputs=0 unproven_marker=fault.transport.ready@1886393308637/stop=1886393309637 boundary=status:1,device_io:0,control_request:7,control_ack:8,logical:1886393309637,raw:941,idle_wake:1886393309637,advance_sequence:88,settled_ceiling:0,settled_sequence:0
//! ```
//!
//! The row is read from host memory only. It changes no scheduling decision
//! and grants no guest time.

use std::fmt;

/// Campaign marker the host drained beside a stop it could not prove.
///
/// A horizon step admits an unproven marker without parking, so the marker
/// event is consumed while the node may still claim its deferred VMStop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnprovenCampaignMarker {
    /// Comma-separated `name@tick` markers the step drained.
    pub(crate) markers: String,
    /// Scheduler-visible tick of the stop the markers did not prove.
    pub(crate) stop_tick: u64,
}

/// Fields of the last accepted boundary that distinguish quiesced writers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StallBoundary {
    pub(crate) status: u8,
    pub(crate) device_io_active: u8,
    pub(crate) control_request: u32,
    pub(crate) control_ack: u32,
    pub(crate) logical: u64,
    pub(crate) raw: u64,
    pub(crate) idle_wake: u64,
    pub(crate) advance_sequence: u64,
    pub(crate) settled_ceiling: u64,
    pub(crate) settled_sequence: u64,
}

/// Host-held evidence reported with a stalled node step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QemuNodeStallContext {
    resume_pending: Vec<&'static str>,
    pending_outputs: usize,
    unproven_marker: Option<UnprovenCampaignMarker>,
    boundary: Option<StallBoundary>,
}

impl QemuNodeStallContext {
    /// Builds the row from named retained-stop flags and host state.
    pub(crate) fn new(
        resume_pending: impl IntoIterator<Item = (&'static str, bool)>,
        pending_outputs: usize,
        unproven_marker: Option<UnprovenCampaignMarker>,
        boundary: Option<StallBoundary>,
    ) -> Self {
        Self {
            resume_pending: resume_pending
                .into_iter()
                .filter_map(|(name, pending)| pending.then_some(name))
                .collect(),
            pending_outputs,
            unproven_marker,
            boundary,
        }
    }
}

impl fmt::Display for QemuNodeStallContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let resume_pending = if self.resume_pending.is_empty() {
            String::from("none")
        } else {
            self.resume_pending.join(",")
        };
        write!(
            formatter,
            "CRUCIBLE-STALL-CONTEXT-V1 resume_pending={resume_pending} pending_outputs={}",
            self.pending_outputs,
        )?;

        match &self.unproven_marker {
            Some(marker) => write!(
                formatter,
                " unproven_marker={}/stop={}",
                marker.markers, marker.stop_tick
            )?,
            None => formatter.write_str(" unproven_marker=none")?,
        }

        match self.boundary {
            Some(boundary) => write!(
                formatter,
                " boundary=status:{},device_io:{},control_request:{},control_ack:{},logical:{},raw:{},idle_wake:{},advance_sequence:{},settled_ceiling:{},settled_sequence:{}",
                boundary.status,
                boundary.device_io_active,
                boundary.control_request,
                boundary.control_ack,
                boundary.logical,
                boundary.raw,
                boundary.idle_wake,
                boundary.advance_sequence,
                boundary.settled_ceiling,
                boundary.settled_sequence,
            ),
            None => formatter.write_str(" boundary=none"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stall_with_no_retained_stop_says_so() {
        let context = QemuNodeStallContext::new(
            [("selectable", false), ("campaign-marker", false)],
            0,
            None,
            None,
        );

        assert_eq!(
            context.to_string(),
            "CRUCIBLE-STALL-CONTEXT-V1 resume_pending=none pending_outputs=0 unproven_marker=none boundary=none"
        );
    }

    #[test]
    fn a_stall_names_retained_stops_and_an_unproven_marker() {
        let context = QemuNodeStallContext::new(
            [
                ("selectable", false),
                ("network-output", true),
                ("campaign-marker", true),
            ],
            2,
            Some(UnprovenCampaignMarker {
                markers: String::from("fault.transport.ready@100"),
                stop_tick: 1_100,
            }),
            Some(StallBoundary {
                status: 1,
                device_io_active: 0,
                control_request: 7,
                control_ack: 8,
                logical: 1_100,
                raw: 11,
                idle_wake: 1_100,
                advance_sequence: 88,
                settled_ceiling: 0,
                settled_sequence: 0,
            }),
        );

        assert_eq!(
            context.to_string(),
            "CRUCIBLE-STALL-CONTEXT-V1 resume_pending=network-output,campaign-marker pending_outputs=2 unproven_marker=fault.transport.ready@100/stop=1100 boundary=status:1,device_io:0,control_request:7,control_ack:8,logical:1100,raw:11,idle_wake:1100,advance_sequence:88,settled_ceiling:0,settled_sequence:0"
        );
    }
}
