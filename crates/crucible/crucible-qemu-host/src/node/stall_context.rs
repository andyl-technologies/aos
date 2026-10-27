//! Host-held evidence for a node that stalls at its own coordinate.
//!
//! Several plugin writers publish an idle wake equal to the node's current
//! coordinate: a deferred selectable or campaign-marker VMStop, a console
//! control pause, a network output stop, a pause while the region's
//! coordinated pause flag is set, and an idle pass whose inbound frame or
//! device completion is due now. The slot does not record which writer
//! published it, so a stall error alone cannot name the owner. The host
//! already retains the native stops it released, the coordinated pause flag,
//! staged outputs, the campaign markers it drained, and the publication it
//! classified together with the clamp it then took, and the stall error
//! carries them as one row:
//!
//! ```text
//! CRUCIBLE-STALL-CONTEXT-V1 resume_pending=none pause_requested=false pending_outputs=0 last_marker=fault.transport.ready@2025602651300 unproven_marker=none discovery=ceiling:2770726265650,status:1,device_io:0,control_request:23520,control_ack:23520,logical:2770600228574,raw:4563176038,idle_wake:2770600228574,advance_sequence:47343,settled_ceiling:0,settled_sequence:0,publish_gen:9310 clamp=ceiling:2770600228574,status:1,device_io:0,control_request:23520,control_ack:23521,logical:2770600228574,raw:4563176038,idle_wake:2770600228574,advance_sequence:47344,settled_ceiling:2770600228574,settled_sequence:47344,publish_gen:9314 classification=guard_start:2770600228574,guard_release:none,fence_gen:9306,discovery_gen:9310
//! ```
//!
//! The clamp always shows an idle wake at its own coordinate, because the
//! control callback publishes an exact-ceiling idle boundary; the discovery
//! is the publication the step classified. The classification says whether
//! the checkpoint guard was armed for that advance and what released it, so
//! a stale boundary left by the previous clamp is told apart from a fresh
//! zero-length answer to the new advance. The row is read from host memory
//! only. It changes no scheduling decision and grants no guest time.

use std::fmt;

use super::QemuNode;
use crate::quantum::AdvanceClassification;

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
    pub(crate) ceiling: u64,
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
    pub(crate) publish_gen: u32,
}

impl StallBoundary {
    /// Copies the distinguishing fields of one coherent slot snapshot.
    pub(crate) const fn from_snapshot(
        snapshot: &crucible_qemu_shmem::NodeSlotSnapshot,
        control_request: u32,
    ) -> Self {
        Self {
            ceiling: snapshot.max_advance_icount,
            status: snapshot.status,
            device_io_active: snapshot.device_io_active,
            control_request,
            control_ack: snapshot.control_boundary_ack,
            logical: snapshot.current_icount,
            raw: snapshot.logical_time_raw_icount,
            idle_wake: snapshot.idle_wake_icount,
            advance_sequence: snapshot.advance_publication_sequence,
            settled_ceiling: snapshot.settled_ceiling_tick,
            settled_sequence: snapshot.settled_publication_sequence,
            publish_gen: snapshot.publish_gen,
        }
    }
}

impl fmt::Display for StallBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ceiling:{},status:{},device_io:{},control_request:{},control_ack:{},logical:{},raw:{},idle_wake:{},advance_sequence:{},settled_ceiling:{},settled_sequence:{},publish_gen:{}",
            self.ceiling,
            self.status,
            self.device_io_active,
            self.control_request,
            self.control_ack,
            self.logical,
            self.raw,
            self.idle_wake,
            self.advance_sequence,
            self.settled_ceiling,
            self.settled_sequence,
            self.publish_gen,
        )
    }
}

/// Host-held evidence reported with a stalled node step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QemuNodeStallContext {
    resume_pending: Vec<&'static str>,
    pause_requested: Option<bool>,
    pending_outputs: usize,
    last_marker: Option<String>,
    unproven_marker: Option<UnprovenCampaignMarker>,
    boundaries: Option<(StallBoundary, StallBoundary)>,
    classification: Option<AdvanceClassification>,
}

impl QemuNodeStallContext {
    /// Builds the row from named retained-stop flags and host state.
    pub(crate) fn new(
        resume_pending: impl IntoIterator<Item = (&'static str, bool)>,
        pause_requested: Option<bool>,
        pending_outputs: usize,
        last_marker: Option<String>,
        unproven_marker: Option<UnprovenCampaignMarker>,
        boundaries: Option<(StallBoundary, StallBoundary)>,
        classification: Option<AdvanceClassification>,
    ) -> Self {
        Self {
            resume_pending: resume_pending
                .into_iter()
                .filter_map(|(name, pending)| pending.then_some(name))
                .collect(),
            pause_requested,
            pending_outputs,
            last_marker,
            unproven_marker,
            boundaries,
            classification,
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
            "CRUCIBLE-STALL-CONTEXT-V1 resume_pending={resume_pending}"
        )?;
        match self.pause_requested {
            Some(requested) => write!(formatter, " pause_requested={requested}")?,
            None => formatter.write_str(" pause_requested=unknown")?,
        }
        write!(formatter, " pending_outputs={}", self.pending_outputs)?;

        match &self.last_marker {
            Some(markers) => write!(formatter, " last_marker={markers}")?,
            None => formatter.write_str(" last_marker=none")?,
        }

        match &self.unproven_marker {
            Some(marker) => write!(
                formatter,
                " unproven_marker={}/stop={}",
                marker.markers, marker.stop_tick
            )?,
            None => formatter.write_str(" unproven_marker=none")?,
        }

        match self.boundaries {
            Some((discovery, clamp)) => {
                write!(formatter, " discovery={discovery} clamp={clamp}")?;
            }
            None => formatter.write_str(" discovery=none clamp=none")?,
        }

        match self.classification {
            Some(classification) => write!(formatter, " {classification}"),
            None => formatter.write_str(" classification=none"),
        }
    }
}

impl QemuNode {
    /// Returns host-held evidence naming which quiesced writer may own a stall.
    pub(crate) fn stall_context(&self) -> QemuNodeStallContext {
        QemuNodeStallContext::new(
            [
                ("selectable", self.selectable_resume_pending),
                ("network-output", self.network_output_resume_pending),
                ("console-output", self.console_output_resume_pending),
                ("hot-fork", self.hot_fork_resume_pending),
                ("campaign-marker", self.campaign_marker_resume_pending),
            ],
            self.host_io_runtime.coordinated_pause_requested(),
            self.pending_network_outputs.len(),
            self.last_campaign_markers.clone(),
            self.unproven_campaign_marker.clone(),
            self.last_step_completed_boundary
                .map(crate::QemuCompletedQuantumBoundary::stall_boundaries),
            self.last_step_completed_boundary
                .and_then(crate::QemuCompletedQuantumBoundary::classification),
        )
    }

    /// Records the newest campaign markers drained from this node, if any.
    ///
    /// A drain with no campaign marker keeps the previous record, so a stall
    /// names the last marker even after later quanta drained nothing.
    pub(crate) fn note_campaign_markers_drained(&mut self, markers: String) {
        if !markers.is_empty() {
            self.last_campaign_markers = Some(markers);
        }
    }

    /// Records the campaign marker a step drained without proving its stop.
    ///
    /// A proven park or a later step with no marker leaves the record alone;
    /// only the next marker step replaces it.
    pub(crate) fn note_campaign_marker_proof(&mut self, unproven: Option<UnprovenCampaignMarker>) {
        self.unproven_campaign_marker = unproven;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boundary(ceiling: u64, idle_wake: u64, control_ack: u32) -> StallBoundary {
        StallBoundary {
            ceiling,
            status: 1,
            device_io_active: 0,
            control_request: 7,
            control_ack,
            logical: 1_100,
            raw: 11,
            idle_wake,
            advance_sequence: 88,
            settled_ceiling: 0,
            settled_sequence: 0,
            publish_gen: control_ack * 2,
        }
    }

    #[test]
    fn a_stall_with_no_host_evidence_says_so() {
        let context = QemuNodeStallContext::new(
            [("selectable", false), ("campaign-marker", false)],
            None,
            0,
            None,
            None,
            None,
            None,
        );

        assert_eq!(
            context.to_string(),
            "CRUCIBLE-STALL-CONTEXT-V1 resume_pending=none pause_requested=unknown pending_outputs=0 last_marker=none unproven_marker=none discovery=none clamp=none classification=none"
        );
    }

    #[test]
    fn a_stall_names_retained_stops_markers_and_both_publications() {
        let context = QemuNodeStallContext::new(
            [
                ("selectable", false),
                ("network-output", true),
                ("campaign-marker", true),
            ],
            Some(true),
            2,
            Some(String::from("fault.transport.ready@100")),
            Some(UnprovenCampaignMarker {
                markers: String::from("fault.transport.ready@100"),
                stop_tick: 1_100,
            }),
            Some((boundary(2_000, 1_100, 7), boundary(1_100, 1_100, 8))),
            Some(AdvanceClassification::begin(Some(1_100)).classified(14)),
        );

        assert_eq!(
            context.to_string(),
            "CRUCIBLE-STALL-CONTEXT-V1 resume_pending=network-output,campaign-marker pause_requested=true pending_outputs=2 last_marker=fault.transport.ready@100 unproven_marker=fault.transport.ready@100/stop=1100 discovery=ceiling:2000,status:1,device_io:0,control_request:7,control_ack:7,logical:1100,raw:11,idle_wake:1100,advance_sequence:88,settled_ceiling:0,settled_sequence:0,publish_gen:14 clamp=ceiling:1100,status:1,device_io:0,control_request:7,control_ack:8,logical:1100,raw:11,idle_wake:1100,advance_sequence:88,settled_ceiling:0,settled_sequence:0,publish_gen:16 classification=guard_start:1100,guard_release:none,fence_gen:none,discovery_gen:14"
        );
    }
}
