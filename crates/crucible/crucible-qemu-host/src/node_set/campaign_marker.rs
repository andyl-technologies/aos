//! Exact proof that a QEMU VMStop belongs to a guest campaign marker.
//!
//! With marker parking, the plugin defers a native VMStop to its first icount
//! publication after a campaign boundary marker. The stopped slot pairs that
//! publication's raw retired count with its logical tick; the marker event
//! carries the marker instruction's own logical tick. A stop is a campaign
//! park only when both clock domains place the marker exactly one
//! instruction before it.

use crucible_engine::{BackendError, Icount, NodeId, ObservableEvent, ObservableEventPayload};

use crate::QemuLogicalTimeCalibration;

/// One QEMU VMStop bound to a campaign marker and its exact retired count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QemuParkedCampaignMarker {
    /// The declared campaign boundary marker name.
    pub marker: String,
    /// Pre-instruction raw retired count of the marker instruction.
    ///
    /// The white-box event carries the instruction's logical tick; this count
    /// is recovered from it through the stopped slot's calibration.
    pub marker_icount: Icount,
    /// Pre-instruction logical tick carried by the white-box marker event.
    pub marker_tick: Icount,
    /// Post-instruction raw retired count paired with QEMU's native VMStop.
    pub physical_raw_icount: Icount,
    /// Scheduler-visible logical tick published with QEMU's native VMStop.
    pub physical_icount: Icount,
}

/// Raw and logical coordinates joined at one campaign-marker VMStop boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QemuCampaignMarkerBoundaryDiagnostic {
    /// Node that emitted the campaign marker.
    pub node: NodeId,
    /// Campaign marker name decoded from the guest event.
    pub marker: String,
    /// Raw retired count immediately before the marker instruction,
    /// recovered from the marker tick through the stopped slot's calibration.
    pub pre_raw: u64,
    /// Raw retired count immediately after the marker instruction.
    pub post_raw: u64,
    /// Logical tick observed after the marker instruction.
    pub observed_tick: u64,
    /// Picosecond bias applied after scaling the raw count.
    pub logical_offset_picoseconds: u64,
    /// Pre-instruction logical tick carried by the marker event.
    pub marker_event_tick: u64,
    /// Raw retired count paired with the physical VMStop publication.
    pub physical_stop_raw: u64,
    /// Scheduler-visible logical tick of the physical VMStop.
    pub physical_stop_tick: u64,
}

impl std::fmt::Display for QemuCampaignMarkerBoundaryDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "CRUCIBLE-QEMU-CAMPAIGN-MARKER-BOUNDARY-V3 node={} marker={} pre_raw={} post_raw={} observed_tick={} logical_offset_picoseconds={} marker_event_tick={} physical_stop_raw={} physical_stop_tick={}",
            self.node.name,
            self.marker,
            self.pre_raw,
            self.post_raw,
            self.observed_tick,
            self.logical_offset_picoseconds,
            self.marker_event_tick,
            self.physical_stop_raw,
            self.physical_stop_tick,
        )
    }
}

impl QemuCampaignMarkerBoundaryDiagnostic {
    /// Returns whether the marker and stopped slot prove one exact instruction boundary.
    #[must_use]
    pub const fn proves_exact_stop(&self) -> bool {
        self.post_raw == self.physical_stop_raw && self.observed_tick == self.physical_stop_tick
    }
}

const CAMPAIGN_BOUNDARY_MARKERS: [&str; 2] = ["fault.transport.ready", "fault.followup.ready"];

/// How a campaign marker that does not prove the observed stop is treated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UnprovenCampaignMarker {
    /// An early pause beside a campaign marker must be that marker's stop.
    Refuse,
    /// A horizon stop is a campaign park only when a marker proves it.
    Admit,
}

/// Returns whether `event` is one of `node`'s campaign boundary markers.
pub(super) fn is_campaign_boundary_marker(node: &NodeId, event: &ObservableEvent) -> bool {
    matches!(
        event.payload(),
        ObservableEventPayload::GuestMarker { node: marker_node, marker, .. }
            if marker_node == node && CAMPAIGN_BOUNDARY_MARKERS.contains(&marker.name.as_str())
    )
}

/// Names a step's campaign markers for `node` as comma-separated `name@tick`.
pub(super) fn campaign_marker_names(node: &NodeId, events: &[ObservableEvent]) -> String {
    events
        .iter()
        .filter(|event| is_campaign_boundary_marker(node, event))
        .filter_map(|event| match event.payload() {
            ObservableEventPayload::GuestMarker {
                retired_icount,
                marker,
                ..
            } => Some(format!("{}@{}", marker.name, retired_icount.retired)),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Writes one diagnostic row for a step that retired a campaign marker.
///
/// Marker steps are rare, and an unproven marker beside a horizon stop is
/// otherwise silent, so the row records what the proof compared.
pub(super) fn report_campaign_marker_stop(
    node: &NodeId,
    physical_icount: Icount,
    calibration: QemuLogicalTimeCalibration,
    events: &[ObservableEvent],
    unproven: UnprovenCampaignMarker,
    stop: &Result<Option<QemuParkedCampaignMarker>, BackendError>,
) {
    use std::io::Write as _;

    let markers = campaign_marker_names(node, events);
    let result = match stop {
        Ok(Some(_)) => String::from("parked"),
        Ok(None) => String::from("unproven"),
        Err(error) => format!("refused({error})"),
    };
    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-QEMU-CAMPAIGN-MARKER-STOP-V1 node={} stop_tick={} unproven={unproven:?} calibration_logical={} calibration_raw={} markers={markers} result={result}",
        node.name,
        physical_icount.retired,
        calibration.logical_icount,
        calibration.raw_icount,
    );
}

/// Applies `unproven` to the exact campaign-marker proof of one stop.
pub(super) fn campaign_marker_stop(
    node: &NodeId,
    physical_icount: Icount,
    calibration: QemuLogicalTimeCalibration,
    events: &[ObservableEvent],
    unproven: UnprovenCampaignMarker,
) -> Result<Option<QemuParkedCampaignMarker>, BackendError> {
    let proof = campaign_marker_parked_at(node, physical_icount, calibration, events);
    match unproven {
        UnprovenCampaignMarker::Refuse => proof,
        UnprovenCampaignMarker::Admit => Ok(proof.ok().flatten()),
    }
}

fn campaign_marker_parked_at(
    node: &NodeId,
    physical_icount: Icount,
    calibration: QemuLogicalTimeCalibration,
    events: &[ObservableEvent],
) -> Result<Option<QemuParkedCampaignMarker>, BackendError> {
    let mut matched = None;
    for event in events {
        let ObservableEventPayload::GuestMarker {
            retired_icount,
            node: marker_node,
            marker,
        } = event.payload()
        else {
            continue;
        };
        if marker_node != node || !CAMPAIGN_BOUNDARY_MARKERS.contains(&marker.name.as_str()) {
            continue;
        }
        // The plugin publishes the marker instruction's pre-retirement logical
        // tick, bound to its callback raw count. The stopped slot independently
        // pairs the post-instruction raw count with its scheduler-visible
        // logical tick, so the raw marker count is recovered through that
        // calibration and must land exactly one instruction before the stop in
        // both clock domains.
        let marker_tick = retired_icount.retired;
        let logical_offset_picoseconds = calibration
            .offset()
            .map_err(|source| BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` campaign marker `{}` has invalid logical-time calibration: {source}",
                    node.name, marker.name,
                ),
            })?;
        let pre_raw = marker_tick
            .checked_sub(logical_offset_picoseconds)
            .filter(|scaled| scaled % crucible_engine::SIM_TICKS_PER_INSTRUCTION == 0)
            .map(|scaled| scaled / crucible_engine::SIM_TICKS_PER_INSTRUCTION)
            .ok_or_else(|| BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` campaign marker `{}` tick {marker_tick} is not on the stopped raw instruction grid with logical offset {logical_offset_picoseconds}",
                    node.name, marker.name,
                ),
            })?;
        let (Some(post_raw), Some(observed_tick)) = (
            pre_raw.checked_add(1),
            marker_tick.checked_add(crucible_engine::SIM_TICKS_PER_INSTRUCTION),
        ) else {
            return Err(BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` campaign marker `{}` coordinate overflowed",
                    node.name, marker.name,
                ),
            });
        };
        let diagnostic = QemuCampaignMarkerBoundaryDiagnostic {
            node: node.clone(),
            marker: marker.name.clone(),
            pre_raw,
            post_raw,
            observed_tick,
            logical_offset_picoseconds,
            marker_event_tick: marker_tick,
            physical_stop_raw: calibration.raw_icount,
            physical_stop_tick: physical_icount.retired,
        };
        if !diagnostic.proves_exact_stop() || matched.is_some() {
            return Err(BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` campaign marker `{}` at {} does not uniquely prove physical stop {}; {diagnostic}",
                    node.name, marker.name, retired_icount.retired, physical_icount.retired,
                ),
            });
        }
        matched = Some(QemuParkedCampaignMarker {
            marker: marker.name.clone(),
            marker_icount: Icount { retired: pre_raw },
            marker_tick: *retired_icount,
            physical_raw_icount: Icount {
                retired: calibration.raw_icount,
            },
            physical_icount,
        });
    }
    Ok(matched)
}

#[cfg(test)]
#[path = "campaign_marker_parking_tests.rs"]
mod campaign_marker_parking_tests;
