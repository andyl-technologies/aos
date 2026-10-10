//! Validates campaign marker evidence against one physical VMStop boundary.
//!
//! The white-box callback reports a pre-instruction raw count. A valid parked
//! marker must uniquely match the independently published post-instruction raw
//! count and its calibrated scheduler-visible logical tick.

use crucible_engine::{BackendError, Icount, NodeId, ObservableEvent, ObservableEventPayload};

use super::{QemuCampaignMarkerBoundaryDiagnostic, QemuParkedCampaignMarker};
use crate::QemuLogicalTimeCalibration;

const CAMPAIGN_BOUNDARY_MARKERS: [&str; 2] = ["fault.transport.ready", "fault.followup.ready"];

/// Matches a unique campaign marker to the calibrated physical VMStop.
///
/// # Errors
///
/// Rejects overflow, invalid time calibration, duplicate markers, or a marker
/// whose post-instruction raw count and logical tick do not prove the stop.
pub(super) fn campaign_marker_parked_at(
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
        // The trap reports its instruction's pre-retirement raw count. The
        // stopped slot independently pairs the post-instruction raw count with
        // its scheduler-visible logical tick.
        let post_raw =
            retired_icount
                .retired
                .checked_add(1)
                .ok_or_else(|| BackendError::Rejected {
                    message: format!("QEMU node `{}` marker retired count overflowed", node.name),
                })?;
        let logical_offset_picoseconds = calibration
            .offset()
            .map_err(|source| BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` campaign marker `{}` has invalid logical-time calibration: {source}",
                    node.name, marker.name,
                ),
            })?;
        let observed_tick = post_raw
            .checked_mul(crucible_engine::SIM_TICKS_PER_INSTRUCTION)
            .and_then(|raw_picoseconds| raw_picoseconds.checked_add(logical_offset_picoseconds))
            .ok_or_else(|| BackendError::Rejected {
                message: format!(
                    "QEMU node `{}` campaign marker `{}` logical coordinate overflowed",
                    node.name, marker.name,
                ),
            })?;
        let diagnostic = QemuCampaignMarkerBoundaryDiagnostic {
            node: node.clone(),
            marker: marker.name.clone(),
            pre_raw: retired_icount.retired,
            post_raw,
            observed_tick,
            logical_offset_picoseconds,
            marker_event_raw: retired_icount.retired,
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
            marker_icount: *retired_icount,
            physical_raw_icount: Icount {
                retired: calibration.raw_icount,
            },
            physical_icount,
        });
    }
    Ok(matched)
}
