//! Checks exact campaign-marker stops against physical and logical calibration.

use super::*;
use crucible::MarkerId;

#[test]
fn only_exact_campaign_marker_stop_is_retained() {
    let node = NodeId {
        name: "west".to_owned(),
    };
    let marker_at = Icount { retired: 41 };
    let event = ObservableEvent::guest_marker(
        marker_at,
        node.clone(),
        MarkerId::from_name("fault.transport.ready"),
    );
    let stopped_at = Icount { retired: 2_100 };
    let calibration = QemuLogicalTimeCalibration {
        logical_icount: 2_100,
        raw_icount: 42,
    };

    assert_eq!(
        campaign_marker_parked_at(&node, stopped_at, calibration, std::slice::from_ref(&event),),
        Ok(Some(QemuParkedCampaignMarker {
            marker: "fault.transport.ready".to_owned(),
            marker_icount: marker_at,
            physical_raw_icount: Icount { retired: 42 },
            physical_icount: stopped_at,
        }))
    );
    let projected_stop = Icount { retired: 2_158 };
    let projected_calibration = QemuLogicalTimeCalibration {
        logical_icount: 2_158,
        raw_icount: 42,
    };
    assert_eq!(
        campaign_marker_parked_at(
            &node,
            projected_stop,
            projected_calibration,
            std::slice::from_ref(&event),
        ),
        Ok(Some(QemuParkedCampaignMarker {
            marker: "fault.transport.ready".to_owned(),
            marker_icount: marker_at,
            physical_raw_icount: Icount { retired: 42 },
            physical_icount: projected_stop,
        }))
    );

    let mismatched_calibration = QemuLogicalTimeCalibration {
        logical_icount: 2_158,
        raw_icount: 43,
    };
    let error = match campaign_marker_parked_at(
        &node,
        projected_stop,
        mismatched_calibration,
        std::slice::from_ref(&event),
    ) {
        Err(error) => error,
        Ok(marker) => {
            panic!("the stopped raw count must be exactly one beyond the marker: {marker:?}")
        }
    };
    assert!(error.to_string().contains(
        "CRUCIBLE-QEMU-CAMPAIGN-MARKER-BOUNDARY-V2 node=west marker=fault.transport.ready pre_raw=41 post_raw=42 observed_tick=2108 logical_offset_picoseconds=8 marker_event_raw=41 physical_stop_raw=43 physical_stop_tick=2158"
    ));
    let mismatched_logical_calibration = QemuLogicalTimeCalibration {
        logical_icount: 2_159,
        raw_icount: 42,
    };
    assert!(
        campaign_marker_parked_at(
            &node,
            projected_stop,
            mismatched_logical_calibration,
            std::slice::from_ref(&event),
        )
        .is_err()
    );
    assert!(
        campaign_marker_parked_at(
            &node,
            projected_stop,
            projected_calibration,
            &[event.clone(), event],
        )
        .is_err()
    );

    let unrelated = ObservableEvent::guest_marker(
        marker_at,
        node.clone(),
        MarkerId::from_name("setup.complete"),
    );
    assert_eq!(
        campaign_marker_parked_at(&node, stopped_at, calibration, &[unrelated]),
        Ok(None)
    );
}
