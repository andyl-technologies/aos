//! Checks exact campaign-marker stops against physical and logical calibration.

use super::*;
use crucible::MarkerId;

fn transport_marker(node: &NodeId, tick: u64) -> ObservableEvent {
    ObservableEvent::guest_marker(
        Icount { retired: tick },
        node.clone(),
        MarkerId::from_name("fault.transport.ready"),
    )
}

#[test]
fn only_exact_campaign_marker_stop_is_retained() {
    let node = NodeId {
        name: "west".to_owned(),
    };
    // The marker instruction retires at raw count 41 and the stopped slot
    // reports the post-instruction raw count 42. The white-box event carries
    // the marker's logical tick, so it moves with the calibration offset.
    let marker_raw = Icount { retired: 41 };
    let stopped_at = Icount { retired: 2_100 };
    let calibration = QemuLogicalTimeCalibration {
        logical_icount: 2_100,
        raw_icount: 42,
    };
    let unbiased = transport_marker(&node, 2_050);

    assert_eq!(
        campaign_marker_parked_at(
            &node,
            stopped_at,
            calibration,
            std::slice::from_ref(&unbiased)
        ),
        Ok(Some(QemuParkedCampaignMarker {
            marker: "fault.transport.ready".to_owned(),
            marker_icount: marker_raw,
            marker_tick: Icount { retired: 2_050 },
            physical_raw_icount: Icount { retired: 42 },
            physical_icount: stopped_at,
        }))
    );

    let projected_stop = Icount { retired: 2_158 };
    let projected_calibration = QemuLogicalTimeCalibration {
        logical_icount: 2_158,
        raw_icount: 42,
    };
    let projected = transport_marker(&node, 2_108);
    assert_eq!(
        campaign_marker_parked_at(
            &node,
            projected_stop,
            projected_calibration,
            std::slice::from_ref(&projected),
        ),
        Ok(Some(QemuParkedCampaignMarker {
            marker: "fault.transport.ready".to_owned(),
            marker_icount: marker_raw,
            marker_tick: Icount { retired: 2_108 },
            physical_raw_icount: Icount { retired: 42 },
            physical_icount: projected_stop,
        }))
    );

    // A marker two instructions before the stop leaves one raw instruction
    // unexplained in both clock domains.
    let stale_calibration = QemuLogicalTimeCalibration {
        logical_icount: 2_158,
        raw_icount: 43,
    };
    let stale = transport_marker(&node, 2_058);
    let error = match campaign_marker_parked_at(
        &node,
        projected_stop,
        stale_calibration,
        std::slice::from_ref(&stale),
    ) {
        Err(error) => error,
        Ok(marker) => {
            panic!("the stopped raw count must be exactly one beyond the marker: {marker:?}")
        }
    };
    assert!(error.to_string().contains(
        "CRUCIBLE-QEMU-CAMPAIGN-MARKER-BOUNDARY-V3 node=west marker=fault.transport.ready pre_raw=41 post_raw=42 observed_tick=2108 logical_offset_picoseconds=8 marker_event_tick=2058 physical_stop_raw=43 physical_stop_tick=2158"
    ));

    // A calibration whose logical tick disagrees with the stop moves the
    // marker off the raw instruction grid.
    let mismatched_logical_calibration = QemuLogicalTimeCalibration {
        logical_icount: 2_159,
        raw_icount: 42,
    };
    assert!(
        campaign_marker_parked_at(
            &node,
            projected_stop,
            mismatched_logical_calibration,
            std::slice::from_ref(&projected),
        )
        .is_err()
    );

    // A logical stop that differs from the calibrated slot is refused even
    // when the raw counts agree.
    assert!(
        campaign_marker_parked_at(
            &node,
            Icount { retired: 2_208 },
            projected_calibration,
            std::slice::from_ref(&projected),
        )
        .is_err()
    );

    assert!(
        campaign_marker_parked_at(
            &node,
            projected_stop,
            projected_calibration,
            &[projected.clone(), projected],
        )
        .is_err()
    );

    let unrelated = ObservableEvent::guest_marker(
        Icount { retired: 2_050 },
        node.clone(),
        MarkerId::from_name("setup.complete"),
    );
    assert_eq!(
        campaign_marker_parked_at(&node, stopped_at, calibration, &[unrelated]),
        Ok(None)
    );
}

#[test]
fn production_hot_fork_marker_coordinates_prove_the_stop() {
    // Coordinates reported by a generation-2 node whose logical clock carries
    // the hot-fork offset: the event tick is one instruction before the stop.
    let node = NodeId {
        name: "traffic-west".to_owned(),
    };
    let calibration = QemuLogicalTimeCalibration {
        logical_icount: 4_168_290_950_600,
        raw_icount: 7_179_545_003,
    };
    let stopped_at = Icount {
        retired: 4_168_290_950_600,
    };
    let marker = transport_marker(&node, 4_168_290_950_550);

    assert_eq!(
        campaign_marker_parked_at(
            &node,
            stopped_at,
            calibration,
            std::slice::from_ref(&marker)
        ),
        Ok(Some(QemuParkedCampaignMarker {
            marker: "fault.transport.ready".to_owned(),
            marker_icount: Icount {
                retired: 7_179_545_002,
            },
            marker_tick: Icount {
                retired: 4_168_290_950_550,
            },
            physical_raw_icount: Icount {
                retired: 7_179_545_003,
            },
            physical_icount: stopped_at,
        }))
    );
}
