//! Unit tests for deterministic network-I/O projections.

use super::drive::discovery_quantum_report_ready;
use super::*;
use crate::LiveNetworkTxObservation;
use crucible_shmem::STATUS_RUNNING;

#[test]
fn idle_discovery_boundaries_are_polled_before_reissue_or_completion() {
    assert!(discovery_quantum_report_ready(
        STATUS_IDLE,
        8_000_001,
        PROBE_DISCOVERY_CEILING_ICOUNT,
    ));
    assert!(discovery_quantum_report_ready(
        STATUS_IDLE,
        PROBE_DISCOVERY_CEILING_ICOUNT,
        PROBE_DISCOVERY_CEILING_ICOUNT,
    ));
    assert!(!discovery_quantum_report_ready(
        STATUS_RUNNING,
        8_000_001,
        PROBE_DISCOVERY_CEILING_ICOUNT,
    ));
}

#[test]
fn deterministic_projection_anchors_the_network_trajectory_at_the_probe() {
    let reference = outcome_at(2_000_000);
    let mut hostile = outcome_at(2_001_481);
    hostile.acknowledgement_icount = Some(102_014_913);
    hostile.snapshot.tx_frames[1].emit_icount = 102_014_913;
    hostile.backpressure_acknowledgement_icount = reference.backpressure_acknowledgement_icount;

    assert_ne!(probe_emit_icount(&reference), probe_emit_icount(&hostile));
    assert_ne!(
        acknowledgement_offset_icount(&reference),
        acknowledgement_offset_icount(&hostile)
    );
    assert_eq!(
        deterministic_projection(&reference),
        deterministic_projection(&hostile)
    );
}

#[test]
fn certification_rejects_ack_before_router_delivery_or_with_wrong_mac() {
    let mut early = outcome_at(2_000_000);
    let reply = early.snapshot.reply_delivery_icount.unwrap_or_default();
    early.acknowledgement_icount = reply.checked_sub(1);
    early.snapshot.tx_frames[1].emit_icount = reply.saturating_sub(1);
    assert!(matches!(
        certify_run("early-ack", &early, false),
        Err(QemuLiveNetworkIoGateError::CertificationFailed { .. })
    ));

    let mut wrong_destination = outcome_at(2_000_000);
    wrong_destination.snapshot.tx_frames[1].payload[..6].fill(0xff);
    assert!(matches!(
        certify_run("wrong-ack-destination", &wrong_destination, false),
        Err(QemuLiveNetworkIoGateError::CertificationFailed { .. })
    ));

    let mut no_completion_owned_frame = outcome_at(2_000_000);
    no_completion_owned_frame.completion_owned_frames = 0;
    assert!(matches!(
        certify_run("no-completion-owned-frame", &no_completion_owned_frame, false),
        Err(QemuLiveNetworkIoGateError::CertificationFailed { .. })
    ));
}

fn outcome_at(probe_icount: u64) -> NetworkIoRunOutcome {
    let acknowledgement_icount = probe_icount + 100_012_871;
    let mut probe = vec![0_u8; 60];
    probe[..6].fill(0xff);
    probe[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    probe[12..14].copy_from_slice(&[0x88, 0xb5]);
    probe[14..14 + LIVE_NETWORK_PROBE_PAYLOAD.len()].copy_from_slice(LIVE_NETWORK_PROBE_PAYLOAD);
    let mut acknowledgement = vec![0_u8; 60];
    acknowledgement[..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    acknowledgement[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    acknowledgement[12..14].copy_from_slice(&[0x88, 0xb5]);
    acknowledgement[14..14 + LIVE_NETWORK_ACK_PAYLOAD.len()]
        .copy_from_slice(LIVE_NETWORK_ACK_PAYLOAD);
    NetworkIoRunOutcome {
        snapshot: LiveNetworkIoSnapshot {
            tx_frames: vec![
                LiveNetworkTxObservation {
                    emit_icount: probe_icount,
                    sequence: 0,
                    payload: probe,
                },
                LiveNetworkTxObservation {
                    emit_icount: acknowledgement_icount,
                    sequence: 1,
                    payload: acknowledgement,
                },
            ],
            reply_delivery_icount: Some(probe_icount + LIVE_NETWORK_REPLY_LATENCY_ICOUNT),
            acknowledgement_seen: true,
            backpressure_acknowledgement_seen: true,
        },
        acknowledgement_icount: Some(acknowledgement_icount),
        boot_backpressure_retained: true,
        canonical_backpressure_retry_delivered: true,
        backpressure_acknowledgement_icount: Some(probe_icount - 1),
        backpressure_delivery_attempts: 1,
        backpressure_last_attempt_icount: 1,
        backpressure_retry_icount: Some(4_000_001),
        delayed_reply_applied: false,
        orderly_child_exit: true,
        scheduler_preemption: None,
        scheduler_preemption_pending_quantum: false,
        completion_owned_frames: 1,
    }
}
