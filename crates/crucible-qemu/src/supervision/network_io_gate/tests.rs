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

fn outcome_at(probe_icount: u64) -> NetworkIoRunOutcome {
    let acknowledgement_icount = probe_icount + 100_012_871;
    NetworkIoRunOutcome {
        snapshot: LiveNetworkIoSnapshot {
            tx_frames: vec![
                LiveNetworkTxObservation {
                    emit_icount: probe_icount,
                    sequence: 0,
                    payload: LIVE_NETWORK_PROBE_PAYLOAD.to_vec(),
                },
                LiveNetworkTxObservation {
                    emit_icount: acknowledgement_icount,
                    sequence: 1,
                    payload: LIVE_NETWORK_ACK_PAYLOAD.to_vec(),
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
    }
}
