//! Certification and deterministic-projection tests for the live 9p gate.

use super::super::ninep_io_servicer::QemuLive9pIoServiceStep;
use super::*;
use crucible_shmem::{KIND_VM, STATUS_RUNNING};

fn idle_snapshot(current_icount: u64, idle_wake_icount: u64) -> NodeSlotSnapshot {
    NodeSlotSnapshot {
        current_icount,
        current_ns: current_icount,
        max_advance_icount: 100,
        idle_wake_icount,
        wake_signal: 0,
        status: STATUS_IDLE,
        kind: KIND_VM,
        device_io_active: 0,
        publish_gen: 0,
        control_boundary_ack: 0,
        logical_time_raw_icount: current_icount,
        logical_time_restore_target: 0,
        logical_time_restore_request: 0,
        logical_time_restore_ack: 0,
    }
}

fn empty_service_step() -> QemuLive9pIoServiceStep {
    QemuLive9pIoServiceStep {
        processed: 0,
        delivered: 0,
        first_request_icount: None,
        computed_completion_icount: None,
        next_completion_icount: None,
    }
}

fn certifying_outcome() -> NinepIoRunOutcome {
    NinepIoRunOutcome {
        advance: NinepIoAdvanceOutcome::ReachedCeiling { icount: 100 },
        diagnostics: NinepIoDiagnosticsSnapshot {
            frames_processed: 1,
            frames_delivered: 1,
            service_calls: 4,
            first_request_icount: Some(20),
            first_completion_horizon: Some(30),
            last_current_icount: 100,
            max_current_icount: 100,
            last_device_io_active: false,
            last_idle_wake_icount: 30,
        },
        orderly_child_exit: true,
        response_delay_applied: true,
    }
}

#[test]
fn certification_requires_forwarding_completion_and_progress() {
    let outcome = certifying_outcome();
    assert!(certify_run("reference", &outcome, false).is_ok());
    assert!(certify_run("host-load", &outcome, true).is_ok());

    let mut quiescent = certifying_outcome();
    quiescent.advance = NinepIoAdvanceOutcome::QuiescentThroughCeiling {
        icount: 99,
        idle_wake_icount: 101,
    };
    quiescent.diagnostics.last_current_icount = 99;
    assert!(certify_run("host-load", &quiescent, true).is_ok());

    let mut missing_forward = certifying_outcome();
    missing_forward.diagnostics.frames_processed = 0;
    assert!(matches!(
        certify_run("reference", &missing_forward, false),
        Err(QemuLive9pIoGateError::CertificationFailed { .. })
    ));

    let mut stalled = certifying_outcome();
    stalled.advance = NinepIoAdvanceOutcome::PausedBelowCeiling { icount: 30 };
    assert!(matches!(
        certify_run("reference", &stalled, false),
        Err(QemuLive9pIoGateError::CertificationFailed { .. })
    ));

    let mut nonfuture_horizon = certifying_outcome();
    nonfuture_horizon.diagnostics.first_completion_horizon = Some(20);
    assert!(matches!(
        certify_run("reference", &nonfuture_horizon, false),
        Err(QemuLive9pIoGateError::CertificationFailed { .. })
    ));

    let mut no_progress_past_completion = certifying_outcome();
    no_progress_past_completion.diagnostics.last_current_icount = 30;
    assert!(matches!(
        certify_run("reference", &no_progress_past_completion, false),
        Err(QemuLive9pIoGateError::CertificationFailed { .. })
    ));
}

#[test]
fn host_load_certification_requires_the_wall_delay() {
    let mut outcome = certifying_outcome();
    outcome.response_delay_applied = false;
    assert!(certify_run("repeat", &outcome, false).is_ok());
    assert!(matches!(
        certify_run("host-load", &outcome, true),
        Err(QemuLive9pIoGateError::CertificationFailed { .. })
    ));
}

#[test]
fn deterministic_projection_excludes_poll_jitter() {
    let reference = certifying_outcome();
    let mut jittered = certifying_outcome();
    jittered.diagnostics.frames_processed += 1;
    jittered.diagnostics.frames_delivered += 1;
    jittered.diagnostics.service_calls += 50;
    jittered.diagnostics.last_current_icount += 1;
    jittered.diagnostics.max_current_icount += 1;
    jittered.diagnostics.last_idle_wake_icount += 1;
    jittered.diagnostics.first_request_icount = jittered
        .diagnostics
        .first_request_icount
        .map(|value| value + 7);
    jittered.diagnostics.first_completion_horizon = jittered
        .diagnostics
        .first_completion_horizon
        .map(|value| value + 7);
    assert_eq!(
        deterministic_projection(&reference.diagnostics),
        deterministic_projection(&jittered.diagnostics)
    );

    let mut missing_forward = certifying_outcome();
    missing_forward.diagnostics.frames_processed = 0;
    assert_ne!(
        deterministic_projection(&reference.diagnostics),
        deterministic_projection(&missing_forward.diagnostics),
        "the projection must still reject a run with no forwarded request"
    );
}

#[test]
fn ceiling_closure_accepts_only_drained_idle_wakes_beyond_the_boundary() {
    let service = empty_service_step();
    assert_eq!(
        completed_ceiling_outcome(&idle_snapshot(99, 101), &service, 100),
        Some(NinepIoAdvanceOutcome::QuiescentThroughCeiling {
            icount: 99,
            idle_wake_icount: 101,
        })
    );
    assert_eq!(
        completed_ceiling_outcome(&idle_snapshot(100, 101), &service, 100),
        Some(NinepIoAdvanceOutcome::ReachedCeiling { icount: 100 })
    );
    assert_eq!(
        completed_ceiling_outcome(&idle_snapshot(99, 100), &service, 100),
        None
    );

    let mut running = idle_snapshot(99, 101);
    running.status = STATUS_RUNNING;
    assert_eq!(completed_ceiling_outcome(&running, &service, 100), None);

    let mut active = idle_snapshot(99, 101);
    active.device_io_active = 1;
    assert_eq!(completed_ceiling_outcome(&active, &service, 100), None);

    let mut delivered = service;
    delivered.delivered = 1;
    assert_eq!(
        completed_ceiling_outcome(&idle_snapshot(99, 101), &delivered, 100),
        None
    );
}
