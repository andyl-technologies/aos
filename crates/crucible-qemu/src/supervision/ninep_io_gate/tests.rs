//! Certification and deterministic-projection tests for the live 9p gate.

use super::*;

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
