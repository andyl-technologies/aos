//! Checks typed QEMU crashed-node status classification.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::VecDeque;
use std::io::{self, ErrorKind};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use crucible_protocol::FrameIoError;
use crucible_qemu::{
    QemuChannelFailure, QemuChildExitProbe, QemuChildStatusProbeError, QemuCrashCause,
    QemuCrashDetector, QemuCrashHandling, QemuNodeRunStatus,
};

#[test]
fn unexpected_child_exit_surfaces_typed_crashed_node_status() {
    let detector = QemuCrashDetector::new("node-a");
    let status = detector.unexpected_child_exit(exit_status(9));

    let crashed = assert_infrastructure_crash(status);
    assert_eq!(crashed.node_id, "node-a");
    assert_eq!(crashed.handling, QemuCrashHandling::ReportAndLocalize);
    assert!(!crashed.handling.retry_on_determinism_gate());
    match crashed.cause {
        QemuCrashCause::UnexpectedChildExit(exit) => {
            assert_eq!(exit.code, Some(9));
            assert_eq!(exit.signal, None);
            assert!(!exit.success);
            assert!(!exit.display.is_empty());
        }
        other => panic!("expected child-exit crash cause, got {other:?}"),
    }
}

#[test]
fn child_exit_probe_surfaces_real_exit_through_detector() {
    let detector = QemuCrashDetector::new("node-a");
    let mut child = ScriptedChildProbe::new([Ok(Some(exit_status(17)))]);

    let Some(status) = detector
        .detect_unexpected_child_exit(&mut child)
        .unwrap_or_else(|error| panic!("child probe failed unexpectedly: {error}"))
    else {
        panic!("expected child exit to be detected");
    };

    let crashed = assert_infrastructure_crash(status);
    match crashed.cause {
        QemuCrashCause::UnexpectedChildExit(exit) => {
            assert_eq!(exit.code, Some(17));
            assert!(!exit.success);
        }
        other => panic!("expected child-exit crash cause, got {other:?}"),
    }
}

#[test]
fn child_exit_probe_reports_running_child_without_crash() {
    let detector = QemuCrashDetector::new("node-a");
    let mut child = ScriptedChildProbe::new([Ok(None)]);

    assert_eq!(detector.detect_unexpected_child_exit(&mut child), Ok(None));
}

#[test]
fn child_exit_probe_errors_remain_probe_errors() {
    let detector = QemuCrashDetector::new("node-a");
    let error = QemuChildStatusProbeError {
        operation: "poll QEMU child exit",
        kind: ErrorKind::PermissionDenied,
    };
    let mut child = ScriptedChildProbe::new([Err(error)]);

    assert_eq!(
        detector.detect_unexpected_child_exit(&mut child),
        Err(error)
    );
}

#[test]
fn std_process_child_is_the_production_exit_probe() {
    fn assert_child_probe<T: QemuChildExitProbe>() {}

    assert_child_probe::<std::process::Child>();
}

#[test]
fn plugin_ipc_close_is_crash_not_intended_fault() {
    let detector = QemuCrashDetector::new("node-a");
    let status = detector.plugin_ipc_closed("read setup ack", "control socket EOF");

    assert!(status.is_infrastructure_crash());
    assert!(!status.is_intended_crash_fault());
    let crashed = assert_infrastructure_crash(status);
    assert_eq!(
        crashed.cause,
        QemuCrashCause::PluginIpcClosed(QemuChannelFailure::new(
            "read setup ack",
            "control socket EOF"
        ))
    );
    assert!(!crashed.handling.retry_on_determinism_gate());
}

#[test]
fn plugin_ipc_frame_failure_is_detected_as_crashed_node() {
    let detector = QemuCrashDetector::new("node-a");
    let result: Result<(), FrameIoError> = Err(FrameIoError::TruncatedPayload { length: 9 });
    let status = match detector.detect_plugin_ipc_result("read run ack", result) {
        Ok(()) => panic!("expected plugin-IPC failure"),
        Err(status) => status,
    };

    let crashed = assert_infrastructure_crash(status);
    assert_eq!(crashed.node_id, "node-a");
    match crashed.cause {
        QemuCrashCause::PluginIpcClosed(failure) => {
            assert_eq!(failure.operation, "read run ack");
            assert!(failure.detail.contains("payload"));
        }
        other => panic!("expected plugin-IPC crash cause, got {other:?}"),
    }
}

#[test]
fn plugin_ipc_success_passes_through_without_crash() {
    let detector = QemuCrashDetector::new("node-a");

    assert_eq!(
        detector.detect_plugin_ipc_result("read run ack", Ok::<_, FrameIoError>(42)),
        Ok(42)
    );
}

#[test]
fn qmp_disconnect_is_crash_not_retried_on_gated_path() {
    let detector = QemuCrashDetector::new("node-a");
    let status = detector.qmp_disconnected("query status", "QMP EOF");

    assert!(status.is_infrastructure_crash());
    assert!(!status.is_intended_crash_fault());
    let crashed = assert_infrastructure_crash(status);
    assert_eq!(
        crashed.cause,
        QemuCrashCause::QmpDisconnected(QemuChannelFailure::new("query status", "QMP EOF"))
    );
    assert_eq!(crashed.handling, QemuCrashHandling::ReportAndLocalize);
    assert!(!crashed.handling.retry_on_determinism_gate());
}

#[test]
fn qmp_io_failure_is_detected_as_crashed_node() {
    let detector = QemuCrashDetector::new("node-a");
    let result: io::Result<()> = Err(io::Error::new(ErrorKind::ConnectionReset, "QMP EOF"));
    let status = match detector.detect_qmp_result("query status", result) {
        Ok(()) => panic!("expected QMP failure"),
        Err(status) => status,
    };

    let crashed = assert_infrastructure_crash(status);
    assert_eq!(crashed.handling, QemuCrashHandling::ReportAndLocalize);
    match crashed.cause {
        QemuCrashCause::QmpDisconnected(failure) => {
            assert_eq!(failure.operation, "query status");
            assert!(failure.detail.contains("QMP EOF"));
        }
        other => panic!("expected QMP crash cause, got {other:?}"),
    }
}

#[test]
fn qmp_success_passes_through_without_crash() {
    let detector = QemuCrashDetector::new("node-a");

    assert_eq!(
        detector.detect_qmp_result("query status", Ok::<_, io::Error>("running")),
        Ok("running")
    );
}

#[test]
fn intended_crash_fault_is_distinct_from_infrastructure_crash() {
    let detector = QemuCrashDetector::new("node-a");
    let status = detector.intended_crash_fault("fault-crash-node-a");

    assert!(!status.is_infrastructure_crash());
    assert!(status.is_intended_crash_fault());
    match status {
        QemuNodeRunStatus::IntendedCrashFault(fault) => {
            assert_eq!(fault.node_id, "node-a");
            assert_eq!(fault.fault_id, "fault-crash-node-a");
        }
        other => panic!("expected intended crash fault status, got {other:?}"),
    }
}

fn assert_infrastructure_crash(status: QemuNodeRunStatus) -> crucible_qemu::QemuCrashedNodeStatus {
    match status {
        QemuNodeRunStatus::Crashed(crashed) => crashed,
        other => panic!("expected infrastructure crash status, got {other:?}"),
    }
}

struct ScriptedChildProbe {
    outcomes: VecDeque<Result<Option<ExitStatus>, QemuChildStatusProbeError>>,
}

impl ScriptedChildProbe {
    fn new(
        outcomes: impl IntoIterator<Item = Result<Option<ExitStatus>, QemuChildStatusProbeError>>,
    ) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
        }
    }
}

impl QemuChildExitProbe for ScriptedChildProbe {
    fn try_wait_for_exit(&mut self) -> Result<Option<ExitStatus>, QemuChildStatusProbeError> {
        match self.outcomes.pop_front() {
            Some(outcome) => outcome,
            None => Ok(None),
        }
    }
}

#[cfg(unix)]
fn exit_status(code: i32) -> ExitStatus {
    ExitStatus::from_raw(code << 8)
}

#[cfg(not(unix))]
fn exit_status(_code: i32) -> ExitStatus {
    let status = std::process::Command::new("false")
        .status()
        .unwrap_or_else(|error| panic!("failed to run false for test exit status: {error}"));
    status
}
