//! Checks QEMU child shutdown escalation.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::VecDeque;
use std::error::Error;
use std::io::{self, Write};
use std::process::Command;
use std::time::Duration;

use crucible_protocol::{HostMsg, control_encode_host_msg};
use crucible_qemu::{
    QEMU_SHUTDOWN_ESCALATION_ORDER, QMP_QUIT_COMMAND, QemuChildWait, QemuReap, QemuShutdownError,
    QemuShutdownPolicy, QemuShutdownRung, QemuShutdownTarget, QemuShutdownTargetError,
    UnixQemuChildShutdownTarget, send_control_quit_frame, send_qmp_quit_command,
    shutdown_qemu_child,
};

#[test]
fn shutdown_escalates_to_sigkill_and_reaps_unresponsive_child() -> Result<(), Box<dyn Error>> {
    let policy = QemuShutdownPolicy::fast_test();
    let mut target = ScriptedTarget::new(
        [
            QemuChildWait::StillRunning,
            QemuChildWait::StillRunning,
            QemuChildWait::StillRunning,
            QemuChildWait::Exited,
        ],
        QemuReap::Reaped,
    );

    let report = shutdown_qemu_child(&mut target, policy)?;

    assert_eq!(
        target.actions,
        [
            QemuShutdownRung::ControlQuit,
            QemuShutdownRung::QmpQuit,
            QemuShutdownRung::Sigterm,
            QemuShutdownRung::Sigkill,
            QemuShutdownRung::Reap,
        ]
    );
    assert_eq!(
        target.waits,
        vec![
            (QemuShutdownRung::ControlQuit, policy.control_quit_wait),
            (QemuShutdownRung::QmpQuit, policy.qmp_quit_wait),
            (QemuShutdownRung::Sigterm, policy.sigterm_wait),
            (QemuShutdownRung::Sigkill, policy.sigkill_wait),
            (QemuShutdownRung::Reap, policy.reap_wait),
        ]
    );
    assert!(report.reaped);
    assert!(!report.leaked);
    assert!(report.failures.is_empty());
    assert_eq!(report.attempts.len(), 4);
    assert_eq!(
        report
            .attempts
            .iter()
            .map(|attempt| attempt.rung)
            .collect::<Vec<_>>(),
        [
            QemuShutdownRung::ControlQuit,
            QemuShutdownRung::QmpQuit,
            QemuShutdownRung::Sigterm,
            QemuShutdownRung::Sigkill,
        ]
    );

    Ok(())
}

#[test]
fn shutdown_stops_escalating_after_qmp_exit() -> Result<(), Box<dyn Error>> {
    let policy = QemuShutdownPolicy::fast_test();
    let mut target = ScriptedTarget::new(
        [QemuChildWait::StillRunning, QemuChildWait::Exited],
        QemuReap::Reaped,
    );

    let report = shutdown_qemu_child(&mut target, policy)?;

    assert_eq!(
        target.actions,
        [
            QemuShutdownRung::ControlQuit,
            QemuShutdownRung::QmpQuit,
            QemuShutdownRung::Reap,
        ]
    );
    assert_eq!(
        report
            .attempts
            .iter()
            .map(|attempt| attempt.rung)
            .collect::<Vec<_>>(),
        [QemuShutdownRung::ControlQuit, QemuShutdownRung::QmpQuit]
    );
    assert!(report.reaped);
    assert!(!report.leaked);
    assert!(report.failures.is_empty());

    Ok(())
}

#[test]
fn shutdown_reports_leak_when_reap_cannot_collect_child() {
    let policy = QemuShutdownPolicy::fast_test();
    let mut target = ScriptedTarget::new(
        [
            QemuChildWait::StillRunning,
            QemuChildWait::StillRunning,
            QemuChildWait::StillRunning,
            QemuChildWait::StillRunning,
        ],
        QemuReap::StillAlive,
    );

    let error = shutdown_qemu_child(&mut target, policy);

    match error {
        Err(QemuShutdownError::LeakedChild { report }) => {
            assert!(!report.reaped);
            assert!(report.leaked);
            assert_eq!(report.attempts.len(), 4);
        }
        other => panic!("expected leaked child error, got {other:?}"),
    }
    assert_eq!(
        target.actions,
        [
            QemuShutdownRung::ControlQuit,
            QemuShutdownRung::QmpQuit,
            QemuShutdownRung::Sigterm,
            QemuShutdownRung::Sigkill,
            QemuShutdownRung::Reap,
        ]
    );
}

#[test]
fn shutdown_records_polite_failures_and_continues_to_reap() -> Result<(), Box<dyn Error>> {
    let policy = QemuShutdownPolicy::fast_test();
    let mut target = ScriptedTarget::new(
        [
            QemuChildWait::StillRunning,
            QemuChildWait::StillRunning,
            QemuChildWait::Exited,
        ],
        QemuReap::Reaped,
    )
    .with_failure(QemuShutdownRung::ControlQuit)
    .with_failure(QemuShutdownRung::QmpQuit);

    let report = shutdown_qemu_child(&mut target, policy)?;

    assert_eq!(
        report
            .failures
            .iter()
            .map(|failure| failure.rung)
            .collect::<Vec<_>>(),
        [QemuShutdownRung::ControlQuit, QemuShutdownRung::QmpQuit]
    );
    assert_eq!(
        target.actions,
        [
            QemuShutdownRung::ControlQuit,
            QemuShutdownRung::QmpQuit,
            QemuShutdownRung::Sigterm,
            QemuShutdownRung::Sigkill,
            QemuShutdownRung::Reap,
        ]
    );
    assert!(report.reaped);
    assert!(!report.leaked);

    Ok(())
}

#[test]
fn control_quit_and_qmp_helpers_write_canonical_shutdown_bytes() -> Result<(), Box<dyn Error>> {
    let mut control = Vec::new();
    send_control_quit_frame(&mut control)?;
    assert_eq!(control, control_encode_host_msg(&HostMsg::Quit));

    let mut qmp = Vec::new();
    send_qmp_quit_command(&mut qmp)?;
    let mut expected_qmp = QMP_QUIT_COMMAND.to_vec();
    expected_qmp.extend_from_slice(b"\r\n");
    assert_eq!(qmp, expected_qmp);

    Ok(())
}

#[test]
fn unix_adapter_continues_after_broken_polite_channels_and_reaps_child()
-> Result<(), Box<dyn Error>> {
    let child = Command::new("sleep").arg("60").spawn()?;
    let mut target = UnixQemuChildShutdownTarget::new(child, FailingWriter, FailingWriter);
    let mut policy = QemuShutdownPolicy::fast_test();
    policy.sigterm_wait = Duration::from_secs(2);
    policy.reap_wait = Duration::from_secs(1);

    let report = shutdown_qemu_child(&mut target, policy)?;

    assert!(report.reaped);
    assert!(!report.leaked);
    assert!(target.reaped());
    assert_eq!(
        report
            .failures
            .iter()
            .map(|failure| failure.rung)
            .collect::<Vec<_>>(),
        [QemuShutdownRung::ControlQuit, QemuShutdownRung::QmpQuit]
    );

    Ok(())
}

#[test]
fn unix_adapter_reaps_real_qemu_child_when_polite_channels_fail() -> Result<(), Box<dyn Error>> {
    let Some(qemu) = std::env::var_os("CRUCIBLE_QEMU_SHUTDOWN_TEST_BINARY") else {
        return Ok(());
    };
    let child = Command::new(qemu)
        .args([
            "-nodefaults",
            "-no-user-config",
            "-display",
            "none",
            "-machine",
            "none",
            "-S",
            "-monitor",
            "none",
            "-serial",
            "none",
        ])
        .spawn()?;
    let mut target = UnixQemuChildShutdownTarget::new(child, FailingWriter, FailingWriter);
    let mut policy = QemuShutdownPolicy::fast_test();
    policy.sigterm_wait = Duration::from_secs(2);
    policy.reap_wait = Duration::from_secs(1);

    let report = shutdown_qemu_child(&mut target, policy)?;

    assert!(report.reaped);
    assert!(!report.leaked);
    assert!(target.reaped());
    assert_eq!(
        report
            .failures
            .iter()
            .map(|failure| failure.rung)
            .collect::<Vec<_>>(),
        [QemuShutdownRung::ControlQuit, QemuShutdownRung::QmpQuit]
    );

    Ok(())
}

#[test]
fn shutdown_order_matches_protocol_spec() {
    assert_eq!(
        QEMU_SHUTDOWN_ESCALATION_ORDER,
        [
            QemuShutdownRung::ControlQuit,
            QemuShutdownRung::QmpQuit,
            QemuShutdownRung::Sigterm,
            QemuShutdownRung::Sigkill,
            QemuShutdownRung::Reap,
        ]
    );
}

#[derive(Debug)]
struct ScriptedTarget {
    actions: Vec<QemuShutdownRung>,
    waits: Vec<(QemuShutdownRung, Duration)>,
    wait_results: VecDeque<QemuChildWait>,
    reap_result: QemuReap,
    fail_rungs: Vec<QemuShutdownRung>,
}

impl ScriptedTarget {
    fn new(wait_results: impl IntoIterator<Item = QemuChildWait>, reap_result: QemuReap) -> Self {
        Self {
            actions: Vec::new(),
            waits: Vec::new(),
            wait_results: wait_results.into_iter().collect(),
            reap_result,
            fail_rungs: Vec::new(),
        }
    }

    fn with_failure(mut self, rung: QemuShutdownRung) -> Self {
        self.fail_rungs.push(rung);
        self
    }

    fn record_action(&mut self, rung: QemuShutdownRung) -> Result<(), QemuShutdownTargetError> {
        self.actions.push(rung);
        if self.fail_rungs.contains(&rung) {
            Err(QemuShutdownTargetError::new(
                "scripted rung",
                "forced failure",
            ))
        } else {
            Ok(())
        }
    }
}

impl QemuShutdownTarget for ScriptedTarget {
    fn send_control_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.record_action(QemuShutdownRung::ControlQuit)
    }

    fn send_qmp_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.record_action(QemuShutdownRung::QmpQuit)
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.record_action(QemuShutdownRung::Sigterm)
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.record_action(QemuShutdownRung::Sigkill)
    }

    fn wait_for_exit(
        &mut self,
        rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        self.waits.push((rung, timeout));
        Ok(self
            .wait_results
            .pop_front()
            .unwrap_or(QemuChildWait::StillRunning))
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        self.actions.push(QemuShutdownRung::Reap);
        self.waits.push((QemuShutdownRung::Reap, timeout));
        Ok(self.reap_result)
    }
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
