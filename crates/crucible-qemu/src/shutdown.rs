//! QEMU child shutdown escalation.
//!
//! This module owns the host-side ladder fixed by RFC-0010 protocol shutdown:
//! send the plugin `Quit`, issue QMP `quit`, send `SIGTERM`, send `SIGKILL`,
//! then reap the child. The runner is target-agnostic so unit tests can model
//! unresponsive guests without spawning QEMU, while [`UnixQemuChildShutdownTarget`]
//! provides the production Unix process adapter.

use std::io::Write;
use std::process::Child;
use std::thread;
use std::time::Duration;

use crucible_protocol::{HostMsg, control_encode_host_msg, write_control_frame};
use thiserror::Error;

/// Ordered shutdown rungs for one QEMU child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuShutdownRung {
    /// Send `Quit` over the Crucible control socket.
    ControlQuit,
    /// Issue QMP `{ "execute": "quit" }`.
    QmpQuit,
    /// Send `SIGTERM` to the QEMU process.
    Sigterm,
    /// Send `SIGKILL` to the QEMU process.
    Sigkill,
    /// Reap the QEMU process.
    Reap,
}

/// Canonical graceful-shutdown escalation order.
pub const QEMU_SHUTDOWN_ESCALATION_ORDER: [QemuShutdownRung; 5] = [
    QemuShutdownRung::ControlQuit,
    QemuShutdownRung::QmpQuit,
    QemuShutdownRung::Sigterm,
    QemuShutdownRung::Sigkill,
    QemuShutdownRung::Reap,
];

/// Bounded waits used between shutdown rungs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuShutdownPolicy {
    /// Maximum wait after sending control-socket `Quit`.
    pub control_quit_wait: Duration,
    /// Maximum wait after issuing QMP `quit`.
    pub qmp_quit_wait: Duration,
    /// Maximum wait after sending `SIGTERM`.
    pub sigterm_wait: Duration,
    /// Maximum wait after sending `SIGKILL`.
    pub sigkill_wait: Duration,
    /// Maximum wait for the final reap.
    pub reap_wait: Duration,
}

impl QemuShutdownPolicy {
    /// Returns a policy suitable for unit tests and fast failure paths.
    #[must_use]
    pub const fn fast_test() -> Self {
        Self {
            control_quit_wait: Duration::from_millis(1),
            qmp_quit_wait: Duration::from_millis(1),
            sigterm_wait: Duration::from_millis(1),
            sigkill_wait: Duration::from_millis(1),
            reap_wait: Duration::from_millis(1),
        }
    }
}

/// Whether a child is still live after a bounded wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuChildWait {
    /// The child is still running after the wait deadline.
    StillRunning,
    /// The child exited and no live process remains.
    Exited,
}

/// Result of the final reap rung.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuReap {
    /// The child was reaped, or had already been reaped by an earlier wait.
    Reaped,
    /// The child still appears live after the reap deadline.
    StillAlive,
}

/// One rung recorded in a shutdown report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuShutdownAttempt {
    /// Rung that was executed.
    pub rung: QemuShutdownRung,
    /// Bounded wait associated with the rung.
    pub wait: Duration,
    /// Child state observed after the rung's wait.
    pub child: QemuChildWait,
}

/// A failed shutdown operation that did not stop escalation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuShutdownFailure {
    /// Rung that reported the failure.
    pub rung: QemuShutdownRung,
    /// Underlying target error.
    pub source: QemuShutdownTargetError,
}

/// Report produced by a completed shutdown escalation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuShutdownReport {
    /// Rungs that were attempted before the child was reaped.
    pub attempts: Vec<QemuShutdownAttempt>,
    /// Non-fatal rung failures encountered while escalating.
    pub failures: Vec<QemuShutdownFailure>,
    /// Whether the final reap rung completed.
    pub reaped: bool,
    /// Whether a live child remained after the final reap deadline.
    pub leaked: bool,
}

/// Error returned by a shutdown target operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{operation} failed: {message}")]
pub struct QemuShutdownTargetError {
    /// Operation being attempted.
    pub operation: &'static str,
    /// Human-readable failure detail.
    pub message: String,
}

impl QemuShutdownTargetError {
    /// Creates a target error from displayable context.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
        }
    }
}

/// Typed errors returned by the shutdown escalation runner.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuShutdownError {
    /// A target operation failed.
    #[error("shutdown rung {rung:?} failed")]
    Target {
        /// Rung that was executing.
        rung: QemuShutdownRung,
        /// Underlying target error.
        source: QemuShutdownTargetError,
    },
    /// The child remained live after `SIGKILL` and the reap deadline.
    #[error("QEMU child remained live after shutdown escalation")]
    LeakedChild {
        /// Report captured before returning the leak error.
        report: QemuShutdownReport,
    },
}

/// Target controlled by the QEMU shutdown escalation runner.
pub trait QemuShutdownTarget {
    /// Sends the Crucible control-socket `Quit` frame.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when the control socket cannot accept
    /// the shutdown frame.
    fn send_control_quit(&mut self) -> Result<(), QemuShutdownTargetError>;

    /// Issues QMP `{ "execute": "quit" }`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when the QMP command cannot be sent.
    fn send_qmp_quit(&mut self) -> Result<(), QemuShutdownTargetError>;

    /// Sends `SIGTERM` to the child.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when signal delivery fails.
    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError>;

    /// Sends `SIGKILL` to the child.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when signal delivery fails.
    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError>;

    /// Waits up to `timeout` for the child to exit.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when the child state cannot be
    /// queried.
    fn wait_for_exit(
        &mut self,
        rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError>;

    /// Reaps the child or confirms an earlier wait already reaped it.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when the child cannot be reaped or
    /// queried.
    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError>;
}

/// Runs the QEMU shutdown escalation ladder.
///
/// # Errors
///
/// Returns [`QemuShutdownError::Target`] when an underlying target operation
/// fails, or [`QemuShutdownError::LeakedChild`] if a live child remains after
/// `SIGKILL` and the final reap deadline.
pub fn shutdown_qemu_child<T>(
    target: &mut T,
    policy: QemuShutdownPolicy,
) -> Result<QemuShutdownReport, QemuShutdownError>
where
    T: QemuShutdownTarget,
{
    let mut report = QemuShutdownReport {
        attempts: Vec::new(),
        failures: Vec::new(),
        reaped: false,
        leaked: false,
    };

    for (rung, wait) in [
        (QemuShutdownRung::ControlQuit, policy.control_quit_wait),
        (QemuShutdownRung::QmpQuit, policy.qmp_quit_wait),
        (QemuShutdownRung::Sigterm, policy.sigterm_wait),
        (QemuShutdownRung::Sigkill, policy.sigkill_wait),
    ] {
        if let Err(source) = execute_shutdown_rung(target, rung) {
            report.failures.push(QemuShutdownFailure { rung, source });
            continue;
        }
        let child = match target.wait_for_exit(rung, wait) {
            Ok(child) => child,
            Err(source) => {
                report.failures.push(QemuShutdownFailure { rung, source });
                QemuChildWait::StillRunning
            }
        };
        report
            .attempts
            .push(QemuShutdownAttempt { rung, wait, child });
        if child == QemuChildWait::Exited {
            break;
        }
    }

    match target
        .reap(policy.reap_wait)
        .map_err(|source| QemuShutdownError::Target {
            rung: QemuShutdownRung::Reap,
            source,
        })? {
        QemuReap::Reaped => {
            report.reaped = true;
            Ok(report)
        }
        QemuReap::StillAlive => {
            report.leaked = true;
            Err(QemuShutdownError::LeakedChild { report })
        }
    }
}

/// Unix process adapter for the QEMU shutdown target.
#[derive(Debug)]
pub struct UnixQemuChildShutdownTarget<C, Q> {
    child: Child,
    control: C,
    qmp: Q,
    reaped: bool,
}

impl<C, Q> UnixQemuChildShutdownTarget<C, Q> {
    /// Creates a Unix shutdown target from a child and shutdown transports.
    ///
    /// `control_quit` sends the Crucible `Quit` frame. `qmp_quit` sends QMP
    /// `{ "execute": "quit" }`.
    #[must_use]
    pub const fn new(child: Child, control: C, qmp: Q) -> Self {
        Self {
            child,
            control,
            qmp,
            reaped: false,
        }
    }

    /// Returns whether this adapter has reaped the child.
    #[must_use]
    pub const fn reaped(&self) -> bool {
        self.reaped
    }
}

impl<C, Q> QemuShutdownTarget for UnixQemuChildShutdownTarget<C, Q>
where
    C: Write,
    Q: Write,
{
    fn send_control_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        send_control_quit_frame(&mut self.control)
    }

    fn send_qmp_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        send_qmp_quit_command(&mut self.qmp)
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        signal_child(self.child.id(), libc::SIGTERM, "send SIGTERM")
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        signal_child(self.child.id(), libc::SIGKILL, "send SIGKILL")
    }

    fn wait_for_exit(
        &mut self,
        _rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        let state = wait_child(&mut self.child, timeout)?;
        if state == QemuChildWait::Exited {
            self.reaped = true;
        }
        Ok(state)
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        if self.reaped {
            return Ok(QemuReap::Reaped);
        }

        match wait_child(&mut self.child, timeout)? {
            QemuChildWait::Exited => {
                self.reaped = true;
                Ok(QemuReap::Reaped)
            }
            QemuChildWait::StillRunning => Ok(QemuReap::StillAlive),
        }
    }
}

/// Writes the protocol `Quit` frame to a control stream.
///
/// # Errors
///
/// Returns [`QemuShutdownTargetError`] when the frame cannot be written or
/// flushed.
pub fn send_control_quit_frame<W>(writer: &mut W) -> Result<(), QemuShutdownTargetError>
where
    W: Write,
{
    let frame = control_encode_host_msg(&HostMsg::Quit);
    write_control_frame(writer, &frame)
        .map_err(|error| QemuShutdownTargetError::new("send control Quit", error.to_string()))
}

/// QMP command issued during graceful shutdown.
pub const QMP_QUIT_COMMAND: &[u8] = br#"{"execute":"quit"}"#;

/// Writes QMP `{ "execute": "quit" }` to a QMP stream.
///
/// # Errors
///
/// Returns [`QemuShutdownTargetError`] when the command cannot be written or
/// flushed.
pub fn send_qmp_quit_command<W>(writer: &mut W) -> Result<(), QemuShutdownTargetError>
where
    W: Write,
{
    writer
        .write_all(QMP_QUIT_COMMAND)
        .and_then(|()| writer.write_all(b"\r\n"))
        .and_then(|()| writer.flush())
        .map_err(|error| QemuShutdownTargetError::new("send QMP quit", error.to_string()))
}

fn execute_shutdown_rung<T>(
    target: &mut T,
    rung: QemuShutdownRung,
) -> Result<(), QemuShutdownTargetError>
where
    T: QemuShutdownTarget,
{
    match rung {
        QemuShutdownRung::ControlQuit => target.send_control_quit(),
        QemuShutdownRung::QmpQuit => target.send_qmp_quit(),
        QemuShutdownRung::Sigterm => target.send_sigterm(),
        QemuShutdownRung::Sigkill => target.send_sigkill(),
        QemuShutdownRung::Reap => Ok(()),
    }
}

pub(crate) fn wait_child(
    child: &mut Child,
    timeout: Duration,
) -> Result<QemuChildWait, QemuShutdownTargetError> {
    let step = Duration::from_millis(1);
    let mut waited = Duration::ZERO;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return Ok(QemuChildWait::Exited),
            Ok(None) if waited >= timeout => return Ok(QemuChildWait::StillRunning),
            Ok(None) => {
                thread::sleep(step);
                waited = waited.saturating_add(step);
            }
            Err(error) => {
                return Err(QemuShutdownTargetError::new(
                    "wait for QEMU child",
                    error.to_string(),
                ));
            }
        }
    }
}

pub(crate) fn signal_child(
    pid: u32,
    signal: libc::c_int,
    operation: &'static str,
) -> Result<(), QemuShutdownTargetError> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|error| QemuShutdownTargetError::new(operation, error.to_string()))?;
    // SAFETY: `pid` was range-checked into `pid_t`; `kill` reads no Rust
    // memory. Callers must authenticate external PIDs before using this helper.
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(QemuShutdownTargetError::new(
            operation,
            std::io::Error::last_os_error().to_string(),
        ))
    }
}
