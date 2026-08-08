//! Minimal typed QMP client.
//!
//! RFC-0010 QEMU-19 limits QMP use to capability negotiation, typed VM
//! status/topology observation, VM snapshot save/load, snapshot job polling,
//! graceful quit, plus the legacy fixed debug-agent device-add sequence used by
//! focused compatibility tests. Production launches use the inert endpoint and
//! do not issue those device-add commands. The client parses
//! JSON-line QMP responses internally, skips asynchronous event objects while
//! waiting for a command response, and exposes no public arbitrary-command
//! execution path.

use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    QEMU_DEBUG_GUEST_ACTIVATION_CHARDEV_ID, QEMU_DEBUG_GUEST_ACTIVATION_PORT_NAME,
    QEMU_DEBUG_GUEST_VIRTIO_SERIAL_ID, QemuLoadvmCommandAuthorization, QemuNodeChannelError,
};

mod snapshot_tag;
#[cfg(target_os = "linux")]
mod unix_socket;
mod vmstate_control;

pub use snapshot_tag::QmpSnapshotTag;
pub use vmstate_control::QemuQmpVmStateControlChannel;

/// QMP command name used for capability negotiation.
pub const QMP_CAPABILITIES_COMMAND: &str = "qmp_capabilities";
/// QMP command name used for saving the QEMU VMState half of a checkpoint.
pub const QMP_SNAPSHOT_SAVE_COMMAND: &str = "snapshot-save";
/// QMP command name used for loading the QEMU VMState half of a checkpoint.
pub const QMP_SNAPSHOT_LOAD_COMMAND: &str = "snapshot-load";
/// QMP command name used for polling snapshot job completion.
pub const QMP_QUERY_JOBS_COMMAND: &str = "query-jobs";
/// QMP command name used for reading the VM run state.
pub const QMP_QUERY_STATUS_COMMAND: &str = "query-status";
/// QMP command name used for reading configured vCPU indexes.
pub const QMP_QUERY_CPUS_FAST_COMMAND: &str = "query-cpus-fast";
/// QMP command name used for graceful QEMU termination.
pub const QMP_QUIT_COMMAND_NAME: &str = "quit";
/// QMP command used to create the activation-only character backend.
pub const QMP_CHARDEV_ADD_COMMAND: &str = "chardev-add";
/// QMP command used to hot-add the activation-only controller and port.
pub const QMP_DEVICE_ADD_COMMAND: &str = "device_add";
/// Versioned token consumed by the dormant fixture-side debugger bootstrap.
pub const QMP_DEBUG_GUEST_ACTIVATION_TOKEN: &str = "CRUCIBLE_DEBUG_AGENT_V1\n";
/// QMP snapshot device name used for diskless VMState snapshots.
pub const QMP_SNAPSHOT_VMSTATE_DEVICE: &str = "vmstate";
/// Default maximum number of `query-jobs` polls for a snapshot operation.
pub const QMP_JOB_QUERY_LIMIT: usize = 1200;
/// Default delay between `query-jobs` polls for a snapshot operation.
pub const QMP_JOB_QUERY_INTERVAL: Duration = Duration::from_millis(250);
/// Default timeout for the initial QMP greeting.
pub const QMP_GREETING_TIMEOUT: Duration = Duration::from_secs(5);
/// Default timeout for one QMP command read or write.
pub const QMP_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// Default maximum bytes in one QMP JSON line.
pub const QMP_MAX_LINE_BYTES: usize = 1024 * 1024;
/// Default maximum asynchronous QMP event objects skipped while awaiting a command.
pub const QMP_MAX_ASYNC_EVENTS_PER_COMMAND: usize = 1024;

/// Stream contract required by the bounded QMP client.
pub trait QmpTimeoutStream: Read + Write + Send {
    /// Installs the read timeout used by the next QMP receive operation.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the stream cannot install the timeout.
    fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()>;

    /// Installs the write timeout used by the next QMP send operation.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the stream cannot install the timeout.
    fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()>;
}

impl QmpTimeoutStream for TcpStream {
    fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }

    fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }
}

#[cfg(unix)]
impl QmpTimeoutStream for UnixStream {
    fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }

    fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }
}

/// Typed minimal QMP client over an established stream.
#[derive(Debug)]
pub struct QmpClient<S> {
    stream: BufReader<S>,
    greeting: QmpGreeting,
    job_poll_policy: QmpJobPollPolicy,
    io_timeout_policy: QmpIoTimeoutPolicy,
    debug_guest_activation_stage: DebugGuestActivationStage,
    predeclared_debug_guest_endpoint: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum DebugGuestActivationStage {
    #[default]
    NotStarted,
    ChardevAdded,
    ControllerAdded,
    PortAdded,
}

impl<S> QmpClient<S>
where
    S: QmpTimeoutStream,
{
    /// Connects a client to an established QMP stream and negotiates capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the greeting cannot be read or decoded, when the
    /// greeting is not a QMP greeting, when the capabilities request cannot be
    /// written, or when QMP reports an error response.
    pub fn connect(stream: S) -> Result<Self, QmpError> {
        Self::connect_with_policies(
            stream,
            QmpJobPollPolicy::default(),
            QmpIoTimeoutPolicy::default(),
        )
    }

    /// Connects a client with an explicit snapshot-job polling policy.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the greeting cannot be read or decoded, when the
    /// greeting is not a QMP greeting, when the capabilities request cannot be
    /// written, or when QMP reports an error response.
    pub fn connect_with_job_poll_policy(
        stream: S,
        job_poll_policy: QmpJobPollPolicy,
    ) -> Result<Self, QmpError> {
        Self::connect_with_policies(stream, job_poll_policy, QmpIoTimeoutPolicy::default())
    }

    /// Connects a client with explicit snapshot-job and stream timeout policies.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when either timeout is zero, when the greeting cannot
    /// be read or decoded, when the greeting is not a QMP greeting, when the
    /// capabilities request cannot be written, or when QMP reports an error
    /// response.
    pub fn connect_with_policies(
        stream: S,
        job_poll_policy: QmpJobPollPolicy,
        io_timeout_policy: QmpIoTimeoutPolicy,
    ) -> Result<Self, QmpError> {
        io_timeout_policy.validate()?;
        let mut client = Self {
            stream: BufReader::new(stream),
            greeting: QmpGreeting {
                version_present: false,
                capabilities_present: false,
            },
            job_poll_policy,
            io_timeout_policy,
            debug_guest_activation_stage: DebugGuestActivationStage::NotStarted,
            predeclared_debug_guest_endpoint: false,
        };
        client.greeting = client.read_greeting()?;
        client.send_command(QmpCommand::Capabilities)?;
        Ok(client)
    }

    /// Returns the QMP greeting fields observed during connection setup.
    #[must_use]
    pub const fn greeting(&self) -> QmpGreeting {
        self.greeting
    }

    /// Returns a client whose launch already contains the fixed inert endpoint.
    #[must_use]
    pub const fn with_predeclared_debug_guest_endpoint(mut self) -> Self {
        self.predeclared_debug_guest_endpoint = true;
        self
    }

    /// Saves the VMState snapshot under a tag derived from a checkpoint address.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request cannot be written, when the response
    /// cannot be read or decoded, when QMP returns an error response, or when
    /// the snapshot job reports failure or does not conclude within
    /// [`QMP_JOB_QUERY_LIMIT`] polls.
    pub fn savevm(&mut self, tag: &QmpSnapshotTag) -> Result<QmpCommandComplete, QmpError> {
        let job_id = snapshot_job_id("save", tag);
        self.send_command(QmpCommand::SaveVm {
            tag,
            job_id: &job_id,
        })?;
        self.wait_for_job(QmpCommandKind::SaveVm, &job_id)
    }

    /// Loads the VMState snapshot named by a checkpoint-derived tag.
    ///
    /// This only performs the low-level QMP command. Runtime admission remains a
    /// separate replay-oracle-validated policy decision.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request cannot be written, when the response
    /// cannot be read or decoded, when QMP returns an error response, or when
    /// the snapshot job reports failure or does not conclude within
    /// [`QMP_JOB_QUERY_LIMIT`] polls.
    pub fn loadvm(
        &mut self,
        tag: &QmpSnapshotTag,
        _authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<QmpCommandComplete, QmpError> {
        let job_id = snapshot_job_id("load", tag);
        self.send_command(QmpCommand::LoadVm {
            tag,
            job_id: &job_id,
        })?;
        self.wait_for_job(QmpCommandKind::LoadVm, &job_id)
    }

    /// Requests graceful QEMU termination over QMP.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request cannot be written, when the response
    /// cannot be read or decoded, or when QMP returns an error response.
    pub fn quit(&mut self) -> Result<QmpCommandComplete, QmpError> {
        self.send_command(QmpCommand::Quit)
    }

    /// Prepares the fixed guest-introspection activation channel.
    ///
    /// Production launches return immediately because their inert endpoint is
    /// already present. The compatibility command surface is deliberately fixed:
    /// callers cannot select an arbitrary device, chardev, or guest-visible bytes.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request cannot be written, when the
    /// response cannot be decoded, or when QEMU rejects the configured socket
    /// chardev, controller, or port.
    pub fn prepare_debug_guest(&mut self) -> Result<QmpCommandComplete, QmpError> {
        if self.predeclared_debug_guest_endpoint {
            return Ok(QmpCommandComplete {
                command: QmpCommandKind::AddDebugGuestPort,
            });
        }
        if self.debug_guest_activation_stage < DebugGuestActivationStage::ChardevAdded {
            self.send_command(QmpCommand::AddDebugGuestChardev)?;
            self.debug_guest_activation_stage = DebugGuestActivationStage::ChardevAdded;
        }
        if self.debug_guest_activation_stage < DebugGuestActivationStage::ControllerAdded
            && !self.predeclared_debug_guest_endpoint
        {
            self.send_command(QmpCommand::AddDebugGuestController)?;
        }
        self.debug_guest_activation_stage = DebugGuestActivationStage::ControllerAdded;
        if self.debug_guest_activation_stage < DebugGuestActivationStage::PortAdded {
            self.send_command(QmpCommand::AddDebugGuestPort)?;
            self.debug_guest_activation_stage = DebugGuestActivationStage::PortAdded;
        }
        Ok(QmpCommandComplete {
            command: QmpCommandKind::AddDebugGuestPort,
        })
    }

    /// Returns the current VM run state.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, when QEMU omits
    /// a required field, reports an unknown QEMU 10.0 run state, or contradicts
    /// the typed relationship between `running` and `status`.
    pub fn query_status(&mut self) -> Result<QmpRunState, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryStatus)?;
        let running = response.value.get("running").and_then(Value::as_bool);
        let status = response
            .value
            .get("status")
            .and_then(Value::as_str)
            .and_then(QmpRunStateKind::from_wire);
        match (running, status) {
            (Some(running), Some(status)) if running == (status == QmpRunStateKind::Running) => {
                Ok(QmpRunState { running, status })
            }
            _ => Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryStatus,
                response: response.value.to_string(),
            }),
        }
    }

    /// Returns the exact sorted set of configured vCPU indexes.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, when QEMU does
    /// not return an array, or when a CPU index is missing, negative, duplicate,
    /// outside the unsigned 64-bit range, nonzero-start, or noncontiguous.
    pub fn query_cpus_fast(&mut self) -> Result<QmpCpuTopology, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryCpusFast)?;
        let Some(cpus) = response.value.as_array() else {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryCpusFast,
                response: response.value.to_string(),
            });
        };
        let mut cpu_indexes = cpus
            .iter()
            .map(|cpu| cpu.get("cpu-index").and_then(Value::as_u64))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryCpusFast,
                response: response.value.to_string(),
            })?;
        cpu_indexes.sort_unstable();
        if cpu_indexes.is_empty()
            || cpu_indexes
                .iter()
                .enumerate()
                .any(|(expected, actual)| *actual != expected as u64)
        {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryCpusFast,
                response: response.value.to_string(),
            });
        }
        Ok(QmpCpuTopology { cpu_indexes })
    }

    fn read_greeting(&mut self) -> Result<QmpGreeting, QmpError> {
        let deadline = QmpOperationDeadline::new(self.io_timeout_policy.greeting_timeout);
        let response = self.read_json_line("read QMP greeting", &deadline)?;
        let Some(qmp) = response.get("QMP") else {
            return Err(QmpError::UnexpectedGreeting {
                response: response.to_string(),
            });
        };
        let Some(qmp) = qmp.as_object() else {
            return Err(QmpError::UnexpectedGreeting {
                response: response.to_string(),
            });
        };

        let greeting = QmpGreeting {
            version_present: qmp.contains_key("version"),
            capabilities_present: qmp.contains_key("capabilities"),
        };
        if !greeting.version_present || !greeting.capabilities_present {
            return Err(QmpError::UnexpectedGreeting {
                response: response.to_string(),
            });
        }

        Ok(greeting)
    }

    fn send_command(&mut self, command: QmpCommand<'_>) -> Result<QmpCommandComplete, QmpError> {
        let command = self.send_command_return(command)?;
        Ok(QmpCommandComplete {
            command: command.command,
        })
    }

    fn send_command_return(
        &mut self,
        command: QmpCommand<'_>,
    ) -> Result<QmpCommandReturn, QmpError> {
        let kind = command.kind();
        let deadline = QmpOperationDeadline::new(self.io_timeout_policy.command_timeout);
        self.write_json_line(kind.wire_name(), command.request(), &deadline)?;
        self.read_command_response(kind, &deadline)
    }

    fn read_command_response(
        &mut self,
        command: QmpCommandKind,
        deadline: &QmpOperationDeadline,
    ) -> Result<QmpCommandReturn, QmpError> {
        let mut skipped_events = 0usize;
        loop {
            let response = self.read_json_line(command.wire_name(), deadline)?;
            if response.get("event").is_some() {
                skipped_events = skipped_events.saturating_add(1);
                if skipped_events > self.io_timeout_policy.max_async_events_per_command {
                    return Err(QmpError::AsyncEventLimitExceeded {
                        command,
                        limit: self.io_timeout_policy.max_async_events_per_command,
                    });
                }
                continue;
            }
            if let Some(value) = response.get("return") {
                return Ok(QmpCommandReturn {
                    command,
                    value: value.clone(),
                });
            }
            if let Some(error) = response.get("error") {
                return Err(command_error(command, error));
            }
            return Err(QmpError::UnexpectedResponse {
                command,
                response: response.to_string(),
            });
        }
    }

    fn wait_for_job(
        &mut self,
        command: QmpCommandKind,
        job_id: &str,
    ) -> Result<QmpCommandComplete, QmpError> {
        for attempt in 0..self.job_poll_policy.max_polls {
            let jobs = self.send_command_return(QmpCommand::QueryJobs)?;
            let Some(jobs) = jobs.value.as_array() else {
                return Err(QmpError::UnexpectedJobList {
                    command,
                    response: jobs.value.to_string(),
                });
            };
            for job in jobs {
                if job.get("id").and_then(Value::as_str) != Some(job_id) {
                    continue;
                }
                if let Some(error) = job.get("error") {
                    return Err(QmpError::JobFailed {
                        command,
                        job_id: job_id.to_owned(),
                        detail: error.to_string(),
                    });
                }
                if job.get("status").and_then(Value::as_str) == Some("concluded") {
                    return Ok(QmpCommandComplete { command });
                }
            }

            if attempt + 1 < self.job_poll_policy.max_polls {
                thread::sleep(self.job_poll_policy.poll_interval);
            }
        }

        Err(QmpError::JobNotConcluded {
            command,
            job_id: job_id.to_owned(),
            polls: self.job_poll_policy.max_polls,
        })
    }

    fn read_json_line(
        &mut self,
        operation: &'static str,
        deadline: &QmpOperationDeadline,
    ) -> Result<Value, QmpError> {
        let mut line = Vec::new();
        loop {
            if line.len() == self.io_timeout_policy.max_line_bytes {
                return Err(QmpError::LineTooLong {
                    operation,
                    max_bytes: self.io_timeout_policy.max_line_bytes,
                });
            }
            let remaining = deadline.remaining(operation)?;
            self.stream
                .get_mut()
                .set_qmp_read_timeout(remaining)
                .map_err(|error| QmpError::from_io("set QMP read timeout", error))?;
            let mut byte = [0u8; 1];
            let read = self.stream.read(&mut byte).map_err(|error| {
                QmpError::from_io_with_timeout(operation, deadline.timeout, error)
            })?;
            if read == 0 {
                return Err(QmpError::Io {
                    operation,
                    kind: ErrorKind::UnexpectedEof,
                });
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        serde_json::from_slice(&line).map_err(|error| QmpError::Json {
            operation,
            message: error.to_string(),
        })
    }

    fn write_json_line(
        &mut self,
        operation: &'static str,
        request: Value,
        deadline: &QmpOperationDeadline,
    ) -> Result<(), QmpError> {
        let mut line = serde_json::to_vec(&request).map_err(|error| QmpError::Json {
            operation,
            message: error.to_string(),
        })?;
        line.extend_from_slice(b"\r\n");
        let mut written = 0usize;
        while written < line.len() {
            let remaining = deadline.remaining(operation)?;
            self.stream
                .get_mut()
                .set_qmp_write_timeout(remaining)
                .map_err(|error| QmpError::from_io("set QMP write timeout", error))?;
            let count = self
                .stream
                .get_mut()
                .write(&line[written..])
                .map_err(|error| {
                    QmpError::from_io_with_timeout("write QMP request", deadline.timeout, error)
                })?;
            if count == 0 {
                return Err(QmpError::Io {
                    operation: "write QMP request",
                    kind: ErrorKind::WriteZero,
                });
            }
            written = written.saturating_add(count);
        }
        self.stream.get_mut().flush().map_err(|error| {
            QmpError::from_io_with_timeout("flush QMP request", deadline.timeout, error)
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct QmpOperationDeadline {
    started_at: Instant,
    timeout: Duration,
}

impl QmpOperationDeadline {
    // crucible-lint: allow clippy-disallowed-method -- QMP host deadlines bound child I/O only.
    #[allow(clippy::disallowed_methods)]
    fn new(timeout: Duration) -> Self {
        // QMP lifecycle I/O uses host realtime only to bound child liveness; the
        // resulting timestamp is never folded into virtual-time ordering state.
        Self {
            started_at: Instant::now(),
            timeout,
        }
    }

    // crucible-lint: allow clippy-disallowed-method -- elapsed host time only gates QMP timeout reporting.
    #[allow(clippy::disallowed_methods)]
    fn remaining(&self, operation: &'static str) -> Result<Duration, QmpError> {
        // See `new`: this deadline gates a host control-plane wait, not guest
        // ordering or replay-visible state.
        let elapsed = self.started_at.elapsed();
        let Some(remaining) = self.timeout.checked_sub(elapsed) else {
            return Err(QmpError::Timeout {
                operation,
                timeout: self.timeout,
            });
        };
        if remaining.is_zero() {
            Err(QmpError::Timeout {
                operation,
                timeout: self.timeout,
            })
        } else {
            Ok(remaining)
        }
    }
}

/// Polling policy for QMP snapshot jobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpJobPollPolicy {
    /// Maximum number of `query-jobs` polls before reporting a non-concluded job.
    pub max_polls: usize,
    /// Delay between polls.
    pub poll_interval: Duration,
}

impl QmpJobPollPolicy {
    /// Returns a zero-delay policy for deterministic unit tests.
    #[must_use]
    pub const fn fast_test(max_polls: usize) -> Self {
        Self {
            max_polls,
            poll_interval: Duration::ZERO,
        }
    }
}

impl Default for QmpJobPollPolicy {
    fn default() -> Self {
        Self {
            max_polls: QMP_JOB_QUERY_LIMIT,
            poll_interval: QMP_JOB_QUERY_INTERVAL,
        }
    }
}

/// Timeout policy for blocking QMP stream operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpIoTimeoutPolicy {
    /// Timeout for the initial QMP greeting read.
    pub greeting_timeout: Duration,
    /// Timeout for each command write and response read.
    pub command_timeout: Duration,
    /// Maximum bytes accepted before a QMP newline.
    pub max_line_bytes: usize,
    /// Maximum asynchronous event objects skipped while awaiting one command.
    pub max_async_events_per_command: usize,
}

impl QmpIoTimeoutPolicy {
    /// Builds a QMP I/O timeout policy from explicit budgets.
    #[must_use]
    pub const fn new(greeting_timeout: Duration, command_timeout: Duration) -> Self {
        Self {
            greeting_timeout,
            command_timeout,
            max_line_bytes: QMP_MAX_LINE_BYTES,
            max_async_events_per_command: QMP_MAX_ASYNC_EVENTS_PER_COMMAND,
        }
    }

    /// Uses one QMP command budget for both greeting and command I/O.
    #[must_use]
    pub const fn from_command_timeout(command_timeout: Duration) -> Self {
        Self::new(command_timeout, command_timeout)
    }

    /// Returns this policy with a custom QMP line-size bound.
    #[must_use]
    pub const fn with_max_line_bytes(mut self, max_line_bytes: usize) -> Self {
        self.max_line_bytes = max_line_bytes;
        self
    }

    /// Returns this policy with a custom asynchronous event bound.
    #[must_use]
    pub const fn with_max_async_events_per_command(
        mut self,
        max_async_events_per_command: usize,
    ) -> Self {
        self.max_async_events_per_command = max_async_events_per_command;
        self
    }

    /// Validates that all QMP stream operations have nonzero timeouts.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::UnboundedTimeout`] when either timeout is zero.
    pub fn validate(self) -> Result<(), QmpError> {
        if self.greeting_timeout.is_zero() {
            return Err(QmpError::UnboundedTimeout {
                operation: "read QMP greeting",
            });
        }
        if self.command_timeout.is_zero() {
            return Err(QmpError::UnboundedTimeout {
                operation: "QMP command",
            });
        }
        if self.max_line_bytes == 0 {
            return Err(QmpError::InvalidBound {
                operation: "QMP line bytes",
            });
        }
        if self.max_async_events_per_command == 0 {
            return Err(QmpError::InvalidBound {
                operation: "QMP async events",
            });
        }
        Ok(())
    }
}

impl Default for QmpIoTimeoutPolicy {
    fn default() -> Self {
        Self {
            greeting_timeout: QMP_GREETING_TIMEOUT,
            command_timeout: QMP_COMMAND_TIMEOUT,
            max_line_bytes: QMP_MAX_LINE_BYTES,
            max_async_events_per_command: QMP_MAX_ASYNC_EVENTS_PER_COMMAND,
        }
    }
}

/// Fields observed in the QMP greeting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpGreeting {
    /// Whether the greeting carried a `version` object.
    pub version_present: bool,
    /// Whether the greeting carried a `capabilities` array.
    pub capabilities_present: bool,
}

/// Current VM run state returned by typed `query-status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpRunState {
    /// Whether the VM is in QEMU's running state.
    pub running: bool,
    /// Exact typed QEMU run state.
    pub status: QmpRunStateKind,
}

/// QEMU 10.0 run-state values admitted by typed `query-status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpRunStateKind {
    /// Execution stopped for debugger control.
    Debug,
    /// Execution stopped to finish migration.
    FinishMigrate,
    /// Waiting for incoming migration.
    InMigrate,
    /// Execution stopped by an internal error.
    InternalError,
    /// Execution stopped by a configured I/O error action.
    IoError,
    /// Execution explicitly paused.
    Paused,
    /// Execution stopped after migration.
    PostMigrate,
    /// VM started with `-S` and has not executed.
    Prelaunch,
    /// Restoring VM state.
    RestoreVm,
    /// Guest execution is running.
    Running,
    /// Saving VM state.
    SaveVm,
    /// Guest shut down under `-no-shutdown`.
    Shutdown,
    /// Guest entered hardware suspend.
    Suspended,
    /// Watchdog action paused execution.
    Watchdog,
    /// Guest panic paused execution.
    GuestPanicked,
    /// COLO checkpoint save or restore state.
    Colo,
}

impl QmpRunStateKind {
    fn from_wire(value: &str) -> Option<Self> {
        Some(match value {
            "debug" => Self::Debug,
            "finish-migrate" => Self::FinishMigrate,
            "inmigrate" => Self::InMigrate,
            "internal-error" => Self::InternalError,
            "io-error" => Self::IoError,
            "paused" => Self::Paused,
            "postmigrate" => Self::PostMigrate,
            "prelaunch" => Self::Prelaunch,
            "restore-vm" => Self::RestoreVm,
            "running" => Self::Running,
            "save-vm" => Self::SaveVm,
            "shutdown" => Self::Shutdown,
            "suspended" => Self::Suspended,
            "watchdog" => Self::Watchdog,
            "guest-panicked" => Self::GuestPanicked,
            "colo" => Self::Colo,
            _ => return None,
        })
    }
}

/// Exact contiguous `0..N` vCPU indexes returned by typed `query-cpus-fast`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpCpuTopology {
    cpu_indexes: Vec<u64>,
}

impl QmpCpuTopology {
    /// Returns the sorted configured vCPU indexes, exactly contiguous from zero.
    #[must_use]
    pub fn cpu_indexes(&self) -> &[u64] {
        &self.cpu_indexes
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn from_test_cpu_indexes(cpu_indexes: Vec<u64>) -> Self {
        Self { cpu_indexes }
    }
}

/// Supported QMP command kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpCommandKind {
    /// QMP capability negotiation.
    Capabilities,
    /// VMState snapshot save.
    SaveVm,
    /// VMState snapshot load.
    LoadVm,
    /// Snapshot job status query.
    QueryJobs,
    /// VM run-state query.
    QueryStatus,
    /// Configured vCPU topology query.
    QueryCpusFast,
    /// Graceful QEMU quit.
    Quit,
    /// Activation-only chardev hot-add.
    AddDebugGuestChardev,
    /// Activation-only virtio-serial controller hot-add.
    AddDebugGuestController,
    /// Activation-only virtio-serial port hot-add.
    AddDebugGuestPort,
}

impl QmpCommandKind {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Capabilities => QMP_CAPABILITIES_COMMAND,
            Self::SaveVm => QMP_SNAPSHOT_SAVE_COMMAND,
            Self::LoadVm => QMP_SNAPSHOT_LOAD_COMMAND,
            Self::QueryJobs => QMP_QUERY_JOBS_COMMAND,
            Self::QueryStatus => QMP_QUERY_STATUS_COMMAND,
            Self::QueryCpusFast => QMP_QUERY_CPUS_FAST_COMMAND,
            Self::Quit => QMP_QUIT_COMMAND_NAME,
            Self::AddDebugGuestChardev => QMP_CHARDEV_ADD_COMMAND,
            Self::AddDebugGuestController | Self::AddDebugGuestPort => QMP_DEVICE_ADD_COMMAND,
        }
    }
}

/// Successful response for a typed QMP command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpCommandComplete {
    /// Command that completed successfully.
    pub command: QmpCommandKind,
}

#[derive(Clone, Debug, PartialEq)]
struct QmpCommandReturn {
    command: QmpCommandKind,
    value: Value,
}

#[path = "qmp/error.rs"]
mod error;

pub use error::QmpError;

enum QmpCommand<'a> {
    Capabilities,
    SaveVm {
        tag: &'a QmpSnapshotTag,
        job_id: &'a str,
    },
    LoadVm {
        tag: &'a QmpSnapshotTag,
        job_id: &'a str,
    },
    QueryJobs,
    QueryStatus,
    QueryCpusFast,
    Quit,
    AddDebugGuestChardev,
    AddDebugGuestController,
    AddDebugGuestPort,
}

impl QmpCommand<'_> {
    const fn kind(&self) -> QmpCommandKind {
        match self {
            Self::Capabilities => QmpCommandKind::Capabilities,
            Self::SaveVm { .. } => QmpCommandKind::SaveVm,
            Self::LoadVm { .. } => QmpCommandKind::LoadVm,
            Self::QueryJobs => QmpCommandKind::QueryJobs,
            Self::QueryStatus => QmpCommandKind::QueryStatus,
            Self::QueryCpusFast => QmpCommandKind::QueryCpusFast,
            Self::Quit => QmpCommandKind::Quit,
            Self::AddDebugGuestChardev => QmpCommandKind::AddDebugGuestChardev,
            Self::AddDebugGuestController => QmpCommandKind::AddDebugGuestController,
            Self::AddDebugGuestPort => QmpCommandKind::AddDebugGuestPort,
        }
    }

    fn request(&self) -> Value {
        match self {
            Self::Capabilities => json!({
                "execute": QMP_CAPABILITIES_COMMAND,
            }),
            Self::SaveVm { tag, job_id } => {
                snapshot_request(QMP_SNAPSHOT_SAVE_COMMAND, job_id, tag)
            }
            Self::LoadVm { tag, job_id } => {
                snapshot_request(QMP_SNAPSHOT_LOAD_COMMAND, job_id, tag)
            }
            Self::QueryJobs => json!({
                "execute": QMP_QUERY_JOBS_COMMAND,
            }),
            Self::QueryStatus => json!({
                "execute": QMP_QUERY_STATUS_COMMAND,
            }),
            Self::QueryCpusFast => json!({
                "execute": QMP_QUERY_CPUS_FAST_COMMAND,
            }),
            Self::Quit => json!({
                "execute": QMP_QUIT_COMMAND_NAME,
            }),
            Self::AddDebugGuestChardev => json!({
                "execute": QMP_CHARDEV_ADD_COMMAND,
                "arguments": {
                    "id": QEMU_DEBUG_GUEST_ACTIVATION_CHARDEV_ID,
                    "backend": {
                        "type": "socket",
                        "data": {
                            "addr": {
                                "type": "unix",
                                "data": { "path": crate::QEMU_DEBUG_GUEST_ACTIVATION_SOCKET_FILE_NAME },
                            },
                            "server": true,
                            "wait": false,
                        },
                    },
                },
            }),
            Self::AddDebugGuestController => json!({
                "execute": QMP_DEVICE_ADD_COMMAND,
                "arguments": {
                    "driver": "virtio-serial-pci",
                    "id": QEMU_DEBUG_GUEST_VIRTIO_SERIAL_ID,
                    "bus": "pcie.0",
                },
            }),
            Self::AddDebugGuestPort => json!({
                "execute": QMP_DEVICE_ADD_COMMAND,
                "arguments": {
                    "driver": "virtserialport",
                    "id": QEMU_DEBUG_GUEST_ACTIVATION_CHARDEV_ID,
                    "chardev": QEMU_DEBUG_GUEST_ACTIVATION_CHARDEV_ID,
                    "name": QEMU_DEBUG_GUEST_ACTIVATION_PORT_NAME,
                    "bus": format!("{QEMU_DEBUG_GUEST_VIRTIO_SERIAL_ID}.0"),
                },
            }),
        }
    }
}

fn snapshot_request(command: &'static str, job_id: &str, tag: &QmpSnapshotTag) -> Value {
    json!({
        "execute": command,
        "arguments": {
            "job-id": job_id,
            "tag": tag.as_str(),
            "vmstate": QMP_SNAPSHOT_VMSTATE_DEVICE,
            "devices": [QMP_SNAPSHOT_VMSTATE_DEVICE],
        },
    })
}

fn snapshot_job_id(job_action: &'static str, tag: &QmpSnapshotTag) -> String {
    format!("crucible-{job_action}-{}", tag.as_str())
}

fn command_error(command: QmpCommandKind, error: &Value) -> QmpError {
    let class = error
        .get("class")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_owned();
    let description = error
        .get("desc")
        .and_then(Value::as_str)
        .unwrap_or("QMP command failed")
        .to_owned();
    QmpError::Command {
        command,
        class,
        description,
    }
}
