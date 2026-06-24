//! Minimal typed QMP client.
//!
//! RFC-0010 QEMU-19 limits QMP use to capability negotiation, VM snapshot
//! save/load, snapshot job polling, and graceful quit. The client parses
//! JSON-line QMP responses internally, skips asynchronous event objects while
//! waiting for a command response, and exposes no public arbitrary-command
//! execution path.

use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::thread;
use std::time::Duration;

use crucible::{Checkpoint, ContentHash};
use serde_json::{Value, json};
use thiserror::Error;

use crate::QemuLoadvmCommandAuthorization;

/// QMP command name used for capability negotiation.
pub const QMP_CAPABILITIES_COMMAND: &str = "qmp_capabilities";
/// QMP command name used for saving the QEMU VMState half of a checkpoint.
pub const QMP_SNAPSHOT_SAVE_COMMAND: &str = "snapshot-save";
/// QMP command name used for loading the QEMU VMState half of a checkpoint.
pub const QMP_SNAPSHOT_LOAD_COMMAND: &str = "snapshot-load";
/// QMP command name used for polling snapshot job completion.
pub const QMP_QUERY_JOBS_COMMAND: &str = "query-jobs";
/// QMP command name used for graceful QEMU termination.
pub const QMP_QUIT_COMMAND_NAME: &str = "quit";
/// QMP snapshot device name used for diskless VMState snapshots.
pub const QMP_SNAPSHOT_VMSTATE_DEVICE: &str = "vmstate";
/// Default maximum number of `query-jobs` polls for a snapshot operation.
pub const QMP_JOB_QUERY_LIMIT: usize = 1200;
/// Default delay between `query-jobs` polls for a snapshot operation.
pub const QMP_JOB_QUERY_INTERVAL: Duration = Duration::from_millis(250);

/// Typed minimal QMP client over an established stream.
#[derive(Debug)]
pub struct QmpClient<S> {
    stream: BufReader<S>,
    greeting: QmpGreeting,
    job_poll_policy: QmpJobPollPolicy,
}

impl<S> QmpClient<S>
where
    S: Read + Write,
{
    /// Connects a client to an established QMP stream and negotiates capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the greeting cannot be read or decoded, when the
    /// greeting is not a QMP greeting, when the capabilities request cannot be
    /// written, or when QMP reports an error response.
    pub fn connect(stream: S) -> Result<Self, QmpError> {
        Self::connect_with_job_poll_policy(stream, QmpJobPollPolicy::default())
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
        let mut client = Self {
            stream: BufReader::new(stream),
            greeting: QmpGreeting {
                version_present: false,
                capabilities_present: false,
            },
            job_poll_policy,
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

    /// Returns the underlying stream, discarding any unread buffered bytes.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
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

    fn read_greeting(&mut self) -> Result<QmpGreeting, QmpError> {
        let response = self.read_json_line("read QMP greeting")?;
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
        self.write_json_line(kind.wire_name(), command.request())?;
        self.read_command_response(kind)
    }

    fn read_command_response(
        &mut self,
        command: QmpCommandKind,
    ) -> Result<QmpCommandReturn, QmpError> {
        loop {
            let response = self.read_json_line(command.wire_name())?;
            if response.get("event").is_some() {
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

    fn read_json_line(&mut self, operation: &'static str) -> Result<Value, QmpError> {
        let mut line = String::new();
        let read = self
            .stream
            .read_line(&mut line)
            .map_err(|error| QmpError::from_io(operation, error))?;
        if read == 0 {
            return Err(QmpError::Io {
                operation,
                kind: ErrorKind::UnexpectedEof,
            });
        }
        serde_json::from_str(&line).map_err(|error| QmpError::Json {
            operation,
            message: error.to_string(),
        })
    }

    fn write_json_line(&mut self, operation: &'static str, request: Value) -> Result<(), QmpError> {
        let line = serde_json::to_string(&request).map_err(|error| QmpError::Json {
            operation,
            message: error.to_string(),
        })?;
        self.stream
            .get_mut()
            .write_all(line.as_bytes())
            .map_err(|error| QmpError::from_io("write QMP request", error))?;
        self.stream
            .get_mut()
            .write_all(b"\r\n")
            .map_err(|error| QmpError::from_io("write QMP request newline", error))?;
        self.stream
            .get_mut()
            .flush()
            .map_err(|error| QmpError::from_io("flush QMP request", error))
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

/// Fields observed in the QMP greeting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpGreeting {
    /// Whether the greeting carried a `version` object.
    pub version_present: bool,
    /// Whether the greeting carried a `capabilities` array.
    pub capabilities_present: bool,
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
    /// Graceful QEMU quit.
    Quit,
}

impl QmpCommandKind {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Capabilities => QMP_CAPABILITIES_COMMAND,
            Self::SaveVm => QMP_SNAPSHOT_SAVE_COMMAND,
            Self::LoadVm => QMP_SNAPSHOT_LOAD_COMMAND,
            Self::QueryJobs => QMP_QUERY_JOBS_COMMAND,
            Self::Quit => QMP_QUIT_COMMAND_NAME,
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

/// QMP snapshot tag derived from a checkpoint content address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpSnapshotTag {
    tag: String,
}

impl QmpSnapshotTag {
    /// Derives a QMP-safe snapshot tag from a checkpoint handle.
    #[must_use]
    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        Self::from_checkpoint_content_address(checkpoint.id)
    }

    /// Derives a QMP-safe snapshot tag from a checkpoint content address.
    #[must_use]
    pub fn from_checkpoint_content_address(address: ContentHash) -> Self {
        Self {
            tag: format!("crucible-{}", lowercase_hex(&address.bytes)),
        }
    }

    /// Returns the QMP snapshot tag string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.tag
    }
}

/// Typed errors returned by the minimal QMP client.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QmpError {
    /// A QMP stream operation failed.
    #[error("{operation} failed with {kind:?}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Error kind returned by the stream.
        kind: ErrorKind,
    },
    /// A QMP JSON line could not be decoded or serialized.
    #[error("{operation} JSON failed: {message}")]
    Json {
        /// Operation being attempted.
        operation: &'static str,
        /// JSON error message.
        message: String,
    },
    /// The first QMP line was not a greeting.
    #[error("unexpected QMP greeting: {response}")]
    UnexpectedGreeting {
        /// JSON response that was not a valid greeting.
        response: String,
    },
    /// QMP returned an error object for a typed command.
    #[error("QMP command {command:?} failed: {class}: {description}")]
    Command {
        /// Command that failed.
        command: QmpCommandKind,
        /// QMP error class.
        class: String,
        /// QMP error description.
        description: String,
    },
    /// QMP returned a malformed `query-jobs` response.
    #[error("unexpected QMP job list for {command:?}: {response}")]
    UnexpectedJobList {
        /// Snapshot command awaiting a job result.
        command: QmpCommandKind,
        /// Unexpected `query-jobs` return value.
        response: String,
    },
    /// A QMP snapshot job reported an error.
    #[error("QMP job {job_id} for {command:?} failed: {detail}")]
    JobFailed {
        /// Snapshot command awaiting a job result.
        command: QmpCommandKind,
        /// QMP job id.
        job_id: String,
        /// QMP job error detail.
        detail: String,
    },
    /// A QMP snapshot job did not reach the concluded state.
    #[error("QMP job {job_id} for {command:?} did not conclude after {polls} polls")]
    JobNotConcluded {
        /// Snapshot command awaiting a job result.
        command: QmpCommandKind,
        /// QMP job id.
        job_id: String,
        /// Number of `query-jobs` polls attempted.
        polls: usize,
    },
    /// QMP returned neither an event, a return object, nor an error object.
    #[error("unexpected QMP response for {command:?}: {response}")]
    UnexpectedResponse {
        /// Command awaiting a response.
        command: QmpCommandKind,
        /// Unexpected JSON response.
        response: String,
    },
}

impl QmpError {
    fn from_io(operation: &'static str, error: io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }
}

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
    Quit,
}

impl QmpCommand<'_> {
    const fn kind(&self) -> QmpCommandKind {
        match self {
            Self::Capabilities => QmpCommandKind::Capabilities,
            Self::SaveVm { .. } => QmpCommandKind::SaveVm,
            Self::LoadVm { .. } => QmpCommandKind::LoadVm,
            Self::QueryJobs => QmpCommandKind::QueryJobs,
            Self::Quit => QmpCommandKind::Quit,
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
            Self::Quit => json!({
                "execute": QMP_QUIT_COMMAND_NAME,
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

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
}
