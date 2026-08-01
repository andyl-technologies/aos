//! Unix-domain socket connection helpers for typed QMP clients.

use std::os::unix::net::UnixStream;
use std::path::Path;

use super::{QmpClient, QmpError, QmpIoTimeoutPolicy, QmpJobPollPolicy};
use crate::QemuQmpVmStateControlChannel;

impl QmpClient<UnixStream> {
    /// Connects to a QMP Unix socket and negotiates capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the Unix socket cannot be opened, when the QMP
    /// greeting cannot be read or decoded, or when capability negotiation fails.
    pub fn connect_unix_socket(path: impl AsRef<Path>) -> Result<Self, QmpError> {
        let stream = UnixStream::connect(path)
            .map_err(|source| QmpError::from_io("connect QMP Unix socket", source))?;
        Self::connect(stream)
    }

    /// Connects to a QMP Unix socket with explicit snapshot and I/O policies.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the Unix socket cannot be opened, when the QMP
    /// greeting cannot be read or decoded, when capability negotiation fails, or
    /// when either supplied policy is invalid.
    pub fn connect_unix_socket_with_policies(
        path: impl AsRef<Path>,
        job_poll_policy: QmpJobPollPolicy,
        io_timeout_policy: QmpIoTimeoutPolicy,
    ) -> Result<Self, QmpError> {
        let stream = UnixStream::connect(path)
            .map_err(|source| QmpError::from_io("connect QMP Unix socket", source))?;
        Self::connect_with_policies(stream, job_poll_policy, io_timeout_policy)
    }
}

impl QemuQmpVmStateControlChannel<UnixStream> {
    /// Connects a checkpoint-tagged VMState control channel to a QMP Unix socket.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the Unix socket cannot be opened or QMP
    /// connection setup fails.
    pub fn connect_unix_socket(path: impl AsRef<Path>) -> Result<Self, QmpError> {
        QmpClient::connect_unix_socket(path).map(Self::new)
    }

    /// Connects a VMState control channel with explicit snapshot and I/O policies.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the Unix socket cannot be opened, QMP connection
    /// setup fails, or either supplied policy is invalid.
    pub fn connect_unix_socket_with_policies(
        path: impl AsRef<Path>,
        job_poll_policy: QmpJobPollPolicy,
        io_timeout_policy: QmpIoTimeoutPolicy,
    ) -> Result<Self, QmpError> {
        QmpClient::connect_unix_socket_with_policies(path, job_poll_policy, io_timeout_policy)
            .map(Self::new)
    }
}
