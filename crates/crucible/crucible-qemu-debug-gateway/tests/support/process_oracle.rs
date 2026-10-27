//! SPDX-License-Identifier: GPL-2.0-only
//! Calls the real Apache gateway client across a private, versioned Unix socket.
//!
//! The separately built oracle owns the gateway. Only permissive protocol bytes
//! cross this boundary; no Apache host library is linked into this test process.

use std::env;
use std::ffi::OsString;
use std::io;
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use crucible_qemu_protocol::debug_gateway::DebugGatewayBackendStatus;
use crucible_qemu_protocol::test_oracle::{Frame, FrameKind, Operation, read_frame, write_frame};

pub(super) struct DebugGatewayProcess {
    stream: UnixStream,
    oracle: Child,
    control_socket: PathBuf,
    operator_endpoint: Option<String>,
    next_request: u64,
}

impl DebugGatewayProcess {
    pub(super) fn launch(executable: &Path) -> io::Result<Self> {
        Self::launch_oracle(executable, false)
    }

    pub(super) fn launch_with_owner_unix(executable: &Path) -> io::Result<Self> {
        Self::launch_oracle(executable, true)
    }

    fn launch_oracle(executable: &Path, owner_unix: bool) -> io::Result<Self> {
        let executable = std::fs::canonicalize(executable)?;
        let helper = env::var_os("CRUCIBLE_QEMU_TEST_ORACLE").ok_or_else(|| {
            invalid("CRUCIBLE_QEMU_TEST_ORACLE must name the built Apache helper")
        })?;
        let (stream, child_stream) = UnixStream::pair()?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let mut command = Command::new(helper);
        command.arg(executable);
        command.stdin(Stdio::from(OwnedFd::from(child_stream)));
        if owner_unix {
            command.arg("--owner-unix");
        }
        let oracle = command.spawn()?;
        let mut process = Self {
            stream,
            oracle,
            control_socket: PathBuf::new(),
            operator_endpoint: None,
            next_request: 1,
        };
        let announcement = process.response(Operation::Ready, 0)?;
        let separator = announcement
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| invalid("oracle announcement has no path separator"))?;
        process.control_socket =
            PathBuf::from(OsString::from_vec(announcement[..separator].to_vec()));
        if !process.control_socket.is_absolute() {
            return Err(invalid("oracle control socket must be absolute"));
        }
        let endpoint = &announcement[separator + 1..];
        if !endpoint.is_empty() {
            process.operator_endpoint = Some(
                String::from_utf8(endpoint.to_vec())
                    .map_err(|_| invalid("oracle endpoint is not UTF-8"))?,
            );
        }
        Ok(process)
    }

    pub(super) fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    pub(super) fn operator_endpoint(&self) -> Option<&str> {
        self.operator_endpoint.as_deref()
    }

    pub(super) fn client_mut(&mut self) -> &mut Self {
        self
    }

    pub(super) fn backend_status(&mut self) -> io::Result<DebugGatewayBackendStatus> {
        let payload = self.request(Operation::BackendStatus, Vec::new())?;
        DebugGatewayBackendStatus::decode(&payload).map_err(|error| invalid(error.to_string()))
    }

    pub(super) fn reconnect_control(&mut self) -> io::Result<()> {
        let payload = self.request(Operation::Reconnect, Vec::new())?;
        if !payload.is_empty() {
            return Err(invalid("reconnect response must be empty"));
        }
        Ok(())
    }

    pub(super) fn promote_backend(&mut self, path: &Path) -> io::Result<u64> {
        let payload = self.request(
            Operation::PromoteBackend,
            path.as_os_str().as_bytes().to_vec(),
        )?;
        let bytes = payload
            .try_into()
            .map_err(|_| invalid("generation response must contain eight bytes"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub(super) fn shutdown(mut self) -> io::Result<ExitStatus> {
        let payload = self.request(Operation::Shutdown, Vec::new())?;
        let bytes = payload
            .try_into()
            .map_err(|_| invalid("exit response must contain four bytes"))?;
        self.stream.shutdown(Shutdown::Both)?;
        let helper_status = self.oracle.wait()?;
        if !helper_status.success() {
            return Err(invalid(format!("oracle exited: {helper_status}")));
        }
        Ok(ExitStatus::from_raw(i32::from_be_bytes(bytes)))
    }

    fn request(&mut self, operation: Operation, payload: Vec<u8>) -> io::Result<Vec<u8>> {
        let request_id = self.next_request;
        self.next_request = request_id
            .checked_add(1)
            .ok_or_else(|| invalid("oracle request IDs exhausted"))?;
        write_frame(
            &mut self.stream,
            &Frame {
                kind: FrameKind::Request,
                operation,
                request_id,
                payload,
            },
        )?;
        self.response(operation, request_id)
    }

    fn response(&mut self, operation: Operation, request_id: u64) -> io::Result<Vec<u8>> {
        let response = read_frame(&mut self.stream)?
            .ok_or_else(|| invalid("oracle closed before its response"))?;
        if response.operation != operation || response.request_id != request_id {
            return Err(invalid("oracle response does not match its request"));
        }
        match response.kind {
            FrameKind::Success => Ok(response.payload),
            FrameKind::Failure => {
                let message = String::from_utf8(response.payload)
                    .map_err(|_| invalid("oracle error is not UTF-8"))?;
                Err(io::Error::other(message))
            }
            FrameKind::Request => Err(invalid("oracle replied with a request")),
        }
    }
}

impl Drop for DebugGatewayProcess {
    fn drop(&mut self) {
        // EOF makes the helper drop the actual client, terminating and reaping
        // the gateway even when a test assertion unwinds without shutdown.
        let _ = self.stream.shutdown(Shutdown::Both);
        let _ = self.oracle.wait();
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
