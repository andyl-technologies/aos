//! Deadline-bounded Unix probes with actual kernel peer and executable measurements.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crucible_node_contract::{ContentRef, U64, canonical};
use serde_json::Value;

use crate::ProviderError;
use crate::handshake::Limits;
use crate::transport::{FrameReader, write_frame_with_limits};

use super::{EndpointMeasurement, ProbeConnector, ProbeSession};

const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

/// Connects protocol probes to a privately installed, independently measured peer.
///
/// Actual SO_PEERCRED must match the configured UID, and `/proc/PID/exe` bytes
/// must match the separately measured expected executable. This authenticates
/// local transport identity for protocol testing; it does not establish model
/// qualification, in-memory integrity or native effect authority.
pub struct UnixProbeConnector {
    socket: PathBuf,
    expected_uid: u32,
    expected_executable: ContentRef,
    timeout: Duration,
}

impl UnixProbeConnector {
    /// Measures the separately selected executable and configures finite probes.
    ///
    /// # Errors
    /// Rejects unreadable/oversized executable bytes or a zero/over-one-minute
    /// per-exchange operational deadline.
    pub fn new(
        socket: PathBuf,
        expected_uid: u32,
        expected_executable: &Path,
        timeout: Duration,
    ) -> Result<Self, ProviderError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(ProviderError::ResourceExhausted("probe exchange deadline"));
        }
        Ok(Self {
            socket,
            expected_uid,
            expected_executable: measure_executable(expected_executable)?,
            timeout,
        })
    }
}

impl ProbeConnector for UnixProbeConnector {
    fn connect(&mut self) -> Result<Box<dyn ProbeSession>, ProviderError> {
        // An exhausted listening backlog must refuse promptly; blocking connect
        // would otherwise evade the per-exchange I/O deadline.
        let socket = rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(std::io::Error::from)?;
        let address =
            rustix::net::SocketAddrUnix::new(&self.socket).map_err(std::io::Error::from)?;
        rustix::net::connect(&socket, &address).map_err(std::io::Error::from)?;
        let stream = UnixStream::from(socket);
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let credentials =
            rustix::net::sockopt::socket_peercred(&stream).map_err(std::io::Error::from)?;
        if credentials.uid.as_raw() != self.expected_uid {
            return Err(ProviderError::Correlation(
                "probe endpoint peer UID differs",
            ));
        }
        let pid = u32::try_from(credentials.pid.as_raw_nonzero().get()).map_err(|_| {
            ProviderError::Correlation("probe endpoint peer PID outside native range")
        })?;
        let executable = measure_executable(Path::new(&format!("/proc/{pid}/exe")))?;
        if executable != self.expected_executable {
            return Err(ProviderError::Correlation(
                "probe endpoint executable measurement differs",
            ));
        }
        Ok(Box::new(UnixProbeSession {
            stream,
            measurement: EndpointMeasurement {
                peer_pid: U64::new(u64::from(pid)),
                peer_uid: U64::new(u64::from(credentials.uid.as_raw())),
                executable,
            },
            timeout: self.timeout,
            deadline: None,
        }))
    }
}

struct UnixProbeSession {
    stream: UnixStream,
    measurement: EndpointMeasurement,
    timeout: Duration,
    deadline: Option<Instant>,
}

impl UnixProbeSession {
    fn begin_exchange(&mut self) -> Result<(), ProviderError> {
        self.deadline = Some(operational_now().checked_add(self.timeout).ok_or(
            ProviderError::ResourceExhausted("probe deadline representation"),
        )?);
        Ok(())
    }

    fn io(&mut self) -> Result<DeadlineIo<'_>, ProviderError> {
        let deadline = self
            .deadline
            .ok_or(ProviderError::Frame("probe read preceded bounded send"))?;
        Ok(DeadlineIo {
            stream: &mut self.stream,
            deadline,
        })
    }
}

impl ProbeSession for UnixProbeSession {
    fn measurement(&self) -> Option<EndpointMeasurement> {
        Some(self.measurement.clone())
    }

    fn send(&mut self, value: &Value, limits: Limits) -> Result<(), ProviderError> {
        self.begin_exchange()?;
        write_frame_with_limits(
            &mut self.io()?,
            value,
            usize::try_from(limits.frame_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("frame allowance representation"))?,
            usize::try_from(limits.nesting.get()).map_err(|_| {
                ProviderError::ResourceExhausted("nesting allowance representation")
            })?,
        )
    }

    fn send_malformed(&mut self, payload: &[u8]) -> Result<(), ProviderError> {
        self.begin_exchange()?;
        let length = u32::try_from(payload.len())
            .map_err(|_| ProviderError::ResourceExhausted("negative frame length"))?;
        let mut io = self.io()?;
        io.write_all(&length.to_be_bytes())?;
        io.write_all(payload)?;
        io.flush()?;
        Ok(())
    }

    fn receive(&mut self, limits: Limits) -> Result<Option<Value>, ProviderError> {
        FrameReader::with_limits(
            self.io()?,
            usize::try_from(limits.frame_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("frame allowance representation"))?,
            usize::try_from(limits.nesting.get()).map_err(|_| {
                ProviderError::ResourceExhausted("nesting allowance representation")
            })?,
        )?
        .read()
    }

    fn fence(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

impl Drop for UnixProbeSession {
    fn drop(&mut self) {
        self.fence();
    }
}

struct DeadlineIo<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl DeadlineIo<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(operational_now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "total probe exchange deadline expired",
                )
            })
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "host time bounds independent transport probes and never enters modeled state or report identities"
)]
fn operational_now() -> Instant {
    Instant::now()
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

/// Measures exact executable bytes under a finite 256-MiB read allowance.
///
/// # Errors
/// Returns an error for inaccessible, oversized or changing files, or a failed
/// canonical content identity. This measurement does not qualify its behavior.
pub fn measure_executable(path: &Path) -> Result<ContentRef, ProviderError> {
    let file = File::open(path)?;
    let before = file.metadata()?;
    if before.len() > MAX_EXECUTABLE_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "probe executable measurement",
        ));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_EXECUTABLE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_EXECUTABLE_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "probe executable measurement",
        ));
    }
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err(ProviderError::Correlation(
            "executable changed during measurement",
        ));
    }
    Ok(canonical::content_ref(&bytes, "application/octet-stream")?)
}
