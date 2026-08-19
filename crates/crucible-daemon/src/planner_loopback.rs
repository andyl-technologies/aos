//! Versioned Unix-stream transport for one local pure-planner component.
//!
//! The protocol contains only bounded canonical component messages:
//!
//! ```text
//! PlannerLoopbackFrameV1 = magic[8] | kind:u8 | reserved[3] |
//!                          body_length:u32be | canonical_body[body_length]
//! kind = 1 (PlannerRequestV1) | 2 (PlannerResponseV1)
//! magic = "CRUCPL01"
//! ```
//!
//! Absolute read and write deadlines prevent partial or drip-fed frames from
//! pinning a local component handler. Any protocol, service, or I/O error
//! poisons the connection by shutting down both stream directions.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crucible_campaign::{
    CampaignCodecError, MAX_PLANNER_COMPONENT_MESSAGE_BYTES, PlannerRequest, PlannerResponse,
    PlannerService,
};

const FRAME_MAGIC: &[u8; 8] = b"CRUCPL01";
const FRAME_HEADER_BYTES: usize = 16;
const PLANNER_REQUEST_KIND: u8 = 1;
const PLANNER_SUBMISSION_KIND: u8 = 2;
const DEFAULT_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Finite read/write deadlines for one loopback planner exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopbackPlannerTimeouts {
    read: Duration,
    write: Duration,
}

impl LoopbackPlannerTimeouts {
    /// Builds nonzero finite socket deadlines no greater than one hour.
    ///
    /// # Errors
    ///
    /// Returns [`LoopbackPlannerProtocolError::InvalidTimeout`] when either
    /// duration is zero or exceeds one hour.
    pub fn new(read: Duration, write: Duration) -> Result<Self, LoopbackPlannerProtocolError> {
        if read.is_zero()
            || write.is_zero()
            || read > MAX_LOOPBACK_TIMEOUT
            || write > MAX_LOOPBACK_TIMEOUT
        {
            return Err(LoopbackPlannerProtocolError::InvalidTimeout);
        }
        Ok(Self { read, write })
    }

    /// Returns the finite read deadline.
    #[must_use]
    pub const fn read(self) -> Duration {
        self.read
    }

    /// Returns the finite write deadline.
    #[must_use]
    pub const fn write(self) -> Duration {
        self.write
    }
}

impl Default for LoopbackPlannerTimeouts {
    fn default() -> Self {
        Self {
            read: DEFAULT_LOOPBACK_TIMEOUT,
            write: DEFAULT_LOOPBACK_TIMEOUT,
        }
    }
}

/// Coordinator-side planner service over one connected Unix stream.
pub struct LoopbackPlannerService {
    stream: UnixStream,
    timeouts: LoopbackPlannerTimeouts,
}

impl LoopbackPlannerService {
    /// Wraps a connected stream with default finite operation deadlines.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when socket deadlines cannot be configured.
    pub fn new(stream: UnixStream) -> Result<Self, LoopbackPlannerProtocolError> {
        Self::with_timeouts(stream, LoopbackPlannerTimeouts::default())
    }

    /// Wraps a connected stream with explicit finite operation deadlines.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when socket deadlines cannot be configured.
    pub fn with_timeouts(
        stream: UnixStream,
        timeouts: LoopbackPlannerTimeouts,
    ) -> Result<Self, LoopbackPlannerProtocolError> {
        configure_stream(&stream, timeouts)?;
        Ok(Self { stream, timeouts })
    }

    /// Returns the owned stream after planner client shutdown.
    #[must_use]
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }
}

impl PlannerService for LoopbackPlannerService {
    type Error = LoopbackPlannerProtocolError;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerResponse, Self::Error> {
        let result = (|| {
            write_frame(
                &mut self.stream,
                PLANNER_REQUEST_KIND,
                &request.canonical_bytes(),
                self.timeouts.write,
            )?;
            let response = read_frame(
                &mut self.stream,
                PLANNER_SUBMISSION_KIND,
                self.timeouts.read,
            )?;
            let response = PlannerResponse::from_canonical_bytes(&response)?;
            response.validate_for(request)?;
            Ok(response)
        })();
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }
}

/// Serves one strict planner request/response exchange.
///
/// The stream is shut down in both directions before any error is returned.
/// Service failures are not converted into semantic planner output.
///
/// # Errors
///
/// Returns [`LoopbackPlannerServerError::Protocol`] for malformed framing,
/// canonical input, invalid response basis, or bounded socket I/O. Returns
/// [`LoopbackPlannerServerError::Service`] when the planner cannot produce an
/// authenticated submission.
pub fn serve_loopback_planner_once<S: PlannerService>(
    stream: &mut UnixStream,
    service: &mut S,
) -> Result<(), LoopbackPlannerServerError<S::Error>> {
    serve_loopback_planner_once_with_timeouts(stream, service, LoopbackPlannerTimeouts::default())
}

/// Serves one strict exchange with explicit finite operation deadlines.
///
/// # Errors
///
/// Returns the same failures as [`serve_loopback_planner_once`].
pub fn serve_loopback_planner_once_with_timeouts<S: PlannerService>(
    stream: &mut UnixStream,
    service: &mut S,
    timeouts: LoopbackPlannerTimeouts,
) -> Result<(), LoopbackPlannerServerError<S::Error>> {
    let result = serve_loopback_planner_inner(stream, service, timeouts);
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

fn serve_loopback_planner_inner<S: PlannerService>(
    stream: &mut UnixStream,
    service: &mut S,
    timeouts: LoopbackPlannerTimeouts,
) -> Result<(), LoopbackPlannerServerError<S::Error>> {
    configure_stream(stream, timeouts)?;
    let request = read_frame(stream, PLANNER_REQUEST_KIND, timeouts.read)?;
    let request = PlannerRequest::from_canonical_bytes(&request)?;
    let response = service
        .plan(&request)
        .map_err(LoopbackPlannerServerError::Service)?;
    response.validate_for(&request)?;
    write_frame(
        stream,
        PLANNER_SUBMISSION_KIND,
        &response.canonical_bytes(),
        timeouts.write,
    )?;
    Ok(())
}

/// Malformed, oversized, or unavailable planner transport data.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackPlannerProtocolError {
    /// The Unix stream could not complete a bounded frame operation.
    #[error("planner loopback I/O failed")]
    Io(#[from] std::io::Error),
    /// Canonical request or response bytes failed strict validation.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// A caller attempted to disable a required finite deadline.
    #[error("planner loopback read/write timeout must be between 1ns and 1h")]
    InvalidTimeout,
    /// The fixed frame header violated the versioned protocol.
    #[error("planner loopback frame is invalid: {reason}")]
    InvalidFrame {
        /// Stable framing failure category.
        reason: &'static str,
    },
}

/// Failure while serving one loopback planner exchange.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackPlannerServerError<E> {
    /// Framing, canonical validation, or socket I/O failed.
    #[error(transparent)]
    Protocol(#[from] LoopbackPlannerProtocolError),
    /// The underlying planner failed to produce a submission.
    #[error("planner service failed")]
    Service(E),
}

impl<E> From<CampaignCodecError> for LoopbackPlannerServerError<E> {
    fn from(error: CampaignCodecError) -> Self {
        Self::Protocol(LoopbackPlannerProtocolError::Codec(error))
    }
}

fn configure_stream(
    stream: &UnixStream,
    timeouts: LoopbackPlannerTimeouts,
) -> Result<(), LoopbackPlannerProtocolError> {
    if timeouts.read.is_zero()
        || timeouts.write.is_zero()
        || timeouts.read > MAX_LOOPBACK_TIMEOUT
        || timeouts.write > MAX_LOOPBACK_TIMEOUT
    {
        return Err(LoopbackPlannerProtocolError::InvalidTimeout);
    }
    stream.set_read_timeout(Some(timeouts.read))?;
    stream.set_write_timeout(Some(timeouts.write))?;
    Ok(())
}

fn write_frame(
    stream: &mut UnixStream,
    kind: u8,
    body: &[u8],
    timeout: Duration,
) -> Result<(), LoopbackPlannerProtocolError> {
    if body.len() > MAX_PLANNER_COMPONENT_MESSAGE_BYTES {
        return Err(LoopbackPlannerProtocolError::InvalidFrame {
            reason: "component-message-too-large",
        });
    }
    let length =
        u32::try_from(body.len()).map_err(|_| LoopbackPlannerProtocolError::InvalidFrame {
            reason: "component-message-length-overflow",
        })?;
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    header[..FRAME_MAGIC.len()].copy_from_slice(FRAME_MAGIC);
    header[8] = kind;
    header[12..].copy_from_slice(&length.to_be_bytes());
    let deadline = operation_deadline(timeout)?;
    write_all_until(stream, &header, deadline)?;
    write_all_until(stream, body, deadline)?;
    Ok(())
}

fn read_frame(
    stream: &mut UnixStream,
    expected_kind: u8,
    timeout: Duration,
) -> Result<Vec<u8>, LoopbackPlannerProtocolError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let deadline = operation_deadline(timeout)?;
    read_exact_until(stream, &mut header, deadline)?;
    if &header[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        return Err(LoopbackPlannerProtocolError::InvalidFrame {
            reason: "unsupported-frame-version",
        });
    }
    if header[8] != expected_kind {
        return Err(LoopbackPlannerProtocolError::InvalidFrame {
            reason: "unexpected-message-kind",
        });
    }
    if header[9..12] != [0; 3] {
        return Err(LoopbackPlannerProtocolError::InvalidFrame {
            reason: "nonzero-reserved-bits",
        });
    }
    let length = u32::from_be_bytes(header[12..].try_into().map_err(|_| {
        LoopbackPlannerProtocolError::InvalidFrame {
            reason: "invalid-length-field",
        }
    })?) as usize;
    if length > MAX_PLANNER_COMPONENT_MESSAGE_BYTES {
        return Err(LoopbackPlannerProtocolError::InvalidFrame {
            reason: "component-message-too-large",
        });
    }
    let mut body = vec![0; length];
    read_exact_until(stream, &mut body, deadline)?;
    Ok(body)
}

fn operation_deadline(timeout: Duration) -> Result<Instant, LoopbackPlannerProtocolError> {
    if timeout.is_zero() || timeout > MAX_LOOPBACK_TIMEOUT {
        return Err(LoopbackPlannerProtocolError::InvalidTimeout);
    }
    transport_now()
        .checked_add(timeout)
        .ok_or(LoopbackPlannerProtocolError::InvalidTimeout)
}

fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), LoopbackPlannerProtocolError> {
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline
            .checked_duration_since(transport_now())
            .ok_or_else(timeout_io_error)?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "planner loopback peer closed a partial frame",
                )
                .into());
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_all_until(
    stream: &mut UnixStream,
    buffer: &[u8],
    deadline: Instant,
) -> Result<(), LoopbackPlannerProtocolError> {
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline
            .checked_duration_since(transport_now())
            .ok_or_else(timeout_io_error)?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(&buffer[offset..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn timeout_io_error() -> LoopbackPlannerProtocolError {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "planner loopback absolute operation deadline elapsed",
    )
    .into()
}

// Monotonic transport time bounds only operational socket blocking and never
// enters planner input, output, or deterministic fuel accounting.
#[allow(clippy::disallowed_methods)]
fn transport_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests;
