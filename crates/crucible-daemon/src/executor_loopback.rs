//! Versioned Unix-stream loopback transport for executor component messages.
//!
//! The framing protocol contains no Rust-native layout or process-private
//! objects:
//!
//! ```text
//! ExecutorLoopbackFrameV1 = magic[8] | kind:u8 | reserved[3] |
//!                           body_length:u32be | canonical_body[body_length]
//! kind = 1 (SubmitAttemptRequestV1) | 2 (SubmitAttemptResponseV1)
//! ```
//!
//! Both sides enforce the same 4-KiB component-message bound before allocation.
//! The coordinator still wraps [`LoopbackExecutorService`] in the shared
//! checked client, while the adapter itself also strictly authenticates the
//! response against the exact request.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crucible_campaign::{
    CampaignCodecError, ExecutorService, MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
    SubmitAttemptRequest, SubmitAttemptResponse,
};

const FRAME_MAGIC: &[u8; 8] = b"CRUCEX01";
const FRAME_HEADER_BYTES: usize = 16;
const SUBMIT_ATTEMPT_REQUEST_KIND: u8 = 1;
const SUBMIT_ATTEMPT_RESPONSE_KIND: u8 = 2;
const DEFAULT_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Finite read/write deadlines for one loopback executor exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopbackExecutorTimeouts {
    read: Duration,
    write: Duration,
}

impl LoopbackExecutorTimeouts {
    /// Builds nonzero finite socket deadlines.
    ///
    /// # Errors
    ///
    /// Returns [`LoopbackExecutorProtocolError::InvalidTimeout`] when either
    /// duration is zero or exceeds one hour.
    pub fn new(read: Duration, write: Duration) -> Result<Self, LoopbackExecutorProtocolError> {
        if read.is_zero()
            || write.is_zero()
            || read > MAX_LOOPBACK_TIMEOUT
            || write > MAX_LOOPBACK_TIMEOUT
        {
            return Err(LoopbackExecutorProtocolError::InvalidTimeout);
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

impl Default for LoopbackExecutorTimeouts {
    fn default() -> Self {
        Self {
            read: DEFAULT_LOOPBACK_TIMEOUT,
            write: DEFAULT_LOOPBACK_TIMEOUT,
        }
    }
}

/// Coordinator-side executor service over one connected Unix stream.
pub struct LoopbackExecutorService {
    stream: UnixStream,
    timeouts: LoopbackExecutorTimeouts,
}

impl LoopbackExecutorService {
    /// Wraps a connected local Unix stream with default finite deadlines.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the socket deadlines cannot be configured.
    pub fn new(stream: UnixStream) -> Result<Self, LoopbackExecutorProtocolError> {
        Self::with_timeouts(stream, LoopbackExecutorTimeouts::default())
    }

    /// Wraps a connected stream with explicit nonzero finite deadlines.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the socket deadlines cannot be configured.
    pub fn with_timeouts(
        stream: UnixStream,
        timeouts: LoopbackExecutorTimeouts,
    ) -> Result<Self, LoopbackExecutorProtocolError> {
        configure_stream(&stream, timeouts)?;
        Ok(Self { stream, timeouts })
    }

    /// Returns the owned stream after the executor client shuts down.
    #[must_use]
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }
}

impl ExecutorService for LoopbackExecutorService {
    type Error = LoopbackExecutorProtocolError;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        let result = (|| {
            write_frame(
                &mut self.stream,
                SUBMIT_ATTEMPT_REQUEST_KIND,
                &request.canonical_bytes(),
                self.timeouts.write,
            )?;
            let response = read_frame(
                &mut self.stream,
                SUBMIT_ATTEMPT_RESPONSE_KIND,
                self.timeouts.read,
            )?;
            SubmitAttemptResponse::from_canonical_bytes_for(request, &response).map_err(Into::into)
        })();
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }
}

/// Serves one strict executor request/response exchange on a Unix stream.
///
/// A long-lived daemon calls this once per request on the same connection, or
/// closes the connection after any error. Service failures are not converted
/// into a misleading protocol rejection.
///
/// # Errors
///
/// Returns [`LoopbackExecutorServerError::Protocol`] for malformed framing,
/// canonical bytes, cross-request responses, or socket I/O. Returns
/// [`LoopbackExecutorServerError::Service`] when the executor cannot produce a
/// protocol response.
pub fn serve_loopback_executor_once<S: ExecutorService>(
    stream: &mut UnixStream,
    service: &mut S,
) -> Result<(), LoopbackExecutorServerError<S::Error>> {
    serve_loopback_executor_once_with_timeouts(stream, service, LoopbackExecutorTimeouts::default())
}

/// Serves one exchange with explicit finite read/write deadlines.
///
/// The stream is shut down in both directions before any error is returned, so
/// a peer never remains blocked waiting for a response the service abandoned.
///
/// # Errors
///
/// Returns the same failures as [`serve_loopback_executor_once`].
pub fn serve_loopback_executor_once_with_timeouts<S: ExecutorService>(
    stream: &mut UnixStream,
    service: &mut S,
    timeouts: LoopbackExecutorTimeouts,
) -> Result<(), LoopbackExecutorServerError<S::Error>> {
    let result = serve_loopback_executor_inner(stream, service, timeouts);
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

fn serve_loopback_executor_inner<S: ExecutorService>(
    stream: &mut UnixStream,
    service: &mut S,
    timeouts: LoopbackExecutorTimeouts,
) -> Result<(), LoopbackExecutorServerError<S::Error>> {
    configure_stream(stream, timeouts)?;
    let request = read_frame(stream, SUBMIT_ATTEMPT_REQUEST_KIND, timeouts.read)?;
    let request = SubmitAttemptRequest::from_canonical_bytes(&request)?;
    let response = service
        .submit_attempt(&request)
        .map_err(LoopbackExecutorServerError::Service)?;
    response.validate_for(&request)?;
    write_frame(
        stream,
        SUBMIT_ATTEMPT_RESPONSE_KIND,
        &response.canonical_bytes(),
        timeouts.write,
    )?;
    Ok(())
}

/// Malformed, oversized, or unavailable loopback executor transport data.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackExecutorProtocolError {
    /// The Unix stream could not complete a bounded frame operation.
    #[error("executor loopback I/O failed")]
    Io(#[from] std::io::Error),
    /// Canonical request or response bytes failed strict validation.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// A caller attempted to disable a required finite deadline.
    #[error("executor loopback read/write timeout must be between 1ns and 1h")]
    InvalidTimeout,
    /// The fixed frame header violated the versioned protocol.
    #[error("executor loopback frame is invalid: {reason}")]
    InvalidFrame {
        /// Stable framing failure category.
        reason: &'static str,
    },
}

fn configure_stream(
    stream: &UnixStream,
    timeouts: LoopbackExecutorTimeouts,
) -> Result<(), LoopbackExecutorProtocolError> {
    if timeouts.read.is_zero()
        || timeouts.write.is_zero()
        || timeouts.read > MAX_LOOPBACK_TIMEOUT
        || timeouts.write > MAX_LOOPBACK_TIMEOUT
    {
        return Err(LoopbackExecutorProtocolError::InvalidTimeout);
    }
    stream.set_read_timeout(Some(timeouts.read))?;
    stream.set_write_timeout(Some(timeouts.write))?;
    Ok(())
}

/// Failure while serving one loopback executor exchange.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackExecutorServerError<E> {
    /// Framing, canonical validation, or socket I/O failed.
    #[error(transparent)]
    Protocol(#[from] LoopbackExecutorProtocolError),
    /// The underlying executor failed to produce a protocol response.
    #[error("executor service failed")]
    Service(E),
}

impl<E> From<CampaignCodecError> for LoopbackExecutorServerError<E> {
    fn from(error: CampaignCodecError) -> Self {
        Self::Protocol(LoopbackExecutorProtocolError::Codec(error))
    }
}

fn write_frame(
    stream: &mut UnixStream,
    kind: u8,
    body: &[u8],
    timeout: Duration,
) -> Result<(), LoopbackExecutorProtocolError> {
    if body.len() > MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES {
        return Err(LoopbackExecutorProtocolError::InvalidFrame {
            reason: "component-message-too-large",
        });
    }
    let length =
        u32::try_from(body.len()).map_err(|_| LoopbackExecutorProtocolError::InvalidFrame {
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
) -> Result<Vec<u8>, LoopbackExecutorProtocolError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let deadline = operation_deadline(timeout)?;
    read_exact_until(stream, &mut header, deadline)?;
    if &header[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        return Err(LoopbackExecutorProtocolError::InvalidFrame {
            reason: "unsupported-frame-version",
        });
    }
    if header[8] != expected_kind {
        return Err(LoopbackExecutorProtocolError::InvalidFrame {
            reason: "unexpected-message-kind",
        });
    }
    if header[9..12] != [0; 3] {
        return Err(LoopbackExecutorProtocolError::InvalidFrame {
            reason: "nonzero-reserved-bits",
        });
    }
    let length = u32::from_be_bytes(header[12..].try_into().map_err(|_| {
        LoopbackExecutorProtocolError::InvalidFrame {
            reason: "invalid-length-field",
        }
    })?) as usize;
    if length > MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES {
        return Err(LoopbackExecutorProtocolError::InvalidFrame {
            reason: "component-message-too-large",
        });
    }
    let mut body = vec![0; length];
    read_exact_until(stream, &mut body, deadline)?;
    Ok(body)
}

fn operation_deadline(timeout: Duration) -> Result<Instant, LoopbackExecutorProtocolError> {
    if timeout.is_zero() || timeout > MAX_LOOPBACK_TIMEOUT {
        return Err(LoopbackExecutorProtocolError::InvalidTimeout);
    }
    transport_now()
        .checked_add(timeout)
        .ok_or(LoopbackExecutorProtocolError::InvalidTimeout)
}

fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), LoopbackExecutorProtocolError> {
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
                    "executor loopback peer closed a partial frame",
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
) -> Result<(), LoopbackExecutorProtocolError> {
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

fn timeout_io_error() -> LoopbackExecutorProtocolError {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "executor loopback absolute operation deadline elapsed",
    )
    .into()
}

// Wall-independent monotonic time bounds only operational socket blocking; it
// never enters a campaign object, semantic result, or deterministic decision.
#[allow(clippy::disallowed_methods)]
fn transport_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests;
