//! Versioned Unix-stream transport for the user-facing campaign service.
//!
//! The protocol contains only bounded canonical component messages:
//!
//! ```text
//! CampaignLoopbackFrameV1 = magic[8] | kind:u8 | reserved[3] |
//!                           body_length:u32be | canonical_body[body_length]
//! kind = 1 (GetCampaignRequestV1) |
//!        2 (GetCampaignResponseV1) |
//!        3 (ApplyCampaignCommandRequestV1) |
//!        4 (ApplyCampaignCommandResponseV1) |
//!        5 (SubmitCampaignBranchRequestV1) |
//!        6 (SubmitCampaignBranchResponseV1)
//! magic = "CRUCCS01"
//! ```
//!
//! One mutex serializes complete request/response exchanges so concurrent
//! local callers cannot interleave frames; a competing caller receives an
//! immediate connection-busy error. Absolute read and write deadlines reject
//! partial or drip-fed frames, and every protocol, I/O, canonical, or service
//! error poisons the connection by shutting down both stream directions.
//!
//! Framing does not authenticate the connected peer. A listener must bind the
//! stream's authenticated peer credential or an exact-request proof into the
//! supplied [`CampaignService`] authorizer. Trusting only the principal string
//! carried inside a request is non-conforming.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

use crucible_campaign::{
    ApplyCampaignCommandRequest, ApplyCampaignCommandResponse, CampaignCodecError, CampaignService,
    GetCampaignRequest, GetCampaignResponse, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES,
    SubmitCampaignBranchRequest, SubmitCampaignBranchResponse,
};

const FRAME_MAGIC: &[u8; 8] = b"CRUCCS01";
const FRAME_HEADER_BYTES: usize = 16;
const GET_CAMPAIGN_REQUEST_KIND: u8 = 1;
const GET_CAMPAIGN_RESPONSE_KIND: u8 = 2;
const APPLY_COMMAND_REQUEST_KIND: u8 = 3;
const APPLY_COMMAND_RESPONSE_KIND: u8 = 4;
const SUBMIT_BRANCH_REQUEST_KIND: u8 = 5;
const SUBMIT_BRANCH_RESPONSE_KIND: u8 = 6;
const DEFAULT_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Finite read/write deadlines for one campaign-service exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopbackCampaignTimeouts {
    read: Duration,
    write: Duration,
}

impl LoopbackCampaignTimeouts {
    /// Builds nonzero finite operation deadlines no greater than one hour.
    ///
    /// # Errors
    ///
    /// Returns [`LoopbackCampaignProtocolError::InvalidTimeout`] when either
    /// duration is zero or exceeds one hour.
    pub fn new(read: Duration, write: Duration) -> Result<Self, LoopbackCampaignProtocolError> {
        validate_timeouts(read, write)?;
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

impl Default for LoopbackCampaignTimeouts {
    fn default() -> Self {
        Self {
            read: DEFAULT_LOOPBACK_TIMEOUT,
            write: DEFAULT_LOOPBACK_TIMEOUT,
        }
    }
}

/// Checked campaign service over one connected local Unix stream.
pub struct LoopbackCampaignService {
    stream: Mutex<UnixStream>,
    timeouts: LoopbackCampaignTimeouts,
}

impl LoopbackCampaignService {
    /// Wraps a connected stream with default finite operation deadlines.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when socket deadlines cannot be configured.
    pub fn new(stream: UnixStream) -> Result<Self, LoopbackCampaignProtocolError> {
        Self::with_timeouts(stream, LoopbackCampaignTimeouts::default())
    }

    /// Wraps a connected stream with explicit finite operation deadlines.
    ///
    /// # Errors
    ///
    /// Returns an invalid-timeout or I/O error when the deadlines cannot be
    /// installed.
    pub fn with_timeouts(
        stream: UnixStream,
        timeouts: LoopbackCampaignTimeouts,
    ) -> Result<Self, LoopbackCampaignProtocolError> {
        configure_stream(&stream, timeouts)?;
        Ok(Self {
            stream: Mutex::new(stream),
            timeouts,
        })
    }

    /// Returns the owned stream after campaign client shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`LoopbackCampaignProtocolError::ConnectionPoisoned`] if a
    /// caller panicked while holding the exchange lock.
    pub fn into_stream(self) -> Result<UnixStream, LoopbackCampaignProtocolError> {
        self.stream
            .into_inner()
            .map_err(|_| LoopbackCampaignProtocolError::ConnectionPoisoned)
    }

    fn exchange<T>(
        &self,
        request_kind: u8,
        response_kind: u8,
        request: &[u8],
        decode_response: impl FnOnce(&[u8]) -> Result<T, LoopbackCampaignProtocolError>,
    ) -> Result<T, LoopbackCampaignProtocolError> {
        let mut stream = match self.stream.try_lock() {
            Ok(stream) => stream,
            Err(TryLockError::WouldBlock) => {
                return Err(LoopbackCampaignProtocolError::ConnectionBusy);
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                let stream = poisoned.into_inner();
                let _ = stream.shutdown(Shutdown::Both);
                return Err(LoopbackCampaignProtocolError::ConnectionPoisoned);
            }
        };
        let result = (|| {
            write_frame(&mut stream, request_kind, request, self.timeouts.write)?;
            let response = read_frame(&mut stream, response_kind, self.timeouts.read)?;
            decode_response(&response)
        })();
        if result.is_err() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        result
    }
}

impl CampaignService for LoopbackCampaignService {
    type Error = LoopbackCampaignProtocolError;

    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_REQUEST_KIND,
            GET_CAMPAIGN_RESPONSE_KIND,
            &request.canonical_bytes(),
            |response| {
                let response = GetCampaignResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
        )
    }

    fn apply_campaign_command(
        &self,
        request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        self.exchange(
            APPLY_COMMAND_REQUEST_KIND,
            APPLY_COMMAND_RESPONSE_KIND,
            &request.canonical_bytes(),
            |response| {
                let response = ApplyCampaignCommandResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
        )
    }

    fn submit_branch_request(
        &self,
        request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        self.exchange(
            SUBMIT_BRANCH_REQUEST_KIND,
            SUBMIT_BRANCH_RESPONSE_KIND,
            &request.canonical_bytes(),
            |response| {
                let response = SubmitCampaignBranchResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
        )
    }
}

/// Serves one strict campaign-service request/response exchange.
///
/// The stream is shut down in both directions before any error is returned.
/// Service failures are never converted into semantic campaign responses.
/// The caller remains responsible for authenticating the connected peer and
/// binding that evidence into the supplied service's principal authorizer.
///
/// # Errors
///
/// Returns [`LoopbackCampaignServerError::Protocol`] for malformed framing,
/// canonical input, invalid response binding, or bounded socket I/O. Returns
/// [`LoopbackCampaignServerError::Service`] when the campaign service fails.
pub fn serve_loopback_campaign_once<S: CampaignService>(
    stream: &mut UnixStream,
    service: &S,
) -> Result<(), LoopbackCampaignServerError<S::Error>> {
    serve_loopback_campaign_once_with_timeouts(stream, service, LoopbackCampaignTimeouts::default())
}

/// Serves one strict exchange with explicit finite operation deadlines.
///
/// # Errors
///
/// Returns the same failures as [`serve_loopback_campaign_once`].
pub fn serve_loopback_campaign_once_with_timeouts<S: CampaignService>(
    stream: &mut UnixStream,
    service: &S,
    timeouts: LoopbackCampaignTimeouts,
) -> Result<(), LoopbackCampaignServerError<S::Error>> {
    let result = serve_loopback_campaign_inner(stream, service, timeouts);
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

fn serve_loopback_campaign_inner<S: CampaignService>(
    stream: &mut UnixStream,
    service: &S,
    timeouts: LoopbackCampaignTimeouts,
) -> Result<(), LoopbackCampaignServerError<S::Error>> {
    configure_stream(stream, timeouts)?;
    let (kind, body) = read_frame_any(stream, timeouts.read)?;
    let (response_kind, response) = match kind {
        GET_CAMPAIGN_REQUEST_KIND => {
            let request = GetCampaignRequest::from_canonical_bytes(&body)?;
            let response = service
                .get_campaign(&request)
                .map_err(LoopbackCampaignServerError::Service)?;
            response.validate_for(&request)?;
            (GET_CAMPAIGN_RESPONSE_KIND, response.canonical_bytes())
        }
        APPLY_COMMAND_REQUEST_KIND => {
            let request = ApplyCampaignCommandRequest::from_canonical_bytes(&body)?;
            let response = service
                .apply_campaign_command(&request)
                .map_err(LoopbackCampaignServerError::Service)?;
            response.validate_for(&request)?;
            (APPLY_COMMAND_RESPONSE_KIND, response.canonical_bytes())
        }
        SUBMIT_BRANCH_REQUEST_KIND => {
            let request = SubmitCampaignBranchRequest::from_canonical_bytes(&body)?;
            let response = service
                .submit_branch_request(&request)
                .map_err(LoopbackCampaignServerError::Service)?;
            response.validate_for(&request)?;
            (SUBMIT_BRANCH_RESPONSE_KIND, response.canonical_bytes())
        }
        _ => {
            return Err(LoopbackCampaignProtocolError::InvalidFrame {
                reason: "unknown-campaign-service-request-kind",
            }
            .into());
        }
    };
    write_frame(stream, response_kind, &response, timeouts.write)?;
    Ok(())
}

/// Malformed, oversized, or unavailable campaign loopback transport data.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackCampaignProtocolError {
    /// The Unix stream could not complete one bounded frame operation.
    #[error("campaign loopback I/O failed")]
    Io(#[from] std::io::Error),
    /// Canonical request or response bytes failed strict validation.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// A caller attempted to disable the required finite deadlines.
    #[error("campaign loopback read/write timeout must be between 1ns and 1h")]
    InvalidTimeout,
    /// A caller panicked while owning the serialized connection exchange.
    #[error("campaign loopback connection is poisoned")]
    ConnectionPoisoned,
    /// Another complete request/response exchange owns this connection.
    #[error("campaign loopback connection is busy")]
    ConnectionBusy,
    /// The fixed frame header violated the versioned protocol.
    #[error("campaign loopback frame is invalid: {reason}")]
    InvalidFrame {
        /// Stable framing failure category.
        reason: &'static str,
    },
}

/// Failure while serving one loopback campaign-service exchange.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackCampaignServerError<E> {
    /// Framing, canonical validation, or bounded socket I/O failed.
    #[error(transparent)]
    Protocol(#[from] LoopbackCampaignProtocolError),
    /// The underlying campaign service failed.
    #[error("campaign service failed")]
    Service(E),
}

impl<E> From<CampaignCodecError> for LoopbackCampaignServerError<E> {
    fn from(error: CampaignCodecError) -> Self {
        Self::Protocol(LoopbackCampaignProtocolError::Codec(error))
    }
}

fn configure_stream(
    stream: &UnixStream,
    timeouts: LoopbackCampaignTimeouts,
) -> Result<(), LoopbackCampaignProtocolError> {
    validate_timeouts(timeouts.read, timeouts.write)?;
    stream.set_read_timeout(Some(timeouts.read))?;
    stream.set_write_timeout(Some(timeouts.write))?;
    Ok(())
}

fn validate_timeouts(read: Duration, write: Duration) -> Result<(), LoopbackCampaignProtocolError> {
    if read.is_zero()
        || write.is_zero()
        || read > MAX_LOOPBACK_TIMEOUT
        || write > MAX_LOOPBACK_TIMEOUT
    {
        Err(LoopbackCampaignProtocolError::InvalidTimeout)
    } else {
        Ok(())
    }
}

fn write_frame(
    stream: &mut UnixStream,
    kind: u8,
    body: &[u8],
    timeout: Duration,
) -> Result<(), LoopbackCampaignProtocolError> {
    if body.len() > MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES {
        return Err(LoopbackCampaignProtocolError::InvalidFrame {
            reason: "component-message-too-large",
        });
    }
    let length =
        u32::try_from(body.len()).map_err(|_| LoopbackCampaignProtocolError::InvalidFrame {
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
) -> Result<Vec<u8>, LoopbackCampaignProtocolError> {
    let (kind, body) = read_frame_any(stream, timeout)?;
    if kind != expected_kind {
        return Err(LoopbackCampaignProtocolError::InvalidFrame {
            reason: "unexpected-message-kind",
        });
    }
    Ok(body)
}

fn read_frame_any(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<(u8, Vec<u8>), LoopbackCampaignProtocolError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let deadline = operation_deadline(timeout)?;
    read_exact_until(stream, &mut header, deadline)?;
    if &header[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        return Err(LoopbackCampaignProtocolError::InvalidFrame {
            reason: "unsupported-frame-version",
        });
    }
    if header[9..12] != [0; 3] {
        return Err(LoopbackCampaignProtocolError::InvalidFrame {
            reason: "nonzero-reserved-bits",
        });
    }
    let length = u32::from_be_bytes(header[12..].try_into().map_err(|_| {
        LoopbackCampaignProtocolError::InvalidFrame {
            reason: "invalid-length-field",
        }
    })?) as usize;
    if length > MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES {
        return Err(LoopbackCampaignProtocolError::InvalidFrame {
            reason: "component-message-too-large",
        });
    }
    let mut body = vec![0; length];
    read_exact_until(stream, &mut body, deadline)?;
    Ok((header[8], body))
}

fn operation_deadline(timeout: Duration) -> Result<Instant, LoopbackCampaignProtocolError> {
    if timeout.is_zero() || timeout > MAX_LOOPBACK_TIMEOUT {
        return Err(LoopbackCampaignProtocolError::InvalidTimeout);
    }
    transport_now()
        .checked_add(timeout)
        .ok_or(LoopbackCampaignProtocolError::InvalidTimeout)
}

fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), LoopbackCampaignProtocolError> {
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
                    "campaign loopback peer closed a partial frame",
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
) -> Result<(), LoopbackCampaignProtocolError> {
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

fn timeout_io_error() -> LoopbackCampaignProtocolError {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "campaign loopback absolute operation deadline elapsed",
    )
    .into()
}

// Monotonic transport time bounds only operational socket blocking and never
// enters campaign semantic state or content identity.
#[allow(clippy::disallowed_methods)]
fn transport_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests;
