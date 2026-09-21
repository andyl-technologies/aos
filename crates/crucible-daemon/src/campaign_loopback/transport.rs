//! Framing errors and bounded Unix-stream I/O.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use rustix::time::{ClockId, clock_gettime};

use crucible_campaign::{
    CampaignAuthorizationError, CampaignCodecError, CampaignServiceFailure,
    CampaignServiceFailureSource, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES,
};

use crate::{CampaignDebugControlCodecError, CampaignRuntimeControlCodecError};

use super::{FRAME_HEADER_BYTES, FRAME_MAGIC, LoopbackCampaignTimeouts, MAX_LOOPBACK_TIMEOUT};

/// Failure observed by a loopback campaign-service caller.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackCampaignServiceError {
    /// Framing, canonical validation, connection state, or socket I/O failed.
    #[error(transparent)]
    Protocol(#[from] LoopbackCampaignProtocolError),
    /// The remote service returned one authenticated stable failure.
    #[error(transparent)]
    Remote(CampaignServiceFailure),
}

impl From<CampaignCodecError> for LoopbackCampaignServiceError {
    fn from(error: CampaignCodecError) -> Self {
        Self::Protocol(LoopbackCampaignProtocolError::Codec(error))
    }
}

impl From<CampaignRuntimeControlCodecError> for LoopbackCampaignServiceError {
    fn from(error: CampaignRuntimeControlCodecError) -> Self {
        Self::Protocol(LoopbackCampaignProtocolError::RuntimeControlCodec(error))
    }
}

impl From<CampaignDebugControlCodecError> for LoopbackCampaignServiceError {
    fn from(error: CampaignDebugControlCodecError) -> Self {
        Self::Protocol(LoopbackCampaignProtocolError::DebugControlCodec(error))
    }
}

impl CampaignServiceFailureSource for LoopbackCampaignServiceError {
    fn campaign_service_failure(&self) -> CampaignServiceFailure {
        match self {
            Self::Remote(failure) => *failure,
            Self::Protocol(LoopbackCampaignProtocolError::InvalidTimeout) => {
                CampaignServiceFailure::InvalidRequest
            }
            Self::Protocol(LoopbackCampaignProtocolError::InvalidRequestLimit) => {
                CampaignServiceFailure::InvalidRequest
            }
            Self::Protocol(
                LoopbackCampaignProtocolError::Codec(_)
                | LoopbackCampaignProtocolError::DebugControlCodec(_)
                | LoopbackCampaignProtocolError::RuntimeControlCodec(_)
                | LoopbackCampaignProtocolError::InvalidFrame { .. },
            ) => CampaignServiceFailure::ProtocolViolation,
            Self::Protocol(
                LoopbackCampaignProtocolError::Io(_)
                | LoopbackCampaignProtocolError::ConnectionBusy
                | LoopbackCampaignProtocolError::ConnectionClosed,
            ) => CampaignServiceFailure::Unavailable,
            Self::Protocol(LoopbackCampaignProtocolError::ConnectionPoisoned) => {
                CampaignServiceFailure::ProtocolViolation
            }
        }
    }
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
    /// Canonical runtime-control bytes failed strict validation.
    #[error(transparent)]
    RuntimeControlCodec(#[from] CampaignRuntimeControlCodecError),
    /// Canonical debug-control bytes failed strict validation.
    #[error(transparent)]
    DebugControlCodec(#[from] CampaignDebugControlCodecError),
    /// A caller attempted to disable the required finite deadlines.
    #[error("campaign loopback read/write timeout must be between 1ns and 1h")]
    InvalidTimeout,
    /// The server-side per-connection request ceiling was invalid.
    #[error("campaign loopback request limit must be between 1 and 65,536")]
    InvalidRequestLimit,
    /// A caller panicked while owning the serialized connection exchange.
    #[error("campaign loopback connection is poisoned")]
    ConnectionPoisoned,
    /// Another complete request/response exchange owns this connection.
    #[error("campaign loopback connection is busy")]
    ConnectionBusy,
    /// The peer closed cleanly between complete frames.
    #[error("campaign loopback peer closed the connection")]
    ConnectionClosed,
    /// The fixed frame header violated the versioned protocol.
    #[error("campaign loopback frame is invalid: {reason}")]
    InvalidFrame {
        /// Stable framing failure category.
        reason: &'static str,
    },
}

/// Failure while serving one loopback campaign-service exchange.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackCampaignServerError {
    /// Framing, canonical validation, or bounded socket I/O failed.
    #[error(transparent)]
    Protocol(#[from] LoopbackCampaignProtocolError),
    /// Kernel peer credentials were denied or could not be resolved.
    #[error(transparent)]
    PeerAuthentication(#[from] CampaignAuthorizationError),
}

impl From<CampaignCodecError> for LoopbackCampaignServerError {
    fn from(error: CampaignCodecError) -> Self {
        Self::Protocol(LoopbackCampaignProtocolError::Codec(error))
    }
}

impl From<CampaignRuntimeControlCodecError> for LoopbackCampaignServerError {
    fn from(error: CampaignRuntimeControlCodecError) -> Self {
        Self::Protocol(LoopbackCampaignProtocolError::RuntimeControlCodec(error))
    }
}

impl From<CampaignDebugControlCodecError> for LoopbackCampaignServerError {
    fn from(error: CampaignDebugControlCodecError) -> Self {
        Self::Protocol(LoopbackCampaignProtocolError::DebugControlCodec(error))
    }
}

pub(super) fn configure_stream(
    stream: &UnixStream,
    timeouts: LoopbackCampaignTimeouts,
) -> Result<(), LoopbackCampaignProtocolError> {
    validate_timeouts(timeouts.read, timeouts.write)?;
    stream.set_read_timeout(Some(timeouts.read))?;
    stream.set_write_timeout(Some(timeouts.write))?;
    Ok(())
}

pub(super) fn validate_timeouts(
    read: Duration,
    write: Duration,
) -> Result<(), LoopbackCampaignProtocolError> {
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

pub(super) fn write_frame(
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

#[cfg(test)]
pub(super) fn read_frame(
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

pub(super) fn read_frame_any(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<(u8, Vec<u8>), LoopbackCampaignProtocolError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let deadline = operation_deadline(timeout)?;
    read_exact_until(stream, &mut header, deadline, true)?;
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
    read_exact_until(stream, &mut body, deadline, false)?;
    Ok((header[8], body))
}

fn operation_deadline(timeout: Duration) -> Result<u64, LoopbackCampaignProtocolError> {
    if timeout.is_zero() || timeout > MAX_LOOPBACK_TIMEOUT {
        return Err(LoopbackCampaignProtocolError::InvalidTimeout);
    }
    transport_now()?
        .checked_add(
            u64::try_from(timeout.as_nanos())
                .map_err(|_| LoopbackCampaignProtocolError::InvalidTimeout)?,
        )
        .ok_or(LoopbackCampaignProtocolError::InvalidTimeout)
}

fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: u64,
    clean_eof: bool,
) -> Result<(), LoopbackCampaignProtocolError> {
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline
            .checked_sub(transport_now()?)
            .map(Duration::from_nanos)
            .ok_or_else(timeout_io_error)?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) if clean_eof && offset == 0 => {
                return Err(LoopbackCampaignProtocolError::ConnectionClosed);
            }
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
    deadline: u64,
) -> Result<(), LoopbackCampaignProtocolError> {
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline
            .checked_sub(transport_now()?)
            .map(Duration::from_nanos)
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

fn transport_now() -> Result<u64, LoopbackCampaignProtocolError> {
    let now = clock_gettime(ClockId::Monotonic);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| timeout_io_error())?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| timeout_io_error())?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanoseconds))
        .ok_or_else(timeout_io_error)
}
