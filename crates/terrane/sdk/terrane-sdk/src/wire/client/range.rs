//! Reads exact bounded pack ranges through the generated native RPC client.
//!
//! The complete response remains private until successful protocol termination.
//! Contiguous offsets and exact byte coverage establish framing only. Callers
//! must independently verify pack structure, chunk plaintext identities, current
//! permission and Original provenance before admission or repository use.

use std::fmt;

use connectrpc::{
    ConnectError,
    client::{CallOptions, ClientTransport},
    http_body::Body,
};
use tokio::time::Instant;

use super::super::{services::ContentServiceClient, v1};
use super::call_deadline;

/// Holds finite resources for a privately buffered fallback range read.
#[derive(Clone, Copy, Debug)]
pub struct RangeLimits {
    bytes: usize,
    frames: u64,
}

impl RangeLimits {
    /// Bounds retained bytes and the number of nonempty data frames.
    ///
    /// # Errors
    /// Rejects zero limits, more than one GiB or more than 1,048,576 frames.
    pub fn new(bytes: usize, frames: u64) -> Result<Self, RangeClientError> {
        if bytes == 0 || bytes > 1024 * 1024 * 1024 || frames == 0 || frames > 1_048_576 {
            return Err(RangeClientError::Limits);
        }
        Ok(Self { bytes, frames })
    }
}

/// Retains a complete private range without claiming verified content identity.
#[derive(Debug)]
pub struct RangeBytes {
    pack: [u8; 16],
    offset: u64,
    bytes: Vec<u8>,
}

impl RangeBytes {
    /// Returns the requested pack identifier without claiming its existence.
    pub const fn pack(&self) -> &[u8; 16] {
        &self.pack
    }

    /// Returns the absolute offset of the requested range in its pack.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Borrows unverified bytes after exact coverage and successful termination.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the private result and returns its unverified bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Reads an exact pack range without exposing intermediate frames.
///
/// A positive explicit timeout, message limit and decoded-element limit are
/// required before connecting. The absolute deadline includes connection and
/// complete reception. Frames must be nonempty, contiguous at absolute pack
/// offsets and no larger than four MiB. Exact coverage alone cannot complete a
/// call: the protocol decoder must accept successful terminal metadata too.
/// An empty requested range accepts no data frames.
///
/// Dropping the future releases the response stream and retained private bytes.
/// Returned bytes require independent content verification before admission.
///
/// # Errors
/// Refuses missing or malformed ranges, offset overflow, invalid call bounds,
/// requested or received resource excess, failed transport, protocol truncation,
/// unsuccessful termination and incomplete or inconsistent byte coverage.
///
/// # Panics
/// Requires a Tokio runtime with its time driver enabled.
pub async fn get_range<T>(
    client: &ContentServiceClient<T>,
    request: v1::GetRangeRequest,
    options: CallOptions,
    limits: RangeLimits,
) -> Result<RangeBytes, RangeClientError>
where
    T: ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as Body>::Error: fmt::Display,
{
    let deadline = call_deadline(&options).ok_or(RangeClientError::Limits)?;
    let range = request.range.as_option().ok_or(RangeClientError::Request)?;
    let pack: [u8; 16] = range
        .pack
        .as_option()
        .ok_or(RangeClientError::Request)?
        .value
        .as_slice()
        .try_into()
        .map_err(|_| RangeClientError::Request)?;
    let offset = range.offset;
    let end = offset
        .checked_add(range.length)
        .ok_or(RangeClientError::Request)?;
    let length = usize::try_from(range.length).map_err(|_| RangeClientError::Limit)?;
    if length > limits.bytes {
        return Err(RangeClientError::Limit);
    }

    let receive = async {
        let mut stream = client
            .get_range_with_options(request, options)
            .await
            .map_err(RangeClientError::Transport)?;
        let mut bytes = Vec::new();
        let mut next = offset;
        let mut frames = 0;
        while let Some(message) = stream
            .message()
            .await
            .map_err(RangeClientError::Transport)?
        {
            let frame = message.view();
            if frame.data.is_empty() || frame.offset != next {
                return Err(RangeClientError::Coverage);
            }
            let frame_end = next
                .checked_add(frame.data.len() as u64)
                .ok_or(RangeClientError::Coverage)?;
            if frame_end > end
                || frame.data.len() > super::super::upload::MAX_BODY_FRAME_BYTES
                || frames >= limits.frames
            {
                return Err(RangeClientError::Limit);
            }
            bytes
                .try_reserve(frame.data.len())
                .map_err(|_| RangeClientError::Allocation)?;
            bytes.extend_from_slice(frame.data);
            next = frame_end;
            frames += 1;
        }
        if next != end {
            return Err(RangeClientError::Coverage);
        }
        Ok(RangeBytes {
            pack,
            offset,
            bytes,
        })
    };
    let result = tokio::time::timeout_at(deadline, receive)
        .await
        .map_err(|_| RangeClientError::Deadline)?;
    if Instant::now() >= deadline {
        return Err(RangeClientError::Deadline);
    }
    result
}

/// Reports a refused fallback read without exposing partial range data.
#[derive(Debug)]
pub enum RangeClientError {
    /// Requires explicit positive and representable call and resource limits.
    Limits,
    /// Requires a range with a sixteen-byte pack ID and no offset overflow.
    Request,
    /// Refuses requested or received byte, frame-size or frame-count excess.
    Limit,
    /// Refuses empty, overlapping, reordered, gapped or incomplete data frames.
    Coverage,
    /// Refuses completion after the absolute whole-call deadline.
    Deadline,
    /// Preserves a transport or protocol termination failure.
    Transport(ConnectError),
    /// Refuses a failed reservation for retained private bytes.
    Allocation,
}

impl fmt::Display for RangeClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limits => "range RPC requires explicit finite call bounds",
            Self::Request => "range RPC requires a valid pack and byte range",
            Self::Limit => "range RPC exceeds configured resources or requested bytes",
            Self::Coverage => "range RPC does not cover the exact requested bytes",
            Self::Deadline => "range RPC exceeded its whole-call deadline",
            Self::Transport(_) => "range RPC transport or protocol failed",
            Self::Allocation => "range RPC could not retain private bytes",
        })
    }
}

impl std::error::Error for RangeClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}
