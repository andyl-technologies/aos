//! Receives exact request-order membership hints through the native RPC client.
//!
//! A well-formed response is a remote assertion, not verified content, current
//! disclosure permission or proof of committed index membership. Server-side
//! authorization and index enforcement remain independent obligations.

use std::fmt;

use connectrpc::{
    ConnectError,
    client::{CallOptions, ClientTransport},
    http_body::Body,
};
use terrane_format::identity::Digest;
use tokio::time::Instant;

use super::call_deadline;
use crate::{
    store::MAX_INDEXED_HASHES,
    wire::{services::ContentServiceClient, v1},
};

/// Reads one bounded batch of remote membership hints in request order.
///
/// Preserves duplicate digests and accepts at most 4,096 entries. Explicit
/// positive timeout, message and decoded-element limits are required before
/// connecting. Empty input returns an empty result without network I/O.
/// The response must have exactly one bitmap byte per eight requested hashes,
/// rounded up; unused bits in the final byte are ignored.
///
/// The absolute deadline includes connection, complete unary reception and
/// decoding. Capability headers and transport security belong to the caller's
/// configured client and options. Returned hints authorize no content access
/// and cannot replace verification before admission.
///
/// # Errors
/// Rejects missing or invalid call bounds and batches larger than 4,096 before
/// network I/O. Preserves transport failures and refuses incomplete or oversized
/// bitmaps and results that complete after the whole-call deadline.
///
/// # Panics
/// Requires a Tokio runtime with its time driver enabled.
pub async fn has<T>(
    client: &ContentServiceClient<T>,
    hashes: &[Digest],
    options: CallOptions,
) -> Result<Vec<bool>, PresenceClientError>
where
    T: ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as Body>::Error: fmt::Display,
{
    let deadline = call_deadline(&options).ok_or(PresenceClientError::Limits)?;
    if hashes.len() > MAX_INDEXED_HASHES {
        return Err(PresenceClientError::Batch);
    }
    if hashes.is_empty() {
        return Ok(Vec::new());
    }

    let request = v1::HasRequest {
        hashes: hashes
            .iter()
            .map(|digest| v1::Hash {
                value: digest.to_vec(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let receive = async {
        let response = client
            .has_with_options(request, options)
            .await
            .map_err(PresenceClientError::Transport)?;
        let bitmap = response.view().present_bitmap;
        if bitmap.len() != hashes.len().div_ceil(8) {
            return Err(PresenceClientError::Bitmap);
        }
        Ok((0..hashes.len())
            .map(|position| bitmap[position / 8] & (1 << (position % 8)) != 0)
            .collect())
    };
    let result = tokio::time::timeout_at(deadline, receive)
        .await
        .map_err(|_| PresenceClientError::Deadline)?;
    if Instant::now() >= deadline {
        return Err(PresenceClientError::Deadline);
    }
    result
}

/// Reports a refused membership call without returning partial hints.
#[derive(Debug)]
pub enum PresenceClientError {
    /// Requires explicit positive call bounds and a representable deadline.
    Limits,
    /// Refuses more than the protocol's 4,096 hashes before network I/O.
    Batch,
    /// Requires exact bitmap coverage of the requested entries.
    Bitmap,
    /// Refuses completion after the configured whole-call deadline.
    Deadline,
    /// Preserves a failed transport or protocol termination.
    Transport(ConnectError),
}

impl fmt::Display for PresenceClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limits => "membership RPC requires explicit positive call bounds",
            Self::Batch => "membership RPC exceeds the 4096-hash request limit",
            Self::Bitmap => "membership RPC bitmap does not cover the exact request",
            Self::Deadline => "membership RPC exceeded its whole-call deadline",
            Self::Transport(_) => "membership RPC transport or protocol failed",
        })
    }
}

impl std::error::Error for PresenceClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}
