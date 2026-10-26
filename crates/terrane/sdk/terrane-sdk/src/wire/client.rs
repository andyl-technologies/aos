//! Receives private native RPC results through generated protocol decoders.
//!
//! Bundle reads require explicit frame, decoded-element and whole-call bounds.
//! Only successful protocol termination permits configured schema validation and
//! a private result. Transport errors, truncation, cancellation and deadline
//! expiry discard retained objects. Transport security and capability headers
//! belong to the caller's configured generated client and per-call options.
//! These representations establish no repository authorization or graph closure.

use std::fmt;

use tokio::time::Instant;

use connectrpc::{
    ConnectError,
    client::{CallOptions, ClientTransport},
    http_body::Body,
};

use super::{
    bundle::{BundleError, BundleLimits, BundleReceiver, ReceivedBundle},
    services::ContentServiceClient,
    v1,
};
use crate::store::ContentValidator;

/// Receives exact private pack ranges without admitting their unverified bytes.
pub mod range;

/// Receives bounded request-order membership hints from the remote peer.
pub mod presence;

/// Receives bounded ancestry, frontier and request-order missing-content hints.
pub mod negotiation;

/// Receives bounded whole-ref observations before independent commit verification.
pub mod references;

/// Receives bounded, ordered canonical reflogs before commit verification.
pub mod reflog;

/// Reads a complete bounded bundle through the generated native RPC client.
///
/// `options` must explicitly set positive message and element-memory limits and
/// a positive timeout. The same timeout covers connection establishment, stream
/// reception and final schema checks; per-frame progress never resets it. The
/// underlying protocol decoder checks terminal metadata, so a plain body EOF
/// cannot complete a truncated response. The request's `include_profile` selects
/// whether a final opaque profile is permitted. Synchronous validator code is
/// not preempted by the timer; its late result is refused.
///
/// No partial objects escape. Dropping the future cancels its private receiver
/// and response stream. Completion verifies representations under `validator`;
/// callers still establish signatures, reachability, complete dependencies and
/// current permission before admitting or using repository content.
///
/// # Errors
/// Refuses missing, zero or unrepresentable call bounds before network I/O.
/// Preserves transport and protocol errors, refuses invalid bundle frames or
/// schemas, and discards results that complete after the whole-call deadline.
///
/// # Panics
/// Requires a Tokio runtime with its time driver enabled.
pub async fn get_bundle<T, V>(
    client: &ContentServiceClient<T>,
    request: v1::GetBundleRequest,
    options: CallOptions,
    limits: BundleLimits,
    validator: &V,
) -> Result<ReceivedBundle, BundleClientError>
where
    T: ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as Body>::Error: fmt::Display,
    V: ContentValidator,
{
    let deadline = call_deadline(&options).ok_or(BundleClientError::Limits)?;

    let receive = async {
        let mut receiver = BundleReceiver::new(limits, request.include_profile);
        let mut stream = client
            .get_bundle_with_options(request, options)
            .await
            .map_err(BundleClientError::Transport)?;
        while let Some(message) = stream
            .message()
            .await
            .map_err(BundleClientError::Transport)?
        {
            receiver
                .push(message.to_owned_message())
                .map_err(BundleClientError::Bundle)?;
        }
        receiver
            .finish(validator)
            .map_err(BundleClientError::Bundle)
    };
    let result = tokio::time::timeout_at(deadline, receive)
        .await
        .map_err(|_| BundleClientError::Deadline)?;

    // Synchronous schema validation can finish without yielding to the timer.
    // Refuse late results even when the inner future becomes Ready first.
    if Instant::now() >= deadline {
        return Err(BundleClientError::Deadline);
    }
    result
}

/// Reports a refused private bundle read without exposing partial objects.
#[derive(Debug)]
pub enum BundleClientError {
    /// Requires explicit positive call bounds and a representable deadline.
    Limits,
    /// Refuses completion after the configured whole-call deadline.
    Deadline,
    /// Preserves a failed transport or protocol termination.
    Transport(ConnectError),
    /// Preserves refused metadata framing, resources, identities or schemas.
    Bundle(BundleError),
}

impl fmt::Display for BundleClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limits => "bundle RPC requires explicit positive call bounds",
            Self::Deadline => "bundle RPC exceeded its whole-call deadline",
            Self::Transport(_) => "bundle RPC transport or protocol failed",
            Self::Bundle(_) => "bundle RPC metadata was refused",
        })
    }
}

impl std::error::Error for BundleClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Bundle(error) => Some(error),
            _ => None,
        }
    }
}

// Validate caller bounds before a generated client can start network I/O.
fn call_deadline(options: &CallOptions) -> Option<Instant> {
    let timeout = options.timeout()?;
    if timeout.is_zero()
        || options.max_message_size().is_none_or(|bytes| bytes == 0)
        || options
            .element_memory_limit()
            .is_none_or(|bytes| bytes == 0)
    {
        return None;
    }
    Instant::now().checked_add(timeout)
}
