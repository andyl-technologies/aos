//! Receives finite ordered reflogs without releasing a partial response.
//!
//! Canonical consistency and stream ordering do not establish committed history
//! or predecessor authority. Each retained entry requires independently verified
//! commit/profile context before exposing its complete canonical record.

use std::{fmt, num::NonZeroUsize};

use connectrpc::{
    ConnectError,
    client::{CallOptions, ClientTransport},
    http_body::Body,
};
use terrane_format::refs::RefName;
use tokio::time::Instant;

use super::call_deadline;
use crate::wire::{
    refs::{ObservedRefLog, RefCodec, RefWireError},
    services::RefServiceClient,
    v1,
};

/// Bounds retained entries and their variable-length represented content.
#[derive(Clone, Copy, Debug)]
pub struct RefLogLimits {
    /// Maximum retained entries, bounding fixed per-entry allocation overhead.
    pub max_entries: NonZeroUsize,
    /// Maximum sum of both canonical buffers and principal/profile/message bytes.
    ///
    /// The generated decoder's per-message and element-memory limits separately
    /// bound each incoming message, including unknown fields that are discarded.
    pub max_content_bytes: NonZeroUsize,
}

/// Retains one private canonical observation with its advisory commit message.
#[derive(Clone, Debug)]
pub struct ReceivedRefLogEntry {
    /// Complete consistent reflog awaiting independent commit/profile validation.
    pub observation: ObservedRefLog,
    /// Peer-supplied advisory text, outside the canonical reflog record.
    pub message: String,
}

/// Retains a completely received finite reflog in increasing sequence order.
///
/// A successful empty stream is a peer assertion, never a substitute for denied
/// or failed reads. Gaps are permitted by increasing-order semantics; this is
/// not a gap-free watch, a committed-history certificate or current authority.
#[derive(Clone, Debug)]
pub struct ReceivedRefLog {
    /// Exact canonical name supplied in the forwarded request.
    pub name: String,
    /// Complete private observations in strictly increasing peer sequence order.
    pub entries: Vec<ReceivedRefLogEntry>,
}

/// Receives a bounded finite reflog through successful protocol termination.
///
/// Requires explicit positive timeout, message and element-memory limits.
/// Entries must have consistent canonical records, sequences at or above the
/// requested starting sequence, and strictly increasing sequence numbers. No
/// contiguity, home execution, committed selection or history authority is
/// inferred. The request's exact name and starting sequence are forwarded.
///
/// One absolute deadline covers connection, all messages, protocol termination
/// and canonical validation. Progress does not reset it. Cancellation, failure,
/// truncation and exceeded resources discard every retained observation.
/// Transport security and capability headers belong to the configured client
/// and call options; repository authorization remains a server obligation.
///
/// # Errors
/// Rejects missing call bounds or malformed/over-budget names before connecting.
/// Preserves transport and canonical-codec failures, rejects sequences before
/// the requested start or not strictly increasing, and refuses exceeded entry,
/// content-byte or whole-call bounds. No partial response escapes a failure.
///
/// # Panics
/// Requires a Tokio runtime with its time driver enabled.
pub async fn get_ref_log<T>(
    client: &RefServiceClient<T>,
    request: v1::GetRefLogRequest,
    options: CallOptions,
    codec: RefCodec,
    limits: RefLogLimits,
) -> Result<ReceivedRefLog, RefLogClientError>
where
    T: ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as Body>::Error: fmt::Display,
{
    let deadline = call_deadline(&options).ok_or(RefLogClientError::Limits)?;
    if options
        .max_message_size()
        .is_some_and(|maximum| request.name.len() > maximum)
    {
        return Err(RefLogClientError::Request);
    }
    RefName::parse(&request.name).map_err(|_| RefLogClientError::Request)?;
    let name = request.name.clone();
    let from_sequence = request.from_sequence;
    if Instant::now() >= deadline {
        return Err(RefLogClientError::Deadline);
    }

    let receive = async {
        let mut stream = client
            .get_ref_log_with_options(request, options)
            .await
            .map_err(RefLogClientError::Transport)?;
        let mut entries = Vec::new();
        let mut content_bytes = 0_usize;
        let mut previous = None;
        while let Some(message) = stream
            .message()
            .await
            .map_err(RefLogClientError::Transport)?
        {
            if entries.len() >= limits.max_entries.get() {
                return Err(RefLogClientError::Resources);
            }
            let entry = message.to_owned_message();
            let value = entry.value.as_option();
            let lengths = [
                entry.canonical_ref_log_record.len(),
                value.map_or(0, |value| value.canonical_ref_record.len()),
                value.map_or(0, |value| value.profile.len()),
                entry.principal.len(),
                entry.message.len(),
            ];
            content_bytes = lengths
                .into_iter()
                .try_fold(content_bytes, usize::checked_add)
                .filter(|bytes| *bytes <= limits.max_content_bytes.get())
                .ok_or(RefLogClientError::Resources)?;
            let observation = codec
                .observe_log(&entry)
                .map_err(RefLogClientError::Value)?;
            let sequence = observation.sequence_hint();
            if sequence < from_sequence || previous.is_some_and(|prior| sequence <= prior) {
                return Err(RefLogClientError::Sequence);
            }
            previous = Some(sequence);
            entries.push(ReceivedRefLogEntry {
                observation,
                message: entry.message,
            });
        }
        Ok(ReceivedRefLog { name, entries })
    };
    let result = tokio::time::timeout_at(deadline, receive)
        .await
        .map_err(|_| RefLogClientError::Deadline)?;
    if Instant::now() >= deadline {
        return Err(RefLogClientError::Deadline);
    }
    result
}

/// Describes a refused whole-reflog reception without exposing partial entries.
#[derive(Debug)]
pub enum RefLogClientError {
    /// Requires explicit positive call bounds and a representable deadline.
    Limits,
    /// Rejects an invalid or over-budget ref name before connecting.
    Request,
    /// Rejects an entry before the requested start, duplicate or decreasing sequence.
    Sequence,
    /// Refuses entry cardinality, content-byte overflow or exceeded content bytes.
    Resources,
    /// Refuses completion after the whole-call deadline.
    Deadline,
    /// Preserves failed transport or protocol termination without synthesizing success.
    Transport(ConnectError),
    /// Preserves an invalid or inconsistent canonical reflog representation.
    Value(RefWireError),
}

impl fmt::Display for RefLogClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limits => "reflog RPC requires explicit positive call bounds",
            Self::Request => "reflog RPC name is invalid or exceeds its bound",
            Self::Sequence => "reflog RPC entries violate requested sequence order",
            Self::Resources => "reflog RPC exceeds retained entry or content limits",
            Self::Deadline => "reflog RPC exceeded its whole-call deadline",
            Self::Transport(_) => "reflog RPC transport or protocol failed",
            Self::Value(_) => "reflog RPC canonical record was refused",
        })
    }
}

impl std::error::Error for RefLogClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Value(error) => Some(error),
            _ => None,
        }
    }
}
