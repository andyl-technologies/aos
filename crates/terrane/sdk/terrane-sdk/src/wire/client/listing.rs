//! Receives finite pattern-matched ref listings without exposing partial rows.
//!
//! Every row remains an untrusted remote observation. Complete protocol reception
//! proves no atomic inventory, current permission, freshness or home execution.

use std::{collections::BTreeSet, fmt, num::NonZeroUsize};

use connectrpc::{
    ConnectError,
    client::{CallOptions, ClientTransport},
    http_body::Body,
};
use terrane_format::{
    auth::{Grant, SubjectPattern, Verb, Verbs},
    refs::RefName,
};
use tokio::time::Instant;

use super::{
    call_deadline,
    references::{ReceivedRef, observe_state},
};
use crate::wire::{
    refs::{RefCodec, RefWireError},
    services::RefServiceClient,
    v1,
};

/// Bounds retained listing rows and their variable-length represented content.
#[derive(Clone, Copy, Debug)]
pub struct RefListLimits {
    /// Maximum retained rows, bounding fixed per-row and duplicate-index overhead.
    pub max_entries: NonZeroUsize,
    /// Maximum sum of name, canonical record, profile, commit and home bytes.
    ///
    /// Names are also retained in the duplicate index, at most doubling their
    /// contribution. Generated per-message and element-memory limits separately
    /// bound incoming messages, including discarded unknown fields.
    pub max_content_bytes: NonZeroUsize,
}

/// Retains a completely received finite listing in the peer's delivery order.
///
/// Successful empty reception is a peer assertion, not proof that no refs exist
/// or a replacement for denied reads. No multi-ref snapshot is established.
#[derive(Clone, Debug)]
pub struct ReceivedRefList {
    /// Exact root-free canonical byte-glob pattern forwarded to the peer.
    pub pattern: String,
    /// Distinct matching canonical names with independently unverified ref values.
    pub entries: Vec<ReceivedRef>,
}

/// Receives a bounded finite listing through successful protocol termination.
///
/// Requires explicit positive timeout, message and element-memory bounds. The
/// pattern uses the same canonical root-free byte globs as guarded enumeration:
/// `*` stays within a slash component and `**` crosses components. All returned
/// names must be canonical, match the pattern and be distinct. Delivery order is
/// preserved without imposing an ordering requirement on the peer.
///
/// Canonical values and home summaries must agree. Absence, fencing, staleness
/// and home remain peer claims; this request selects no freshness policy. Values
/// remain private until independent commit/profile verification. Server-side
/// authorization and inventory completeness are separate responsibilities.
///
/// One absolute deadline covers connection, all messages, canonical checks and
/// protocol termination. Progress never resets it. Cancellation and any failure
/// discard the entire private result. Synchronous checks are not preempted; late
/// completion is refused. Transport security and capability headers belong to the
/// configured client and call options.
///
/// # Errors
/// Rejects missing call bounds or invalid/over-budget patterns before connecting.
/// Rejects malformed, nonmatching or duplicate names, inconsistent canonical
/// values, exceeded row/content bounds and late completion. Preserves transport
/// and protocol errors without returning partially received rows.
///
/// # Panics
/// Requires a Tokio runtime with its time driver enabled.
pub async fn list_refs<T>(
    client: &RefServiceClient<T>,
    request: v1::ListRefsRequest,
    options: CallOptions,
    codec: RefCodec,
    limits: RefListLimits,
) -> Result<ReceivedRefList, RefListClientError>
where
    T: ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as Body>::Error: fmt::Display,
{
    let deadline = call_deadline(&options).ok_or(RefListClientError::Limits)?;
    if request.pattern.contains(':')
        || options
            .max_message_size()
            .is_some_and(|maximum| request.pattern.len() > maximum)
    {
        return Err(RefListClientError::Request);
    }
    let verbs = Verbs::new(Verb::Read as u8).map_err(|_| RefListClientError::Request)?;
    Grant::new(request.pattern.clone(), verbs).map_err(|_| RefListClientError::Request)?;
    let pattern = request.pattern.clone();
    let matcher = SubjectPattern::new(pattern.clone());
    if Instant::now() >= deadline {
        return Err(RefListClientError::Deadline);
    }

    let receive = async {
        let mut stream = client
            .list_refs_with_options(request, options)
            .await
            .map_err(RefListClientError::Transport)?;
        let mut entries = Vec::new();
        let mut names = BTreeSet::new();
        let mut content_bytes = 0_usize;
        while let Some(message) = stream
            .message()
            .await
            .map_err(RefListClientError::Transport)?
        {
            if entries.len() >= limits.max_entries.get() {
                return Err(RefListClientError::Resources);
            }
            let state = message.to_owned_message();
            content_bytes = add_content_bytes(content_bytes, &state)?;
            if content_bytes > limits.max_content_bytes.get() {
                return Err(RefListClientError::Resources);
            }
            RefName::parse(&state.name).map_err(|_| RefListClientError::Name)?;
            if !matcher.matches(&state.name) || !names.insert(state.name.clone()) {
                return Err(RefListClientError::Name);
            }
            entries.push(observe_state(state, codec).map_err(RefListClientError::Value)?);
        }
        Ok(ReceivedRefList { pattern, entries })
    };
    let result = tokio::time::timeout_at(deadline, receive)
        .await
        .map_err(|_| RefListClientError::Deadline)?;
    if Instant::now() >= deadline {
        return Err(RefListClientError::Deadline);
    }
    result
}

fn add_content_bytes(mut total: usize, state: &v1::RefState) -> Result<usize, RefListClientError> {
    let value = state.value.as_option();
    let home = state.home.as_option();
    for length in [
        state.name.len(),
        value.map_or(0, |value| value.canonical_ref_record.len()),
        value.map_or(0, |value| value.profile.len()),
        value
            .and_then(|value| value.commit.as_option())
            .map_or(0, |commit| commit.value.len()),
        home.map_or(0, |home| home.region.len()),
        home.map_or(0, |home| home.zone.len()),
        home.map_or(0, |home| home.host.len()),
    ] {
        total = total
            .checked_add(length)
            .ok_or(RefListClientError::Resources)?;
    }
    Ok(total)
}

/// Reports a refused finite listing without exporting partial rows.
#[derive(Debug)]
pub enum RefListClientError {
    /// Requires explicit positive call bounds and a representable deadline.
    Limits,
    /// Rejects an invalid or over-budget pattern before connecting.
    Request,
    /// Rejects malformed, nonmatching or duplicate returned names.
    Name,
    /// Refuses row cardinality, content overflow or exceeded content bytes.
    Resources,
    /// Refuses completion after the whole-call deadline.
    Deadline,
    /// Preserves transport and failed protocol termination.
    Transport(ConnectError),
    /// Preserves invalid or inconsistent canonical ref representations.
    Value(RefWireError),
}

impl fmt::Display for RefListClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limits => "ref listing RPC requires explicit positive call bounds",
            Self::Request => "ref listing RPC pattern is invalid or exceeds its bound",
            Self::Name => "ref listing RPC name is invalid, nonmatching or duplicated",
            Self::Resources => "ref listing RPC exceeds retained row or content limits",
            Self::Deadline => "ref listing RPC exceeded its whole-call deadline",
            Self::Transport(_) => "ref listing RPC transport or protocol failed",
            Self::Value(_) => "ref listing RPC canonical value was refused",
        })
    }
}

impl std::error::Error for RefListClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Value(error) => Some(error),
            _ => None,
        }
    }
}
