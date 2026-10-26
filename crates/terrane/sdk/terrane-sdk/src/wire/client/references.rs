//! Receives exact-name ref observations without trusting remote commit context.
//!
//! Reception checks canonical records, redundant summaries and the reported
//! freshness bound. Peer claims cannot prove home execution or actual staleness.
//! The retained value requires independent commit/profile verification before
//! exposing the complete record; every repository operation still needs Guard.

use std::fmt;

use connectrpc::{
    ConnectError,
    client::{CallOptions, ClientTransport},
    http_body::Body,
};
use terrane_format::refs::RefName;
use tokio::time::Instant;

use super::call_deadline;
use crate::wire::{
    refs::{ObservedRefValue, RefCodec, RefWireError},
    services::RefServiceClient,
    v1,
};

/// Retains one complete remote ref observation and its advisory metadata.
///
/// Absence is a peer assertion, never a substitute for denied or failed reads.
/// Fencing, staleness and home require actual server enforcement independently
/// of this representation check. The value grants no current authorization.
#[derive(Clone, Debug)]
pub struct ReceivedRef {
    /// Exact canonical name requested and returned by the peer.
    pub name: String,
    /// Consistent canonical value awaiting independent commit/profile validation.
    pub value: Option<ObservedRefValue>,
    /// Peer assertion that the caller's writer epoch has been superseded.
    pub fenced: bool,
    /// Reported staleness, checked against this request's freshness policy.
    pub staleness_ms: u32,
    /// Peer-reported home, without evidence that this operation executed there.
    pub home: Option<v1::Locality>,
}

/// Receives one bounded exact-name ref observation through the native client.
///
/// Requires explicit positive timeout, message and element-memory limits.
/// Invalid or over-budget names, unknown freshness modes and `bounded` without a
/// positive millisecond bound refuse before connecting. Names must fit the
/// configured message-byte limit before canonical parsing allocates a copy.
/// The whole-call deadline includes connection, complete response reception and
/// canonical validation.
///
/// The response must name the requested ref. Its reported staleness must fit a
/// bounded request and must be zero for a linearizable request. Those checks do
/// not prove actual freshness or home execution. A present value remains private
/// until its commit and registered profile have been independently verified.
/// Transport security and capability headers belong to the caller's client and
/// call options. This operation implements no server, routing or authorization.
///
/// # Errors
/// Rejects missing call bounds or invalid requests before network I/O. Preserves
/// transport failures and refuses changed names, inconsistent canonical values,
/// exceeded reported freshness and completion after the absolute deadline.
/// No partial record or observation escapes a failed call.
///
/// # Panics
/// Requires a Tokio runtime with its time driver enabled.
pub async fn get_ref<T>(
    client: &RefServiceClient<T>,
    request: v1::GetRefRequest,
    options: CallOptions,
    codec: RefCodec,
) -> Result<ReceivedRef, RefClientError>
where
    T: ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as Body>::Error: fmt::Display,
{
    let deadline = call_deadline(&options).ok_or(RefClientError::Limits)?;
    if options
        .max_message_size()
        .is_some_and(|maximum| request.name.len() > maximum)
    {
        return Err(RefClientError::Request);
    }
    RefName::parse(&request.name).map_err(|_| RefClientError::Request)?;
    let freshness = request
        .freshness
        .as_known()
        .ok_or(RefClientError::Request)?;
    if freshness == v1::Freshness::Bounded && request.bound_ms == 0 {
        return Err(RefClientError::Request);
    }
    let name = request.name.clone();
    let bound_ms = request.bound_ms;
    if Instant::now() >= deadline {
        return Err(RefClientError::Deadline);
    }

    let receive = async {
        let response = client
            .get_ref_with_options(request, options)
            .await
            .map_err(RefClientError::Transport)?;
        let state = response.into_owned();
        if state.name != name {
            return Err(RefClientError::Name);
        }
        if (freshness == v1::Freshness::Bounded && state.staleness_ms > bound_ms)
            || (freshness == v1::Freshness::Linearizable && state.staleness_ms != 0)
        {
            return Err(RefClientError::Freshness);
        }
        let value = state
            .value
            .as_option()
            .map(|value| codec.observe_value(value))
            .transpose()
            .map_err(RefClientError::Value)?;
        if let (Some(value), Some(home)) = (&value, state.home.as_option()) {
            value.check_home(home).map_err(RefClientError::Value)?;
        }
        Ok(ReceivedRef {
            name: state.name,
            value,
            fenced: state.fenced,
            staleness_ms: state.staleness_ms,
            home: state.home.into_option(),
        })
    };
    let result = tokio::time::timeout_at(deadline, receive)
        .await
        .map_err(|_| RefClientError::Deadline)?;
    if Instant::now() >= deadline {
        return Err(RefClientError::Deadline);
    }
    result
}

/// Describes a refused whole-ref reception without exposing a partial record.
#[derive(Debug)]
pub enum RefClientError {
    /// Requires explicit positive call resources and a representable deadline.
    Limits,
    /// Rejects an invalid/over-budget name or freshness policy before connecting.
    Request,
    /// Rejects a response naming a different ref.
    Name,
    /// Rejects reported staleness exceeding the requested policy.
    Freshness,
    /// Refuses completion after the whole-call deadline.
    Deadline,
    /// Preserves transport or protocol failure without synthesizing absence.
    Transport(ConnectError),
    /// Preserves inconsistent or oversized canonical ref representations.
    Value(RefWireError),
}

impl fmt::Display for RefClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limits => "ref RPC requires explicit positive call bounds",
            Self::Request => "ref RPC request name or freshness policy is invalid",
            Self::Name => "ref RPC response names a different ref",
            Self::Freshness => "ref RPC response exceeds requested freshness",
            Self::Deadline => "ref RPC exceeded its whole-call deadline",
            Self::Transport(_) => "ref RPC transport or protocol failed",
            Self::Value(_) => "ref RPC canonical value was refused",
        })
    }
}

impl std::error::Error for RefClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Value(error) => Some(error),
            _ => None,
        }
    }
}
