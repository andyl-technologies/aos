//! Receives bounded negotiation hints without treating peer assertions as authority.
//!
//! A known commit must occur in the request, frontier identities must have the
//! registered width, and the missing bitmap must cover exactly the requested
//! hashes. These checks establish representation consistency, not correct graph
//! comparison, committed index membership or permission to disclose content.

use std::{collections::BTreeSet, fmt};

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

/// Bounds ancestry and root inputs and the received missing-node frontier.
///
/// These are caller resource policies, independent of the protocol's fixed
/// 4,096-entry limit on the request's `hashes` stage. Message and decoded-memory
/// limits additionally bound protobuf reception through the call options.
#[derive(Clone, Copy, Debug)]
pub struct NegotiationLimits {
    commits: usize,
    roots: usize,
    frontier: usize,
}

impl NegotiationLimits {
    /// Requires positive limits for ancestry hints, roots and frontier nodes.
    ///
    /// Empty request stages remain valid; a positive limit permits that stage
    /// without requiring it to contain any entries.
    ///
    /// # Errors
    /// Rejects a zero limit.
    pub fn new(
        commits: usize,
        roots: usize,
        frontier: usize,
    ) -> Result<Self, NegotiationClientError> {
        if commits == 0 || roots == 0 || frontier == 0 {
            return Err(NegotiationClientError::Limits);
        }

        Ok(Self {
            commits,
            roots,
            frontier,
        })
    }
}

/// Retains a complete, consistently represented set of remote negotiation hints.
///
/// The peer still supplies every assertion. Callers independently establish
/// reachability, current permission and verified content before repository use.
#[derive(Debug)]
pub struct NegotiationHints {
    known_commits: Vec<Digest>,
    missing_nodes: Vec<Digest>,
    missing: Vec<bool>,
}

impl NegotiationHints {
    /// Borrows peer-reported known commits in response order.
    pub fn known_commits(&self) -> &[Digest] {
        &self.known_commits
    }

    /// Borrows peer-reported missing frontier nodes in response order.
    pub fn missing_nodes(&self) -> &[Digest] {
        &self.missing_nodes
    }

    /// Borrows missing-content bits in request order, preserving duplicates.
    pub fn missing(&self) -> &[bool] {
        &self.missing
    }
}

/// Receives one complete bounded negotiation response through the native client.
///
/// Any combination of ancestry, roots and hashes is permitted. Empty input
/// returns empty hints without connecting. All input hashes must have exactly
/// 32 bytes; the hash stage accepts at most 4,096 entries. Explicit positive
/// timeout, message and decoded-memory bounds are required before network I/O.
///
/// Known commits must be drawn from the supplied ancestry hints. Frontier nodes
/// require at least one requested root. Missing bits preserve input order and
/// duplicates; unused bits in the final bitmap byte are ignored. A whole-call
/// deadline includes connection, reception and representation checks. Capability
/// headers and transport security belong to the configured client and options.
///
/// # Errors
/// Rejects invalid call bounds, exceeded input limits or malformed input hashes
/// before connecting. Refuses malformed or excessive response hints, transport
/// failures and completion after the deadline without returning partial hints.
///
/// # Panics
/// Requires a Tokio runtime with its time driver enabled.
pub async fn negotiate<T>(
    client: &ContentServiceClient<T>,
    request: v1::NegotiateRequest,
    options: CallOptions,
    limits: NegotiationLimits,
) -> Result<NegotiationHints, NegotiationClientError>
where
    T: ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as Body>::Error: fmt::Display,
{
    let deadline = call_deadline(&options).ok_or(NegotiationClientError::Limits)?;
    if request.have_commits.len() > limits.commits
        || request.roots.len() > limits.roots
        || request.hashes.len() > MAX_INDEXED_HASHES
        || request
            .have_commits
            .iter()
            .chain(&request.roots)
            .chain(&request.hashes)
            .any(|hash| hash.value.len() != 32)
    {
        return Err(NegotiationClientError::Request);
    }

    let commits = request.have_commits.len();
    let roots = request.roots.len();
    let hashes = request.hashes.len();
    if commits == 0 && roots == 0 && hashes == 0 {
        return Ok(NegotiationHints {
            known_commits: Vec::new(),
            missing_nodes: Vec::new(),
            missing: Vec::new(),
        });
    }

    // Retain fixed-width identities before moving the request into transport.
    let offered: BTreeSet<Digest> = request
        .have_commits
        .iter()
        .map(|hash| {
            hash.value
                .as_slice()
                .try_into()
                .map_err(|_| NegotiationClientError::Request)
        })
        .collect::<Result<_, _>>()?;
    let receive = async {
        let response = client
            .negotiate_with_options(request, options)
            .await
            .map_err(NegotiationClientError::Transport)?;
        let view = response.view();
        if view.known_commits.len() > commits
            || view.missing_nodes.len() > limits.frontier
            || (roots == 0 && !view.missing_nodes.is_empty())
            || view.missing_bitmap.len() != hashes.div_ceil(8)
        {
            return Err(NegotiationClientError::Response);
        }

        let response = response.into_owned();
        let mut known_commits = Vec::new();
        for hash in response.known_commits {
            let digest = decode_hash(&hash)?;
            if !offered.contains(&digest) {
                return Err(NegotiationClientError::Response);
            }
            known_commits.push(digest);
        }
        let missing_nodes = response
            .missing_nodes
            .iter()
            .map(decode_hash)
            .collect::<Result<_, _>>()?;
        let missing = (0..hashes)
            .map(|position| response.missing_bitmap[position / 8] & (1 << (position % 8)) != 0)
            .collect();
        Ok(NegotiationHints {
            known_commits,
            missing_nodes,
            missing,
        })
    };
    let result = tokio::time::timeout_at(deadline, receive)
        .await
        .map_err(|_| NegotiationClientError::Deadline)?;
    if Instant::now() >= deadline {
        return Err(NegotiationClientError::Deadline);
    }
    result
}

fn decode_hash(hash: &v1::Hash) -> Result<Digest, NegotiationClientError> {
    hash.value
        .as_slice()
        .try_into()
        .map_err(|_| NegotiationClientError::Response)
}

/// Reports a refused negotiation call without exposing partial hints.
#[derive(Debug)]
pub enum NegotiationClientError {
    /// Requires explicit positive call and negotiation resource limits.
    Limits,
    /// Refuses malformed or excessive input before network I/O.
    Request,
    /// Refuses malformed, unsolicited or excessive response hints.
    Response,
    /// Refuses completion after the whole-call deadline.
    Deadline,
    /// Preserves transport and protocol termination failures.
    Transport(ConnectError),
}

impl fmt::Display for NegotiationClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limits => "negotiation RPC requires explicit positive resource bounds",
            Self::Request => "negotiation RPC request is malformed or exceeds its limits",
            Self::Response => "negotiation RPC response contains invalid or excessive hints",
            Self::Deadline => "negotiation RPC exceeded its whole-call deadline",
            Self::Transport(_) => "negotiation RPC transport or protocol failed",
        })
    }
}

impl std::error::Error for NegotiationClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}
