//! Owns original authenticated HTTP/2 Git requests and their transport buffers.
//!
//! An accepted head, receive stream and response handle enter connection custody
//! before parsing. Every delivered body frame enters that same custody before
//! bounds, allocation or flow-control checks. READY is a borrowing view, not a
//! buffer owner; errors, cancellation and unwinding end the same socket while
//! leaving the original fields resident for a future owning Gateway.
//!
//! This dormant owner grants no Git authority and installs no handler. A queued
//! response is not a peer acknowledgement, a Source callback or Storage drain.
//! Lower TLS/HTTP2 handshake cancellation and the private session sender remain
//! separate lifetime contracts. Transport byte ceilings are not funded ODB quotas.
//!
//! The existing closed request profile is:
//!
//! ```text
//! POST /aos/<32 lowercase project hex>/<32 lowercase repository hex>/git-upload-pack
//! Content-Type: application/x-git-upload-pack-request
//! ```
//!
//! Receive-pack uses the corresponding standard route and media type.

use std::collections::TryReserveError;
use std::fmt;
use std::future::{Future, poll_fn};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use aos_sandbox_core::{ProjectId, ResourceId};
use aos_sandbox_linux::seqpacket::bounded::{BoundedRecordError, boottime};
use bytes::Bytes;
use h2::server::{Connection, SendResponse};
use http::{Method, Response};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::public_api_session::{
    AuthenticatedPublicApiStream, GitPublicTransportShutdownErrorV1, PublicApiOriginalSocketErrorV1,
    PublicApiPeer, PublicApiSessionAcceptor, PublicApiSessionError,
};

use super::{
    GitChannelBindingDigestV1, GitExchangePlanV1, GitProtocolV2ServiceV1, GitSmartDispatchPhaseV1,
    GitSmartDispatchStateV1, GitSmartEndpointV1, GitSmartRequestV1, GitSmartTransportErrorV1,
};

use super::gateway_funding::FundedBodyBackingV1;
use super::delegated_read::{BasicHolderV1, GitReadKindV1, NegativeGitResponseV1};

type GitConnection = Connection<AuthenticatedPublicApiStream<TcpStream>, Bytes>;

// Both legacy and retained accepts use this closed HTTP/2 configuration.
pub(super) fn fixed_handshake(
    transport: AuthenticatedPublicApiStream<TcpStream>,
) -> h2::server::Handshake<AuthenticatedPublicApiStream<TcpStream>, Bytes> {
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(1)
        .initial_window_size(FRAME_BYTES as u32)
        .initial_connection_window_size(FRAME_BYTES as u32)
        .max_header_list_size(8192)
        .max_send_buffer_size(FRAME_BYTES);
    builder.handshake(transport)
}

pub(super) const MAXIMUM_BODY_BYTES: usize = 256 * 1024 * 1024;
pub(super) const FRAME_BYTES: usize = 16 * 1024;
const REQUEST_LIFETIME_NANOSECONDS: u64 = 300_000_000_000;

/// Preserves the first actual transport cause with redacted diagnostics.
pub(crate) enum GitHttpErrorV1 {
    /// The fixed authenticated peer is no longer current.
    Session(PublicApiSessionError),
    /// The concrete socket observation failed.
    OriginalSocket(PublicApiOriginalSocketErrorV1),
    /// The HTTP/2 engine reported its actual error.
    Transport(h2::Error),
    /// The protected boot clock could not be observed.
    Clock(BoundedRecordError),
    /// The original finite wait expired.
    Timeout(tokio::time::error::Elapsed),
    /// The standard Git route or command rejected its actual profile.
    Profile(GitSmartTransportErrorV1),
    /// The fixed HTTP response could not be formed.
    Headers(http::Error),
    /// The bounded contiguous input could not acquire storage.
    Allocation(TryReserveError),
    /// The actual original stream reported its reset reason.
    Reset(h2::Reason),
    /// The head or original stream does not match the closed request profile.
    Request,
    /// The original transport closed.
    Closed,
    /// The original absolute request cut expired.
    Expired,
    /// The delivered input or proposed output exceeded its transport ceiling.
    ByteLimit,
    /// The output is not bound to the protected terminal exchange.
    TerminalMismatch,
    /// The borrowing operation was cancelled.
    Cancelled,
    /// The borrowing operation unwound.
    Unwound,
    /// The original owning or borrowing transport view was abandoned.
    Abandoned,
    /// The original first cause remains owned once in connection state.
    Retained(Arc<GitHttpErrorV1>),
}

impl GitHttpErrorV1 {
    fn kind(&self) -> &'static str {
        match self {
            Self::Session(_) => "peer",
            Self::OriginalSocket(_) => "original-socket",
            Self::Transport(_) => "http2",
            Self::Clock(_) => "clock",
            Self::Timeout(_) => "timeout",
            Self::Profile(_) => "profile",
            Self::Headers(_) => "response-headers",
            Self::Allocation(_) => "allocation",
            Self::Reset(_) => "reset",
            Self::Request => "request",
            Self::Closed => "closed",
            Self::Expired => "expired",
            Self::ByteLimit => "byte-limit",
            Self::TerminalMismatch => "terminal-mismatch",
            Self::Cancelled => "cancelled",
            Self::Unwound => "unwound",
            Self::Abandoned => "abandoned",
            Self::Retained(cause) => cause.kind(),
        }
    }
}

impl fmt::Debug for GitHttpErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("GitHttpErrorV1").field(&self.kind()).finish()
    }
}

impl fmt::Display for GitHttpErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "original Git HTTP transport failed ({})", self.kind())
    }
}

impl std::error::Error for GitHttpErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Session(cause) => Some(cause),
            Self::OriginalSocket(cause) => Some(cause),
            Self::Transport(cause) => Some(cause),
            Self::Clock(cause) => Some(cause),
            Self::Timeout(cause) => Some(cause),
            Self::Profile(cause) => Some(cause),
            Self::Headers(cause) => Some(cause),
            Self::Allocation(cause) => Some(cause),
            Self::Retained(cause) => Some(cause.as_ref()),
            _ => None,
        }
    }
}

/// Owns a formed original h2 connection on a post-handshake rejection.
///
/// Earlier TLS/h2 handshake errors preserve their cause only; no consumed
/// application request is claimed, and lower handshake custody remains separate.
#[derive(Debug)]
pub(crate) enum GitHttpAcceptFailureV1 {
    /// The h2 connection had not yet entered this owner.
    BeforeConnection(GitHttpErrorV1),
    /// The actual formed connection ended and remains owned intact.
    Retained(RetainedGitHttpConnectionCustodyV1),
}

impl GitHttpAcceptFailureV1 {
    /// Moves the actual formed ended owner without reconstructing its fields.
    ///
    /// # Errors
    ///
    /// Returns the original lower cause when no h2 connection owner formed.
    pub(crate) fn into_retained_custody(
        self,
    ) -> Result<RetainedGitHttpConnectionCustodyV1, GitHttpErrorV1> {
        match self {
            Self::BeforeConnection(cause) => Err(cause),
            Self::Retained(custody) => Ok(custody),
        }
    }
}

impl fmt::Display for GitHttpAcceptFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original Git HTTP connection was not admitted")
    }
}

impl std::error::Error for GitHttpAcceptFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BeforeConnection(cause) => Some(cause),
            Self::Retained(custody) => custody.owner.state.status.first_actual_cause()
                .map(|cause| cause as &dyn std::error::Error),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OriginalHttpPhaseV1 {
    Idle,
    Receiving,
    Ready,
    ResponseQueued,
    Ended,
}

#[derive(Clone, Copy)]
enum InterruptionV1 {
    Cancelled,
    Unwound,
    Abandoned,
}

impl InterruptionV1 {
    fn error(self) -> GitHttpErrorV1 {
        match self {
            Self::Cancelled => GitHttpErrorV1::Cancelled,
            Self::Unwound => GitHttpErrorV1::Unwound,
            Self::Abandoned => GitHttpErrorV1::Abandoned,
        }
    }
}

enum FirstFailureV1 {
    Actual(Arc<GitHttpErrorV1>),
    Interrupted(InterruptionV1),
}

struct OriginalHttpStatusV1 {
    phase: OriginalHttpPhaseV1,
    first_failure: Option<FirstFailureV1>,
    shutdown_attempted: bool,
    shutdown_debt: Option<GitPublicTransportShutdownErrorV1>,
}

impl OriginalHttpStatusV1 {
    fn new() -> Self {
        Self {
            phase: OriginalHttpPhaseV1::Idle,
            first_failure: None,
            shutdown_attempted: false,
            shutdown_debt: None,
        }
    }

    fn end_with(&mut self, peer: &PublicApiPeer, cause: GitHttpErrorV1) {
        if self.first_failure.is_none() {
            self.first_failure = Some(FirstFailureV1::Actual(Arc::new(cause)));
        }
        self.end_transport(peer);
    }

    fn end_interrupted(&mut self, peer: &PublicApiPeer, interruption: InterruptionV1) {
        if self.first_failure.is_none() {
            // Drop does not allocate an error container or move resident fields.
            self.first_failure = Some(FirstFailureV1::Interrupted(interruption));
        }
        self.end_transport(peer);
    }

    fn end_transport(&mut self, peer: &PublicApiPeer) {
        self.phase = OriginalHttpPhaseV1::Ended;
        if !self.shutdown_attempted {
            self.shutdown_attempted = true;
            // Do not demand a now-failed currentness check before retiring it.
            self.shutdown_debt = peer.end_original_git_transport().err();
        }
    }

    fn retained_error(&self) -> GitHttpErrorV1 {
        match &self.first_failure {
            Some(FirstFailureV1::Actual(cause)) => GitHttpErrorV1::Retained(Arc::clone(cause)),
            Some(FirstFailureV1::Interrupted(interruption)) => interruption.error(),
            None => GitHttpErrorV1::Closed,
        }
    }

    fn first_actual_cause(&self) -> Option<&GitHttpErrorV1> {
        match &self.first_failure {
            Some(FirstFailureV1::Actual(cause)) => Some(cause.as_ref()),
            _ => None,
        }
    }
}

struct OriginalRequestCutV1 {
    cookie: NonZeroU64,
    deadline_boottime: u64,
    wait_cut: Instant,
}

impl OriginalRequestCutV1 {
    fn capture(peer: &PublicApiPeer) -> Result<Self, GitHttpErrorV1> {
        Self::capture_lifetime(peer, REQUEST_LIFETIME_NANOSECONDS)
    }

    fn capture_lifetime(peer: &PublicApiPeer, maximum_lifetime: u64) -> Result<Self, GitHttpErrorV1> {
        peer.recheck_original_socket().map_err(GitHttpErrorV1::OriginalSocket)?;
        let session_deadline = peer.deadline_boottime_nanoseconds().map_err(GitHttpErrorV1::Session)?;
        let now = boottime().map_err(GitHttpErrorV1::Clock)?;
        let deadline_boottime = if maximum_lifetime == REQUEST_LIFETIME_NANOSECONDS {
            request_deadline(now, session_deadline)?
        } else {
            let deadline = session_deadline.min(now.checked_add(maximum_lifetime)
                .ok_or(GitHttpErrorV1::Clock(BoundedRecordError::Clock))?);
            if deadline <= now { return Err(GitHttpErrorV1::Expired); }
            deadline
        };
        let cookie = peer.original_socket_cookie().map_err(GitHttpErrorV1::OriginalSocket)?;

        Ok(Self {
            cookie,
            deadline_boottime,
            wait_cut: Instant::now() + Duration::from_nanos(deadline_boottime - now),
        })
    }
}

fn request_deadline(now: u64, session_deadline: u64) -> Result<u64, GitHttpErrorV1> {
    let maximum = now.checked_add(REQUEST_LIFETIME_NANOSECONDS)
        .ok_or(GitHttpErrorV1::Clock(BoundedRecordError::Clock))?;
    let deadline = session_deadline.min(maximum);
    if deadline <= now {
        return Err(GitHttpErrorV1::Expired);
    }
    Ok(deadline)
}

fn require_current(
    peer: &PublicApiPeer,
    status: &OriginalHttpStatusV1,
    cut: &OriginalRequestCutV1,
) -> Result<(), GitHttpErrorV1> {
    if status.phase == OriginalHttpPhaseV1::Ended {
        return Err(status.retained_error());
    }
    peer.recheck_original_socket().map_err(GitHttpErrorV1::OriginalSocket)?;
    if boottime().map_err(GitHttpErrorV1::Clock)? >= cut.deadline_boottime {
        return Err(GitHttpErrorV1::Expired);
    }
    if peer.original_socket_cookie().map_err(GitHttpErrorV1::OriginalSocket)? != cut.cookie {
        return Err(GitHttpErrorV1::Closed);
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct RequestFactsV1 {
    request: GitSmartRequestV1,
    stream_id: h2::StreamId,
    cookie: NonZeroU64,
    binding: GitChannelBindingDigestV1,
}

/// Owns a delivered frame until its append and flow-control release both finish.
#[derive(Default)]
struct OriginalBodyV1 {
    bytes: Vec<u8>,
    pending: Option<Bytes>,
    release_debt: Option<usize>,
}

impl OriginalBodyV1 {
    fn append_pending(&mut self, maximum: usize) -> Result<usize, GitHttpErrorV1> {
        if self.release_debt.is_some() {
            return Err(GitHttpErrorV1::Request);
        }
        let pending = self.pending.as_ref().ok_or(GitHttpErrorV1::Request)?;
        let length = pending.len();
        let next_length = self.bytes.len().checked_add(length).ok_or(GitHttpErrorV1::ByteLimit)?;
        if length > FRAME_BYTES || next_length > maximum {
            return Err(GitHttpErrorV1::ByteLimit);
        }

        self.bytes.try_reserve(length).map_err(GitHttpErrorV1::Allocation)?;
        self.bytes.extend_from_slice(pending);
        self.release_debt = Some(length);
        Ok(length)
    }

    fn released(&mut self) {
        self.pending = None;
        self.release_debt = None;
    }
}

struct RetainedGitResponseV1 {
    bytes: Bytes,
    stream: Option<h2::SendStream<Bytes>>,
    queued: usize,
}

struct OriginalGitRequestV1 {
    head: http::request::Parts,
    parsed: Option<GitSmartRequestV1>,
    facts: Option<RequestFactsV1>,
    incoming: h2::RecvStream,
    response: Option<SendResponse<Bytes>>,
    outgoing: Option<RetainedGitResponseV1>,
    body: OriginalBodyV1,
    read_kind: Option<GitReadKindV1>,
    holder: Option<BasicHolderV1>,
    negative_delivery: Option<Result<Result<(), h2::Error>, tokio::time::error::Elapsed>>,
}

impl OriginalGitRequestV1 {
    fn park(request: http::Request<h2::RecvStream>, response: SendResponse<Bytes>) -> Self {
        let (head, incoming) = request.into_parts();
        Self {
            head,
            parsed: None,
            facts: None,
            incoming,
            response: Some(response),
            outgoing: None,
            body: OriginalBodyV1::default(),
            read_kind: None,
            holder: None,
            negative_delivery: None,
        }
    }
}

struct OriginalHttpStateV1 {
    status: OriginalHttpStatusV1,
    cut: Option<OriginalRequestCutV1>,
    original: Option<OriginalGitRequestV1>,
    funded_body: Option<Vec<u8>>,
    delegated_read: bool,
}

/// Retains one concrete connection, its original request and its one-way end state.
pub(crate) struct GitHttpConnectionV1 {
    connection: GitConnection,
    peer: PublicApiPeer,
    state: OriginalHttpStateV1,
}

impl GitHttpConnectionV1 {
    /// Authenticates the concrete TCP socket before the bounded HTTP/2 handshake.
    ///
    /// This constructor does not claim custody of a request accepted by h2.
    /// Lower handshake errors and cancellation remain a separate owner gap.
    ///
    /// # Errors
    ///
    /// Preserves socket/TLS, HTTP/2 and actual handshake timeout failures.
    ///
    /// # Panics
    ///
    /// Tokio's timers require a running time-enabled runtime when polled.
    pub(crate) async fn accept(
        socket: TcpStream,
        acceptor: &PublicApiSessionAcceptor,
    ) -> Result<Self, GitHttpAcceptFailureV1> {
        let before_connection = GitHttpAcceptFailureV1::BeforeConnection;
        let transport = acceptor.accept_tcp(socket).await
            .map_err(|cause| before_connection(GitHttpErrorV1::OriginalSocket(cause)))?;
        let peer = transport.peer().clone();
        peer.recheck_original_socket()
            .map_err(|cause| before_connection(GitHttpErrorV1::OriginalSocket(cause)))?;

        let connection = tokio::time::timeout(
            Duration::from_secs(10),
            fixed_handshake(transport),
        )
        .await
        .map_err(|cause| before_connection(GitHttpErrorV1::Timeout(cause)))?
        .map_err(|cause| before_connection(GitHttpErrorV1::Transport(cause)))?;

        let owner = Self::from_handshake(connection, peer);
        if owner.handshake_rejected() {
            return Err(GitHttpAcceptFailureV1::Retained(owner.into_retained_custody()));
        }
        Ok(owner)
    }

    /// Parks a real TCP handshake without installing a listener or handler.
    pub(crate) fn begin_retained_handshake(
        socket: TcpStream,
        acceptor: Arc<PublicApiSessionAcceptor>,
    ) -> super::http_handshake::GitHttpHandshakeOwnerV1 {
        super::http_handshake::GitHttpHandshakeOwnerV1::begin(socket, acceptor)
    }

    pub(super) fn from_handshake(connection: GitConnection, peer: PublicApiPeer) -> Self {
        let mut owner = Self {
            connection,
            peer,
            state: OriginalHttpStateV1 {
                status: OriginalHttpStatusV1::new(),
                cut: None,
                original: None,
                funded_body: None,
                delegated_read: false,
            },
        };
        owner.recheck_handshake();
        owner
    }

    pub(super) fn recheck_handshake(&mut self) {
        if !self.handshake_rejected() {
            if let Err(cause) = self.peer.recheck_original_socket() {
                self.state.status.end_with(&self.peer, GitHttpErrorV1::OriginalSocket(cause));
            }
        }
    }

    pub(super) fn select_delegated_read(&mut self) {
        if self.state.status.phase == OriginalHttpPhaseV1::Idle {
            self.state.delegated_read = true;
        }
    }

    pub(super) fn handshake_rejected(&self) -> bool {
        self.state.status.phase == OriginalHttpPhaseV1::Ended
    }

    pub(super) fn handshake_cause(&self) -> Option<&GitHttpErrorV1> {
        self.state.status.first_actual_cause()
    }

    pub(super) fn interrupt_handshake(
        &mut self,
        kind: crate::public_api_session::HandshakeInterruptionV1,
    ) {
        use crate::public_api_session::HandshakeInterruptionV1;
        let interruption = match kind {
            HandshakeInterruptionV1::Cancelled => InterruptionV1::Cancelled,
            HandshakeInterruptionV1::Unwound => InterruptionV1::Unwound,
            HandshakeInterruptionV1::Abandoned => InterruptionV1::Abandoned,
        };
        self.state.status.end_interrupted(&self.peer, interruption);
    }

    pub(super) fn handshake_shutdown_debt(&self) -> Option<&GitPublicTransportShutdownErrorV1> {
        self.state.status.shutdown_debt.as_ref()
    }

    /// Receives one original request and exposes only a borrowing READY view.
    ///
    /// Accepted head/handles and every delivered frame remain in this connection
    /// on parse, currentness, bounds, release-capacity or timeout failure. Dropping
    /// the future ends the same transport; dropping the failure view does not
    /// drop the owner. The caller must retain the owner or its opaque ended capsule.
    ///
    /// # Errors
    ///
    /// Returns a borrowing first-cause view for malformed, closed, reset, stale,
    /// oversized or expired input. No replacement stream or request is accepted.
    ///
    /// # Panics
    ///
    /// Tokio's timers require a running time-enabled runtime when polled.
    /// An h2 internal poisoned lock can panic; the guard retains the original owner.
    pub(crate) async fn next_request(
        &mut self,
    ) -> Result<GitHttpRequestV1<'_>, GitHttpReceiveFailureV1<'_>> {
        let ready = self.receive_ready_facts().await;
        self.ready_view(ready)
    }

    /// Parks the sole allocated body before any funded receive future exists.
    pub(super) fn park_funded_body(
        &mut self,
        backing: FundedBodyBackingV1,
    ) -> Result<(), FundedBodyBackingV1> {
        if self.state.status.phase != OriginalHttpPhaseV1::Idle
            || self.state.original.is_some()
            || self.state.funded_body.is_some()
        {
            return Err(backing);
        }
        self.state.funded_body = Some(backing.into_vec());
        Ok(())
    }

    // Both legacy and funded loans run this one receive/check/end engine.
    pub(super) async fn receive_ready_facts(&mut self) -> Option<RequestFactsV1> {
        {
            let mut attempt = ReceiveAttemptV1 { owner: self, armed: true };
            let result = attempt.owner.receive_original_request().await;
            let ready = match result {
                Ok(facts) => Some(facts),
                Err(cause) => {
                    attempt.owner.state.status.end_with(&attempt.owner.peer, cause);
                    None
                }
            };
            attempt.armed = false;
            ready
        }
    }

    pub(super) fn ready_view(
        &mut self,
        ready: Option<RequestFactsV1>,
    ) -> Result<GitHttpRequestV1<'_>, GitHttpReceiveFailureV1<'_>> {
        let Self { connection, peer, state } = self;
        match (ready, state.original.as_mut(), state.cut.as_ref()) {
            (Some(facts), Some(original), Some(cut))
                if original.facts == Some(facts)
                    && original.parsed == Some(facts.request)
                    && state.status.phase == OriginalHttpPhaseV1::Ready =>
            {
                Ok(GitHttpRequestV1 {
                    connection,
                    peer,
                    status: &mut state.status,
                    cut,
                    original,
                    facts,
                })
            }
            _ => {
                state.status.end_with(peer, GitHttpErrorV1::Request);
                Err(GitHttpReceiveFailureV1 { status: &state.status })
            }
        }
    }

    async fn receive_original_request(&mut self) -> Result<RequestFactsV1, GitHttpErrorV1> {
        if self.state.status.phase == OriginalHttpPhaseV1::Ended {
            return Err(self.state.status.retained_error());
        }
        if self.state.status.phase != OriginalHttpPhaseV1::Idle {
            return Err(GitHttpErrorV1::Request);
        }
        self.state.status.phase = OriginalHttpPhaseV1::Receiving;
        self.state.cut = Some(if self.state.delegated_read {
            OriginalRequestCutV1::capture_lifetime(&self.peer, 10_000_000_000)?
        } else {
            OriginalRequestCutV1::capture(&self.peer)?
        });
        let cut = self.state.cut.as_ref().ok_or(GitHttpErrorV1::Request)?;

        let accepted = tokio::time::timeout_at(cut.wait_cut, self.connection.accept()).await;
        match accepted {
            Ok(Some(Ok((request, response)))) => {
                // No parse, stream-id call, currentness check or await precedes parking.
                self.state.original = Some(OriginalGitRequestV1::park(request, response));
                if let Some(backing) = self.state.funded_body.take() {
                    if let Some(original) = self.state.original.as_mut() {
                        original.body.bytes = backing;
                    }
                }
            }
            Ok(Some(Err(cause))) => return Err(GitHttpErrorV1::Transport(cause)),
            Ok(None) => return Err(GitHttpErrorV1::Closed),
            Err(cause) => return Err(GitHttpErrorV1::Timeout(cause)),
        }

        let original = self.state.original.as_mut().ok_or(GitHttpErrorV1::Request)?;
        let parsed = if self.state.delegated_read {
            let (request, kind) = parse_delegated_request(&original.head)?;
            original.read_kind = Some(kind);
            original.holder = Some(BasicHolderV1::capture(&original.head.headers));
            request
        } else {
            parse_request(&original.head)?
        };
        original.parsed = Some(parsed);
        if parsed.endpoint().project() != self.peer.project() {
            return Err(GitHttpErrorV1::Request);
        }
        let stream_id = original.incoming.stream_id();
        if stream_id != original.response.as_ref().ok_or(GitHttpErrorV1::Request)?.stream_id() {
            return Err(GitHttpErrorV1::Request);
        }

        tokio::time::timeout_at(cut.wait_cut, self.receive_body()).await
            .map_err(GitHttpErrorV1::Timeout)??;
        let cut = self.state.cut.as_ref().ok_or(GitHttpErrorV1::Request)?;
        require_current(&self.peer, &self.state.status, cut)?;
        let original = self.state.original.as_mut().ok_or(GitHttpErrorV1::Request)?;
        if original.read_kind == Some(GitReadKindV1::Discovery)
            && !original.body.bytes.is_empty()
        {
            return Err(GitHttpErrorV1::Request);
        }
        let facts = RequestFactsV1 {
            request: parsed,
            stream_id,
            cookie: cut.cookie,
            binding: transport_binding(
                self.peer.session_binding(),
                cut.cookie,
                stream_id.as_u32(),
                parsed,
                Sha256::digest(&original.body.bytes).into(),
            ),
        };
        original.facts = Some(facts);
        self.state.status.phase = OriginalHttpPhaseV1::Ready;
        Ok(facts)
    }

    async fn receive_body(&mut self) -> Result<(), GitHttpErrorV1> {
        let Self { connection, peer, state } = self;
        let OriginalHttpStateV1 { status, cut, original, .. } = state;
        let cut = cut.as_ref().ok_or(GitHttpErrorV1::Request)?;
        let original = original.as_mut().ok_or(GitHttpErrorV1::Request)?;

        loop {
            let has_frame = poll_fn(|context| {
                if let Err(cause) = require_current(peer, status, cut) {
                    return Poll::Ready(Err(cause));
                }
                if original.body.pending.is_some() {
                    return Poll::Ready(Err(GitHttpErrorV1::Request));
                }
                if let Poll::Ready(cause) = poll_connection(connection, context) {
                    return Poll::Ready(Err(cause));
                }
                match original.incoming.poll_data(context) {
                    Poll::Ready(Some(Ok(frame))) => {
                        // Ownership transfer is the first action after DATA delivery.
                        original.body.pending = Some(frame);
                        Poll::Ready(Ok(true))
                    }
                    Poll::Ready(Some(Err(cause))) => Poll::Ready(Err(GitHttpErrorV1::Transport(cause))),
                    Poll::Ready(None) => Poll::Ready(Ok(false)),
                    Poll::Pending => Poll::Pending,
                }
            }).await?;
            if !has_frame {
                return Ok(());
            }

            let length = original.body.append_pending(MAXIMUM_BODY_BYTES)?;
            original.incoming.flow_control().release_capacity(length)
                .map_err(GitHttpErrorV1::Transport)?;
            original.body.released();
        }
    }

    /// Moves the entire ended original owner into an opaque future-Gateway capsule.
    ///
    /// This conversion neither drains owners nor turns shutdown failure into success.
    pub(crate) fn into_retained_custody(mut self) -> RetainedGitHttpConnectionCustodyV1 {
        self.state.status.end_interrupted(&self.peer, InterruptionV1::Abandoned);
        RetainedGitHttpConnectionCustodyV1 { owner: self }
    }
}

impl Drop for GitHttpConnectionV1 {
    fn drop(&mut self) {
        let interruption = if std::thread::panicking() {
            InterruptionV1::Unwound
        } else {
            InterruptionV1::Abandoned
        };
        self.state.status.end_interrupted(&self.peer, interruption);
    }
}

struct ReceiveAttemptV1<'owner> {
    owner: &'owner mut GitHttpConnectionV1,
    armed: bool,
}

impl Drop for ReceiveAttemptV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            let interruption = if std::thread::panicking() {
                InterruptionV1::Unwound
            } else {
                InterruptionV1::Cancelled
            };
            self.owner.state.status.end_interrupted(&self.owner.peer, interruption);
        }
    }
}

/// Borrows the ended original owner's failure without taking its resident fields.
#[must_use = "the ended original connection must remain retained"]
pub(crate) struct GitHttpReceiveFailureV1<'owner> {
    status: &'owner OriginalHttpStatusV1,
}

impl GitHttpReceiveFailureV1<'_> {
    /// Returns a redacted error view that retains the actual original first source.
    pub(crate) fn cause(&self) -> GitHttpErrorV1 {
        self.status.retained_error()
    }

    /// Borrows the separate same-original shutdown failure, if any.
    pub(crate) fn shutdown_debt(&self) -> Option<&GitPublicTransportShutdownErrorV1> {
        self.status.shutdown_debt.as_ref()
    }
}

impl fmt::Debug for GitHttpReceiveFailureV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("GitHttpReceiveFailureV1").finish_non_exhaustive()
    }
}

impl fmt::Display for GitHttpReceiveFailureV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original Git HTTP request ended")
    }
}

impl std::error::Error for GitHttpReceiveFailureV1<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.status.first_actual_cause().map(|cause| cause as &dyn std::error::Error)
    }
}

/// Retains all actual ended connection fields without a raw or reviving interface.
#[must_use = "original transport custody is not drain or settlement"]
pub(crate) struct RetainedGitHttpConnectionCustodyV1 {
    owner: GitHttpConnectionV1,
}

impl RetainedGitHttpConnectionCustodyV1 {
    /// Borrows the selected negative delivery's actual nested native refusal.
    pub(super) fn negative_delivery_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let result = self.owner.state.original.as_ref()?.negative_delivery.as_ref()?;
        match result {
            Err(cause) => Some(cause),
            Ok(Err(cause)) => Some(cause),
            Ok(Ok(())) => None,
        }
    }

    /// Borrows an actual source; interruption state has no nested error object.
    pub(super) fn actual_cause(&self) -> Option<&GitHttpErrorV1> {
        self.owner.state.status.first_actual_cause()
    }

    /// Returns a redacted view of the original first cause.
    pub(crate) fn cause(&self) -> GitHttpErrorV1 {
        self.owner.state.status.retained_error()
    }

    /// Borrows the independent same-original shutdown debt.
    pub(crate) fn shutdown_debt(&self) -> Option<&GitPublicTransportShutdownErrorV1> {
        self.owner.state.status.shutdown_debt.as_ref()
    }
}

impl fmt::Debug for RetainedGitHttpConnectionCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RetainedGitHttpConnectionCustodyV1").finish_non_exhaustive()
    }
}

/// Borrows a READY original stream and its connection-resident complete body.
#[must_use = "dropping the READY view ends the original transport"]
pub(crate) struct GitHttpRequestV1<'connection> {
    connection: &'connection mut GitConnection,
    peer: &'connection PublicApiPeer,
    status: &'connection mut OriginalHttpStatusV1,
    cut: &'connection OriginalRequestCutV1,
    original: &'connection mut OriginalGitRequestV1,
    facts: RequestFactsV1,
}

impl GitHttpRequestV1<'_> {
    pub(super) fn delegated_input(&self) -> Option<(GitReadKindV1, &BasicHolderV1)> {
        Some((self.original.read_kind?, self.original.holder.as_ref()?))
    }

    /// Sends only a closed negative status, with no Git advertisement or body.
    /// Returned stream custody precedes the final same-original bookend.
    pub(super) fn send_negative(
        &mut self,
        response: NegativeGitResponseV1,
    ) -> impl Future<Output = Result<(), GitHttpErrorV1>> + '_ {
        let mut attempt = RequestAttemptV1 { request: self, armed: true };
        async move {
            let result = attempt.request.send_negative_inner(response).await;
            attempt.finish(result)
        }
    }

    async fn send_negative_inner(
        &mut self,
        response: NegativeGitResponseV1,
    ) -> Result<(), GitHttpErrorV1> {
        self.recheck_original().await?;
        if self.original.outgoing.is_some() {
            return Err(GitHttpErrorV1::TerminalMismatch);
        }
        self.original.outgoing = Some(RetainedGitResponseV1 {
            bytes: Bytes::new(), stream: None, queued: 0,
        });
        let mut headers = Response::builder()
            .status(response.status())
            .header(http::header::CACHE_CONTROL, "no-store")
            .header(http::header::CONTENT_LENGTH, "0");
        if response == NegativeGitResponseV1::Unauthorized {
            headers = headers.header(http::header::WWW_AUTHENTICATE, "Basic realm=\"aos-git\"");
        }
        let headers = headers.body(()).map_err(GitHttpErrorV1::Headers)?;
        let response = self.original.response.as_mut().ok_or(GitHttpErrorV1::Closed)?;
        let stream = response.send_response(headers, true).map_err(GitHttpErrorV1::Transport)?;
        let outgoing = self.original.outgoing.as_mut().ok_or(GitHttpErrorV1::Closed)?;
        outgoing.stream = Some(stream);
        self.original.response = None;
        require_current(self.peer, self.status, self.cut)?;
        // Queuing headers alone does not deliver them. Drive the SAME H2/TLS
        // connection through bounded graceful close before deliberate disposal.
        self.connection.graceful_shutdown();
        self.original.negative_delivery = Some(tokio::time::timeout_at(
            self.cut.wait_cut,
            poll_fn(|context| self.connection.poll_closed(context)),
        ).await);
        if !matches!(self.original.negative_delivery, Some(Ok(Ok(())))) {
            // The nested native close/timeout error stays in this actual slot.
            return Err(GitHttpErrorV1::Closed);
        }
        // RDHUP after intentional closure is not a fresh socket proof. Only
        // the original trust/cut are checked here; no remote ACK is inferred.
        self.peer.recheck().map_err(GitHttpErrorV1::Session)?;
        if boottime().map_err(GitHttpErrorV1::Clock)? >= self.cut.deadline_boottime {
            return Err(GitHttpErrorV1::Expired);
        }
        self.status.phase = OriginalHttpPhaseV1::ResponseQueued;
        Ok(())
    }

    /// Borrows the authenticated peer for independent protected admission.
    pub(crate) fn peer(&self) -> &PublicApiPeer {
        self.peer
    }

    /// Returns the closed standard smart request.
    pub(crate) const fn request(&self) -> GitSmartRequestV1 {
        self.facts.request
    }

    /// Returns the binding formed from this original complete request.
    pub(crate) const fn binding(&self) -> GitChannelBindingDigestV1 {
        self.facts.binding
    }

    /// Borrows the original complete input without copying its allocation.
    pub(crate) fn body(&self) -> &[u8] {
        &self.original.body.bytes
    }

    /// Returns the actual stream number as nonauthorizing DATA.
    pub(super) fn original_stream_id(&self) -> u32 {
        self.facts.stream_id.as_u32()
    }

    /// Returns the original kernel cookie as nonauthorizing DATA.
    pub(super) const fn original_socket_cookie(&self) -> NonZeroU64 {
        self.facts.cookie
    }

    /// Rechecks the same peer, socket, deadline and retained stream reset state.
    ///
    /// # Errors
    ///
    /// Preserves the first actual error/reset reason and ends the original
    /// transport on failure. Cancellation and unwinding retain the same fields.
    ///
    /// # Panics
    ///
    /// A poisoned h2 internal stream lock can panic; the borrowing guard ends
    /// the same transport without moving the resident request fields.
    pub(crate) async fn recheck(&mut self) -> Result<(), GitHttpErrorV1> {
        let mut attempt = RequestAttemptV1 { request: self, armed: true };
        let result = attempt.request.recheck_original().await;
        attempt.finish(result)
    }

    async fn recheck_original(&mut self) -> Result<(), GitHttpErrorV1> {
        self.require_ready_original()?;
        poll_fn(|context| self.poll_original_reset(context)).await?;
        require_current(self.peer, self.status, self.cut)
    }

    fn require_ready_original(&self) -> Result<(), GitHttpErrorV1> {
        require_current(self.peer, self.status, self.cut)?;
        if !matches!(self.status.phase, OriginalHttpPhaseV1::Ready | OriginalHttpPhaseV1::ResponseQueued)
            || self.original.incoming.stream_id() != self.facts.stream_id
            || self.cut.cookie != self.facts.cookie
        {
            return Err(GitHttpErrorV1::Closed);
        }

        Ok(())
    }

    fn poll_original_reset(&mut self, context: &mut Context<'_>) -> Poll<Result<(), GitHttpErrorV1>> {
        if let Err(cause) = require_current(self.peer, self.status, self.cut) {
            return Poll::Ready(Err(cause));
        }
        if let Poll::Ready(cause) = poll_connection(self.connection, context) {
            return Poll::Ready(Err(cause));
        }
        let reset = match (&mut self.original.response, &mut self.original.outgoing) {
            (Some(response), _) => response.poll_reset(context),
            (None, Some(outgoing)) => match outgoing.stream.as_mut() {
                Some(stream) => stream.poll_reset(context),
                None => return Poll::Ready(Err(GitHttpErrorV1::Closed)),
            },
            _ => return Poll::Ready(Err(GitHttpErrorV1::Closed)),
        };
        match reset {
            Poll::Pending => Poll::Ready(Ok(())),
            Poll::Ready(Ok(reason)) => Poll::Ready(Err(GitHttpErrorV1::Reset(reason))),
            Poll::Ready(Err(cause)) => Poll::Ready(Err(GitHttpErrorV1::Transport(cause))),
        }
    }

    /// Polls the same original checks and installs connection/reset wakers.
    /// Successful observation returns Pending, never a fresh Ready token.
    /// The existing Ready view must remain owned by its driving future so its
    /// Drop, and this prearmed local guard on panic, end the same transport.
    pub(crate) fn poll_while_child_parked(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<std::convert::Infallible, GitHttpErrorV1>> {
        let mut attempt = RequestAttemptV1 { request: self, armed: true };
        let result = (|| {
            attempt.request.require_ready_original()?;
            match attempt.request.poll_original_reset(context) {
                Poll::Ready(result) => result?,
                Poll::Pending => {}
            }
            require_current(attempt.request.peer, attempt.request.status, attempt.request.cut)
        })();
        match attempt.finish(result) {
            Ok(()) => Poll::Pending,
            Err(cause) => Poll::Ready(Err(cause)),
        }
    }

    /// Projects the captured original exclusive endpoint as nonauthorizing DATA.
    pub(crate) const fn original_deadline_boottime(&self) -> u64 {
        self.cut.deadline_boottime
    }

    /// Moves one complete output into original custody before validation or send.
    ///
    /// The returned future already borrows an armed end guard, including before
    /// its first poll. Only ownership parking happens synchronously; transport
    /// checks, errors and sending retain their asynchronous operation order.
    ///
    /// The original output is never replaced or copied per frame. h2 receives
    /// immutable slices sharing its backing, and `queued` records accepted
    /// send_data calls, not delivery. The READY view and connection still retain
    /// both bodies after any partial-send error or dropped future.
    ///
    /// # Errors
    ///
    /// Rejects changed transport, a second output attempt, nonterminal or
    /// differently bound settlement, overflow, timeout or actual h2 send failure.
    /// A second attempt cannot replace the original retained output.
    ///
    /// # Panics
    ///
    /// Polling requires a time-enabled Tokio runtime. An h2 poisoned lock can
    /// panic; the already resident output and end guard survive the unwind.
    pub(crate) fn send_terminal<'attempt>(
        &'attempt mut self,
        terminal: &'attempt GitSmartDispatchStateV1,
        output: Vec<u8>,
    ) -> impl Future<Output = Result<(), GitHttpErrorV1>> + 'attempt {
        let mut attempt = RequestAttemptV1 { request: self, armed: true };
        let is_original = if attempt.request.original.outgoing.is_some() {
            // A caller-supplied second buffer is not the original accepted output.
            // It cannot overwrite the resident first output or its send state.
            false
        } else {
            attempt.request.original.outgoing = Some(RetainedGitResponseV1 {
                bytes: Bytes::from(output),
                stream: None,
                queued: 0,
            });
            true
        };

        async move {
            let result = if is_original {
                attempt.request.send_original_terminal(terminal).await
            } else {
                Err(GitHttpErrorV1::TerminalMismatch)
            };
            attempt.finish(result)
        }
    }

    async fn send_original_terminal(
        &mut self,
        terminal: &GitSmartDispatchStateV1,
    ) -> Result<(), GitHttpErrorV1> {
        self.recheck_original().await?;
        let (principal, binding, output_limit) = match terminal.plan() {
            GitExchangePlanV1::Upload(plan) => (
                plan.principal(), plan.channel_binding(), plan.maximum_output_bytes(),
            ),
            GitExchangePlanV1::Receive(plan) => (
                plan.principal(), plan.channel_binding(), plan.maximum_output_bytes(),
            ),
        };
        if terminal.request() != self.facts.request
            || principal != self.peer.principal()
            || binding != self.facts.binding
            || !matches!(
                terminal.phase(),
                GitSmartDispatchPhaseV1::Completed | GitSmartDispatchPhaseV1::Rejected,
            )
            || terminal.terminal_receipt().is_none()
        {
            return Err(GitHttpErrorV1::TerminalMismatch);
        }
        let outgoing = self.original.outgoing.as_mut().ok_or(GitHttpErrorV1::Request)?;
        if outgoing.bytes.len() as u64 > output_limit || outgoing.bytes.len() > MAXIMUM_BODY_BYTES {
            return Err(GitHttpErrorV1::ByteLimit);
        }

        let content_type = match self.facts.request.endpoint().service() {
            GitProtocolV2ServiceV1::UploadPack => "application/x-git-upload-pack-result",
            GitProtocolV2ServiceV1::ReceivePack => "application/x-git-receive-pack-result",
        };
        let headers = Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, content_type)
            .header(http::header::CACHE_CONTROL, "no-store")
            .body(())
            .map_err(GitHttpErrorV1::Headers)?;
        let response = self.original.response.as_mut().ok_or(GitHttpErrorV1::Closed)?;
        let stream = response.send_response(headers, outgoing.bytes.is_empty())
            .map_err(GitHttpErrorV1::Transport)?;
        outgoing.stream = Some(stream);
        self.original.response = None;

        tokio::time::timeout_at(self.cut.wait_cut, self.send_body()).await
            .map_err(GitHttpErrorV1::Timeout)??;
        require_current(self.peer, self.status, self.cut)?;
        self.status.phase = OriginalHttpPhaseV1::ResponseQueued;
        Ok(())
    }

    async fn send_body(&mut self) -> Result<(), GitHttpErrorV1> {
        let connection = &mut *self.connection;
        let peer = self.peer;
        let status = &*self.status;
        let cut = self.cut;
        let outgoing = self.original.outgoing.as_mut().ok_or(GitHttpErrorV1::Request)?;
        let stream = outgoing.stream.as_mut().ok_or(GitHttpErrorV1::Request)?;

        while outgoing.queued < outgoing.bytes.len() {
            require_current(peer, status, cut)?;
            stream.reserve_capacity(FRAME_BYTES.min(outgoing.bytes.len() - outgoing.queued));
            let available = poll_fn(|context| {
                if let Err(cause) = require_current(peer, status, cut) {
                    return Poll::Ready(Err(cause));
                }
                if let Poll::Ready(cause) = poll_connection(connection, context) {
                    return Poll::Ready(Err(cause));
                }
                match stream.poll_capacity(context) {
                    Poll::Ready(Some(Ok(available))) => Poll::Ready(Ok(available)),
                    Poll::Ready(Some(Err(cause))) => Poll::Ready(Err(GitHttpErrorV1::Transport(cause))),
                    Poll::Ready(None) => Poll::Ready(Err(GitHttpErrorV1::Closed)),
                    Poll::Pending => Poll::Pending,
                }
            }).await?;
            if available == 0 {
                continue;
            }

            require_current(peer, status, cut)?;
            let length = available.min(FRAME_BYTES).min(outgoing.bytes.len() - outgoing.queued);
            let end = outgoing.queued + length;
            stream.send_data(
                outgoing.bytes.slice(outgoing.queued..end),
                end == outgoing.bytes.len(),
            ).map_err(GitHttpErrorV1::Transport)?;
            outgoing.queued = end;
        }
        Ok(())
    }
}

impl Drop for GitHttpRequestV1<'_> {
    fn drop(&mut self) {
        let interruption = if std::thread::panicking() {
            InterruptionV1::Unwound
        } else {
            InterruptionV1::Abandoned
        };
        self.status.end_interrupted(self.peer, interruption);
    }
}

struct RequestAttemptV1<'attempt, 'connection> {
    request: &'attempt mut GitHttpRequestV1<'connection>,
    armed: bool,
}

impl RequestAttemptV1<'_, '_> {
    fn finish(&mut self, result: Result<(), GitHttpErrorV1>) -> Result<(), GitHttpErrorV1> {
        let result = match result {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.request.status.end_with(self.request.peer, cause);
                Err(self.request.status.retained_error())
            }
        };
        self.armed = false;
        result
    }
}

impl Drop for RequestAttemptV1<'_, '_> {
    fn drop(&mut self) {
        if self.armed {
            let interruption = if std::thread::panicking() {
                InterruptionV1::Unwound
            } else {
                InterruptionV1::Cancelled
            };
            self.request.status.end_interrupted(self.request.peer, interruption);
        }
    }
}

/// Drives the one retained h2 connection; completion is always a terminal error.
fn poll_connection(
    connection: &mut GitConnection,
    context: &mut Context<'_>,
) -> Poll<GitHttpErrorV1> {
    match connection.poll_closed(context) {
        Poll::Ready(Ok(())) => Poll::Ready(GitHttpErrorV1::Closed),
        Poll::Ready(Err(cause)) => Poll::Ready(GitHttpErrorV1::Transport(cause)),
        Poll::Pending => Poll::Pending,
    }
}

fn parse_request(head: &http::request::Parts) -> Result<GitSmartRequestV1, GitHttpErrorV1> {
    if head.method != Method::POST || head.uri.query().is_some()
        || head.headers.contains_key(http::header::CONTENT_ENCODING)
        || head.headers.contains_key(http::header::TRANSFER_ENCODING)
    {
        return Err(GitHttpErrorV1::Request);
    }
    let path = head.uri.path().as_bytes();
    let route = path.strip_prefix(b"/aos/").ok_or(GitHttpErrorV1::Request)?;
    if route.len() < 66 || route[32] != b'/' || route[65] != b'/' {
        return Err(GitHttpErrorV1::Request);
    }
    let service = match &route[66..] {
        b"git-upload-pack" => GitProtocolV2ServiceV1::UploadPack,
        b"git-receive-pack" => GitProtocolV2ServiceV1::ReceivePack,
        _ => return Err(GitHttpErrorV1::Request),
    };
    let content_type = match service {
        GitProtocolV2ServiceV1::UploadPack => "application/x-git-upload-pack-request",
        GitProtocolV2ServiceV1::ReceivePack => "application/x-git-receive-pack-request",
    };
    let mut content_types = head.headers.get_all(http::header::CONTENT_TYPE).iter();
    if content_types.next().map(|value| value.as_bytes()) != Some(content_type.as_bytes())
        || content_types.next().is_some()
    {
        return Err(GitHttpErrorV1::Request);
    }
    let project = ProjectId::from_bytes(decode_id(&route[..32])?);
    let repository = ResourceId::from_bytes(decode_id(&route[33..65])?);
    let endpoint = GitSmartEndpointV1::new(project, repository, service).map_err(GitHttpErrorV1::Profile)?;
    GitSmartRequestV1::parse(&endpoint.command()).map_err(GitHttpErrorV1::Profile)
}

fn parse_delegated_request(
    head: &http::request::Parts,
) -> Result<(GitSmartRequestV1, GitReadKindV1), GitHttpErrorV1> {
    let mut protocols = head.headers.get_all("git-protocol").iter();
    if protocols.next().map(|value| value.as_bytes()) != Some(b"version=2")
        || protocols.next().is_some()
    {
        return Err(GitHttpErrorV1::Request);
    }
    if head.method == Method::POST {
        let request = parse_request(head)?;
        if request.endpoint().service() != GitProtocolV2ServiceV1::UploadPack {
            return Err(GitHttpErrorV1::Request);
        }
        return Ok((request, GitReadKindV1::Upload));
    }
    if head.method != Method::GET
        || head.uri.query() != Some("service=git-upload-pack")
        || head.headers.contains_key(http::header::CONTENT_ENCODING)
        || head.headers.contains_key(http::header::TRANSFER_ENCODING)
    {
        return Err(GitHttpErrorV1::Request);
    }
    let route = head.uri.path().as_bytes().strip_prefix(b"/aos/")
        .ok_or(GitHttpErrorV1::Request)?;
    if route.len() != 75 || route[32] != b'/' || route[65] != b'/'
        || &route[66..] != b"info/refs"
    {
        return Err(GitHttpErrorV1::Request);
    }
    let endpoint = GitSmartEndpointV1::new(
        ProjectId::from_bytes(decode_id(&route[..32])?),
        ResourceId::from_bytes(decode_id(&route[33..65])?),
        GitProtocolV2ServiceV1::UploadPack,
    ).map_err(GitHttpErrorV1::Profile)?;
    let request = GitSmartRequestV1::parse(&endpoint.command()).map_err(GitHttpErrorV1::Profile)?;
    Ok((request, GitReadKindV1::Discovery))
}

fn decode_id(bytes: &[u8]) -> Result<[u8; 16], GitHttpErrorV1> {
    if bytes.len() != 32 {
        return Err(GitHttpErrorV1::Request);
    }
    let mut decoded = [0; 16];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let digit = |value| match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(GitHttpErrorV1::Request),
        };
        *byte = (digit(bytes[index * 2])? << 4) | digit(bytes[index * 2 + 1])?;
    }
    Ok(decoded)
}

/// Commits the existing purpose-specific original-stream binding without changing its bytes.
pub(super) fn transport_binding(
    exporter: [u8; 32],
    cookie: NonZeroU64,
    stream: u32,
    request: GitSmartRequestV1,
    body_digest: [u8; 32],
) -> GitChannelBindingDigestV1 {
    GitChannelBindingDigestV1::commit(
        &Sha256::new()
            .chain_update(b"aos.sandbox.git.original-http2-stream.v1\0")
            .chain_update(exporter)
            .chain_update(cookie.get().to_be_bytes())
            .chain_update(stream.to_be_bytes())
            .chain_update(request.command_digest().as_bytes())
            .chain_update(body_digest)
            .finalize()
            .to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_identity_rejects_wrong_length_uppercase_and_nonhex() {
        assert_eq!(decode_id(b"00112233445566778899aabbccddeeff").unwrap()[15], 0xff);
        assert!(decode_id(b"00112233445566778899AABBCCDDEEFF").is_err());
        assert!(decode_id(b"00112233445566778899aabbccddee/g").is_err());
        assert!(decode_id(b"00").is_err());
    }

    #[test]
    fn exceeded_body_bound_keeps_exact_prefix_and_delivered_frame() {
        let mut body = OriginalBodyV1 {
            bytes: vec![1, 2],
            pending: Some(Bytes::from_static(&[3, 4])),
            release_debt: None,
        };

        assert!(matches!(body.append_pending(3), Err(GitHttpErrorV1::ByteLimit)));

        assert_eq!(body.bytes, [1, 2]);
        assert_eq!(body.pending.as_ref().unwrap().as_ref(), &[3, 4]);
        assert_eq!(body.release_debt, None);
    }

    #[test]
    fn oversized_delivered_frame_remains_pending_without_append() {
        let mut body = OriginalBodyV1 {
            pending: Some(Bytes::from(vec![7; FRAME_BYTES + 1])),
            ..OriginalBodyV1::default()
        };

        assert!(matches!(body.append_pending(MAXIMUM_BODY_BYTES), Err(GitHttpErrorV1::ByteLimit)));

        assert!(body.bytes.is_empty());
        assert_eq!(body.pending.as_ref().unwrap().len(), FRAME_BYTES + 1);
    }

    #[test]
    fn appended_frame_keeps_original_bytes_until_release_succeeds() {
        let mut body = OriginalBodyV1 {
            bytes: vec![1, 2],
            pending: Some(Bytes::from_static(&[3, 4])),
            release_debt: None,
        };

        assert_eq!(body.append_pending(4).unwrap(), 2);

        assert_eq!(body.bytes, [1, 2, 3, 4]);
        assert_eq!(body.pending.as_ref().unwrap().as_ref(), &[3, 4]);
        assert_eq!(body.release_debt, Some(2));
        assert!(matches!(body.append_pending(4), Err(GitHttpErrorV1::Request)));
        assert_eq!(body.bytes, [1, 2, 3, 4]);
    }

    #[test]
    fn successful_release_discards_only_redundant_delivered_frame() {
        let mut body = OriginalBodyV1 {
            pending: Some(Bytes::from_static(&[3, 4])),
            ..OriginalBodyV1::default()
        };
        body.append_pending(2).unwrap();

        body.released();

        assert_eq!(body.bytes, [3, 4]);
        assert!(body.pending.is_none());
        assert_eq!(body.release_debt, None);
    }

    #[test]
    fn request_cut_never_renews_the_original_session_deadline() {
        assert_eq!(request_deadline(100, 200).unwrap(), 200);
        assert_eq!(request_deadline(100, u64::MAX).unwrap(), 100 + REQUEST_LIFETIME_NANOSECONDS);
        assert!(matches!(request_deadline(200, 200), Err(GitHttpErrorV1::Expired)));
        assert!(matches!(request_deadline(u64::MAX, u64::MAX), Err(GitHttpErrorV1::Clock(_))));
    }

    #[test]
    fn retained_first_cause_keeps_one_error_without_sensitive_debug() {
        let original = Arc::new(GitHttpErrorV1::Reset(h2::Reason::CANCEL));
        let retained = GitHttpErrorV1::Retained(Arc::clone(&original));

        let GitHttpErrorV1::Retained(cause) = &retained else { panic!("retained cause") };

        assert!(Arc::ptr_eq(cause, &original));
        assert_eq!(format!("{retained:?}"), "GitHttpErrorV1(\"reset\")");
        assert!(std::error::Error::source(&retained).is_some());
    }

    #[test]
    fn output_slices_share_the_owned_original_backing() {
        let output = vec![1, 2, 3, 4];
        let original_backing = output.as_ptr();
        let bytes = Bytes::from(output);

        let frame = bytes.slice(1..3);

        assert_eq!(bytes.as_ptr(), original_backing);
        assert_eq!(frame.as_ref(), &[2, 3]);
        assert_eq!(frame.as_ptr(), bytes.as_ptr().wrapping_add(1));
        assert_eq!(bytes.as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn standard_route_data_preserves_both_service_profiles() {
        for (service, route, content_type) in [
            (
                GitProtocolV2ServiceV1::UploadPack,
                "git-upload-pack",
                "application/x-git-upload-pack-request",
            ),
            (
                GitProtocolV2ServiceV1::ReceivePack,
                "git-receive-pack",
                "application/x-git-receive-pack-request",
            ),
        ] {
            let path = format!("/aos/{}/{}/{route}", "01".repeat(16), "02".repeat(16));
            let (head, ()) = http::Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(http::header::CONTENT_TYPE, content_type)
                .body(())
                .unwrap()
                .into_parts();

            let parsed = parse_request(&head).unwrap();

            assert_eq!(parsed.endpoint().project(), ProjectId::from_bytes([1; 16]));
            assert_eq!(parsed.endpoint().repository(), ResourceId::from_bytes([2; 16]));
            assert_eq!(parsed.endpoint().service(), service);
        }
    }

    #[test]
    fn duplicate_content_type_precedes_sentinel_endpoint_profile_failure() {
        let path = format!("/aos/{}/{}/git-upload-pack", "00".repeat(16), "02".repeat(16));
        let (mut head, ()) = http::Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(http::header::CONTENT_TYPE, "application/x-git-upload-pack-request")
            .body(())
            .unwrap()
            .into_parts();
        head.headers.append(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-git-upload-pack-request"),
        );

        assert!(matches!(parse_request(&head), Err(GitHttpErrorV1::Request)));

        head.headers.remove(http::header::CONTENT_TYPE);
        head.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-git-upload-pack-request"),
        );
        assert!(matches!(
            parse_request(&head),
            Err(GitHttpErrorV1::Profile(GitSmartTransportErrorV1::InvalidRequest)),
        ));
    }
}
