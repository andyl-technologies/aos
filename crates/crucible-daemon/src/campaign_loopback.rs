//! Versioned Unix-stream transport for the user-facing campaign service.
//!
//! The protocol contains only bounded canonical component messages:
//!
//! ```text
//! CampaignLoopbackFrameV11 = magic[8] | kind:u8 | reserved[3] |
//!                           body_length:u32be | canonical_body[body_length]
//! kind = 1 (GetCampaignRequestV1) |
//!        2 (GetCampaignResponseV1) |
//!        3 (ApplyCampaignCommandRequestV1) |
//!        4 (ApplyCampaignCommandResponseV1) |
//!        5 (SubmitCampaignBranchRequestV1) |
//!        6 (SubmitCampaignBranchResponseV1) |
//!        7 (CampaignServiceErrorResponseV1) |
//!        8 (CreateCampaignRequestV1) |
//!        9 (CreateCampaignResponseV1) |
//!       10 (DeriveCampaignRequestV1) |
//!       11 (DeriveCampaignResponseV1) |
//!       12 (WatchCampaignRequestV1) |
//!       13 (WatchCampaignResponseV1) |
//!       14 (QueryCampaignGraphRequestV1) |
//!       15 (QueryCampaignGraphResponseV1) |
//!       16 (GetCampaignSnapshotRequestV1) |
//!       17 (GetCampaignSnapshotResponseV1) |
//!       18 (GetCampaignGraphObjectRequestV1) |
//!       19 (GetCampaignGraphObjectResponseV1) |
//!       20 (QueryCampaignChoicesRequestV1) |
//!       21 (QueryCampaignChoicesResponseV1) |
//!       22 (GetCampaignChoiceObjectRequestV1) |
//!       23 (GetCampaignChoiceObjectResponseV1) |
//!       24 (QueryCampaignFrontierRequestV1) |
//!       25 (QueryCampaignFrontierResponseV1)
//! magic = "CRUCCS11"
//! ```
//!
//! One mutex serializes complete request/response exchanges so concurrent
//! local callers cannot interleave frames; a competing caller receives an
//! immediate connection-busy error. Absolute read and write deadlines reject
//! partial or drip-fed frames, and every protocol, I/O, or canonical error
//! poisons the connection by shutting down both stream directions. A valid
//! request-bound service error leaves the connection reusable.
//!
//! Framing alone does not authenticate the connected peer. The authenticated
//! repository adapter in this module reads Linux `SO_PEERCRED`, resolves it to
//! one operational principal, and requires every request on that connection to
//! claim exactly that principal before applying the ordinary service policy.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

use crucible_campaign::{
    ApplyCampaignCommandRequest, ApplyCampaignCommandResponse, CampaignAuthorizationError,
    CampaignCodecError, CampaignName, CampaignPrincipal, CampaignPrincipalAuthorizer,
    CampaignRepository, CampaignService, CampaignServiceErrorResponse, CampaignServiceFailure,
    CampaignServiceFailureSource, CampaignServiceOperation, CreateCampaignRequest,
    CreateCampaignResponse, DeriveCampaignRequest, DeriveCampaignResponse,
    GetCampaignChoiceObjectRequest, GetCampaignChoiceObjectResponse, GetCampaignGraphObjectRequest,
    GetCampaignGraphObjectResponse, GetCampaignRequest, GetCampaignResponse,
    GetCampaignSnapshotRequest, GetCampaignSnapshotResponse, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES,
    QueryCampaignChoicesRequest, QueryCampaignChoicesResponse, QueryCampaignFrontierRequest,
    QueryCampaignFrontierResponse, QueryCampaignGraphRequest, QueryCampaignGraphResponse,
    RepositoryCampaignService, SubmitCampaignBranchRequest, SubmitCampaignBranchResponse,
    WatchCampaignRequest, WatchCampaignResponse,
};

const FRAME_MAGIC: &[u8; 8] = b"CRUCCS11";
const FRAME_HEADER_BYTES: usize = 16;
const GET_CAMPAIGN_REQUEST_KIND: u8 = 1;
const GET_CAMPAIGN_RESPONSE_KIND: u8 = 2;
const APPLY_COMMAND_REQUEST_KIND: u8 = 3;
const APPLY_COMMAND_RESPONSE_KIND: u8 = 4;
const SUBMIT_BRANCH_REQUEST_KIND: u8 = 5;
const SUBMIT_BRANCH_RESPONSE_KIND: u8 = 6;
const SERVICE_ERROR_RESPONSE_KIND: u8 = 7;
const CREATE_CAMPAIGN_REQUEST_KIND: u8 = 8;
const CREATE_CAMPAIGN_RESPONSE_KIND: u8 = 9;
const DERIVE_CAMPAIGN_REQUEST_KIND: u8 = 10;
const DERIVE_CAMPAIGN_RESPONSE_KIND: u8 = 11;
const WATCH_CAMPAIGN_REQUEST_KIND: u8 = 12;
const WATCH_CAMPAIGN_RESPONSE_KIND: u8 = 13;
const QUERY_CAMPAIGN_GRAPH_REQUEST_KIND: u8 = 14;
const QUERY_CAMPAIGN_GRAPH_RESPONSE_KIND: u8 = 15;
const GET_CAMPAIGN_SNAPSHOT_REQUEST_KIND: u8 = 16;
const GET_CAMPAIGN_SNAPSHOT_RESPONSE_KIND: u8 = 17;
const GET_CAMPAIGN_GRAPH_OBJECT_REQUEST_KIND: u8 = 18;
const GET_CAMPAIGN_GRAPH_OBJECT_RESPONSE_KIND: u8 = 19;
const QUERY_CAMPAIGN_CHOICES_REQUEST_KIND: u8 = 20;
const QUERY_CAMPAIGN_CHOICES_RESPONSE_KIND: u8 = 21;
const GET_CAMPAIGN_CHOICE_OBJECT_REQUEST_KIND: u8 = 22;
const GET_CAMPAIGN_CHOICE_OBJECT_RESPONSE_KIND: u8 = 23;
const QUERY_CAMPAIGN_FRONTIER_REQUEST_KIND: u8 = 24;
const QUERY_CAMPAIGN_FRONTIER_RESPONSE_KIND: u8 = 25;
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
    poisoned: AtomicBool,
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
            poisoned: AtomicBool::new(false),
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
        request_digest: crucible_campaign::CampaignHash,
        request: &[u8],
        decode_response: impl FnOnce(&[u8]) -> Result<T, LoopbackCampaignServiceError>,
        validate_failure: impl FnOnce(CampaignServiceFailure) -> Result<(), CampaignCodecError>,
    ) -> Result<T, LoopbackCampaignServiceError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(LoopbackCampaignProtocolError::ConnectionPoisoned.into());
        }
        let mut stream = match self.stream.try_lock() {
            Ok(stream) => stream,
            Err(TryLockError::WouldBlock) => {
                return Err(LoopbackCampaignProtocolError::ConnectionBusy.into());
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                let stream = poisoned.into_inner();
                self.poisoned.store(true, Ordering::Release);
                let _ = stream.shutdown(Shutdown::Both);
                return Err(LoopbackCampaignProtocolError::ConnectionPoisoned.into());
            }
        };
        let result = (|| {
            write_frame(&mut stream, request_kind, request, self.timeouts.write)?;
            let (kind, response) = read_frame_any(&mut stream, self.timeouts.read)?;
            match kind {
                kind if kind == response_kind => decode_response(&response),
                SERVICE_ERROR_RESPONSE_KIND => {
                    let response = CampaignServiceErrorResponse::from_canonical_bytes(&response)?;
                    response.validate_for_digest(request_digest)?;
                    let failure = response.failure();
                    validate_failure(failure)?;
                    Err(LoopbackCampaignServiceError::Remote(failure))
                }
                _ => Err(LoopbackCampaignProtocolError::InvalidFrame {
                    reason: "unexpected-message-kind",
                }
                .into()),
            }
        })();
        if matches!(
            result,
            Err(LoopbackCampaignServiceError::Protocol(_))
                | Err(LoopbackCampaignServiceError::Remote(
                    CampaignServiceFailure::ProtocolViolation
                ))
        ) {
            self.poisoned.store(true, Ordering::Release);
            let _ = stream.shutdown(Shutdown::Both);
        }
        result
    }
}

impl CampaignService for LoopbackCampaignService {
    type Error = LoopbackCampaignServiceError;

    fn create_campaign(
        &self,
        request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error> {
        self.exchange(
            CREATE_CAMPAIGN_REQUEST_KIND,
            CREATE_CAMPAIGN_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = CreateCampaignResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            CampaignServiceFailure::validate_for_create_campaign,
        )
    }

    fn derive_campaign(
        &self,
        request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, Self::Error> {
        self.exchange(
            DERIVE_CAMPAIGN_REQUEST_KIND,
            DERIVE_CAMPAIGN_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = DeriveCampaignResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            CampaignServiceFailure::validate_for_derive_campaign,
        )
    }

    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_REQUEST_KIND,
            GET_CAMPAIGN_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = GetCampaignResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            CampaignServiceFailure::validate_for_get_campaign,
        )
    }

    fn get_campaign_snapshot(
        &self,
        request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_SNAPSHOT_REQUEST_KIND,
            GET_CAMPAIGN_SNAPSHOT_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = GetCampaignSnapshotResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            CampaignServiceFailure::validate_for_get_campaign,
        )
    }

    fn watch_campaign(
        &self,
        request: &WatchCampaignRequest,
    ) -> Result<WatchCampaignResponse, Self::Error> {
        self.exchange(
            WATCH_CAMPAIGN_REQUEST_KIND,
            WATCH_CAMPAIGN_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = WatchCampaignResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            CampaignServiceFailure::validate_for_watch_campaign,
        )
    }

    fn query_campaign_graph(
        &self,
        request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, Self::Error> {
        self.exchange(
            QUERY_CAMPAIGN_GRAPH_REQUEST_KIND,
            QUERY_CAMPAIGN_GRAPH_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = QueryCampaignGraphResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_query_campaign_graph(request.snapshot()),
        )
    }

    fn get_campaign_graph_object(
        &self,
        request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_GRAPH_OBJECT_REQUEST_KIND,
            GET_CAMPAIGN_GRAPH_OBJECT_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = GetCampaignGraphObjectResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_get_campaign_graph_object(request.snapshot()),
        )
    }

    fn query_campaign_choices(
        &self,
        request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
        self.exchange(
            QUERY_CAMPAIGN_CHOICES_REQUEST_KIND,
            QUERY_CAMPAIGN_CHOICES_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = QueryCampaignChoicesResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_query_campaign_choices(request.snapshot()),
        )
    }

    fn query_campaign_frontier(
        &self,
        request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
        self.exchange(
            QUERY_CAMPAIGN_FRONTIER_REQUEST_KIND,
            QUERY_CAMPAIGN_FRONTIER_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = QueryCampaignFrontierResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_query_campaign_frontier(request.snapshot()),
        )
    }

    fn get_campaign_choice_object(
        &self,
        request: &GetCampaignChoiceObjectRequest,
    ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_CHOICE_OBJECT_REQUEST_KIND,
            GET_CAMPAIGN_CHOICE_OBJECT_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = GetCampaignChoiceObjectResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_get_campaign_choice_object(request.snapshot()),
        )
    }

    fn apply_campaign_command(
        &self,
        request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        self.exchange(
            APPLY_COMMAND_REQUEST_KIND,
            APPLY_COMMAND_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = ApplyCampaignCommandResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| {
                failure.validate_for_apply_campaign_command(request.command().expected_snapshot)
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
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = SubmitCampaignBranchResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_submit_branch_request(request.expected_snapshot()),
        )
    }
}

/// Authenticated Linux credentials for one connected Unix-stream peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnixPeerCampaignCredentials {
    process_id: i32,
    user_id: u32,
    group_id: u32,
}

impl UnixPeerCampaignCredentials {
    /// Returns the peer process ID captured by `SO_PEERCRED`.
    #[must_use]
    pub const fn process_id(self) -> i32 {
        self.process_id
    }

    /// Returns the peer effective user ID captured by `SO_PEERCRED`.
    #[must_use]
    pub const fn user_id(self) -> u32 {
        self.user_id
    }

    /// Returns the peer effective group ID captured by `SO_PEERCRED`.
    #[must_use]
    pub const fn group_id(self) -> u32 {
        self.group_id
    }
}

/// Resolves authenticated Unix peer credentials to one campaign principal.
///
/// The resolver is an operational identity-policy seam. Its output never
/// enters immutable campaign state, but every request on the connection must
/// claim the exact resolved principal.
pub trait UnixPeerCampaignPrincipalResolver {
    /// Resolves one kernel-authenticated peer identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignAuthorizationError`] when the peer is denied or the
    /// identity policy cannot make a definitive decision.
    fn resolve_campaign_principal(
        &self,
        credentials: UnixPeerCampaignCredentials,
    ) -> Result<CampaignPrincipal, CampaignAuthorizationError>;
}

impl<F> UnixPeerCampaignPrincipalResolver for F
where
    F: Fn(UnixPeerCampaignCredentials) -> Result<CampaignPrincipal, CampaignAuthorizationError>,
{
    fn resolve_campaign_principal(
        &self,
        credentials: UnixPeerCampaignCredentials,
    ) -> Result<CampaignPrincipal, CampaignAuthorizationError> {
        self(credentials)
    }
}

struct PeerBoundCampaignAuthorizer<'a, A: ?Sized> {
    principal: CampaignPrincipal,
    inner: &'a A,
}

impl<A> CampaignPrincipalAuthorizer for PeerBoundCampaignAuthorizer<'_, A>
where
    A: CampaignPrincipalAuthorizer + ?Sized,
{
    fn authorize(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
        campaign: &CampaignName,
        request_digest: crucible_campaign::CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        if principal != &self.principal {
            return Err(CampaignAuthorizationError::Unauthorized);
        }
        self.inner
            .authorize(principal, operation, campaign, request_digest)
    }
}

/// Serves one repository request after binding Linux peer credentials.
///
/// This is the production connected-stream authorization boundary. It reads
/// `SO_PEERCRED` before decoding the request, resolves the credential through
/// `principal_resolver`, and rejects a request whose self-described principal
/// differs from that authenticated result before repository access.
///
/// # Errors
///
/// Returns [`LoopbackCampaignServerError`] when peer authentication,
/// authorization resolution, framing, canonical validation, response binding,
/// or bounded socket I/O fails.
pub fn serve_authenticated_repository_campaign_once<R, A>(
    stream: &mut UnixStream,
    repository: &CampaignRepository,
    principal_resolver: &R,
    authorizer: &A,
) -> Result<(), LoopbackCampaignServerError>
where
    R: UnixPeerCampaignPrincipalResolver + ?Sized,
    A: CampaignPrincipalAuthorizer + ?Sized,
{
    serve_authenticated_repository_campaign_once_with_timeouts(
        stream,
        repository,
        principal_resolver,
        authorizer,
        LoopbackCampaignTimeouts::default(),
    )
}

/// Serves one peer-bound repository request with explicit finite deadlines.
///
/// # Errors
///
/// Returns the same failures as
/// [`serve_authenticated_repository_campaign_once`].
pub fn serve_authenticated_repository_campaign_once_with_timeouts<R, A>(
    stream: &mut UnixStream,
    repository: &CampaignRepository,
    principal_resolver: &R,
    authorizer: &A,
    timeouts: LoopbackCampaignTimeouts,
) -> Result<(), LoopbackCampaignServerError>
where
    R: UnixPeerCampaignPrincipalResolver + ?Sized,
    A: CampaignPrincipalAuthorizer + ?Sized,
{
    let result = (|| {
        let peer = rustix::net::sockopt::socket_peercred(&*stream)
            .map_err(|error| LoopbackCampaignProtocolError::Io(std::io::Error::from(error)))?;
        let credentials = UnixPeerCampaignCredentials {
            process_id: peer.pid.as_raw_pid(),
            user_id: peer.uid.as_raw(),
            group_id: peer.gid.as_raw(),
        };
        let principal = principal_resolver.resolve_campaign_principal(credentials)?;
        let peer_authorizer = PeerBoundCampaignAuthorizer {
            principal,
            inner: authorizer,
        };
        let service = RepositoryCampaignService::new(repository, peer_authorizer);
        serve_loopback_campaign_inner(stream, &service, timeouts)
    })();
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

/// Serves one strict campaign-service request/response exchange.
///
/// The stream is shut down in both directions before any protocol error is
/// returned. Service failures become exact request-bound error responses and
/// leave the connection reusable.
/// The caller remains responsible for authenticating the connected peer and
/// binding that evidence into the supplied service's principal authorizer.
///
/// # Errors
///
/// Returns [`LoopbackCampaignServerError::Protocol`] for malformed framing,
/// canonical input, invalid response binding, or bounded socket I/O.
pub fn serve_loopback_campaign_once<S>(
    stream: &mut UnixStream,
    service: &S,
) -> Result<(), LoopbackCampaignServerError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    serve_loopback_campaign_once_with_timeouts(stream, service, LoopbackCampaignTimeouts::default())
}

/// Serves one strict exchange with explicit finite operation deadlines.
///
/// # Errors
///
/// Returns the same failures as [`serve_loopback_campaign_once`].
pub fn serve_loopback_campaign_once_with_timeouts<S>(
    stream: &mut UnixStream,
    service: &S,
    timeouts: LoopbackCampaignTimeouts,
) -> Result<(), LoopbackCampaignServerError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let result = serve_loopback_campaign_inner(stream, service, timeouts);
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

fn serve_loopback_campaign_inner<S>(
    stream: &mut UnixStream,
    service: &S,
    timeouts: LoopbackCampaignTimeouts,
) -> Result<(), LoopbackCampaignServerError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    configure_stream(stream, timeouts)?;
    let (kind, body) = read_frame_any(stream, timeouts.read)?;
    let (response_kind, response) = match kind {
        CREATE_CAMPAIGN_REQUEST_KIND => {
            let request = CreateCampaignRequest::from_canonical_bytes(&body)?;
            match service.create_campaign(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (CREATE_CAMPAIGN_RESPONSE_KIND, response.canonical_bytes())
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure.validate_for_create_campaign() {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        DERIVE_CAMPAIGN_REQUEST_KIND => {
            let request = DeriveCampaignRequest::from_canonical_bytes(&body)?;
            match service.derive_campaign(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (DERIVE_CAMPAIGN_RESPONSE_KIND, response.canonical_bytes())
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure.validate_for_derive_campaign() {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        GET_CAMPAIGN_REQUEST_KIND => {
            let request = GetCampaignRequest::from_canonical_bytes(&body)?;
            match service.get_campaign(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (GET_CAMPAIGN_RESPONSE_KIND, response.canonical_bytes())
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure.validate_for_get_campaign() {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        GET_CAMPAIGN_SNAPSHOT_REQUEST_KIND => {
            let request = GetCampaignSnapshotRequest::from_canonical_bytes(&body)?;
            match service.get_campaign_snapshot(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (
                        GET_CAMPAIGN_SNAPSHOT_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure.validate_for_get_campaign() {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        WATCH_CAMPAIGN_REQUEST_KIND => {
            let request = WatchCampaignRequest::from_canonical_bytes(&body)?;
            match service.watch_campaign(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (WATCH_CAMPAIGN_RESPONSE_KIND, response.canonical_bytes())
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure.validate_for_watch_campaign() {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        QUERY_CAMPAIGN_GRAPH_REQUEST_KIND => {
            let request = QueryCampaignGraphRequest::from_canonical_bytes(&body)?;
            match service.query_campaign_graph(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (
                        QUERY_CAMPAIGN_GRAPH_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_query_campaign_graph(request.snapshot())
                    {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        GET_CAMPAIGN_GRAPH_OBJECT_REQUEST_KIND => {
            let request = GetCampaignGraphObjectRequest::from_canonical_bytes(&body)?;
            match service.get_campaign_graph_object(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (
                        GET_CAMPAIGN_GRAPH_OBJECT_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_get_campaign_graph_object(request.snapshot())
                    {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        QUERY_CAMPAIGN_CHOICES_REQUEST_KIND => {
            let request = QueryCampaignChoicesRequest::from_canonical_bytes(&body)?;
            match service.query_campaign_choices(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (
                        QUERY_CAMPAIGN_CHOICES_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_query_campaign_choices(request.snapshot())
                    {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        QUERY_CAMPAIGN_FRONTIER_REQUEST_KIND => {
            let request = QueryCampaignFrontierRequest::from_canonical_bytes(&body)?;
            match service.query_campaign_frontier(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (
                        QUERY_CAMPAIGN_FRONTIER_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_query_campaign_frontier(request.snapshot())
                    {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        GET_CAMPAIGN_CHOICE_OBJECT_REQUEST_KIND => {
            let request = GetCampaignChoiceObjectRequest::from_canonical_bytes(&body)?;
            match service.get_campaign_choice_object(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (
                        GET_CAMPAIGN_CHOICE_OBJECT_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_get_campaign_choice_object(request.snapshot())
                    {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        APPLY_COMMAND_REQUEST_KIND => {
            let request = ApplyCampaignCommandRequest::from_canonical_bytes(&body)?;
            match service.apply_campaign_command(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (APPLY_COMMAND_RESPONSE_KIND, response.canonical_bytes())
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure
                        .validate_for_apply_campaign_command(request.command().expected_snapshot)
                    {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        SUBMIT_BRANCH_REQUEST_KIND => {
            let request = SubmitCampaignBranchRequest::from_canonical_bytes(&body)?;
            match service.submit_branch_request(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (SUBMIT_BRANCH_RESPONSE_KIND, response.canonical_bytes())
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_submit_branch_request(request.expected_snapshot())
                    {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    service_error_response(request.request_digest(), &failure)?
                }
            }
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

fn service_error_response(
    request_digest: crucible_campaign::CampaignHash,
    error: &impl CampaignServiceFailureSource,
) -> Result<(u8, Vec<u8>), LoopbackCampaignServerError> {
    let response =
        CampaignServiceErrorResponse::new(request_digest, error.campaign_service_failure())?;
    Ok((SERVICE_ERROR_RESPONSE_KIND, response.canonical_bytes()))
}

fn reject_invalid_service_response(
    stream: &mut UnixStream,
    request_digest: crucible_campaign::CampaignHash,
    source: CampaignCodecError,
    write_timeout: Duration,
) -> Result<(), LoopbackCampaignServerError> {
    let response = CampaignServiceErrorResponse::new(
        request_digest,
        CampaignServiceFailure::ProtocolViolation,
    )?;
    write_frame(
        stream,
        SERVICE_ERROR_RESPONSE_KIND,
        &response.canonical_bytes(),
        write_timeout,
    )?;
    Err(source.into())
}

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

impl CampaignServiceFailureSource for LoopbackCampaignServiceError {
    fn campaign_service_failure(&self) -> CampaignServiceFailure {
        match self {
            Self::Remote(failure) => *failure,
            Self::Protocol(LoopbackCampaignProtocolError::InvalidTimeout) => {
                CampaignServiceFailure::InvalidRequest
            }
            Self::Protocol(
                LoopbackCampaignProtocolError::Codec(_)
                | LoopbackCampaignProtocolError::InvalidFrame { .. },
            ) => CampaignServiceFailure::ProtocolViolation,
            Self::Protocol(
                LoopbackCampaignProtocolError::Io(_)
                | LoopbackCampaignProtocolError::ConnectionBusy,
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

#[cfg(test)]
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
